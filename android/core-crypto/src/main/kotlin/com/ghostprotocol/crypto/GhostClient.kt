package com.ghostprotocol.crypto

import com.google.gson.Gson
import com.google.gson.JsonParseException
import java.security.SecureRandom
import java.util.Base64
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.UntrustedIdentityException

/** The contact's identity key differs from the one we pinned. Never auto-trusted: the user must decide. */
class KeyChangedException(val contact: String) : Exception("identity key for $contact changed")
class UnknownContactException(val contact: String) : Exception("unknown contact $contact")

data class Contact(
    val name: String,
    val mailboxId: String,
    val verified: Boolean = false,       // user compared safety numbers
    val keyChanged: Boolean = false,     // a different identity key was presented since we pinned one
    val ttlSeconds: Long = 0,            // local disappearing-message timer for this chat; 0 = keep
)

/** For group messages [contact] is the author and [group] the group id; for 1:1 chats [group] is null. */
data class StoredMessage(
    val id: String, val contact: String, val outgoing: Boolean, val text: String,
    val timestamp: Long, val expiresAt: Long = 0,
    val group: String? = null, val system: Boolean = false,
    val attachment: AttachmentRef? = null,
)

/** Points at an encrypted file in the [AttachmentStore]. The key lives here (inside the encrypted client state). */
data class AttachmentRef(val id: String, val name: String, val mime: String, val size: Int, val key: String)

/** Where encrypted attachment bytes live. The app backs this with files under app-private storage. */
interface AttachmentStore {
    fun put(id: String, data: ByteArray)
    fun get(id: String): ByteArray?
    fun delete(id: String)
}
class MemoryAttachmentStore : AttachmentStore {
    private val m = HashMap<String, ByteArray>()
    @Synchronized override fun put(id: String, data: ByteArray) { m[id] = data }
    @Synchronized override fun get(id: String) = m[id]
    @Synchronized override fun delete(id: String) { m.remove(id) }
}

class AttachmentException(msg: String) : Exception(msg)

/** A file being received: chunks accumulate here (persisted) until the whole encrypted file is present. */
data class PendingAttachment(
    val id: String, val from: String, val name: String, val mime: String, val size: Int, val count: Int,
    val key: String, val hash: String, val ttl: Long, val startedAt: Long,
    val chunks: MutableMap<Int, String> = mutableMapOf(),
)

/** Group membership is controlled by the creator ([admin]); members are usernames and include yourself. */
data class Group(val id: String, val name: String, val admin: String, val members: List<String>, val ttlSeconds: Long = 0)

data class PollResult(val received: Int, val dropped: Int, val keyChanges: List<String>)

/** Outcome of sending to several people: who got it, and who did not (with a short reason). */
data class SendReport(val sent: List<String>, val failed: Map<String, String>)

private class ClientState(
    var contacts: MutableList<Contact> = mutableListOf(),
    var messages: MutableList<StoredMessage> = mutableListOf(),
    var groups: MutableList<Group> = mutableListOf(),
    var pending: MutableMap<String, PendingAttachment> = mutableMapOf(),
)

/**
 * Plaintext carried INSIDE the end-to-end encrypted envelope (never visible to the relay).
 * t: text | g_create | g_update | g_leave | g_text. ttl = disappearing timer the sender chose, honoured by the receiver.
 */
internal data class Payload(
    val t: String = "text",
    val m: String? = null,
    val ttl: Long = 0,
    val g: String? = null,
    val gn: String? = null,
    val gm: List<String>? = null,
    // attachments: a_meta (a, fn, mime, sz, n, k, h) and a_chunk (a, i, d)
    val a: String? = null, val fn: String? = null, val mime: String? = null, val sz: Int = 0, val n: Int = 0,
    val k: String? = null, val h: String? = null, val i: Int = -1, val d: String? = null,
)

/**
 * Messaging logic: contacts, send, receive, key-change handling, safety numbers, local history.
 * Cryptography is entirely libsignal (via [Messenger]); transport is [RelayApi].
 *
 * Persistence: after every change [persist] gets the full client state (contacts + message history)
 * as bytes. It contains plaintext messages, so the host MUST write it only to encrypted storage.
 *
 * Failure policy for incoming relay messages: anything that fails deterministically (malformed packet,
 * replay, bad MAC, wrong key) is acknowledged and dropped so it cannot jam the inbox; a transient failure
 * (network) leaves the message unacknowledged so it is retried. Errors are never silently "trusted".
 */
class GhostClient(
    private val device: LocalDevice,
    private val relay: RelayApi,
    state: ByteArray? = null,
    private val persist: (ByteArray) -> Unit = {},
    private val clock: () -> Long = System::currentTimeMillis,
    private val attachments: AttachmentStore = MemoryAttachmentStore(),
    private val sleeper: (Long) -> Unit = { Thread.sleep(it) },
) {
    private val gson = Gson()
    private val messenger = Messenger(device)
    private val st: ClientState = state?.let { decodeState(it) } ?: ClientState()
    private val random = SecureRandom()

    val username: String get() = device.name

    @Synchronized fun contacts(): List<Contact> = st.contacts.toList()
    @Synchronized fun messages(contact: String): List<StoredMessage> =
        st.messages.filter { it.group == null && it.contact == contact }.sortedBy { it.timestamp }

    @Synchronized fun groups(): List<Group> = st.groups.toList()
    @Synchronized fun groupMessages(id: String): List<StoredMessage> =
        st.messages.filter { it.group == id }.sortedBy { it.timestamp }

    private fun contact(name: String) = st.contacts.firstOrNull { it.name == name }
    private fun addr(name: String) = org.signal.libsignal.protocol.SignalProtocolAddress(name, 1)
    private fun save() = persist(gson.toJson(st).toByteArray(Charsets.UTF_8))
    private fun put(c: Contact) { st.contacts.removeAll { it.name == c.name }; st.contacts.add(c) }

    /** Fetch the contact's bundle and start a session. Throws [KeyChangedException] if their identity differs from the pinned one. */
    @Synchronized fun addContact(name: String): Contact {
        require(name.matches(Regex("^[a-z0-9_]{3,32}$"))) { "invalid username" }
        require(name != username) { "cannot add yourself" }
        val fetched = relay.fetchBundle(name)
        val bundle = PublicBundle.decode(fetched.bundle)
        try {
            messenger.startSession(addr(name), bundle.toPreKeyBundle(fetched.oneTimePreKey?.let { OneTimePreKey.decode(it) }))
        } catch (e: UntrustedIdentityException) {
            contact(name)?.let { put(it.copy(keyChanged = true)); save() }
            throw KeyChangedException(name)
        }
        val c = (contact(name) ?: Contact(name, fetched.mailboxId)).copy(mailboxId = fetched.mailboxId)
        put(c); save()
        return c
    }

    private fun nameOk(n: String) = n.matches(Regex("^[a-z0-9_]{3,32}$"))
    private fun exp(ttl: Long, now: Long) = if (ttl in 1..MAX_TTL) now + ttl * 1000 else 0L

    private fun encodePayload(p: Payload): ByteArray = byteArrayOf(PAYLOAD_V2) + gson.toJson(p).toByteArray(Charsets.UTF_8)

    /** Parses and validates a payload. Returns null for anything malformed or out of bounds (caller drops it). */
    private fun decodePayload(b: ByteArray): Payload? {
        if (b.isEmpty() || b[0] != PAYLOAD_V2) return null
        val p = try { gson.fromJson(String(b, 1, b.size - 1, Charsets.UTF_8), Payload::class.java) } catch (e: Exception) { return null } ?: return null
        if (p.ttl !in 0..MAX_TTL) return null
        if (p.m != null && (p.m.isEmpty() || p.m.length > MAX_TEXT)) return null
        if (p.gn != null && (p.gn.isEmpty() || p.gn.length > MAX_GROUP_NAME)) return null
        if (p.g != null && !p.g.matches(Regex("^[0-9a-f]{32}$"))) return null
        if (p.gm != null && (p.gm.size !in 2..MAX_MEMBERS || p.gm.toSet().size != p.gm.size || !p.gm.all(::nameOk))) return null
        if (p.t == "a_meta") {
            val name = p.fn; val mime = p.mime
            if (p.a == null || !p.a.matches(HEX32) || name == null || name.isEmpty() || name.length > MAX_FILENAME) return null
            if (mime == null || mime.length > 60 || !mime.matches(MIME)) return null
            if (p.sz !in 1..MAX_ATTACHMENT || p.n != chunkCount(p.sz) || p.k == null || p.h == null) return null
            if (!p.h.matches(Regex("^[0-9a-f]{64}$"))) return null
            val key = try { Base64.getDecoder().decode(p.k) } catch (e: Exception) { return null }
            if (key.size != 32) return null
        }
        if (p.t == "a_chunk") {
            if (p.a == null || !p.a.matches(HEX32) || p.i !in 0 until MAX_CHUNKS || p.d == null || p.d.length > CHUNK * 2) return null
        }
        return p
    }

    /** Encrypt [payload] for one contact and hand it to the relay. Does not store anything locally. */
    private fun deliver(name: String, payload: Payload) {
        val c0 = contact(name) ?: throw UnknownContactException(name)
        if (c0.keyChanged) throw KeyChangedException(name)
        if (c0.mailboxId.isEmpty() && !resolveMailbox(name)) throw KeyChangedException(name)
        val c = contact(name)!!
        val envelope = messenger.encrypt(addr(name), encodePayload(payload))
        relay.send(c.mailboxId, Packet.encode(username, envelope))
    }

    @Synchronized fun send(name: String, text: String): StoredMessage {
        val c = contact(name) ?: throw UnknownContactException(name)
        require(text.isNotEmpty() && text.length <= MAX_TEXT) { "message length" }
        deliver(name, Payload("text", text, ttl = c.ttlSeconds))
        val now = clock()
        val m = StoredMessage(newId(), name, true, text, now, exp(c.ttlSeconds, now))
        st.messages.add(m); save()
        return m
    }

    private fun reason(e: Exception) = when (e) {
        is KeyChangedException -> "key changed"
        is UnknownContactException -> "not a contact"
        is java.io.IOException -> "network"
        is RelayException -> "relay ${e.status}"
        else -> "failed"
    }

    private fun ensureContact(name: String) { if (contact(name) == null) addContact(name) }

    private fun fanOut(targets: List<String>, payload: Payload): SendReport {
        val sent = mutableListOf<String>(); val failed = linkedMapOf<String, String>()
        for (t in targets) {
            try { ensureContact(t); deliver(t, payload); sent += t } catch (e: Exception) { failed[t] = reason(e) }
        }
        save()
        return SendReport(sent, failed)
    }

    // ---------------------------------------------------------------- broadcast
    /** Send the same text to several contacts as ordinary one-to-one messages (recipients cannot see each other). */
    @Synchronized fun broadcast(names: List<String>, text: String): SendReport {
        require(names.isNotEmpty() && names.size <= MAX_MEMBERS * 2 && names.toSet().size == names.size) { "recipients" }
        require(text.isNotEmpty() && text.length <= MAX_TEXT) { "message length" }
        val sent = mutableListOf<String>(); val failed = linkedMapOf<String, String>()
        for (n in names) { try { send(n, text); sent += n } catch (e: Exception) { failed[n] = reason(e) } }
        return SendReport(sent, failed)
    }

    // ---------------------------------------------------------------- groups
    private fun group(id: String?) = st.groups.firstOrNull { it.id == id }
    private fun system(group: String, text: String, now: Long = clock()) =
        st.messages.add(StoredMessage(newId(), "", false, text, now, 0, group, system = true))

    /**
     * Groups use pairwise fan-out: every message is encrypted separately for each member with their one-to-one Signal
     * session (NOT Sender Keys). Cost grows with group size; the benefit is that removing someone simply stops sending
     * them anything. Only the creator can change membership; members ignore membership changes from anyone else.
     */
    @Synchronized fun createGroup(name: String, others: List<String>): Pair<Group, SendReport> {
        require(name.isNotBlank() && name.length <= MAX_GROUP_NAME) { "group name" }
        require(others.isNotEmpty() && others.size < MAX_MEMBERS && others.toSet().size == others.size && others.all(::nameOk) && username !in others) { "members" }
        val id = ByteArray(16).also { random.nextBytes(it) }.joinToString("") { "%02x".format(it) }
        val g = Group(id, name.trim(), username, listOf(username) + others)
        st.groups.add(g); system(id, "You created the group")
        return g to fanOut(others, Payload("g_create", g = id, gn = g.name, gm = g.members))
    }

    @Synchronized fun sendGroup(id: String, text: String): SendReport {
        val g = group(id) ?: throw IllegalArgumentException("unknown group")
        require(text.isNotEmpty() && text.length <= MAX_TEXT) { "message length" }
        val now = clock()
        st.messages.add(StoredMessage(newId(), username, true, text, now, exp(g.ttlSeconds, now), id))
        return fanOut(g.members - username, Payload("g_text", text, ttl = g.ttlSeconds, g = id))
    }

    /** Creator only. Removed members are told they were removed and receive nothing further. */
    @Synchronized fun updateGroup(id: String, add: List<String> = emptyList(), remove: List<String> = emptyList()): SendReport {
        val g = group(id) ?: throw IllegalArgumentException("unknown group")
        check(g.admin == username) { "only the group creator can change members" }
        require(add.all(::nameOk) && username !in remove) { "members" }
        val newMembers = ((g.members + add).distinct() - remove.toSet())
        require(newMembers.size in 2..MAX_MEMBERS) { "group size" }
        val ng = g.copy(members = newMembers)
        st.groups.removeAll { it.id == id }; st.groups.add(ng)
        remove.filter { it in g.members }.forEach { system(id, "$it was removed") }
        add.filter { it !in g.members }.forEach { system(id, "$it was added") }
        val joining = newMembers - g.members.toSet()                       // new members have no group yet: send a create
        val a = fanOut(joining, Payload("g_create", g = id, gn = g.name, gm = newMembers))
        val b = fanOut(((g.members + newMembers).distinct() - username) - joining.toSet(), Payload("g_update", g = id, gn = g.name, gm = newMembers))
        return SendReport(a.sent + b.sent, a.failed + b.failed)
    }

    @Synchronized fun leaveGroup(id: String): SendReport {
        val g = group(id) ?: throw IllegalArgumentException("unknown group")
        val report = fanOut(g.members - username, Payload("g_leave", g = id))
        st.groups.removeAll { it.id == id }; dropMessages { it.group == id }; save()
        return report
    }

    @Synchronized fun setGroupDisappearing(id: String, seconds: Long) {
        require(seconds in 0..MAX_TTL)
        val g = group(id) ?: throw IllegalArgumentException("unknown group")
        st.groups.removeAll { it.id == id }; st.groups.add(g.copy(ttlSeconds = seconds)); save()
    }

    /** Apply one decrypted payload from [sender]. Returns false if it must be dropped (invalid or not allowed). */
    private fun handleIncoming(sender: String, plain: ByteArray, now: Long): Int {
        val p = decodePayload(plain) ?: return DROP
        var kind = MSG
        when (p.t) {
            "text" -> {
                val text = p.m ?: return DROP
                st.messages.add(StoredMessage(newId(), sender, false, text, now, exp(p.ttl, now)))
            }
            "g_text" -> {
                val g = group(p.g) ?: return DROP
                val text = p.m ?: return DROP
                if (sender !in g.members) return DROP
                st.messages.add(StoredMessage(newId(), sender, false, text, now, exp(p.ttl, now), g.id))
            }
            "g_create" -> {
                val id = p.g ?: return DROP; val members = p.gm ?: return DROP; val name = p.gn ?: return DROP
                if (group(id) != null || sender !in members || username !in members) return DROP
                st.groups.add(Group(id, name, sender, members)); system(id, "$sender added you to the group", now)
            }
            "g_update" -> {
                val g = group(p.g) ?: return DROP
                val members = p.gm ?: return DROP
                if (sender != g.admin) return DROP                      // only the creator may change membership
                if (sender !in members) return DROP
                if (username !in members) {
                    st.groups.removeAll { it.id == g.id }; dropMessages { it.group == g.id }
                    st.messages.add(StoredMessage(newId(), "", false, "You were removed from \"${g.name}\"", now, 0, null, system = true))
                } else {
                    (members - g.members.toSet()).forEach { system(g.id, "$it was added", now) }
                    (g.members - members.toSet()).forEach { system(g.id, "$it was removed", now) }
                    st.groups.removeAll { it.id == g.id }; st.groups.add(g.copy(name = p.gn ?: g.name, members = members))
                }
            }
            "g_leave" -> {
                val g = group(p.g) ?: return DROP
                if (sender !in g.members || sender == username) return DROP
                st.groups.removeAll { it.id == g.id }; st.groups.add(g.copy(members = g.members - sender))
                system(g.id, "$sender left", now)
            }
            "a_meta" -> {
                if (st.pending.size >= MAX_PENDING || st.pending.containsKey(p.a!!)) return DROP
                st.pending[p.a] = PendingAttachment(p.a, sender, cleanName(p.fn!!), p.mime!!, p.sz, p.n, p.k!!, p.h!!, p.ttl, now)
                kind = INTERNAL
            }
            "a_chunk" -> {
                val pa = st.pending[p.a!!] ?: return DROP
                if (p.i >= pa.count || pa.chunks.containsKey(p.i)) return DROP
                val raw = try { Base64.getDecoder().decode(p.d!!) } catch (e: Exception) { return DROP }
                if (raw.isEmpty() || raw.size > CHUNK) return DROP
                pa.chunks[p.i] = p.d
                if (pa.chunks.size == pa.count) {
                    st.pending.remove(pa.id)
                    if (!finishAttachment(pa, now)) return DROP
                } else kind = INTERNAL
            }
            else -> return DROP
        }
        return kind
    }

    // ---------------------------------------------------------------- attachments (one-to-one only)
    private fun cleanName(raw: String): String {
        val base = raw.substringAfterLast('/').substringAfterLast('\\').filter { !it.isISOControl() }.trim().take(MAX_FILENAME)
        return base.ifEmpty { "file" }
    }
    private fun chunkCount(size: Int) = (size + GCM_OVERHEAD + CHUNK - 1) / CHUNK
    private fun expirePending() {
        val now = clock()
        if (st.pending.values.removeAll { now - it.startedAt > PENDING_MS }) save()
    }
    private fun sha256Hex(b: ByteArray) = java.security.MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    private fun gcm(mode: Int, key: ByteArray, iv: ByteArray, data: ByteArray, off: Int = 0): ByteArray =
        javax.crypto.Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(mode, javax.crypto.spec.SecretKeySpec(key, "AES"), javax.crypto.spec.GCMParameterSpec(128, iv))
        }.doFinal(data, off, data.size - off)

    /** All chunks are in: verify the transport hash, then the AEAD tag and size, and only then keep the (still encrypted) file. */
    private fun finishAttachment(pa: PendingAttachment, now: Long): Boolean = try {
        val ct = java.io.ByteArrayOutputStream().also { o -> for (i in 0 until pa.count) o.write(Base64.getDecoder().decode(pa.chunks[i] ?: return false)) }.toByteArray()
        if (sha256Hex(ct) != pa.hash) false
        else {
            val key = Base64.getDecoder().decode(pa.key)
            val plain = gcm(javax.crypto.Cipher.DECRYPT_MODE, key, ct.copyOfRange(0, 12), ct, 12)
            if (plain.size != pa.size) false
            else {
                attachments.put(pa.id, ct)
                st.messages.add(StoredMessage(newId(), pa.from, false, pa.name, now, exp(pa.ttl, now), null, false, AttachmentRef(pa.id, pa.name, pa.mime, pa.size, pa.key)))
                true
            }
        }
    } catch (e: Exception) { false }

    /** Encrypt a file with a fresh random key and send it as numbered chunks, each inside the normal end-to-end channel. */
    @Synchronized fun sendAttachment(name: String, fileName: String, mime: String, data: ByteArray): StoredMessage {
        val c = contact(name) ?: throw UnknownContactException(name)
        require(data.isNotEmpty() && data.size <= MAX_ATTACHMENT) { "attachment size" }
        require(mime.length <= 60 && mime.matches(MIME)) { "mime type" }
        val fname = cleanName(fileName)
        val key = ByteArray(32).also { random.nextBytes(it) }
        val iv = ByteArray(12).also { random.nextBytes(it) }
        val ct = iv + gcm(javax.crypto.Cipher.ENCRYPT_MODE, key, iv, data)
        val chunks = ct.toList().chunked(CHUNK).map { it.toByteArray() }
        val id = ByteArray(16).also { random.nextBytes(it) }.joinToString("") { "%02x".format(it) }
        val k64 = Base64.getEncoder().encodeToString(key)
        retrying { deliver(name, Payload("a_meta", a = id, fn = fname, mime = mime, sz = data.size, n = chunks.size, k = k64, h = sha256Hex(ct), ttl = c.ttlSeconds)) }
        chunks.forEachIndexed { i, ch -> retrying { deliver(name, Payload("a_chunk", a = id, i = i, d = Base64.getEncoder().encodeToString(ch))) } }
        attachments.put(id, ct)
        val now = clock()
        val m = StoredMessage(newId(), name, true, fname, now, exp(c.ttlSeconds, now), null, false, AttachmentRef(id, fname, mime, data.size, k64))
        st.messages.add(m); save()
        return m
    }

    /** Relay rate limits (429) are expected during a burst of chunks: pause and retry a few times. */
    private fun retrying(block: () -> Unit) {
        var tries = 0
        while (true) {
            try { block(); return } catch (e: RelayException) {
                if (e.status != 429 || ++tries > 10) throw e
                sleeper(700)
            }
        }
    }

    /** Decrypt a stored attachment for display. Throws [AttachmentException] if missing or if it fails authentication. */
    @Synchronized fun attachmentBytes(ref: AttachmentRef): ByteArray {
        val ct = attachments.get(ref.id) ?: throw AttachmentException("file missing")
        return try { gcm(javax.crypto.Cipher.DECRYPT_MODE, Base64.getDecoder().decode(ref.key), ct.copyOfRange(0, 12), ct, 12) }
        catch (e: Exception) { throw AttachmentException("file failed authentication") }
    }

    /** Fetch, decrypt and store new messages. */
    @Synchronized fun poll(): PollResult {
        val toAck = mutableListOf<String>()
        var received = 0; var dropped = 0
        val changes = linkedSetOf<String>()
        expirePending()
        for (d in relay.inbox()) {
            try {
                val (sender, envelope) = Packet.decode(d.body)
                val known = contact(sender)
                if (known?.keyChanged == true) { dropped++; toAck += d.id; continue } // refuse until user resolves
                val plain = try {
                    messenger.decrypt(addr(sender), envelope)
                } catch (e: UntrustedIdentityException) {
                    if (known != null) put(known.copy(keyChanged = true))
                    changes += sender; save(); dropped++; toAck += d.id; continue
                }
                if (known == null) {
                    // New sender. The message is already decrypted (session state advanced), so it MUST be stored and
                    // acknowledged no matter what: a retry would be rejected as a replay and the message would be lost.
                    // Their mailbox is looked up best-effort now and lazily at send time if that fails.
                    put(Contact(sender, ""))
                    try { if (!resolveMailbox(sender)) changes += sender } catch (e: java.io.IOException) {} catch (e: RelayException) {}
                }
                when (handleIncoming(sender, plain, clock())) { MSG -> received++; INTERNAL -> {}; else -> dropped++ }
                toAck += d.id
            } catch (e: Exception) {
                dropped++; toAck += d.id // deterministic failure (tamper, replay, malformed): drop
            }
        }
        save()
        if (toAck.isNotEmpty()) relay.ack(toAck)
        return PollResult(received, dropped, changes.toList())
    }

    /**
     * Learn the mailbox of a contact whose session already exists, and check the identity the relay serves for
     * them equals the one pinned from their messages. Returns false (and flags the contact) on mismatch.
     */
    private fun resolveMailbox(name: String): Boolean {
        val f = relay.fetchBundle(name)
        val relayIdentity = IdentityKey(org.signal.libsignal.protocol.ecc.ECPublicKey(PublicBundle.decode(f.bundle).identityKey))
        val pinned = device.store.getIdentity(addr(name))
        val c = contact(name) ?: return false
        if (pinned != null && pinned != relayIdentity) { put(c.copy(keyChanged = true)); save(); return false }
        put(c.copy(mailboxId = f.mailboxId)); save()
        return true
    }

    /** Numeric safety number both users compare out of band (in person, or over another channel). */
    @Synchronized fun safetyNumber(name: String): String {
        contact(name) ?: throw UnknownContactException(name)
        val id = device.store.getIdentity(addr(name)) ?: throw UnknownContactException(name)
        return SafetyNumber.compute(device, name, id).displayableFingerprint.displayText
    }

    @Synchronized fun markVerified(name: String) {
        val c = contact(name) ?: throw UnknownContactException(name); put(c.copy(verified = true)); save()
    }

    /**
     * Explicit user decision after a key-change warning: forget the old identity and session, fetch the contact's
     * current keys, and start over UNVERIFIED. Old messages are kept.
     */
    @Synchronized fun acceptKeyChange(name: String): Contact {
        val c = contact(name) ?: throw UnknownContactException(name)
        device.store.forgetContact(addr(name))
        put(c.copy(keyChanged = false, verified = false))
        return addContact(name)
    }

    @Synchronized fun setDisappearing(name: String, seconds: Long) {
        require(seconds in 0..MAX_TTL)
        val c = contact(name) ?: throw UnknownContactException(name); put(c.copy(ttlSeconds = seconds)); save()
    }

    /** Remove messages whose timer has run out. Returns how many were removed. */
    @Synchronized fun purgeExpired(): Int {
        val now = clock()
        val n = st.messages.size
        dropMessages { it.expiresAt in 1..now }
        if (st.messages.size != n) save()
        return n - st.messages.size
    }

    /** Remove messages AND their encrypted attachment files (the key goes with the message record). */
    private fun dropMessages(pred: (StoredMessage) -> Boolean) {
        st.messages.filter(pred).forEach { m -> m.attachment?.let { runCatching { attachments.delete(it.id) } } }
        st.messages.removeAll(pred)
    }

    @Synchronized fun deleteChat(name: String) { dropMessages { it.group == null && it.contact == name }; save() }

    companion object {
        private const val PAYLOAD_V2: Byte = 2
        private const val MAX_TEXT = 4000
        private const val MAX_GROUP_NAME = 40
        private const val MAX_MEMBERS = 32
        private const val MAX_TTL = 30L * 24 * 3600
        private const val MAX_ATTACHMENT = 1 shl 20          // 1 MiB: bounded by relay limits (64 KiB envelopes, 60-request bursts)
        private const val CHUNK = 32 * 1024
        private const val GCM_OVERHEAD = 12 + 16
        private const val MAX_CHUNKS = (MAX_ATTACHMENT + GCM_OVERHEAD + CHUNK - 1) / CHUNK
        private const val MAX_FILENAME = 80
        private const val MAX_PENDING = 4
        private const val PENDING_MS = 60L * 60 * 1000
        private const val DROP = 0
        private const val MSG = 1
        private const val INTERNAL = 2
        private val HEX32 = Regex("^[0-9a-f]{32}$")
        private val MIME = Regex("^[a-z0-9][a-z0-9.+-]*/[a-z0-9][a-z0-9.+-]*$")
    }

    private fun newId() = ByteArray(12).also { random.nextBytes(it) }.joinToString("") { "%02x".format(it) }

    private fun decodeState(b: ByteArray): ClientState = try {
        gson.fromJson(String(b, Charsets.UTF_8), ClientState::class.java) ?: throw StoreFormatException("empty client state")
    } catch (e: JsonParseException) { throw StoreFormatException("corrupt client state") }
}
