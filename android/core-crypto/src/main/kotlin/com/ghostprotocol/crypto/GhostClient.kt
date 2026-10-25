package com.ghostprotocol.crypto

import com.google.gson.Gson
import com.google.gson.JsonParseException
import java.security.SecureRandom
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

data class StoredMessage(
    val id: String, val contact: String, val outgoing: Boolean, val text: String,
    val timestamp: Long, val expiresAt: Long = 0,
)

data class PollResult(val received: Int, val dropped: Int, val keyChanges: List<String>)

private class ClientState(
    var contacts: MutableList<Contact> = mutableListOf(),
    var messages: MutableList<StoredMessage> = mutableListOf(),
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
) {
    private val gson = Gson()
    private val messenger = Messenger(device)
    private val st: ClientState = state?.let { decodeState(it) } ?: ClientState()
    private val random = SecureRandom()

    val username: String get() = device.name

    @Synchronized fun contacts(): List<Contact> = st.contacts.toList()
    @Synchronized fun messages(contact: String): List<StoredMessage> =
        st.messages.filter { it.contact == contact }.sortedBy { it.timestamp }

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

    @Synchronized fun send(name: String, text: String): StoredMessage {
        val c = contact(name) ?: throw UnknownContactException(name)
        require(text.isNotEmpty() && text.length <= 4000) { "message length" }
        val envelope = messenger.encrypt(addr(name), text.toByteArray(Charsets.UTF_8))
        relay.send(c.mailboxId, Packet.encode(username, envelope))
        val now = clock()
        val m = StoredMessage(newId(), name, true, text, now, if (c.ttlSeconds > 0) now + c.ttlSeconds * 1000 else 0)
        st.messages.add(m); save()
        return m
    }

    /** Fetch, decrypt and store new messages. */
    @Synchronized fun poll(): PollResult {
        val toAck = mutableListOf<String>()
        var received = 0; var dropped = 0
        val changes = linkedSetOf<String>()
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
                    // First message from someone new: learn their mailbox so we can reply, and confirm the
                    // identity on the relay's bundle matches the one libsignal just pinned from the message.
                    val f = relay.fetchBundle(sender)
                    val relayIdentity = IdentityKey(org.signal.libsignal.protocol.ecc.ECPublicKey(PublicBundle.decode(f.bundle).identityKey))
                    val pinned = device.store.getIdentity(addr(sender))
                    put(Contact(sender, f.mailboxId, keyChanged = pinned != null && pinned != relayIdentity))
                    if (pinned != null && pinned != relayIdentity) changes += sender
                }
                val now = clock()
                val ttl = contact(sender)?.ttlSeconds ?: 0
                st.messages.add(StoredMessage(newId(), sender, false, String(plain, Charsets.UTF_8), now, if (ttl > 0) now + ttl * 1000 else 0))
                received++; toAck += d.id
            } catch (e: java.io.IOException) {
                throw e // transient: leave unacked, retry later
            } catch (e: RelayException) {
                throw e
            } catch (e: Exception) {
                dropped++; toAck += d.id // deterministic failure (tamper, replay, malformed): drop
            }
        }
        save()
        if (toAck.isNotEmpty()) relay.ack(toAck)
        return PollResult(received, dropped, changes.toList())
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
        require(seconds in 0..30L * 24 * 3600)
        val c = contact(name) ?: throw UnknownContactException(name); put(c.copy(ttlSeconds = seconds)); save()
    }

    /** Remove messages whose timer has run out. Returns how many were removed. */
    @Synchronized fun purgeExpired(): Int {
        val now = clock()
        val n = st.messages.size
        st.messages.removeAll { it.expiresAt in 1..now }
        if (st.messages.size != n) save()
        return n - st.messages.size
    }

    @Synchronized fun deleteChat(name: String) { st.messages.removeAll { it.contact == name }; save() }

    private fun newId() = ByteArray(12).also { random.nextBytes(it) }.joinToString("") { "%02x".format(it) }

    private fun decodeState(b: ByteArray): ClientState = try {
        gson.fromJson(String(b, Charsets.UTF_8), ClientState::class.java) ?: throw StoreFormatException("empty client state")
    } catch (e: JsonParseException) { throw StoreFormatException("corrupt client state") }
}
