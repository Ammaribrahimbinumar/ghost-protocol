package com.ghostprotocol.app.messaging

import android.content.Context
import com.ghostprotocol.app.security.DeviceVault
import com.ghostprotocol.app.security.KeystoreRelaySigner
import com.ghostprotocol.app.security.KeystoreSecretStore
import com.ghostprotocol.crypto.Contact
import com.ghostprotocol.crypto.Group
import com.ghostprotocol.crypto.SendReport
import com.ghostprotocol.crypto.GhostClient
import com.ghostprotocol.crypto.KeyChangedException
import com.ghostprotocol.crypto.RelayClient
import com.ghostprotocol.crypto.RelayException
import com.ghostprotocol.crypto.RequestSigner
import com.ghostprotocol.crypto.StoredMessage
import java.io.File
import java.io.IOException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

sealed interface Phase {
    data object Loading : Phase
    data object NeedsRegistration : Phase
    data object Ready : Phase
    data class Broken(val reason: String) : Phase
}

/**
 * Glue between the UI and [GhostClient]: owns the encrypted stores, runs network work off the main thread,
 * and exposes plain state. All user-visible error text is generated here from exception TYPES only, so no
 * message content, key material or server detail can end up on screen or in logs.
 *
 * Messages are fetched only while the app is open and unlocked (no push service, so no third party sees
 * delivery timing). There are no notifications yet.
 */
class AppController(
    context: Context,
    private val relayFactory: (url: String, signer: RequestSigner, mailbox: String?) -> RelayClient =
        { url, signer, mailbox -> RelayClient(url, signer, mailbox) },
    private val deviceAlias: String = DeviceVault.DEFAULT_ALIAS,
    private val prefix: String = "",
    private val signerAlias: String = KeystoreRelaySigner.ALIAS,
) {
    private val ctx = context.applicationContext
    private val vault = DeviceVault(ctx, deviceAlias, prefix + "device.state")
    private val configStore = KeystoreSecretStore(File(ctx.filesDir, prefix + "config.rec"), "ghost_config_v1$prefix")
    private val clientAlias = "ghost_client_v1$prefix"
    private val clientStore = KeystoreSecretStore(File(ctx.filesDir, prefix + "client.rec"), clientAlias)
    private val attachments = FileAttachmentStore(File(ctx.filesDir, prefix + "attachments"))
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    /** Bumped by [wipeAll]; any write from work started before the wipe is discarded. */
    @Volatile private var generation = 0

    private val _phase = MutableStateFlow<Phase>(Phase.Loading)
    val phase: StateFlow<Phase> = _phase.asStateFlow()
    private val _contacts = MutableStateFlow<List<Contact>>(emptyList())
    val contacts: StateFlow<List<Contact>> = _contacts.asStateFlow()
    private val _messages = MutableStateFlow<List<StoredMessage>>(emptyList())
    val messages: StateFlow<List<StoredMessage>> = _messages.asStateFlow()
    private val _groups = MutableStateFlow<List<Group>>(emptyList())
    val groups: StateFlow<List<Group>> = _groups.asStateFlow()
    private val _notice = MutableStateFlow<String?>(null)
    val notice: StateFlow<String?> = _notice.asStateFlow()
    private val _busy = MutableStateFlow(false)
    val busy: StateFlow<Boolean> = _busy.asStateFlow()
    private val _online = MutableStateFlow(true)
    val online: StateFlow<Boolean> = _online.asStateFlow()

    @Volatile private var client: GhostClient? = null
    @Volatile private var openChat: String? = null
    @Volatile private var openGroup: String? = null
    val username: String? get() = client?.username

    fun start() {
        scope.launch { _phase.value = try { load() } catch (e: Exception) { Phase.Broken(describeStartup(e)) } }
    }

    private fun load(): Phase {
        val cfg = configStore.read()
        if (cfg == null) return if (vault.exists()) Phase.Broken("Identity exists but its settings are missing.") else Phase.NeedsRegistration
        val j = JSONObject(String(cfg, Charsets.UTF_8))
        if (!KeystoreRelaySigner.exists(signerAlias)) return Phase.Broken("The relay signing key is missing.")
        val device = vault.load(j.getString("username"))
        val relay = relayFactory(j.getString("url"), KeystoreRelaySigner.getOrCreate(signerAlias), j.getString("mailbox"))
        val gen = generation
        client = GhostClient(device, relay, clientStore.read(), { if (gen == generation) clientStore.write(it) }, attachments = attachments)
        refresh()
        return Phase.Ready
    }

    /** Create the identity, register with the relay using an invitation, and go to Ready. Rolls back on failure. */
    fun register(url: String, invite: String, username: String) {
        scope.launch {
            _busy.value = true; _notice.value = null
            try {
                require(username.matches(Regex("^[a-z0-9_]{3,32}$"))) { "Username: 3-32 characters, a-z 0-9 _" }
                require(invite.isNotBlank()) { "Enter your invitation code" }
                val device = vault.create(username)
                try {
                    val signer = KeystoreRelaySigner.getOrCreate(signerAlias)
                    val relay = relayFactory(url.trim(), signer, null)
                    val mailbox = relay.register(
                        invite.trim(), username, signer.publicKey,
                        device.publicBundle().encode(), device.oneTimePreKeyList().map { it.encode() },
                    )
                    configStore.write(JSONObject().put("url", url.trim()).put("username", username).put("mailbox", mailbox).toString().toByteArray())
                } catch (e: Exception) {
                    vault.destroy(); vault.reset(); KeystoreRelaySigner.delete(signerAlias); throw e
                }
                _phase.value = load()
            } catch (e: Exception) {
                _notice.value = describe(e)
            } finally { _busy.value = false }
        }
    }

    suspend fun pollOnce() = withContext(Dispatchers.IO) {
        val c = client ?: return@withContext
        try {
            val r = c.poll(); c.purgeExpired(); _online.value = true
            if (r.keyChanges.isNotEmpty()) _notice.value = "Security warning: ${r.keyChanges.joinToString()} presented a different key. Open the chat to review."
        } catch (e: IOException) { _online.value = false
        } catch (e: RelayException) { _online.value = e.status !in 500..599 && e.status != 0
        } catch (e: Exception) { _notice.value = describe(e) }
        refresh()
    }

    fun addContact(name: String) = act { addContact(name.trim().lowercase()) }
    fun send(name: String, text: String) = act { send(name, text) }
    fun markVerified(name: String) = act { markVerified(name) }
    fun acceptKeyChange(name: String) = act { acceptKeyChange(name) }
    fun setDisappearing(name: String, seconds: Long) = act { setDisappearing(name, seconds) }
    fun deleteChat(name: String) = act { deleteChat(name) }
    fun sendAttachment(name: String, fileName: String, mime: String, data: ByteArray) = act { sendAttachment(name, fileName, mime, data) }
    fun attachmentBytes(ref: com.ghostprotocol.crypto.AttachmentRef): ByteArray? = try { client?.attachmentBytes(ref) } catch (e: Exception) { null }
    fun safetyNumber(name: String): String? = try { client?.safetyNumber(name) } catch (e: Exception) { null }

    /**
     * Erase everything of this profile, offline and immediately: Keystore keys first (which makes every encrypted file
     * unreadable even if a later step is interrupted), then the files. The relay account is NOT deleted (no network
     * here); it simply becomes unreachable from this phone. Afterwards the profile is a blank install.
     */
    fun wipeAll() {
        generation++
        scope.coroutineContext[kotlinx.coroutines.Job]?.children?.forEach { it.cancel() }
        client = null; openChat = null; openGroup = null
        runCatching {
            val ks = java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            listOf(deviceAlias, "ghost_config_v1$prefix", clientAlias, signerAlias).forEach { if (ks.containsAlias(it)) ks.deleteEntry(it) }
        }
        vault.destroy(); vault.reset()
        listOf("config.rec", "client.rec").forEach { File(ctx.filesDir, prefix + it).delete() }
        attachments.deleteAll()
        _contacts.value = emptyList(); _groups.value = emptyList(); _messages.value = emptyList(); _notice.value = null; _busy.value = false
        _phase.value = Phase.NeedsRegistration
    }

    fun open(name: String?) { openChat = name; openGroup = null; refresh() }
    fun openGroupChat(id: String?) { openGroup = id; openChat = null; refresh() }

    fun createGroup(name: String, members: List<String>) = actR { createGroup(name, members).second }
    fun sendGroup(id: String, text: String) = actR { sendGroup(id, text) }
    fun addToGroup(id: String, member: String) = actR { updateGroup(id, add = listOf(member.trim().lowercase())) }
    fun removeFromGroup(id: String, member: String) = actR { updateGroup(id, remove = listOf(member)) }
    fun leaveGroup(id: String) = actR { leaveGroup(id) }
    fun setGroupDisappearing(id: String, seconds: Long) = act { setGroupDisappearing(id, seconds) }
    fun broadcast(names: List<String>, text: String) = actR { broadcast(names, text) }

    /** Reads the chosen file (max 1 MiB + 1 byte, so oversize is detected without loading it all) and sends it. */
    fun sendAttachmentUri(name: String, uri: android.net.Uri) {
        scope.launch {
            _busy.value = true
            try {
                val cr = ctx.contentResolver
                val mime = (cr.getType(uri) ?: "application/octet-stream").lowercase().takeIf { it.matches(Regex("^[a-z0-9][a-z0-9.+-]*/[a-z0-9][a-z0-9.+-]*$")) } ?: "application/octet-stream"
                val label = cr.query(uri, arrayOf(android.provider.OpenableColumns.DISPLAY_NAME), null, null, null)?.use { if (it.moveToFirst()) it.getString(0) else null } ?: "file"
                val data = cr.openInputStream(uri)?.use { it.readNBytes((1 shl 20) + 1) } ?: throw IllegalArgumentException("Cannot read that file.")
                require(data.size <= (1 shl 20)) { "Files up to 1 MiB are supported." }
                client?.sendAttachment(name, label, mime, data)
            } catch (e: Exception) { _notice.value = describe(e) } finally { _busy.value = false }
            refresh()
        }
    }
    fun dismissNotice() { _notice.value = null }

    /** Called on lock: nothing readable stays in UI state. (Keys remain in process memory; see SECURITY_LIMITATIONS.) */
    fun lock() { openChat = null; openGroup = null; _messages.value = emptyList(); _notice.value = null }

    private fun act(block: GhostClient.() -> Unit) {
        scope.launch {
            _busy.value = true
            try { client?.block() } catch (e: Exception) { _notice.value = describe(e) } finally { _busy.value = false }
            refresh()
        }
    }

    private fun actR(block: GhostClient.() -> SendReport?) {
        scope.launch {
            _busy.value = true
            try {
                val r = client?.block()
                if (r != null && r.failed.isNotEmpty()) _notice.value = "Not delivered to: " + r.failed.entries.joinToString { "${it.key} (${it.value})" }
            } catch (e: Exception) { _notice.value = describe(e) } finally { _busy.value = false }
            refresh()
        }
    }

    private fun refresh() {
        val c = client ?: return
        _contacts.value = c.contacts().sortedBy { it.name }
        _groups.value = c.groups().sortedBy { it.name }
        _messages.value = openGroup?.let { c.groupMessages(it) } ?: openChat?.let { c.messages(it) } ?: emptyList()
    }

    private fun describe(e: Exception): String = when (e) {
        is KeyChangedException -> "Security warning: ${e.contact}'s key changed. Compare safety numbers before trusting it."
        is RelayException -> when (e.status) {
            404 -> "No such user on this relay."
            401, 403 -> "The relay refused this request (invalid or used invitation, or username taken)."
            409 -> "That username is already taken."
            429 -> "Too many requests. Wait a minute."
            else -> "The relay returned an error (${e.status})."
        }
        is IOException -> "Cannot reach the relay. Check the address and your connection."
        is IllegalArgumentException, is IllegalStateException -> e.message ?: "Invalid input."
        else -> "Something went wrong."
    }

    private fun describeStartup(e: Exception) = when (e) {
        is com.ghostprotocol.app.security.StoreCorruptedException, is com.ghostprotocol.crypto.StoreFormatException ->
            "Local data could not be verified. It is not reset automatically."
        else -> "Could not start."
    }
}
