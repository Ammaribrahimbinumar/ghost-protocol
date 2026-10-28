package com.ghostprotocol.app.security

import android.content.Context
import com.ghostprotocol.crypto.LocalDevice
import com.ghostprotocol.crypto.StoreFormatException
import java.io.File
import java.security.KeyStore

/**
 * Owns this phone's Signal identity and sessions. All state is written, after every change, through
 * [KeystoreSecretStore]: AES-256-GCM under a non-exportable Android Keystore key, in app-private storage
 * that is excluded from backups. A missing or damaged file is reported, never silently replaced by a new
 * identity (that would look to contacts like a stolen or reinstalled account).
 */
class DeviceVault(context: Context, private val alias: String = DEFAULT_ALIAS, fileName: String = "device.state") {
    private val file = File(context.filesDir, fileName)
    private val store: SecretStore = KeystoreSecretStore(file, alias)

    fun exists(): Boolean = store.read() != null

    /** Allow writes again after a wipe, so a fresh identity can be created. */
    fun reset() { destroyed = false }

    /** Creates a brand-new identity. Refuses if one already exists, so it can never overwrite a real one. */
    fun create(username: String): LocalDevice {
        check(store.read() == null) { "a device identity already exists" }
        return LocalDevice.create(username, onChange = { if (!destroyed) store.write(it) })
    }

    /** Loads the existing identity. Throws [StoreCorruptedException]/[StoreFormatException] if it cannot be trusted. */
    fun load(username: String): LocalDevice {
        val snap = store.read() ?: throw StoreCorruptedException("no device state")
        return LocalDevice.restore(username, snap, onChange = { if (!destroyed) store.write(it) })
    }

    /** Deletes the identity file and its Keystore key. Only for rolling back a failed registration. */
    @Volatile private var destroyed = false

    fun destroy() {
        destroyed = true                         // late writes from in-flight work must not recreate state
        file.delete()
        runCatching { KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(alias) }
    }

    companion object { const val DEFAULT_ALIAS = "ghost_device_state_key" }
}
