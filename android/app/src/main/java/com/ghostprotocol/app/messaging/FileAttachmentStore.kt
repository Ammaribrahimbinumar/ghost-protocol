package com.ghostprotocol.app.messaging

import android.util.AtomicFile
import com.ghostprotocol.crypto.AttachmentStore
import java.io.File

/**
 * Keeps attachment files in app-private storage. The bytes are already AES-256-GCM ciphertext (the key lives only in
 * the Keystore-encrypted client state), so deleting a message's record also makes any leftover file unreadable.
 * Ids are 32 hex characters; anything else is refused so a crafted id can never point outside [dir].
 */
class FileAttachmentStore(private val dir: File) : AttachmentStore {
    private val ok = Regex("^[0-9a-f]{32}$")
    private fun file(id: String): File { require(ok.matches(id)) { "bad attachment id" }; return File(dir, id) }

    override fun put(id: String, data: ByteArray) {
        dir.mkdirs()
        val af = AtomicFile(file(id))
        val out = af.startWrite()
        try { out.write(data); af.finishWrite(out) } catch (e: Exception) { af.failWrite(out); throw e }
    }
    override fun get(id: String): ByteArray? = file(id).takeIf { it.exists() }?.let { AtomicFile(it).readFully() }
    override fun delete(id: String) { file(id).delete() }
    fun deleteAll() { dir.listFiles()?.forEach { it.delete() }; dir.delete() }
}
