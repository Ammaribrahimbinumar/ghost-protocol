package com.ghostprotocol.app.security

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.AtomicFile
import java.io.File
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Stores a small blob in app-private storage, encrypted with a non-exportable AES-256-GCM key
 * held in Android Keystore (StrongBox when the device has it, otherwise the TEE/software-backed
 * Keystore). The key never leaves the Keystore; only ciphertext touches the filesystem.
 *
 * If the Keystore key is gone or the file does not authenticate, [read] throws
 * [StoreCorruptedException] instead of pretending nothing is configured. Silently resetting would
 * let a corrupted or tampered state look like a fresh install.
 *
 * NOT COMPILED OR RUN. Keystore behaviour varies by device and must be verified on hardware.
 */
class KeystoreSecretStore(
    private val file: File,
    private val alias: String,
) : SecretStore {

    private val atomicFile = AtomicFile(file)

    override fun read(): ByteArray? {
        if (!file.exists()) return null
        try {
            val raw = atomicFile.readFully()
            if (raw.size < 2) throw StoreCorruptedException("file too short")
            val ivLen = raw[0].toInt() and 0xFF
            if (ivLen != 12 || raw.size <= 1 + ivLen) throw StoreCorruptedException("bad header")
            val iv = raw.copyOfRange(1, 1 + ivLen)
            val ct = raw.copyOfRange(1 + ivLen, raw.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, iv))
            return cipher.doFinal(ct)
        } catch (e: GeneralSecurityException) {
            throw StoreCorruptedException("record did not authenticate")
        } catch (e: IOException) {
            throw StoreCorruptedException("record unreadable")
        }
    }

    override fun write(data: ByteArray) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key()) // Keystore generates a fresh random IV
        val iv = cipher.iv
        val ct = cipher.doFinal(data)
        val stream = atomicFile.startWrite()
        try {
            stream.write(byteArrayOf(iv.size.toByte()))
            stream.write(iv)
            stream.write(ct)
            atomicFile.finishWrite(stream)
        } catch (e: IOException) {
            atomicFile.failWrite(stream)
            throw e
        }
    }

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(alias, null) as? SecretKey)?.let { return it }
        if (file.exists()) {
            // Ciphertext exists but its key does not: do not mint a new key and pretend all is well.
            throw StoreCorruptedException("wrapping key missing")
        }
        return generate(strongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
    }

    private fun generate(strongBox: Boolean): SecretKey {
        val spec = KeyGenParameterSpec.Builder(
            alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
            .apply {
                if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) setIsStrongBoxBacked(true)
            }
            .build()
        return try {
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
                .apply { init(spec) }.generateKey()
        } catch (e: StrongBoxUnavailableException) {
            generate(strongBox = false)
        }
    }
}
