package com.ghostprotocol.crypto

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.kem.KEMPublicKey
import org.signal.libsignal.protocol.state.PreKeyBundle

class OneTimePreKey(val id: Int, val publicKey: ByteArray) {
    /** 4-byte big-endian id + serialized public key. Stored by the relay as an opaque blob. */
    fun encode(): ByteArray = java.nio.ByteBuffer.allocate(4 + publicKey.size).putInt(id).put(publicKey).array()

    companion object {
        fun decode(data: ByteArray): OneTimePreKey {
            if (data.size <= 4 || data.size > 4 + 4096) throw BundleFormatException("bad one-time prekey")
            val buf = java.nio.ByteBuffer.wrap(data)
            return OneTimePreKey(buf.int, data.copyOfRange(4, data.size))
        }
    }
}

/** Thrown when a bundle from the relay is malformed. Treat as hostile input. */
class BundleFormatException(message: String) : Exception(message)

/**
 * The public, long-term part of a prekey bundle. This is what the relay stores as an opaque blob.
 * Its signatures are checked by libsignal when a session is built, so a relay that swaps keys is
 * detected only if the identity key is verified out of band (safety numbers).
 */
class PublicBundle(
    val registrationId: Int,
    val deviceId: Int,
    val identityKey: ByteArray,
    val signedPreKeyId: Int,
    val signedPreKey: ByteArray,
    val signedPreKeySignature: ByteArray,
    val kyberPreKeyId: Int,
    val kyberPreKey: ByteArray,
    val kyberPreKeySignature: ByteArray,
) {
    fun encode(): ByteArray {
        val out = ByteArrayOutputStream()
        DataOutputStream(out).use {
            it.writeByte(VERSION)
            it.writeInt(registrationId)
            it.writeInt(deviceId)
            it.writeInt(signedPreKeyId); writeBytes(it, signedPreKey); writeBytes(it, signedPreKeySignature)
            it.writeInt(kyberPreKeyId); writeBytes(it, kyberPreKey); writeBytes(it, kyberPreKeySignature)
            writeBytes(it, identityKey)
        }
        return out.toByteArray()
    }

    /** Builds the libsignal bundle used to start a session. [oneTime] may be null if the relay had none left. */
    fun toPreKeyBundle(oneTime: OneTimePreKey?): PreKeyBundle = try {
        PreKeyBundle(
            registrationId, deviceId,
            oneTime?.id ?: PreKeyBundle.NULL_PRE_KEY_ID,
            oneTime?.let { ECPublicKey(it.publicKey) },
            signedPreKeyId, ECPublicKey(signedPreKey), signedPreKeySignature,
            IdentityKey(ECPublicKey(identityKey)),
            kyberPreKeyId, KEMPublicKey(kyberPreKey), kyberPreKeySignature,
        )
    } catch (e: Exception) {
        throw BundleFormatException("invalid key material")
    }

    companion object {
        private const val VERSION = 1
        private const val MAX_FIELD = 4096

        private fun writeBytes(o: DataOutputStream, b: ByteArray) {
            o.writeShort(b.size); o.write(b)
        }

        private fun readBytes(i: DataInputStream): ByteArray {
            val n = i.readUnsignedShort()
            if (n > MAX_FIELD) throw BundleFormatException("field too large")
            return ByteArray(n).also { i.readFully(it) }
        }

        fun decode(data: ByteArray): PublicBundle = try {
            DataInputStream(ByteArrayInputStream(data)).use {
                if (it.readUnsignedByte() != VERSION) throw BundleFormatException("unknown version")
                val reg = it.readInt()
                val dev = it.readInt()
                val sId = it.readInt(); val sKey = readBytes(it); val sSig = readBytes(it)
                val kId = it.readInt(); val kKey = readBytes(it); val kSig = readBytes(it)
                val ident = readBytes(it)
                if (it.available() != 0) throw BundleFormatException("trailing data")
                PublicBundle(reg, dev, ident, sId, sKey, sSig, kId, kKey, kSig)
            }
        } catch (e: BundleFormatException) {
            throw e
        } catch (e: Exception) {
            throw BundleFormatException("malformed bundle")
        }
    }
}
