package com.ghostprotocol.crypto

import org.signal.libsignal.protocol.SessionBuilder
import org.signal.libsignal.protocol.SessionCipher
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.fingerprint.Fingerprint
import org.signal.libsignal.protocol.fingerprint.NumericFingerprintGenerator
import org.signal.libsignal.protocol.message.CiphertextMessage
import org.signal.libsignal.protocol.message.PreKeySignalMessage
import org.signal.libsignal.protocol.message.SignalMessage
import org.signal.libsignal.protocol.state.PreKeyBundle

/** Ciphertext handed to the relay: 1 type byte + libsignal's serialized message. Opaque to the relay. */
class Envelope(val bytes: ByteArray) {
    val isPreKeyMessage: Boolean get() = bytes.isNotEmpty() && bytes[0].toInt() == CiphertextMessage.PREKEY_TYPE
}

/**
 * One-to-one encryption between this device and remote devices.
 *
 * Errors from libsignal (tampering, replay, untrusted identity change, no session) propagate as
 * exceptions on purpose: the caller must surface them, never swallow or auto-trust.
 */
class Messenger(private val device: LocalDevice) {

    /** Start a session from the peer's bundle. Throws UntrustedIdentityException if the stored identity differs. */
    fun startSession(remote: SignalProtocolAddress, bundle: PreKeyBundle) {
        SessionBuilder(device.store, remote).process(bundle)
    }

    fun encrypt(remote: SignalProtocolAddress, plaintext: ByteArray): Envelope {
        val msg = SessionCipher(device.store, remote).encrypt(plaintext)
        return Envelope(byteArrayOf(msg.type.toByte()) + msg.serialize())
    }

    fun decrypt(remote: SignalProtocolAddress, envelope: Envelope): ByteArray {
        require(envelope.bytes.size > 1) { "empty envelope" }
        val body = envelope.bytes.copyOfRange(1, envelope.bytes.size)
        val cipher = SessionCipher(device.store, remote)
        return when (envelope.bytes[0].toInt()) {
            CiphertextMessage.PREKEY_TYPE -> cipher.decrypt(PreKeySignalMessage(body))
            CiphertextMessage.WHISPER_TYPE -> cipher.decrypt(SignalMessage(body))
            else -> throw IllegalArgumentException("unknown message type")
        }
    }
}

/** Safety numbers: both users compare this out of band to detect a man in the middle. */
object SafetyNumber {
    fun compute(local: LocalDevice, remoteName: String, remoteIdentity: org.signal.libsignal.protocol.IdentityKey): Fingerprint =
        NumericFingerprintGenerator(5200).createFor(
            2,
            local.name.toByteArray(Charsets.UTF_8), local.identityKey,
            remoteName.toByteArray(Charsets.UTF_8), remoteIdentity,
        )
}
