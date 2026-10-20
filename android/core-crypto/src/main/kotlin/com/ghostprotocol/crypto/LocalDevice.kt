package com.ghostprotocol.crypto

import java.security.SecureRandom
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.ecc.ECKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyPair
import org.signal.libsignal.protocol.kem.KEMKeyType
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.state.PreKeyRecord
import org.signal.libsignal.protocol.state.SignedPreKeyRecord
import org.signal.libsignal.protocol.state.impl.InMemorySignalProtocolStore

/**
 * One device's cryptographic identity and key stores.
 *
 * All key generation, signing, session setup and encryption are delegated to libsignal
 * (Signal protocol: PQXDH + Double Ratchet). This class only wires those calls together.
 *
 * STORAGE LIMIT: the store is in memory only. Persisting it in an encrypted database wrapped by
 * an Android Keystore key is Phase 4. Until then, nothing here survives a process restart.
 */
class LocalDevice private constructor(
    val name: String,
    val deviceId: Int,
    internal val store: InMemorySignalProtocolStore,
    private val signedPreKey: SignedPreKeyRecord,
    private val kyberPreKey: KyberPreKeyRecord,
    private val oneTimePreKeys: List<PreKeyRecord>,
) {
    val address: SignalProtocolAddress = SignalProtocolAddress(name, deviceId)
    val identityKey: IdentityKey get() = store.identityKeyPair.publicKey
    val registrationId: Int get() = store.localRegistrationId

    /** Long-term public data other users need. Safe to upload to the relay. */
    fun publicBundle(): PublicBundle = PublicBundle(
        registrationId = registrationId,
        deviceId = deviceId,
        identityKey = identityKey.serialize(),
        signedPreKeyId = signedPreKey.id,
        signedPreKey = signedPreKey.keyPair.publicKey.serialize(),
        signedPreKeySignature = signedPreKey.signature,
        kyberPreKeyId = kyberPreKey.id,
        kyberPreKey = kyberPreKey.keyPair.publicKey.serialize(),
        kyberPreKeySignature = kyberPreKey.signature,
    )

    /** Public halves of the one-time prekeys, for upload to the relay (relay hands out one per fetch). */
    fun oneTimePreKeyList(): List<OneTimePreKey> =
        oneTimePreKeys.map { OneTimePreKey(it.id, it.keyPair.publicKey.serialize()) }

    companion object {
        private val random = SecureRandom()

        fun create(name: String, deviceId: Int = 1, oneTimePreKeyCount: Int = 20): LocalDevice {
            require(name.isNotEmpty() && oneTimePreKeyCount in 0..100)
            val identity = IdentityKeyPair.generate()
            val registrationId = random.nextInt(16380) + 1
            val store = InMemorySignalProtocolStore(identity, registrationId)
            val now = System.currentTimeMillis()

            val signedPair = ECKeyPair.generate()
            val signed = SignedPreKeyRecord(
                1, now, signedPair,
                identity.privateKey.calculateSignature(signedPair.publicKey.serialize()),
            )
            val kyberPair = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
            val kyber = KyberPreKeyRecord(
                1, now, kyberPair,
                identity.privateKey.calculateSignature(kyberPair.publicKey.serialize()),
            )
            val oneTime = (1..oneTimePreKeyCount).map { PreKeyRecord(it, ECKeyPair.generate()) }

            store.storeSignedPreKey(signed.id, signed)
            store.storeKyberPreKey(kyber.id, kyber)
            oneTime.forEach { store.storePreKey(it.id, it) }
            return LocalDevice(name, deviceId, store, signed, kyber, oneTime)
        }
    }
}
