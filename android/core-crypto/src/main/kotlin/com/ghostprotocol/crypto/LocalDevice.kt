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

/**
 * One device's cryptographic identity and key stores.
 *
 * All key generation, signing, session setup and encryption are delegated to libsignal
 * (Signal protocol: PQXDH + Double Ratchet). This class only wires those calls together.
 *
 * PERSISTENCE: state lives in a [PersistentSignalStore]; pass `onChange` to receive an up-to-date
 * snapshot after every change and write it ONLY to encrypted storage. [restore] reloads it.
 */
class LocalDevice private constructor(
    val name: String,
    val deviceId: Int,
    internal val store: PersistentSignalStore,
) {
    private val signedPreKey: SignedPreKeyRecord get() = store.loadSignedPreKey(1)
    private val kyberPreKey: KyberPreKeyRecord get() = store.loadKyberPreKey(1)
    private val oneTimePreKeys: List<PreKeyRecord> get() = store.allPreKeys()

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

        fun create(name: String, deviceId: Int = 1, oneTimePreKeyCount: Int = 20, onChange: (ByteArray) -> Unit = {}): LocalDevice {
            require(name.isNotEmpty() && oneTimePreKeyCount in 0..100)
            val identity = IdentityKeyPair.generate()
            val registrationId = random.nextInt(16380) + 1
            var sink: (ByteArray) -> Unit = {}          // silent while generating, then one write
            val store = PersistentSignalStore.create(identity, registrationId) { sink(it) }
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
            store.storeSignedPreKey(signed.id, signed)
            store.storeKyberPreKey(kyber.id, kyber)
            (1..oneTimePreKeyCount).forEach { store.storePreKey(it, PreKeyRecord(it, ECKeyPair.generate())) }
            sink = onChange
            onChange(store.snapshot())
            return LocalDevice(name, deviceId, store)
        }

        /** Reload a device from a snapshot produced via `onChange`. Throws [StoreFormatException] on any damage. */
        fun restore(name: String, snapshot: ByteArray, deviceId: Int = 1, onChange: (ByteArray) -> Unit = {}): LocalDevice {
            val store = PersistentSignalStore.restore(snapshot, onChange)
            if (!store.containsSignedPreKey(1) || !store.containsKyberPreKey(1)) throw StoreFormatException("missing prekeys")
            return LocalDevice(name, deviceId, store)
        }
    }
}
