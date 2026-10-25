package com.ghostprotocol.crypto

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.util.UUID
import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.libsignal.protocol.InvalidKeyIdException
import org.signal.libsignal.protocol.NoSessionException
import org.signal.libsignal.protocol.ReusedBaseKeyException
import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.groups.state.SenderKeyRecord
import org.signal.libsignal.protocol.state.IdentityKeyStore
import org.signal.libsignal.protocol.state.KyberPreKeyRecord
import org.signal.libsignal.protocol.state.PreKeyRecord
import org.signal.libsignal.protocol.state.SessionRecord
import org.signal.libsignal.protocol.state.SignalProtocolStore
import org.signal.libsignal.protocol.state.SignedPreKeyRecord

class StoreFormatException(msg: String) : Exception(msg)

/**
 * libsignal protocol store whose whole state can be serialized. Every mutation calls [onChange] with a
 * fresh snapshot so the host (the Android app) can write it to encrypted storage.
 *
 * SECURITY: a snapshot is raw private key material and session state. It must only ever be written
 * through an encrypting store keyed by a non-exportable key (Android Keystore on the device). This class
 * does no encryption itself and never logs.
 *
 * Trust model is trust-on-first-use: the first identity seen for an address is pinned; a different one is
 * refused (libsignal then raises UntrustedIdentityException) until the caller explicitly replaces it.
 */
class PersistentSignalStore private constructor(
    private val identity: IdentityKeyPair,
    private val registrationId: Int,
    private val onChange: (ByteArray) -> Unit,
) : SignalProtocolStore {

    private val preKeys = sortedMapOf<Int, PreKeyRecord>()
    private val signedPreKeys = sortedMapOf<Int, SignedPreKeyRecord>()
    private val kyberPreKeys = sortedMapOf<Int, KyberPreKeyRecord>()
    private val usedKyberBaseKeys = linkedSetOf<String>()
    private val sessions = linkedMapOf<String, SessionRecord>()
    private val identities = linkedMapOf<String, IdentityKey>()
    private val senderKeys = linkedMapOf<String, SenderKeyRecord>()

    private fun key(a: SignalProtocolAddress) = "${a.name}\u0000${a.deviceId}"
    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    private fun changed() = onChange(snapshot())

    // ---- identity ----
    @Synchronized override fun getIdentityKeyPair(): IdentityKeyPair = identity
    @Synchronized override fun getLocalRegistrationId(): Int = registrationId

    @Synchronized override fun saveIdentity(address: SignalProtocolAddress, identityKey: IdentityKey): IdentityKeyStore.IdentityChange {
        val old = identities[key(address)]
        identities[key(address)] = identityKey
        changed()
        return if (old == null || old == identityKey) IdentityKeyStore.IdentityChange.NEW_OR_UNCHANGED
        else IdentityKeyStore.IdentityChange.REPLACED_EXISTING
    }

    @Synchronized override fun isTrustedIdentity(address: SignalProtocolAddress, identityKey: IdentityKey, direction: IdentityKeyStore.Direction): Boolean {
        val known = identities[key(address)] ?: return true // first use: trust and pin
        return known == identityKey
    }

    @Synchronized override fun getIdentity(address: SignalProtocolAddress): IdentityKey? = identities[key(address)]

    /** Explicit user decision after a key-change warning: forget the pinned identity and session for [address]. */
    @Synchronized fun forgetContact(address: SignalProtocolAddress) {
        identities.remove(key(address)); sessions.remove(key(address)); changed()
    }

    // ---- one-time prekeys ----
    @Synchronized override fun loadPreKey(id: Int): PreKeyRecord = preKeys[id] ?: throw InvalidKeyIdException("no prekey $id")
    @Synchronized override fun storePreKey(id: Int, record: PreKeyRecord) { preKeys[id] = record; changed() }
    @Synchronized override fun containsPreKey(id: Int) = preKeys.containsKey(id)
    @Synchronized override fun removePreKey(id: Int) { if (preKeys.remove(id) != null) changed() }
    @Synchronized fun allPreKeys(): List<PreKeyRecord> = preKeys.values.toList()

    // ---- signed prekeys ----
    @Synchronized override fun loadSignedPreKey(id: Int): SignedPreKeyRecord = signedPreKeys[id] ?: throw InvalidKeyIdException("no signed prekey $id")
    @Synchronized override fun loadSignedPreKeys(): List<SignedPreKeyRecord> = signedPreKeys.values.toList()
    @Synchronized override fun storeSignedPreKey(id: Int, record: SignedPreKeyRecord) { signedPreKeys[id] = record; changed() }
    @Synchronized override fun containsSignedPreKey(id: Int) = signedPreKeys.containsKey(id)
    @Synchronized override fun removeSignedPreKey(id: Int) { if (signedPreKeys.remove(id) != null) changed() }

    // ---- post-quantum (Kyber) prekeys ----
    @Synchronized override fun loadKyberPreKey(id: Int): KyberPreKeyRecord = kyberPreKeys[id] ?: throw InvalidKeyIdException("no kyber prekey $id")
    @Synchronized override fun loadKyberPreKeys(): List<KyberPreKeyRecord> = kyberPreKeys.values.toList()
    @Synchronized override fun storeKyberPreKey(id: Int, record: KyberPreKeyRecord) { kyberPreKeys[id] = record; changed() }
    @Synchronized override fun containsKyberPreKey(id: Int) = kyberPreKeys.containsKey(id)

    /** The Kyber prekey is reusable ("last resort"), so reuse is only safe with a fresh base key: refuse replays. */
    @Synchronized override fun markKyberPreKeyUsed(kyberId: Int, signedId: Int, baseKey: ECPublicKey) {
        val tag = "$kyberId:$signedId:${hex(baseKey.serialize())}"
        if (!usedKyberBaseKeys.add(tag)) throw ReusedBaseKeyException()
        changed()
    }

    // ---- sessions ----
    @Synchronized override fun loadSession(address: SignalProtocolAddress): SessionRecord =
        sessions[key(address)]?.let { SessionRecord(it.serialize()) } ?: SessionRecord()

    @Synchronized override fun loadExistingSessions(addresses: List<SignalProtocolAddress>): List<SessionRecord> =
        addresses.map { a -> sessions[key(a)]?.let { SessionRecord(it.serialize()) } ?: throw NoSessionException("no session for ${a.name}") }

    @Synchronized override fun getSubDeviceSessions(name: String): List<Int> =
        sessions.keys.map { it.split('\u0000') }.filter { it[0] == name && it[1].toInt() != 1 }.map { it[1].toInt() }

    @Synchronized override fun storeSession(address: SignalProtocolAddress, record: SessionRecord) {
        sessions[key(address)] = SessionRecord(record.serialize()); changed()
    }
    @Synchronized override fun containsSession(address: SignalProtocolAddress): Boolean =
        sessions[key(address)]?.let { it.hasSenderChain() } ?: false
    @Synchronized override fun deleteSession(address: SignalProtocolAddress) { if (sessions.remove(key(address)) != null) changed() }
    @Synchronized override fun deleteAllSessions(name: String) {
        if (sessions.keys.removeAll { it.substringBefore('\u0000') == name }) changed()
    }

    // ---- sender keys (groups; stored now, used later) ----
    @Synchronized override fun storeSenderKey(sender: SignalProtocolAddress, distributionId: UUID, record: SenderKeyRecord) {
        senderKeys["${key(sender)}\u0000$distributionId"] = SenderKeyRecord(record.serialize()); changed()
    }
    @Synchronized override fun loadSenderKey(sender: SignalProtocolAddress, distributionId: UUID): SenderKeyRecord? =
        senderKeys["${key(sender)}\u0000$distributionId"]?.let { SenderKeyRecord(it.serialize()) }

    // ---- snapshot ----
    @Synchronized fun snapshot(): ByteArray {
        val bos = ByteArrayOutputStream()
        DataOutputStream(bos).use { o ->
            o.writeInt(MAGIC); o.writeByte(VERSION)
            blob(o, identity.serialize()); o.writeInt(registrationId)
            records(o, preKeys.entries.map { it.key to it.value.serialize() })
            records(o, signedPreKeys.entries.map { it.key to it.value.serialize() })
            records(o, kyberPreKeys.entries.map { it.key to it.value.serialize() })
            o.writeInt(usedKyberBaseKeys.size); usedKyberBaseKeys.forEach { o.writeUTF(it) }
            o.writeInt(sessions.size); sessions.forEach { (k, v) -> o.writeUTF(k); blob(o, v.serialize()) }
            o.writeInt(identities.size); identities.forEach { (k, v) -> o.writeUTF(k); blob(o, v.serialize()) }
            o.writeInt(senderKeys.size); senderKeys.forEach { (k, v) -> o.writeUTF(k); blob(o, v.serialize()) }
        }
        return bos.toByteArray()
    }

    companion object {
        private const val MAGIC = 0x47505331 // "GPS1"
        private const val VERSION = 1
        private const val MAX_BLOB = 8 * 1024 * 1024

        private fun blob(o: DataOutputStream, b: ByteArray) { o.writeInt(b.size); o.write(b) }
        private fun records(o: DataOutputStream, r: List<Pair<Int, ByteArray>>) {
            o.writeInt(r.size); r.forEach { (id, b) -> o.writeInt(id); blob(o, b) }
        }
        private fun readBlob(i: DataInputStream): ByteArray {
            val n = i.readInt()
            if (n < 0 || n > MAX_BLOB) throw StoreFormatException("bad length")
            return ByteArray(n).also { i.readFully(it) }
        }
        private fun count(i: DataInputStream): Int = i.readInt().also { if (it < 0 || it > 100_000) throw StoreFormatException("bad count") }

        fun create(identity: IdentityKeyPair, registrationId: Int, onChange: (ByteArray) -> Unit) =
            PersistentSignalStore(identity, registrationId, onChange)

        /** Rebuilds a store from [snapshot]. Any malformed input raises [StoreFormatException]; nothing is guessed. */
        fun restore(snapshot: ByteArray, onChange: (ByteArray) -> Unit): PersistentSignalStore {
            try {
                DataInputStream(ByteArrayInputStream(snapshot)).use { i ->
                    if (i.readInt() != MAGIC) throw StoreFormatException("not a Ghost_Protocol store")
                    if (i.readUnsignedByte() != VERSION) throw StoreFormatException("unsupported store version")
                    val s = PersistentSignalStore(IdentityKeyPair(readBlob(i)), i.readInt(), onChange)
                    repeat(count(i)) { val id = i.readInt(); s.preKeys[id] = PreKeyRecord(readBlob(i)) }
                    repeat(count(i)) { val id = i.readInt(); s.signedPreKeys[id] = SignedPreKeyRecord(readBlob(i)) }
                    repeat(count(i)) { val id = i.readInt(); s.kyberPreKeys[id] = KyberPreKeyRecord(readBlob(i)) }
                    repeat(count(i)) { s.usedKyberBaseKeys.add(i.readUTF()) }
                    repeat(count(i)) { val k = i.readUTF(); s.sessions[k] = SessionRecord(readBlob(i)) }
                    repeat(count(i)) { val k = i.readUTF(); s.identities[k] = IdentityKey(readBlob(i)) }
                    repeat(count(i)) { val k = i.readUTF(); s.senderKeys[k] = SenderKeyRecord(readBlob(i)) }
                    if (i.available() != 0) throw StoreFormatException("trailing bytes")
                    return s
                }
            } catch (e: StoreFormatException) { throw e
            } catch (e: IOException) { throw StoreFormatException("truncated store")
            } catch (e: Exception) { throw StoreFormatException("corrupt store record") }
        }
    }
}
