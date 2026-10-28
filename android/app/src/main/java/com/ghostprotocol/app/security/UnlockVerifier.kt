package com.ghostprotocol.app.security

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/** Where the verifier record lives. The Android implementation encrypts it with a Keystore key. */
interface SecretStore {
    fun read(): ByteArray?
    fun write(data: ByteArray)
}

fun interface Clock {
    fun nowMillis(): Long
}

/** The stored record cannot be read or fails sanity checks. Never silently treated as "unconfigured". */
class StoreCorruptedException(message: String) : Exception(message)

enum class VerifyResult { ACCEPTED, REJECTED, THROTTLED, NOT_CONFIGURED, DECOY, DURESS }

/**
 * Verifies the user-configured numeric unlock secret.
 *
 * - No default or hardcoded secret exists. [configure] must be called by the user.
 * - Only a PBKDF2-HMAC-SHA256 verifier (random per-install salt) is stored, never the secret.
 * - Wrong guesses are throttled with exponential back-off after [FREE_ATTEMPTS] failures.
 *   While throttled, [verify] does not even look at the candidate, so the calculator behaves
 *   identically for right and wrong input.
 * - There is deliberately no recovery path that bypasses the secret. Resetting means wiping the
 *   app's data, which also destroys the vault (no hidden backdoor).
 *
 * Known limit: throttle timing uses the wall clock. Someone who can set the device clock forward
 * can skip a lockout. A hardware-backed counter would be needed to prevent that.
 */
class UnlockVerifier(
    private val store: SecretStore,
    private val clock: Clock = Clock { System.currentTimeMillis() },
    private val iterations: Int = DEFAULT_ITERATIONS,
    private val random: SecureRandom = SecureRandom(),
) {
    companion object {
        const val DEFAULT_ITERATIONS = 600_000
        const val MIN_LEN = 4
        const val MAX_LEN = 16
        const val FREE_ATTEMPTS = 5
        const val BASE_LOCK_MS = 30_000L
        const val MAX_LOCK_MS = 3_600_000L
        private const val FORMAT_VERSION = 2
        private const val SALT_BYTES = 16
        private const val HASH_BITS = 256
    }

    private class Record(
        val iterations: Int,
        val salt: ByteArray,
        val hash: ByteArray,
        val failures: Int,
        val lockedUntil: Long,
        val decoySalt: ByteArray? = null, val decoyHash: ByteArray? = null,     // optional second code: opens a separate empty profile
        val duressSalt: ByteArray? = null, val duressHash: ByteArray? = null,   // optional third code: wipes real data, then opens the decoy
    ) {
        fun with(failures: Int = this.failures, lockedUntil: Long = this.lockedUntil) =
            Record(iterations, salt, hash, failures, lockedUntil, decoySalt, decoyHash, duressSalt, duressHash)
    }

    fun isValidShape(candidate: CharArray): Boolean =
        candidate.size in MIN_LEN..MAX_LEN && candidate.all { it in '0'..'9' }

    @Synchronized
    fun isConfigured(): Boolean = store.read() != null

    /** Sets (or replaces) the unlock secret. The caller should zero [secret] afterwards. */
    @Synchronized
    fun configure(secret: CharArray) {
        require(isValidShape(secret)) { "secret must be $MIN_LEN-$MAX_LEN digits" }
        val salt = ByteArray(SALT_BYTES).also { random.nextBytes(it) }
        val hash = derive(secret, salt, iterations)
        save(Record(iterations, salt, hash, failures = 0, lockedUntil = 0L))
    }

    /**
     * Checks [candidate]. The caller owns the array and must zero it afterwards.
     * Candidates that are not 4-16 digits are rejected without counting as an attempt.
     */
    @Synchronized
    fun verify(candidate: CharArray): VerifyResult {
        val rec = load() ?: return VerifyResult.NOT_CONFIGURED
        val now = clock.nowMillis()

        var lockedUntil = rec.lockedUntil
        if (lockedUntil - now > MAX_LOCK_MS) {
            // Clock was moved backwards; clamp so a rollback cannot extend a lockout indefinitely.
            lockedUntil = now + MAX_LOCK_MS
            save(rec.with(lockedUntil = lockedUntil))
        }
        if (now < lockedUntil) return VerifyResult.THROTTLED
        if (!isValidShape(candidate)) return VerifyResult.REJECTED

        // All three codes are always derived and compared (a missing one uses a dummy salt), so timing does not reveal
        // whether a decoy or duress code is configured, or which code was typed.
        val a = derive(candidate, rec.salt, rec.iterations)
        val d = derive(candidate, rec.decoySalt ?: rec.salt, rec.iterations)
        val u = derive(candidate, rec.duressSalt ?: rec.salt, rec.iterations)
        val isPrimary = MessageDigest.isEqual(a, rec.hash)
        val isDecoy = MessageDigest.isEqual(d, rec.decoyHash ?: ByteArray(HASH_BITS / 8)) and (rec.decoyHash != null)
        val isDuress = MessageDigest.isEqual(u, rec.duressHash ?: ByteArray(HASH_BITS / 8)) and (rec.duressHash != null)
        a.fill(0); d.fill(0); u.fill(0)
        val result = when {
            isPrimary -> VerifyResult.ACCEPTED
            isDuress -> VerifyResult.DURESS
            isDecoy -> VerifyResult.DECOY
            else -> null
        }
        return if (result != null) {
            if (rec.failures != 0 || rec.lockedUntil != 0L) save(rec.with(failures = 0, lockedUntil = 0L))
            result
        } else {
            val failures = rec.failures + 1
            val lock = if (failures >= FREE_ATTEMPTS) now + lockoutMillis(failures) else 0L
            save(rec.with(failures = failures, lockedUntil = lock))
            VerifyResult.REJECTED
        }
    }

    /** True if a decoy / duress code is set. (Only meaningful while unlocked in the real profile.) */
    @Synchronized fun hasDecoy(): Boolean = load()?.decoyHash != null
    @Synchronized fun hasDuress(): Boolean = load()?.duressHash != null

    /** Distinct-code rule: the new code must differ from the primary and from the other secondary code. */
    private fun requireDistinct(rec: Record, code: CharArray, other: Pair<ByteArray?, ByteArray?>) {
        val p = derive(code, rec.salt, rec.iterations)
        val sameAsPrimary = MessageDigest.isEqual(p, rec.hash); p.fill(0)
        require(!sameAsPrimary) { "must differ from the main code" }
        if (other.first != null && other.second != null) {
            val o = derive(code, other.first!!, rec.iterations)
            val sameAsOther = MessageDigest.isEqual(o, other.second); o.fill(0)
            require(!sameAsOther) { "decoy and duress codes must differ" }
        }
    }

    @Synchronized fun configureDecoy(code: CharArray) {
        require(isValidShape(code)) { "code must be $MIN_LEN-$MAX_LEN digits" }
        val rec = load() ?: throw IllegalStateException("main code not set")
        requireDistinct(rec, code, rec.duressSalt to rec.duressHash)
        val salt = ByteArray(SALT_BYTES).also { random.nextBytes(it) }
        save(Record(rec.iterations, rec.salt, rec.hash, rec.failures, rec.lockedUntil, salt, derive(code, salt, rec.iterations), rec.duressSalt, rec.duressHash))
    }

    @Synchronized fun configureDuress(code: CharArray) {
        require(isValidShape(code)) { "code must be $MIN_LEN-$MAX_LEN digits" }
        val rec = load() ?: throw IllegalStateException("main code not set")
        requireDistinct(rec, code, rec.decoySalt to rec.decoyHash)
        val salt = ByteArray(SALT_BYTES).also { random.nextBytes(it) }
        save(Record(rec.iterations, rec.salt, rec.hash, rec.failures, rec.lockedUntil, rec.decoySalt, rec.decoyHash, salt, derive(code, salt, rec.iterations)))
    }

    @Synchronized fun clearDecoy() { load()?.let { save(Record(it.iterations, it.salt, it.hash, it.failures, it.lockedUntil, null, null, it.duressSalt, it.duressHash)) } }
    @Synchronized fun clearDuress() { load()?.let { save(Record(it.iterations, it.salt, it.hash, it.failures, it.lockedUntil, it.decoySalt, it.decoyHash, null, null)) } }

    private fun lockoutMillis(failures: Int): Long {
        val doublings = (failures - FREE_ATTEMPTS).coerceIn(0, 20)
        return (BASE_LOCK_MS shl doublings).coerceAtMost(MAX_LOCK_MS)
    }

    private fun derive(secret: CharArray, salt: ByteArray, iter: Int): ByteArray {
        val spec = PBEKeySpec(secret, salt, iter, HASH_BITS)
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
        }
    }

    private fun save(r: Record) {
        val out = ByteArrayOutputStream()
        DataOutputStream(out).use {
            it.writeByte(FORMAT_VERSION)
            it.writeInt(r.iterations)
            it.writeByte(r.salt.size); it.write(r.salt)
            it.writeByte(r.hash.size); it.write(r.hash)
            it.writeInt(r.failures)
            it.writeLong(r.lockedUntil)
            val flags = (if (r.decoyHash != null) 1 else 0) or (if (r.duressHash != null) 2 else 0)
            it.writeByte(flags)
            if (r.decoyHash != null) { it.write(r.decoySalt!!); it.write(r.decoyHash) }
            if (r.duressHash != null) { it.write(r.duressSalt!!); it.write(r.duressHash) }
        }
        store.write(out.toByteArray())
    }

    private fun load(): Record? {
        val raw = store.read() ?: return null
        try {
            DataInputStream(ByteArrayInputStream(raw)).use {
                val version = it.readUnsignedByte()
                if (version != 1 && version != FORMAT_VERSION) throw StoreCorruptedException("unknown record version")
                val iter = it.readInt()
                val salt = ByteArray(it.readUnsignedByte()).also { b -> it.readFully(b) }
                val hash = ByteArray(it.readUnsignedByte()).also { b -> it.readFully(b) }
                val failures = it.readInt()
                val lockedUntil = it.readLong()
                if (iter !in 1..10_000_000 || salt.size != SALT_BYTES || hash.size != HASH_BITS / 8 || failures < 0) {
                    throw StoreCorruptedException("record failed sanity checks")
                }
                var dS: ByteArray? = null; var dH: ByteArray? = null; var uS: ByteArray? = null; var uH: ByteArray? = null
                if (version >= 2) {
                    val flags = it.readUnsignedByte()
                    if (flags and 1 != 0) { dS = ByteArray(SALT_BYTES).also { b -> it.readFully(b) }; dH = ByteArray(HASH_BITS / 8).also { b -> it.readFully(b) } }
                    if (flags and 2 != 0) { uS = ByteArray(SALT_BYTES).also { b -> it.readFully(b) }; uH = ByteArray(HASH_BITS / 8).also { b -> it.readFully(b) } }
                }
                return Record(iter, salt, hash, failures, lockedUntil, dS, dH, uS, uH)
            }
        } catch (e: IOException) {
            throw StoreCorruptedException("record truncated")
        }
    }
}
