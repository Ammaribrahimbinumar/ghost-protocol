package com.ghostprotocol.app

import com.ghostprotocol.app.security.Clock
import com.ghostprotocol.app.security.SecretStore
import com.ghostprotocol.app.security.StoreCorruptedException
import com.ghostprotocol.app.security.UnlockVerifier
import com.ghostprotocol.app.security.VerifyResult
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class MemoryStore : SecretStore {
    var data: ByteArray? = null
    override fun read(): ByteArray? = data?.copyOf()
    override fun write(data: ByteArray) { this.data = data.copyOf() }
}

class FakeClock(var now: Long = 1_000_000L) : Clock {
    override fun nowMillis(): Long = now
}

class UnlockVerifierTest {
    private val secret = "246813"
    private val store = MemoryStore()
    private val clock = FakeClock()

    // 1,000 iterations keeps the test fast; production uses UnlockVerifier.DEFAULT_ITERATIONS.
    private fun verifier() = UnlockVerifier(store, clock, iterations = 1000)
    private fun good() = secret.toCharArray()
    private fun bad() = "111111".toCharArray()

    private fun configured(): UnlockVerifier = verifier().also { it.configure(good()) }

    @Test fun notConfiguredByDefault() {
        val v = verifier()
        assertFalse(v.isConfigured())
        assertEquals(VerifyResult.NOT_CONFIGURED, v.verify(good()))
    }

    @Test fun correctAndIncorrect() {
        val v = configured()
        assertEquals(VerifyResult.ACCEPTED, v.verify(good()))
        assertEquals(VerifyResult.REJECTED, v.verify(bad()))
    }

    @Test fun rejectsBadShapeAtConfigure() {
        for (s in listOf("123", "12a456", "", "1".repeat(17))) {
            assertThrows(IllegalArgumentException::class.java) { verifier().configure(s.toCharArray()) }
        }
    }

    @Test fun storedRecordContainsNoPlaintextSecret() {
        configured()
        val raw = store.data!!
        assertFalse(String(raw, Charsets.ISO_8859_1).contains(secret))
        // Also not as UTF-16 chars.
        assertFalse(String(raw, Charsets.UTF_16BE).contains(secret))
    }

    @Test fun saltIsRandomPerConfigure() {
        val a = MemoryStore(); val b = MemoryStore()
        UnlockVerifier(a, clock, iterations = 1000).configure(good())
        UnlockVerifier(b, clock, iterations = 1000).configure(good())
        assertFalse(a.data!!.contentEquals(b.data!!))
    }

    @Test fun reconfigureReplacesSecret() {
        val v = configured()
        v.configure("999999".toCharArray())
        assertEquals(VerifyResult.REJECTED, v.verify(good()))
        assertEquals(VerifyResult.ACCEPTED, v.verify("999999".toCharArray()))
    }

    @Test fun lockoutAfterFiveFailuresEvenForCorrectSecret() {
        val v = configured()
        repeat(5) { assertEquals(VerifyResult.REJECTED, v.verify(bad())) }
        assertEquals(VerifyResult.THROTTLED, v.verify(good()))
        assertEquals(VerifyResult.THROTTLED, v.verify(bad())) // right and wrong are indistinguishable
        clock.now += 29_999
        assertEquals(VerifyResult.THROTTLED, v.verify(good()))
        clock.now += 2
        assertEquals(VerifyResult.ACCEPTED, v.verify(good()))
    }

    @Test fun backoffDoublesAfterEachFurtherFailure() {
        val v = configured()
        repeat(5) { v.verify(bad()) }
        clock.now += 30_001
        assertEquals(VerifyResult.REJECTED, v.verify(bad())) // 6th failure -> 60s
        clock.now += 59_999
        assertEquals(VerifyResult.THROTTLED, v.verify(good()))
        clock.now += 2
        assertEquals(VerifyResult.ACCEPTED, v.verify(good()))
    }

    @Test fun successResetsFailureCounter() {
        val v = configured()
        repeat(4) { v.verify(bad()) }
        assertEquals(VerifyResult.ACCEPTED, v.verify(good()))
        repeat(4) { assertEquals(VerifyResult.REJECTED, v.verify(bad())) } // still not locked: counter restarted
    }

    @Test fun lockoutIsCappedAtOneHour() {
        val v = configured()
        repeat(30) {
            clock.now += UnlockVerifier.MAX_LOCK_MS + 1
            v.verify(bad())
        }
        clock.now += UnlockVerifier.MAX_LOCK_MS - 1
        assertEquals(VerifyResult.THROTTLED, v.verify(good()))
        clock.now += 2
        assertEquals(VerifyResult.ACCEPTED, v.verify(good()))
    }

    @Test fun clockRollbackCannotExtendLockoutBeyondCap() {
        val v = configured()
        repeat(5) { v.verify(bad()) }
        clock.now -= 10 * UnlockVerifier.MAX_LOCK_MS
        assertEquals(VerifyResult.THROTTLED, v.verify(good()))
        clock.now += UnlockVerifier.MAX_LOCK_MS + 1
        assertEquals(VerifyResult.ACCEPTED, v.verify(good()))
    }

    @Test fun wrongShapeCandidatesDoNotCountAsAttempts() {
        val v = configured()
        repeat(20) { assertEquals(VerifyResult.REJECTED, v.verify("12".toCharArray())) }
        assertEquals(VerifyResult.ACCEPTED, v.verify(good()))
    }

    @Test fun lockoutSurvivesRestart() {
        configured().also { v -> repeat(5) { v.verify(bad()) } }
        val restarted = verifier() // same store, new instance
        assertEquals(VerifyResult.THROTTLED, restarted.verify(good()))
    }

    @Test fun corruptedRecordIsReportedNotTreatedAsFreshInstall() {
        configured()
        val valid = store.data!!

        store.data = byteArrayOf(9, 9, 9)
        assertThrows(StoreCorruptedException::class.java) { verifier().verify(good()) }

        store.data = valid.copyOf(10) // truncated
        assertThrows(StoreCorruptedException::class.java) { verifier().verify(good()) }
    }

    @Test fun verifyDoesNotModifyCallerArrayContractIsCallerZeroes() {
        val v = configured()
        val c = good()
        v.verify(c)
        assertArrayEquals(good(), c) // the verifier leaves zeroing to the caller, who must do it
        assertNotEquals(0, c.size)
        assertTrue(c.all { it in '0'..'9' })
    }
}
