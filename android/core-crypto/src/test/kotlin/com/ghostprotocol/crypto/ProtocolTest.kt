package com.ghostprotocol.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.signal.libsignal.protocol.DuplicateMessageException
import org.signal.libsignal.protocol.UntrustedIdentityException

/** All identities and messages here are synthetic. */
class ProtocolTest {
    private val alice = LocalDevice.create("alice")
    private val bob = LocalDevice.create("bob")
    private val a = Messenger(alice)
    private val b = Messenger(bob)

    /** What the relay would hand Alice: Bob's public bundle blob plus one one-time key. */
    private fun fetchBundle(dev: LocalDevice, otpIndex: Int = 0) =
        PublicBundle.decode(dev.publicBundle().encode()).toPreKeyBundle(dev.oneTimePreKeyList().getOrNull(otpIndex))

    private fun connect() = a.startSession(bob.address, fetchBundle(bob))
    private fun text(s: String) = s.toByteArray()

    @Test fun roundTripBothDirections() {
        connect()
        val first = a.encrypt(bob.address, text("hello bob"))
        assertTrue("first message must be a prekey message", first.isPreKeyMessage)
        assertArrayEquals(text("hello bob"), b.decrypt(alice.address, first))

        val reply = b.encrypt(alice.address, text("hello alice"))
        assertFalse(reply.isPreKeyMessage)
        assertArrayEquals(text("hello alice"), a.decrypt(bob.address, reply))

        repeat(20) { i ->
            assertArrayEquals(text("a$i"), b.decrypt(alice.address, a.encrypt(bob.address, text("a$i"))))
            assertArrayEquals(text("b$i"), a.decrypt(bob.address, b.encrypt(alice.address, text("b$i"))))
        }
    }

    @Test fun ciphertextHidesPlaintextAndIsRandomised() {
        connect()
        val secret = "TOP-SECRET-PLAINTEXT-MARKER"
        val c1 = a.encrypt(bob.address, text(secret))
        val c2 = a.encrypt(bob.address, text(secret))
        assertFalse(String(c1.bytes, Charsets.ISO_8859_1).contains(secret))
        assertFalse(c1.bytes.contentEquals(c2.bytes)) // same plaintext, different ciphertext
    }

    @Test fun everySingleByteTamperingIsRejected() {
        connect()
        b.decrypt(alice.address, a.encrypt(bob.address, text("establish")))
        b.decrypt(alice.address, a.encrypt(bob.address, text("establish2")))
        val reply = b.encrypt(alice.address, text("authentic reply"))
        a.decrypt(bob.address, reply.also { }) // consume one so state is established on both sides
        val genuine = a.encrypt(bob.address, text("genuine message"))

        for (i in genuine.bytes.indices) {
            val bad = genuine.bytes.copyOf().also { it[i] = (it[i].toInt() xor 0x01).toByte() }
            val result = runCatching { b.decrypt(alice.address, Envelope(bad)) }
            assertTrue("tampering byte $i was accepted", result.isFailure)
        }
        // A failed forgery must not damage the session: the genuine message still decrypts.
        assertArrayEquals(text("genuine message"), b.decrypt(alice.address, genuine))
    }

    @Test fun truncatedAndEmptyEnvelopesAreRejected() {
        connect()
        val m = a.encrypt(bob.address, text("x"))
        for (len in listOf(0, 1, 2, m.bytes.size / 2, m.bytes.size - 1)) {
            val result = runCatching { b.decrypt(alice.address, Envelope(m.bytes.copyOf(len))) }
            assertTrue("length $len accepted", result.isFailure)
        }
    }

    @Test fun replayIsRejected() {
        connect()
        val m = a.encrypt(bob.address, text("once only"))
        assertArrayEquals(text("once only"), b.decrypt(alice.address, m))
        assertThrows(DuplicateMessageException::class.java) { b.decrypt(alice.address, m) }

        val m2 = a.encrypt(bob.address, text("second"))
        b.decrypt(alice.address, m2)
        assertThrows(DuplicateMessageException::class.java) { b.decrypt(alice.address, m2) }
    }

    @Test fun outOfOrderDeliveryStillWorks() {
        connect()
        val m1 = a.encrypt(bob.address, text("one"))
        b.decrypt(alice.address, m1) // establish
        val reply = b.encrypt(alice.address, text("ack"))
        a.decrypt(bob.address, reply)
        val m2 = a.encrypt(bob.address, text("two"))
        val m3 = a.encrypt(bob.address, text("three"))
        val m4 = a.encrypt(bob.address, text("four"))
        assertArrayEquals(text("four"), b.decrypt(alice.address, m4))
        assertArrayEquals(text("two"), b.decrypt(alice.address, m2))
        assertArrayEquals(text("three"), b.decrypt(alice.address, m3))
    }

    @Test fun wrongRecipientCannotDecrypt() {
        connect()
        val m = a.encrypt(bob.address, text("for bob only"))
        val carol = LocalDevice.create("carol")
        val c = Messenger(carol)
        assertTrue(runCatching { c.decrypt(alice.address, m) }.isFailure)
    }

    @Test fun messageFromTheWrongSenderAddressIsRejected() {
        connect()
        val m = a.encrypt(bob.address, text("hi"))
        b.decrypt(alice.address, m)
        val m2 = a.encrypt(bob.address, text("again"))
        val mallory = LocalDevice.create("mallory")
        assertTrue(runCatching { b.decrypt(mallory.address, m2) }.isFailure)
    }

    @Test fun changedIdentityKeyIsNotSilentlyTrusted() {
        connect()
        b.decrypt(alice.address, a.encrypt(bob.address, text("hi")))
        // "Bob" reinstalls (or a relay substitutes keys): same name, brand-new identity key.
        val impostor = LocalDevice.create("bob")
        assertNotEquals(bob.identityKey, impostor.identityKey)
        assertThrows(UntrustedIdentityException::class.java) {
            a.startSession(impostor.address, fetchBundle(impostor))
        }
        // The original session keeps working.
        val still = a.encrypt(bob.address, text("still bob"))
        assertArrayEquals(text("still bob"), b.decrypt(alice.address, still))
    }

    @Test fun safetyNumbersMatchBetweenHonestPartiesAndDifferUnderMitm() {
        val ab = SafetyNumber.compute(alice, "bob", bob.identityKey)
        val ba = SafetyNumber.compute(bob, "alice", alice.identityKey)
        assertEquals(ab.displayableFingerprint.displayText, ba.displayableFingerprint.displayText)
        assertTrue(ab.scannableFingerprint.compareTo(ba.scannableFingerprint.serialized))
        assertEquals(60, ab.displayableFingerprint.displayText.length)

        // A man in the middle presents his own key to Alice in place of Bob's.
        val mitm = LocalDevice.create("bob")
        val seenByAlice = SafetyNumber.compute(alice, "bob", mitm.identityKey)
        assertNotEquals(seenByAlice.displayableFingerprint.displayText, ba.displayableFingerprint.displayText)
        assertFalse(seenByAlice.scannableFingerprint.compareTo(ba.scannableFingerprint.serialized))
    }

    @Test fun oneTimePreKeysAreIndependent() {
        val bundle1 = bob.publicBundle().toPreKeyBundle(bob.oneTimePreKeyList()[0])
        val bundle2 = bob.publicBundle().toPreKeyBundle(bob.oneTimePreKeyList()[1])
        val a1 = LocalDevice.create("alice1"); val a2 = LocalDevice.create("alice2")
        Messenger(a1).startSession(bob.address, bundle1)
        Messenger(a2).startSession(bob.address, bundle2)
        val m1 = Messenger(a1).encrypt(bob.address, text("from 1"))
        val m2 = Messenger(a2).encrypt(bob.address, text("from 2"))
        assertArrayEquals(text("from 1"), b.decrypt(a1.address, m1))
        assertArrayEquals(text("from 2"), b.decrypt(a2.address, m2))
    }

    @Test fun sessionWorksWithoutAOneTimePreKey() {
        a.startSession(bob.address, PublicBundle.decode(bob.publicBundle().encode()).toPreKeyBundle(null))
        assertArrayEquals(text("no otpk"), b.decrypt(alice.address, a.encrypt(bob.address, text("no otpk"))))
    }

    @Test fun oneTimePreKeyCannotBeReusedByASecondSessionMessage() {
        val bundle = bob.publicBundle().toPreKeyBundle(bob.oneTimePreKeyList()[0])
        a.startSession(bob.address, bundle)
        val m = a.encrypt(bob.address, text("uses otpk 1"))
        b.decrypt(alice.address, m)
        // Replaying the prekey message after the one-time key was consumed must fail.
        assertTrue(runCatching { b.decrypt(alice.address, m) }.isFailure)
    }

    @Test fun malformedBundlesAreRejectedWithoutCrashing() {
        val good = bob.publicBundle().encode()
        val cases = listOf(
            ByteArray(0), byteArrayOf(1), byteArrayOf(9) + good.copyOfRange(1, good.size), // unknown version
            good.copyOf(good.size - 3), good + byteArrayOf(0), ByteArray(300) { 0x7f },
        )
        for ((i, c) in cases.withIndex()) {
            assertThrows("case $i", BundleFormatException::class.java) { PublicBundle.decode(c) }
        }
        // Corrupted key material decodes structurally but must not build a bundle.
        val corrupt = PublicBundle(1, 1, ByteArray(33), 1, ByteArray(33), ByteArray(64), 1, ByteArray(50), ByteArray(64))
        assertThrows(BundleFormatException::class.java) { corrupt.toPreKeyBundle(null) }
    }

    @Test fun forgedSignedPreKeySignatureIsRejected() {
        val real = bob.publicBundle()
        val forged = PublicBundle(
            real.registrationId, real.deviceId, real.identityKey, real.signedPreKeyId, real.signedPreKey,
            real.signedPreKeySignature.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() },
            real.kyberPreKeyId, real.kyberPreKey, real.kyberPreKeySignature,
        )
        assertTrue(runCatching { a.startSession(bob.address, forged.toPreKeyBundle(null)) }.isFailure)
    }
}
