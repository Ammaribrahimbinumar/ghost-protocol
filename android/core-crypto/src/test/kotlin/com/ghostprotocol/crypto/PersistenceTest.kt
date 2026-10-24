package com.ghostprotocol.crypto

import org.junit.Assert.*
import org.junit.Test
import org.signal.libsignal.protocol.UntrustedIdentityException

class PersistenceTest {
    private fun bundleOf(d: LocalDevice, i: Int = 0) =
        PublicBundle.decode(d.publicBundle().encode()).toPreKeyBundle(d.oneTimePreKeyList().getOrNull(i))
    private fun t(s: String) = s.toByteArray()

    /** Keeps the latest snapshot of a device, as the app does through encrypted storage. */
    private class Disk { var bytes = ByteArray(0); var writes = 0; val sink: (ByteArray) -> Unit = { bytes = it; writes++ } }

    @Test fun conversationContinuesAfterRestart() {
        val da = Disk(); val db = Disk()
        var alice = LocalDevice.create("alice", onChange = da.sink)
        var bob = LocalDevice.create("bob", onChange = db.sink)
        Messenger(alice).startSession(bob.address, bundleOf(bob))
        assertArrayEquals(t("one"), Messenger(bob).decrypt(alice.address, Messenger(alice).encrypt(bob.address, t("one"))))
        assertArrayEquals(t("two"), Messenger(alice).decrypt(bob.address, Messenger(bob).encrypt(alice.address, t("two"))))

        // "Kill the process": rebuild both devices from their snapshots only.
        alice = LocalDevice.restore("alice", da.bytes, onChange = da.sink)
        bob = LocalDevice.restore("bob", db.bytes, onChange = db.sink)
        assertEquals(alice.identityKey, LocalDevice.restore("alice", da.bytes).identityKey)

        assertArrayEquals(t("three"), Messenger(bob).decrypt(alice.address, Messenger(alice).encrypt(bob.address, t("three"))))
        assertArrayEquals(t("four"), Messenger(alice).decrypt(bob.address, Messenger(bob).encrypt(alice.address, t("four"))))
    }

    @Test fun consumedOneTimePreKeyStaysConsumedAfterRestart() {
        val da = Disk(); val db = Disk()
        val alice = LocalDevice.create("alice", onChange = da.sink)
        val bob = LocalDevice.create("bob", onChange = db.sink)
        val before = bob.oneTimePreKeyList().size
        Messenger(alice).startSession(bob.address, bundleOf(bob, 0))
        Messenger(bob).decrypt(alice.address, Messenger(alice).encrypt(bob.address, t("x")))
        assertEquals(before - 1, bob.oneTimePreKeyList().size)
        val restored = LocalDevice.restore("bob", db.bytes)
        assertEquals(before - 1, restored.oneTimePreKeyList().size)
    }

    @Test fun pinnedIdentitySurvivesRestartAndImpostorIsStillRefused() {
        val da = Disk()
        val alice0 = LocalDevice.create("alice", onChange = da.sink)
        val bob = LocalDevice.create("bob")
        Messenger(alice0).startSession(bob.address, bundleOf(bob))
        val alice = LocalDevice.restore("alice", da.bytes)
        val impostor = LocalDevice.create("bob")
        assertThrows(UntrustedIdentityException::class.java) {
            Messenger(alice).startSession(impostor.address, bundleOf(impostor))
        }
    }

    @Test fun replayedPreKeyMessageStillRejectedAfterRestart() {
        val da = Disk(); val db = Disk()
        val alice = LocalDevice.create("alice", onChange = da.sink)
        val bob0 = LocalDevice.create("bob", onChange = db.sink)
        Messenger(alice).startSession(bob0.address, bundleOf(bob0))
        val first = Messenger(alice).encrypt(bob0.address, t("once"))
        Messenger(bob0).decrypt(alice.address, first)
        val bob = LocalDevice.restore("bob", db.bytes)
        assertThrows(Exception::class.java) { Messenger(bob).decrypt(alice.address, first) }
    }

    @Test fun snapshotsAreWrittenOnEveryChangeButCreateIsBatched() {
        val d = Disk()
        val a = LocalDevice.create("alice", onChange = d.sink)
        assertEquals("create writes once", 1, d.writes)
        val b = LocalDevice.create("bob")
        Messenger(a).startSession(b.address, bundleOf(b))
        assertTrue(d.writes > 1)
    }

    @Test fun damagedSnapshotsAreRejectedNotGuessed() {
        val d = Disk(); LocalDevice.create("alice", onChange = d.sink)
        val good = d.bytes
        fun rejects(b: ByteArray) = assertThrows(StoreFormatException::class.java) { LocalDevice.restore("alice", b) }
        rejects(ByteArray(0))
        rejects(good.copyOf(good.size / 2))
        rejects(good + byteArrayOf(1))
        rejects(good.copyOf().also { it[0] = (it[0] + 1).toByte() })
        rejects(good.copyOf().also { it[4] = 9 })
        // flip bytes inside the identity-key record
        rejects(good.copyOf().also { for (i in 10..40) it[i] = (it[i].toInt() xor 0x55).toByte() })
    }

    @Test fun restoreNeverReturnsAFreshIdentity() {
        val d = Disk(); val a = LocalDevice.create("alice", onChange = d.sink)
        assertEquals(a.identityKey, LocalDevice.restore("alice", d.bytes).identityKey)
        assertEquals(a.registrationId, LocalDevice.restore("alice", d.bytes).registrationId)
    }
}
