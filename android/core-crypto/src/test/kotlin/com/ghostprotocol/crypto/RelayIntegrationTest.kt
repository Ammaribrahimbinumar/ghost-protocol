package com.ghostprotocol.crypto

import java.net.HttpURLConnection
import java.net.URL
import java.security.SecureRandom
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.signal.libsignal.protocol.DuplicateMessageException
import org.signal.libsignal.protocol.SignalProtocolAddress

/**
 * Two clients exchange messages through the REAL relay process (built from ../relay).
 * Runs only when GHOST_RELAY_URL is set; in CI GHOST_REQUIRE_RELAY=1 turns a missing relay into a failure.
 * Tampering, replay and key substitution are performed on the client side of the relay to simulate a
 * malicious or compromised relay.
 */
class RelayIntegrationTest {
    private val url: String? = System.getenv("GHOST_RELAY_URL")
    private val admin: String? = System.getenv("GHOST_ADMIN_TOKEN")
    private val marker = "PLAINTEXT-MARKER-" + SecureRandom().nextInt(1_000_000)

    @Before fun gate() {
        if (url == null || admin == null) {
            if (System.getenv("GHOST_REQUIRE_RELAY") != null) fail("GHOST_REQUIRE_RELAY is set but relay env is missing")
            assumeTrue("no relay available", false)
        }
    }

    inner class User(label: String) {
        val name = label + "_" + java.lang.Long.toHexString(SecureRandom().nextLong()).take(8)
        val device = LocalDevice.create(name)
        val messenger = Messenger(device)
        val signer = EcdsaP256Signer.generateSoftware()
        val client = RelayClient(url!!, signer, allowLoopbackHttpForTests = true)
        val address: SignalProtocolAddress get() = device.address
        val mailbox: String

        init {
            mailbox = client.register(
                invite(), name, signer.publicKey,
                device.publicBundle().encode(), device.oneTimePreKeyList().map { it.encode() },
            )
        }

        /** Fetch the peer's bundle from the relay and start a session. Returns the identity key used. */
        fun connectTo(peer: User) {
            val f = client.fetchBundle(peer.name)
            assertEquals(peer.mailbox, f.mailboxId)
            messenger.startSession(
                peer.address,
                PublicBundle.decode(f.bundle).toPreKeyBundle(f.oneTimePreKey?.let { OneTimePreKey.decode(it) }),
            )
        }

        fun send(peer: User, text: String) {
            val env = messenger.encrypt(peer.address, text.toByteArray())
            client.send(peer.mailbox, Packet.encode(name, env))
        }

        /** Returns (relay message id, sender, envelope) for each queued item. */
        fun pending(): List<Triple<String, String, Envelope>> =
            client.inbox().map { d -> Packet.decode(d.body).let { Triple(d.id, it.first, it.second) } }

        fun decrypt(sender: String, env: Envelope): String =
            String(messenger.decrypt(SignalProtocolAddress(sender, 1), env))
    }

    private fun invite(): String {
        val c = URL(url + "/v1/admin/invites").openConnection() as HttpURLConnection
        c.requestMethod = "POST"
        c.setRequestProperty("Authorization", "Bearer $admin")
        check(c.responseCode == 201) { "invite failed: ${c.responseCode}" }
        return JSONObject(String(c.inputStream.readBytes())).getString("invite")
    }

    @Test fun twoClientsExchangeEncryptedMessagesThroughTheRealRelay() {
        val alice = User("alice"); val bob = User("bob")
        alice.connectTo(bob)
        alice.send(bob, marker)

        val raw = bob.client.inbox()
        assertEquals(1, raw.size)
        assertFalse("relay-held bytes contain plaintext", String(raw[0].body, Charsets.ISO_8859_1).contains(marker))

        val (id, sender, env) = bob.pending().single()
        assertEquals(alice.name, sender)
        assertEquals(marker, bob.decrypt(sender, env))
        bob.client.ack(listOf(id))
        assertTrue(bob.pending().isEmpty())

        bob.send(alice, "reply $marker")
        val (id2, sender2, env2) = alice.pending().single()
        assertEquals("reply $marker", alice.decrypt(sender2, env2))
        alice.client.ack(listOf(id2))
        assertTrue(alice.pending().isEmpty())
    }

    @Test fun relayTamperingWithAnyEnvelopeByteIsDetected() {
        val alice = User("alice"); val bob = User("bob")
        alice.connectTo(bob)
        alice.send(bob, "establish"); bob.pending().single().let { bob.decrypt(it.second, it.third); bob.client.ack(listOf(it.first)) }
        bob.send(alice, "ack"); alice.pending().single().let { alice.decrypt(it.second, it.third); alice.client.ack(listOf(it.first)) }
        alice.send(bob, marker)
        val (id, sender, env) = bob.pending().single()
        for (i in env.bytes.indices) {
            val bad = env.bytes.copyOf().also { it[i] = (it[i].toInt() xor 1).toByte() }
            assertTrue("byte $i accepted", runCatching { bob.decrypt(sender, Envelope(bad)) }.isFailure)
        }
        assertEquals(marker, bob.decrypt(sender, env)) // the genuine message still works
        bob.client.ack(listOf(id))
    }

    @Test fun relayReplayingADeliveredMessageIsRejected() {
        val alice = User("alice"); val bob = User("bob")
        alice.connectTo(bob)
        alice.send(bob, marker)
        val (_, sender, env) = bob.pending().single()
        assertEquals(marker, bob.decrypt(sender, env))
        // Not acknowledged: the relay delivers the same bytes again, as a malicious relay might.
        val again = bob.pending().single()
        assertArrayEquals(env.bytes, again.third.bytes)
        assertThrows(DuplicateMessageException::class.java) { bob.decrypt(again.second, again.third) }
    }

    @Test fun relaySubstitutingKeysIsExposedBySafetyNumbers() {
        val alice = User("alice"); val bob = User("bob"); val mallory = User("mallory")
        // A compromised relay answers Alice's request for "bob" with Mallory's bundle.
        val forged = PublicBundle.decode(mallory.device.publicBundle().encode()).toPreKeyBundle(null)
        // First contact cannot detect this by itself: the session is established.
        alice.messenger.startSession(bob.address, forged)

        val aliceView = SafetyNumber.compute(alice.device, bob.name, forged.identityKey)
        val bobView = SafetyNumber.compute(bob.device, alice.name, alice.device.identityKey)
        assertNotEquals(aliceView.displayableFingerprint.displayText, bobView.displayableFingerprint.displayText)

        // Control: with Bob's genuine key the two views match.
        val genuine = SafetyNumber.compute(alice.device, bob.name, bob.device.identityKey)
        assertEquals(genuine.displayableFingerprint.displayText, bobView.displayableFingerprint.displayText)
    }

    @Test fun spoofedSenderNameCannotImpersonateAnotherUser() {
        val alice = User("alice"); val bob = User("bob"); val mallory = User("mallory")
        alice.connectTo(bob)
        alice.send(bob, "hi")
        bob.pending().single().let { bob.decrypt(it.second, it.third); bob.client.ack(listOf(it.first)) }

        mallory.connectTo(bob)
        val env = mallory.messenger.encrypt(bob.address, "I am alice".toByteArray())
        // Mallory claims to be alice (the name is only a lookup hint; Packet allows any valid name).
        mallory.client.send(bob.mailbox, Packet.encode(alice.name, env))
        val (_, claimed, spoofed) = bob.pending().single()
        assertEquals(alice.name, claimed)
        assertTrue("spoofed message was accepted", runCatching { bob.decrypt(claimed, spoofed) }.isFailure)
    }

    @Test fun relayRejectsUnauthenticatedAndMisauthenticatedRequests() {
        val alice = User("alice"); val bob = User("bob")
        val anon = RelayClient(url!!, null, allowLoopbackHttpForTests = true)
        assertEquals(0, assertThrows(RelayException::class.java) { anon.send(bob.mailbox, byteArrayOf(1, 2, 3)) }.status)
        // Wrong key: Alice's mailbox but a different signer.
        val impostor = RelayClient(url, EcdsaP256Signer.generateSoftware(), alice.mailbox, allowLoopbackHttpForTests = true)
        assertEquals(401, assertThrows(RelayException::class.java) { impostor.send(bob.mailbox, byteArrayOf(1, 2, 3)) }.status)
        assertEquals(401, assertThrows(RelayException::class.java) { impostor.inbox() }.status)
        // Oversized payload.
        assertEquals(400, assertThrows(RelayException::class.java) { alice.client.send(bob.mailbox, ByteArray(70_000)) }.status)
    }
}
