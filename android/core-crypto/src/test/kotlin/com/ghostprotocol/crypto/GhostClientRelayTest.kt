package com.ghostprotocol.crypto

import java.net.HttpURLConnection
import java.net.URL
import java.security.SecureRandom
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test

/** Full client (GhostClient) against the real relay process: invites, signed requests, mailboxes. */
class GhostClientRelayTest {
    private val url: String? = System.getenv("GHOST_RELAY_URL")
    private val admin: String? = System.getenv("GHOST_ADMIN_TOKEN")
    @Before fun gate() {
        if (url == null || admin == null) {
            if (System.getenv("GHOST_REQUIRE_RELAY") != null) fail("relay env missing")
            assumeTrue(false)
        }
    }
    private fun invite(): String {
        val c = URL(url + "/v1/admin/invites").openConnection() as HttpURLConnection
        c.requestMethod = "POST"; c.setRequestProperty("Authorization", "Bearer $admin")
        check(c.responseCode == 201)
        return JSONObject(String(c.inputStream.readBytes())).getString("invite")
    }
    private class Person(val name: String, url: String, invite: String) {
        var devDisk = ByteArray(0); var cliDisk = ByteArray(0)
        val signer = EcdsaP256Signer.generateSoftware()
        val relay = RelayClient(url, signer, allowLoopbackHttpForTests = true)
        var device = LocalDevice.create(name, onChange = { devDisk = it })
        init { relay.register(invite, name, signer.publicKey, device.publicBundle().encode(), device.oneTimePreKeyList().map { it.encode() }) }
        var client = GhostClient(device, relay, null, { cliDisk = it })
        fun restart() { device = LocalDevice.restore(name, devDisk, onChange = { devDisk = it }); client = GhostClient(device, relay, cliDisk, { cliDisk = it }) }
    }
    private fun nm(p: String) = p + "_" + java.lang.Long.toHexString(SecureRandom().nextLong()).take(8)

    @Test fun fullConversationThroughRealRelayIncludingRestartAndSafetyNumbers() {
        val alice = Person(nm("alice"), url!!, invite()); val bob = Person(nm("bob"), url, invite())
        alice.client.addContact(bob.name)
        alice.client.send(bob.name, "secret one")
        val r = bob.client.poll()
        assertEquals(1, r.received)
        bob.client.send(alice.name, "secret two")
        assertEquals(1, alice.client.poll().received)
        assertEquals(alice.client.safetyNumber(bob.name), bob.client.safetyNumber(alice.name))
        alice.restart(); bob.restart()
        alice.client.send(bob.name, "after restart")
        assertEquals(1, bob.client.poll().received)
        assertEquals(listOf("secret one", "after restart"), bob.client.messages(alice.name).filter { !it.outgoing }.map { it.text })
        assertEquals(0, bob.client.poll().received)   // acked: nothing left in the inbox
    }

    @Test fun unknownUserAndBadInviteAreRefused() {
        val alice = Person(nm("alice"), url!!, invite())
        assertThrows(RelayException::class.java) { alice.client.addContact("nobody_here_" + nm("x").takeLast(6)) }
        val signer = EcdsaP256Signer.generateSoftware(); val d = LocalDevice.create(nm("eve"))
        val ex = assertThrows(RelayException::class.java) {
            RelayClient(url, signer, allowLoopbackHttpForTests = true)
                .register("not-a-real-invite", d.name, signer.publicKey, d.publicBundle().encode(), emptyList())
        }
        assertTrue(ex.status in 400..403)
    }
}
