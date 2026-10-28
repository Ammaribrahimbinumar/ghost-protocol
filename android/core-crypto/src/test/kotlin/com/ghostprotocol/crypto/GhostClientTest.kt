package com.ghostprotocol.crypto

import org.junit.Assert.*
import org.junit.Test

/** In-memory relay that can also misbehave (drop/duplicate/tamper), standing in for a hostile relay. */
class FakeRelay : RelayApi {
    class Account(val mailbox: String, val device: LocalDevice)
    val accounts = mutableMapOf<String, Account>()
    val boxes = mutableMapOf<String, MutableList<Delivered>>()
    val acked = mutableListOf<String>()
    var failInbox = false
    var failFetch = false
    var send429 = 0
    private var n = 0
    var current: String = ""      // mailbox of whoever is calling

    fun register(d: LocalDevice): String { val mb = "mb${++n}"; accounts[d.name] = Account(mb, d); boxes[mb] = mutableListOf(); return mb }
    fun api(of: LocalDevice): RelayApi = object : RelayApi {
        override fun fetchBundle(username: String) = this@FakeRelay.fetchBundle(username)
        override fun send(recipientMailbox: String, payload: ByteArray) = this@FakeRelay.send(recipientMailbox, payload)
        override fun inbox(): List<Delivered> { if (failInbox) throw java.io.IOException("offline"); return boxes[accounts[of.name]!!.mailbox]!!.toList() }
        override fun ack(ids: List<String>) { acked += ids; boxes[accounts[of.name]!!.mailbox]!!.removeAll { it.id in ids } }
    }
    private var bundleOverride = mutableMapOf<String, LocalDevice>()
    fun impersonate(name: String, d: LocalDevice) { bundleOverride[name] = d; accounts[name]!!.let { accounts[name] = Account(it.mailbox, d) } }
    override fun fetchBundle(username: String): FetchedBundle {
        if (failFetch) throw java.io.IOException("offline")
        val a = accounts[username] ?: throw RelayException(404, "no such user")
        return FetchedBundle(a.mailbox, a.device.publicBundle().encode(), a.device.oneTimePreKeyList().firstOrNull()?.encode())
    }
    override fun send(recipientMailbox: String, payload: ByteArray) { if (send429 > 0) { send429--; throw RelayException(429, "slow down") }; boxes[recipientMailbox]!!.add(Delivered("m${++n}", payload)) }
    override fun inbox() = emptyList<Delivered>()
    override fun ack(ids: List<String>) {}
}

class GhostClientTest {
    private class Rig(name: String, val relay: FakeRelay) {
        var disk = ByteArray(0); var devDisk = ByteArray(0)
        var device = LocalDevice.create(name, onChange = { devDisk = it })
        init { relay.register(device) }
        var now = 1_000_000L
        var client = GhostClient(device, relay.api(device), null, { disk = it }, { now })
        fun restart() {
            device = LocalDevice.restore(device.name, devDisk, onChange = { devDisk = it })
            relay.accounts[device.name] = FakeRelay.Account(relay.accounts[device.name]!!.mailbox, device)
            client = GhostClient(device, relay.api(device), disk, { disk = it }, { now })
        }
    }
    private val relay = FakeRelay()
    private val alice = Rig("alice_x", relay)
    private val bob = Rig("bob_xyz", relay)

    private fun texts(r: Rig, who: String) = r.client.messages(who).map { (if (it.outgoing) ">" else "<") + it.text }

    @Test fun twoWayConversationAndNewSenderBecomesContact() {
        alice.client.addContact("bob_xyz")
        alice.client.send("bob_xyz", "hello")
        val r = bob.client.poll()
        assertEquals(1, r.received)
        assertEquals(listOf("<hello"), texts(bob, "alice_x"))
        assertEquals("alice_x", bob.client.contacts().single().name)       // learned from first message
        bob.client.send("alice_x", "hi back")
        alice.client.poll()
        assertEquals(listOf(">hello", "<hi back"), texts(alice, "bob_xyz"))
    }

    @Test fun safetyNumbersMatchOnBothSides() {
        alice.client.addContact("bob_xyz"); alice.client.send("bob_xyz", "x"); bob.client.poll()
        val a = alice.client.safetyNumber("bob_xyz"); val b = bob.client.safetyNumber("alice_x")
        assertEquals(a, b)
        assertTrue(a.replace(" ", "").length >= 60)
    }

    @Test fun historyAndSessionSurviveRestart() {
        alice.client.addContact("bob_xyz"); alice.client.send("bob_xyz", "one"); bob.client.poll()
        bob.client.send("alice_x", "two"); alice.client.poll()
        alice.restart(); bob.restart()
        assertEquals(listOf(">one", "<two"), texts(alice, "bob_xyz"))
        alice.client.send("bob_xyz", "three"); bob.client.poll()
        assertEquals(listOf("<one", ">two", "<three"), texts(bob, "alice_x"))
    }

    @Test fun replayedAndTamperedMessagesAreDroppedAndAcked() {
        alice.client.addContact("bob_xyz"); alice.client.send("bob_xyz", "real")
        val box = relay.boxes[relay.accounts["bob_xyz"]!!.mailbox]!!
        val orig = box[0]
        val tampered = orig.body.copyOf().also { it[it.size - 3] = (it[it.size - 3].toInt() xor 1).toByte() }
        box.add(Delivered("evil1", tampered))
        box.add(Delivered("junk", byteArrayOf(9, 9, 9)))
        val r1 = bob.client.poll()
        assertEquals(1, r1.received); assertEquals(2, r1.dropped)
        assertTrue(relay.acked.containsAll(listOf("evil1", "junk")))
        box.add(Delivered("replay", orig.body))                       // replay of an already-processed message
        val r2 = bob.client.poll()
        assertEquals(0, r2.received); assertEquals(1, r2.dropped)
        assertEquals(listOf("<real"), texts(bob, "alice_x"))
    }

    @Test fun transientRelayFailureLeavesMessagesUnackedAndRetries() {
        alice.client.addContact("bob_xyz"); alice.client.send("bob_xyz", "later")
        relay.failInbox = true
        assertThrows(java.io.IOException::class.java) { bob.client.poll() }
        assertTrue(relay.acked.isEmpty())
        relay.failInbox = false
        assertEquals(1, bob.client.poll().received)
    }

    @Test fun mailboxLookupFailureForNewSenderDoesNotLoseTheMessage() {
        alice.client.addContact("bob_xyz"); alice.client.send("bob_xyz", "first")
        relay.failFetch = true
        val r = bob.client.poll()                                         // lookup of alice's mailbox fails mid-poll
        assertEquals(1, r.received)
        assertEquals(listOf("<first"), texts(bob, "alice_x"))
        assertEquals(0, relay.boxes[relay.accounts["bob_xyz"]!!.mailbox]!!.size)   // acked, not stuck
        assertThrows(java.io.IOException::class.java) { bob.client.send("alice_x", "x") }
        relay.failFetch = false
        bob.client.send("alice_x", "reply")                               // mailbox resolved lazily
        alice.client.poll()
        assertEquals(listOf(">first", "<reply"), texts(alice, "bob_xyz"))
    }

    @Test fun keyChangeIsBlockedUntilUserAccepts() {
        alice.client.addContact("bob_xyz"); alice.client.send("bob_xyz", "m1"); bob.client.poll()
        alice.client.markVerified("bob_xyz")
        // Bob "reinstalls": same username, brand-new identity key.
        val bob2 = LocalDevice.create("bob_xyz"); relay.impersonate("bob_xyz", bob2)
        assertThrows(KeyChangedException::class.java) { alice.client.addContact("bob_xyz") }
        assertTrue(alice.client.contacts().single().keyChanged)
        assertThrows(KeyChangedException::class.java) { alice.client.send("bob_xyz", "must not send") }
        // user explicitly accepts: old chat kept, trust reset to unverified
        alice.client.acceptKeyChange("bob_xyz")
        val c = alice.client.contacts().single()
        assertFalse(c.keyChanged); assertFalse(c.verified)
        assertEquals(listOf(">m1"), texts(alice, "bob_xyz"))
        alice.client.send("bob_xyz", "to new bob")
    }

    @Test fun incomingFromChangedIdentityIsRejectedAndFlagged() {
        alice.client.addContact("bob_xyz"); alice.client.send("bob_xyz", "m1"); bob.client.poll()
        bob.client.send("alice_x", "ok"); alice.client.poll()
        // Attacker/new install claiming to be bob_xyz with a different identity messages alice.
        val fake = LocalDevice.create("bob_xyz"); val fm = Messenger(fake)
        fm.startSession(alice.device.address, alice.device.publicBundle().toPreKeyBundle(alice.device.oneTimePreKeyList().first()))
        val pkt = Packet.encode("bob_xyz", fm.encrypt(alice.device.address, "I am bob".toByteArray()))
        relay.boxes[relay.accounts["alice_x"]!!.mailbox]!!.add(Delivered("fake", pkt))
        val r = alice.client.poll()
        assertEquals(0, r.received); assertEquals(listOf("bob_xyz"), r.keyChanges)
        assertTrue(alice.client.contacts().single().keyChanged)
        assertFalse(texts(alice, "bob_xyz").contains("<I am bob"))
    }

    @Test fun disappearingMessagesArePurgedFromHistory() {
        alice.client.addContact("bob_xyz")
        alice.client.setDisappearing("bob_xyz", 60)
        alice.client.send("bob_xyz", "temp")
        assertEquals(0, alice.client.purgeExpired())
        alice.now += 59_000; assertEquals(0, alice.client.purgeExpired())
        alice.now += 2_000; assertEquals(1, alice.client.purgeExpired())
        assertTrue(alice.client.messages("bob_xyz").isEmpty())
        assertFalse(String(alice.disk).contains("temp"))               // gone from the persisted state too
    }

    @Test fun cannotAddSelfOrBadNamesAndCorruptStateIsRejected() {
        assertThrows(IllegalArgumentException::class.java) { alice.client.addContact("alice_x") }
        assertThrows(IllegalArgumentException::class.java) { alice.client.addContact("Bad Name!") }
        assertThrows(UnknownContactException::class.java) { alice.client.send("nobody_x", "hi") }
        assertThrows(StoreFormatException::class.java) { GhostClient(alice.device, relay.api(alice.device), "not json{".toByteArray()) }
    }
}
