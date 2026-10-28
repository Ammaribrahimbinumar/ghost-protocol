package com.ghostprotocol.crypto

import org.junit.Assert.*
import org.junit.Test

class GroupTest {
    private class Rig(val name: String, val relay: FakeRelay) {
        var disk = ByteArray(0); var devDisk = ByteArray(0); var now = 5_000_000L
        var device = LocalDevice.create(name, onChange = { devDisk = it })
        init { relay.register(device) }
        var client = GhostClient(device, relay.api(device), null, { disk = it }, { now })
        fun restart() {
            device = LocalDevice.restore(name, devDisk, onChange = { devDisk = it })
            relay.accounts[name] = FakeRelay.Account(relay.accounts[name]!!.mailbox, device)
            client = GhostClient(device, relay.api(device), disk, { disk = it }, { now })
        }
        fun box() = relay.boxes[relay.accounts[name]!!.mailbox]!!
    }
    private val relay = FakeRelay()
    private val alice = Rig("alice_x", relay); private val bob = Rig("bob_xyz", relay)
    private val carol = Rig("carol_x", relay); private val dave = Rig("dave_xx", relay)

    private fun incoming(r: Rig, g: String) = r.client.groupMessages(g).filter { !it.system }.map { it.contact + ":" + it.text }
    private fun makeGroup(): String {
        val (g, rep) = alice.client.createGroup("team", listOf("bob_xyz", "carol_x"))
        assertTrue(rep.failed.isEmpty())
        bob.client.poll(); carol.client.poll()
        return g.id
    }
    /** Craft an arbitrary payload from a real, authenticated sender (a malicious or buggy client). */
    private fun forge(from: Rig, toName: String, json: String) {
        val toDev = relay.accounts[toName]!!.device
        if (from.client.contacts().none { it.name == toName }) from.client.addContact(toName)
        val env = Messenger(from.device).encrypt(toDev.address, byteArrayOf(2) + json.toByteArray())
        relay.boxes[relay.accounts[toName]!!.mailbox]!!.add(Delivered("f${System.nanoTime()}", Packet.encode(from.name, env)))
    }

    @Test fun membersShareGroupMessages() {
        val id = makeGroup()
        assertEquals(listOf("alice_x", "bob_xyz", "carol_x"), bob.client.groups().single().members.sorted())
        assertEquals("alice_x", carol.client.groups().single().admin)
        bob.client.sendGroup(id, "hi all")
        alice.client.poll(); carol.client.poll()
        assertEquals(listOf("bob_xyz:hi all"), incoming(alice, id))
        assertEquals(listOf("bob_xyz:hi all"), incoming(carol, id))
        assertEquals(listOf("bob_xyz:hi all"), incoming(bob, id))        // own copy too
    }

    @Test fun outsiderCannotInjectIntoGroup() {
        val id = makeGroup()
        forge(dave, "alice_x", """{"t":"g_text","m":"i am not in this","g":"$id"}""")
        val r = alice.client.poll()
        assertEquals(0, r.received); assertEquals(1, r.dropped)
        assertTrue(incoming(alice, id).isEmpty())
    }

    @Test fun onlyTheCreatorCanChangeMembership() {
        val id = makeGroup()
        forge(bob, "alice_x", """{"t":"g_update","g":"$id","gn":"team","gm":["alice_x","bob_xyz"]}""")
        forge(bob, "carol_x", """{"t":"g_update","g":"$id","gn":"team","gm":["bob_xyz","carol_x"]}""")
        alice.client.poll(); carol.client.poll()
        assertEquals(3, alice.client.groups().single().members.size)
        assertEquals(3, carol.client.groups().single().members.size)
        // and a hostile member cannot re-create an existing group to take over as admin
        forge(bob, "carol_x", """{"t":"g_create","g":"$id","gn":"mine","gm":["bob_xyz","carol_x"]}""")
        carol.client.poll()
        assertEquals("alice_x", carol.client.groups().single().admin)
        assertThrows(IllegalStateException::class.java) { bob.client.updateGroup(id, remove = listOf("carol_x")) }
    }

    @Test fun removedMemberLosesGroupAndReceivesNothingFurther() {
        val id = makeGroup()
        val rep = alice.client.updateGroup(id, remove = listOf("carol_x"))
        assertTrue(rep.failed.isEmpty())
        carol.client.poll(); bob.client.poll()
        assertTrue(carol.client.groups().isEmpty())
        assertTrue(carol.client.groupMessages(id).isEmpty())
        assertEquals(2, bob.client.groups().single().members.size)
        alice.client.sendGroup(id, "after removal")
        assertEquals(0, carol.box().size)                                // nothing is even sent to her
        bob.client.poll()
        assertEquals(listOf("alice_x:after removal"), incoming(bob, id))
        // she cannot talk into it either
        forge(carol, "alice_x", """{"t":"g_text","m":"still here?","g":"$id"}""")
        assertEquals(1, alice.client.poll().dropped)
    }

    @Test fun addedMemberJoinsAndSeesLaterMessages() {
        val id = makeGroup()
        alice.client.updateGroup(id, add = listOf("dave_xx"))
        dave.client.poll(); bob.client.poll(); carol.client.poll()
        assertEquals(4, dave.client.groups().single().members.size)
        assertEquals(4, bob.client.groups().single().members.size)
        dave.client.sendGroup(id, "hello from dave")
        alice.client.poll(); bob.client.poll(); carol.client.poll()
        assertEquals(listOf("dave_xx:hello from dave"), incoming(carol, id))
    }

    @Test fun leavingRemovesYouAndTellsOthers() {
        val id = makeGroup()
        bob.client.leaveGroup(id)
        alice.client.poll(); carol.client.poll()
        assertTrue(bob.client.groups().isEmpty())
        assertFalse("bob_xyz" in alice.client.groups().single().members)
        alice.client.sendGroup(id, "bye bob")
        assertEquals(0, bob.box().size)
    }

    @Test fun broadcastSendsIndividualMessagesAndReportsPartialFailure() {
        alice.client.addContact("bob_xyz"); alice.client.addContact("carol_x")
        val rep = alice.client.broadcast(listOf("bob_xyz", "carol_x", "nobody_here"), "announcement")
        assertEquals(listOf("bob_xyz", "carol_x"), rep.sent)
        assertEquals(mapOf("nobody_here" to "not a contact"), rep.failed)
        bob.client.poll(); carol.client.poll()
        assertEquals(listOf("announcement"), bob.client.messages("alice_x").map { it.text })
        assertEquals(listOf("announcement"), carol.client.messages("alice_x").map { it.text })
        assertTrue(bob.client.groups().isEmpty())                       // recipients cannot tell it was a broadcast
    }

    @Test fun disappearingTimerTravelsWithTheMessage() {
        alice.client.addContact("bob_xyz"); alice.client.setDisappearing("bob_xyz", 60)
        alice.client.send("bob_xyz", "temp")
        bob.client.poll()                                               // bob never configured a timer
        val m = bob.client.messages("alice_x").single()
        assertEquals(bob.now + 60_000, m.expiresAt)
        bob.now += 61_000; assertEquals(1, bob.client.purgeExpired())
    }

    @Test fun groupDisappearingTimerAppliesToAllMembers() {
        val id = makeGroup(); alice.client.setGroupDisappearing(id, 30)
        alice.client.sendGroup(id, "short lived"); bob.client.poll()
        assertTrue(bob.client.groupMessages(id).single { !it.system && !it.outgoing }.expiresAt > 0)
    }

    @Test fun malformedOrOutOfBoundsPayloadsAreDropped() {
        val id = makeGroup()
        val bad = listOf(
            """{"t":"text","m":"x","ttl":-5}""", """{"t":"text","m":"x","ttl":99999999999}""", """{"t":"weird"}""",
            """{"t":"g_create","g":"zz","gn":"x","gm":["alice_x","bob_xyz"]}""",
            """{"t":"g_create","g":"${"a".repeat(32)}","gn":"x","gm":["bob_xyz","bob_xyz","alice_x"]}""",
            """{"t":"g_text","m":"","g":"$id"}""", "not json at all", """{"t":"text"}""",
        )
        bad.forEach { forge(dave, "bob_xyz", it) }
        forge(dave, "bob_xyz", "{\"t\":\"text\",\"m\":\"${"x".repeat(4001)}\"}")
        val r = bob.client.poll()
        assertEquals(0, r.received); assertEquals(bad.size + 1, r.dropped)
        assertTrue(bob.client.messages("dave_xx").isEmpty())
    }

    @Test fun groupsSurviveRestart() {
        val id = makeGroup()
        alice.restart(); bob.restart()
        bob.client.sendGroup(id, "after restart"); alice.client.poll()
        assertEquals(listOf("bob_xyz:after restart"), incoming(alice, id))
        assertEquals("alice_x", alice.client.groups().single().admin)
    }

    @Test fun groupInputValidation() {
        assertThrows(IllegalArgumentException::class.java) { alice.client.createGroup("", listOf("bob_xyz")) }
        assertThrows(IllegalArgumentException::class.java) { alice.client.createGroup("g", emptyList()) }
        assertThrows(IllegalArgumentException::class.java) { alice.client.createGroup("g", listOf("alice_x")) }
        assertThrows(IllegalArgumentException::class.java) { alice.client.createGroup("g", listOf("bob_xyz", "bob_xyz")) }
        assertThrows(IllegalArgumentException::class.java) { alice.client.createGroup("g", listOf("Bad Name")) }
        assertThrows(IllegalArgumentException::class.java) { alice.client.sendGroup("00".repeat(16), "x") }
    }
}
