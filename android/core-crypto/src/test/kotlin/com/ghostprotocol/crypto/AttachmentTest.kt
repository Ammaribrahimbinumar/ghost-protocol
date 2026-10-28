package com.ghostprotocol.crypto

import java.security.MessageDigest
import java.util.Base64
import org.junit.Assert.*
import org.junit.Test

class AttachmentTest {
    /** Records what is stored/deleted so tests can look at the "disk". */
    private class SpyStore : AttachmentStore {
        val files = HashMap<String, ByteArray>(); val deleted = mutableListOf<String>()
        override fun put(id: String, data: ByteArray) { files[id] = data }
        override fun get(id: String) = files[id]
        override fun delete(id: String) { files.remove(id); deleted += id }
    }
    private class Rig(val name: String, val relay: FakeRelay) {
        val store = SpyStore(); var disk = ByteArray(0); var devDisk = ByteArray(0); var now = 9_000_000L; val sleeps = mutableListOf<Long>()
        var device = LocalDevice.create(name, onChange = { devDisk = it })
        init { relay.register(device) }
        var client = GhostClient(device, relay.api(device), null, { disk = it }, { now }, store, { sleeps += it })
        fun restart() {
            device = LocalDevice.restore(name, devDisk, onChange = { devDisk = it })
            relay.accounts[name] = FakeRelay.Account(relay.accounts[name]!!.mailbox, device)
            client = GhostClient(device, relay.api(device), disk, { disk = it }, { now }, store, { sleeps += it })
        }
        fun box() = relay.boxes[relay.accounts[name]!!.mailbox]!!
    }
    private val relay = FakeRelay()
    private val alice = Rig("alice_x", relay); private val bob = Rig("bob_xyz", relay); private val carol = Rig("carol_x", relay)
    private fun bytes(n: Int, seed: Int = 7) = ByteArray(n).also { java.util.Random(seed.toLong()).nextBytes(it) }
    private fun b64(b: ByteArray) = Base64.getEncoder().encodeToString(b)
    private fun sha(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }
    private fun forge(from: Rig, toName: String, json: String) {
        val toDev = relay.accounts[toName]!!.device
        if (from.client.contacts().none { it.name == toName }) from.client.addContact(toName)
        val env = Messenger(from.device).encrypt(toDev.address, byteArrayOf(2) + json.toByteArray())
        relay.boxes[relay.accounts[toName]!!.mailbox]!!.add(Delivered("f${System.nanoTime()}", Packet.encode(from.name, env)))
    }
    private fun connect() { alice.client.addContact("bob_xyz") }

    @Test fun fileRoundTripsAndIsStoredOnlyEncrypted() {
        connect()
        val data = bytes(100_000); data[0] = 'P'.code.toByte()
        val m = alice.client.sendAttachment("bob_xyz", "plan.png", "image/png", data)
        assertEquals("plan.png", m.attachment!!.name)
        val r = bob.client.poll()
        assertEquals(1, r.received); assertEquals(0, r.dropped)
        val got = bob.client.messages("alice_x").single()
        assertEquals("plan.png", got.text); assertEquals(100_000, got.attachment!!.size); assertEquals("image/png", got.attachment!!.mime)
        assertArrayEquals(data, bob.client.attachmentBytes(got.attachment!!))
        val onDisk = bob.store.files[got.attachment!!.id]!!
        assertFalse("stored bytes must not contain the plaintext", onDisk.toList().windowed(64).any { it == data.toList().take(64) })
        assertTrue(onDisk.size == data.size + 28)
        assertArrayEquals(data, alice.client.attachmentBytes(m.attachment!!))
        assertEquals(0, bob.client.poll().received)
    }

    @Test fun maximumSizeWorksAndBoundsAreEnforced() {
        connect()
        val big = bytes(1 shl 20)
        alice.client.sendAttachment("bob_xyz", "big.bin", "application/octet-stream", big)
        assertEquals(1, bob.client.poll().received)
        assertArrayEquals(big, bob.client.attachmentBytes(bob.client.messages("alice_x").single().attachment!!))
        assertThrows(IllegalArgumentException::class.java) { alice.client.sendAttachment("bob_xyz", "x", "a/b", bytes((1 shl 20) + 1)) }
        assertThrows(IllegalArgumentException::class.java) { alice.client.sendAttachment("bob_xyz", "x", "a/b", ByteArray(0)) }
        assertThrows(IllegalArgumentException::class.java) { alice.client.sendAttachment("bob_xyz", "x", "not a mime", bytes(10)) }
        assertThrows(UnknownContactException::class.java) { alice.client.sendAttachment("carol_x", "x", "a/b", bytes(10)) }
    }

    @Test fun tamperedChunkIsRejectedAndFileNeverAppears() {
        connect()
        alice.client.sendAttachment("bob_xyz", "f.bin", "application/octet-stream", bytes(70_000))
        val box = bob.box()
        val last = box[box.size - 1]
        box[box.size - 1] = Delivered(last.id, last.body.copyOf().also { it[it.size - 5] = (it[it.size - 5].toInt() xor 1).toByte() })
        val r = bob.client.poll()
        assertEquals("poll=$r boxsize=${box.size} msgs=${bob.client.messages("alice_x").size} files=${bob.store.files.size}", 1, r.dropped)
        assertTrue(bob.client.messages("alice_x").isEmpty())
        assertTrue(bob.store.files.isEmpty())
    }

    @Test fun wrongHashOrBadAeadTagIsDropped() {
        val ct = bytes(40)                                              // random: neither a valid GCM message
        val key = b64(bytes(32, 9))
        val cd = "[\"" + b64(ct) + "\"]"
        for ((idx, hash) in listOf("0".repeat(64), sha(ct)).withIndex()) {   // 1st: hash mismatch, 2nd: hash ok but tag fails
            val id = "ab".repeat(15) + "0$idx"
            forge(alice, "bob_xyz", """{"t":"a_meta","a":"$id","fn":"x.bin","mime":"a/b","sz":12,"n":1,"k":"$key","h":"$hash"}""")
            forge(alice, "bob_xyz", """{"t":"a_chunk","a":"$id","i":0,"d":"${b64(ct)}"}""")
        }
        val r = bob.client.poll()
        assertEquals(2, r.dropped)
        assertTrue(bob.client.messages("alice_x").isEmpty()); assertTrue(bob.store.files.isEmpty())
    }

    @Test fun nobodyElseCanAddChunksAndStrayOrBadChunksAreDropped() {
        connect(); carol.client.addContact("bob_xyz")
        val id = "cd".repeat(16)
        forge(alice, "bob_xyz", """{"t":"a_meta","a":"$id","fn":"x.bin","mime":"a/b","sz":50000,"n":2,"k":"${b64(bytes(32))}","h":"${"1".repeat(64)}"}""")
        forge(carol, "bob_xyz", """{"t":"a_chunk","a":"$id","i":0,"d":"${b64(bytes(100))}"}""")                      // wrong sender
        forge(alice, "bob_xyz", """{"t":"a_chunk","a":"${"ee".repeat(16)}","i":0,"d":"${b64(bytes(100))}"}""")         // no such assembly
        forge(alice, "bob_xyz", """{"t":"a_chunk","a":"$id","i":5,"d":"${b64(bytes(100))}"}""")                       // index out of range
        forge(alice, "bob_xyz", """{"t":"a_chunk","a":"$id","i":0,"d":"${b64(bytes(40000))}"}""")                     // oversized chunk
        forge(alice, "bob_xyz", """{"t":"a_chunk","a":"$id","i":0,"d":"!!notbase64!!"}""")
        val r = bob.client.poll()
        assertEquals(0, r.received); assertEquals(5, r.dropped)
        forge(alice, "bob_xyz", """{"t":"a_chunk","a":"$id","i":0,"d":"${b64(bytes(100))}"}""")
        forge(alice, "bob_xyz", """{"t":"a_chunk","a":"$id","i":0,"d":"${b64(bytes(100))}"}""")                       // duplicate
        assertEquals(1, bob.client.poll().dropped)
    }

    @Test fun invalidMetadataIsRejected() {
        val k = b64(bytes(32))
        val bad = listOf(
            """{"t":"a_meta","a":"short","fn":"x","mime":"a/b","sz":10,"n":1,"k":"$k","h":"${"0".repeat(64)}"}""",
            """{"t":"a_meta","a":"${"aa".repeat(16)}","fn":"x","mime":"a/b","sz":10,"n":9,"k":"$k","h":"${"0".repeat(64)}"}""",       // wrong chunk count
            """{"t":"a_meta","a":"${"aa".repeat(16)}","fn":"x","mime":"a/b","sz":5000000,"n":160,"k":"$k","h":"${"0".repeat(64)}"}""", // too big
            """{"t":"a_meta","a":"${"aa".repeat(16)}","fn":"x","mime":"BAD MIME","sz":10,"n":1,"k":"$k","h":"${"0".repeat(64)}"}""",
            """{"t":"a_meta","a":"${"aa".repeat(16)}","fn":"x","mime":"a/b","sz":10,"n":1,"k":"${b64(bytes(16))}","h":"${"0".repeat(64)}"}""", // short key
            """{"t":"a_meta","a":"${"aa".repeat(16)}","fn":"","mime":"a/b","sz":10,"n":1,"k":"$k","h":"${"0".repeat(64)}"}""",
        )
        bad.forEach { forge(alice, "bob_xyz", it) }
        assertEquals(bad.size, bob.client.poll().dropped)
    }

    @Test fun fileNamesCannotEscapeOrCarryControlCharacters() {
        connect()
        alice.client.sendAttachment("bob_xyz", "../../etc/pass\u0007wd", "text/plain", bytes(20))
        alice.client.sendAttachment("bob_xyz", "C:\\Users\\me\\secret.txt", "text/plain", bytes(20))
        bob.client.poll()
        assertEquals(listOf("passwd", "secret.txt"), bob.client.messages("alice_x").map { it.text })
    }

    @Test fun interruptedTransferResumesAfterRestart() {
        connect()
        alice.client.sendAttachment("bob_xyz", "f.bin", "application/octet-stream", bytes(100_000))   // meta + 4 chunks
        val held = bob.box().takeLast(2).toList(); repeat(2) { bob.box().removeAt(bob.box().size - 1) }
        assertEquals(0, bob.client.poll().received)                    // meta + 2 chunks: nothing visible yet
        assertTrue(bob.client.messages("alice_x").isEmpty())
        bob.restart()                                                   // app killed mid-transfer
        bob.box().addAll(held)
        assertEquals(1, bob.client.poll().received)
        assertEquals(100_000, bob.client.messages("alice_x").single().attachment!!.size)
    }

    @Test fun staleIncompleteTransfersExpire() {
        connect()
        alice.client.sendAttachment("bob_xyz", "f.bin", "application/octet-stream", bytes(100_000))
        val last = bob.box().removeAt(bob.box().size - 1)
        bob.client.poll()
        bob.now += 3_700_000
        bob.box().add(last)
        assertEquals(1, bob.client.poll().dropped)                      // assembly was discarded after an hour
        assertTrue(bob.client.messages("alice_x").isEmpty())
    }

    @Test fun deletingOrExpiringMessageDeletesTheEncryptedFile() {
        connect(); alice.client.setDisappearing("bob_xyz", 60)
        alice.client.sendAttachment("bob_xyz", "t.bin", "application/octet-stream", bytes(5_000))
        bob.client.poll()
        val ref = bob.client.messages("alice_x").single().attachment!!
        assertNotNull(bob.store.get(ref.id))
        bob.now += 61_000; assertEquals(1, bob.client.purgeExpired())
        assertNull(bob.store.get(ref.id)); assertTrue(ref.id in bob.store.deleted)
        assertThrows(AttachmentException::class.java) { bob.client.attachmentBytes(ref) }
        alice.client.sendAttachment("bob_xyz", "u.bin", "application/octet-stream", bytes(5_000))
        bob.client.poll()
        val ref2 = bob.client.messages("alice_x").last().attachment!!
        bob.client.deleteChat("alice_x"); assertNull(bob.store.get(ref2.id))
    }

    @Test fun corruptedStoredFileFailsAuthentication() {
        connect()
        alice.client.sendAttachment("bob_xyz", "f.bin", "application/octet-stream", bytes(3_000)); bob.client.poll()
        val ref = bob.client.messages("alice_x").single().attachment!!
        val f = bob.store.files[ref.id]!!; f[f.size / 2] = (f[f.size / 2].toInt() xor 1).toByte()
        assertThrows(AttachmentException::class.java) { bob.client.attachmentBytes(ref) }
    }

    @Test fun relayRateLimitsArePacedAndRetried() {
        connect(); relay.send429 = 3
        alice.client.sendAttachment("bob_xyz", "f.bin", "application/octet-stream", bytes(1_000))
        assertEquals(3, alice.sleeps.size)
        assertEquals(1, bob.client.poll().received)
        relay.send429 = 100
        assertThrows(RelayException::class.java) { alice.client.sendAttachment("bob_xyz", "g.bin", "application/octet-stream", bytes(1_000)) }
        assertEquals(1, alice.client.messages("bob_xyz").count { it.attachment != null })   // failed send is not recorded
    }
}
