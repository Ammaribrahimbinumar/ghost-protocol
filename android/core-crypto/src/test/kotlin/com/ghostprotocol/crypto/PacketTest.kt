package com.ghostprotocol.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class PacketTest {
    private val env = Envelope(byteArrayOf(3, 1, 2, 3, 4))

    @Test fun roundTrip() {
        val (name, e) = Packet.decode(Packet.encode("alice_01", env))
        assertEquals("alice_01", name)
        assertArrayEquals(env.bytes, e.bytes)
    }

    @Test fun invalidSenderNamesCannotBeEncoded() {
        for (bad in listOf("", "ab", "Alice", "a b c", "x".repeat(33), "ünï")) {
            assertThrows(bad, IllegalArgumentException::class.java) { Packet.encode(bad, env) }
        }
    }

    @Test fun malformedPacketsAreRejected() {
        val good = Packet.encode("alice_01", env)
        val cases = listOf(
            ByteArray(0), byteArrayOf(1), good.copyOf(4), good.copyOf(2 + 8 + 1),
            byteArrayOf(9) + good.copyOfRange(1, good.size),
            byteArrayOf(1, 40) + ByteArray(60) { 'a'.code.toByte() },
            byteArrayOf(1, 3, 'A'.code.toByte(), 'B'.code.toByte(), 'C'.code.toByte(), 1, 2),
        )
        for ((i, c) in cases.withIndex()) {
            assertThrows("case $i", PacketFormatException::class.java) { Packet.decode(c) }
        }
    }

    @Test fun oneTimePreKeyEncoding() {
        val k = OneTimePreKey(77, ByteArray(33) { it.toByte() })
        val d = OneTimePreKey.decode(k.encode())
        assertEquals(77, d.id)
        assertArrayEquals(k.publicKey, d.publicKey)
        assertThrows(BundleFormatException::class.java) { OneTimePreKey.decode(ByteArray(3)) }
    }

    @Test fun relayClientRefusesPlainHttp() {
        assertThrows(IllegalArgumentException::class.java) { RelayClient("http://example.com") }
        assertThrows(IllegalArgumentException::class.java) { RelayClient("http://127.0.0.1:8443") }
        RelayClient("https://relay.example")
        RelayClient("http://127.0.0.1:8443", allowLoopbackHttpForTests = true)
    }
}
