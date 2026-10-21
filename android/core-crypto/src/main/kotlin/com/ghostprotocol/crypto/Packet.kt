package com.ghostprotocol.crypto

class PacketFormatException(message: String) : Exception(message)

/**
 * What is actually posted to a recipient's mailbox: version byte, sender username, then the
 * libsignal envelope. The sender name is needed so the recipient can pick the right session.
 *
 * METADATA NOTE: the sender name is visible to the relay in clear. (The relay already sees which
 * mailbox sent the request.) Sealed sender would hide it and is NOT IMPLEMENTED.
 * The name is only a lookup hint: a forged name makes decryption fail, it cannot impersonate.
 */
object Packet {
    private const val VERSION = 1
    private val NAME = Regex("^[a-z0-9_]{3,32}$")

    fun encode(senderName: String, envelope: Envelope): ByteArray {
        require(NAME.matches(senderName)) { "invalid sender name" }
        val n = senderName.toByteArray(Charsets.US_ASCII)
        return byteArrayOf(VERSION.toByte(), n.size.toByte()) + n + envelope.bytes
    }

    fun decode(data: ByteArray): Pair<String, Envelope> {
        if (data.size < 3 + 2) throw PacketFormatException("too short")
        if (data[0].toInt() != VERSION) throw PacketFormatException("unknown version")
        val len = data[1].toInt() and 0xFF
        if (len < 3 || len > 32 || data.size < 2 + len + 2) throw PacketFormatException("bad sender length")
        val name = String(data, 2, len, Charsets.US_ASCII)
        if (!NAME.matches(name)) throw PacketFormatException("bad sender name")
        return name to Envelope(data.copyOfRange(2 + len, data.size))
    }
}
