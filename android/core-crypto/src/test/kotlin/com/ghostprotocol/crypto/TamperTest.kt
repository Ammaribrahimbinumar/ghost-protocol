package com.ghostprotocol.crypto

import org.junit.Assert.*
import org.junit.Test

/** Flip each bit position of real ciphertexts and require that libsignal refuses every modified message. */
class TamperTest {
    private fun pair(): Triple<LocalDevice, LocalDevice, Pair<Messenger, Messenger>> {
        val a = LocalDevice.create("alice_t"); val b = LocalDevice.create("bob_tt")
        val ma = Messenger(a); val mb = Messenger(b)
        ma.startSession(b.address, b.publicBundle().toPreKeyBundle(b.oneTimePreKeyList().first()))
        return Triple(a, b, ma to mb)
    }
    private fun accepted(tamper: (Envelope) -> Envelope, normal: Boolean): List<Int> {
        // collect positions (by index) where a modified message was still accepted
        val ok = mutableListOf<Int>()
        var size = -1
        var i = 0
        while (size < 0 || i < size) {
            val (a, b, m) = pair(); val (ma, mb) = m
            var env = ma.encrypt(b.address, "payload-0123456789".toByteArray())
            if (normal) {
                mb.decrypt(a.address, env)
                env = ma.encrypt(b.address, "payload-0123456789".toByteArray()).let { e ->
                    val reply = mb.encrypt(a.address, "r".toByteArray()); ma.decrypt(b.address, reply)
                    ma.encrypt(b.address, "payload-0123456789".toByteArray())
                }
            }
            if (size < 0) size = env.bytes.size
            val t = env.bytes.copyOf().also { it[i] = (it[i].toInt() xor 1).toByte() }
            try { mb.decrypt(a.address, Envelope(t)); ok += i } catch (e: Exception) { }
            i++
        }
        return ok
    }
    @Test fun everyBitFlipInAPreKeyMessageIsRejected() {
        val ok = accepted({ it }, normal = false)
        assertTrue("positions accepted after a bit flip: $ok", ok.isEmpty())
    }
    @Test fun everyBitFlipInANormalMessageIsRejected() {
        val ok = accepted({ it }, normal = true)
        assertTrue("positions accepted after a bit flip: $ok", ok.isEmpty())
    }
}
