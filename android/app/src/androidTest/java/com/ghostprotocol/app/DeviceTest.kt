package com.ghostprotocol.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.ghostprotocol.app.security.KeystoreRelaySigner
import com.ghostprotocol.crypto.LocalDevice
import com.ghostprotocol.crypto.Messenger
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Runs on a real Android system image (emulator in CI). Not a substitute for a physical phone. */
@RunWith(AndroidJUnit4::class)
class DeviceTest {
    @After fun cleanup() { KeystoreRelaySigner.delete() }

    @Test fun keystoreSignerProducesValidP256Signature() {
        val signer = KeystoreRelaySigner.getOrCreate()
        val msg = "GET\n/v1/inbox\n1\nnonce\nabc".toByteArray()
        val sig = signer.sign(msg)
        val pub = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(signer.publicKey))
        val ok = Signature.getInstance("SHA256withECDSA").apply { initVerify(pub); update(msg) }.verify(sig)
        assertTrue("signature must verify with the exported SPKI public key", ok)
    }

    @Test fun keystoreKeyIsStableAndNotExportable() {
        val a = KeystoreRelaySigner.getOrCreate().publicKey
        val b = KeystoreRelaySigner.getOrCreate().publicKey
        assertArrayEquals(a, b)
        val ks = java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val priv = ks.getKey("ghost_relay_auth_p256", null)
        assertNull("private key material must not be extractable", priv.encoded)
    }

    @Test fun libsignalNativeLibraryLoadsAndRoundTripsOnAndroid() {
        val alice = LocalDevice.create("alice"); val bob = LocalDevice.create("bob")
        val a = Messenger(alice); val b = Messenger(bob)
        a.startSession(bob.address, bob.publicBundle().toPreKeyBundle(bob.oneTimePreKeyList().first()))
        val env = a.encrypt(bob.address, "hello from android".toByteArray())
        assertTrue(env.isPreKeyMessage)
        assertEquals("hello from android", String(b.decrypt(alice.address, env)))
        val reply = b.encrypt(alice.address, "reply".toByteArray())
        assertEquals("reply", String(a.decrypt(bob.address, reply)))
    }
}
