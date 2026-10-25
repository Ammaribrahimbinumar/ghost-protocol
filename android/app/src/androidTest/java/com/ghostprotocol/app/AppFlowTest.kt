package com.ghostprotocol.app

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ghostprotocol.app.messaging.AppController
import com.ghostprotocol.app.messaging.Phase
import com.ghostprotocol.app.security.KeystoreRelaySigner
import com.ghostprotocol.crypto.EcdsaP256Signer
import com.ghostprotocol.crypto.GhostClient
import com.ghostprotocol.crypto.LocalDevice
import com.ghostprotocol.crypto.RelayClient
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.KeyStore
import java.security.SecureRandom
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The real app controller on an Android emulator talking to the REAL relay process (forwarded with adb reverse):
 * registration with an invitation, receiving, replying, key storage. Skipped unless the relay arguments are passed.
 */
@RunWith(AndroidJUnit4::class)
class AppFlowTest {
    private val ctx: Context = ApplicationProvider.getApplicationContext()
    private val args = InstrumentationRegistry.getArguments()
    private val url = args.getString("relayUrl") ?: "http://127.0.0.1:8443"
    private val token = args.getString("adminToken")
    private val prefix = "apptest_"
    private val deviceAlias = "ghost_device_state_key_apptest"

    @Before fun setUp() { assumeTrue("relay not provided", token != null); wipe() }
    @After fun wipe() {
        ctx.filesDir.listFiles()?.filter { it.name.startsWith(prefix) }?.forEach { it.delete() }
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        ks.aliases().toList().filter { it.endsWith(prefix) || it == deviceAlias }.forEach { ks.deleteEntry(it) }
        if (KeystoreRelaySigner.exists()) KeystoreRelaySigner.delete()
    }

    private fun invite(): String {
        val c = URL("$url/v1/admin/invites").openConnection() as HttpURLConnection
        c.requestMethod = "POST"; c.setRequestProperty("Authorization", "Bearer $token")
        check(c.responseCode == 201) { "invite failed ${c.responseCode}" }
        return JSONObject(String(c.inputStream.readBytes())).getString("invite")
    }
    private fun nm(p: String) = p + "_" + java.lang.Long.toHexString(SecureRandom().nextLong()).take(8)
    private fun controller() = AppController(ctx, { u, s, m -> RelayClient(u, s, m, allowLoopbackHttpForTests = true) }, deviceAlias, prefix)
    private fun <T> StateFlow<T>.await(pred: (T) -> Boolean): T = runBlocking { withTimeout(30_000) { first(pred) } }

    @Test fun registerReceiveReplyOnAndroidThroughRealRelay() {
        val app = controller().also { it.start() }
        app.phase.await { it == Phase.NeedsRegistration }
        val me = nm("me")
        app.register(url, invite(), me)
        app.phase.await { it == Phase.Ready }
        assertEquals(me, app.username)

        // a second user (plain JVM-style client running inside the test process)
        val peerName = nm("peer")
        val signer = EcdsaP256Signer.generateSoftware()
        val relay = RelayClient(url, signer, allowLoopbackHttpForTests = true)
        val dev = LocalDevice.create(peerName)
        relay.register(invite(), peerName, signer.publicKey, dev.publicBundle().encode(), dev.oneTimePreKeyList().map { it.encode() })
        val peer = GhostClient(dev, relay)
        peer.addContact(me); peer.send(me, "hello android")

        runBlocking { app.pollOnce() }
        app.open(peerName)
        assertEquals(listOf("hello android"), app.messages.await { it.isNotEmpty() }.map { it.text })
        assertTrue(app.contacts.value.any { it.name == peerName })
        assertNotNull(app.safetyNumber(peerName))
        assertEquals(app.safetyNumber(peerName), peer.safetyNumber(me))

        app.send(peerName, "reply from phone")
        app.messages.await { m -> m.any { it.outgoing } }
        assertEquals(listOf("reply from phone"), peer.let { it.poll(); it.messages(me).filter { m -> !m.outgoing }.map { m -> m.text } })

        // restart: everything comes back from encrypted storage
        val app2 = controller().also { it.start() }
        app2.phase.await { it == Phase.Ready }
        app2.open(peerName)
        assertEquals(2, app2.messages.await { it.size == 2 }.size)
        app2.lock()
        assertTrue("lock must clear readable state", app2.messages.value.isEmpty())
    }

    @Test fun failedRegistrationLeavesNoIdentityBehind() {
        val app = controller().also { it.start() }
        app.phase.await { it == Phase.NeedsRegistration }
        app.register(url, "definitely-not-a-valid-invite", nm("me"))
        app.notice.await { it != null }
        assertEquals(Phase.NeedsRegistration, app.phase.value)
        assertFalse(File(ctx.filesDir, prefix + "device.state").exists())
        assertFalse(File(ctx.filesDir, prefix + "config.rec").exists())
        assertFalse(KeystoreRelaySigner.exists())
    }
}
