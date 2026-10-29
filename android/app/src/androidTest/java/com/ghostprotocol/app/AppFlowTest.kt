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

    private fun register(app: AppController, me: String) {
        app.phase.await { it == Phase.NeedsRegistration }
        app.register(url, invite(), me)
        app.phase.await { it == Phase.Ready }
    }
    private fun peer(): GhostClient {
        val name = nm("peer"); val signer = EcdsaP256Signer.generateSoftware()
        val relay = RelayClient(url, signer, allowLoopbackHttpForTests = true)
        val dev = LocalDevice.create(name)
        relay.register(invite(), name, signer.publicKey, dev.publicBundle().encode(), dev.oneTimePreKeyList().map { it.encode() })
        return GhostClient(dev, relay)
    }

    @Test fun fileArrivesEncryptedOnDiskAndDecryptsOnAndroid() {
        val app = controller().also { it.start() }; val me = nm("me"); register(app, me)
        val p = peer(); p.addContact(me)
        val data = ByteArray(150_000).also { java.util.Random(3).nextBytes(it) }
        p.sendAttachment(me, "pic.bin", "application/octet-stream", data)
        runBlocking { app.pollOnce() }
        app.open(p.username)
        val ref = app.messages.await { it.any { m -> m.attachment != null } }.first { it.attachment != null }.attachment!!
        assertArrayEquals(data, app.attachmentBytes(ref))
        val f = File(ctx.filesDir, prefix + "attachments/" + ref.id)
        assertTrue(f.exists()); assertEquals(data.size + 28L, f.length())
        assertFalse("plaintext must not be on disk", f.readBytes().toList().windowed(32).any { it == data.toList().take(32) })
    }

    @Test fun groupConversationAcrossAndroidAndTwoPeers() {
        val app = controller().also { it.start() }; val me = nm("me"); register(app, me)
        val a = peer(); val b = peer()
        a.addContact(me); b.addContact(me)
        val (g, rep) = a.createGroup("crew", listOf(me, b.username))
        assertTrue(rep.failed.isEmpty())
        runBlocking { app.pollOnce() }
        val gid = app.groups.await { it.isNotEmpty() }.single().id
        assertEquals(g.id, gid)
        app.openGroupChat(gid)
        app.sendGroup(gid, "from the phone")
        app.messages.await { m -> m.any { it.outgoing && !it.system } }
        a.poll(); b.poll()
        assertEquals(listOf("from the phone"), a.groupMessages(gid).filter { !it.system && !it.outgoing }.map { it.text })
        assertEquals(listOf("from the phone"), b.groupMessages(gid).filter { !it.system && !it.outgoing }.map { it.text })
    }

    @Test fun eraseEverythingRemovesFilesAndKeysAndLateWritesDoNotBringThemBack() {
        val app = controller().also { it.start() }; val me = nm("me"); register(app, me)
        val p = peer(); p.addContact(me); p.sendAttachment(me, "x.bin", "application/octet-stream", ByteArray(5_000) { 1 })
        runBlocking { app.pollOnce() }
        assertTrue(File(ctx.filesDir, prefix + "device.state").exists() && File(ctx.filesDir, prefix + "client.rec").exists())
        app.wipeAll()
        assertEquals(Phase.NeedsRegistration, app.phase.value)
        assertTrue(app.contacts.value.isEmpty() && app.messages.value.isEmpty())
        for (f in listOf("device.state", "config.rec", "client.rec")) assertFalse("$f must be gone", File(ctx.filesDir, prefix + f).exists())
        assertFalse(File(ctx.filesDir, prefix + "attachments").exists())
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertTrue("all profile keys must be gone", ks.aliases().toList().none { it.endsWith(prefix) || it == deviceAlias || it == KeystoreRelaySigner.ALIAS })
        runBlocking { app.pollOnce() }                               // late work after the wipe must not recreate anything
        assertFalse(File(ctx.filesDir, prefix + "client.rec").exists())
        // and a fresh identity can be created afterwards
        app.register(url, invite(), nm("again")); app.phase.await { it == Phase.Ready }
    }
}
