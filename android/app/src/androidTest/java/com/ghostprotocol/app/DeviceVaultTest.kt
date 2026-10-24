package com.ghostprotocol.app

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.ghostprotocol.app.security.DeviceVault
import com.ghostprotocol.app.security.StoreCorruptedException
import com.ghostprotocol.crypto.Messenger
import com.ghostprotocol.crypto.LocalDevice
import java.io.File
import java.security.KeyStore
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** Persistence through the real Android Keystore on an emulator image. Not a physical-device result. */
@RunWith(AndroidJUnit4::class)
class DeviceVaultTest {
    private val ctx: Context = ApplicationProvider.getApplicationContext()
    private val alias = "ghost_device_state_key_test"
    private val name = "vault_test.state"
    private fun vault() = DeviceVault(ctx, alias, name)
    private fun file() = File(ctx.filesDir, name)

    private fun wipe() {
        file().delete()
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.apply { if (containsAlias(alias)) deleteEntry(alias) }
    }
    @Before fun setUp() = wipe()
    @After fun tearDown() = wipe()

    private fun bundleOf(d: LocalDevice) = d.publicBundle().toPreKeyBundle(d.oneTimePreKeyList().first())

    @Test fun identitySurvivesRestartAndConversationContinues() {
        val v1 = vault()
        assertFalse(v1.exists())
        val alice = v1.create("alice")
        val bob = LocalDevice.create("bob")
        Messenger(alice).startSession(bob.address, bundleOf(bob))
        Messenger(bob).decrypt(alice.address, Messenger(alice).encrypt(bob.address, "hi".toByteArray()))
        val idBefore = alice.identityKey

        val v2 = vault() // fresh object = process restart, only the file + Keystore key remain
        assertTrue(v2.exists())
        val alice2 = v2.load("alice")
        assertEquals(idBefore, alice2.identityKey)
        val reply = Messenger(bob).encrypt(alice.address, "back".toByteArray())
        assertEquals("back", String(Messenger(alice2).decrypt(bob.address, reply)))
    }

    @Test fun fileOnDiskContainsNoKeyMaterial() {
        val alice = vault().create("alice")
        val raw = file().readBytes()
        assertTrue(raw.size > 100)
        fun contains(needle: ByteArray) = raw.toList().windowed(needle.size).any { it == needle.toList() }
        assertFalse("public identity key must not appear in clear", contains(alice.identityKey.serialize()))
        assertFalse("magic header must not appear in clear", contains("GPS1".toByteArray()))
    }

    @Test fun tamperedFileIsReportedNotReplaced() {
        vault().create("alice")
        val raw = file().readBytes()
        raw[raw.size / 2] = (raw[raw.size / 2].toInt() xor 1).toByte()
        file().writeBytes(raw)
        assertThrows(StoreCorruptedException::class.java) { vault().load("alice") }
    }

    @Test fun missingKeystoreKeyIsReportedNotReplaced() {
        vault().create("alice")
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(alias)
        assertThrows(StoreCorruptedException::class.java) { vault().load("alice") }
    }

    @Test fun createRefusesToOverwriteExistingIdentity() {
        vault().create("alice")
        assertThrows(IllegalStateException::class.java) { vault().create("alice") }
    }
}
