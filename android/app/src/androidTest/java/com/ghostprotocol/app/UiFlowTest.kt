package com.ghostprotocol.app

import android.content.Context
import android.view.WindowManager
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onAllNodesWithContentDescription
import androidx.compose.ui.test.performClick
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.ghostprotocol.app.security.KeystoreRelaySigner
import java.security.KeyStore
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Drives the real MainActivity by tapping on-screen keys: first-run setup, calculator, unlock, forms. */
@RunWith(AndroidJUnit4::class)
class UiFlowTest {
    @get:Rule val rule = createEmptyComposeRule()
    private val ctx: Context = ApplicationProvider.getApplicationContext()
    private val files = listOf("unlock.rec", "device.state", "config.rec", "client.rec")
    private val aliases = listOf("ghost_unlock_v1", "ghost_device_state_key", "ghost_config_v1", "ghost_client_v1")

    private fun wipe() {
        files.forEach { java.io.File(ctx.filesDir, it).delete() }
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        aliases.forEach { if (ks.containsAlias(it)) ks.deleteEntry(it) }
        if (KeystoreRelaySigner.exists()) KeystoreRelaySigner.delete()
    }
    @Before fun setUp() = wipe()
    @After fun tearDown() = wipe()

    private fun tap(desc: String) = rule.onNodeWithContentDescription(desc).performClick()
    private fun type(s: String) = s.forEach { tap(it.toString()) }
    private fun waitFor(text: String) = rule.waitUntil(40_000) { rule.onAllNodesWithText(text).fetchSemanticsNodes().isNotEmpty() }

    @Test fun setupUnlockAndRegistrationFormWork() {
        ActivityScenario.launch(MainActivity::class.java).use { sc ->
            waitFor("Set up")
            type("246802"); tap("Confirm")
            waitFor("Enter the same code again to confirm.")
            type("246802"); tap("Confirm")
            // calculator appears; a wrong code must NOT unlock
            rule.waitUntil(30_000) { rule.onAllNodesWithText("÷").fetchSemanticsNodes().isNotEmpty() }
            type("13579"); tap("=")
            Thread.sleep(2_500)
            assertTrue("wrong code must stay on the calculator", rule.onAllNodesWithText("Join a relay").fetchSemanticsNodes().isEmpty())
            tap("C")
            type("246802"); tap("=")
            waitFor("Join a relay")
            // the registration form takes input from the in-app keyboard only
            rule.onNodeWithText("Username").performClick()
            type("abc"); tap("123"); tap("_"); tap("ABC")
            waitFor("abc_")
            sc.onActivity { act ->
                assertTrue("FLAG_SECURE must still be set after unlock",
                    act.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0)
            }
        }
    }

    @Test fun settingsCanSetDecoyAndDuressCodesAndWrongEntriesAreHandled() {
        ActivityScenario.launch(MainActivity::class.java).use {
            waitFor("Set up"); type("246802"); tap("Confirm"); waitFor("Enter the same code again to confirm."); type("246802"); tap("Confirm")
            rule.waitUntil(30_000) { rule.onAllNodesWithText("÷").fetchSemanticsNodes().isNotEmpty() }
            type("246802"); tap("="); waitFor("Join a relay")
            tap("Settings"); waitFor("Decoy code")
            // decoy: 1357 twice
            rule.onAllNodesWithContentDescription("Set")[0].performClick()
            waitFor("Set decoy code"); type("1357"); tap("Confirm"); waitFor("Enter the same code again."); type("1357"); tap("Confirm")
            waitFor("Decoy code")
            // duress: same digits as the decoy must be refused
            rule.onAllNodesWithContentDescription("Set")[0].performClick()
            waitFor("Set duress code"); type("1357"); tap("Confirm"); waitFor("Enter the same code again."); type("1357"); tap("Confirm")
            waitFor("Decoy code")
            val v = com.ghostprotocol.app.security.UnlockVerifier(com.ghostprotocol.app.security.KeystoreSecretStore(java.io.File(ctx.filesDir, "unlock.rec"), alias = "ghost_unlock_v1"))
            assertTrue(v.hasDecoy()); assertTrue("same digits as decoy must be refused", !v.hasDuress())
            rule.onAllNodesWithContentDescription("Set")[0].performClick()
            waitFor("Set duress code"); type("8642"); tap("Confirm"); waitFor("Enter the same code again."); type("8642"); tap("Confirm")
            waitFor("Decoy code")
            assertTrue(v.hasDuress())
        }
    }
}
