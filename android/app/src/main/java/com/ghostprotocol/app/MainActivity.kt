package com.ghostprotocol.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import com.ghostprotocol.app.calc.CalculatorController
import com.ghostprotocol.app.security.KeystoreSecretStore
import com.ghostprotocol.app.security.RiskCheck
import com.ghostprotocol.app.security.RiskFinding
import com.ghostprotocol.app.security.RiskPolicy
import com.ghostprotocol.app.security.SecureWindow
import com.ghostprotocol.app.security.StoreCorruptedException
import com.ghostprotocol.app.security.UnlockVerifier
import com.ghostprotocol.app.ui.CalculatorScreen
import com.ghostprotocol.app.ui.GhostTheme
import com.ghostprotocol.app.ui.SetupScreen
import com.ghostprotocol.app.ui.StoreCorruptedScreen
import com.ghostprotocol.app.ui.MessagingApp
import com.ghostprotocol.app.messaging.AppController
import java.io.File

/**
 * Phase 1 entry point: calculator -> (secret) -> unlocked placeholder.
 *
 * NOT COMPILED OR RUN. See docs/FEATURE_REPORT.md.
 */
class MainActivity : ComponentActivity() {
    private var unlocked by mutableStateOf(false)
    private var findings by mutableStateOf<List<RiskFinding>>(emptyList())
    private lateinit var controller: CalculatorController
    private lateinit var app: AppController

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        SecureWindow.apply(this) // before any content is drawn

        val store = KeystoreSecretStore(File(filesDir, "unlock.rec"), alias = "ghost_unlock_v1")
        val verifier = UnlockVerifier(store)
        controller = CalculatorController(verifier)
        app = AppController(applicationContext).also { it.start() }

        var corrupted = false
        var configured = false
        try {
            configured = verifier.isConfigured()
        } catch (e: StoreCorruptedException) {
            corrupted = true
        }

        setContent {
            GhostTheme {
                var isConfigured by remember { mutableStateOf(configured) }
                when {
                    corrupted -> StoreCorruptedScreen()
                    !isConfigured -> SetupScreen(verifier) { isConfigured = true }
                    !unlocked -> CalculatorScreen(controller) {
                        // Re-scan the environment immediately before revealing anything sensitive.
                        findings = RiskCheck.scan(this@MainActivity)
                        unlocked = true
                    }
                    // Default is warn-only: TalkBack and other legitimate accessibility tools can read the screen,
                    // and blocking them by default would lock out users who rely on them.
                    else -> MessagingApp(app, findings, onLock = ::lockNow)
                }
            }
        }
    }

    /** Leaving the app always returns to the calculator and wipes input. */
    override fun onStop() {
        super.onStop()
        lockNow()
    }

    private fun lockNow() {
        unlocked = false
        controller.lock()
        app.lock()
    }
}
