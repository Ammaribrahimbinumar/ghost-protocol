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
import kotlinx.coroutines.flow.first

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
    private var decoyApp: AppController? = null
    private var decoyMode by mutableStateOf(false)
    private fun decoy(): AppController = decoyApp ?: AppController(
        applicationContext, deviceAlias = "ghost_device_state_key_decoy", prefix = "decoy_", signerAlias = "ghost_relay_auth_decoy",
    ).also { it.start(); decoyApp = it }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        SecureWindow.apply(this) // before any content is drawn

        val store = KeystoreSecretStore(File(filesDir, "unlock.rec"), alias = "ghost_unlock_v1")
        val verifier = UnlockVerifier(store)
        controller = CalculatorController(verifier)
        app = (application as GhostApplication).controller

        var corrupted = false
        var configured = false
        try {
            configured = verifier.isConfigured()
        } catch (e: StoreCorruptedException) {
            corrupted = true
        }

        setContent {
            // Once the identity exists: start the periodic check and (Android 13+) ask once to allow the generic notification.
            androidx.compose.runtime.LaunchedEffect(Unit) {
                app.phase.first { it == com.ghostprotocol.app.messaging.Phase.Ready }
                if (com.ghostprotocol.app.background.BackgroundCheck.isEnabled(this@MainActivity)) {
                    com.ghostprotocol.app.background.BackgroundCheck.schedule(this@MainActivity)
                    if (android.os.Build.VERSION.SDK_INT >= 33 && !com.ghostprotocol.app.background.BackgroundCheck.wasAsked(this@MainActivity) &&
                        checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
                        com.ghostprotocol.app.background.BackgroundCheck.markAsked(this@MainActivity)
                        askNotifications.launch(android.Manifest.permission.POST_NOTIFICATIONS)
                    }
                }
            }
            GhostTheme {
                var isConfigured by remember { mutableStateOf(configured) }
                when {
                    corrupted -> StoreCorruptedScreen()
                    !isConfigured -> SetupScreen(verifier) { isConfigured = true }
                    !unlocked -> CalculatorScreen(controller) { outcome ->
                        // Re-scan the environment immediately before revealing anything sensitive.
                        findings = RiskCheck.scan(this@MainActivity)
                        when (outcome) {
                            com.ghostprotocol.app.calc.UnlockOutcome.REAL -> decoyMode = false
                            com.ghostprotocol.app.calc.UnlockOutcome.DECOY -> { decoy(); decoyMode = true }
                            // Duress: erase the real profile immediately and silently, then show the decoy.
                            com.ghostprotocol.app.calc.UnlockOutcome.DURESS -> { app.wipeAll(); decoy(); decoyMode = true }
                            com.ghostprotocol.app.calc.UnlockOutcome.NONE -> Unit
                        }
                        unlocked = true
                    }
                    // Default is warn-only: TalkBack and other legitimate accessibility tools can read the screen,
                    // and blocking them by default would lock out users who rely on them.
                    else -> MessagingApp(
                        if (decoyMode) decoy() else app, findings, onLock = ::lockNow,
                        settings = if (decoyMode) null else verifier,
                    )
                }
            }
        }
    }

    /** Leaving the app always returns to the calculator and wipes input. */
    override fun onStart() { super.onStart(); (application as GhostApplication).inForeground = true }

    override fun onStop() {
        super.onStop()
        (application as GhostApplication).inForeground = false
        lockNow()
    }

    private val askNotifications = registerForActivityResult(androidx.activity.result.contract.ActivityResultContracts.RequestPermission()) { }

    private fun lockNow() {
        unlocked = false
        controller.lock()
        app.lock()
        decoyApp?.lock()
    }
}
