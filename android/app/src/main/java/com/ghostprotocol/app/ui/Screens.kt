package com.ghostprotocol.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ghostprotocol.app.calc.CalculatorController
import com.ghostprotocol.app.security.RiskFinding
import com.ghostprotocol.app.security.SecureInputBuffer
import com.ghostprotocol.app.security.Severity
import com.ghostprotocol.app.security.UnlockVerifier
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private val Bg = Color(0xFF0B0B0C)
private val Fg = Color(0xFFECECEC)
private val Muted = Color(0xFF8A8A90)
private val Accent = Color(0xFF3A3A40)

@Composable
fun GhostTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = darkColorScheme(background = Bg, surface = Bg, onBackground = Fg, onSurface = Fg),
        content = content,
    )
}

/** The disguise. Looks and works like a calculator; "=" on the configured secret opens the app. */
@Composable
fun CalculatorScreen(controller: CalculatorController, onUnlocked: () -> Unit) {
    val display by controller.display.collectAsState()
    val scope = rememberCoroutineScope()
    val rows = listOf(
        listOf("C", "⌫", "(", ")"),
        listOf("7", "8", "9", "÷"),
        listOf("4", "5", "6", "×"),
        listOf("1", "2", "3", "−"),
        listOf("0", ".", "%", "+"),
    )
    Column(Modifier.fillMaxSize().background(Bg).systemBarsPadding().padding(12.dp)) {
        Box(Modifier.weight(1f).fillMaxWidth().padding(8.dp), contentAlignment = Alignment.BottomEnd) {
            Text(display, color = Fg, fontSize = 48.sp, maxLines = 2, textAlign = TextAlign.End)
        }
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            rows.forEach { row ->
                KeyRow {
                    row.forEach { k ->
                        val isOp = k in listOf("÷", "×", "−", "+")
                        KeyCap(
                            k, Modifier.weight(1f),
                            container = if (isOp) Accent else Color(0xFF1C1C1F),
                        ) { controller.press(k) }
                    }
                }
            }
            KeyRow {
                KeyCap("=", Modifier.weight(1f), container = Accent) {
                    scope.launch { if (controller.submit()) onUnlocked() }
                }
            }
        }
    }
}

/** First run: the owner chooses the unlock secret. There is no default. */
@Composable
fun SetupScreen(verifier: UnlockVerifier, onDone: () -> Unit) {
    val buffer = remember { SecureInputBuffer(UnlockVerifier.MAX_LEN) }
    var first by remember { mutableStateOf<CharArray?>(null) }
    var dots by remember { mutableIntStateOf(0) }
    var message by remember { mutableStateOf("Choose an unlock code (${UnlockVerifier.MIN_LEN}-${UnlockVerifier.MAX_LEN} digits).") }
    val scope = rememberCoroutineScope()

    DisposableEffect(Unit) {
        onDispose {
            buffer.clear()
            first?.fill('\u0000')
        }
    }

    Column(Modifier.fillMaxSize().background(Bg).systemBarsPadding().padding(16.dp)) {
        Text("Set up", color = Fg, fontSize = 28.sp)
        Spacer(Modifier.height(8.dp))
        Text(message, color = Muted)
        Text(
            "There is no recovery option. If the code is forgotten, the only fix is clearing the app's data, " +
                "which permanently erases everything stored in it.",
            color = Muted, fontSize = 13.sp, modifier = Modifier.padding(top = 8.dp),
        )
        Box(Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center) {
            Text("•".repeat(dots), color = Fg, fontSize = 36.sp)
        }
        NumericKeypad(onKey = { action ->
            when (action) {
                is KeyAction.Type -> {
                    if (buffer.append(action.ch)) dots = buffer.length
                }
                KeyAction.Backspace -> {
                    buffer.deleteLast()
                    dots = buffer.length
                }
                KeyAction.Space -> Unit
                KeyAction.Enter -> {
                    if (buffer.length < UnlockVerifier.MIN_LEN) {
                        message = "Too short."
                    } else if (first == null) {
                        first = buffer.snapshot()
                        buffer.clear(); dots = 0
                        message = "Enter the same code again to confirm."
                    } else {
                        val attempt = buffer.snapshot()
                        val expected = first!!
                        if (attempt.contentEquals(expected)) {
                            scope.launch {
                                withContext(Dispatchers.Default) { verifier.configure(attempt) }
                                attempt.fill('\u0000'); expected.fill('\u0000')
                                buffer.clear(); first = null
                                onDone()
                            }
                        } else {
                            attempt.fill('\u0000'); expected.fill('\u0000')
                            first = null; buffer.clear(); dots = 0
                            message = "Codes did not match. Start again."
                        }
                    }
                }
            }
        })
    }
}

@Composable
fun StoreCorruptedScreen() {
    Column(Modifier.fillMaxSize().background(Bg).systemBarsPadding().padding(24.dp), verticalArrangement = Arrangement.Center) {
        Text("Local data cannot be verified", color = Fg, fontSize = 22.sp)
        Spacer(Modifier.height(12.dp))
        Text(
            "The stored unlock record is missing, damaged, or its key is gone. The app will not guess or reset " +
                "automatically. Clearing the app's storage in Android Settings starts fresh, and permanently " +
                "erases any local data.",
            color = Muted,
        )
    }
}
