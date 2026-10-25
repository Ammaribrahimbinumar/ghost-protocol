package com.ghostprotocol.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.TextUnit
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

sealed interface KeyAction {
    data class Type(val ch: Char) : KeyAction
    data object Backspace : KeyAction
    data object Space : KeyAction
    data object Enter : KeyAction
}

/**
 * A single on-screen key. 52dp minimum height keeps the touch target above Android's 48dp guidance.
 */
@Composable
internal fun KeyCap(
    label: String,
    modifier: Modifier = Modifier,
    description: String = label,
    container: Color = Color(0xFF1C1C1F),
    content: Color = Color(0xFFECECEC),
    fontSize: TextUnit = 22.sp,
    onClick: () -> Unit,
) {
    Box(
        modifier = modifier
            .heightIn(min = 52.dp)
            .clip(RoundedCornerShape(10.dp))
            .background(container)
            .clickable(onClickLabel = description, role = androidx.compose.ui.semantics.Role.Button, onClick = onClick)
            .semantics { contentDescription = description },
        contentAlignment = Alignment.Center,
    ) {
        Text(text = label, color = content, fontSize = fontSize)
    }
}

@Composable
internal fun KeyRow(content: @Composable RowScope.() -> Unit) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp), content = content)
}

private val LETTER_ROWS = listOf("qwertyuiop", "asdfghjkl", "zxcvbnm")
private val SYMBOL_ROWS = listOf("1234567890", "-/:;()_&@\"", ".,?!'#%+=")

/**
 * In-app keyboard drawn entirely by this app. No input method editor is ever invoked for message
 * entry: there is no TextField, so Android never shows a third-party keyboard, and nothing typed
 * here reaches an IME's learning, prediction, clipboard or cloud features. It keeps no history and
 * no dictionary. It is not a system keyboard and cannot be used in other apps.
 *
 * Not implemented yet: a language/layout selector (single QWERTY layout only).
 */
@Composable
fun SecureKeyboard(onKey: (KeyAction) -> Unit, modifier: Modifier = Modifier) {
    var shift by remember { mutableStateOf(false) }
    var symbols by remember { mutableStateOf(false) }
    val rows = if (symbols) SYMBOL_ROWS else LETTER_ROWS

    Column(modifier.fillMaxWidth().padding(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
        rows.forEach { row ->
            KeyRow {
                row.forEach { base ->
                    val ch = if (!symbols && shift) base.uppercaseChar() else base
                    KeyCap(ch.toString(), Modifier.weight(1f), fontSize = 20.sp) {
                        onKey(KeyAction.Type(ch))
                        if (shift && !symbols) shift = false
                    }
                }
            }
        }
        KeyRow {
            KeyCap(if (symbols) "ABC" else "123", Modifier.weight(1.3f), fontSize = 16.sp) { symbols = !symbols }
            if (!symbols) {
                KeyCap(
                    "⇧", Modifier.weight(1.3f), description = "Shift",
                    container = if (shift) Color(0xFF3A3A40) else Color(0xFF1C1C1F),
                ) { shift = !shift }
            }
            KeyCap("space", Modifier.weight(4f), fontSize = 16.sp) { onKey(KeyAction.Space) }
            KeyCap("⌫", Modifier.weight(1.3f), description = "Delete") { onKey(KeyAction.Backspace) }
            KeyCap("↵", Modifier.weight(1.3f), description = "Enter") { onKey(KeyAction.Enter) }
        }
    }
}

/** Numeric keypad for PIN entry. */
@Composable
fun NumericKeypad(onKey: (KeyAction) -> Unit, modifier: Modifier = Modifier) {
    val rows = listOf("123", "456", "789")
    Column(modifier.fillMaxWidth().padding(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
        rows.forEach { row ->
            KeyRow {
                row.forEach { d -> KeyCap(d.toString(), Modifier.weight(1f)) { onKey(KeyAction.Type(d)) } }
            }
        }
        KeyRow {
            KeyCap("⌫", Modifier.weight(1f), description = "Delete") { onKey(KeyAction.Backspace) }
            KeyCap("0", Modifier.weight(1f)) { onKey(KeyAction.Type('0')) }
            KeyCap("OK", Modifier.weight(1f), description = "Confirm", fontSize = 18.sp) { onKey(KeyAction.Enter) }
        }
    }
}
