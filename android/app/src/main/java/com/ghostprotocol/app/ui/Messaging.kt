package com.ghostprotocol.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ghostprotocol.app.messaging.AppController
import com.ghostprotocol.app.messaging.Phase
import com.ghostprotocol.app.security.RiskFinding
import com.ghostprotocol.app.security.SecureInputBuffer
import com.ghostprotocol.app.security.Severity
import com.ghostprotocol.crypto.Contact
import com.ghostprotocol.crypto.StoredMessage
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlinx.coroutines.delay

private val Bg = Color(0xFF0B0B0C)
private val Fg = Color(0xFFECECEC)
private val Muted = Color(0xFF8A8A90)
private val Warn = Color(0xFFE5A04B)
private val Panel = Color(0xFF1C1C1F)
private val Mine = Color(0xFF2B3A55)

private sealed interface Screen {
    data object Contacts : Screen
    data object Add : Screen
    data class Chat(val name: String) : Screen
    data class Safety(val name: String) : Screen
}

/** Everything shown after the calculator is unlocked. */
@Composable
fun MessagingApp(controller: AppController, findings: List<RiskFinding>, onLock: () -> Unit) {
    val phase by controller.phase.collectAsState()
    val notice by controller.notice.collectAsState()
    val busy by controller.busy.collectAsState()
    var screen by remember { mutableStateOf<Screen>(Screen.Contacts) }

    LaunchedEffect(phase) {
        if (phase == Phase.Ready) while (true) { controller.pollOnce(); delay(5_000) }
    }
    DisposableEffect(Unit) { onDispose { controller.lock() } }

    when (val p = phase) {
        Phase.Loading -> Centered("Loading…")
        is Phase.Broken -> Column(Modifier.fillMaxSize().background(Bg).systemBarsPadding().padding(24.dp), verticalArrangement = Arrangement.Center) {
            Text("Cannot continue", color = Fg, fontSize = 22.sp)
            Spacer(Modifier.height(12.dp))
            Text(p.reason + " The app will not create a new identity on its own. Clearing the app's storage in Android Settings starts fresh and erases local data.", color = Muted)
            Spacer(Modifier.height(16.dp))
            KeyCap("Lock", Modifier.fillMaxWidth(), fontSize = 18.sp) { onLock() }
        }
        Phase.NeedsRegistration -> FormScreen(
            title = "Join a relay",
            intro = "You need the relay address and a single-use invitation code from whoever runs it. No phone number or email is used. Pick a username (a-z, 0-9, _).",
            fields = listOf(Field("Relay address", "https://…", 120), Field("Invitation code", "", 100), Field("Username", "", 32)),
            submitLabel = "Register", notice = notice, busy = busy,
            onSubmit = { v -> controller.register(v[0], v[1], v[2]) },
            onCancel = onLock,
        )
        Phase.Ready -> when (val s = screen) {
            Screen.Contacts -> ContactsScreen(controller, findings, onAdd = { screen = Screen.Add }, onOpen = { controller.open(it); screen = Screen.Chat(it) }, onLock = onLock)
            Screen.Add -> FormScreen(
                title = "Add contact", intro = "Enter their exact username. There is no search; the relay cannot list users.",
                fields = listOf(Field("Username", "", 32)), submitLabel = "Add", notice = notice, busy = busy,
                onSubmit = { v -> controller.addContact(v[0]); screen = Screen.Contacts }, onCancel = { screen = Screen.Contacts },
            )
            is Screen.Chat -> ChatScreen(controller, s.name, onBack = { controller.open(null); screen = Screen.Contacts }, onSafety = { screen = Screen.Safety(s.name) })
            is Screen.Safety -> SafetyScreen(controller, s.name, onBack = { screen = Screen.Chat(s.name) })
        }
    }
}

@Composable private fun Centered(text: String) =
    Box(Modifier.fillMaxSize().background(Bg), contentAlignment = Alignment.Center) { Text(text, color = Muted) }

@Composable private fun Banner(text: String, onDismiss: (() -> Unit)? = null, danger: Boolean = true) {
    Row(Modifier.fillMaxWidth().clip(RoundedCornerShape(8.dp)).background(Panel).padding(10.dp)) {
        Text(text, color = if (danger) Warn else Muted, modifier = Modifier.weight(1f), fontSize = 14.sp)
        if (onDismiss != null) Text("✕", color = Muted, modifier = Modifier.clickable { onDismiss() }.padding(start = 12.dp))
    }
}

class Field(val label: String, val hint: String, val max: Int)

/** Text entry using only the in-app keyboard (no TextField, so no system IME ever sees the input). */
@Composable
fun FormScreen(
    title: String, intro: String, fields: List<Field>, submitLabel: String,
    notice: String?, busy: Boolean, onSubmit: (List<String>) -> Unit, onCancel: () -> Unit,
) {
    val buffers = remember { fields.map { SecureInputBuffer(it.max) } }
    var active by remember { mutableIntStateOf(0) }
    var tick by remember { mutableIntStateOf(0) }
    DisposableEffect(Unit) { onDispose { buffers.forEach { it.clear() } } }

    Column(Modifier.fillMaxSize().background(Bg).systemBarsPadding().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Column(Modifier.weight(1f).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(title, color = Fg, fontSize = 22.sp)
            Text(intro, color = Muted, fontSize = 14.sp)
            notice?.let { Banner(it) }
            fields.forEachIndexed { i, f ->
                tick.let {
                    Column(
                        Modifier.fillMaxWidth().clip(RoundedCornerShape(8.dp))
                            .background(if (i == active) Color(0xFF26262B) else Panel)
                            .clickable { active = i }.padding(10.dp),
                    ) {
                        Text(f.label, color = Muted, fontSize = 12.sp)
                        val v = buffers[i].asString()
                        Text(if (v.isEmpty()) f.hint.ifEmpty { " " } else v, color = if (v.isEmpty()) Muted else Fg, fontSize = 16.sp)
                    }
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                KeyCap("Cancel", Modifier.weight(1f), fontSize = 16.sp) { onCancel() }
                KeyCap(if (busy) "Working…" else submitLabel, Modifier.weight(1f), fontSize = 16.sp) {
                    if (!busy) onSubmit(buffers.map { it.asString() })
                }
            }
        }
        SecureKeyboard(onKey = { a ->
            val b = buffers[active]
            when (a) {
                is KeyAction.Type -> b.append(a.ch)
                KeyAction.Space -> b.append(' ')
                KeyAction.Backspace -> b.deleteLast()
                KeyAction.Enter -> if (active < fields.size - 1) active++ else if (!busy) onSubmit(buffers.map { it.asString() })
            }
            tick++
        })
    }
}

@Composable
private fun ContactsScreen(controller: AppController, findings: List<RiskFinding>, onAdd: () -> Unit, onOpen: (String) -> Unit, onLock: () -> Unit) {
    val contacts by controller.contacts.collectAsState()
    val notice by controller.notice.collectAsState()
    val online by controller.online.collectAsState()
    Column(Modifier.fillMaxSize().background(Bg).systemBarsPadding().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("Chats  ·  ${controller.username ?: ""}", color = Fg, fontSize = 22.sp)
        if (!online) Banner("Relay unreachable. Messages arrive only while the app is open and connected.", danger = false)
        notice?.let { Banner(it, onDismiss = controller::dismissNotice) }
        findings.filter { it.severity == Severity.HIGH }.forEach { Banner("${it.severity}: ${it.message}") }
        LazyColumn(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            if (contacts.isEmpty()) item { Text("No contacts yet. Add one by exact username.", color = Muted) }
            items(contacts, key = { it.name }) { c ->
                Row(Modifier.fillMaxWidth().clip(RoundedCornerShape(8.dp)).background(Panel).clickable { onOpen(c.name) }.padding(14.dp)) {
                    Text(c.name, color = Fg, fontSize = 17.sp, modifier = Modifier.weight(1f))
                    Text(
                        when { c.keyChanged -> "⚠ key changed"; c.verified -> "✓ verified"; else -> "unverified" },
                        color = if (c.keyChanged) Warn else Muted, fontSize = 13.sp,
                    )
                }
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            KeyCap("Add contact", Modifier.weight(1f), fontSize = 16.sp) { onAdd() }
            KeyCap("Lock", Modifier.weight(1f), fontSize = 16.sp) { onLock() }
        }
    }
}

private val TIMERS = listOf(0L to "off", 60L to "1 min", 3600L to "1 hour", 86400L to "1 day")
private val timeFmt = SimpleDateFormat("HH:mm", Locale.getDefault())

@Composable
private fun ChatScreen(controller: AppController, name: String, onBack: () -> Unit, onSafety: () -> Unit) {
    val messages by controller.messages.collectAsState()
    val contacts by controller.contacts.collectAsState()
    val notice by controller.notice.collectAsState()
    val contact = contacts.firstOrNull { it.name == name }
    val buf = remember { SecureInputBuffer(2000) }
    var tick by remember { mutableIntStateOf(0) }
    DisposableEffect(Unit) { onDispose { buf.clear() } }
    val list = rememberLazyListState()
    LaunchedEffect(messages.size) { if (messages.isNotEmpty()) list.scrollToItem(messages.size - 1) }

    Column(Modifier.fillMaxSize().background(Bg).systemBarsPadding().padding(8.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
            KeyCap("←", Modifier.weight(0.6f), description = "Back", fontSize = 18.sp) { onBack() }
            Text(name + if (contact?.verified == true) "  ✓" else "", color = Fg, fontSize = 18.sp, modifier = Modifier.weight(2f))
            KeyCap("Safety #", Modifier.weight(1.2f), fontSize = 13.sp) { onSafety() }
            val ttl = contact?.ttlSeconds ?: 0
            KeyCap("⏱ " + (TIMERS.firstOrNull { it.first == ttl }?.second ?: "${ttl}s"), Modifier.weight(1.2f), description = "Disappearing messages timer", fontSize = 13.sp) {
                val next = TIMERS[(TIMERS.indexOfFirst { it.first == ttl } + 1).mod(TIMERS.size)].first
                controller.setDisappearing(name, next)
            }
        }
        if (contact?.keyChanged == true) Banner("This contact's security key changed. Sending is blocked until you review the safety number.")
        else if (contact?.verified == false) Banner("Not verified. Compare the safety number with them in person or on another channel.", danger = false)
        notice?.let { Banner(it, onDismiss = controller::dismissNotice) }
        LazyColumn(Modifier.weight(1f), state = list, verticalArrangement = Arrangement.spacedBy(4.dp)) {
            items(messages, key = { it.id }) { m -> Bubble(m) }
        }
        tick.let {
            Text(buf.asString().ifEmpty { "Message" }, color = if (buf.length == 0) Muted else Fg,
                modifier = Modifier.fillMaxWidth().clip(RoundedCornerShape(8.dp)).background(Panel).padding(10.dp), fontSize = 16.sp)
        }
        SecureKeyboard(onKey = { a ->
            when (a) {
                is KeyAction.Type -> buf.append(a.ch)
                KeyAction.Space -> buf.append(' ')
                KeyAction.Backspace -> buf.deleteLast()
                KeyAction.Enter -> if (buf.length > 0) { controller.send(name, buf.asString()); buf.clear() }
            }
            tick++
        })
    }
}

@Composable
private fun Bubble(m: StoredMessage) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = if (m.outgoing) Arrangement.End else Arrangement.Start) {
        Column(Modifier.clip(RoundedCornerShape(10.dp)).background(if (m.outgoing) Mine else Panel).padding(horizontal = 10.dp, vertical = 6.dp)) {
            Text(m.text, color = Fg, fontSize = 16.sp)
            Text(timeFmt.format(Date(m.timestamp)) + if (m.expiresAt > 0) "  ⏱" else "", color = Muted, fontSize = 11.sp)
        }
    }
}

@Composable
private fun SafetyScreen(controller: AppController, name: String, onBack: () -> Unit) {
    val contacts by controller.contacts.collectAsState()
    val contact = contacts.firstOrNull { it.name == name }
    val number = remember(contact?.keyChanged, contact?.verified) { controller.safetyNumber(name) }
    Column(Modifier.fillMaxSize().background(Bg).systemBarsPadding().padding(16.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("Safety number with $name", color = Fg, fontSize = 22.sp)
        Text("Both of you should see exactly the same numbers. Compare them in person or over a different channel (a call). If they match, nobody is intercepting your chat.", color = Muted, fontSize = 14.sp)
        Text(number?.chunked(5)?.chunked(4)?.joinToString("\n") { it.joinToString("  ") } ?: "Not available yet. Add the contact and exchange a message first.",
            color = Fg, fontSize = 20.sp, lineHeight = 30.sp)
        if (contact?.keyChanged == true) {
            Banner("This contact's key CHANGED since you last talked. That happens when they reinstall or get a new phone, but it is also what an interception attempt looks like. Verify with them first.")
            KeyCap("Accept new key (resets verification)", Modifier.fillMaxWidth(), fontSize = 15.sp) { controller.acceptKeyChange(name) }
        } else if (number != null) {
            KeyCap(if (contact?.verified == true) "Verified ✓" else "Mark as verified", Modifier.fillMaxWidth(), fontSize = 16.sp) { controller.markVerified(name) }
        }
        KeyCap("Back", Modifier.fillMaxWidth(), fontSize = 16.sp) { onBack() }
    }
}
