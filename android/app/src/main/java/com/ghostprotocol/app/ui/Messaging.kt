package com.ghostprotocol.app.ui

import android.graphics.BitmapFactory
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
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
import androidx.compose.runtime.produceState
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.foundation.layout.heightIn
import com.ghostprotocol.app.security.UnlockVerifier
import com.ghostprotocol.crypto.AttachmentRef
import com.ghostprotocol.crypto.Group
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
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
    data object Settings : Screen
    data class SetCode(val duress: Boolean) : Screen
    data object NewGroup : Screen
    data object Broadcast : Screen
    data class GroupChat(val id: String) : Screen
    data class Members(val id: String) : Screen
    data class AddMember(val id: String) : Screen
}

/** Everything shown after the calculator is unlocked. */
@Composable
fun MessagingApp(controller: AppController, findings: List<RiskFinding>, onLock: () -> Unit, settings: UnlockVerifier? = null) {
    val phase by controller.phase.collectAsState()
    val notice by controller.notice.collectAsState()
    val busy by controller.busy.collectAsState()
    var screen by remember { mutableStateOf<Screen>(Screen.Contacts) }

    LaunchedEffect(phase) {
        if (phase == Phase.Ready) while (true) { controller.pollOnce(); delay(5_000) }
    }
    DisposableEffect(Unit) { onDispose { controller.lock() } }

    if (screen == Screen.Settings && settings != null) {
        SettingsScreen(settings, onBack = { screen = Screen.Contacts }, onSetCode = { screen = Screen.SetCode(it) }, onWipe = { controller.wipeAll(); screen = Screen.Contacts })
        return
    }
    if (screen is Screen.SetCode && settings != null) {
        val s = screen as Screen.SetCode
        CodeEntryScreen(
            title = if (s.duress) "Set duress code" else "Set decoy code",
            intro = if (s.duress) "Typing this code on the calculator ERASES all real data on this phone at once and then opens the empty decoy profile. It cannot be undone. Pick digits different from your main code."
            else "Typing this code opens a separate, empty profile instead of your real chats. Pick digits different from your main code.",
            onDone = { code ->
                if (code != null) {
                    try { if (s.duress) settings.configureDuress(code) else settings.configureDecoy(code); code.fill('\u0000') } catch (e: Exception) { code.fill('\u0000'); screen = Screen.Settings; return@CodeEntryScreen "That code is not allowed: ${e.message}" }
                }
                screen = Screen.Settings; null
            },
        )
        return
    }
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
            extraLabel = if (settings != null) "Settings" else null, onExtra = { screen = Screen.Settings },
        )
        Phase.Ready -> when (val s = screen) {
            Screen.Contacts -> ContactsScreen(
                controller, findings, onAdd = { screen = Screen.Add }, onOpen = { controller.open(it); screen = Screen.Chat(it) },
                onOpenGroup = { controller.openGroupChat(it); screen = Screen.GroupChat(it) },
                onNewGroup = { screen = Screen.NewGroup }, onBroadcast = { screen = Screen.Broadcast },
                onSettings = if (settings != null) ({ screen = Screen.Settings }) else null, onLock = onLock,
            )
            Screen.Settings, is Screen.SetCode -> Unit   // handled above
            Screen.NewGroup -> PickerScreen(controller, "New group", "Group name", "Create", needText = true, onBack = { screen = Screen.Contacts }) { name, picked -> controller.createGroup(name, picked); screen = Screen.Contacts }
            Screen.Broadcast -> PickerScreen(controller, "Broadcast", "Message", "Send to selected", needText = true, onBack = { screen = Screen.Contacts }) { text, picked -> controller.broadcast(picked, text); screen = Screen.Contacts }
            is Screen.GroupChat -> GroupChatScreen(controller, s.id, onBack = { controller.openGroupChat(null); screen = Screen.Contacts }, onMembers = { screen = Screen.Members(s.id) })
            is Screen.Members -> MembersScreen(controller, s.id, onBack = { screen = Screen.GroupChat(s.id) }, onAdd = { screen = Screen.AddMember(s.id) }, onLeft = { controller.openGroupChat(null); screen = Screen.Contacts })
            is Screen.AddMember -> FormScreen(
                title = "Add member", intro = "Exact username. Only the group creator can add people.",
                fields = listOf(Field("Username", "", 32)), submitLabel = "Add", notice = notice, busy = busy,
                onSubmit = { v -> controller.addToGroup(s.id, v[0]); screen = Screen.Members(s.id) }, onCancel = { screen = Screen.Members(s.id) },
            )
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
    extraLabel: String? = null, onExtra: () -> Unit = {},
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
                if (extraLabel != null) KeyCap(extraLabel, Modifier.weight(1f), fontSize = 16.sp) { onExtra() }
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
private fun ContactsScreen(
    controller: AppController, findings: List<RiskFinding>, onAdd: () -> Unit, onOpen: (String) -> Unit,
    onOpenGroup: (String) -> Unit, onNewGroup: () -> Unit, onBroadcast: () -> Unit, onSettings: (() -> Unit)?, onLock: () -> Unit,
) {
    val contacts by controller.contacts.collectAsState()
    val groups by controller.groups.collectAsState()
    val notice by controller.notice.collectAsState()
    val online by controller.online.collectAsState()
    Column(Modifier.fillMaxSize().background(Bg).systemBarsPadding().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("Chats  ·  ${controller.username ?: ""}", color = Fg, fontSize = 22.sp)
        if (!online) Banner("Relay unreachable. Messages arrive only while the app is open and connected.", danger = false)
        notice?.let { Banner(it, onDismiss = controller::dismissNotice) }
        findings.filter { it.severity == Severity.HIGH }.forEach { Banner("${it.severity}: ${it.message}") }
        LazyColumn(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            if (contacts.isEmpty() && groups.isEmpty()) item { Text("No chats yet. Add a contact by exact username.", color = Muted) }
            items(groups, key = { "g" + it.id }) { g ->
                Row(Modifier.fillMaxWidth().clip(RoundedCornerShape(8.dp)).background(Panel).clickable { onOpenGroup(g.id) }.padding(14.dp)) {
                    Text("👥 " + g.name, color = Fg, fontSize = 17.sp, modifier = Modifier.weight(1f))
                    Text("${g.members.size} members", color = Muted, fontSize = 13.sp)
                }
            }
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
            KeyCap("Add contact", Modifier.weight(1f), fontSize = 14.sp) { onAdd() }
            KeyCap("New group", Modifier.weight(1f), fontSize = 14.sp) { onNewGroup() }
            KeyCap("Broadcast", Modifier.weight(1f), fontSize = 14.sp) { onBroadcast() }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            if (onSettings != null) KeyCap("Settings", Modifier.weight(1f), fontSize = 14.sp) { onSettings() }
            KeyCap("Lock", Modifier.weight(1f), fontSize = 14.sp) { onLock() }
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
            val pick = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri -> if (uri != null) controller.sendAttachmentUri(name, uri) }
            KeyCap("📎", Modifier.weight(0.6f), description = "Attach a file (up to 1 MiB)", fontSize = 16.sp) { pick.launch(arrayOf("*/*")) }
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
            items(messages, key = { it.id }) { m -> Bubble(m, controller) }
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
private fun Bubble(m: StoredMessage, controller: AppController, showAuthor: Boolean = false) {
    if (m.system) {
        Text(m.text, color = Muted, fontSize = 12.sp, modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp), textAlign = androidx.compose.ui.text.style.TextAlign.Center)
        return
    }
    Row(Modifier.fillMaxWidth(), horizontalArrangement = if (m.outgoing) Arrangement.End else Arrangement.Start) {
        Column(Modifier.clip(RoundedCornerShape(10.dp)).background(if (m.outgoing) Mine else Panel).padding(horizontal = 10.dp, vertical = 6.dp)) {
            if (showAuthor && !m.outgoing) Text(m.contact, color = Warn, fontSize = 12.sp)
            val ref = m.attachment
            if (ref != null) AttachmentView(ref, controller) else Text(m.text, color = Fg, fontSize = 16.sp)
            Text(timeFmt.format(Date(m.timestamp)) + if (m.expiresAt > 0) "  ⏱" else "", color = Muted, fontSize = 11.sp)
        }
    }
}

/** Images are decoded in-app (bounded size) and shown only here; other files are listed but cannot leave the app yet. */
@Composable
private fun AttachmentView(ref: AttachmentRef, controller: AppController) {
    if (ref.mime.startsWith("image/")) {
        val bmp = produceState<androidx.compose.ui.graphics.ImageBitmap?>(null, ref.id) {
            value = withContext(Dispatchers.Default) {
                val bytes = controller.attachmentBytes(ref) ?: return@withContext null
                val o = BitmapFactory.Options().apply { inJustDecodeBounds = true }
                BitmapFactory.decodeByteArray(bytes, 0, bytes.size, o)
                if (o.outWidth <= 0 || o.outHeight <= 0 || o.outWidth.toLong() * o.outHeight > 40_000_000L) return@withContext null
                var sample = 1
                while (o.outWidth / sample > 1600 || o.outHeight / sample > 1600) sample *= 2
                BitmapFactory.decodeByteArray(bytes, 0, bytes.size, BitmapFactory.Options().apply { inSampleSize = sample })?.asImageBitmap()
            }
        }.value
        if (bmp != null) { Image(bmp, contentDescription = ref.name, modifier = Modifier.heightIn(max = 220.dp)); return }
    }
    Text("📎 ${ref.name}  (${ref.size / 1024 + 1} KB)", color = Fg, fontSize = 15.sp)
    Text("Stored encrypted inside the app", color = Muted, fontSize = 11.sp)
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


@Composable
private fun SettingsScreen(v: UnlockVerifier, onBack: () -> Unit, onSetCode: (Boolean) -> Unit, onWipe: () -> Unit) {
    var decoy by remember { mutableStateOf(runCatching { v.hasDecoy() }.getOrDefault(false)) }
    var duress by remember { mutableStateOf(runCatching { v.hasDuress() }.getOrDefault(false)) }
    var confirm by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxSize().background(Bg).systemBarsPadding().padding(16.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("Settings", color = Fg, fontSize = 22.sp)
        Text("Decoy code", color = Fg, fontSize = 17.sp)
        Text("A second code that opens an empty, separate profile. Status: " + if (decoy) "set" else "not set", color = Muted, fontSize = 14.sp)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            KeyCap(if (decoy) "Change" else "Set", Modifier.weight(1f), fontSize = 15.sp) { onSetCode(false) }
            if (decoy) KeyCap("Remove", Modifier.weight(1f), fontSize = 15.sp) { v.clearDecoy(); decoy = false }
        }
        Text("Duress code", color = Fg, fontSize = 17.sp)
        Text("A code that silently ERASES all real data on this phone, then shows the decoy profile. Messages already on the relay and your account there are not touched. Status: " + if (duress) "set" else "not set", color = Muted, fontSize = 14.sp)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            KeyCap(if (duress) "Change" else "Set", Modifier.weight(1f), fontSize = 15.sp) { onSetCode(true) }
            if (duress) KeyCap("Remove", Modifier.weight(1f), fontSize = 15.sp) { v.clearDuress(); duress = false }
        }
        val ctx = androidx.compose.ui.platform.LocalContext.current
        var bg by remember { mutableStateOf(com.ghostprotocol.app.background.BackgroundCheck.isEnabled(ctx)) }
        Text("Background check", color = Fg, fontSize = 17.sp)
        Text("While the app is closed, Android checks the relay about every 15 minutes or later (not instant) and shows only \"Calculator got an update\" with no names or text. Status: " + if (bg) "on" else "off", color = Muted, fontSize = 14.sp)
        KeyCap(if (bg) "Turn off" else "Turn on", Modifier.fillMaxWidth(), fontSize = 15.sp) {
            bg = !bg; com.ghostprotocol.app.background.BackgroundCheck.setEnabled(ctx, bg)
        }
        Text("Erase everything now", color = Fg, fontSize = 17.sp)
        Text("Deletes your identity, keys, chats and files from this phone. Cannot be undone.", color = Muted, fontSize = 14.sp)
        KeyCap(if (confirm) "Tap again to erase" else "Erase", Modifier.fillMaxWidth(), container = if (confirm) Color(0xFF6B2323) else Color(0xFF1C1C1F), fontSize = 15.sp) {
            if (confirm) onWipe() else confirm = true
        }
        KeyCap("Back", Modifier.fillMaxWidth(), fontSize = 16.sp) { onBack() }
    }
}

/** Enter a numeric code twice. [onDone] gets the confirmed code (caller zeroes it) or null on cancel, and may return an error to show. */
@Composable
private fun CodeEntryScreen(title: String, intro: String, onDone: (CharArray?) -> String?) {
    val buf = remember { SecureInputBuffer(UnlockVerifier.MAX_LEN) }
    var first by remember { mutableStateOf<CharArray?>(null) }
    var dots by remember { mutableIntStateOf(0) }
    var message by remember { mutableStateOf("Enter ${UnlockVerifier.MIN_LEN}-${UnlockVerifier.MAX_LEN} digits.") }
    val scope = rememberCoroutineScope()
    DisposableEffect(Unit) { onDispose { buf.clear(); first?.fill('\u0000') } }
    Column(Modifier.fillMaxSize().background(Bg).systemBarsPadding().padding(16.dp)) {
        Text(title, color = Fg, fontSize = 24.sp)
        Text(intro, color = Muted, fontSize = 14.sp, modifier = Modifier.padding(top = 8.dp))
        Text(message, color = Warn, modifier = Modifier.padding(top = 8.dp))
        Box(Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center) { Text("•".repeat(dots), color = Fg, fontSize = 36.sp) }
        KeyCap("Cancel", Modifier.fillMaxWidth(), fontSize = 15.sp) { onDone(null) }
        NumericKeypad(onKey = { a ->
            when (a) {
                is KeyAction.Type -> if (buf.append(a.ch)) dots = buf.length
                KeyAction.Backspace -> { buf.deleteLast(); dots = buf.length }
                KeyAction.Space -> Unit
                KeyAction.Enter -> when {
                    buf.length < UnlockVerifier.MIN_LEN -> message = "Too short."
                    first == null -> { first = buf.snapshot(); buf.clear(); dots = 0; message = "Enter the same code again." }
                    else -> {
                        val attempt = buf.snapshot(); val expected = first!!
                        if (attempt.contentEquals(expected)) {
                            expected.fill('\u0000'); first = null; buf.clear(); dots = 0
                            scope.launch { val err = withContext(Dispatchers.Default) { onDone(attempt) }; if (err != null) message = err }
                        } else { attempt.fill('\u0000'); expected.fill('\u0000'); first = null; buf.clear(); dots = 0; message = "Codes did not match. Start again." }
                    }
                }
            }
        })
    }
}

/** Choose contacts with taps and type one line of text with the in-app keyboard (group name or broadcast message). */
@Composable
private fun PickerScreen(
    controller: AppController, title: String, textLabel: String, action: String, needText: Boolean,
    onBack: () -> Unit, onSubmit: (String, List<String>) -> Unit,
) {
    val contacts by controller.contacts.collectAsState()
    val picked = remember { mutableStateListOf<String>() }
    val buf = remember { SecureInputBuffer(if (textLabel == "Message") 2000 else 40) }
    var tick by remember { mutableIntStateOf(0) }
    DisposableEffect(Unit) { onDispose { buf.clear() } }
    Column(Modifier.fillMaxSize().background(Bg).systemBarsPadding().padding(10.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text(title, color = Fg, fontSize = 22.sp)
        Text("Tap contacts to select (${picked.size}).", color = Muted, fontSize = 13.sp)
        LazyColumn(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            items(contacts, key = { it.name }) { c ->
                val on = c.name in picked
                Row(Modifier.fillMaxWidth().clip(RoundedCornerShape(8.dp)).background(if (on) Mine else Panel).clickable { if (on) picked.remove(c.name) else picked.add(c.name) }.padding(12.dp)) {
                    Text((if (on) "☑ " else "☐ ") + c.name, color = Fg, fontSize = 16.sp)
                }
            }
        }
        tick.let {
            Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(8.dp)).background(Panel).padding(10.dp)) {
                Text(textLabel, color = Muted, fontSize = 12.sp)
                Text(buf.asString().ifEmpty { " " }, color = Fg, fontSize = 16.sp)
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            KeyCap("Cancel", Modifier.weight(1f), fontSize = 15.sp) { onBack() }
            KeyCap(action, Modifier.weight(2f), fontSize = 15.sp) { if (picked.isNotEmpty() && (!needText || buf.length > 0)) onSubmit(buf.asString(), picked.toList()) }
        }
        SecureKeyboard(onKey = { a ->
            when (a) {
                is KeyAction.Type -> buf.append(a.ch); KeyAction.Space -> buf.append(' '); KeyAction.Backspace -> buf.deleteLast(); KeyAction.Enter -> Unit
            }
            tick++
        })
    }
}

@Composable
private fun GroupChatScreen(controller: AppController, id: String, onBack: () -> Unit, onMembers: () -> Unit) {
    val messages by controller.messages.collectAsState()
    val groups by controller.groups.collectAsState()
    val notice by controller.notice.collectAsState()
    val group = groups.firstOrNull { it.id == id }
    val buf = remember { SecureInputBuffer(2000) }
    var tick by remember { mutableIntStateOf(0) }
    DisposableEffect(Unit) { onDispose { buf.clear() } }
    val list = rememberLazyListState()
    LaunchedEffect(messages.size) { if (messages.isNotEmpty()) list.scrollToItem(messages.size - 1) }
    if (group == null) { LaunchedEffect(Unit) { onBack() }; return }
    Column(Modifier.fillMaxSize().background(Bg).systemBarsPadding().padding(8.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
            KeyCap("←", Modifier.weight(0.6f), description = "Back", fontSize = 18.sp) { onBack() }
            Text("👥 " + group.name, color = Fg, fontSize = 18.sp, modifier = Modifier.weight(2f))
            KeyCap("⏱ " + (TIMERS.firstOrNull { it.first == group.ttlSeconds }?.second ?: "${group.ttlSeconds}s"), Modifier.weight(1.2f), description = "Disappearing messages timer", fontSize = 13.sp) {
                controller.setGroupDisappearing(id, TIMERS[(TIMERS.indexOfFirst { it.first == group.ttlSeconds } + 1).mod(TIMERS.size)].first)
            }
            KeyCap("Members", Modifier.weight(1.2f), fontSize = 13.sp) { onMembers() }
        }
        notice?.let { Banner(it, onDismiss = controller::dismissNotice) }
        LazyColumn(Modifier.weight(1f), state = list, verticalArrangement = Arrangement.spacedBy(4.dp)) {
            items(messages, key = { it.id }) { m -> Bubble(m, controller, showAuthor = true) }
        }
        tick.let { Text(buf.asString().ifEmpty { "Message the group" }, color = if (buf.length == 0) Muted else Fg, modifier = Modifier.fillMaxWidth().clip(RoundedCornerShape(8.dp)).background(Panel).padding(10.dp), fontSize = 16.sp) }
        SecureKeyboard(onKey = { a ->
            when (a) {
                is KeyAction.Type -> buf.append(a.ch); KeyAction.Space -> buf.append(' '); KeyAction.Backspace -> buf.deleteLast()
                KeyAction.Enter -> if (buf.length > 0) { controller.sendGroup(id, buf.asString()); buf.clear() }
            }
            tick++
        })
    }
}

@Composable
private fun MembersScreen(controller: AppController, id: String, onBack: () -> Unit, onAdd: () -> Unit, onLeft: () -> Unit) {
    val groups by controller.groups.collectAsState()
    val g: Group = groups.firstOrNull { it.id == id } ?: run { LaunchedEffect(Unit) { onLeft() }; return }
    val me = controller.username
    Column(Modifier.fillMaxSize().background(Bg).systemBarsPadding().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(g.name, color = Fg, fontSize = 22.sp)
        Text("Created by ${g.admin}. Only the creator can add or remove people. Each message is encrypted separately for every member.", color = Muted, fontSize = 13.sp)
        LazyColumn(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            items(g.members, key = { it }) { m ->
                Row(Modifier.fillMaxWidth().clip(RoundedCornerShape(8.dp)).background(Panel).padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text(m + if (m == g.admin) "  (creator)" else if (m == me) "  (you)" else "", color = Fg, modifier = Modifier.weight(1f))
                    if (me == g.admin && m != g.admin) Text("Remove", color = Warn, modifier = Modifier.clickable { controller.removeFromGroup(id, m) }.padding(8.dp))
                }
            }
        }
        if (me == g.admin) KeyCap("Add member", Modifier.fillMaxWidth(), fontSize = 15.sp) { onAdd() }
        KeyCap("Leave group", Modifier.fillMaxWidth(), fontSize = 15.sp) { controller.leaveGroup(id); onLeft() }
        KeyCap("Back", Modifier.fillMaxWidth(), fontSize = 15.sp) { onBack() }
    }
}
