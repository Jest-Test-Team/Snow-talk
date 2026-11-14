@file:OptIn(ExperimentalLayoutApi::class)

package app.snowtalk.android

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import uniffi.snow_core.ChatMessage
import uniffi.snow_core.ChatState
import uniffi.snow_core.EndReason
import uniffi.snow_core.PeerEvent
import uniffi.snow_core.SafetyLevel
import uniffi.snow_core.TagCategory
import java.util.Locale

@Composable
fun SnowApp(vm: ChatViewModel) {
    val s by vm.ui.collectAsStateWithLifecycle()
    if (!vm.onboarded) {
        Onboarding(onDone = vm::finishOnboarding)
        return
    }
    Box(Modifier.fillMaxSize().safeDrawingPadding()) {
        when (val st = s.chat) {
            null -> HomeScreen(vm, s)
            is ChatState.Ended -> EndedScreen(vm, st.reason, s)
            ChatState.Chatting, is ChatState.Reconnecting -> ChatScreen(vm, s)
            else -> WaitingScreen(vm, st, s)
        }
    }
    if (s.error == "server") {
        AlertDialog(
            onDismissRequest = vm::dismissError,
            confirmButton = { TextButton(onClick = vm::dismissError) { Text(stringResource(R.string.ok)) } },
            text = { Text(stringResource(R.string.error_server)) },
        )
    }
}

@Composable
private fun HomeScreen(vm: ChatViewModel, s: UiState) {
    var advanced by rememberSaveable { mutableStateOf(vm.serverUrl.isBlank()) }
    var picking by rememberSaveable { mutableStateOf(false) }
    if (picking) {
        TagPicker(vm) { picking = false }
        return
    }
    Column(
        Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Spacer(Modifier.height(24.dp))
        Text("Snow-talk", style = MaterialTheme.typography.headlineLarge, fontWeight = FontWeight.Bold)
        Text(stringResource(R.string.tagline), style = MaterialTheme.typography.bodyMedium)
        TextButton(onClick = vm::replayOnboarding) { Text(stringResource(R.string.how_privacy)) }
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(
            value = vm.nickname,
            onValueChange = { vm.nickname = it.take(32) },
            label = { Text(stringResource(R.string.nickname)) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        Text(stringResource(R.string.tags), style = MaterialTheme.typography.titleSmall)
        if (vm.selectedTags.isEmpty()) {
            Text(stringResource(R.string.tags_hint), style = MaterialTheme.typography.bodySmall)
        } else {
            FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                for (key in vm.selectedTags) {
                    FilterChip(selected = true, onClick = { vm.toggleTag(key) }, label = { Text(tagLabel(vm, key)) })
                }
            }
        }
        OutlinedButton(onClick = { picking = true }) {
            Text(stringResource(R.string.pick_tags, vm.selectedTags.size, vm.maxTagCount))
        }
        TextButton(onClick = { advanced = !advanced }) { Text(stringResource(R.string.advanced)) }
        if (advanced) {
            OutlinedTextField(
                value = vm.serverUrl,
                onValueChange = { vm.serverUrl = it },
                label = { Text(stringResource(R.string.server)) },
                placeholder = { Text("https://relay.example  /  http://192.168.x.x:8787") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(stringResource(R.string.tor))
                    Text(stringResource(R.string.tor_hint), style = MaterialTheme.typography.bodySmall)
                }
                Switch(checked = vm.useTor, onCheckedChange = { vm.useTor = it })
            }
        }
        Spacer(Modifier.weight(1f))
        Text(
            stringResource(R.string.good_tokens, s.goodTokens),
            style = MaterialTheme.typography.bodySmall,
        )
        Button(onClick = vm::start, modifier = Modifier.fillMaxWidth().height(52.dp)) {
            Text(stringResource(R.string.start))
        }
    }
}

private val zh: Boolean get() = Locale.getDefault().language == "zh"

private fun tagLabel(vm: ChatViewModel, key: String): String =
    (vm.catalog + vm.adultCatalog).asSequence().flatMap { it.tags }.firstOrNull { it.key == key }
        ?.let { if (zh) it.zh else it.en } ?: key

/** Tinder-style interest picker: tap chips, up to [ChatViewModel.maxTagCount]. */
@Composable
private fun TagPicker(vm: ChatViewModel, onDone: () -> Unit) {
    var full by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                Text(stringResource(R.string.tags), style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                Text(
                    stringResource(R.string.tags_count, vm.selectedTags.size, vm.maxTagCount),
                    style = MaterialTheme.typography.bodySmall,
                    color = if (full) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Button(onClick = onDone) { Text(stringResource(R.string.done)) }
        }
        LazyColumn(
            Modifier.weight(1f).fillMaxWidth().padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            items(vm.catalog, key = { it.zh }) { cat -> CategoryChips(vm, cat) { full = it } }
            if (vm.adultAvailable) {
                if (vm.adultConfirmed) {
                    items(vm.adultCatalog, key = { it.zh }) { cat -> CategoryChips(vm, cat) { full = it } }
                    item { TextButton(onClick = vm::revokeAdult) { Text(stringResource(R.string.adult_hide)) } }
                } else {
                    item { AdultGate { vm.adultConfirmed = true } }
                }
            }
            item { Spacer(Modifier.height(24.dp)) }
        }
    }
}

@Composable
private fun CategoryChips(vm: ChatViewModel, cat: TagCategory, onFull: (Boolean) -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(
                if (zh) cat.zh else cat.en,
                style = MaterialTheme.typography.titleSmall,
                color = if (cat.adult) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface,
            )
            if (cat.singleChoice) {
                Text(stringResource(R.string.pick_one), style = MaterialTheme.typography.labelSmall)
            }
        }
        FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            for (t in cat.tags) {
                FilterChip(
                    selected = t.key in vm.selectedTags,
                    onClick = { onFull(!vm.toggleTag(t.key)) },
                    label = { Text(if (zh) t.zh else t.en) },
                )
            }
        }
    }
}

/** 18+ section: hidden behind an explicit age confirmation and content warning. */
@Composable
private fun AdultGate(onConfirm: () -> Unit) {
    var asking by remember { mutableStateOf(false) }
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("🔞 " + stringResource(R.string.adult_title), fontWeight = FontWeight.SemiBold)
            Text(stringResource(R.string.adult_teaser), style = MaterialTheme.typography.bodySmall)
            OutlinedButton(onClick = { asking = true }) { Text(stringResource(R.string.adult_show)) }
        }
    }
    if (asking) {
        AlertDialog(
            onDismissRequest = { asking = false },
            title = { Text("🔞 " + stringResource(R.string.adult_warning_title)) },
            text = { Text(stringResource(R.string.adult_warning)) },
            confirmButton = {
                TextButton(onClick = { asking = false; onConfirm() }) { Text(stringResource(R.string.adult_confirm)) }
            },
            dismissButton = {
                TextButton(onClick = { asking = false }) { Text(stringResource(R.string.adult_decline)) }
            },
        )
    }
}

@Composable
private fun WaitingScreen(vm: ChatViewModel, st: ChatState, s: UiState) {
    val label = when (st) {
        ChatState.ConnectingTor -> R.string.state_tor
        ChatState.SolvingPow -> R.string.state_pow
        ChatState.Queued -> R.string.state_queued
        else -> R.string.state_handshake
    }
    val context = LocalContext.current
    Column(
        Modifier.fillMaxSize().padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
    ) {
        CircularProgressIndicator()
        Text(stringResource(label), style = MaterialTheme.typography.titleMedium)
        // Sponsored cards: chosen on this device from the whole catalog.
        for (card in s.sponsors) {
            Card(
                Modifier.fillMaxWidth().clickable {
                    context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(card.url)))
                },
            ) {
                Column(Modifier.padding(12.dp)) {
                    Text(stringResource(R.string.sponsored), style = MaterialTheme.typography.labelSmall)
                    Text(card.title, fontWeight = FontWeight.SemiBold)
                    Text(card.body, style = MaterialTheme.typography.bodySmall)
                }
            }
        }
        OutlinedButton(onClick = { vm.leave() }) { Text(stringResource(R.string.cancel)) }
    }
}

@Composable
private fun ChatScreen(vm: ChatViewModel, s: UiState) {
    var draft by rememberSaveable { mutableStateOf("") }
    var burn by rememberSaveable { mutableStateOf(false) }
    var confirmReport by remember { mutableStateOf(false) }
    val list = rememberLazyListState()
    LaunchedEffect(s.messages.size) {
        if (s.messages.isNotEmpty()) list.animateScrollToItem(s.messages.size - 1)
    }
    Column(Modifier.fillMaxSize().imePadding()) {
        // Header: peer, verification emoji, actions.
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                Text(
                    s.peerProfile?.nickname ?: stringResource(R.string.stranger),
                    fontWeight = FontWeight.SemiBold,
                )
                if (s.sas.isNotEmpty()) {
                    Text(
                        stringResource(R.string.sas, s.sas.joinToString("")),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
            TextButton(onClick = { confirmReport = true }) { Text(stringResource(R.string.report)) }
            TextButton(onClick = { vm.leave() }) { Text(stringResource(R.string.leave)) }
        }
        Notice(s)
        LazyColumn(
            Modifier.weight(1f).fillMaxWidth().padding(horizontal = 12.dp),
            state = list,
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            items(s.messages, key = { it.id.toLong() }) { Bubble(it) }
        }
        Row(
            Modifier.fillMaxWidth().padding(8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            FilterChip(
                selected = burn,
                onClick = { burn = !burn },
                label = { Text("🔥10s") },
            )
            OutlinedTextField(
                value = draft,
                onValueChange = { draft = it.take(2000) },
                placeholder = { Text(stringResource(R.string.type)) },
                modifier = Modifier.weight(1f),
                maxLines = 4,
            )
            Button(
                onClick = { if (draft.isNotBlank() && vm.send(draft.trim(), burn)) draft = "" },
                enabled = draft.isNotBlank() && s.chat == ChatState.Chatting,
            ) { Text(stringResource(R.string.send)) }
        }
    }
    if (confirmReport) {
        AlertDialog(
            onDismissRequest = { confirmReport = false },
            confirmButton = {
                TextButton(onClick = { confirmReport = false; vm.report() }) {
                    Text(stringResource(R.string.report))
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmReport = false }) { Text(stringResource(R.string.cancel)) }
            },
            text = { Text(stringResource(R.string.report_confirm)) },
        )
    }
}

@Composable
private fun Notice(s: UiState) {
    val text = when {
        s.chat is ChatState.Reconnecting ->
            stringResource(R.string.reconnecting, (s.chat as ChatState.Reconnecting).secondsLeft.toInt())
        s.peer is PeerEvent.Disconnected ->
            stringResource(R.string.peer_away, (s.peer as PeerEvent.Disconnected).graceSecs.toInt())
        s.peer is PeerEvent.Extended -> stringResource(R.string.peer_saved)
        s.commonTags.isNotEmpty() -> stringResource(R.string.common_tags, s.commonTags.joinToString("、"))
        else -> null
    } ?: return
    Text(
        text,
        Modifier.fillMaxWidth()
            .background(MaterialTheme.colorScheme.secondaryContainer)
            .padding(horizontal = 12.dp, vertical = 6.dp),
        style = MaterialTheme.typography.bodySmall,
    )
}

@Composable
private fun Bubble(m: ChatMessage) {
    var revealed by remember(m.id) { mutableStateOf(false) }
    val hidden = m.safety == SafetyLevel.BLUR && !revealed
    Row(Modifier.fillMaxWidth(), horizontalArrangement = if (m.fromMe) Arrangement.End else Arrangement.Start) {
        Column(
            Modifier
                .widthIn(max = 300.dp)
                .background(
                    if (m.fromMe) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant,
                    RoundedCornerShape(14.dp),
                )
                .clickable(enabled = hidden) { revealed = true }
                .padding(horizontal = 12.dp, vertical = 8.dp),
        ) {
            if (hidden) {
                Text(stringResource(R.string.blurred), style = MaterialTheme.typography.bodySmall)
            } else {
                Text(m.body)
                if (!m.fromMe && m.safety == SafetyLevel.CAUTION) {
                    Text(stringResource(R.string.caution), style = MaterialTheme.typography.labelSmall)
                }
            }
            if (m.ttlSecs > 0u) Text("🔥", style = MaterialTheme.typography.labelSmall)
        }
    }
}

@Composable
private fun EndedScreen(vm: ChatViewModel, reason: EndReason, s: UiState) {
    val text = when (reason) {
        EndReason.SelfLeft -> stringResource(R.string.end_self)
        EndReason.PeerLeft -> stringResource(R.string.end_peer_left)
        EndReason.PeerGone -> stringResource(R.string.end_peer_gone)
        EndReason.Cancelled -> stringResource(R.string.end_cancelled)
        EndReason.ConnectionLost -> stringResource(R.string.end_lost)
        EndReason.NoCommonTags -> stringResource(R.string.end_no_common)
        EndReason.Reported -> stringResource(R.string.end_reported)
        EndReason.Wiped, EndReason.Suspended -> stringResource(R.string.end_self)
        is EndReason.Error -> stringResource(R.string.end_error, reason.message)
    }
    var reported by remember { mutableStateOf(false) }
    Column(
        Modifier.fillMaxSize().padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
    ) {
        Text(text, style = MaterialTheme.typography.titleMedium, textAlign = TextAlign.Center)
        if (reason == EndReason.PeerLeft && !reported) {
            // The room keeps a short window open for reporting someone who left.
            OutlinedButton(onClick = { reported = true; vm.report() }) { Text(stringResource(R.string.report)) }
        }
        Text(stringResource(R.string.good_tokens, s.goodTokens), style = MaterialTheme.typography.bodySmall)
        Button(onClick = vm::start, modifier = Modifier.fillMaxWidth().height(52.dp)) {
            Text(stringResource(R.string.next))
        }
        TextButton(onClick = vm::home) { Text(stringResource(R.string.home)) }
        Box(Modifier.size(1.dp))
    }
}
