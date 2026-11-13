package app.snowtalk.android

import android.app.Application
import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import uniffi.snow_core.ChatListener
import uniffi.snow_core.ChatMessage
import uniffi.snow_core.ChatState
import uniffi.snow_core.Config
import uniffi.snow_core.MediaInfo
import uniffi.snow_core.PeerEvent
import uniffi.snow_core.SnowClient
import uniffi.snow_core.SponsorCard
import uniffi.snow_core.UserProfile

/** Everything the screens render. Plaintext lives here only while visible. */
data class UiState(
    /** `null` = home screen. */
    val chat: ChatState? = null,
    val sas: List<String> = emptyList(),
    val messages: List<ChatMessage> = emptyList(),
    val peer: PeerEvent? = null,
    val commonTags: List<String> = emptyList(),
    val peerProfile: UserProfile? = null,
    val sponsors: List<SponsorCard> = emptyList(),
    val goodTokens: Int = 0,
    val error: String? = null,
)

/**
 * Bridges the Rust core to Compose. Callbacks arrive on a Rust thread;
 * [MutableStateFlow] is thread-safe. The transcript itself stays in Rust
 * (zeroizing memory): the UI re-reads it and drops its copy when hidden.
 */
class ChatViewModel(app: Application) : AndroidViewModel(app), ChatListener {
    private val prefs = app.getSharedPreferences("settings", Context.MODE_PRIVATE)
    private val wallet = WalletStore(app)
    private val _ui = MutableStateFlow(UiState())
    val ui: StateFlow<UiState> = _ui

    // Only the relay address is remembered. Nickname and tags are re-entered
    // each launch, so nothing about the user is written to disk.
    var serverUrl by mutableStateOf(prefs.getString(KEY_SERVER, null) ?: BuildConfig.SNOW_SERVER_URL)
    var nickname by mutableStateOf("")
    var tags by mutableStateOf("")

    @Volatile private var client: SnowClient? = null
    private var clientKey: List<String>? = null
    @Volatile private var visible = true

    private fun parsedTags(): List<String> =
        tags.split(',', '，', '、', ' ').map { it.trim() }.filter { it.isNotEmpty() }.take(16)

    /** A client is bound to its config; rebuild it (keeping the wallet) when settings change. */
    private fun clientFor(): SnowClient {
        val key = listOf(serverUrl.trim(), nickname.trim(), parsedTags().joinToString("\u0000"))
        client?.let { if (key == clientKey) return it }
        val saved = client?.walletExport() ?: wallet.load()
        client?.close()
        val cfg = Config(
            serverUrl = key[0],
            tags = parsedTags(),
            profile = nickname.trim().takeIf { it.isNotEmpty() }?.let { UserProfile(nickname = it) },
        )
        val c = SnowClient(cfg, this)
        saved?.let { runCatching { c.walletImport(it) } }
        client = c
        clientKey = key
        return c
    }

    fun start() {
        val url = serverUrl.trim()
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            _ui.update { it.copy(error = "server") }
            return
        }
        prefs.edit().putString(KEY_SERVER, url).apply()
        val c = clientFor()
        _ui.value = UiState(chat = ChatState.SolvingPow, goodTokens = c.goodTokens().toInt())
        c.startMatch()
    }

    fun send(text: String, burn: Boolean): Boolean {
        val c = client ?: return false
        val ok = runCatching { c.sendText(text, if (burn) BURN_SECS else 0u) }.isSuccess
        refresh()
        return ok
    }

    fun leave() = client?.leave()
    fun report() = client?.report()

    /** Panic button: wipe keys and plaintext, tell nobody, go home. */
    fun panic() {
        client?.panicWipe()
        _ui.value = UiState(goodTokens = _ui.value.goodTokens)
    }

    fun home() {
        _ui.value = UiState(goodTokens = client?.goodTokens()?.toInt() ?: _ui.value.goodTokens)
    }

    fun dismissError() = _ui.update { it.copy(error = null) }

    /** App lifecycle: cover traffic pauses, and the UI drops its plaintext copy. */
    fun setVisible(v: Boolean) {
        visible = v
        client?.setForeground(v)
        if (v) refresh() else _ui.update { it.copy(messages = emptyList()) }
    }

    private fun refresh() {
        val c = client ?: return
        if (!visible) return
        _ui.update { it.copy(messages = c.transcript()) }
    }

    override fun onCleared() {
        client?.close()
        client = null
    }

    // ── ChatListener (called from a Rust thread) ──────────────────────────

    override fun onState(state: ChatState) {
        _ui.update {
            when (state) {
                is ChatState.Ended -> it.copy(chat = state, messages = emptyList(), sponsors = emptyList())
                ChatState.Chatting -> it.copy(chat = state, sponsors = emptyList())
                else -> it.copy(chat = state)
            }
        }
        if (state == ChatState.Chatting) refresh()
    }

    override fun onSas(emoji: List<String>) = _ui.update { it.copy(sas = emoji) }
    override fun onMessage(message: ChatMessage) = refresh()
    override fun onPeer(event: PeerEvent) = _ui.update { it.copy(peer = event) }
    override fun onBurn(id: ULong, fromMe: Boolean) = refresh()
    override fun onCommonTags(tags: List<String>) = _ui.update { it.copy(commonTags = tags) }
    override fun onProfile(profile: UserProfile) = _ui.update { it.copy(peerProfile = profile) }
    override fun onMedia(media: MediaInfo) {} // flash photos: next step
    override fun onMediaBurned(id: ULong, fromMe: Boolean) {}
    override fun onSponsors(cards: List<SponsorCard>) = _ui.update { it.copy(sponsors = cards) }

    override fun onWalletChanged() {
        val c = client ?: return
        runCatching { wallet.save(c.walletExport()) }
        _ui.update { it.copy(goodTokens = c.goodTokens().toInt()) }
    }

    private companion object {
        const val KEY_SERVER = "server_url"
        const val BURN_SECS = 10u
    }
}
