package app.snowtalk.android

import android.app.Application
import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
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
import uniffi.snow_core.TagCategory
import uniffi.snow_core.UserProfile
import uniffi.snow_core.adultContentEnabled
import uniffi.snow_core.adultTagCatalog
import uniffi.snow_core.maxTags
import uniffi.snow_core.tagCatalog

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

    // Only the relay address is remembered. Nickname and interests are picked
    // again each launch, so nothing about the user is written to disk.
    var serverUrl by mutableStateOf(prefs.getString(KEY_SERVER, null) ?: BuildConfig.SNOW_SERVER_URL)
    /** First launch: show the privacy walkthrough. (A flag, nothing about the user.) */
    var onboarded by mutableStateOf(prefs.getBoolean(KEY_ONBOARDED, false))
        private set

    fun finishOnboarding() {
        onboarded = true
        prefs.edit().putBoolean(KEY_ONBOARDED, true).apply()
    }

    fun replayOnboarding() {
        onboarded = false
    }

    /** Tor mode through Orbot's local SOCKS5 proxy. */
    var useTor by mutableStateOf(prefs.getBoolean(KEY_TOR, false))
    var nickname by mutableStateOf("")
    /** Picked interest keys (canonical, from [catalog]), in pick order. */
    val selectedTags = mutableStateListOf<String>()
    val catalog: List<TagCategory> by lazy { tagCatalog() }
    /** Empty in builds without adult content. */
    val adultCatalog: List<TagCategory> by lazy { adultTagCatalog() }
    val adultAvailable: Boolean = adultContentEnabled()
    val maxTagCount: Int = maxTags().toInt()
    /** The user confirmed they are 18+ (asked again every launch, never stored). */
    var adultConfirmed by mutableStateOf(false)

    private val categoryOf: Map<String, TagCategory> by lazy {
        (catalog + adultCatalog).flatMap { c -> c.tags.map { it.key to c } }.toMap()
    }

    fun isAdult(key: String) = categoryOf[key]?.adult == true

    /** Pick or unpick a tag; returns false if the limit is reached. */
    fun toggleTag(key: String): Boolean {
        if (selectedTags.remove(key)) return true
        val cat = categoryOf[key]
        if (cat?.adult == true && !adultConfirmed) return false
        // Single-choice categories (what you're looking for): swap, don't add.
        if (cat?.singleChoice == true) {
            val other = cat.tags.map { it.key }.firstOrNull { it in selectedTags }
            if (other != null) {
                selectedTags[selectedTags.indexOf(other)] = key
                return true
            }
        }
        if (selectedTags.size >= maxTagCount) return false
        selectedTags.add(key)
        return true
    }

    /** Hide adult content again and drop any adult picks. */
    fun revokeAdult() {
        adultConfirmed = false
        selectedTags.removeAll { isAdult(it) }
    }

    @Volatile private var client: SnowClient? = null
    private var clientKey: List<String>? = null
    @Volatile private var visible = true

    private fun parsedTags(): List<String> = selectedTags.filterNot { isAdult(it) }
    private fun parsedAdultTags(): List<String> =
        if (adultConfirmed) selectedTags.filter { isAdult(it) } else emptyList()

    /** A client is bound to its config; rebuild it (keeping the wallet) when settings change. */
    private fun clientFor(): SnowClient {
        val key = listOf(
            serverUrl.trim(), nickname.trim(), parsedTags().joinToString("\u0000"),
            parsedAdultTags().joinToString("\u0000"), useTor.toString(),
        )
        client?.let { if (key == clientKey) return it }
        val saved = client?.walletExport() ?: wallet.load()
        client?.close()
        val cfg = Config(
            serverUrl = key[0],
            tags = parsedTags(),
            adultTags = parsedAdultTags(),
            profile = UserProfile(
                nickname = nickname.trim().takeIf { it.isNotEmpty() },
                adultOk = parsedAdultTags().isNotEmpty(),
            ),
            socksProxy = if (useTor) ORBOT_SOCKS else null,
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
        prefs.edit().putString(KEY_SERVER, url).putBoolean(KEY_TOR, useTor).apply()
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
        const val KEY_TOR = "use_tor"
        const val KEY_ONBOARDED = "onboarded"
        const val ORBOT_SOCKS = "127.0.0.1:9050"
        const val BURN_SECS = 10u
    }
}
