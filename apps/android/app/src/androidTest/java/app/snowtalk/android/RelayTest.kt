package app.snowtalk.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.snow_core.ChatListener
import uniffi.snow_core.ChatMessage
import uniffi.snow_core.ChatState
import uniffi.snow_core.Config
import uniffi.snow_core.MediaInfo
import uniffi.snow_core.PeerEvent
import uniffi.snow_core.SnowClient
import uniffi.snow_core.SponsorCard
import uniffi.snow_core.UserProfile
import java.util.UUID
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/**
 * Two app clients on this device pair through the production relay: DoH
 * (with resolver fallback), ECH/TLS, PoW, matchmaking, E2EE and relay, all on
 * Android's real network stack.
 */
@RunWith(AndroidJUnit4::class)
class RelayTest {
    private class Rec : ChatListener {
        val states = LinkedBlockingQueue<ChatState>()
        val messages = LinkedBlockingQueue<ChatMessage>()
        override fun onState(state: ChatState) { states.put(state) }
        override fun onSas(emoji: List<String>) {}
        override fun onMessage(message: ChatMessage) { messages.put(message) }
        override fun onPeer(event: PeerEvent) {}
        override fun onBurn(id: ULong, fromMe: Boolean) {}
        override fun onCommonTags(tags: List<String>) {}
        override fun onProfile(profile: UserProfile) {}
        override fun onMedia(media: MediaInfo) {}
        override fun onMediaBurned(id: ULong, fromMe: Boolean) {}
        override fun onWalletChanged() {}
        override fun onSponsors(cards: List<SponsorCard>) {}

        fun awaitChatting(who: String) {
            val deadline = System.currentTimeMillis() + 150_000
            while (true) {
                val left = deadline - System.currentTimeMillis()
                if (left <= 0) fail("$who: not chatting in time")
                when (val s = states.poll(left, TimeUnit.MILLISECONDS)) {
                    ChatState.Chatting -> return
                    is ChatState.Ended -> fail("$who ended: ${s.reason}")
                    else -> {}
                }
            }
        }
    }

    @Test
    fun pairsThroughProductionRelay() {
        // A tag nobody else has, so we only match each other.
        val cfg = Config(
            serverUrl = BuildConfig.SNOW_SERVER_URL,
            tags = listOf("ci-" + UUID.randomUUID().toString().take(8)),
        )
        val a = Rec()
        val b = Rec()
        SnowClient(cfg, a).use { ca ->
            SnowClient(cfg, b).use { cb ->
                ca.startMatch()
                cb.startMatch()
                a.awaitChatting("A")
                b.awaitChatting("B")
                ca.sendText("hello from the Android emulator", 0u)
                val got = b.messages.poll(60, TimeUnit.SECONDS) ?: fail("B got nothing")
                assertEquals("hello from the Android emulator", (got as ChatMessage).body)
                ca.leave()
                cb.leave()
            }
        }
    }
}
