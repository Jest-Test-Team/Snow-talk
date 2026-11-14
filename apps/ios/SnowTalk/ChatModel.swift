import Foundation
import SwiftUI

/// Bridges the Rust core to SwiftUI. Callbacks arrive on a Rust thread and are
/// hopped to the main queue. The transcript stays in Rust; the UI re-reads it
/// and drops its copy whenever the app leaves the foreground.
final class ChatModel: ObservableObject, ChatListener, @unchecked Sendable {
    @Published var chat: ChatState? = nil   // nil = home
    @Published var sas: [String] = []
    @Published var messages: [ChatMessage] = []
    @Published var peer: PeerEvent? = nil
    @Published var commonTags: [String] = []
    @Published var peerName: String? = nil
    @Published var sponsors: [SponsorCard] = []
    @Published var goodTokens: UInt32 = 0
    @Published var badServer = false

    // Only the relay address is remembered; nickname and interests are not stored.
    @Published var serverUrl = UserDefaults.standard.string(forKey: "server_url")
        ?? "https://snow-talk.pcleegood.workers.dev"
    @Published var nickname = ""
    /// Picked interest keys (canonical, from `catalog`), in pick order.
    @Published var selectedTags: [String] = []
    let catalog: [TagCategory] = tagCatalog()
    let maxTagCount = Int(maxTags())

    /// Pick or unpick a tag; returns false if the limit is reached.
    @discardableResult
    func toggleTag(_ key: String) -> Bool {
        if let i = selectedTags.firstIndex(of: key) { selectedTags.remove(at: i); return true }
        guard selectedTags.count < maxTagCount else { return false }
        selectedTags.append(key)
        return true
    }

    func label(_ key: String) -> String {
        for c in catalog { if let t = c.tags.first(where: { $0.key == key }) { return Self.zh ? t.zh : t.en } }
        return key
    }

    static var zh: Bool { Locale.preferredLanguages.first?.hasPrefix("zh") ?? false }

    private var client: SnowClient?
    private var clientKey: [String] = []
    private var visible = true

    private var parsedTags: [String] { selectedTags }

    private func clientFor() -> SnowClient {
        let nick = nickname.trimmingCharacters(in: .whitespaces)
        let key = [serverUrl.trimmingCharacters(in: .whitespaces), nick, parsedTags.joined(separator: "\u{0}")]
        if let c = client, key == clientKey { return c }
        let saved = client?.walletExport() ?? Wallet.load()
        let cfg = Config(
            serverUrl: key[0],
            tags: parsedTags,
            profile: nick.isEmpty ? nil : UserProfile(nickname: nick)
        )
        let c = SnowClient(cfg: cfg, listener: self)
        if let saved { try? c.walletImport(bytes: saved) }
        client = c
        clientKey = key
        return c
    }

    func start() {
        let url = serverUrl.trimmingCharacters(in: .whitespaces)
        guard url.hasPrefix("https://") || url.hasPrefix("http://") else { badServer = true; return }
        UserDefaults.standard.set(url, forKey: "server_url")
        let c = clientFor()
        reset()
        goodTokens = c.goodTokens()
        chat = .solvingPow
        c.startMatch()
    }

    private func reset() {
        sas = []; messages = []; peer = nil; commonTags = []; peerName = nil; sponsors = []
    }

    func send(_ text: String, burn: Bool) -> Bool {
        guard let c = client else { return false }
        let ok = (try? c.sendText(body: text, ttlSecs: burn ? 10 : 0)) != nil
        refresh()
        return ok
    }

    func leave() { client?.leave() }
    func report() { client?.report() }
    func home() { reset(); chat = nil }

    /// Panic button: wipe keys and plaintext without telling anyone.
    func panic() { client?.panicWipe(); home() }

    func screenCaptured() { client?.notifyScreenCaptured() }

    func setVisible(_ v: Bool) {
        visible = v
        client?.setForeground(foreground: v)
        if v { refresh() } else { messages = [] }
    }

    private func refresh() {
        guard visible, let c = client else { return }
        messages = c.transcript()
    }

    private func onMain(_ f: @escaping () -> Void) { DispatchQueue.main.async(execute: f) }

    // MARK: ChatListener (Rust thread)

    func onState(state: ChatState) {
        onMain {
            self.chat = state
            switch state {
            case .chatting: self.sponsors = []; self.refresh()
            case .ended: self.messages = []; self.sponsors = []
            default: break
            }
        }
    }
    func onSas(emoji: [String]) { onMain { self.sas = emoji } }
    func onMessage(message: ChatMessage) { onMain { self.refresh() } }
    func onPeer(event: PeerEvent) { onMain { self.peer = event } }
    func onBurn(id: UInt64, fromMe: Bool) { onMain { self.refresh() } }
    func onCommonTags(tags: [String]) { onMain { self.commonTags = tags } }
    func onProfile(profile: UserProfile) { onMain { self.peerName = profile.nickname } }
    func onMedia(media: MediaInfo) {}
    func onMediaBurned(id: UInt64, fromMe: Bool) {}
    func onSponsors(cards: [SponsorCard]) { onMain { self.sponsors = cards } }
    func onWalletChanged() {
        onMain {
            guard let c = self.client else { return }
            Wallet.save(c.walletExport())
            self.goodTokens = c.goodTokens()
        }
    }
}
