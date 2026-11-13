import SwiftUI

struct RootView: View {
    @ObservedObject var model: ChatModel

    var body: some View {
        Group {
            switch model.chat {
            case nil: HomeView(model: model)
            case .ended(let reason): EndedView(model: model, reason: reason)
            case .chatting, .reconnecting: ChatView(model: model)
            case let other?: WaitingView(model: model, state: other)
            }
        }
        .alert("Set a relay server URL (http:// or https://) under Server settings.", isPresented: $model.badServer) {
            Button("OK", role: .cancel) {}
        }
    }
}

struct HomeView: View {
    @ObservedObject var model: ChatModel
    @State private var advanced = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Snow-talk").font(.largeTitle.bold())
            Text("Anonymous, end-to-end encrypted chats with strangers. Nothing is stored.")
                .font(.subheadline).foregroundStyle(.secondary)
            TextField("Nickname (optional)", text: $model.nickname).textFieldStyle(.roundedBorder)
            TextField("Interests (optional)", text: $model.tags).textFieldStyle(.roundedBorder)
            Text("Comma-separated. Compared privately with your match.").font(.caption).foregroundStyle(.secondary)
            Button("Server settings") { advanced.toggle() }.font(.callout)
            if advanced || model.serverUrl.isEmpty {
                TextField("Relay server URL", text: $model.serverUrl)
                    .textFieldStyle(.roundedBorder)
                    .keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
            }
            Spacer()
            Text("Good-chat tokens: \(model.goodTokens)").font(.caption)
            Button { model.start() } label: {
                Text("Find someone").frame(maxWidth: .infinity).padding(.vertical, 6)
            }
            .buttonStyle(.borderedProminent)
        }
        .padding(24)
    }
}

struct WaitingView: View {
    @ObservedObject var model: ChatModel
    let state: ChatState

    private var label: LocalizedStringKey {
        switch state {
        case .connectingTor: return "Connecting through Tor…"
        case .solvingPow: return "Proving you're not a bot…"
        case .queued: return "Looking for someone…"
        default: return "Setting up encryption…"
        }
    }

    var body: some View {
        VStack(spacing: 18) {
            Spacer()
            ProgressView()
            Text(label).font(.headline)
            // Sponsored cards: chosen on this device from the whole catalog.
            ForEach(model.sponsors, id: \.id) { card in
                if let url = URL(string: card.url) {
                    Link(destination: url) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Sponsored").font(.caption2).foregroundStyle(.secondary)
                            Text(card.title).font(.subheadline.bold())
                            Text(card.body).font(.caption)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(12)
                        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 12))
                    }
                    .buttonStyle(.plain)
                }
            }
            Spacer()
            Button("Cancel") { model.leave() }.buttonStyle(.bordered)
        }
        .padding(24)
    }
}

struct ChatView: View {
    @ObservedObject var model: ChatModel
    @State private var draft = ""
    @State private var burn = false
    @State private var confirmReport = false

    private var notice: String? {
        if case .reconnecting(let s) = model.chat {
            return String(localized: "Reconnecting… \(Int(s))s")
        }
        switch model.peer {
        case .disconnected(let g)?: return String(localized: "The other person lost connection. Waiting \(Int(g))s…")
        case .extended?: return String(localized: "This chat is held for 24 h. The other person may keep an encrypted copy on their device.")
        case .screenCaptured?: return String(localized: "The other person took a screenshot.")
        default: break
        }
        if !model.commonTags.isEmpty {
            return String(localized: "You both like: \(model.commonTags.joined(separator: "、"))")
        }
        return nil
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                VStack(alignment: .leading) {
                    Text(model.peerName ?? String(localized: "Stranger")).font(.headline)
                    if !model.sas.isEmpty {
                        Text("Verify: \(model.sas.joined())").font(.caption)
                    }
                }
                Spacer()
                Button("Report") { confirmReport = true }
                Button("Leave") { model.leave() }
            }
            .padding(.horizontal).padding(.vertical, 8)
            if let notice {
                Text(notice).font(.caption).frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal).padding(.vertical, 6).background(Color.secondary.opacity(0.15))
            }
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(spacing: 6) {
                        ForEach(model.messages, id: \.id) { Bubble(message: $0).id($0.id) }
                    }
                    .padding(.horizontal, 12).padding(.vertical, 8)
                }
                .onChange(of: model.messages.count) { _ in
                    if let last = model.messages.last { withAnimation { proxy.scrollTo(last.id, anchor: .bottom) } }
                }
            }
            HStack(spacing: 8) {
                Toggle("🔥10s", isOn: $burn).toggleStyle(.button)
                TextField("Message", text: $draft).textFieldStyle(.roundedBorder)
                Button("Send") {
                    let t = draft.trimmingCharacters(in: .whitespacesAndNewlines)
                    if !t.isEmpty, model.send(t, burn: burn) { draft = "" }
                }
                .disabled(draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || model.chat != .chatting)
            }
            .padding(8)
        }
        .confirmationDialog(
            "Report this person and leave? Nothing you wrote is sent; they just won't earn a good-chat token.",
            isPresented: $confirmReport, titleVisibility: .visible
        ) {
            Button("Report", role: .destructive) { model.report() }
        }
    }
}

struct Bubble: View {
    let message: ChatMessage
    @State private var revealed = false

    var body: some View {
        let hidden = message.safety == .blur && !revealed
        HStack {
            if message.fromMe { Spacer(minLength: 40) }
            VStack(alignment: .leading, spacing: 2) {
                if hidden {
                    Text("This message may contain inappropriate content. Tap to view.").font(.caption)
                } else {
                    Text(message.body)
                    if !message.fromMe && message.safety == .caution {
                        Text("⚠ May be trying to move you off-platform or talk money").font(.caption2)
                    }
                }
                if message.ttlSecs > 0 { Text("🔥").font(.caption2) }
            }
            .padding(.horizontal, 12).padding(.vertical, 8)
            .background(message.fromMe ? Color.accentColor.opacity(0.2) : Color.secondary.opacity(0.15),
                        in: RoundedRectangle(cornerRadius: 14))
            .onTapGesture { if hidden { revealed = true } }
            if !message.fromMe { Spacer(minLength: 40) }
        }
    }
}

struct EndedView: View {
    @ObservedObject var model: ChatModel
    let reason: EndReason
    @State private var reported = false

    private var text: String {
        switch reason {
        case .selfLeft, .wiped, .suspended: return String(localized: "You left the chat.")
        case .peerLeft: return String(localized: "The other person left the chat.")
        case .peerGone: return String(localized: "The other person disconnected.")
        case .cancelled: return String(localized: "Search cancelled.")
        case .connectionLost: return String(localized: "Connection lost.")
        case .noCommonTags: return String(localized: "No shared interests. Try again to find someone else.")
        case .reported: return String(localized: "Reported. Thanks for keeping this place safe.")
        case .error(let m): return String(localized: "Something went wrong: \(m)")
        }
    }

    var body: some View {
        VStack(spacing: 16) {
            Spacer()
            Text(text).font(.headline).multilineTextAlignment(.center)
            if reason == .peerLeft && !reported {
                Button("Report") { reported = true; model.report() }.buttonStyle(.bordered)
            }
            Text("Good-chat tokens: \(model.goodTokens)").font(.caption)
            Spacer()
            Button { model.start() } label: {
                Text("Find someone else").frame(maxWidth: .infinity).padding(.vertical, 6)
            }
            .buttonStyle(.borderedProminent)
            Button("Home") { model.home() }
        }
        .padding(24)
    }
}
