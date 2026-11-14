import SwiftUI

struct RootView: View {
    @ObservedObject var model: ChatModel
    let replayOnboarding: () -> Void

    var body: some View {
        Group {
            switch model.chat {
            case nil: HomeView(model: model, replayOnboarding: replayOnboarding)
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
    let replayOnboarding: () -> Void
    @State private var advanced = false
    @State private var picking = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Snow-talk").font(.largeTitle.bold())
            Text("Anonymous, end-to-end encrypted chats with strangers. Nothing is stored.")
                .font(.subheadline).foregroundStyle(.secondary)
            Button("How does the privacy work?", action: replayOnboarding).font(.callout)
            TextField("Nickname (optional)", text: $model.nickname).textFieldStyle(.roundedBorder)
            Text("Interests").font(.headline)
            if model.selectedTags.isEmpty {
                Text("Optional. Only the ones you share with your match are revealed, privately.")
                    .font(.caption).foregroundStyle(.secondary)
            } else {
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 84), spacing: 6)], alignment: .leading, spacing: 6) {
                    ForEach(model.selectedTags, id: \.self) { key in
                        Chip(label: model.label(key), selected: true) { model.toggleTag(key) }
                    }
                }
            }
            Button("Pick interests (\(model.selectedTags.count)/\(model.maxTagCount))") { picking = true }
                .buttonStyle(.bordered)
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
        .sheet(isPresented: $picking) { TagPickerView(model: model) }
    }
}

struct Chip: View {
    let label: String
    let selected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(label).font(.subheadline).lineLimit(1)
                .padding(.horizontal, 12).padding(.vertical, 7)
                .frame(maxWidth: .infinity)
                .foregroundStyle(selected ? Color.white : Color.primary)
                .background(selected ? Color.accentColor : Color.secondary.opacity(0.15), in: Capsule())
        }
        .buttonStyle(.plain)
    }
}

/// Tinder-style interest picker: tap chips, up to `maxTagCount`.
struct TagPickerView: View {
    @ObservedObject var model: ChatModel
    @Environment(\.dismiss) private var dismiss
    @State private var full = false
    @State private var askAdult = false

    private func categoryView(_ cat: TagCategory) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(ChatModel.zh ? cat.zh : cat.en).font(.headline)
                    .foregroundColor(cat.adult ? .red : .primary)
                if cat.singleChoice { Text("Pick one").font(.caption2).foregroundStyle(.secondary) }
            }
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 84), spacing: 6)], spacing: 6) {
                ForEach(cat.tags, id: \.key) { t in
                    Chip(label: ChatModel.zh ? t.zh : t.en, selected: model.selectedTags.contains(t.key)) {
                        full = !model.toggleTag(t.key)
                    }
                }
            }
        }
    }

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    Text("\(model.selectedTags.count) of \(model.maxTagCount) picked")
                        .font(.caption).foregroundColor(full ? .red : .secondary)
                    ForEach(model.catalog, id: \.zh) { cat in categoryView(cat) }
                    if model.adultAvailable {
                        if model.adultConfirmed {
                            ForEach(model.adultCatalog, id: \.zh) { cat in categoryView(cat) }
                            Button("Hide 18+ interests") { model.revokeAdult() }
                        } else {
                            VStack(alignment: .leading, spacing: 8) {
                                Text("🔞 Adult interests (18+)").font(.headline)
                                Text("Explicit topics, kinks and orientations. Only matched with other adults who picked the same ones.")
                                    .font(.caption).foregroundStyle(.secondary)
                                Button("Show 18+ interests") { askAdult = true }.buttonStyle(.bordered)
                            }
                            .padding(12)
                            .background(Color.secondary.opacity(0.1), in: RoundedRectangle(cornerRadius: 12))
                        }
                    }
                }
                .padding()
            }
            .navigationTitle(Text("Interests"))
            .alert("🔞 18+ content warning", isPresented: $askAdult) {
                Button("I am 18 or older", role: .destructive) { model.adultConfirmed = true }
                Button("Not now", role: .cancel) {}
            } message: {
                Text("This section contains sexually explicit topics. Continue only if you are at least 18 years old (or the age of majority where you live) and want to see adult content. Adult picks are only compared with other users who chose them too, never shown to anyone else, and never stored. Strictly between consenting adults: any involvement of minors, non-consent or paid sex is forbidden and can be reported.")
            }
            .toolbar {
                ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } }
            }
        }
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
