import SwiftUI

private struct Slide {
    let emoji: String
    let title: LocalizedStringKey
    let body: LocalizedStringKey
    let colors: [Color]
}

private let slides: [Slide] = [
    Slide(emoji: "❄️", title: "Welcome to Snow-talk",
          body: "Chat with strangers anonymously, with privacy built into the design.\nNo sign-up, no phone number, no email: there is no account to link to you.",
          colors: [Color(red: 0.12, green: 0.23, blue: 0.54), Color(red: 0.05, green: 0.65, blue: 0.91)]),
    Slide(emoji: "🔐", title: "Only the two of you can read it",
          body: "Messages are encrypted on your phone and can only be opened on the other person's phone. Our server only passes along ciphertext it cannot read.\nThe 7 emoji in each chat let you both check that nobody is in the middle.",
          colors: [Color(red: 0.19, green: 0.18, blue: 0.51), Color(red: 0.49, green: 0.23, blue: 0.93)]),
    Slide(emoji: "🧊", title: "Nothing is kept",
          body: "No accounts, no chat history, no trackers, no ad SDKs. When a chat ends its keys are destroyed.\nMessages can burn after reading, the app hides itself in the app switcher, and the other person is told if you take a screenshot.",
          colors: [Color(red: 0.06, green: 0.46, blue: 0.43), Color(red: 0.13, green: 0.83, blue: 0.93)]),
    Slide(emoji: "🎯", title: "Interests, compared in private",
          body: "The server only sees a coarse group number. Your interests are compared in encrypted form between the two phones, so the other person only learns the ones you share, and nobody ever sees the rest.",
          colors: [Color(red: 0.62, green: 0.09, blue: 0.30), Color(red: 0.96, green: 0.45, blue: 0.71)]),
    Slide(emoji: "🧭", title: "Safety without giving up privacy",
          body: "Scam warnings are worked out on your own phone. Reporting someone sends no conversation at all; it just stops them earning trust. Trust tokens are anonymous and can't be traced to you.",
          colors: [Color(red: 0.49, green: 0.18, blue: 0.07), Color(red: 0.96, green: 0.62, blue: 0.04)]),
    Slide(emoji: "💬", title: "How to use it",
          body: "1. Pick some interests (optional)\n2. Tap “Find someone”\n3. Chat, and leave or move on whenever you like\n\nNone of this costs you privacy: every pick, match and message stays unknown to the server. It never learns who you are or what you say.",
          colors: [Color(red: 0.08, green: 0.33, blue: 0.18), Color(red: 0.13, green: 0.77, blue: 0.37)]),
]

/// First-launch walkthrough: how the privacy works, and how to use the app.
struct OnboardingView: View {
    let onDone: () -> Void
    @State private var page = 0

    private var last: Bool { page == slides.count - 1 }

    var body: some View {
        ZStack {
            LinearGradient(colors: slides[page].colors, startPoint: .top, endPoint: .bottom)
                .ignoresSafeArea()
                .animation(.easeInOut(duration: 0.5), value: page)
            VStack(spacing: 0) {
                HStack {
                    Spacer()
                    Button("Skip", action: onDone).foregroundColor(.white).opacity(last ? 0 : 1).disabled(last)
                }
                .padding()
                TabView(selection: $page) {
                    ForEach(slides.indices, id: \.self) { i in
                        SlideView(slide: slides[i]).tag(i)
                    }
                }
                .tabViewStyle(.page(indexDisplayMode: .never))
                HStack(spacing: 8) {
                    ForEach(slides.indices, id: \.self) { i in
                        Capsule().fill(Color.white.opacity(i == page ? 1 : 0.4))
                            .frame(width: i == page ? 24 : 8, height: 8)
                    }
                }
                .animation(.spring(), value: page)
                .padding(.vertical, 16)
                Button {
                    if last { onDone() } else { withAnimation { page += 1 } }
                } label: {
                    Text(last ? "Start chatting" : "Next")
                        .font(.headline)
                        .frame(maxWidth: .infinity, minHeight: 54)
                        .foregroundColor(slides[page].colors[0])
                        .background(Color.white, in: RoundedRectangle(cornerRadius: 16))
                }
                .padding(.horizontal, 24).padding(.bottom, 24)
            }
        }
    }
}

private struct SlideView: View {
    let slide: Slide

    var body: some View {
        VStack(spacing: 0) {
            Spacer()
            ZStack {
                Circle().fill(RadialGradient(colors: [.white.opacity(0.35), .white.opacity(0.05)],
                                             center: .center, startRadius: 4, endRadius: 90))
                    .frame(width: 168, height: 168)
                Text(slide.emoji).font(.system(size: 76))
            }
            Text(slide.title)
                .font(.system(size: 28, weight: .bold))
                .foregroundColor(.white)
                .multilineTextAlignment(.center)
                .padding(.top, 36)
            Text(slide.body)
                .font(.system(size: 16))
                .foregroundColor(.white.opacity(0.92))
                .multilineTextAlignment(.center)
                .lineSpacing(5)
                .padding(.top, 16)
            Spacer()
        }
        .padding(.horizontal, 32)
    }
}
