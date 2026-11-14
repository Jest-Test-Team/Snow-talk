import SwiftUI
import UIKit

@main
struct SnowTalkApp: App {
    @StateObject private var model = ChatModel()
    /// First launch: show the privacy walkthrough. (A flag, nothing about the user.)
    @AppStorage("onboarded") private var onboarded = false
    @Environment(\.scenePhase) private var phase

    var body: some Scene {
        WindowGroup {
            ZStack {
                if onboarded {
                    RootView(model: model, replayOnboarding: { onboarded = false })
                } else {
                    OnboardingView { onboarded = true }
                }
                // App-switcher snapshots and glances see a blank cover (Phase 6).
                if phase != .active {
                    Rectangle().fill(.ultraThinMaterial).ignoresSafeArea()
                    Text("Snow-talk").font(.title.bold())
                }
            }
            .onChange(of: phase) { p in model.setVisible(p == .active) }
            .onReceive(NotificationCenter.default.publisher(for: UIApplication.userDidTakeScreenshotNotification)) { _ in
                model.screenCaptured()
            }
            .onReceive(NotificationCenter.default.publisher(for: UIScreen.capturedDidChangeNotification)) { _ in
                if UIScreen.main.isCaptured { model.screenCaptured() }
            }
        }
    }
}
