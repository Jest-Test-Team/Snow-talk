import SwiftUI

/// Shell: proves the Rust core links and loads. The chat UI comes in Phase 3.
@main
struct SnowTalkApp: App {
    var body: some Scene {
        WindowGroup {
            Text("Snow-talk · core \(version())")
                .padding()
        }
    }
}
