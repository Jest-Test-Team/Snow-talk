import XCTest

/// A fresh install: walkthrough → home → interest picker (single choice; the
/// App Store build has no 18+ section). Screenshots are kept for review.
final class FirstRunUITests: XCTestCase {
    private func shot(_ app: XCUIApplication, _ name: String) {
        let a = XCTAttachment(screenshot: app.screenshot())
        a.name = name
        a.lifetime = .keepAlways
        add(a)
    }

    func testWalkthroughThenInterestPicker() {
        let app = XCUIApplication()
        // Fresh user, English UI.
        app.launchArguments = ["--fresh-install", "-AppleLanguages", "(en)", "-AppleLocale", "en_US"]
        app.launch()

        let titles = [
            "Welcome to Snow-talk",
            "Only the two of you can read it",
            "Nothing is kept",
            "Interests, compared in private",
            "Safety without giving up privacy",
            "How to use it",
        ]
        for (i, title) in titles.enumerated() {
            XCTAssertTrue(app.staticTexts[title].waitForExistence(timeout: 5), "slide \(i + 1): \(title)")
            shot(app, "1-walkthrough-\(i + 1)")
            app.buttons[i == titles.count - 1 ? "Start chatting" : "Next"].tap()
        }

        XCTAssertTrue(app.buttons["Find someone"].waitForExistence(timeout: 5))
        shot(app, "2-home")

        app.buttons["Pick interests (0/10)"].tap()
        XCTAssertTrue(app.buttons["Long-term partner"].waitForExistence(timeout: 5))
        app.buttons["Long-term partner"].tap()
        app.buttons["Short-term fun"].tap()
        // "Looking for" is single choice: the second pick replaced the first.
        XCTAssertTrue(app.staticTexts["1 of 10 picked"].waitForExistence(timeout: 2))
        XCTAssertFalse(app.buttons["Show 18+ interests"].exists, "iOS builds have no adult content")
        shot(app, "3-picker")
    }
}
