package app.snowtalk.android

import android.content.Context
import android.graphics.Bitmap
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotSelected
import androidx.compose.ui.test.assertIsSelected
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollToNode
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.services.storage.TestStorage
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** A fresh install: walkthrough → home → interest picker (single choice, 18+ gate). */
@RunWith(AndroidJUnit4::class)
class FirstRunTest {
    @get:Rule val compose = createEmptyComposeRule()
    private val ctx: Context = ApplicationProvider.getApplicationContext()

    private fun s(id: Int, vararg args: Any) = ctx.getString(id, *args)

    /** Saved to the test storage service; CI uploads them for review. */
    private fun shot(name: String) {
        compose.waitForIdle()
        val bmp = InstrumentationRegistry.getInstrumentation().uiAutomation.takeScreenshot() ?: return
        TestStorage().openOutputFile("screenshots/$name.png").use { bmp.compress(Bitmap.CompressFormat.PNG, 100, it) }
    }

    @Test
    fun walkthroughThenInterestPicker() {
        ctx.getSharedPreferences("settings", Context.MODE_PRIVATE).edit().clear().commit()
        ActivityScenario.launch(MainActivity::class.java).use {
            val titles = listOf(
                R.string.ob1_title, R.string.ob2_title, R.string.ob3_title,
                R.string.ob4_title, R.string.ob5_title, R.string.ob6_title,
            )
            titles.forEachIndexed { i, title ->
                compose.onNodeWithText(s(title)).assertIsDisplayed()
                shot("1-walkthrough-${i + 1}")
                val button = if (i == titles.lastIndex) R.string.ob_start else R.string.ob_next
                compose.onNodeWithText(s(button)).performClick()
                compose.waitForIdle()
            }
            compose.onNodeWithText(s(R.string.start)).assertIsDisplayed()
            shot("2-home")

            compose.onNodeWithText(s(R.string.pick_tags, 0, 10)).performClick()
            compose.onNodeWithText("Long-term partner").performClick()
            compose.onNodeWithText("Short-term fun").performClick()
            // "Looking for" is single choice: the second pick replaced the first.
            compose.onNodeWithText("Short-term fun").assertIsSelected()
            compose.onNodeWithText("Long-term partner").assertIsNotSelected()
            compose.onNodeWithText(s(R.string.tags_count, 1, 10)).assertIsDisplayed()
            shot("3-picker")

            // 18+ interests stay hidden until the age warning is confirmed.
            compose.onNodeWithTag("tagList").performScrollToNode(hasText(s(R.string.adult_show)))
            compose.onNodeWithText("Adult videos").assertDoesNotExist()
            shot("4-adult-gate")
            compose.onNodeWithText(s(R.string.adult_show)).performClick()
            compose.onNodeWithText(s(R.string.adult_confirm)).assertIsDisplayed()
            shot("5-adult-warning")
            compose.onNodeWithText(s(R.string.adult_confirm)).performClick()
            compose.onNodeWithTag("tagList").performScrollToNode(hasText("Adult videos"))
            compose.onNodeWithText("Adult videos").performClick()
            compose.onNodeWithText(s(R.string.tags_count, 2, 10)).assertIsDisplayed()
            shot("6-adult-tags")
        }
    }
}
