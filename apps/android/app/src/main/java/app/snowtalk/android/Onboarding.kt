package app.snowtalk.android

import androidx.annotation.StringRes
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch
import kotlin.math.absoluteValue

private data class Slide(
    val emoji: String,
    @StringRes val title: Int,
    @StringRes val body: Int,
    val from: Color,
    val to: Color,
)

private val slides = listOf(
    Slide("❄️", R.string.ob1_title, R.string.ob1_body, Color(0xFF1E3A8A), Color(0xFF0EA5E9)),
    Slide("🔐", R.string.ob2_title, R.string.ob2_body, Color(0xFF312E81), Color(0xFF7C3AED)),
    Slide("🧊", R.string.ob3_title, R.string.ob3_body, Color(0xFF0F766E), Color(0xFF22D3EE)),
    Slide("🎯", R.string.ob4_title, R.string.ob4_body, Color(0xFF9D174D), Color(0xFFF472B6)),
    Slide("🧭", R.string.ob5_title, R.string.ob5_body, Color(0xFF7C2D12), Color(0xFFF59E0B)),
    Slide("💬", R.string.ob6_title, R.string.ob6_body, Color(0xFF14532D), Color(0xFF22C55E)),
)

/** First-launch walkthrough: how the privacy works, and how to use the app. */
@OptIn(ExperimentalFoundationApi::class)
@Composable
fun Onboarding(onDone: () -> Unit) {
    val pager = rememberPagerState { slides.size }
    val scope = rememberCoroutineScope()
    val last = pager.currentPage == slides.lastIndex
    val top by animateColorAsState(slides[pager.currentPage].from, label = "top")
    val bottom by animateColorAsState(slides[pager.currentPage].to, label = "bottom")
    Box(Modifier.fillMaxSize().background(Brush.verticalGradient(listOf(top, bottom)))) {
        Column(Modifier.fillMaxSize().safeDrawingPadding()) {
            Row(Modifier.fillMaxWidth().padding(8.dp), horizontalArrangement = Arrangement.End) {
                if (!last) {
                    TextButton(onClick = onDone) { Text(stringResource(R.string.ob_skip), color = Color.White) }
                } else {
                    Spacer(Modifier.height(48.dp))
                }
            }
            HorizontalPager(state = pager, modifier = Modifier.weight(1f)) { page ->
                val s = slides[page]
                // Parallax-ish fade/scale as pages slide.
                val offset = ((pager.currentPage - page) + pager.currentPageOffsetFraction).absoluteValue
                Column(
                    Modifier.fillMaxSize().padding(horizontal = 32.dp).graphicsLayer {
                        alpha = 1f - offset.coerceIn(0f, 1f) * 0.6f
                        scaleX = 1f - offset.coerceIn(0f, 1f) * 0.08f
                        scaleY = scaleX
                    },
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center,
                ) {
                    Box(
                        Modifier.size(168.dp).clip(CircleShape).background(
                            Brush.radialGradient(listOf(Color.White.copy(alpha = 0.35f), Color.White.copy(alpha = 0.05f))),
                        ),
                        contentAlignment = Alignment.Center,
                    ) { Text(s.emoji, fontSize = 76.sp) }
                    Spacer(Modifier.height(36.dp))
                    Text(
                        stringResource(s.title),
                        color = Color.White,
                        fontSize = 28.sp,
                        fontWeight = FontWeight.Bold,
                        textAlign = TextAlign.Center,
                        lineHeight = 34.sp,
                    )
                    Spacer(Modifier.height(16.dp))
                    Text(
                        stringResource(s.body),
                        color = Color.White.copy(alpha = 0.92f),
                        fontSize = 16.sp,
                        lineHeight = 24.sp,
                        textAlign = TextAlign.Center,
                    )
                }
            }
            Row(Modifier.fillMaxWidth().padding(vertical = 16.dp), horizontalArrangement = Arrangement.Center) {
                repeat(slides.size) { i ->
                    val w by animateDpAsState(if (i == pager.currentPage) 24.dp else 8.dp, label = "dot")
                    Box(
                        Modifier.padding(horizontal = 4.dp).height(8.dp).width(w).clip(RoundedCornerShape(4.dp))
                            .background(Color.White.copy(alpha = if (i == pager.currentPage) 1f else 0.4f)),
                    )
                }
            }
            Button(
                onClick = { if (last) onDone() else scope.launch { pager.animateScrollToPage(pager.currentPage + 1) } },
                colors = ButtonDefaults.buttonColors(containerColor = Color.White, contentColor = bottom),
                modifier = Modifier.fillMaxWidth().padding(horizontal = 24.dp).padding(bottom = 24.dp).height(54.dp),
            ) {
                Text(
                    stringResource(if (last) R.string.ob_start else R.string.ob_next),
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 17.sp,
                )
            }
        }
    }
}
