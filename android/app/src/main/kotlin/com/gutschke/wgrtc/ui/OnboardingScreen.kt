package com.gutschke.wgrtc.ui

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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ContentPaste
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.QrCodeScanner
import androidx.compose.material.icons.outlined.VpnKey
import androidx.compose.material.icons.outlined.WifiTethering
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.gutschke.wgrtc.ui.theme.BrandMark
import kotlinx.coroutines.launch

/**
 * Three-page first-launch tour. Shown once after install, gated
 * by [com.gutschke.wgrtc.data.SettingsStore.onboardingSeen].
 *
 * Each page is full-screen with a centred hero (brand mark or
 * icon-grid) above a short headline + body paragraph. Bottom row
 * carries the page indicator + a Skip / Next / Get started action.
 *
 * Why three pages instead of one:
 * - Page 1 frames the app's identity at a glance — important
 * because the launcher icon is the user's first encounter; a
 * written confirmation of "this is the WireGuard app I just
 * installed" calms the second-where-am-I moment.
 * - Page 2 makes the three join paths discoverable before the
 * user is staring at a "tap +" empty state.
 * - Page 3 surfaces the privacy story so non-technical users
 * understand keys never leave the device — a question the
 * "VPN apps" category gets asked constantly.
 */
@Composable
fun OnboardingScreen(onDone: () -> Unit) {
    val pagerState = rememberPagerState { 3 }
    val scope = rememberCoroutineScope()

    Scaffold { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp),
        ) {
            // Skip stays visible the whole tour — short-circuits any
            // user who's already familiar with the app from a
            // reinstall or who'd rather just dive in.
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.End,
            ) {
                if (pagerState.currentPage < 2) {
                    TextButton(onClick = onDone) { Text("Skip") }
                } else {
                    // Reserve the space so the layout doesn't jump
                    // when we hide the Skip button on the last page.
                    Spacer(Modifier.height(48.dp))
                }
            }
            HorizontalPager(
                state = pagerState,
                modifier = Modifier.weight(1f),
            ) { page ->
                when (page) {
                    0 -> WelcomePage()
                    1 -> JoinMethodsPage()
                    2 -> PrivacyPage()
                }
            }
            // Indicators + primary CTA.
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 16.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                PageIndicator(pagerState.currentPage, total = 3)
                if (pagerState.currentPage < 2) {
                    TextButton(onClick = {
                        scope.launch {
                            pagerState.animateScrollToPage(pagerState.currentPage + 1)
                        }
                    }) { Text("Next") }
                } else {
                    Button(onClick = onDone) { Text("Get started") }
                }
            }
        }
    }
}

@Composable
private fun PageIndicator(current: Int, total: Int) {
    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        for (i in 0 until total) {
            val active = i == current
            Box(
                modifier = Modifier
                    .size(if (active) 10.dp else 8.dp)
                    .clip(CircleShape)
                    .background(
                        if (active) MaterialTheme.colorScheme.primary
                        else MaterialTheme.colorScheme.outline.copy(alpha = 0.4f)
                    ),
            )
        }
    }
}

// ─── Page 1: welcome ─────────────────────────────────────────────

@Composable
private fun WelcomePage() {
    Column(
        modifier = Modifier.fillMaxSize().padding(top = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        BrandMark(size = 120.dp)
        Spacer(Modifier.height(24.dp))
        Text(
            "Private networks, when you need them",
            style = MaterialTheme.typography.headlineMedium,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(12.dp))
        Text(
            "wgrtc connects your devices through tunnels you control — " +
                "no accounts, no subscription, no central service. " +
                "Hosts run the tunnel; everyone else joins.",
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
            modifier = Modifier.padding(horizontal = 16.dp),
        )
    }
}

// ─── Page 2: join methods ───────────────────────────────────────

@Composable
private fun JoinMethodsPage() {
    Column(
        modifier = Modifier.fillMaxSize().padding(top = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(20.dp),
    ) {
        Text(
            "Three ways to join",
            style = MaterialTheme.typography.headlineSmall,
            textAlign = TextAlign.Center,
        )
        Text(
            "When the host invites you, they hand you one of these. " +
                "Use whatever's most convenient.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
            modifier = Modifier.padding(horizontal = 16.dp),
        )
        Spacer(Modifier.height(8.dp))
        MethodTeaser(
            icon = Icons.Outlined.QrCodeScanner,
            title = "Scan a QR",
            body = "Camera-based — fastest path.",
        )
        MethodTeaser(
            icon = Icons.Outlined.VpnKey,
            title = "Type a wormhole code",
            body = "Six letters; both screens show the same " +
                "confirmation phrase before connecting.",
        )
        MethodTeaser(
            icon = Icons.Outlined.ContentPaste,
            title = "Paste a config block",
            body = "For invitations sent over chat or email.",
        )
        Spacer(Modifier.height(8.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                Icons.Outlined.WifiTethering,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.tertiary,
                modifier = Modifier.size(20.dp),
            )
            Spacer(Modifier.width(8.dp))
            Text(
                "Or be the host yourself.",
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.tertiary,
            )
        }
    }
}

@Composable
private fun MethodTeaser(icon: ImageVector, title: String, body: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.Top,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Box(
            modifier = Modifier
                .size(36.dp)
                .clip(RoundedCornerShape(10.dp))
                .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.10f)),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                icon, contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(20.dp),
            )
        }
        Column {
            Text(title, style = MaterialTheme.typography.titleSmall)
            Text(
                body,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

// ─── Page 3: privacy ────────────────────────────────────────────

@Composable
private fun PrivacyPage() {
    Column(
        modifier = Modifier.fillMaxSize().padding(top = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Box(
            modifier = Modifier
                .size(96.dp)
                .clip(CircleShape)
                .background(MaterialTheme.colorScheme.primaryContainer),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                Icons.Outlined.Lock,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onPrimaryContainer,
                modifier = Modifier.size(48.dp),
            )
        }
        Spacer(Modifier.height(24.dp))
        Text(
            "Yours, on this device",
            style = MaterialTheme.typography.headlineSmall,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(12.dp))
        Text(
            "Keys are generated and stored locally — they never " +
                "leave your phone. No analytics, no tracking, no " +
                "account. wgrtc routes your traffic only through " +
                "tunnels you've explicitly added.",
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
            modifier = Modifier.padding(horizontal = 16.dp),
        )
    }
}
