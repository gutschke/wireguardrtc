package com.gutschke.wgrtc.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.gutschke.wgrtc.ui.theme.BrandMark

/**
 * About / acknowledgements screen. Two roles:
 *
 * - **Identity**: brand mark + app name + version + tagline,
 * reachable from Settings. Gives the user a tap-to-confirm
 * "yes, this is the app I installed" surface, which doubles
 * as a pleasant aesthetic touchpoint.
 * - **License compliance**: every third-party library we ship
 * gets a short attribution line (name + license + one-line
 * description). Required-ish before Play Store review
 * because the bundled native code (`libwgbridge_native.so`
 * embedding wireguard-go + gVisor netstack,
 * `libsodiumjni.so` from lazysodium) carries upstream
 * copyright notices that need to be surfaced somewhere
 * reachable from the app UI.
 *
 * Kept entirely static — no dynamic license scraping — because
 * the dependency set is small and slow-moving. Update by hand
 * when [build.gradle.kts] grows a new entry.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AboutScreen(onBack: () -> Unit) {
    val ctx = androidx.compose.ui.platform.LocalContext.current
    val versionName = remember {
        try {
            ctx.packageManager.getPackageInfo(ctx.packageName, 0).versionName
                ?: ""
        } catch (_: Throwable) { "" }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("About") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                ),
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
        ) {
            Column(
                modifier = Modifier.fillMaxWidth().padding(top = 16.dp, bottom = 24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                BrandMark(size = 96.dp)
                Spacer(Modifier.height(16.dp))
                Text(
                    "wgrtc",
                    style = MaterialTheme.typography.headlineSmall,
                )
                Spacer(Modifier.height(2.dp))
                Text(
                    if (versionName.isNotEmpty()) "Version $versionName" else "",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(12.dp))
                Text(
                    "WireGuard tunnels that find their way home through " +
                        "NAT and roaming IPs.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.padding(horizontal = 24.dp),
                )
                Spacer(Modifier.height(14.dp))
                Text(
                    "Licensed under the Apache License 2.0",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    "github.com/gutschke/wgrtc",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontFamily = FontFamily.Monospace,
                )
            }

            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)

            Spacer(Modifier.height(20.dp))
            Text(
                "Open-source ingredients",
                style = MaterialTheme.typography.titleMedium,
            )
            Spacer(Modifier.height(4.dp))
            Text(
                "wgrtc is built on top of the work of these " +
                    "projects. Each ships under a permissive licence " +
                    "that lets us combine and redistribute their code; " +
                    "the licences themselves are below.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(16.dp))
            Acknowledgements.entries.forEach { entry ->
                AckRow(entry)
                Spacer(Modifier.height(12.dp))
            }

            Spacer(Modifier.height(20.dp))
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            Spacer(Modifier.height(16.dp))
            Text(
                "WireGuard is a registered trademark of Jason A. Donenfeld.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(20.dp))
        }
    }
}

@Composable
private fun AckRow(entry: AcknowledgementEntry) {
    Column {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.Top,
        ) {
            Text(
                entry.name,
                style = MaterialTheme.typography.titleSmall,
                fontFamily = FontFamily.Monospace,
            )
            Text(
                entry.license,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Spacer(Modifier.height(2.dp))
        Text(
            entry.description,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

private data class AcknowledgementEntry(
    val name: String,
    val license: String,
    val description: String,
)

private object Acknowledgements {
    val entries: List<AcknowledgementEntry> = listOf(
        AcknowledgementEntry(
            "wireguard-go",
            "MIT",
            "Userspace Go implementation of the WireGuard protocol. " +
                "Built into libwgbridge_native.so via cgo + //export " +
                "(see docs/wireguard-runtime-architecture.md).",
        ),
        AcknowledgementEntry(
            "gvisor netstack",
            "Apache 2.0",
            "Userspace TCP/IP stack from Google's gVisor. Lets us " +
                "speak TCP / UDP through the userspace WireGuard tun " +
                "without a kernel /dev/net/tun.",
        ),
        AcknowledgementEntry(
            "lazysodium-android",
            "MPL 2.0",
            "Java bindings for libsodium. Provides X25519, BLAKE2b, " +
                "secretbox, Ristretto255 — the cryptographic primitives " +
                "behind the wormhole / SAS flow and the signalling-OFFER " +
                "envelope.",
        ),
        AcknowledgementEntry(
            "ZXing + zxing-android-embedded",
            "Apache 2.0",
            "QR code encoder / scanner. Powers the invitation QR + " +
                "the in-app camera scanner.",
        ),
        AcknowledgementEntry(
            "OkHttp",
            "Apache 2.0",
            "HTTP / WebSocket client. Used for the long-lived broker " +
                "session and one-shot enrolment requests.",
        ),
        AcknowledgementEntry(
            "kotlinx.coroutines + kotlinx.serialization",
            "Apache 2.0",
            "Async runtime + JSON codec from JetBrains. Underpin every " +
                "background task and every wire-format envelope.",
        ),
        AcknowledgementEntry(
            "Jetpack Compose + AndroidX",
            "Apache 2.0",
            "UI toolkit, navigation, lifecycle scaffolding, Material 3 " +
                "design system.",
        ),
        AcknowledgementEntry(
            "Material Symbols (Outlined)",
            "Apache 2.0",
            "Icon set used throughout the app, via Compose's " +
                "material-icons-extended.",
        ),
        AcknowledgementEntry(
            "JNA",
            "Apache 2.0 / LGPL 2.1",
            "Java Native Access — used by lazysodium to call libsodium " +
                "without writing JNI by hand.",
        ),
    )
}
