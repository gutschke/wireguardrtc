package com.gutschke.wgrtc.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.ContentPaste
import androidx.compose.material.icons.outlined.Edit
import androidx.compose.material.icons.outlined.QrCodeScanner
import androidx.compose.material.icons.outlined.VpnKey
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp

/**
 * Methods for joining a tunnel — listed in expected-frequency
 * order:
 *
 * 1. **Scan QR** — fastest path; what host operators hand out
 * most often.
 * 2. **Type wormhole code** — six-letter shared secret with SAS
 * confirmation; doesn't require a camera.
 * 3. **Paste config** — clipboard-friendly path for users who
 * receive a config block via chat or email.
 * 4. **Enter manually** — escape hatch when the user has the
 * individual fields written down.
 *
 * Visual: each method gets a tinted icon tile and a one-line
 * description. The list is dense rather than card-spaced — the
 * methods are siblings, not co-equal headline choices.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun JoinTunnelScreen(
    onBack: () -> Unit,
    onScanQr: () -> Unit,
    onWormhole: () -> Unit,
    onPaste: () -> Unit,
    onManual: () -> Unit,
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Join a tunnel") },
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
            modifier = Modifier.fillMaxSize().padding(padding).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                "How was the tunnel shared with you?",
                style = MaterialTheme.typography.titleMedium,
            )
            Spacer(Modifier.height(4.dp))
            MethodRow(
                icon = Icons.Outlined.QrCodeScanner,
                title = "Scan a QR code",
                body = "Open the camera and point it at a QR shown by the host.",
                onClick = onScanQr,
            )
            MethodRow(
                icon = Icons.Outlined.VpnKey,
                title = "Type a wormhole code",
                body = "Enter the short code the host is showing you. " +
                    "Both screens display the same confirmation phrase " +
                    "before connecting.",
                onClick = onWormhole,
            )
            MethodRow(
                icon = Icons.Outlined.ContentPaste,
                title = "Paste a config",
                body = "Paste a wg-quick block or a wgrtc-enroll:// URI " +
                    "from the clipboard.",
                onClick = onPaste,
            )
            MethodRow(
                icon = Icons.Outlined.Edit,
                title = "Enter the details by hand",
                body = "Type each WireGuard field individually. Useful " +
                    "when the parameters are listed on another screen.",
                onClick = onManual,
            )
        }
    }
}

@Composable
private fun MethodRow(
    icon: ImageVector,
    title: String,
    body: String,
    onClick: () -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface,
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(44.dp)
                    .clip(RoundedCornerShape(10.dp))
                    .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.10f)),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    icon,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(24.dp),
                )
            }
            Column(modifier = Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.titleSmall)
                Spacer(Modifier.height(2.dp))
                Text(
                    body,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}
