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
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.outlined.Login
import androidx.compose.material.icons.outlined.WifiTethering
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.gutschke.wgrtc.WgrtcViewModel
import com.gutschke.wgrtc.data.Tunnel
import com.gutschke.wgrtc.ui.theme.BrandMark
import com.gutschke.wgrtc.ui.theme.StatusConnectingContainerLight
import com.gutschke.wgrtc.ui.theme.StatusConnectingLight
import com.gutschke.wgrtc.ui.theme.StatusUpContainerLight
import com.gutschke.wgrtc.ui.theme.StatusUpLight

/**
 * The home screen. Lists configured tunnels with a status pill
 * + a connect/disconnect Switch on each. Empty state shows the
 * brand mark + tagline + a single primary CTA.
 *
 * Top bar uses an extended FAB pattern with the brand mark in the
 * title slot — gives the app a recognisable visual fingerprint
 * without using a wordmark image. Settings live behind a gear
 * icon in the trailing position.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TunnelListScreen(
    onAddClick: () -> Unit,
    onTunnelClick: (Tunnel) -> Unit,
    onSettings: () -> Unit = {},
    vm: WgrtcViewModel = viewModel(),
) {
    val tunnels by vm.tunnels.collectAsState()
    val activeIds by vm.activeTunnelIds.collectAsState()
    val connectingId by vm.connectingTunnelId.collectAsState()
    // dropped vm.liveState — it's a singular legacy signal
    // that can't tell two concurrent tunnels apart.  Per-row state
    // is now (isActive contains id, connectingId == id) only.
    val error by vm.lastError.collectAsState()
    val tokenUsed by vm.tokenUsedAlert.collectAsState()
    val networkBlocked by com.gutschke.wgrtc.WgrtcApp.instance
        .networkBlockDetected.collectAsState()
    val connect = LocalConnect.current
    val disconnect = LocalDisconnect.current

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        BrandMark(size = 28.dp)
                        Spacer(Modifier.width(10.dp))
                        Text(
                            "wgrtc",
                            style = MaterialTheme.typography.titleLarge,
                        )
                    }
                },
                actions = {
                    IconButton(onClick = onSettings) {
                        Icon(Icons.Default.Settings, contentDescription = "Settings")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                ),
            )
        },
        floatingActionButton = {
            // Extended FAB with a label is more discoverable on a
            // sparse home screen than the bare "+" button. The
            // legacy short FAB was fine when the empty-state copy
            // already explained "tap +", but breaking the visual
            // tie between empty-state-text and FAB-icon helps when
            // the user has *one* tunnel: the FAB's role is "add
            // another" rather than "you forgot something".
            if (tunnels.isNotEmpty()) {
                ExtendedFloatingActionButton(
                    onClick = onAddClick,
                    icon = { Icon(Icons.Default.Add, contentDescription = null) },
                    text = { Text("Add tunnel") },
                )
            }
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding).padding(16.dp)) {
            if (networkBlocked) NetworkBlockedBanner()
            tokenUsed?.let { TokenUsedBanner(it.serverNote) { vm.dismissTokenUsedAlert() } }
            error?.let {
                Spacer(Modifier.height(8.dp))
                Text(
                    it,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
            if (tunnels.isEmpty()) {
                EmptyState(onAddClick)
            } else {
                Spacer(Modifier.height(4.dp))
                LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    items(tunnels, key = { it.id }) { t ->
                        TunnelCard(
                            tunnel = t,
                            isActive = activeIds.contains(t.id),
                            isConnecting = t.id == connectingId,
                            onClick = { onTunnelClick(t) },
                            onToggle = { wantUp ->
                                if (wantUp) connect(t.id) else disconnect(t.id)
                            },
                        )
                    }
                }
            }
        }
    }
}

// ─── Empty state ──────────────────────────────────────────────────

@Composable
private fun EmptyState(onAddClick: () -> Unit) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        modifier = Modifier.fillMaxWidth().padding(top = 48.dp),
    ) {
        BrandMark(size = 96.dp)
        Spacer(Modifier.height(20.dp))
        Text(
            "No tunnels yet",
            style = MaterialTheme.typography.headlineSmall,
        )
        Spacer(Modifier.height(6.dp))
        Text(
            "Connect to a network someone else is hosting, or set " +
                "up your own private tunnel for other devices to " +
                "join.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
            modifier = Modifier.padding(horizontal = 24.dp),
        )
        Spacer(Modifier.height(24.dp))
        ExtendedFloatingActionButton(
            onClick = onAddClick,
            icon = { Icon(Icons.Default.Add, contentDescription = null) },
            text = { Text("Add your first tunnel") },
        )
    }
}

// ─── Tunnel card ─────────────────────────────────────────────────

@Composable
private fun TunnelCard(
    tunnel: Tunnel,
    isActive: Boolean,
    isConnecting: Boolean,
    onClick: () -> Unit,
    onToggle: (Boolean) -> Unit,
) {
    val isHost = tunnel.source == Tunnel.Source.HOST_MODE
    val (badgeIcon, badgeTint) = if (isHost) {
        Icons.Outlined.WifiTethering to MaterialTheme.colorScheme.tertiary
    } else {
        Icons.Outlined.Login to MaterialTheme.colorScheme.primary
    }
    // state derives from per-tunnel signals only —
    // `isActive` from the unified active set, `isConnecting` from
    // the in-flight connect id.  No global liveState read here.
    val state = when {
        isConnecting -> ConnState.Connecting
        isActive -> ConnState.Up
        else -> ConnState.Down
    }

    Card(
        modifier = Modifier.fillMaxWidth().clickable { onClick() },
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface,
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(44.dp)
                    .clip(RoundedCornerShape(10.dp))
                    .background(badgeTint.copy(alpha = 0.10f)),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    badgeIcon,
                    contentDescription = null,
                    tint = badgeTint,
                    modifier = Modifier.size(22.dp),
                )
            }

            Column(modifier = Modifier.weight(1f)) {
                Text(tunnel.name, style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(4.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    StatusPill(state)
                    Spacer(Modifier.width(8.dp))
                    Text(
                        if (isHost) "Hosting" else "Client",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }

            if (isConnecting) {
                CircularProgressIndicator(
                    modifier = Modifier.size(28.dp),
                    strokeWidth = 3.dp,
                )
            } else {
                Switch(checked = isActive, onCheckedChange = onToggle)
            }
        }
    }
}

private enum class ConnState { Up, Down, Connecting }

@Composable
private fun StatusPill(state: ConnState) {
    val (label, fg, bg) = when (state) {
        ConnState.Up -> Triple("Connected", StatusUpLight, StatusUpContainerLight)
        ConnState.Connecting -> Triple("Connecting…", StatusConnectingLight, StatusConnectingContainerLight)
        ConnState.Down -> Triple(
            "Idle",
            MaterialTheme.colorScheme.onSurfaceVariant,
            MaterialTheme.colorScheme.surfaceVariant,
        )
    }
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(6.dp))
            .background(bg as Color)
            .padding(horizontal = 8.dp, vertical = 2.dp),
    ) {
        Text(
            label as String,
            style = MaterialTheme.typography.labelSmall,
            color = fg as Color,
        )
    }
}

// ─── Banners ──────────────────────────────────────────────────────

@Composable
private fun NetworkBlockedBanner() {
    val ctx = androidx.compose.ui.platform.LocalContext.current
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.errorContainer,
            contentColor = MaterialTheme.colorScheme.onErrorContainer,
        ),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Filled.Warning, contentDescription = null,
                    modifier = Modifier.padding(end = 8.dp))
                Text("Network access blocked",
                    style = MaterialTheme.typography.titleMedium)
            }
            Spacer(Modifier.height(8.dp))
            Text(
                "Android is silently dropping this app's outbound " +
                    "traffic, so we can't reach the broker to set up " +
                    "tunnels.\n\n" +
                    "Try in order:\n" +
                    " 1. Settings → Apps → wgrtc → Mobile data " +
                    "& WiFi: enable Background data\n" +
                    " 2. Settings → Apps → wgrtc → Battery: " +
                    "make sure \"Restricted\" isn't selected\n" +
                    " 3. If neither works: uninstall, reboot, " +
                    "reinstall — Android occasionally applies " +
                    "invisible per-app restrictions that user " +
                    "settings can't fully clear.",
                style = MaterialTheme.typography.bodyMedium,
            )
            Spacer(Modifier.height(8.dp))
            TextButton(onClick = {
                val intent = android.content.Intent(
                    android.provider.Settings
                        .ACTION_APPLICATION_DETAILS_SETTINGS,
                    android.net.Uri.fromParts("package", ctx.packageName, null),
                ).apply {
                    addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                ctx.startActivity(intent)
            }) { Text("Open app settings") }
        }
    }
    Spacer(Modifier.height(12.dp))
}

@Composable
private fun TokenUsedBanner(serverNote: String?, onDismiss: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.errorContainer,
            contentColor = MaterialTheme.colorScheme.onErrorContainer,
        ),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Filled.Warning, contentDescription = null,
                    modifier = Modifier.padding(end = 8.dp))
                Text("Enrollment hijack possible",
                    style = MaterialTheme.typography.titleMedium)
            }
            Spacer(Modifier.height(8.dp))
            Text(
                "The server reported the enrollment QR you just used " +
                    "was already consumed. If this is a re-launch with " +
                    "the same QR, ignore this; otherwise treat the QR " +
                    "as compromised and ask for a fresh one.",
                style = MaterialTheme.typography.bodyMedium,
            )
            serverNote?.let {
                Spacer(Modifier.height(4.dp))
                Text("Server note: $it",
                    style = MaterialTheme.typography.bodySmall)
            }
            Spacer(Modifier.height(8.dp))
            TextButton(onClick = onDismiss) { Text("Dismiss") }
        }
    }
    Spacer(Modifier.height(12.dp))
}
