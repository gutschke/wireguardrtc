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
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Login
import androidx.compose.material.icons.outlined.WifiTethering
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Button
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.OutlinedButton
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
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
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
    val chromeOsWarningFor by vm.chromeOsLoopWarningFor.collectAsState()
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
                // CASCADE-2 §2.3 banner eligibility — surfaced once
                // per host tunnel that's actively running while at
                // least one joiner is connected.  Empty when no host
                // is in Ask state.
                val activeJoinerCount = tunnels.count { t ->
                    t.source != Tunnel.Source.HOST_MODE && activeIds.contains(t.id)
                }
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
                        if (t.source == Tunnel.Source.HOST_MODE &&
                            t.relayPolicy == com.gutschke.wgrtc.data.RelayPolicy.Ask &&
                            activeIds.contains(t.id) &&
                            activeJoinerCount > 0
                        ) {
                            CascadeAskBanner(
                                hostName = t.name,
                                onAllow = { vm.setRelayPolicy(t.id, com.gutschke.wgrtc.data.RelayPolicy.Always) },
                                onBlock = { vm.setRelayPolicy(t.id, com.gutschke.wgrtc.data.RelayPolicy.Never) },
                            )
                        }
                    }
                }
            }
        }
    }

    // §6.2 ChromeOS routing-loop warning.  Sticky dismissal lives
    // on the persisted Tunnel; the dialog only renders once per
    // host tunnel.  See `docs/ux-design-v2.md` §6.2.
    val ctx = androidx.compose.ui.platform.LocalContext.current
    chromeOsWarningFor?.let { t ->
        ChromeOsRoutingLoopDialog(
            hostName = t.name,
            onOpenSettings = {
                val intent = android.content.Intent(
                    android.provider.Settings.ACTION_VPN_SETTINGS)
                intent.flags = android.content.Intent.FLAG_ACTIVITY_NEW_TASK
                runCatching { ctx.startActivity(intent) }
                vm.acknowledgeChromeOsLoopWarning(t.id, proceed = true)
            },
            onContinue = {
                vm.acknowledgeChromeOsLoopWarning(t.id, proceed = true)
            },
            onCancel = {
                vm.acknowledgeChromeOsLoopWarning(t.id, proceed = false)
            },
        )
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
    // §11.4 — registry-derived state is the source of truth.  Old
    // (isActive, isConnecting) tuple is a fallback when the registry
    // hasn't seen any transitions yet (typically because the user
    // just imported a tunnel and hasn't tapped Connect).
    val registry = com.gutschke.wgrtc.data.TunnelStateRegistry
        .getProcessSingleton()
    val tunnelState by registry.stateOf(tunnel.id).collectAsState()
    val state = stateForPill(
        registryState = tunnelState,
        isActive = isActive,
        isConnecting = isConnecting,
    )
    // §4.1 — when the pill represents a Failed or PausedSystem
    // state we make it tappable so the user can see the structured
    // human-readable reason + one-tap remediation.
    var failureDetail by remember(tunnel.id) {
        mutableStateOf<com.gutschke.wgrtc.data.TunnelState?>(null)
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
                    StatusPill(
                        state = state,
                        onClick = if (tunnelState is com.gutschke.wgrtc.data.TunnelState.Failed ||
                            tunnelState is com.gutschke.wgrtc.data.TunnelState.PausedSystem) {
                            { failureDetail = tunnelState }
                        } else null,
                    )
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

    failureDetail?.let { detail ->
        FailureDetailDialog(
            tunnel = tunnel,
            state = detail,
            onDismiss = { failureDetail = null },
        )
    }
}

/**
 * Status alphabet shown in the row pill.  Maps the registry's
 * 9-state machine down to a smaller-cardinality presentation —
 * the design's §3.1 colour palette has 8 distinct slots but the
 * `Disabled` and `PausedUser` cases share "switch off" visual
 * affordances, and `Connecting` covers both `Arming` and
 * `Connecting` proper.
 */
private enum class ConnState {
    Connected,    // green
    Idle,         // gray (no-traffic non-fault)
    Connecting,   // amber spinner
    PausedSystem, // amber pill — "system paused"
    PausedUser,   // blue pill — user pause
    Pairing,      // violet — wormhole flow
    Degraded,     // amber — handshake stale
    FailedRec,    // red — recoverable
    FailedPerm,   // dark red — needs user action
    Disabled,     // neutral (also the legacy "Down")
}

/**
 * Translate a registry state + the legacy (isActive, isConnecting)
 * tuple into a single ConnState.  Registry wins when it has anything
 * other than [TunnelState.Disabled]; otherwise we fall back so a
 * never-touched tunnel doesn't appear as "Disabled" while the user
 * thinks it just imported it (the legacy code rendered "Idle").
 */
private fun stateForPill(
    registryState: com.gutschke.wgrtc.data.TunnelState,
    isActive: Boolean,
    isConnecting: Boolean,
): ConnState = when (registryState) {
    com.gutschke.wgrtc.data.TunnelState.Connected -> ConnState.Connected
    com.gutschke.wgrtc.data.TunnelState.Idle -> ConnState.Idle
    com.gutschke.wgrtc.data.TunnelState.Connecting,
    com.gutschke.wgrtc.data.TunnelState.Arming -> ConnState.Connecting
    com.gutschke.wgrtc.data.TunnelState.Degraded -> ConnState.Degraded
    is com.gutschke.wgrtc.data.TunnelState.PausedSystem -> ConnState.PausedSystem
    com.gutschke.wgrtc.data.TunnelState.PausedUser -> ConnState.PausedUser
    com.gutschke.wgrtc.data.TunnelState.Pairing -> ConnState.Pairing
    is com.gutschke.wgrtc.data.TunnelState.Failed ->
        if (registryState.recoverable) ConnState.FailedRec else ConnState.FailedPerm
    com.gutschke.wgrtc.data.TunnelState.Disabled -> when {
        // Legacy fallback — the registry hasn't seen this tunnel
        // yet but the ViewModel's old active-set still says it's
        // up.  Trust the older signal until the rest of the
        // pipeline starts emitting transitions.
        isConnecting -> ConnState.Connecting
        isActive -> ConnState.Connected
        else -> ConnState.Idle
    }
}

@Composable
private fun StatusPill(state: ConnState, onClick: (() -> Unit)? = null) {
    val (label, fg, bg) = when (state) {
        ConnState.Connected ->
            Triple("Connected", StatusUpLight, StatusUpContainerLight)
        ConnState.Connecting ->
            Triple("Connecting…", StatusConnectingLight, StatusConnectingContainerLight)
        ConnState.Idle -> Triple(
            "Idle",
            MaterialTheme.colorScheme.onSurfaceVariant,
            MaterialTheme.colorScheme.surfaceVariant,
        )
        ConnState.Disabled -> Triple(
            "Off",
            MaterialTheme.colorScheme.onSurfaceVariant,
            MaterialTheme.colorScheme.surfaceVariant,
        )
        ConnState.PausedSystem -> Triple(
            "System paused",
            MaterialTheme.colorScheme.onTertiaryContainer,
            MaterialTheme.colorScheme.tertiaryContainer,
        )
        ConnState.PausedUser -> Triple(
            "Paused",
            MaterialTheme.colorScheme.onSecondaryContainer,
            MaterialTheme.colorScheme.secondaryContainer,
        )
        ConnState.Pairing -> Triple(
            "Pairing…",
            MaterialTheme.colorScheme.onSecondaryContainer,
            MaterialTheme.colorScheme.secondaryContainer,
        )
        ConnState.Degraded -> Triple(
            "Reconnecting",
            MaterialTheme.colorScheme.onTertiaryContainer,
            MaterialTheme.colorScheme.tertiaryContainer,
        )
        ConnState.FailedRec -> Triple(
            "Connection failed",
            MaterialTheme.colorScheme.onErrorContainer,
            MaterialTheme.colorScheme.errorContainer,
        )
        ConnState.FailedPerm -> Triple(
            "Needs attention",
            MaterialTheme.colorScheme.onError,
            MaterialTheme.colorScheme.error,
        )
    }
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(6.dp))
            .background(bg as Color)
            .let { if (onClick != null) it.clickable { onClick() } else it }
            .padding(horizontal = 8.dp, vertical = 2.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                label as String,
                style = MaterialTheme.typography.labelSmall,
                color = fg as Color,
            )
            if (onClick != null) {
                // Subtle tap affordance — the i in a circle nudges
                // discoverability without shouting.
                Spacer(Modifier.width(4.dp))
                Icon(
                    Icons.Outlined.Info,
                    contentDescription = "Details",
                    tint = fg,
                    modifier = Modifier.size(14.dp),
                )
            }
        }
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

/**
 * §4.1 failure-cause dialog.  Shown when the user taps the status
 * pill on a row in [TunnelState.Failed] or [TunnelState.PausedSystem].
 * Renders the human-readable message + a single one-tap remediation
 * action when one applies.
 */
@Composable
private fun FailureDetailDialog(
    tunnel: Tunnel,
    state: com.gutschke.wgrtc.data.TunnelState,
    onDismiss: () -> Unit,
) {
    val ctx = androidx.compose.ui.platform.LocalContext.current
    val connect = LocalConnect.current
    val (title, body, action) = remember(state) {
        failureCopy(tunnel, state)
    }
    androidx.compose.material3.AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = { Text(body) },
        confirmButton = {
            action?.let { (label, intent) ->
                Button(onClick = {
                    when (intent) {
                        is FailureRemediation.Retry -> connect(tunnel.id)
                        is FailureRemediation.OpenVpnSettings -> {
                            val i = android.content.Intent(
                                android.provider.Settings.ACTION_VPN_SETTINGS,
                            ).apply {
                                flags = android.content.Intent.FLAG_ACTIVITY_NEW_TASK
                            }
                            runCatching { ctx.startActivity(i) }
                        }
                        is FailureRemediation.OpenAppInfo -> {
                            val i = android.content.Intent(
                                android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                                android.net.Uri.fromParts("package", ctx.packageName, null),
                            ).apply {
                                flags = android.content.Intent.FLAG_ACTIVITY_NEW_TASK
                            }
                            runCatching { ctx.startActivity(i) }
                        }
                    }
                    onDismiss()
                }) { Text(label) }
            } ?: TextButton(onClick = onDismiss) { Text("Got it") }
        },
        dismissButton = if (action != null) {
            { TextButton(onClick = onDismiss) { Text("Dismiss") } }
        } else null,
    )
}

/** One-tap action the user can take from a failure dialog. */
internal sealed class FailureRemediation {
    object Retry : FailureRemediation()
    object OpenVpnSettings : FailureRemediation()
    object OpenAppInfo : FailureRemediation()
}

/** Maps a [TunnelState] to (title, body, optional (label, intent))
 *  triples.  Pure function; tests live in `TunnelListFailureCopyTest`. */
internal fun failureCopy(
    tunnel: Tunnel,
    state: com.gutschke.wgrtc.data.TunnelState,
): Triple<String, String, Pair<String, FailureRemediation>?> = when (state) {
    is com.gutschke.wgrtc.data.TunnelState.Failed -> when (val cause = state.cause) {
        com.gutschke.wgrtc.data.FailureCause.ConsentDenied -> Triple(
            "Permission needed",
            "Android didn't grant permission for this connection. Tap to ask again.",
            "Ask again" to FailureRemediation.Retry,
        )
        com.gutschke.wgrtc.data.FailureCause.ConsentSilentlyDenied -> Triple(
            "Permission blocked",
            "Android is silently refusing the VPN permission for this app. " +
                "Open System Settings → Apps → wgrtc → Permissions to clear the denial.",
            "Open app info" to FailureRemediation.OpenAppInfo,
        )
        com.gutschke.wgrtc.data.FailureCause.BrokerMissing -> Triple(
            "No signaling server",
            "This tunnel relies on a signaling server to keep your peer's " +
                "endpoint up to date. The broker URL is empty — open the " +
                "tunnel's details and set one, or restore the default in " +
                "Settings.",
            null,
        )
        is com.gutschke.wgrtc.data.FailureCause.BrokerUnreachable -> Triple(
            "Signaling server unreachable",
            "Can't reach the signaling server at ${cause.url}. Check your " +
                "internet connection.",
            "Retry" to FailureRemediation.Retry,
        )
        com.gutschke.wgrtc.data.FailureCause.PeerKeyRejected -> Triple(
            "Identity rejected",
            "The other side rejected this connection's identity. " +
                "The remote server may have removed this device.",
            null,
        )
        is com.gutschke.wgrtc.data.FailureCause.HandshakeTimeout -> Triple(
            "Couldn't reach the server",
            "Couldn't reach the server at ${cause.endpoint}. The endpoint " +
                "may be down or moved.",
            "Retry" to FailureRemediation.Retry,
        )
        is com.gutschke.wgrtc.data.FailureCause.PortInUse -> Triple(
            "Port in use",
            "UDP port ${cause.port} is busy. Another VPN app or wgrtc " +
                "tunnel is probably using it.",
            null,
        )
        com.gutschke.wgrtc.data.FailureCause.RoutingLoopUserConfirmed -> Triple(
            "Routing-loop risk",
            "You said another WireGuard client routes through this device. " +
                "Disable that client first, then re-enable this tunnel.",
            "Open VPN settings" to FailureRemediation.OpenVpnSettings,
        )
        com.gutschke.wgrtc.data.FailureCause.CascadePolicyBlocked -> Triple(
            "Relay blocked",
            "This tunnel is set to never relay. Open the tunnel's details " +
                "to allow relay.",
            null,
        )
        com.gutschke.wgrtc.data.FailureCause.PairingSasMismatch -> Triple(
            "Pairing code mismatch",
            "The pairing code didn't match. Re-enter or ask the other side " +
                "for a fresh one.",
            "Retry" to FailureRemediation.Retry,
        )
        com.gutschke.wgrtc.data.FailureCause.PairingCancelled -> Triple(
            "Pairing cancelled",
            "The pairing flow ended before both sides confirmed. Restart " +
                "from the other side.",
            null,
        )
    }
    is com.gutschke.wgrtc.data.TunnelState.PausedSystem -> when (state.reason) {
        com.gutschke.wgrtc.data.PauseReason.AnotherVpnTookOver -> Triple(
            "Another VPN is active",
            "Another VPN app took over the system VPN slot. Disable it, " +
                "then turn this tunnel back on.",
            "Open VPN settings" to FailureRemediation.OpenVpnSettings,
        )
        com.gutschke.wgrtc.data.PauseReason.EstablishNull,
        com.gutschke.wgrtc.data.PauseReason.ForegroundResync,
        com.gutschke.wgrtc.data.PauseReason.BackgroundResync -> Triple(
            "VPN permission revoked",
            "Android revoked permission for this tunnel. Tap to reconnect " +
                "and we'll ask for permission again.",
            "Reconnect" to FailureRemediation.Retry,
        )
        com.gutschke.wgrtc.data.PauseReason.FgsKilledByDoze -> Triple(
            "Background killed by Doze",
            "Android stopped the background service that keeps your " +
                "connection alive. Open battery settings to mark wgrtc " +
                "as unrestricted.",
            "Open app info" to FailureRemediation.OpenAppInfo,
        )
    }
    else -> Triple("", "", null)
}

/**
 * §6.2 ChromeOS routing-loop warning.  Fires once per host tunnel
 * at first Connect on ARC.  Sticky dismissal lives on the
 * persisted [Tunnel] via [Tunnel.chromeOsLoopWarned].
 *
 * Three actions:
 *   * **Open settings** — deep-links to ChromeOS Network → VPN so
 *     the user can verify no other WG client routes through this
 *     device's IP.  Treats this as "ack" — same as Continue.
 *   * **Continue** — user vouches they checked.  Proceeds.
 *   * **Cancel** — user backs out; the tunnel transitions to
 *     `Failed (permanent, RoutingLoopUserConfirmed)` so the row
 *     surfaces the reason.  Re-tapping Connect later re-shows the
 *     dialog (the sticky flag isn't set yet).
 */
@Composable
private fun ChromeOsRoutingLoopDialog(
    hostName: String,
    onOpenSettings: () -> Unit,
    onContinue: () -> Unit,
    onCancel: () -> Unit,
) {
    androidx.compose.material3.AlertDialog(
        onDismissRequest = onCancel,
        title = { Text("Possible routing loop?") },
        text = {
            Text(
                "Before \"$hostName\" comes up: if another WireGuard " +
                    "client on this Chromebook has this device's IP " +
                    "in its AllowedIPs, traffic will loop back here " +
                    "and your network will break.\n\n" +
                    "Open ChromeOS Settings → Network → VPN and check.",
            )
        },
        confirmButton = {
            Button(onClick = onOpenSettings) { Text("Open settings") }
        },
        dismissButton = {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = onCancel) { Text("Cancel") }
                OutlinedButton(onClick = onContinue) { Text("I've checked") }
            }
        },
    )
}

/**
 * §2.3 cascade-eligibility banner.  Renders under a host tunnel
 * row whose `relayPolicy == Ask` while at least one joiner tunnel
 * is connected.  Two buttons:
 *
 *  - **Allow** writes `relayPolicy = Always`; cascade auto-installs
 *    for this host and any current/future Connected joiner.
 *  - **Block** writes `relayPolicy = Never`; cascade routes for
 *    this host stay torn down even when a cascade-eligible joiner
 *    is up.
 *
 *  Fail-safe: ignoring the banner equals Block until the user
 *  decides — `relayPolicy=Ask` blocks cascade in
 *  [HostModeBackend.start].  The banner sticks around until the
 *  user picks; it dismisses itself only after a policy is set.
 *
 *  Round-2 amendment A4 resolution: decision is per-host (not
 *  per-(host, joiner) pair); we never re-prompt for a new joiner.
 *  See `docs/ux-design-v2.md` §2.4.
 */
@Composable
private fun CascadeAskBanner(
    hostName: String,
    onAllow: () -> Unit,
    onBlock: () -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.secondaryContainer,
            contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
        ),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                "Allow $hostName to relay through your other tunnels?",
                style = MaterialTheme.typography.titleMedium,
            )
            Spacer(Modifier.height(6.dp))
            Text(
                "Devices on $hostName could reach networks your " +
                    "currently-connected outbound tunnels cover.  " +
                    "If you don't want them to, leave this blocked.",
                style = MaterialTheme.typography.bodySmall,
            )
            Spacer(Modifier.height(10.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                // Block on the left = LTR-prominent fail-safe default.
                OutlinedButton(onClick = onBlock) { Text("Block") }
                Button(onClick = onAllow) { Text("Allow") }
            }
        }
    }
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
