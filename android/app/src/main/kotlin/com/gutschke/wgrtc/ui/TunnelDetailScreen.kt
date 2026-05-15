package com.gutschke.wgrtc.ui

import androidx.compose.animation.animateColorAsState
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.NetworkCheck
import androidx.compose.material.icons.outlined.Bolt
import androidx.compose.material.icons.outlined.Cable
import androidx.compose.material.icons.outlined.PauseCircle
import androidx.compose.material.icons.outlined.Public
import androidx.compose.material.icons.outlined.Sync
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.gutschke.wgrtc.WgrtcViewModel
import com.gutschke.wgrtc.data.Tunnel
import com.gutschke.wgrtc.data.formatBytes
import com.gutschke.wgrtc.data.formatHandshakeAgo
import com.gutschke.wgrtc.data.formatRate
import com.gutschke.wgrtc.data.parseEndpoint
import com.gutschke.wgrtc.data.rememberReverseDns
import com.gutschke.wgrtc.ui.components.rememberCurrentTimeMs
import com.gutschke.wgrtc.ui.theme.StatusConnectingContainerLight
import com.gutschke.wgrtc.ui.theme.StatusConnectingLight
import com.gutschke.wgrtc.ui.theme.StatusUpContainerLight
import com.gutschke.wgrtc.ui.theme.StatusUpLight

/**
 * Tunnel detail screen — completely reorganised in . Layout
 * pattern:
 *
 * 1. **Status hero card** — color-keyed to the current state
 * (Connected = teal-green, Connecting = amber, Idle =
 * neutral). Shows the headline status, a one-line summary of
 * the connection (last handshake age / endpoint hint), and
 * the primary Connect/Disconnect button as part of the same
 * card so the user's eye lands on the action together with
 * the state.
 * 2. **Connection card** — address pool, endpoint(s), advanced
 * live-vs-fallback distinction for ENROLL tunnels.
 * 3. **Activity card** — RX/TX bytes + rate.
 * 4. **Hosting card** — peers + invite-a-peer (host-mode only).
 * 5. **Advanced disclosure** — raw wg-quick text + delete.
 *
 * This replaces the previous one-long-scroll layout that mixed
 * status, throughput, peer list, and config text without visual
 * hierarchy.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TunnelDetailScreen(
    tunnelId: String,
    onBack: () -> Unit,
    onMintWormholeCode: () -> Unit = {},
    onEdit: () -> Unit = {},
    onDiagnose: () -> Unit = {},
    vm: WgrtcViewModel = viewModel(),
) {
    val tunnels by vm.tunnels.collectAsState()
    val isUp by vm.isActive(tunnelId).collectAsState()
    val connectingId by vm.connectingTunnelId.collectAsState()
    // TunnelDetailScreen used to read vm.liveState (a
    // legacy single-tunnel global) to derive its ConnectionState.
    // With N concurrent tunnels that's wrong — tunnel A's UP
    // would paint tunnel B's screen as Connected.  isActive(id)
    // is per-tunnel; connectingTunnelId is already per-tunnel.
    // Together they cover the full state ladder without touching
    // the global signal.
    val liveEndpoints by vm.liveEndpoints.collectAsState()
    val throughput by vm.throughputFor(tunnelId).collectAsState()
    val tunnel = tunnels.firstOrNull { it.id == tunnelId }
    val connect = LocalConnect.current
    val disconnect = LocalDisconnect.current
    var confirmDelete by remember { mutableStateOf(false) }
    var showAdvanced by remember(tunnelId) { mutableStateOf(false) }

    if (tunnel == null) {
        Scaffold { pad ->
            Box(modifier = Modifier.fillMaxSize().padding(pad), contentAlignment = Alignment.Center) {
                Text("This tunnel was deleted.", style = MaterialTheme.typography.bodyLarge)
            }
        }
        return
    }

    val isConnecting = connectingId == tunnel.id
    val state = when {
        isConnecting -> ConnectionState.Connecting
        isUp -> ConnectionState.Up
        else -> ConnectionState.Idle
    }

    val addressLine = tunnel.configText.lineSequence()
        .firstOrNull { it.trim().startsWith("Address", ignoreCase = true) }
        ?.substringAfter("=")?.trim()
    val endpointLine = tunnel.configText.lineSequence()
        .firstOrNull { it.trim().startsWith("Endpoint", ignoreCase = true) }
        ?.substringAfter("=")?.trim()
    val allowedLine = tunnel.configText.lineSequence()
        .firstOrNull { it.trim().startsWith("AllowedIPs", ignoreCase = true) }
        ?.substringAfter("=")?.trim()
    val liveEp = liveEndpoints[tunnel.id]
    val liveEpStr = liveEp?.let { "${it.ip}:${it.port}" }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(tunnel.name, style = MaterialTheme.typography.titleLarge) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back")
                    }
                },
                actions = {
                    IconButton(onClick = onDiagnose) {
                        Icon(Icons.Filled.NetworkCheck, "Diagnose")
                    }
                    IconButton(onClick = onEdit) {
                        Icon(Icons.Filled.Edit, "Edit")
                    }
                    IconButton(onClick = { confirmDelete = true }) {
                        Icon(Icons.Filled.Delete, "Delete")
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
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            StatusHeroCard(
                state = state,
                tunnel = tunnel,
                handshakeMs = throughput?.lastHandshakeEpochMs,
                onConnect = { connect(tunnel.id) },
                onDisconnect = { disconnect(tunnel.id) },
            )

            ConnectionCard(
                addressLine = addressLine,
                endpointLine = endpointLine,
                allowedLine = allowedLine,
                liveEpStr = liveEpStr,
                isUp = isUp,
                source = tunnel.source,
                isHost = tunnel.source == Tunnel.Source.HOST_MODE,
            )

            ActivityCard(
                rxBytes = throughput?.rxBytes ?: 0L,
                txBytes = throughput?.txBytes ?: 0L,
                rxRate = throughput?.rxBytesPerSec ?: 0.0,
                txRate = throughput?.txBytesPerSec ?: 0.0,
                handshakeMs = throughput?.lastHandshakeEpochMs,
            )

            HostModeSection(
                tunnel = tunnel,
                vm = vm,
                isActive = isUp,
                onConnect = { connect(tunnel.id) },
                onMintWormholeCode = onMintWormholeCode,
            )

            AdvancedDisclosure(
                expanded = showAdvanced,
                onToggle = { showAdvanced = !showAdvanced },
                tunnel = tunnel,
                onDelete = { confirmDelete = true },
            )
            Spacer(Modifier.height(8.dp))
        }
    }

    if (confirmDelete) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text("Delete this tunnel?") },
            text = {
                Text(
                    "\"${tunnel.name}\" will be removed from this device. " +
                        "If it's currently connected, it disconnects first."
                )
            },
            confirmButton = {
                TextButton(
                    onClick = { confirmDelete = false; vm.deleteTunnel(tunnel.id); onBack() },
                    colors = ButtonDefaults.textButtonColors(
                        contentColor = MaterialTheme.colorScheme.error
                    ),
                ) { Text("Delete") }
            },
            dismissButton = {
                TextButton(onClick = { confirmDelete = false }) { Text("Cancel") }
            },
        )
    }
}

private enum class ConnectionState { Up, Connecting, Idle }

// ─── Status hero ─────────────────────────────────────────────────

@Composable
private fun StatusHeroCard(
    state: ConnectionState,
    tunnel: Tunnel,
    handshakeMs: Long?,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
) {
    // 1-Hz wall-clock ticker so the "Last handshake Ns ago" line in the
    // summary actually counts up between WG handshakes (which happen
    // every ~2 minutes on a healthy tunnel — the byte-counter-driven
    // recomposition can't be relied on to tick the age in between).
    val nowMs by rememberCurrentTimeMs()
    val (icon, label, fg, bg) = when (state) {
        ConnectionState.Up -> Quad(
            Icons.Outlined.Bolt, "Connected",
            StatusUpLight, StatusUpContainerLight,
        )
        ConnectionState.Connecting -> Quad(
            Icons.Outlined.Sync, "Connecting…",
            StatusConnectingLight, StatusConnectingContainerLight,
        )
        ConnectionState.Idle -> Quad(
            Icons.Outlined.PauseCircle, "Idle",
            MaterialTheme.colorScheme.onSurfaceVariant,
            MaterialTheme.colorScheme.surfaceVariant,
        )
    }
    val animatedBg by animateColorAsState(targetValue = bg as Color, label = "bg")

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = animatedBg),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
    ) {
        Column(modifier = Modifier.padding(20.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (state == ConnectionState.Connecting) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(24.dp),
                        strokeWidth = 3.dp,
                        color = fg as Color,
                    )
                } else {
                    Icon(
                        icon as ImageVector,
                        contentDescription = null,
                        tint = fg as Color,
                        modifier = Modifier.size(24.dp),
                    )
                }
                Spacer(Modifier.width(10.dp))
                Text(
                    label as String,
                    style = MaterialTheme.typography.titleMedium,
                    color = fg,
                )
            }
            Spacer(Modifier.height(6.dp))
            Text(
                summaryLine(state, tunnel, handshakeMs, nowMs),
                style = MaterialTheme.typography.bodyMedium,
                color = (fg as Color).copy(alpha = 0.85f),
            )
            Spacer(Modifier.height(16.dp))
            // All three states use a filled Button so the action is
            // clearly tappable. We pull the button colors from the
            // hero's status palette so the button reads as an
            // intentional inverse of the card (dark fill, light
            // label) rather than a translucent overlay that fights
            // for contrast with the tinted background.
            when (state) {
                ConnectionState.Up -> Button(
                    onClick = onDisconnect,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = StatusUpLight,
                        contentColor = StatusUpContainerLight,
                    ),
                ) { Text("Disconnect") }
                ConnectionState.Connecting -> Button(
                    onClick = {},
                    modifier = Modifier.fillMaxWidth(),
                    enabled = false,
                    colors = ButtonDefaults.buttonColors(
                        disabledContainerColor = StatusConnectingLight,
                        disabledContentColor = StatusConnectingContainerLight,
                    ),
                ) { Text("Connecting…") }
                ConnectionState.Idle -> Button(
                    onClick = onConnect,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Connect") }
            }
        }
    }
}

private fun summaryLine(
    state: ConnectionState, tunnel: Tunnel, handshakeMs: Long?, nowMs: Long,
): String =
    when (state) {
        ConnectionState.Up -> {
            val ago = handshakeMs?.let { formatHandshakeAgo(it, nowMs) } ?: "no handshake yet"
            "Last handshake $ago"
        }
        ConnectionState.Connecting ->
            "Reaching the host — first contact takes a few seconds"
        ConnectionState.Idle -> {
            val source = when (tunnel.source) {
                Tunnel.Source.HOST_MODE -> "you're hosting this network"
                Tunnel.Source.ENROLL -> "joined via QR or wormhole"
                Tunnel.Source.LEGACY -> "imported from a config"
                Tunnel.Source.MANUAL -> "configured by hand"
            }
            "Tap Connect to bring this up — $source"
        }
    }

// ─── Connection card ────────────────────────────────────────────

@Composable
private fun ConnectionCard(
    addressLine: String?,
    endpointLine: String?,
    allowedLine: String?,
    liveEpStr: String?,
    isUp: Boolean,
    source: Tunnel.Source,
    isHost: Boolean = false,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface,
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            SectionHeader(Icons.Outlined.Cable, "Connection")
            Spacer(Modifier.height(12.dp))
            addressLine?.let {
                // For host-mode tunnels, the [Interface] Address is
                // the in-tunnel IP joiners use to reach this device
                // — flag it explicitly so the user knows what to
                // ping after a join completes.
                if (isHost) {
                    DetailRow(
                        "Reach this device at",
                        it,
                        mono = true,
                        emphasised = true,
                    )
                    Text(
                        "Joiners can ping this address once their " +
                            "WireGuard handshake completes.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(top = 4.dp, bottom = 8.dp),
                    )
                } else {
                    DetailRow("Your address", it, mono = true)
                }
            }
            endpointLine?.let { ep ->
                val isLive = isUp && liveEpStr != null && liveEpStr != ep
                if (isLive && liveEpStr != null) {
                    DetailRow(
                        "Active path",
                        liveEpStr,
                        mono = true,
                        emphasised = true,
                    )
                }
                val parsed = parseEndpoint(ep)
                val rdns by rememberReverseDns(parsed?.first)
                val display = if (rdns != null && parsed != null)
                    "$rdns (${parsed.first}:${parsed.second})"
                else ep
                DetailRow(
                    if (isLive) "Persisted endpoint" else "Endpoint",
                    display,
                    mono = !isLive || (rdns == null),
                )
                if (source == Tunnel.Source.ENROLL) {
                    Text(
                        if (isLive)
                            "The host is roaming — the active path is " +
                                "the lower-latency one currently in use; " +
                                "the persisted endpoint is the long-term " +
                                "fallback."
                        else
                            "Auto-detected when you joined — may change " +
                                "as the host's IP roams.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(top = 6.dp),
                    )
                }
            }
            allowedLine?.let {
                DetailRow("Allowed IPs", it, mono = true)
            }
        }
    }
}

// ─── Activity card ──────────────────────────────────────────────

@Composable
private fun ActivityCard(
    rxBytes: Long,
    txBytes: Long,
    rxRate: Double,
    txRate: Double,
    handshakeMs: Long?,
) {
    val nowMs by rememberCurrentTimeMs()
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface,
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            SectionHeader(Icons.Outlined.Public, "Activity")
            Spacer(Modifier.height(12.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                ActivityCell("Received", formatBytes(rxBytes), formatRate(rxRate))
                ActivityCell("Sent", formatBytes(txBytes), formatRate(txRate))
            }
            Spacer(Modifier.height(12.dp))
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            Spacer(Modifier.height(12.dp))
            Text(
                "Last handshake ${formatHandshakeAgo(handshakeMs, nowMs)}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun ActivityCell(label: String, big: String, small: String) {
    Column {
        Text(label, style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(2.dp))
        Text(big, style = MaterialTheme.typography.titleMedium)
        Text(small, style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

// ─── Advanced disclosure ────────────────────────────────────────

@Composable
private fun AdvancedDisclosure(
    expanded: Boolean,
    onToggle: () -> Unit,
    tunnel: Tunnel,
    onDelete: () -> Unit,
) {
    TextButton(onClick = onToggle, modifier = Modifier.fillMaxWidth()) {
        Text(if (expanded) "Hide advanced" else "Show advanced")
    }
    if (expanded) {
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceVariant,
            ),
            elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    "Source: ${tunnel.source.name.lowercase()}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    "Raw configuration",
                    style = MaterialTheme.typography.titleSmall,
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    tunnel.configText,
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                )
                Spacer(Modifier.height(16.dp))
                OutlinedButton(
                    onClick = onDelete,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.outlinedButtonColors(
                        contentColor = MaterialTheme.colorScheme.error,
                    ),
                ) {
                    Icon(Icons.Filled.Delete, contentDescription = null,
                        modifier = Modifier.padding(end = 8.dp))
                    Text("Delete this tunnel")
                }
            }
        }
    }
}

// ─── Tiny helpers ───────────────────────────────────────────────

@Composable
private fun SectionHeader(icon: ImageVector, label: String) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(
            modifier = Modifier
                .size(28.dp)
                .clip(RoundedCornerShape(8.dp))
                .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.10f)),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                icon,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(16.dp),
            )
        }
        Spacer(Modifier.width(8.dp))
        Text(label, style = MaterialTheme.typography.titleSmall)
    }
}

@Composable
private fun DetailRow(
    label: String,
    value: String,
    mono: Boolean = false,
    emphasised: Boolean = false,
) {
    Column(modifier = Modifier.padding(vertical = 4.dp)) {
        Text(
            label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            value,
            style = MaterialTheme.typography.bodyMedium,
            fontFamily = if (mono) FontFamily.Monospace else null,
            color = if (emphasised) MaterialTheme.colorScheme.primary
                    else MaterialTheme.colorScheme.onSurface,
        )
    }
}

/** Tiny generic 4-tuple — Kotlin's standard library ships only Pair
 * and Triple. Used by [StatusHeroCard] to bundle (icon, label, fg,
 * bg) without three separate `when` statements. */
private data class Quad<A, B, C, D>(val a: A, val b: B, val c: C, val d: D)

private operator fun <A, B, C, D> Quad<A, B, C, D>.component1() = a
private operator fun <A, B, C, D> Quad<A, B, C, D>.component2() = b
private operator fun <A, B, C, D> Quad<A, B, C, D>.component3() = c
private operator fun <A, B, C, D> Quad<A, B, C, D>.component4() = d
