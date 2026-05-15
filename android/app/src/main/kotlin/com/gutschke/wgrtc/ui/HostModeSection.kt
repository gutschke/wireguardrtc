package com.gutschke.wgrtc.ui

import android.graphics.Bitmap
import android.graphics.Color
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.outlined.Edit
import androidx.compose.material.icons.outlined.PersonAdd
import androidx.compose.material.icons.outlined.PersonRemove
import androidx.compose.material.icons.outlined.QrCode
import androidx.compose.material.icons.outlined.VpnKey
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.google.zxing.BarcodeFormat
import com.google.zxing.MultiFormatWriter
import com.google.zxing.WriterException
import com.gutschke.wgrtc.WgrtcApp
import com.gutschke.wgrtc.WgrtcViewModel
import com.gutschke.wgrtc.data.Tunnel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Host-mode panel on the tunnel-detail screen. Renders only when
 * [tunnel] has `source = HOST_MODE`. Surfaces:
 *
 * - a small "Hosting" header with subnet + enrolled-peer count.
 * - the list of currently-enrolled peers.
 * - a single primary CTA: **Invite a peer**. Tapping opens a
 * bottom sheet with the three invitation methods (QR, wormhole
 * code, manual config) — replaces the previous flat list of
 * three "Or: …" buttons that grew incrementally during
 * development.
 */
@Composable
fun HostModeSection(
    tunnel: Tunnel,
    vm: WgrtcViewModel,
    /** Whether the tunnel's wg-go is currently UP. Drives the
     * "Network not running" callout that appears for idle host
     * tunnels — peers can't actually reach the host until this
     * is true. */
    isActive: Boolean = false,
    onConnect: () -> Unit = {},
    onMintWormholeCode: () -> Unit = {},
) {
    val hm = tunnel.hostMode ?: return
    if (tunnel.source != Tunnel.Source.HOST_MODE) return

    var mintedUri by remember(tunnel.id) { mutableStateOf<String?>(null) }
    var mintedAtMs by remember(tunnel.id) { mutableStateOf(0L) }
    var ttlMs by remember(tunnel.id) { mutableStateOf(0L) }
    var manualConfigText by remember(tunnel.id) { mutableStateOf<String?>(null) }
    var inviteSheetOpen by remember(tunnel.id) { mutableStateOf(false) }

    Spacer(Modifier.height(20.dp))
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(
            "Hosting",
            style = MaterialTheme.typography.titleMedium,
        )
    }
    if (!isActive) {
        Spacer(Modifier.height(8.dp))
        NetworkNotRunningBanner(onConnect = onConnect)
    }
    Spacer(Modifier.height(4.dp))
    Text(
        "Subnet ${hm.subnet} · ${hm.enrolledPeers.size} peer" +
            if (hm.enrolledPeers.size == 1) "" else "s",
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )

    if (hm.enrolledPeers.isNotEmpty()) {
        Spacer(Modifier.height(12.dp))
        val invitations by vm.lastInvitations.collectAsState()
        val peerStats by vm.peerStats.collectAsState()
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            for (p in hm.enrolledPeers) {
                // Prefer the durable copy on the EnrolledPeer
                // so a restart doesn't lose the invitation; fall
                // back to the in-process cache for peers
                // enrolled in builds before landed.
                val cachedInvitation =
                    p.manualInvitationText ?: invitations[p.pubkeyB64]
                val stats = peerStats[p.pubkeyB64]
                PeerRow(
                    name = p.nameHint,
                    ip = p.assignedIp,
                    handshakeMs = stats?.lastHandshakeEpochMs,
                    rxBytes = stats?.rxBytes ?: 0L,
                    txBytes = stats?.txBytes ?: 0L,
                    isActive = isActive,
                    onRevoke = { vm.revokeEnrolledPeer(tunnel.id, p.pubkeyB64) },
                    onShowInvitation = cachedInvitation?.let {
                        { manualConfigText = it }
                    },
                )
            }
        }
    } else {
        Spacer(Modifier.height(12.dp))
        Text(
            "No one has joined yet. Tap below to invite a peer.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }

    Spacer(Modifier.height(16.dp))
    Button(
        onClick = { inviteSheetOpen = true },
        modifier = Modifier.fillMaxWidth(),
    ) {
        Icon(
            Icons.Outlined.PersonAdd,
            contentDescription = null,
            modifier = Modifier.padding(end = 8.dp),
        )
        Text("Invite a peer")
    }

    if (inviteSheetOpen) {
        InvitePeerSheet(
            onDismiss = { inviteSheetOpen = false },
            onMintQr = {
                inviteSheetOpen = false
                val uri = vm.mintHostEnrollToken(
                    tunnelId = tunnel.id,
                    nameHint = "guest-${hm.enrolledPeers.size + 1}",
                    ttlMs = DEFAULT_TOKEN_TTL_MS,
                )
                if (uri != null) {
                    mintedUri = uri
                    mintedAtMs = System.currentTimeMillis()
                    ttlMs = DEFAULT_TOKEN_TTL_MS
                }
            },
            onMintWormhole = {
                inviteSheetOpen = false
                onMintWormholeCode()
            },
            onManualConfig = {
                inviteSheetOpen = false
                val addrLine = com.gutschke.wgrtc.data
                    .parseInterfaceField(tunnel.configText, "Address")
                    ?.substringBefore('/')
                val nextIp = if (addrLine != null) {
                    com.gutschke.wgrtc.data.HostSubnetAllocator.nextFreeIp(
                        hm.subnet, addrLine,
                        com.gutschke.wgrtc.data.allocatedIps(tunnel))
                } else null
                // V6.3 — v6 sibling alloc; soft-fail to v4-only.
                val v6Cidr = hm.subnetV6?.let { sv6 ->
                    val v6Host = sv6.removeSuffix("/64") + "1"
                    com.gutschke.wgrtc.data.HostSubnetAllocator.nextFreeIpV6(
                        sv6, v6Host,
                        com.gutschke.wgrtc.data.allocatedIpsV6(tunnel),
                    )?.let { "$it/128" }
                }
                val snapshot = if (nextIp != null) {
                    com.gutschke.wgrtc.data.buildHostTunnelSnapshot(
                        tunnel = tunnel,
                        assignedAddressCidr = "$nextIp/32",
                        assignedAddressV6Cidr = v6Cidr,
                    )
                } else null
                if (snapshot != null) {
                    val r = com.gutschke.wgrtc.data.ManualConfigGenerator.generate(
                        snapshot = snapshot,
                        deviceLabel = "manual-${hm.enrolledPeers.size + 1}",
                    )
                    vm.addWormholeEnrolledPeer(r.joinerPeer)
                    vm.rememberInvitation(
                        r.joinerPeer.joinerPubkeyB64, r.wgQuickText)
                    manualConfigText = r.wgQuickText
                }
            },
        )
    }

    // Host's in-tunnel address — shown in the manual-config dialog
    // so the joiner knows what to ping after the tunnel comes up.
    val hostInTunnelAddr = remember(tunnel.configText) {
        com.gutschke.wgrtc.data.parseInterfaceField(tunnel.configText, "Address")
    }

    mintedUri?.let { uri ->
        EnrollmentTokenDialog(
            uri = uri,
            mintedAtMs = mintedAtMs,
            ttlMs = ttlMs,
            onDismiss = { mintedUri = null },
        )
    }
    manualConfigText?.let { txt ->
        ManualConfigDialog(
            wgQuickText = txt,
            hostInTunnelAddress = hostInTunnelAddr,
            onDismiss = { manualConfigText = null },
        )
    }
}

/** One-line summary of a peer's WG state. Drives the secondary
 * text under each peer name in the host detail. Honest about
 * the diagnostic implications: "Never connected" with the tunnel
 * up means handshake never completed (endpoint mismatch / firewall
 * / pubkey drift), versus "Tunnel offline" with the tunnel down
 * means the joiner literally can't reach us regardless of config. */
private fun peerStatusLine(
    isActive: Boolean,
    handshakeMs: Long?,
    rxBytes: Long,
    txBytes: Long,
    nowMs: Long,
): String {
    if (!isActive) return "Network not running"
    if (handshakeMs == null) return "Never connected · check endpoint / firewall"
    val ago = com.gutschke.wgrtc.data.formatHandshakeAgo(handshakeMs, nowMs)
    val bytes = if (rxBytes == 0L && txBytes == 0L) "no data yet"
        else "↓ ${com.gutschke.wgrtc.data.formatBytes(rxBytes)} · " +
             "↑ ${com.gutschke.wgrtc.data.formatBytes(txBytes)}"
    return "Last handshake $ago · $bytes"
}

/**
 * Yellow-ish callout that appears when a host-mode tunnel is idle.
 *
 * UX motivation: in real-device testing users were creating a host
 * tunnel + handing out invitations + then noticing nothing worked,
 * because "Hosting" and "tunnel UP" are two separate states. Most
 * people expect them to be the same thing. We can't auto-Connect
 * (Android requires a VpnService consent dialog every time the
 * VPN service starts the first time), so the next-best thing is a
 * persistent banner that explains the situation and offers a
 * one-tap fix.
 */
@Composable
private fun NetworkNotRunningBanner(onConnect: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = com.gutschke.wgrtc.ui.theme.StatusConnectingContainerLight,
            contentColor = com.gutschke.wgrtc.ui.theme.StatusConnectingLight,
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Text(
                "Network not running",
                style = MaterialTheme.typography.titleSmall,
            )
            Spacer(Modifier.height(2.dp))
            Text(
                "Peers can't connect until this device's WireGuard " +
                    "endpoint is up. Inviting + accepting peers " +
                    "configures the network — tap Connect to actually " +
                    "start it.",
                style = MaterialTheme.typography.bodySmall,
            )
            Spacer(Modifier.height(10.dp))
            Button(
                onClick = onConnect,
                colors = androidx.compose.material3.ButtonDefaults.buttonColors(
                    containerColor = com.gutschke.wgrtc.ui.theme.StatusConnectingLight,
                    contentColor = com.gutschke.wgrtc.ui.theme.StatusConnectingContainerLight,
                ),
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Start network") }
        }
    }
}

@Composable
private fun PeerRow(
    name: String,
    ip: String,
    handshakeMs: Long? = null,
    rxBytes: Long = 0L,
    txBytes: Long = 0L,
    isActive: Boolean = false,
    onRevoke: () -> Unit,
    /** Set when there's an in-process cached invitation for this peer
     * — surfaced as a "Show invitation" overflow item. Null when the
     * cache has nothing (e.g. peer was enrolled before this app
     * process started, or via the QR token path which never produces
     * a wg-quick block to remember). */
    onShowInvitation: (() -> Unit)? = null,
) {
    var menuOpen by remember(name, ip) { mutableStateOf(false) }
    var confirmRevoke by remember(name, ip) { mutableStateOf(false) }

    // Health dot color — green when this peer has handshook recently,
    // amber when the tunnel is up but this specific peer hasn't, grey
    // when the tunnel itself is down. Threshold: WG re-keys every
    // 2 minutes, so a handshake older than 180 s probably means the
    // peer is offline; under that we count as "live".
    val healthy = isActive && handshakeMs != null &&
        (System.currentTimeMillis() - handshakeMs) < 180_000L
    val dotColor = when {
        !isActive -> MaterialTheme.colorScheme.outline
        healthy -> com.gutschke.wgrtc.ui.theme.StatusUpLight
        else -> com.gutschke.wgrtc.ui.theme.StatusConnectingLight
    }

    Column {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(8.dp)
                    .clip(RoundedCornerShape(4.dp))
                    .background(dotColor),
            )
            Text(name, style = MaterialTheme.typography.bodyMedium)
            Spacer(Modifier.weight(1f))
            Text(
                ip,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Box {
                androidx.compose.material3.IconButton(
                    onClick = { menuOpen = true },
                    modifier = Modifier.size(36.dp),
                ) {
                    androidx.compose.material3.Icon(
                        Icons.Filled.MoreVert,
                        contentDescription = "Peer actions",
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                androidx.compose.material3.DropdownMenu(
                    expanded = menuOpen,
                    onDismissRequest = { menuOpen = false },
                ) {
                    if (onShowInvitation != null) {
                        androidx.compose.material3.DropdownMenuItem(
                            text = { Text("Show invitation") },
                            leadingIcon = {
                                androidx.compose.material3.Icon(
                                    Icons.Outlined.QrCode, contentDescription = null,
                                )
                            },
                            onClick = {
                                menuOpen = false
                                onShowInvitation()
                            },
                        )
                    }
                    androidx.compose.material3.DropdownMenuItem(
                        text = { Text("Revoke") },
                        leadingIcon = {
                            androidx.compose.material3.Icon(
                                Icons.Outlined.PersonRemove, contentDescription = null,
                            )
                        },
                        onClick = {
                            menuOpen = false
                            confirmRevoke = true
                        },
                    )
                }
            }
        }
        // Status sub-line — handshake age + byte counters. Hides
        // the bytes when both directions are 0 (typical for a peer
        // that's enrolled but never connected) so the row stays
        // compact in the common case.
        val nowMs by com.gutschke.wgrtc.ui.components.rememberCurrentTimeMs()
        val statusText = peerStatusLine(isActive, handshakeMs, rxBytes, txBytes, nowMs)
        Text(
            statusText,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(start = 18.dp, top = 1.dp),
        )
    }

    if (confirmRevoke) {
        AlertDialog(
            onDismissRequest = { confirmRevoke = false },
            title = { Text("Revoke this peer?") },
            text = {
                Text(
                    "\"$name\" ($ip) will no longer be able to connect to " +
                        "this network. Other peers stay connected; they'll " +
                        "see a brief reconnect (about a quarter-second) " +
                        "while wg-go applies the change.",
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        confirmRevoke = false
                        onRevoke()
                    },
                    colors = androidx.compose.material3.ButtonDefaults.textButtonColors(
                        contentColor = MaterialTheme.colorScheme.error,
                    ),
                ) { Text("Revoke") }
            },
            dismissButton = {
                TextButton(onClick = { confirmRevoke = false }) { Text("Cancel") }
            },
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun InvitePeerSheet(
    onDismiss: () -> Unit,
    onMintQr: () -> Unit,
    onMintWormhole: () -> Unit,
    onManualConfig: () -> Unit,
) {
    val sheetState = rememberModalBottomSheetState()
    val scope = rememberCoroutineScope()

    fun close(then: () -> Unit) {
        scope.launch {
            sheetState.hide()
            onDismiss()
            then()
        }
    }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
    ) {
        Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
            Text(
                "Invite a peer",
                style = MaterialTheme.typography.titleLarge,
                modifier = Modifier.padding(bottom = 4.dp),
            )
            Text(
                "Pick the method that matches the device they're on.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(16.dp))
            InviteMethodRow(
                icon = Icons.Outlined.QrCode,
                title = "Generate a QR code",
                body = "Best when the joining device runs wgrtc. " +
                    "Single-use, expires after 10 minutes.",
                onClick = { close { onMintQr() } },
            )
            InviteMethodRow(
                icon = Icons.Outlined.VpnKey,
                title = "Mint a wormhole code",
                body = "Six-letter shared secret. Both screens show " +
                    "the same confirmation phrase before connecting.",
                onClick = { close { onMintWormhole() } },
            )
            InviteMethodRow(
                icon = Icons.Outlined.Edit,
                title = "Generate a config block",
                body = "For devices that can't run wgrtc — " +
                    "ChromeOS, generic WireGuard apps, routers.",
                onClick = { close { onManualConfig() } },
            )
            Spacer(Modifier.height(16.dp))
        }
    }
}

@Composable
private fun InviteMethodRow(
    icon: ImageVector,
    title: String,
    body: String,
    onClick: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Box(
            modifier = Modifier
                .size(40.dp)
                .clip(RoundedCornerShape(10.dp))
                .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.10f)),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                icon,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
            )
        }
        Column(modifier = Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.titleSmall)
            Text(
                body,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

/**
 * Modal dialog that displays a freshly-minted wgrtc-enroll URI as
 * both human-readable text and a QR code, plus a remaining-time
 * countdown. Dismissing closes the dialog (the token stays valid
 * server-side until it's consumed or expires).
 */
@Composable
private fun EnrollmentTokenDialog(
    uri: String,
    mintedAtMs: Long,
    ttlMs: Long,
    onDismiss: () -> Unit,
) {
    var nowMs by remember { mutableStateOf(System.currentTimeMillis()) }
    LaunchedEffect(uri) {
        while (true) {
            nowMs = System.currentTimeMillis()
            delay(1000)
        }
    }
    val remainingS = (((mintedAtMs + ttlMs) - nowMs) / 1000).coerceAtLeast(0)

    val qr = remember(uri) { encodeQrToBitmap(uri, 480) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Invitation QR") },
        text = {
            Column {
                Text(
                    "Have your guest scan this with the wgrtc app, " +
                        "or paste the URI below into a browser address " +
                        "bar. Single-use; expires in $remainingS s.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Spacer(Modifier.height(12.dp))
                if (qr != null) {
                    Image(
                        bitmap = qr.asImageBitmap(),
                        contentDescription = "Invitation QR",
                        modifier = Modifier
                            .fillMaxWidth()
                            .size(240.dp)
                            .clip(RoundedCornerShape(8.dp)),
                    )
                } else {
                    Text(
                        "(QR rendering failed — fall back to URI text)",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
                Spacer(Modifier.height(8.dp))
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.surfaceVariant,
                    ),
                ) {
                    Text(
                        uri,
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        modifier = Modifier.padding(8.dp),
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text("Close") }
        },
    )
}

/**
 * Encode [content] as a square QR code [pixels] on a side, returning
 * an Android [Bitmap]. Returns null on encoding error so the caller
 * can fall back to plain-text URI display.
 */
private fun encodeQrToBitmap(content: String, pixels: Int): Bitmap? {
    return try {
        val matrix = MultiFormatWriter().encode(
            content, BarcodeFormat.QR_CODE, pixels, pixels)
        val w = matrix.width
        val h = matrix.height
        val pixelArray = IntArray(w * h)
        for (y in 0 until h) {
            val row = y * w
            for (x in 0 until w) {
                pixelArray[row + x] = if (matrix.get(x, y)) Color.BLACK else Color.WHITE
            }
        }
        Bitmap.createBitmap(pixelArray, w, h, Bitmap.Config.ARGB_8888)
    } catch (_: WriterException) {
        null
    } catch (_: Exception) {
        null
    }
}

private const val DEFAULT_TOKEN_TTL_MS: Long = 600_000L
