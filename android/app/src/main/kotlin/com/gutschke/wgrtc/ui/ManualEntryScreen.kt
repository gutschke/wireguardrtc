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
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.gutschke.wgrtc.WgrtcViewModel
import com.gutschke.wgrtc.data.Tunnel
import com.gutschke.wgrtc.signalling.EnrollUri
import com.gutschke.wgrtc.ui.components.HelpHint
import kotlinx.coroutines.launch

/**
 * Manual entry screen — escape hatch for users whose host gave them
 * the individual fields rather than a QR or paste-able config. Two
 * modes: a wgrtc-enroll URI re-assembled from its parts, and a raw
 * single-peer wg-quick block. Tooltips on every technical field
 * cushion the experience for users who don't speak WireGuard.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ManualEntryScreen(
    onBack: () -> Unit,
    onAdded: () -> Unit,
    vm: WgrtcViewModel = viewModel(),
) {
    var mode by rememberSaveable { mutableStateOf(EntryMode.WGRTC) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Enter the details") },
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
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Text(
                "Pick the format you were given.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(
                    selected = mode == EntryMode.WGRTC,
                    onClick = { mode = EntryMode.WGRTC },
                    label = { Text("Invitation fields") },
                )
                FilterChip(
                    selected = mode == EntryMode.LEGACY,
                    onClick = { mode = EntryMode.LEGACY },
                    label = { Text("Raw WireGuard config") },
                )
            }
            Spacer(Modifier.height(4.dp))
            when (mode) {
                EntryMode.WGRTC -> WgrtcForm(vm, onAdded)
                EntryMode.LEGACY -> LegacyForm(vm, onAdded)
            }
        }
    }
}

private enum class EntryMode { WGRTC, LEGACY }

@Composable
private fun WgrtcForm(vm: WgrtcViewModel, onAdded: () -> Unit) {
    var name by remember { mutableStateOf("") }
    var serverPub by remember { mutableStateOf("") }
    var salt by remember { mutableStateOf("") }
    var brokerUrl by remember { mutableStateOf("") }
    var brokerKey by remember { mutableStateOf("peerjs") }
    var token by remember { mutableStateOf("") }
    var deviceLabel by remember {
        mutableStateOf(android.os.Build.MODEL ?: "android device")
    }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    Text(
        "Reassembles the invitation URI from individual fields. " +
            "If you have one already, prefer scanning or pasting it.",
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    Field(name, { name = it }, "Tunnel name", placeholder = vm.defaultName(),
        help = "How this appears in your tunnel list. Optional.")
    Field(serverPub, { serverPub = it }, "Host's public key",
        help = "A 44-character base64 string the host gave you. This " +
            "uniquely identifies their tunnel and lets WireGuard " +
            "encrypt to them.",
        mono = true)
    Field(salt, { salt = it }, "Salt",
        help = "A short base64 string the host gave you. Used to " +
            "look up the host on the signaling server.",
        mono = true)
    Field(brokerUrl, { brokerUrl = it }, "Signaling server",
        help = "Where this app first contacts the host — usually a " +
            "wss:// URL.")
    Field(brokerKey, { brokerKey = it }, "Signaling key",
        help = "API key the signaling server requires. PeerJS-" +
            "compatible servers use \"peerjs\".")
    Field(token, { token = it }, "Invitation token",
        help = "Single-use token from the host's invitation URI. " +
            "Expires after a few minutes.",
        mono = true)
    Field(deviceLabel, { deviceLabel = it }, "Device label",
        help = "A short name the host sees in their peer list — " +
            "usually your phone model.")

    error?.let {
        Text(it, color = MaterialTheme.colorScheme.error,
            style = MaterialTheme.typography.bodySmall)
    }
    Spacer(Modifier.height(8.dp))
    Button(
        onClick = {
            error = null
            val raw = mapOf(
                "pk" to serverPub.trim(),
                "salt" to salt.trim(),
                "broker" to brokerUrl.trim(),
                "brokerkey" to brokerKey.trim(),
                "token" to token.trim(),
            )
            val missing = raw.filterValues { it.isEmpty() }.keys
            if (missing.isNotEmpty()) {
                error = "Missing: ${missing.joinToString(", ")}"
                return@Button
            }
            busy = true
            scope.launch {
                try {
                    val uriStr = "wgrtc-enroll://v1?" + raw.entries
                        .joinToString("&") { (k, v) ->
                            "${k}=${android.net.Uri.encode(v, "-_.~")}"
                        }
                    val uri = EnrollUri.parse(uriStr)
                    vm.enrollAndAdd(uri, deviceLabel,
                        name.takeIf { it.isNotBlank() })
                    onAdded()
                } catch (t: Throwable) {
                    error = t.message ?: t.javaClass.simpleName
                } finally { busy = false }
            }
        },
        enabled = !busy,
        modifier = Modifier.fillMaxWidth(),
    ) { Text(if (busy) "Joining…" else "Join tunnel") }
}

@Composable
private fun LegacyForm(vm: WgrtcViewModel, onAdded: () -> Unit) {
    var name by remember { mutableStateOf("") }
    var privateKey by remember { mutableStateOf("") }
    var address by remember { mutableStateOf("") }
    var dns by remember { mutableStateOf("") }
    var mtu by remember { mutableStateOf("") }
    var peerPubKey by remember { mutableStateOf("") }
    var endpoint by remember { mutableStateOf("") }
    // Canonical (no whitespace) — see WgAllowedIps. Keeps the
    // user's input clean from the start so they never see the
    // ChromeOS-incompatible variant in our own UI.
    var allowedIps by remember {
        mutableStateOf(com.gutschke.wgrtc.data.WgAllowedIps.FULL_TUNNEL)
    }
    var keepalive by remember { mutableStateOf("25") }
    var error by remember { mutableStateOf<String?>(null) }

    Text(
        "Build a tunnel from the WireGuard fields directly.",
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    Field(name, { name = it }, "Tunnel name", placeholder = vm.defaultName(),
        help = "Your local label for this tunnel. Optional.")
    Spacer(Modifier.height(8.dp))
    Text("This device", style = MaterialTheme.typography.titleSmall)
    Field(privateKey, { privateKey = it }, "Private key",
        help = "A 44-character base64 string that proves your identity " +
            "to the host. Stays on this device — never sent to the " +
            "host directly.",
        mono = true)
    Field(address, { address = it }, "Address",
        help = "Your IP within the tunnel. Notation includes the " +
            "subnet mask: e.g. 10.0.0.2/32 means just this address.",
        mono = true)
    Field(dns, { dns = it }, "DNS (optional)",
        help = "Comma-separated DNS servers used while the tunnel is " +
            "up. Leave blank to keep your phone's normal DNS.")
    Field(mtu, { mtu = it }, "MTU (optional)",
        help = "Largest packet size allowed. Leave blank for the WG " +
            "default (${com.gutschke.wgrtc.data.MtuMath.DEFAULT_WG_MTU}). " +
            "Lower it (1280, 1380) if the tunnel feels broken on " +
            "flaky networks.")
    Spacer(Modifier.height(8.dp))
    Text("Host", style = MaterialTheme.typography.titleSmall)
    Field(peerPubKey, { peerPubKey = it }, "Public key",
        help = "Host's 44-character base64 public key. WireGuard " +
            "encrypts every packet to this key.",
        mono = true)
    Field(endpoint, { endpoint = it }, "Endpoint",
        help = "Where to send WireGuard packets — `host:port`. Can " +
            "be an IP or a domain name.",
        mono = true)
    Field(allowedIps, { allowedIps = it }, "Allowed IPs",
        help = "What gets routed through the tunnel. 0.0.0.0/0 + " +
            "::/0 means everything (full-tunnel VPN). A narrower " +
            "range like 10.0.0.0/24 only routes that subnet (split " +
            "tunnel).",
        mono = true)
    Field(keepalive, { keepalive = it }, "Keepalive",
        help = "Seconds between heartbeat packets. 25 is typical — " +
            "keeps the connection alive through stateful NAT/firewall " +
            "boxes that would otherwise drop the session.")

    error?.let {
        Text(it, color = MaterialTheme.colorScheme.error,
            style = MaterialTheme.typography.bodySmall)
    }
    Spacer(Modifier.height(8.dp))
    Button(
        onClick = {
            error = null
            try {
                val cfg = buildString {
                    appendLine("[Interface]")
                    appendLine("PrivateKey = ${privateKey.trim()}")
                    appendLine("Address = ${address.trim()}")
                    if (dns.isNotBlank()) appendLine("DNS = ${dns.trim()}")
                    if (mtu.isNotBlank()) appendLine("MTU = ${mtu.trim()}")
                    appendLine()
                    appendLine("[Peer]")
                    appendLine("PublicKey = ${peerPubKey.trim()}")
                    appendLine("Endpoint = ${endpoint.trim()}")
                    appendLine("AllowedIPs = ${allowedIps.trim()}")
                    if (keepalive.isNotBlank())
                        appendLine("PersistentKeepalive = ${keepalive.trim()}")
                }
                // §11.6 Tile-#3 — bridge-aware save path.  See
                // PasteTunnelScreen for the doc; this is the
                // manual-entry sibling.
                if (vm.pendingBridgeGroupId.value != null) {
                    vm.addLegacyTunnelInBridgeFlow(name, cfg, Tunnel.Source.MANUAL)
                } else {
                    vm.addLegacyTunnel(name, cfg, Tunnel.Source.MANUAL)
                }
                onAdded()
            } catch (t: Throwable) {
                error = t.message ?: t.javaClass.simpleName
            }
        },
        modifier = Modifier.fillMaxWidth(),
    ) { Text("Save tunnel") }
}

@Composable
private fun Field(
    value: String,
    onChange: (String) -> Unit,
    label: String,
    placeholder: String? = null,
    help: String? = null,
    mono: Boolean = false,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onChange,
        label = { Text(label) },
        placeholder = placeholder?.let { { Text(it) } },
        trailingIcon = help?.let { { HelpHint(body = it) } },
        modifier = Modifier.fillMaxWidth(),
        singleLine = true,
        textStyle = if (mono) MaterialTheme.typography.bodyMedium.copy(
            fontFamily = FontFamily.Monospace,
        ) else MaterialTheme.typography.bodyMedium,
    )
}
