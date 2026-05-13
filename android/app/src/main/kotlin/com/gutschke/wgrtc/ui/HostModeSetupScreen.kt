package com.gutschke.wgrtc.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.Column
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
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.gutschke.wgrtc.WgrtcViewModel

/**
 * host-mode setup form. Collects:
 *
 * - tunnel name (defaults to a generated one if blank)
 * - host-mode subnet — clients get IPs from here
 * - the host's IP within that subnet
 * - UDP listen port
 * - PeerJS broker URL + key
 *
 * Sensible defaults so a user can usually just tap Create. The
 * generated keypair, salt, and `[Interface]` block live inside
 * [com.gutschke.wgrtc.data.HostModeFactory] — this screen doesn't
 * need to know about them.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HostModeSetupScreen(
    onBack: () -> Unit,
    onCreated: (tunnelId: String) -> Unit,
    vm: WgrtcViewModel = viewModel(),
) {
    val tunnels by vm.tunnels.collectAsState()
    val defaultName = remember(tunnels.size) { vm.defaultName() }
    val settings = remember {
        com.gutschke.wgrtc.WgrtcApp.instance.settings.snapshot()
    }
    var name by remember { mutableStateOf("") }
    var subnet by remember { mutableStateOf("10.99.0.0/24") }
    var hostIp by remember { mutableStateOf("10.99.0.1") }
    var listenPort by remember { mutableStateOf("51820") }
    // Pre-fill the signalling server from settings — most users
    // won't need to change it. Stays editable for advanced cases.
    var brokerWss by remember { mutableStateOf(settings.brokerWss) }
    var brokerKey by remember { mutableStateOf(settings.brokerKey) }
    // What joiners route through the tunnel. See enum kdoc.
    var routingMode by remember { mutableStateOf(RoutingMode.LOCAL_ONLY) }
    var customAllowedIps by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var showAdvanced by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Host a tunnel") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back")
                    }
                },
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
            Text(
                "This device will host a private network. Other " +
                    "devices join with a QR code, a wormhole code, or " +
                    "a config block you hand them.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedTextField(
                value = name,
                onValueChange = { name = it },
                singleLine = true,
                label = { Text("Name") },
                placeholder = { Text(defaultName) },
                trailingIcon = {
                    com.gutschke.wgrtc.ui.components.HelpHint(
                        title = "Tunnel name",
                        body = "How this network appears in your tunnel " +
                            "list. Anything memorable — \"Home\", " +
                            "\"Office\", \"Trip backup\".",
                    )
                },
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = subnet,
                onValueChange = { subnet = it },
                singleLine = true,
                label = { Text("Address pool") },
                trailingIcon = {
                    com.gutschke.wgrtc.ui.components.HelpHint(
                        title = "What's an address pool?",
                        body = "A range of private IP addresses the host " +
                            "hands out to joining devices. 10.99.0.0/24 " +
                            "fits up to 254 peers and rarely conflicts " +
                            "with home or office networks. The /24 part " +
                            "controls the size; /16 fits 65 thousand.",
                    )
                },
                modifier = Modifier.fillMaxWidth(),
            )

            Spacer(Modifier.height(8.dp))
            RoutingModePicker(
                selected = routingMode,
                onSelect = { routingMode = it },
            )
            if (routingMode == RoutingMode.CUSTOM) {
                OutlinedTextField(
                    value = customAllowedIps,
                    onValueChange = { customAllowedIps = it },
                    singleLine = true,
                    label = { Text("AllowedIPs to advertise") },
                    placeholder = { Text("10.0.0.0/8, 192.168.0.0/16") },
                    trailingIcon = {
                        com.gutschke.wgrtc.ui.components.HelpHint(
                            title = "Custom routes",
                            body = "Comma-separated CIDR list joiners will " +
                                "route through this tunnel. Use this when " +
                                "you want the tunnel to carry traffic for " +
                                "a specific corporate / home subnet but " +
                                "not the rest of the internet.",
                        )
                    },
                    modifier = Modifier.fillMaxWidth(),
                )
            }

            Spacer(Modifier.height(4.dp))
            androidx.compose.material3.TextButton(
                onClick = { showAdvanced = !showAdvanced },
            ) {
                Text(if (showAdvanced) "Hide advanced" else "Show advanced settings")
            }
            if (showAdvanced) {
                OutlinedTextField(
                    value = hostIp,
                    onValueChange = { hostIp = it },
                    singleLine = true,
                    label = { Text("This device's address") },
                    trailingIcon = {
                        com.gutschke.wgrtc.ui.components.HelpHint(
                            body = "The IP this device claims inside " +
                                "the address pool. Convention is the " +
                                "first usable address — `10.99.0.1` " +
                                "for `10.99.0.0/24`.",
                        )
                    },
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = listenPort,
                    onValueChange = { listenPort = it },
                    singleLine = true,
                    label = { Text("UDP port") },
                    trailingIcon = {
                        com.gutschke.wgrtc.ui.components.HelpHint(
                            title = "WireGuard handshake port",
                            body = "The UDP port WireGuard listens on. " +
                                "51820 is the convention; pick a random " +
                                "number between 49152 and 65535 if your " +
                                "network blocks the well-known one.",
                        )
                    },
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = brokerWss,
                    onValueChange = { brokerWss = it },
                    singleLine = true,
                    label = { Text("Signaling server") },
                    placeholder = { Text("wss://example.com/peerjs") },
                    trailingIcon = {
                        com.gutschke.wgrtc.ui.components.HelpHint(
                            title = "What's a signaling server?",
                            body = "Where joining devices first contact " +
                                "this host so they can exchange a one-" +
                                "time setup message. Defaults to your " +
                                "app-wide Settings choice — change " +
                                "here only for per-tunnel overrides.",
                        )
                    },
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = brokerKey,
                    onValueChange = { brokerKey = it },
                    singleLine = true,
                    label = { Text("Signaling key") },
                    trailingIcon = {
                        com.gutschke.wgrtc.ui.components.HelpHint(
                            body = "API key the signaling server " +
                                "requires. PeerJS-compatible servers " +
                                "use \"peerjs\" by default.",
                        )
                    },
                    modifier = Modifier.fillMaxWidth(),
                )
            }

            error?.let { msg ->
                Text(msg, color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodyMedium)
            }
            Spacer(Modifier.height(8.dp))
            Button(
                onClick = {
                    val port = listenPort.toIntOrNull()
                    if (port == null || port !in 1..65535) {
                        error = "Listen port must be 1..65535"
                        return@Button
                    }
                    if (brokerWss.isBlank()) {
                        error = "Broker URL is required"
                        return@Button
                    }
                    error = null
                    val advertised = when (routingMode) {
                        RoutingMode.LOCAL_ONLY -> null
                        // Canonical form — see WgAllowedIps for the
                        // ChromeOS-rejects-whitespace constraint.
                        RoutingMode.FULL_TUNNEL ->
                            com.gutschke.wgrtc.data.WgAllowedIps.FULL_TUNNEL
                        RoutingMode.CUSTOM ->
                            customAllowedIps.trim().ifBlank { null }?.let {
                                com.gutschke.wgrtc.data.WgAllowedIps.canonicalize(it)
                            }
                    }
                    try {
                        val t = vm.addHostModeTunnel(
                            name = name,
                            subnet = subnet,
                            hostIp = hostIp,
                            listenPort = port,
                            brokerWss = brokerWss,
                            brokerKey = brokerKey,
                            advertisedAllowedIps = advertised,
                        )
                        onCreated(t.id)
                    } catch (e: Throwable) {
                        error = e.message ?: e.javaClass.simpleName
                    }
                },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Create network") }
        }
    }
}

/** What joiners route through the tunnel. */
private enum class RoutingMode { LOCAL_ONLY, FULL_TUNNEL, CUSTOM }

@Composable
private fun RoutingModePicker(
    selected: RoutingMode,
    onSelect: (RoutingMode) -> Unit,
) {
    androidx.compose.foundation.layout.Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
        Text("What joiners route through the tunnel",
            style = MaterialTheme.typography.titleSmall)
        com.gutschke.wgrtc.ui.components.HelpHint(
            title = "Routing scope",
            body = "Sets the AllowedIPs joiners advertise on their " +
                "[Peer] block.\n\n" +
                " • Local-only: just the address pool. Joiners " +
                "use their own internet, but can reach this device " +
                "and other peers on the tunnel.\n\n" +
                " • Full tunnel: 0.0.0.0/0 + ::/0. Joiners send " +
                "*all* their traffic through this device. The host " +
                "relays each flow out its own network — IPv4 works " +
                "today; IPv6 egress is still in development, so " +
                "v6-preferring joiners may see slow page loads " +
                "until IPv6 lands.\n\n" +
                " • Custom: type a CIDR list. Useful for routing " +
                "specific subnets through (split-tunnel).",
        )
    }
    Spacer(Modifier.height(4.dp))
    androidx.compose.foundation.layout.Column(
        verticalArrangement = androidx.compose.foundation.layout.Arrangement.spacedBy(4.dp),
    ) {
        RoutingModeRow(
            label = "Local-only access (recommended)",
            sub = "Joiners reach this device + other peers; " +
                "internet stays on their normal network.",
            selected = selected == RoutingMode.LOCAL_ONLY,
            onSelect = { onSelect(RoutingMode.LOCAL_ONLY) },
        )
        RoutingModeRow(
            label = "Full tunnel (host forwards everything)",
            sub = "Joiners send all traffic through this device. " +
                "IPv4 works; IPv6 egress is still in development.",
            selected = selected == RoutingMode.FULL_TUNNEL,
            onSelect = { onSelect(RoutingMode.FULL_TUNNEL) },
        )
        RoutingModeRow(
            label = "Custom AllowedIPs",
            sub = "Type a comma-separated CIDR list below.",
            selected = selected == RoutingMode.CUSTOM,
            onSelect = { onSelect(RoutingMode.CUSTOM) },
        )
    }
}

@Composable
private fun RoutingModeRow(
    label: String,
    sub: String,
    selected: Boolean,
    onSelect: () -> Unit,
) {
    androidx.compose.foundation.layout.Row(
        modifier = Modifier
            .fillMaxWidth()
            .selectable(selected = selected, onClick = onSelect)
            .padding(vertical = 4.dp),
        verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
    ) {
        androidx.compose.material3.RadioButton(
            selected = selected,
            onClick = onSelect,
        )
        Spacer(Modifier.width(4.dp))
        androidx.compose.foundation.layout.Column(modifier = Modifier.weight(1f)) {
            Text(label, style = MaterialTheme.typography.bodyMedium)
            Text(
                sub,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
