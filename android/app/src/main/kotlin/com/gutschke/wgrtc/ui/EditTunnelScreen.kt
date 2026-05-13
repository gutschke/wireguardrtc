package com.gutschke.wgrtc.ui

import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.gutschke.wgrtc.WgrtcViewModel
import com.gutschke.wgrtc.data.Tunnel
import com.gutschke.wgrtc.ui.components.HelpHint
import kotlinx.coroutines.launch

/**
 * Edit-an-existing-tunnel screen. Less common than create — the
 * common flows (rename, delete) live in `TunnelDetailScreen`'s
 * top-bar — but it's the only way to change the wg-quick body, the
 * per-tunnel broker, or the tunnel source after the fact without
 * delete-and-recreate.
 *
 * Layout:
 *
 * - Name field (matches the rename dialog's behavior but inline).
 * - Configuration text — multi-line, monospace. Validated on
 * Save via [WgQuickUapi.render] (same path the paste-tunnel
 * flow uses).
 * - For ENROLL / HOST_MODE: per-tunnel signaling-server fields.
 * Editable so a user can switch a tunnel from the public
 * default to a private broker without re-enrolling. For
 * LEGACY / MANUAL the broker fields are hidden — those tunnels
 * don't run a listener.
 * - For HOST_MODE: subnet readout (read-only with a tooltip
 * explaining why — changing it would invalidate every enrolled
 * peer's IP allocation).
 *
 * On Save: ViewModel disconnects if active, validates, persists,
 * and reconciles the listener subscription. Failures surface in
 * the screen's error label without leaving the screen.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EditTunnelScreen(
    tunnelId: String,
    onBack: () -> Unit,
    onSaved: () -> Unit,
    vm: WgrtcViewModel = viewModel(),
) {
    val tunnels by vm.tunnels.collectAsState()
    val tunnel = tunnels.firstOrNull { it.id == tunnelId }
    if (tunnel == null) {
        Scaffold { pad ->
            androidx.compose.foundation.layout.Box(
                modifier = Modifier.fillMaxSize().padding(pad),
                contentAlignment = androidx.compose.ui.Alignment.Center,
            ) {
                Text("This tunnel was deleted.", style = MaterialTheme.typography.bodyLarge)
            }
        }
        return
    }

    var name by remember(tunnelId) { mutableStateOf(tunnel.name) }
    var configText by remember(tunnelId) { mutableStateOf(tunnel.configText) }
    var brokerWss by remember(tunnelId) { mutableStateOf(tunnel.brokerWss ?: "") }
    var brokerKey by remember(tunnelId) { mutableStateOf(tunnel.brokerKey ?: "") }
    var error by remember(tunnelId) { mutableStateOf<String?>(null) }
    var busy by remember(tunnelId) { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    val canEditBroker = tunnel.source == Tunnel.Source.ENROLL ||
        tunnel.source == Tunnel.Source.HOST_MODE

    val nameDirty = name.trim() != tunnel.name
    val configDirty = configText != tunnel.configText
    val brokerDirty = canEditBroker && (
        brokerWss != (tunnel.brokerWss ?: "") ||
        brokerKey != (tunnel.brokerKey ?: "")
    )
    val dirty = nameDirty || configDirty || brokerDirty

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Edit tunnel") },
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
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                "Changes take effect immediately. If this tunnel is " +
                    "currently connected, it'll disconnect first and " +
                    "you'll need to reconnect manually.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            OutlinedTextField(
                value = name,
                onValueChange = { name = it },
                label = { Text("Name") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )

            OutlinedTextField(
                value = configText,
                onValueChange = { configText = it },
                label = { Text("Configuration") },
                trailingIcon = {
                    HelpHint(
                        title = "WireGuard configuration",
                        body = "The wg-quick block as you'd see it in " +
                            "any standard WireGuard client. Hand-edit " +
                            "with care — broken syntax means the " +
                            "tunnel won't come up.",
                    )
                },
                modifier = Modifier.fillMaxWidth(),
                maxLines = 16,
                textStyle = MaterialTheme.typography.bodySmall.copy(
                    fontFamily = FontFamily.Monospace,
                ),
            )

            if (canEditBroker) {
                Spacer(Modifier.height(8.dp))
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                Spacer(Modifier.height(8.dp))
                Text(
                    "Signaling server",
                    style = MaterialTheme.typography.titleSmall,
                )
                Text(
                    if (tunnel.source == Tunnel.Source.HOST_MODE)
                        "Where joining devices first contact this host."
                    else
                        "Where this device picks up roaming-IP updates " +
                            "from the host.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                OutlinedTextField(
                    value = brokerWss,
                    onValueChange = { brokerWss = it },
                    label = { Text("Server URL") },
                    placeholder = { Text("wss://…") },
                    trailingIcon = {
                        HelpHint(
                            body = "A wss:// URL. For ENROLL tunnels, " +
                                "this overrides what the host's " +
                                "invitation specified — only change " +
                                "if you know what you're doing.",
                        )
                    },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = brokerKey,
                    onValueChange = { brokerKey = it },
                    label = { Text("Server key") },
                    trailingIcon = {
                        HelpHint(
                            body = "API key the signaling server " +
                                "requires. PeerJS-compatible servers " +
                                "use \"peerjs\" by default.",
                        )
                    },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            }

            if (tunnel.hostMode != null) {
                Spacer(Modifier.height(8.dp))
                Text(
                    "Hosting details",
                    style = MaterialTheme.typography.titleSmall,
                )
                ReadOnlyDetail(
                    label = "Address pool",
                    value = tunnel.hostMode.subnet,
                    help = "Locked because changing the subnet would " +
                        "invalidate every currently-enrolled peer's IP. " +
                        "If you really need to migrate, delete the " +
                        "tunnel and re-create it; peers will re-join " +
                        "with fresh invitations.",
                )
                ReadOnlyDetail(
                    label = "Enrolled peers",
                    value = "${tunnel.hostMode.enrolledPeers.size}",
                )
            }

            error?.let {
                Text(
                    it,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodyMedium,
                )
            }

            Spacer(Modifier.height(8.dp))
            Button(
                onClick = {
                    val newName = name.trim().ifBlank { tunnel.name }
                    val newCfg = configText
                    val newBrokerWss = if (canEditBroker)
                        brokerWss.trim().ifBlank { null } else tunnel.brokerWss
                    val newBrokerKey = if (canEditBroker)
                        brokerKey.trim().ifBlank { null } else tunnel.brokerKey
                    busy = true; error = null
                    scope.launch {
                        val ok = vm.updateTunnel(
                            tunnel.copy(
                                name = newName,
                                configText = newCfg,
                                brokerWss = newBrokerWss,
                                brokerKey = newBrokerKey,
                            ),
                        )
                        busy = false
                        if (ok) onSaved()
                        else error = vm.lastError.value
                            ?: "Save failed for an unknown reason."
                    }
                },
                enabled = !busy && dirty,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(if (busy) "Saving…" else "Save changes")
            }
        }
    }
}

@Composable
private fun ReadOnlyDetail(label: String, value: String, help: String? = null) {
    androidx.compose.foundation.layout.Row(
        verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(label, style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(value, style = MaterialTheme.typography.bodyMedium,
                fontFamily = FontFamily.Monospace)
        }
        if (help != null) {
            HelpHint(title = "Locked", body = help)
        }
    }
}
