package com.gutschke.wgrtc.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.gutschke.wgrtc.WgrtcViewModel

/**
 * Host for the §6.2 ChromeOS routing-loop dialog.  Mounted once at
 * the NavHost level (`MainActivity.AppNavHost`) so the warning
 * surfaces regardless of which route the user tapped Connect from.
 *
 * Why a dedicated host: the dialog was originally embedded inside
 * `TunnelListScreen`.  When the user navigated to `TunnelDetailScreen`
 * and tapped Connect there, `WgrtcViewModel.connect`'s ARC precheck
 * still fired and set `_chromeOsLoopWarningFor.value`, but the
 * dialog never rendered because `TunnelListScreen` wasn't in the
 * active composition.  The user saw Connect → "nothing happens".
 * Hoisting the renderer here closes that gap.
 */
@Composable
fun ChromeOsRoutingLoopHost(vm: WgrtcViewModel) {
    val warningFor by vm.chromeOsLoopWarningFor.collectAsState()
    val ctx = androidx.compose.ui.platform.LocalContext.current
    warningFor?.let { t ->
        AlertDialog(
            onDismissRequest = { vm.acknowledgeChromeOsLoopWarning(t.id, proceed = false) },
            title = { Text("Possible routing loop?") },
            text = {
                Text(
                    "Before \"${t.name}\" comes up: if another WireGuard " +
                        "client on this Chromebook has this device's IP " +
                        "in its AllowedIPs, traffic will loop back here " +
                        "and your network will break.\n\n" +
                        "Open ChromeOS Settings → Network → VPN and check.",
                )
            },
            confirmButton = {
                Button(onClick = {
                    val intent = android.content.Intent(
                        android.provider.Settings.ACTION_VPN_SETTINGS,
                    )
                    intent.flags = android.content.Intent.FLAG_ACTIVITY_NEW_TASK
                    runCatching { ctx.startActivity(intent) }
                    vm.acknowledgeChromeOsLoopWarning(t.id, proceed = true)
                }) { Text("Open settings") }
            },
            dismissButton = {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TextButton(onClick = {
                        vm.acknowledgeChromeOsLoopWarning(t.id, proceed = false)
                    }) { Text("Cancel") }
                    OutlinedButton(onClick = {
                        vm.acknowledgeChromeOsLoopWarning(t.id, proceed = true)
                    }) { Text("I've checked") }
                }
            },
            modifier = Modifier,
        )
    }
}
