package com.gutschke.wgrtc.ui

import android.graphics.Bitmap
import android.graphics.Color
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.google.zxing.BarcodeFormat
import com.google.zxing.MultiFormatWriter
import com.gutschke.wgrtc.data.ManualConfigServer
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow

/**
 * Modal that displays a manually-generated wg-quick config block
 * and (optionally, after explicit user opt-in) hands it out via a
 * one-shot HTTP server. Owns the [ManualConfigServer] lifecycle
 * via [DisposableEffect] so dismissing the dialog stops the
 * server even if the user didn't tap the explicit Stop button.
 */
@Composable
fun ManualConfigDialog(
    wgQuickText: String,
    hostInTunnelAddress: String? = null,
    onDismiss: () -> Unit,
) {
    var server by remember { mutableStateOf<ManualConfigServer?>(null) }
    val serverUrl = remember { MutableStateFlow<String?>(null) }
    val urlState by serverUrl.collectAsState()

    DisposableEffect(Unit) {
        onDispose {
            server?.stop()
            server = null
        }
    }

    // Tick the server-state observer every 500 ms so the URL
    // reflects the (possibly TTL-driven) auto-stop.
    LaunchedEffect(server) {
        val s = server ?: return@LaunchedEffect
        while (s === server && s.url != null) {
            serverUrl.value = s.url
            delay(500)
        }
        serverUrl.value = null
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Manual configuration") },
        text = {
            Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
                Text(
                    "Have your guest paste this into their WireGuard " +
                        "client (e.g. ChromeOS Settings → Network → " +
                        "WireGuard, or the Play-Store WireGuard app).",
                    style = MaterialTheme.typography.bodyMedium,
                )
                hostInTunnelAddress?.let { addr ->
                    Spacer(Modifier.height(8.dp))
                    Card(
                        colors = androidx.compose.material3.CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.primaryContainer,
                            contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                        ),
                    ) {
                        Column(modifier = Modifier.padding(12.dp)) {
                            Text(
                                "Reach this device at",
                                style = MaterialTheme.typography.labelSmall,
                            )
                            Text(
                                addr,
                                style = MaterialTheme.typography.titleMedium,
                                fontFamily = FontFamily.Monospace,
                            )
                            Text(
                                "Once the joiner imports + connects, " +
                                    "they can ping this address to confirm " +
                                    "the tunnel is up.",
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                    }
                }
                Spacer(Modifier.height(12.dp))

                val qr = remember(wgQuickText) { encodeQr(wgQuickText, 480) }
                if (qr != null) {
                    Image(
                        bitmap = qr.asImageBitmap(),
                        contentDescription = "Config QR",
                        modifier = Modifier
                            .fillMaxWidth()
                            .size(240.dp)
                            .clip(RoundedCornerShape(8.dp)),
                    )
                    Spacer(Modifier.height(12.dp))
                }
                Card(modifier = Modifier.fillMaxWidth()) {
                    Text(
                        wgQuickText,
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        modifier = Modifier.padding(8.dp),
                    )
                }
                Spacer(Modifier.height(8.dp))

                // Per-field view for ChromeOS / router-firmware imports
                // that don't accept a paste-the-block. Hidden behind
                // a disclosure to keep the default dialog short.
                var showFields by remember { mutableStateOf(false) }
                androidx.compose.material3.TextButton(
                    onClick = { showFields = !showFields },
                ) {
                    Text(if (showFields) "Hide field-by-field view"
                         else "Show field-by-field view (for ChromeOS)")
                }
                if (showFields) {
                    val fields = remember(wgQuickText) {
                        com.gutschke.wgrtc.data.WgQuickFields.parse(wgQuickText).named()
                    }
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = androidx.compose.material3.CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.surfaceVariant,
                        ),
                    ) {
                        Column(modifier = Modifier.padding(8.dp)) {
                            for ((label, value) in fields) {
                                Text(label,
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                                Text(
                                    value,
                                    style = MaterialTheme.typography.bodySmall,
                                    fontFamily = FontFamily.Monospace,
                                    modifier = Modifier.padding(bottom = 6.dp),
                                )
                            }
                        }
                    }
                }
                Spacer(Modifier.height(16.dp))

                // The HTTP-server option is opt-in. Until the user
                // taps "Serve via HTTP", the config never touches the
                // network.
                if (server == null) {
                    Text(
                        "Or — share this config over your local network:",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(4.dp))
                    OutlinedButton(
                        onClick = {
                            try {
                                val s = ManualConfigServer(wgQuickText)
                                s.start()
                                server = s
                            } catch (t: Throwable) {
                                // Bind failure — leave the dialog
                                // showing the text/QR fallback.
                            }
                        },
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Serve over HTTP (10 minutes)") }
                } else {
                    Text(
                        "Open this URL on the joining device:",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    Spacer(Modifier.height(4.dp))
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Text(
                            urlState ?: "(server stopped)",
                            style = MaterialTheme.typography.bodyMedium,
                            fontFamily = FontFamily.Monospace,
                            modifier = Modifier.padding(8.dp),
                        )
                    }
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "Valid for 10 minutes. The page presents the " +
                            "config as text — the joiner taps the " +
                            "box to select, copies, and pastes into " +
                            "their WireGuard client. (Chrome blocks " +
                            "downloads over plain HTTP, so saving as " +
                            "a file isn't an option from a browser.)",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(8.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.End,
                    ) {
                        TextButton(onClick = {
                            server?.stop()
                            server = null
                        }) { Text("Stop server") }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text("Done") }
        },
    )
}

private fun encodeQr(content: String, pixels: Int): Bitmap? = try {
    val matrix = MultiFormatWriter().encode(content, BarcodeFormat.QR_CODE, pixels, pixels)
    val w = matrix.width
    val h = matrix.height
    val arr = IntArray(w * h)
    for (y in 0 until h) {
        val r = y * w
        for (x in 0 until w) {
            arr[r + x] = if (matrix.get(x, y)) Color.BLACK else Color.WHITE
        }
    }
    Bitmap.createBitmap(arr, w, h, Bitmap.Config.ARGB_8888)
} catch (_: Exception) { null }
