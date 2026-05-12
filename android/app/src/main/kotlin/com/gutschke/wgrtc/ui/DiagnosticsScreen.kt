package com.gutschke.wgrtc.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshots.SnapshotStateList
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.gutschke.wgrtc.data.IcmpPinger
import com.gutschke.wgrtc.data.TcpTraceroute
import com.gutschke.wgrtc.data.Tunnel
import com.gutschke.wgrtc.data.WgQuickFields
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import java.net.InetAddress

/**
 * **Per-tunnel diagnostics.**
 *
 * Two operations, both bound to the phone's current egress
 * (whatever Android picks; respecting the active WG VpnService
 * if one is connected — pings to the tunnel's address will
 * naturally flow through the kernel TUN):
 *
 * - **Ping** — fires 4 ICMPv4 echo requests via
 * `Os.socket(IPPROTO_ICMP)`. Real RTT, real packet loss.
 * - **Traceroute** — TCP-based with `IP_TTL`-varying connects;
 * shows per-hop timing. No intermediate hop IPs (see
 * [TcpTraceroute] kdoc).
 *
 * Targets are user-editable text fields prefilled with sensible
 * defaults: the host's address inferred from the tunnel's
 * AllowedIPs, plus `1.1.1.1` for an internet sanity check.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DiagnosticsScreen(
    tunnel: Tunnel?,
    onBack: () -> Unit,
) {
    val title = "Diagnose " + (tunnel?.name ?: "tunnel")
    val inferredTunnelTarget = remember(tunnel) {
        tunnel?.configText?.let { DiagnosticsTargets.inferHostAddress(it) }
            ?: tunnel?.hostMode?.subnet?.let {
                DiagnosticsTargets.firstIpOfSubnet(it)
            }
    }
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(title) },
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
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            PingSection(tunnelTargetDefault = inferredTunnelTarget)
            androidx.compose.material3.HorizontalDivider()
            TracerouteSection()
            androidx.compose.material3.HorizontalDivider()
            Text(
                "Notes:\n" +
                "• Ping uses unprivileged ICMP (no special permissions).\n" +
                "• Traceroute is TCP-based — intermediate hops show as " +
                "TIMEOUT. Timing pattern still localises path " +
                "problems (e.g. \"hops 1-3 fast, 4 onwards slow\").\n" +
                "• If a tunnel is connected, traffic to its address " +
                "automatically routes through the tunnel.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun PingSection(tunnelTargetDefault: String?) {
    var target by remember(tunnelTargetDefault) {
        mutableStateOf(tunnelTargetDefault ?: "1.1.1.1")
    }
    var result by remember { mutableStateOf<IcmpPinger.PingResult?>(null) }
    var inFlight by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    Text("Ping", style = MaterialTheme.typography.titleMedium)
    OutlinedTextField(
        value = target,
        onValueChange = { target = it.trim() },
        label = { Text("Target host or IP") },
        singleLine = true,
        enabled = !inFlight,
        modifier = Modifier.fillMaxWidth(),
    )
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(
            enabled = !inFlight && target.isNotBlank(),
            onClick = {
                inFlight = true
                result = null
                scope.launch {
                    result = runCatching {
                        val ip = InetAddress.getByName(target)
                        IcmpPinger().pingMany(ip, count = 4,
                            intervalMs = 250, timeoutMs = 1500)
                    }.getOrElse {
                        IcmpPinger.PingResult.fatal(
                            "could not resolve / open socket: ${it.message}")
                    }
                    inFlight = false
                }
            },
            modifier = Modifier.weight(1f),
        ) { Text(if (inFlight) "Pinging…" else "Ping (4 packets)") }
        OutlinedButton(
            enabled = !inFlight,
            onClick = { target = "1.1.1.1" },
        ) { Text("Internet") }
        if (tunnelTargetDefault != null) {
            OutlinedButton(
                enabled = !inFlight,
                onClick = { target = tunnelTargetDefault },
            ) { Text("Tunnel") }
        }
    }
    result?.let { r -> PingResultBlock(r) }
}

@Composable
private fun PingResultBlock(r: IcmpPinger.PingResult) {
    if (r.errorMessage != null) {
        Text(
            "Error: ${r.errorMessage}",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.error,
        )
        return
    }
    val summary = buildString {
        append("${r.packetsReceived}/${r.packetsSent} received")
        if (r.rttsMs.isNotEmpty()) {
            append(
                ", min ${r.minRttMs}ms / avg ${r.avgRttMs}ms " +
                    "/ max ${r.maxRttMs}ms")
        }
        if (r.packetLossPct > 0) append(" — ${r.packetLossPct}% loss")
    }
    Text(summary, style = MaterialTheme.typography.bodyMedium)
    if (r.rttsMs.isNotEmpty()) {
        Text(
            "RTTs: " + r.rttsMs.joinToString(", ") { "${it}ms" },
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun TracerouteSection() {
    var host by remember { mutableStateOf("1.1.1.1") }
    var port by remember { mutableStateOf("80") }
    var inFlight by remember { mutableStateOf(false) }
    val hops = remember { mutableStateListOf<TcpTraceroute.HopResult>() }
    val scope = rememberCoroutineScope()
    var traceJob by remember { mutableStateOf<Job?>(null) }

    Text("Traceroute", style = MaterialTheme.typography.titleMedium)
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedTextField(
            value = host,
            onValueChange = { host = it.trim() },
            label = { Text("Host") },
            singleLine = true,
            enabled = !inFlight,
            modifier = Modifier.weight(1f),
        )
        OutlinedTextField(
            value = port,
            onValueChange = { port = it.filter(Char::isDigit).take(5) },
            label = { Text("Port") },
            singleLine = true,
            enabled = !inFlight,
            modifier = Modifier.width(96.dp),
        )
    }
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(
            enabled = !inFlight && host.isNotBlank() && port.isNotBlank(),
            onClick = {
                inFlight = true
                hops.clear()
                val portInt = port.toIntOrNull() ?: 80
                traceJob = scope.launch {
                    try {
                        val target = InetAddress.getByName(host)
                        TcpTraceroute(maxHops = 20, timeoutMsPerHop = 1500)
                            .traceStreaming(target, portInt) { hop ->
                                hops.add(hop)
                            }
                    } catch (t: Throwable) {
                        hops.add(TcpTraceroute.HopResult(
                            ttl = 0,
                            status = TcpTraceroute.HopStatus.ERROR,
                            rttMs = null,
                            errorMessage = "trace failed: ${t.message}",
                        ))
                    } finally { inFlight = false }
                }
            },
            modifier = Modifier.weight(1f),
        ) { Text(if (inFlight) "Tracing…" else "Start traceroute") }
        if (inFlight) {
            OutlinedButton(onClick = { traceJob?.cancel() }) {
                Text("Cancel")
            }
        }
    }
    if (hops.isNotEmpty()) HopList(hops)
}

@Composable
private fun HopList(hops: SnapshotStateList<TcpTraceroute.HopResult>) {
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        hops.forEach { hop ->
            val statusLabel = when (hop.status) {
                TcpTraceroute.HopStatus.REACHED_OPEN -> "reached, port open"
                TcpTraceroute.HopStatus.REACHED_CLOSED -> "reached, port closed (RST)"
                TcpTraceroute.HopStatus.TIMEOUT -> "no response"
                TcpTraceroute.HopStatus.UNREACHABLE -> "unreachable"
                TcpTraceroute.HopStatus.ERROR -> "error"
            }
            val rttSuffix = hop.rttMs?.let { " — ${it}ms" } ?: ""
            val color = when (hop.status) {
                TcpTraceroute.HopStatus.REACHED_OPEN,
                TcpTraceroute.HopStatus.REACHED_CLOSED -> MaterialTheme.colorScheme.primary
                TcpTraceroute.HopStatus.UNREACHABLE,
                TcpTraceroute.HopStatus.ERROR -> MaterialTheme.colorScheme.error
                TcpTraceroute.HopStatus.TIMEOUT -> MaterialTheme.colorScheme.onSurfaceVariant
            }
            Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                Text(
                    "%2d.".format(hop.ttl),
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.width(36.dp),
                )
                Text(
                    statusLabel + rttSuffix,
                    style = MaterialTheme.typography.bodyMedium,
                    color = color,
                )
            }
            hop.errorMessage?.takeIf {
                hop.status == TcpTraceroute.HopStatus.ERROR
            }?.let {
                Text(
                    " $it",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
        }
    }
}

/** Helpers for inferring sensible default ping/traceroute targets
 * from a tunnel's wg-quick config text. Pure — unit-testable.
 */
object DiagnosticsTargets {

    /** Best-effort guess at the *host's* IP from a JOINER's
     * wg-quick config. Strategy:
     *
     * 1. Parse `[Peer] AllowedIPs`; the first listed network's
     * first usable host (the `.1` of an IPv4 prefix) is the
     * canonical "host address" for our subnet layout.
     * 2. If AllowedIPs is a `/32`, that IS the host's IP.
     * 3. Fallback: replace the last octet of `[Interface]
     * Address` with `1` (same convention).
     *
     * Returns null if neither yields a parseable address. */
    fun inferHostAddress(wgQuick: String): String? {
        val fields = WgQuickFields.parse(wgQuick)
        fields.peerAllowedIps?.let { allowed ->
            val first = allowed.split(',').map { it.trim() }
                .firstOrNull { it.isNotEmpty() }
            if (first != null) {
                if (first.contains('/')) {
                    val (ip, prefix) = first.split('/', limit = 2)
                    if (prefix.trim() == "32") return ip.trim()
                    return firstIpOfSubnet(first)
                } else {
                    return first
                }
            }
        }
        fields.interfaceAddress?.let { addr ->
            val ip = addr.substringBefore('/').trim()
            val parts = ip.split('.')
            if (parts.size == 4 && parts.all { it.toIntOrNull() in 0..255 }) {
                return "${parts[0]}.${parts[1]}.${parts[2]}.1"
            }
        }
        return null
    }

    /** First usable IPv4 in a `prefix/mask` subnet. Returns
     * null on parse failure. */
    fun firstIpOfSubnet(cidr: String): String? {
        val (ipPart, maskPart) = if (cidr.contains('/')) {
            cidr.split('/', limit = 2).let { it[0].trim() to it[1].trim() }
        } else cidr.trim() to "32"
        val parts = ipPart.split('.')
        if (parts.size != 4 || parts.any { it.toIntOrNull() !in 0..255 }) return null
        val prefix = maskPart.toIntOrNull() ?: return null
        if (prefix !in 0..32) return null
        // Compute network address.
        val ipInt = (parts[0].toInt() shl 24) or
            (parts[1].toInt() shl 16) or
            (parts[2].toInt() shl 8) or
            parts[3].toInt()
        val mask = if (prefix == 0) 0 else (-1 shl (32 - prefix))
        val networkInt = ipInt and mask
        val firstHostInt = if (prefix == 32) networkInt
            else if (prefix == 31) networkInt // RFC 3021
            else networkInt + 1
        return "${(firstHostInt ushr 24) and 0xff}.${(firstHostInt ushr 16) and 0xff}." +
            "${(firstHostInt ushr 8) and 0xff}.${firstHostInt and 0xff}"
    }
}
