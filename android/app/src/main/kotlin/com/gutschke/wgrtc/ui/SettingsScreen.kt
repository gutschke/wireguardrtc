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
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.gutschke.wgrtc.data.EgressLiveStatus
import com.gutschke.wgrtc.data.EgressLiveStatusObserver
import com.gutschke.wgrtc.data.EgressPolicy
import com.gutschke.wgrtc.data.SettingsStore
import com.gutschke.wgrtc.data.WormholeDefaults
import com.gutschke.wgrtc.data.decideEgress
import com.gutschke.wgrtc.data.EgressDecision
import com.gutschke.wgrtc.signalling.IpFamily
import com.gutschke.wgrtc.signalling.NatClassification
import com.gutschke.wgrtc.signalling.NatType
import com.gutschke.wgrtc.signalling.classifyNat
import com.gutschke.wgrtc.signalling.lookupIsp
import com.gutschke.wgrtc.signalling.reverseDns
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Settings screen for app-level preferences. Currently the
 * default-broker URL + key — see [SettingsStore]'s kdoc for the
 * deployment-scenario rationale.
 *
 * Stateless w.r.t. persistence: takes a [SettingsStore] from the
 * caller (typically the Application singleton) so the screen is
 * directly previewable / instrumentation-testable.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    settings: SettingsStore,
    onBack: () -> Unit,
    onReplayOnboarding: () -> Unit = {},
    onAbout: () -> Unit = {},
) {
    val storedWss by settings.defaultBrokerWssFlow.collectAsState()
    val storedKey by settings.defaultBrokerKeyFlow.collectAsState()

    // Local edit state; persists when the user taps Save. Live-save
    // would be tempting but a half-typed URL would break the wormhole
    // flow if a session opened mid-edit.
    var wss by remember(storedWss) { mutableStateOf(storedWss) }
    var key by remember(storedKey) { mutableStateOf(storedKey) }

    val dirty = wss != storedWss || key != storedKey

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Settings") },
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
                "Signaling server",
                style = MaterialTheme.typography.titleMedium,
            )
            Text(
                "Where peers find each other for the first time. " +
                    "Both ends of an introduction must use the same " +
                    "server. After joining, each tunnel uses whatever " +
                    "server its host configured.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            OutlinedTextField(
                value = wss,
                onValueChange = { wss = it },
                label = { Text("Server URL") },
                placeholder = { Text("wss://…") },
                trailingIcon = {
                    com.gutschke.wgrtc.ui.components.HelpHint(
                        title = "Signaling server URL",
                        body = "A `wss://` (secure WebSocket) URL. " +
                            "Both ends of an introduction need to use " +
                            "the same server — leave the default if " +
                            "you don't run your own.",
                    )
                },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = key,
                onValueChange = { key = it },
                label = { Text("Server key") },
                trailingIcon = {
                    com.gutschke.wgrtc.ui.components.HelpHint(
                        body = "API key the signaling server requires. " +
                            "PeerJS-compatible servers use \"peerjs\" " +
                            "by default.",
                    )
                },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )

            Spacer(Modifier.height(8.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Button(
                    onClick = {
                        settings.defaultBrokerWss = wss.trim()
                        settings.defaultBrokerKey = key.trim()
                    },
                    enabled = dirty,
                    modifier = Modifier.weight(1f),
                ) { Text("Save") }
                OutlinedButton(
                    onClick = {
                        settings.resetToDefaults()
                        wss = WormholeDefaults.BROKER_WSS
                        key = WormholeDefaults.BROKER_KEY
                    },
                    modifier = Modifier.weight(1f),
                ) { Text("Reset") }
            }

            Spacer(Modifier.height(8.dp))
            Text(
                "Compiled-in defaults:",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                " ${WormholeDefaults.BROKER_WSS}\n" +
                    " key: ${WormholeDefaults.BROKER_KEY}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            Spacer(Modifier.height(24.dp))
            androidx.compose.material3.HorizontalDivider(
                color = MaterialTheme.colorScheme.outlineVariant,
            )
            Spacer(Modifier.height(16.dp))
            NetworkCheckSection()

            Spacer(Modifier.height(24.dp))
            androidx.compose.material3.HorizontalDivider(
                color = MaterialTheme.colorScheme.outlineVariant,
            )
            Spacer(Modifier.height(16.dp))
            AdvancedNetworkSection(settings)

            Spacer(Modifier.height(24.dp))
            androidx.compose.material3.HorizontalDivider(
                color = MaterialTheme.colorScheme.outlineVariant,
            )
            Spacer(Modifier.height(16.dp))
            NotificationSection(settings)

            Spacer(Modifier.height(24.dp))
            androidx.compose.material3.HorizontalDivider(
                color = MaterialTheme.colorScheme.outlineVariant,
            )
            Spacer(Modifier.height(16.dp))
            Text("App", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(4.dp))
            Text(
                "Replay the welcome tour to see the three-page intro " +
                    "again — useful when handing the device to someone " +
                    "who hasn't seen it.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(8.dp))
            OutlinedButton(
                onClick = onReplayOnboarding,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Replay welcome tour") }
            Spacer(Modifier.height(4.dp))
            OutlinedButton(
                onClick = onAbout,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("About + open-source notices") }

            // Version string — read once from PackageInfo at
            // composition. Saves us a BuildConfig.gen build flag
            // and works for both debug + release flavors.
            val ctx = androidx.compose.ui.platform.LocalContext.current
            val versionName = remember {
                try {
                    ctx.packageManager
                        .getPackageInfo(ctx.packageName, 0).versionName ?: ""
                } catch (_: Throwable) { "" }
            }
            Spacer(Modifier.height(16.dp))
            Text(
                "wgrtc v$versionName",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

// HostingMode / JoinerBackend pickers were removed in
// libwgbridge_native.so is the only supported runtime now.

/**
 * Notification preferences section. The endpoint-tracking
 * foreground service must post a notification for Android to keep
 * it alive — but users who run a stable network can demote that
 * notification to MIN importance so it stays out of the shade.
 */
@Composable
private fun NotificationSection(settings: SettingsStore) {
    val hidden by settings.hideListenerNotificationFlow.collectAsState()
    Text("Notifications", style = MaterialTheme.typography.titleMedium)
    Spacer(Modifier.height(8.dp))
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                "Hide endpoint-tracking notification",
                style = MaterialTheme.typography.bodyLarge,
            )
            Text(
                "The background listener keeps your enrolled tunnels' " +
                    "endpoints in sync as your server's IP changes. " +
                    "Android requires it to post a foreground-service " +
                    "notification; switching this on demotes the " +
                    "notification to minimum importance so it stays " +
                    "out of the shade. The listener itself keeps " +
                    "running.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Switch(
            checked = hidden,
            onCheckedChange = { newValue ->
                settings.hideListenerNotification = newValue
                // Re-poke the service so it re-posts using the new
                // channel + priority immediately; otherwise the
                // change wouldn't be visible until the next
                // listener-count change.
                com.gutschke.wgrtc.WgrtcApp.instance.ensureListenerServiceRunning()
            },
        )
    }
}

/**
 * **advanced network section.** When the phone is hosting,
 * traffic from joiners egresses out one of the phone's networks
 * (Wi-Fi, cellular, …). By default Android picks; this section
 * lets the user pin a transport, useful when a ChromeOS device
 * tethers through the phone and the user wants to make sure the
 * egress goes out the home Wi-Fi rather than burning cellular
 * data.
 *
 * Collapsed by default — the default policy (`OsDefault`) is what
 * most users want, and exposing the picker prominently would
 * suggest a wrong-thing-to-tweak. Tap to expand.
 */
/**
 * "Network check" — runs the same STUN-based NAT classifier that the
 * daemon's `wireguardrtc --check-nat` exposes, and surfaces the verdict
 * in plain language.  Lives in Settings rather than per-tunnel
 * Diagnostics because a first-time user wants to test their NAT *before*
 * they create a tunnel, not after.  See task D2.
 */
@Composable
private fun NetworkCheckSection() {
    var inFlight by remember { mutableStateOf(false) }
    var v4 by remember { mutableStateOf<NatClassification?>(null) }
    var v6 by remember { mutableStateOf<NatClassification?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = androidx.compose.runtime.rememberCoroutineScope()

    Text("Network check", style = MaterialTheme.typography.titleMedium)
    Spacer(Modifier.height(4.dp))
    Text(
        "Probe your current network's NAT independently for IPv4 and " +
            "IPv6 — they're often routed differently and IPv6 frequently " +
            "has no NAT at all.  Sends a handful of small UDP packets to " +
            "public STUN servers; takes a few seconds.  No data leaves " +
            "the device.",
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    Spacer(Modifier.height(8.dp))
    Button(
        enabled = !inFlight,
        onClick = {
            inFlight = true
            v4 = null
            v6 = null
            error = null
            scope.launch {
                try {
                    val (rv4, rv6) = withContext(Dispatchers.IO) {
                        val a = classifyNat(NETWORK_CHECK_STUN_SERVERS,
                            family = IpFamily.V4)
                        val b = classifyNat(NETWORK_CHECK_STUN_SERVERS,
                            family = IpFamily.V6)
                        a to b
                    }
                    v4 = rv4
                    v6 = rv6
                } catch (t: Throwable) {
                    error = "Network check failed: ${t.message}"
                } finally {
                    inFlight = false
                }
            }
        },
        modifier = Modifier.fillMaxWidth(),
    ) { Text(if (inFlight) "Checking…" else "Run NAT test") }

    val rv4 = v4
    val rv6 = v6
    if (rv4 != null || rv6 != null) {
        Spacer(Modifier.height(12.dp))
        if (rv4 != null) {
            NetworkCheckVerdict(rv4)
        }
        if (rv4 != null && rv6 != null) {
            Spacer(Modifier.height(12.dp))
        }
        if (rv6 != null) {
            NetworkCheckVerdict(rv6)
        }
    }
    val currentError = error
    if (currentError != null) {
        Spacer(Modifier.height(12.dp))
        Text(
            currentError,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.error,
        )
    }
}

@Composable
private fun NetworkCheckVerdict(r: NatClassification) {
    val familyLabel = if (r.family == IpFamily.V4) "IPv4" else "IPv6"
    val headline: String
    val detail: String
    val viable: Boolean
    val noRoute = r.natType == NatType.UNKNOWN && r.localIp == null
    when {
        noRoute -> {
            headline = "$familyLabel: no route on this device"
            detail = "Skipping STUN probe — this device has no " +
                "$familyLabel connectivity right now."
            viable = false
        }
        r.natType == NatType.CONE_PRESERVING -> {
            // Disambiguate "port-preserving cone NAT" from "no NAT at
            // all" using the local-vs-external comparison the classifier
            // has already done.
            headline = when (r.natDetected) {
                false -> "$familyLabel: no NAT — direct end-to-end"
                true ->
                    if (r.family == IpFamily.V6)
                        "$familyLabel: NAT66 / NPT, port-preserving"
                    else
                        "$familyLabel: cone NAT, port-preserving"
                null -> "$familyLabel: port-preserving"
            }
            detail = "wgrtc's hole-punch should work as designed " +
                "over $familyLabel."
            viable = true
        }
        r.natType == NatType.CONE_REMAPPED -> {
            headline = "$familyLabel: cone NAT, not port-preserving"
            detail = "The router rewrites your source port.  wgrtc will " +
                "publish the wrong port; enable UPnP / NAT-PMP / PCP on " +
                "the router, or use a static port forward."
            viable = false
        }
        r.natType == NatType.SYMMETRIC -> {
            headline = "$familyLabel: symmetric NAT"
            detail = "The router picks a different external port for " +
                "every destination.  Direct hole-punching is infeasible " +
                "on $familyLabel here — wgrtc would need a relay (which " +
                "this project doesn't ship).  Mobile data or a different " +
                "Wi-Fi network usually works."
            viable = false
        }
        else -> {
            headline = "$familyLabel: couldn't classify"
            detail = if (r.note.isNotBlank()) r.note
                     else "No STUN responses.  Check outbound UDP is " +
                          "allowed, then retry."
            viable = false
        }
    }
    Text(
        headline,
        style = MaterialTheme.typography.titleSmall,
        color = if (viable) MaterialTheme.colorScheme.primary
                else MaterialTheme.colorScheme.error,
    )
    Spacer(Modifier.height(4.dp))
    Text(detail, style = MaterialTheme.typography.bodyMedium)

    // Background reverse-DNS + ISP lookups.  These are best-effort
    // UI sugar — the verdict itself doesn't wait for them.  Each
    // lookup independently writes its result into local state, which
    // triggers a recomposition when it arrives (or when the timeout
    // hits and we never set anything).
    var localRdns by remember(r) { mutableStateOf<String?>(null) }
    var externalRdns by remember(r) { mutableStateOf<String?>(null) }
    var isp by remember(r) { mutableStateOf<String?>(null) }
    LaunchedEffect(r) {
        coroutineScope {
            r.localIp?.let { li ->
                launch { localRdns = reverseDns(li) }
            }
            r.externalIp?.let { ei ->
                launch { externalRdns = reverseDns(ei) }
                launch { isp = lookupIsp(ei) }
            }
        }
    }

    val localIp = r.localIp
    val externalIp = r.externalIp
    if (localIp != null) {
        Spacer(Modifier.height(4.dp))
        Text(
            "Local $familyLabel: $localIp" +
                (localRdns?.let { "  ($it)" } ?: ""),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
    if (externalIp != null) {
        Text(
            "External $familyLabel: $externalIp" +
                (externalRdns?.let { "  ($it)" } ?: ""),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
    // NAT presence: shown only after the verdict so the user can read
    // it alongside the addresses they're already looking at.
    if (r.natDetected != null && r.localIp != null && r.externalIp != null) {
        Text(
            if (r.natDetected == true) "NAT: detected (external differs from local)"
            else "NAT: none — direct end-to-end",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
    isp?.let {
        Text(
            "ISP: $it",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

/** STUN servers used by the Settings → Network check panel.  Kept in
 *  sync with `ListenerHub.DEFAULT_STUN_SERVERS` and the daemon's
 *  `DEFAULT_STUN_SERVERS`. */
private val NETWORK_CHECK_STUN_SERVERS = listOf(
    "stun.l.google.com:19302",
    "stun.cloudflare.com:3478",
    "stun.nextcloud.com:3478",
)

@Composable
private fun AdvancedNetworkSection(settings: SettingsStore) {
    var expanded by remember { mutableStateOf(false) }
    val policy by settings.egressPolicyFlow.collectAsState()
    val liveStatus = rememberEgressLiveStatus()

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { expanded = !expanded },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            "Network routing (advanced)",
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier.weight(1f),
        )
        Icon(
            imageVector = if (expanded) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
            contentDescription = if (expanded) "Collapse" else "Expand",
        )
    }
    if (expanded) {
        Spacer(Modifier.height(4.dp))
        Text(
            "When you host a tunnel, traffic from joiners exits via " +
                "one of this phone's networks. Pin a transport if you " +
                "want to make sure a tethered ChromeOS device's traffic " +
                "goes out the same Wi-Fi you're on, rather than the " +
                "cellular data plan.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(8.dp))
        EgressOption(
            label = "Let Android choose",
            description = "Default route. Whatever the phone is " +
                "currently using.",
            selected = policy == EgressPolicy.OsDefault,
            enabled = true,
            onSelect = { settings.egressPolicy = EgressPolicy.OsDefault },
        )
        EgressOption(
            label = "Wi-Fi only",
            description = "Refuse to forward if Wi-Fi is down. " +
                "Prevents cellular spend if Wi-Fi drops.",
            selected = policy == EgressPolicy.WifiOnly,
            enabled = true,
            onSelect = { settings.egressPolicy = EgressPolicy.WifiOnly },
        )
        EgressOption(
            label = "Prefer Wi-Fi",
            description = "Use Wi-Fi when available, fall back to " +
                "whatever Android picks otherwise.",
            selected = policy == EgressPolicy.WifiPreferred,
            enabled = true,
            onSelect = { settings.egressPolicy = EgressPolicy.WifiPreferred },
        )
        // Disable the cellular radio when the phone reports no
        // cellular transport (airplane mode, no SIM, etc.) so the
        // user can't pick a policy that's guaranteed to refuse.
        EgressOption(
            label = "Cellular only",
            description = if (liveStatus.cellularAvailable)
                "Force traffic out the cellular plan even when on " +
                    "Wi-Fi. Useful if Wi-Fi can't reach what you're " +
                    "trying to access."
            else
                "(disabled — no cellular network available on " +
                    "this device)",
            selected = policy == EgressPolicy.CellularOnly,
            enabled = liveStatus.cellularAvailable,
            onSelect = { settings.egressPolicy = EgressPolicy.CellularOnly },
        )

        // Live "Currently:" indicator — ground truth in real time
        // rather than a confirmation dialog after a misclick.
        Spacer(Modifier.height(12.dp))
        EgressEffectiveLine(policy, liveStatus)
    }
}

@Composable
private fun EgressEffectiveLine(
    policy: EgressPolicy,
    status: EgressLiveStatus,
) {
    val decision = decideEgress(
        policy = policy,
        wifiAvailable = status.wifiAvailable,
        cellularAvailable = status.cellularAvailable,
    )
    val (label, isRefusal) = when (decision) {
        EgressDecision.OS_DEFAULT -> {
            val pick = when {
                status.wifiAvailable && status.wifiLabel != null ->
                    "Wi-Fi (${status.wifiLabel})"
                status.wifiAvailable -> "Wi-Fi"
                status.cellularAvailable && status.cellularLabel != null ->
                    "Cellular (${status.cellularLabel})"
                status.cellularAvailable -> "Cellular"
                else -> "no network"
            }
            "Currently: Android default ($pick)" to false
        }
        EgressDecision.USE_WIFI ->
            ("Currently: Wi-Fi" + (status.wifiLabel?.let { " ($it)" } ?: "")) to false
        EgressDecision.USE_CELLULAR ->
            ("Currently: Cellular" + (status.cellularLabel?.let { " ($it)" } ?: "")) to false
        EgressDecision.FAIL_WIFI_REQUIRED ->
            "Currently: will refuse to forward — Wi-Fi unavailable" to true
        EgressDecision.FAIL_CELLULAR_REQUIRED ->
            "Currently: will refuse to forward — cellular unavailable" to true
    }
    Text(
        text = label,
        style = MaterialTheme.typography.bodySmall,
        color = if (isRefusal) MaterialTheme.colorScheme.error
        else MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

@Composable
private fun rememberEgressLiveStatus(): EgressLiveStatus {
    val context = LocalContext.current
    var status by remember {
        mutableStateOf(EgressLiveStatus.snapshot(context))
    }
    DisposableEffect(context) {
        val obs = EgressLiveStatusObserver(context)
        obs.start { newStatus -> status = newStatus }
        onDispose { obs.stop() }
    }
    return status
}

@Composable
private fun EgressOption(
    label: String,
    description: String,
    selected: Boolean,
    enabled: Boolean,
    onSelect: () -> Unit,
) {
    val mod = if (enabled) Modifier
        .fillMaxWidth()
        .clickable { onSelect() }
        .padding(vertical = 4.dp)
    else Modifier
        .fillMaxWidth()
        .padding(vertical = 4.dp)
    Row(
        modifier = mod,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        RadioButton(
            selected = selected,
            onClick = if (enabled) onSelect else null,
            enabled = enabled,
            modifier = Modifier.size(40.dp),
        )
        Spacer(Modifier.size(8.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                label,
                style = MaterialTheme.typography.bodyMedium,
                color = if (enabled) MaterialTheme.colorScheme.onSurface
                else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.38f),
            )
            Text(
                description,
                style = MaterialTheme.typography.bodySmall,
                color = if (enabled) MaterialTheme.colorScheme.onSurfaceVariant
                else MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.38f),
            )
        }
    }
}
