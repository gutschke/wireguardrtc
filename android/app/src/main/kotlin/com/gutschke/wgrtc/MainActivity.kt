package com.gutschke.wgrtc

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.core.content.ContextCompat
import androidx.compose.material3.MaterialTheme
import com.gutschke.wgrtc.ui.theme.WgrtcTheme
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.lifecycle.lifecycleScope
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import com.gutschke.wgrtc.data.WormholeDefaults
import com.gutschke.wgrtc.data.WormholeHostController
import com.gutschke.wgrtc.data.WormholeJoinController
import com.gutschke.wgrtc.signalling.WormholeCode
import com.gutschke.wgrtc.ui.AddTunnelScreen
import com.gutschke.wgrtc.ui.HostModeSetupScreen
import com.gutschke.wgrtc.ui.LocalConnect
import com.gutschke.wgrtc.ui.LocalDisconnect
import com.gutschke.wgrtc.ui.ManualEntryScreen
import com.gutschke.wgrtc.ui.PasteTunnelScreen
import com.gutschke.wgrtc.ui.Routes
import com.gutschke.wgrtc.ui.ScanQrScreen
import com.gutschke.wgrtc.ui.TunnelDetailScreen
import com.gutschke.wgrtc.ui.TunnelListScreen
import com.gutschke.wgrtc.ui.WormholeHostScreen
import com.gutschke.wgrtc.ui.WormholeJoinScreen
import com.gutschke.wgrtc.ui.launchHostDevStub
import com.gutschke.wgrtc.ui.launchJoinDevStub
import kotlinx.coroutines.launch

/**
 * Hosts the navigation graph and owns the VPN-consent launcher.
 *
 * The two callbacks plumbed via `LocalConnect`/`LocalDisconnect` let
 * arbitrary screens trigger Connect/Disconnect without holding an
 * Activity reference; the consent dialog is fired here, the actual
 * `setState` call is delegated to [WgrtcViewModel].
 */
class MainActivity : ComponentActivity() {

    private val vm: WgrtcViewModel by viewModels()
    private lateinit var consentLauncher: ActivityResultLauncher<Intent>
    private var pendingTunnelId: String? = null
    private lateinit var notificationPermissionLauncher:
        ActivityResultLauncher<String>

    override fun onResume() {
        super.onResume()
        // Returning to the foreground is a strong hint the user is
        // about to tap Connect — fire a debounced wake at every
        // ENROLL tunnel so the daemon's STUN-discovered endpoint is
        // fresh by the time setState(UP) runs. Hub coalesces, so
        // multiple onResume calls inside the debounce window are
        // free.
        vm.wakeAllEnrollTunnels()
        // The user may have added a tunnel during the previous
        // foreground life without consenting to notifications.
        // Re-check on every resume so the system permission sheet
        // shows up next time the app is in front.
        maybeRequestNotificationPermission()
        // PHANTOM-ACTIVE FIX (v2 §6.1 signal 3):
        // re-check VPN consent on every foreground.  If prepare()
        // returns a non-null Intent it means consent has been
        // revoked between connect attempts (typically the user
        // toggled VPN permission off in Settings → Apps → wgrtc).
        // Don't launch the consent UI here — that's the user's call
        // when they next tap Connect.  Just emit the registry
        // event so the row stops claiming Connected.
        if (VpnService.prepare(this) != null) {
            val registry = com.gutschke.wgrtc.data.TunnelStateRegistry
                .getProcessSingleton()
            for (id in vm.activeJoinerNTunnelIds.value) {
                registry.recordRevoke(
                    id,
                    com.gutschke.wgrtc.data.PauseReason.ForegroundResync,
                    note = "VpnService.prepare() returned non-null on resume",
                )
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        consentLauncher = registerForActivityResult(
            ActivityResultContracts.StartActivityForResult()
        ) { result ->
            val id = pendingTunnelId
            pendingTunnelId = null
            if (result.resultCode != RESULT_OK || id == null) return@registerForActivityResult
            connectAfterConsent(id)
        }

        // POST_NOTIFICATIONS is a runtime permission on Android 13+.
        // Without it the OfferListenerService runs but its foreground
        // notification is silently suppressed — the user has no way
        // to see that wgrtc is keeping a long-lived connection open,
        // and Play Store review for FOREGROUND_SERVICE_SPECIAL_USE
        // requires the notification to be visible. We only request
        // when there's actually something to notify about (the user
        // has at least one ENROLL or HOST_MODE tunnel).
        notificationPermissionLauncher = registerForActivityResult(
            ActivityResultContracts.RequestPermission()
        ) { granted ->
            Log.i("wgrtc-main", "POST_NOTIFICATIONS granted=$granted")
            if (granted) {
                // Re-poke the service so it re-posts its notification
                // now that the system will actually surface it.
                WgrtcApp.instance.ensureListenerServiceRunning()
            }
        }

        // Ask once on every cold start when the situation calls for
        // it. No-op when the permission was already granted (the
        // system returns PERMISSION_GRANTED immediately) or when we
        // have nothing to notify about.
        maybeRequestNotificationPermission()

        setContent {
            WgrtcTheme {
                CompositionLocalProvider(
                    LocalConnect provides ::requestConnect,
                    LocalDisconnect provides ::requestDisconnect,
                ) {
                    AppNavHost()
                }
            }
        }
    }

    /** Request POST_NOTIFICATIONS at runtime when (a) we're on
     * Android 13+, (b) the permission isn't already granted, and
     * (c) the user has at least one tunnel that needs the
     * foreground service to be alive. Without (c) we'd be asking
     * for a permission the app doesn't yet need, which Play
     * reviewers and users both dislike. */
    private fun maybeRequestNotificationPermission() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        val perm = Manifest.permission.POST_NOTIFICATIONS
        val already = ContextCompat.checkSelfPermission(this, perm) ==
            PackageManager.PERMISSION_GRANTED
        if (already) return
        if (WgrtcApp.instance.listenerHub.activeCount == 0) return
        notificationPermissionLauncher.launch(perm)
    }

    /** Pull a URI out of [intent]. Single legitimate source: third-
     * party VIEW intents carrying a `wgrtc-enroll://` URI. Skips
     * history-replayed VIEW intents because the embedded
     * single-use token would just time out at the daemon and the
     * resulting "auto-enroll failed" ERROR confuses users.
     *
     * Returns null if no URI is present. Consumes [intent.data] on
     * success so a recompose doesn't re-fire the same URI.
     *
     * (The earlier `--es config`, `ACTION_SCAN_RESULT`, and the
     * other agentic-test intent surfaces have been moved to the
     * `agent` buildType so they are not present in
     * Play-Store / GitHub release builds.) */
    private fun consumeIncomingUri(intent: Intent?): String? {
        if (intent == null) return null
        if (intent.action != Intent.ACTION_VIEW) return null
        if ((intent.flags and Intent.FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY) != 0) {
            Log.i("wgrtc-main",
                "ignoring history-replayed VIEW intent " +
                "(single-use token would just time out): " +
                intent.data)
            intent.data = null
            return null
        }
        val data = intent.data?.toString() ?: return null
        intent.data = null
        return data
    }

    /** Dispatch a URI received via intent: if it's a wgrtc-enroll URI
     * fire enrollment silently; if it's a wg-quick paste, stash for
     * the paste screen; anything else is logged and ignored. */
    private fun handleIncomingUri(raw: String) {
        if (raw.startsWith("wgrtc-enroll://")) {
            lifecycleScope.launch {
                try {
                    val uri = com.gutschke.wgrtc.signalling.EnrollUri.parse(raw)
                    vm.enrollAndAdd(uri, deviceLabel = "android-wgrtc", name = null)
                } catch (t: Throwable) {
                    Log.e("wgrtc-main", "auto-enroll from intent failed", t)
                }
            }
        } else {
            vm.setPendingPaste(raw)
        }
    }

    override fun onNewIntent(intent: Intent) {
        // singleTask / singleTop activities receive subsequent
        // launches here rather than in onCreate. Mirror the same
        // dispatch so a second VIEW-intent (e.g. user scans another
        // QR while we're still in the foreground) is handled.
        Log.i("wgrtc-main", "onNewIntent fired: action=${intent.action}")
        super.onNewIntent(intent)
        setIntent(intent)
        consumeIncomingUri(intent)?.let { uri -> handleIncomingUri(uri) }
    }

    @androidx.compose.runtime.Composable
    private fun AppNavHost() {
        val nav = rememberNavController()
        consumeIncomingUri(intent)?.let { uri -> handleIncomingUri(uri) }

        // First-launch onboarding gate — read once at composition.
        // Starting at ONBOARDING when the flag is unset means a
        // fresh install lands the user on the tour without having
        // to navigate there manually; subsequent launches start at
        // LIST. Marking the flag is the user's job (Get started /
        // Skip) so a process kill mid-tour doesn't quietly retire
        // a screen they didn't actually finish reading.
        val app = application as WgrtcApp
        val startDest = remember {
            if (app.settings.onboardingSeen) Routes.LIST else Routes.ONBOARDING
        }
        NavHost(navController = nav, startDestination = startDest) {
            composable(Routes.ONBOARDING) {
                com.gutschke.wgrtc.ui.OnboardingScreen(
                    onDone = {
                        app.settings.onboardingSeen = true
                        nav.popBackStack(Routes.ONBOARDING, inclusive = true)
                        nav.navigate(Routes.LIST) {
                            launchSingleTop = true
                            popUpTo(0) { inclusive = true }
                        }
                    },
                )
            }
            composable(Routes.LIST) {
                TunnelListScreen(
                    onAddClick = { nav.navigate(Routes.ADD) },
                    onTunnelClick = { t -> nav.navigate(Routes.detail(t.id)) },
                    onSettings = { nav.navigate(Routes.SETTINGS) },
                    onJoinClick = { nav.navigate(Routes.JOIN) },
                    onHostClick = { nav.navigate(Routes.HOST_SETUP) },
                    // §11.6 — Tile 3 currently routes to the join
                    // flow.  The orchestrated wizard that creates
                    // both halves with a shared groupId is §11.8;
                    // until it lands, the user has a clean entry
                    // point for the first half.
                    onBridgeClick = { nav.navigate(Routes.JOIN) },
                    vm = vm,
                )
            }
            composable(Routes.SETTINGS) {
                com.gutschke.wgrtc.ui.SettingsScreen(
                    settings = (application as WgrtcApp).settings,
                    onBack = { nav.popBackStack() },
                    onReplayOnboarding = {
                        // Don't unset the seen flag — that would
                        // re-trigger the gate on next process start.
                        // Just navigate forward; "Get started" /
                        // "Skip" pop back to whatever was below.
                        nav.navigate(Routes.ONBOARDING)
                    },
                    onAbout = { nav.navigate(Routes.ABOUT) },
                )
            }
            composable(Routes.ABOUT) {
                com.gutschke.wgrtc.ui.AboutScreen(
                    onBack = { nav.popBackStack() },
                )
            }
            composable(Routes.ADD) {
                AddTunnelScreen(
                    onBack = { nav.popBackStack() },
                    onJoin = { nav.navigate(Routes.JOIN) },
                    onHost = { nav.navigate(Routes.HOST_SETUP) },
                )
            }
            composable(Routes.JOIN) {
                com.gutschke.wgrtc.ui.JoinTunnelScreen(
                    onBack = { nav.popBackStack() },
                    onScanQr = { nav.navigate(Routes.SCAN) },
                    onWormhole = { nav.navigate(Routes.WORMHOLE_JOIN) },
                    onPaste = { nav.navigate(Routes.PASTE) },
                    onManual = { nav.navigate(Routes.MANUAL) },
                )
            }
            composable(Routes.WORMHOLE_JOIN) {
                // Real broker-driven controller. Broker config
                // comes from SettingsStore so a custom broker takes
                // effect without a rebuild. On Succeeded with a
                // resultingTunnel ( payload received), the tunnel
                // is persisted before we navigate back.
                val scope = rememberCoroutineScope()
                val app = application as WgrtcApp
                val settings = app.settings.snapshot()
                val controller = remember(settings) {
                    WormholeJoinController(
                        brokerWss = settings.brokerWss,
                        brokerKey = settings.brokerKey,
                        parentScope = scope,
                        deviceName = android.os.Build.MODEL,
                    )
                }
                DisposableEffect(controller) {
                    onDispose { controller.dispose() }
                }
                val state by controller.state.collectAsState()
                WormholeJoinScreen(
                    state = state,
                    onEvent = { ev ->
                        when (ev) {
                            is com.gutschke.wgrtc.data.WormholeJoinUiEvent.CodeChanged ->
                                controller.onTyped(ev.typed)
                            com.gutschke.wgrtc.data.WormholeJoinUiEvent.Submit ->
                                controller.submit()
                            com.gutschke.wgrtc.data.WormholeJoinUiEvent.UserConfirm ->
                                controller.userConfirm()
                            com.gutschke.wgrtc.data.WormholeJoinUiEvent.Cancel ->
                                controller.cancel()
                            else -> {} // network-only events not produced by UI
                        }
                    },
                    onBack = { nav.popBackStack() },
                    onSucceeded = {
                        controller.resultingTunnel.value?.let { vm.addWormholeJoinedTunnel(it) }
                        nav.popBackStack(Routes.LIST, false)
                    },
                )
            }
            composable(Routes.WORMHOLE_HOST) { backStackEntry ->
                val tunnelId = backStackEntry.arguments?.getString("tunnelId").orEmpty()
                val scope = rememberCoroutineScope()
                val app = application as WgrtcApp
                val tunnels by vm.tunnels.collectAsState()
                val tunnel = tunnels.firstOrNull { it.id == tunnelId }
                // Pre-allocate the next free IP for this session.
                // The slot is uncommitted until SAS Succeeded fires
                // and we persist via vm.addWormholeEnrolledPeer.
                val snapshot = remember(tunnel) {
                    if (tunnel == null) null
                    else {
                        val hm = tunnel.hostMode ?: return@remember null
                        // Host's own IP comes from the configText's
                        // `[Interface] Address = a.b.c.d/N` line. We
                        // strip the CIDR suffix for the allocator API.
                        val addrLine = com.gutschke.wgrtc.data
                            .parseInterfaceField(tunnel.configText, "Address")
                            ?.substringBefore('/')
                            ?: return@remember null
                        val nextIp = com.gutschke.wgrtc.data.HostSubnetAllocator
                            .nextFreeIp(hm.subnet, addrLine,
                                com.gutschke.wgrtc.data.allocatedIps(tunnel))
                            ?: return@remember null
                        // V6.3 — allocate the v6 sibling when the
                        // tunnel has a subnetV6.  Soft-fail to v4
                        // only if the v6 alloc returns null.
                        val v6Cidr = hm.subnetV6?.let { sv6 ->
                            val v6Host = sv6.removeSuffix("/64") + "1"
                            com.gutschke.wgrtc.data.HostSubnetAllocator.nextFreeIpV6(
                                sv6, v6Host,
                                com.gutschke.wgrtc.data.allocatedIpsV6(tunnel),
                            )?.let { "$it/128" }
                        }
                        com.gutschke.wgrtc.data.buildHostTunnelSnapshot(
                            tunnel = tunnel,
                            assignedAddressCidr = "$nextIp/32",
                            assignedAddressV6Cidr = v6Cidr,
                        )
                    }
                }
                val code = remember { WormholeCode.generate() }
                // Use the host tunnel's broker if present (so the
                // post-enrollment OFFER traffic stays on the same
                // private broker), otherwise fall back to the
                // app-level default for first contact.
                val brokerWss = tunnel?.brokerWss ?: app.settings.defaultBrokerWss
                val brokerKey = tunnel?.brokerKey ?: app.settings.defaultBrokerKey
                val controller = remember(snapshot, brokerWss, brokerKey) {
                    WormholeHostController(
                        brokerWss = brokerWss,
                        brokerKey = brokerKey,
                        parentScope = scope,
                        code = code,
                        tunnelSnapshot = snapshot,
                    )
                }
                DisposableEffect(controller) {
                    controller.start()
                    onDispose { controller.dispose() }
                }
                val state by controller.state.collectAsState()
                WormholeHostScreen(
                    state = state,
                    onEvent = { ev ->
                        when (ev) {
                            com.gutschke.wgrtc.data.WormholeHostUiEvent.UserConfirm ->
                                controller.userConfirm()
                            com.gutschke.wgrtc.data.WormholeHostUiEvent.Cancel ->
                                controller.cancel()
                            else -> {}
                        }
                    },
                    onBack = { nav.popBackStack() },
                    onSucceeded = {
                        controller.wormholeResult.value?.let {
                            vm.addWormholeEnrolledPeer(it)
                        }
                        nav.popBackStack(Routes.LIST, false)
                    },
                )
            }
            composable(Routes.HOST_SETUP) {
                HostModeSetupScreen(
                    onBack = { nav.popBackStack() },
                    onCreated = { id ->
                        // Created — drop straight to the new tunnel's
                        // detail screen so the user can mint an
                        // enrollment QR.
                        nav.popBackStack(Routes.LIST, false)
                        nav.navigate(Routes.detail(id))
                    },
                    vm = vm,
                )
            }
            composable(Routes.PASTE) {
                PasteTunnelScreen(
                    onBack = { nav.popBackStack() },
                    onAdded = { nav.popBackStack(Routes.LIST, false) },
                    vm = vm,
                )
            }
            composable(Routes.SCAN) {
                ScanQrScreen(
                    onBack = { nav.popBackStack() },
                    onScanned = { scanned ->
                        if (scanned.startsWith("wgrtc-enroll://")) {
                            // Same UX as the URL handler: a wgrtc-enroll
                            // URI carries an authenticated single-use
                            // token, no further confirmation needed.
                            // Drop straight to the tunnel list while
                            // enrollment runs in the background.
                            handleIncomingUri(scanned)
                            nav.popBackStack(Routes.LIST, false)
                        } else {
                            // wg-quick paste — route to PasteTunnelScreen
                            // for confirmation (user can tweak the name,
                            // verify the decoded text).
                            vm.setPendingPaste(scanned)
                            nav.popBackStack(Routes.ADD, false)
                            nav.navigate(Routes.PASTE)
                        }
                    },
                )
            }
            composable(Routes.MANUAL) {
                ManualEntryScreen(
                    onBack = { nav.popBackStack() },
                    onAdded = { nav.popBackStack(Routes.LIST, false) },
                    vm = vm,
                )
            }
            composable(Routes.DETAIL) { backStackEntry ->
                val id = backStackEntry.arguments?.getString("tunnelId").orEmpty()
                TunnelDetailScreen(
                    tunnelId = id,
                    onBack = { nav.popBackStack() },
                    onMintWormholeCode = { nav.navigate(Routes.wormholeHost(id)) },
                    onEdit = { nav.navigate(Routes.edit(id)) },
                    onDiagnose = { nav.navigate(Routes.diagnostics(id)) },
                    vm = vm,
                )
            }
            composable(Routes.EDIT) { backStackEntry ->
                val id = backStackEntry.arguments?.getString("tunnelId").orEmpty()
                com.gutschke.wgrtc.ui.EditTunnelScreen(
                    tunnelId = id,
                    onBack = { nav.popBackStack() },
                    onSaved = { nav.popBackStack() },
                    vm = vm,
                )
            }
            composable(Routes.DIAGNOSTICS) { backStackEntry ->
                val id = backStackEntry.arguments?.getString("tunnelId").orEmpty()
                val tunnels by vm.tunnels.collectAsState()
                val tunnel = tunnels.firstOrNull { it.id == id }
                com.gutschke.wgrtc.ui.DiagnosticsScreen(
                    tunnel = tunnel,
                    onBack = { nav.popBackStack() },
                )
            }
        }
    }

    private fun requestConnect(tunnelId: String) {
        val consent = VpnService.prepare(this)
        if (consent != null) {
            pendingTunnelId = tunnelId
            consentLauncher.launch(consent)
        } else {
            connectAfterConsent(tunnelId)
        }
    }

    private fun connectAfterConsent(tunnelId: String) {
        lifecycleScope.launch {
            try {
                vm.connect(tunnelId)
            } catch (t: Throwable) {
                Log.e(TAG, "connect failed", t)
            }
        }
    }

    private fun requestDisconnect(tunnelId: String) {
        lifecycleScope.launch {
            vm.disconnect(tunnelId)
        }
    }

    companion object {
        const val TAG = "wgrtc"
    }
}
