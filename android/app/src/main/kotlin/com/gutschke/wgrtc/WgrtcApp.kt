package com.gutschke.wgrtc

import android.app.Application
import android.net.ConnectivityManager
import android.util.Log
import androidx.core.content.ContextCompat
import com.gutschke.wgrtc.data.ConnectivityManagerNetworkRegistry
import com.gutschke.wgrtc.data.DnsProxy
import com.gutschke.wgrtc.data.EgressSelector
import com.gutschke.wgrtc.data.ListenerHub
import com.gutschke.wgrtc.data.HostModeBackend
import com.gutschke.wgrtc.data.NetworkDiagnostics
import com.gutschke.wgrtc.data.OsDnsResolver
import com.gutschke.wgrtc.data.RealWgBridgeBackendNative
import com.gutschke.wgrtc.data.SettingsStore
import com.gutschke.wgrtc.data.WgBridgeBackendFactory
import com.gutschke.wgrtc.signalling.BrokerNetworkPin
import com.gutschke.wgrtc.signalling.SignallingLogger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.StateFlow

/**
 * Application singleton. Lifetime-scopes the host backend +
 * [ListenerHub] so the OFFER listeners survive Activity destruction.
 */
class WgrtcApp : Application() {
    val listenerHub: ListenerHub by lazy { ListenerHub(this) }
    val settings: SettingsStore by lazy { SettingsStore.create(this) }

    /** Application-scoped supervisor for long-running background work
     * that doesn't belong to a particular ViewModel. Currently used
     * for the startup network diagnostic. */
    private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    /**
     * host backend. Lazy by design — instantiating
     * loads `libwgbridge_native.so`, the cgo + //export path
     * we ship as the only userspace WG runtime since .
     */
    val hostModeBackend: HostModeBackend by lazy {
        // egress selector reads the user's policy choice from
        // SettingsStore on every outbound NAT socket open, so the
        // user's "Wi-Fi only" / "Cellular only" toggle takes effect
        // for the next flow without restarting the tunnel.
        val cm = getSystemService(ConnectivityManager::class.java)
        val selector = cm?.let {
            EgressSelector(
                policyProvider = { settings.egressPolicy },
                networkRegistry = ConnectivityManagerNetworkRegistry(it),
            )
        }
        // UDP/53 short-circuits through OsDnsResolver so the
        // joiner's queries follow the phone's normal resolver chain
        // (DoH / private DNS / etc.) instead of egressing as raw
        // UDP to whatever the joiner thinks the DNS server is.
        val dnsProxy = DnsProxy(OsDnsResolver())
        HostModeBackend(
            factory = WgBridgeBackendFactory { localAddr, mtu, port ->
                RealWgBridgeBackendNative.open(localAddr, mtu, port)
            },
            parentScope = appScope,
            egressSelector = selector,
            dnsProxy = dnsProxy,
        )
    }

    private val diagnostics by lazy { NetworkDiagnostics(this) }

    /** True when the OS is broadly blocking this app's outbound
     * network access (probes confirm). Drives the user-visible
     * recovery banner in [com.gutschke.wgrtc.ui.TunnelListScreen]. */
    val networkBlockDetected: StateFlow<Boolean> get() = diagnostics.broadBlockDetected

    override fun onCreate() {
        super.onCreate()
        instance = this
        // Stamp the running build into logcat so we can tell at a
        // glance whether a freshly-installed APK has actually been
        // launched (Android does NOT auto-restart on package replace,
        // so a running process can outlive an "install -r" indefinitely).
        try {
            val pi = packageManager.getPackageInfo(packageName, 0)
            @Suppress("DEPRECATION")
            val vc = pi.longVersionCode
            Log.i("wgrtc-app",
                "starting wgrtc v${pi.versionName} (versionCode=$vc, pid=${android.os.Process.myPid()})")
        } catch (_: Throwable) {
            Log.i("wgrtc-app", "starting wgrtc (version lookup failed)")
        }
        // Wire signalling-module logging into android.util.Log. Must
        // happen before any signalling-module code runs.
        SignallingLogger.hook = SignallingLogger.Hook { p, t, m ->
            when (p) {
                4 -> Log.i(t, m)
                5 -> Log.w(t, m)
                6 -> Log.e(t, m)
            }
        }
        // Defense-in-depth pin against the VpnService per-uid routing
        // trap. See BrokerNetworkPin's doc for full rationale and
        // the case where it doesn't help.
        BrokerNetworkPin.register(this)
        // No startup JNI probe: the SIGSEGV class we used to chase
        // turned out to be gomobile-bind's marshalling, not a
        // dual-runtime conflict. deleted WgBridgeSmokeProbe;
        // the cgo-built libwgbridge_native.so is loaded lazily on
        // first use and doesn't need a startup ping.
        diagnostics.runStartupSnapshot(appScope)
        // Re-attach OFFER listeners for every ENROLL-source tunnel
        // we have on disk. Doing this here rather than in
        // WgrtcViewModel.init means the listeners survive activity
        // destruction. If at least one tunnel needs a listener, we
        // also start the foreground service so the OS keeps the
        // process alive while the user is in another app.
        listenerHub.reconcileFromStore()
        if (listenerHub.activeCount > 0) {
            ContextCompat.startForegroundService(
                this, OfferListenerService.startIntent(this))
        }
    }

    /** Convenience for callers (mostly the ViewModel) — start the
     * foreground service if there's at least one ENROLL tunnel. */
    fun ensureListenerServiceRunning() {
        if (listenerHub.activeCount > 0) {
            ContextCompat.startForegroundService(
                this, OfferListenerService.startIntent(this))
        }
    }

    companion object {
        @Volatile lateinit var instance: WgrtcApp
            private set
    }
}
