package com.gutschke.wgrtc.data

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.util.Log
import com.gutschke.wgrtc.signalling.BrokerNetworkPin
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.SocketFactory

/**
 * Application-level network diagnostics: probes the app's outbound
 * reachability and Android's view of the uid's network policy at
 * startup, decides whether to surface a "network access blocked"
 * banner to the user.
 *
 * Background: when an app's TCP connect from its own uid times out
 * but the same connect works from `adb shell` (uid 2000), and every
 * documented Android API claims the uid isn't blocked, the most
 * likely cause is an eBPF-layer per-uid filter installed by Adaptive
 * Battery / App Standby — invisible to the public diagnostic
 * surfaces. See `docs/ANDROID_NETWORKING_INVESTIGATIONS.md` for the
 * full investigation that informed this code.
 *
 * Decision tree this implements:
 * - probe[unbound] succeeds → no broad block; banner stays hidden
 * - probe[unbound] fails, probe[bound] succeeds → VpnService routing
 * trap. Pin (already installed) handles okhttp; no banner
 * - both probes fail → confirmed broad block; show the recovery
 * banner with actionable Settings paths
 *
 * The probes target `1.1.1.1:443` because it's universally reachable
 * from any internet-connected network and never a configured peer
 * destination, so a probe failure unambiguously means "this app's
 * uid can't reach *anything*".
 */
class NetworkDiagnostics(private val context: Context) {

    /** True iff both probes failed. Single-signal failure isn't
     * surfaced to the UI — only both-fail. Observed from compose
     * to drive the recovery banner. */
    private val _broadBlockDetected = MutableStateFlow(false)
    val broadBlockDetected: StateFlow<Boolean> = _broadBlockDetected.asStateFlow()

    /** Snapshot what Android tells us about the active network and
     * this uid's policy state, then run paired bound/unbound probes
     * to compare against empirical reachability. Logs everything
     * to logcat (tag: `wgrtc-net`) for offline diagnosis. */
    fun runStartupSnapshot(scope: CoroutineScope) {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return
        registerBlockedStatusListener(cm)
        logSnapshot(cm)
        scope.launch(Dispatchers.IO) {
            // Wait briefly for BrokerNetworkPin's NetworkCallback to
            // settle if it hasn't yet.
            if (BrokerNetworkPin.activeNonVpnNetwork() == null) delay(500)
            val pin = BrokerNetworkPin.activeNonVpnNetwork()
            val unboundOk = probeOnce(null, "unbound")
            val boundOk = pin?.let { probeOnce(it, "bound:$it") }
            classify(unboundOk, boundOk)
        }
    }

    private fun classify(unboundOk: Boolean, boundOk: Boolean?) {
        when {
            boundOk == false -> {
                Log.w("wgrtc-net",
                    "BROAD BLOCK: even bound probe failed. " +
                    "App uid is blocked at a layer below routing — likely " +
                    "Adaptive Battery / BPF (see investigation doc).")
                _broadBlockDetected.value = true
            }
            unboundOk && boundOk == true -> {
                Log.i("wgrtc-net",
                    "no broad block: app uid reaches internet, " +
                    "both bound and unbound paths work")
            }
            unboundOk && boundOk == null -> {
                // Pin not yet available; trust the unbound result.
                Log.i("wgrtc-net",
                    "no broad block: app uid reaches internet (unbound)")
            }
            !unboundOk && boundOk == true -> {
                Log.i("wgrtc-net",
                    "VpnService routing trap detected: unbound socket " +
                    "is dropped, bound-to-Network works. " +
                    "BrokerNetworkPin handles broker traffic for this case.")
            }
            !unboundOk && boundOk == null -> {
                // Unbound failed and no pin to compare; ambiguous.
                // Don't surface a popup yet — could be transient.
                Log.w("wgrtc-net",
                    "unbound probe failed and no non-VPN Network was " +
                    "available to compare; cause indeterminate")
            }
        }
    }

    private fun probeOnce(network: Network?, label: String): Boolean = try {
        val started = System.currentTimeMillis()
        val factory: SocketFactory = network?.socketFactory ?: SocketFactory.getDefault()
        factory.createSocket().use { s ->
            s.connect(InetSocketAddress(PROBE_HOST, PROBE_PORT), PROBE_TIMEOUT_MS)
            Log.i("wgrtc-net",
                "probe[$label]: $PROBE_HOST:$PROBE_PORT connected in " +
                "${System.currentTimeMillis() - started}ms")
        }
        true
    } catch (e: Throwable) {
        Log.w("wgrtc-net",
            "probe[$label]: $PROBE_HOST:$PROBE_PORT failed: " +
            "${e.javaClass.simpleName}: ${e.message}")
        false
    }

    private fun logSnapshot(cm: ConnectivityManager) {
        try {
            val active = cm.activeNetwork
            val caps = active?.let { cm.getNetworkCapabilities(it) }
            val lp = active?.let { cm.getLinkProperties(it) }
            @Suppress("DEPRECATION")
            val procDefault = ConnectivityManager.getProcessDefaultNetwork()
            val bg = cm.restrictBackgroundStatus
            Log.i("wgrtc-net",
                "snapshot: activeNetwork=$active, " +
                "transports=${transportNames(caps)}, " +
                "iface=${lp?.interfaceName}, " +
                "metered=${cm.isActiveNetworkMetered}, " +
                "restrictBackgroundStatus=${bgStatusName(bg)} ($bg), " +
                "processDefaultNetwork=$procDefault")
        } catch (t: Throwable) {
            Log.w("wgrtc-net",
                "snapshot threw: ${t.javaClass.simpleName}: ${t.message}")
        }
    }

    private fun registerBlockedStatusListener(cm: ConnectivityManager) {
        try {
            val req = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .build()
            cm.registerNetworkCallback(req,
                object : ConnectivityManager.NetworkCallback() {
                    override fun onBlockedStatusChanged(
                        network: Network, blocked: Boolean,
                    ) {
                        Log.i("wgrtc-net",
                            "blockedStatus on $network: blocked=$blocked")
                    }
                    override fun onCapabilitiesChanged(
                        network: Network, caps: NetworkCapabilities,
                    ) {
                        Log.i("wgrtc-net",
                            "capabilities on $network: " +
                            "transports=${transportNames(caps)}, " +
                            "validated=${caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)}, " +
                            "notMetered=${caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)}, " +
                            "notRestricted=${caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)}")
                    }
                })
        } catch (t: Throwable) {
            Log.w("wgrtc-net",
                "registerBlockedStatusListener failed: " +
                "${t.javaClass.simpleName}: ${t.message}")
        }
    }

    companion object {
        private const val PROBE_HOST = "1.1.1.1"
        private const val PROBE_PORT = 443
        private const val PROBE_TIMEOUT_MS = 5_000

        internal fun transportNames(caps: NetworkCapabilities?): String {
            if (caps == null) return "none"
            val out = mutableListOf<String>()
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) out.add("WIFI")
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) out.add("CELLULAR")
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) out.add("VPN")
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) out.add("ETHERNET")
            return out.joinToString("|").ifEmpty { "?" }
        }

        internal fun bgStatusName(s: Int): String = when (s) {
            ConnectivityManager.RESTRICT_BACKGROUND_STATUS_DISABLED -> "DISABLED"
            ConnectivityManager.RESTRICT_BACKGROUND_STATUS_WHITELISTED -> "WHITELISTED"
            ConnectivityManager.RESTRICT_BACKGROUND_STATUS_ENABLED -> "ENABLED(restricted)"
            else -> "?"
        }
    }
}
