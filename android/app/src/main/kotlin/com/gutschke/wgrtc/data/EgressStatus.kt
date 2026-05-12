package com.gutschke.wgrtc.data

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.telephony.TelephonyManager

/**
 * **Live snapshot of the phone's networks for the egress UI.**
 *
 * Built lean: just enough info for the "Currently: Wi-Fi" status
 * line under the egress-policy radio buttons + the cellular-radio
 * enabled-state gate. No reactive plumbing here — see
 * [EgressLiveStatusObserver] for the callback-driven Compose
 * wrapper.
 */
data class EgressLiveStatus(
    /** Wi-Fi network is registered + has INTERNET capability. */
    val wifiAvailable: Boolean,
    /** Cellular network is registered + has INTERNET capability. */
    val cellularAvailable: Boolean,
    /** Human-readable label for the Wi-Fi network — usually the
     * link-local IP (e.g. "192.168.1.42") because Android
     * hides the SSID without ACCESS_FINE_LOCATION. */
    val wifiLabel: String? = null,
    /** Human-readable label for the cellular network — usually
     * the carrier name from `TelephonyManager`. */
    val cellularLabel: String? = null,
) {
    companion object {

        /** One-shot snapshot. Reads [ConnectivityManager.getAllNetworks]
         * (deprecated on API 31+ but still the only way to enumerate
         * on-device transports cheaply without a registered callback). */
        @Suppress("DEPRECATION")
        fun snapshot(context: Context): EgressLiveStatus {
            val cm = context.getSystemService(ConnectivityManager::class.java)
                ?: return EgressLiveStatus(false, false)
            val tm = context.getSystemService(TelephonyManager::class.java)
            var wifi = false
            var cell = false
            var wifiLabel: String? = null
            var cellLabel: String? = null
            for (net in cm.allNetworks) {
                val caps = cm.getNetworkCapabilities(net) ?: continue
                if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                    wifi = true
                    wifiLabel = wifiLabel ?: describeLink(cm.getLinkProperties(net))
                }
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
                    cell = true
                    cellLabel = cellLabel ?: describeCellular(tm)
                }
            }
            return EgressLiveStatus(wifi, cell, wifiLabel, cellLabel)
        }

        private fun describeLink(lp: LinkProperties?): String? {
            if (lp == null) return null
            // First non-link-local v4 if present, else first v6.
            val addrs = lp.linkAddresses.map { it.address }
            val v4 = addrs.firstOrNull { it is java.net.Inet4Address }
            if (v4 != null) return v4.hostAddress
            val v6 = addrs.firstOrNull()
            return v6?.hostAddress
        }

        private fun describeCellular(tm: TelephonyManager?): String? {
            if (tm == null) return null
            val name = tm.networkOperatorName ?: ""
            return if (name.isBlank()) null else name
        }
    }
}

/**
 * Network-callback-driven observer for [EgressLiveStatus].
 * Designed to be used as the source for a Compose `produceState`
 * or coroutine flow — register on `onActive`, unregister on
 * `onDispose`.
 *
 * Lean by design: each callback recomputes the full snapshot
 * instead of doing incremental updates. Cheap relative to the
 * UI work that follows.
 */
class EgressLiveStatusObserver(private val context: Context) {

    fun interface Listener {
        fun onStatusChanged(status: EgressLiveStatus)
    }

    private val cm: ConnectivityManager? =
        context.getSystemService(ConnectivityManager::class.java)
    private var callback: ConnectivityManager.NetworkCallback? = null

    fun start(listener: Listener) {
        val mgr = cm ?: return
        // Push the initial state synchronously so the UI doesn't
        // have to wait for the first network change.
        listener.onStatusChanged(EgressLiveStatus.snapshot(context))
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) =
                listener.onStatusChanged(EgressLiveStatus.snapshot(context))
            override fun onLost(network: Network) =
                listener.onStatusChanged(EgressLiveStatus.snapshot(context))
            override fun onCapabilitiesChanged(
                network: Network, networkCapabilities: NetworkCapabilities,
            ) = listener.onStatusChanged(EgressLiveStatus.snapshot(context))
        }
        val req = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        try {
            mgr.registerNetworkCallback(req, cb)
            callback = cb
        } catch (_: Throwable) {
            // Swallow — UI just won't auto-refresh, which is fine.
        }
    }

    fun stop() {
        val cb = callback ?: return
        try { cm?.unregisterNetworkCallback(cb) } catch (_: Throwable) {}
        callback = null
    }
}
