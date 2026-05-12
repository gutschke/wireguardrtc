package com.gutschke.wgrtc.data

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.util.Log

/**
 * Step G of the candidate-negotiation v2 design — listens for Android
 * network changes and fires [onChange] whenever the underlying network
 * topology shifts (Wi-Fi joins/leaves, hotspot toggles, cellular
 * comes/goes, default route changes, link-properties updates).
 *
 * The receiving handler is expected to fire a force-wake at the
 * daemon (`ListenerHub.wake(id, force=true)`) so a fresh OFFER lands
 * before the user's next Connect/race attempt.
 *
 * The full design memo asks for the receiver to ALSO cancel any
 * in-flight `ConnectionRunner` race and re-run §1–§4 from scratch.
 * That's a meaningful piece of state machine that depends on
 * ConnectionRunner being mid-attempt at change time, so it's
 * deferred — the force-wake alone covers the common case where the
 * tunnel is already UP and a stale endpoint just needs refreshing.
 *
 * Cancellation safety: [stop] is idempotent. A monitor that's
 * already started ignores subsequent [start] calls. Both
 * register/unregister calls are wrapped in try/catch — Android
 * occasionally rejects a re-registered callback with
 * IllegalArgumentException, and a misbehaving monitor that crashes
 * the app on suspend/resume is worse than one that quietly stops
 * working.
 */
class NetworkChangeMonitor(
    private val context: Context,
    private val onChange: () -> Unit,
) {
    private val cm: ConnectivityManager? =
        context.getSystemService(Context.CONNECTIVITY_SERVICE)
            as? ConnectivityManager

    private val filteredCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            Log.d(TAG, "filtered.onAvailable: $network")
            onChange()
        }
        override fun onLost(network: Network) {
            Log.d(TAG, "filtered.onLost: $network")
            onChange()
        }
        override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) {
            Log.d(TAG, "filtered.onLinkPropertiesChanged: $network")
            onChange()
        }
        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
            // Capability changes (e.g., metered ↔ unmetered, validated ↔
            // not) don't usually alter routing topology, so we don't
            // wake on them. Documented here so future-me doesn't add
            // a noisy wake by mistake.
        }
    }

    // Why two callbacks: registerNetworkCallback(INTERNET) reliably
    // delivers full available/lost/linkProperties events for each
    // matching network — except when a VpnService is in front and the
    // OS silently switches the VPN's underlying transport (Wi-Fi ↔
    // cellular) without delivering an event on the filtered request.
    // Observed on Android phone: WiFi disabled, VPN auto-fell-back to
    // cellular, no onLost fired on the filtered callback for 3 minutes.
    // registerDefaultNetworkCallback DOES fire onCapabilitiesChanged
    // (with the new transport) on the default-network switchover —
    // we use that as a fallback signal.
    private val defaultCallback = object : ConnectivityManager.NetworkCallback() {
        @Volatile private var lastTransports: Int = -1
        override fun onAvailable(network: Network) {
            Log.d(TAG, "default.onAvailable: $network")
            onChange()
        }
        override fun onLost(network: Network) {
            Log.d(TAG, "default.onLost: $network")
            lastTransports = -1
            onChange()
        }
        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
            // Encode transports as a bitmask so we only fire when the
            // *transport* changes (Wi-Fi ↔ cellular). Sub-changes
            // (metered/validated/etc.) on the same transport don't
            // need a re-race.
            var mask = 0
            for (t in intArrayOf(
                NetworkCapabilities.TRANSPORT_WIFI,
                NetworkCapabilities.TRANSPORT_CELLULAR,
                NetworkCapabilities.TRANSPORT_ETHERNET,
                NetworkCapabilities.TRANSPORT_BLUETOOTH,
                NetworkCapabilities.TRANSPORT_VPN,
            )) {
                if (caps.hasTransport(t)) mask = mask or (1 shl t)
            }
            if (mask != lastTransports) {
                Log.d(TAG, "default.transports: $network (mask=0x${mask.toString(16)})")
                lastTransports = mask
                onChange()
            }
        }
    }

    @Volatile private var registered = false

    fun start() {
        if (registered || cm == null) return
        val req = NetworkRequest.Builder()
            // INTERNET-capable networks only — listening on every
            // network (including pipe-dream Bluetooth-PAN that the
            // OS surfaces but won't route) generates noise without
            // changing routing decisions.
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        try {
            cm.registerNetworkCallback(req, filteredCallback)
            cm.registerDefaultNetworkCallback(defaultCallback)
            registered = true
            Log.i(TAG, "network change monitor registered (filtered + default)")
        } catch (e: Throwable) {
            Log.w(TAG, "registerNetworkCallback failed", e)
            // If one succeeded and the other failed, unregister the
            // first so we don't leak callbacks across start/stop cycles.
            try { cm.unregisterNetworkCallback(filteredCallback) } catch (_: Throwable) {}
            try { cm.unregisterNetworkCallback(defaultCallback) } catch (_: Throwable) {}
        }
    }

    fun stop() {
        if (!registered || cm == null) return
        try { cm.unregisterNetworkCallback(filteredCallback) }
        catch (e: Throwable) {
            Log.w(TAG, "unregister filteredCallback failed (idempotent)", e)
        }
        try { cm.unregisterNetworkCallback(defaultCallback) }
        catch (e: Throwable) {
            Log.w(TAG, "unregister defaultCallback failed (idempotent)", e)
        }
        registered = false
    }

    private companion object { const val TAG = "wgrtc-netchange" }
}
