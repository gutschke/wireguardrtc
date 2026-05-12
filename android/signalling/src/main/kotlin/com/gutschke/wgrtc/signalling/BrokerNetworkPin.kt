package com.gutschke.wgrtc.signalling

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities

/**
 * Defense-in-depth: provides a non-VPN [Network] that broker sockets
 * are pinned to. Protects against the (documented, but uncommon-in-
 * practice) VpnService per-uid routing trap.
 *
 * The trap: an app registered as a VpnService provider can have its
 * outbound traffic routed into `tun0` for any socket NOT bound to a
 * specific Network and NOT `VpnService.protect()`'d. When the WG
 * tunnel is DOWN, `tun0` doesn't exist and packets silently drop —
 * with `NetworkCallback.blockedStatus=false` (Android doesn't see it
 * as a block; the socket is just routed nowhere). Binding to a
 * non-VPN [Network] sidesteps this entirely because Android's per-uid
 * VPN-routing rule applies only to *unbound* sockets.
 *
 * Reality check: in the failure case we debugged extensively (Pixel
 * 9, Adaptive Battery / BPF-layer block — see
 * `docs/ANDROID_NETWORKING_INVESTIGATIONS.md`), this pin **did not**
 * help — the block was below the routing layer. We keep the pin
 * because (a) the trap is real on devices where it does fire, (b) the
 * fix is correct in principle, (c) the runtime cost is one
 * NetworkCallback registration per app lifetime. Don't expect this
 * to be the answer if you see "uid blocked outbound but Android says
 * not blocked" — start with the network-policy snapshot in
 * [com.gutschke.wgrtc.WgrtcApp.logNetworkPolicySnapshot] and the
 * investigation doc.
 *
 * Usage: call [register] from `Application.onCreate`, then okhttp
 * clients can pull [activeNonVpnNetwork]'s `socketFactory` for their
 * sockets. The Network auto-updates as the active default shifts
 * between WiFi and cellular.
 */
object BrokerNetworkPin {
    @Volatile private var active: Network? = null

    fun activeNonVpnNetwork(): Network? = active

    /** A [javax.net.SocketFactory] that re-reads [activeNonVpnNetwork]
     * at every `createSocket()` call. Use this for okhttp clients
     * built at process start, before the underlying NetworkCallback
     * has had a chance to fire its initial `onAvailable`. When the
     * pin is null at the moment of socket creation, falls through to
     * [javax.net.SocketFactory.getDefault] — same behavior as not
     * installing a custom factory at all. */
    val lazySocketFactory: javax.net.SocketFactory = object : javax.net.SocketFactory() {
        private fun current(): javax.net.SocketFactory =
            active?.socketFactory ?: getDefault()
        override fun createSocket(): java.net.Socket = current().createSocket()
        override fun createSocket(host: String, port: Int): java.net.Socket =
            current().createSocket(host, port)
        override fun createSocket(
            host: String, port: Int,
            localHost: java.net.InetAddress, localPort: Int,
        ): java.net.Socket = current().createSocket(host, port, localHost, localPort)
        override fun createSocket(host: java.net.InetAddress, port: Int): java.net.Socket =
            current().createSocket(host, port)
        override fun createSocket(
            address: java.net.InetAddress, port: Int,
            localAddress: java.net.InetAddress, localPort: Int,
        ): java.net.Socket = current().createSocket(address, port, localAddress, localPort)
    }

    /** Idempotent — safe to call multiple times. After registration,
     * [active] tracks Android's current non-VPN default. Survives
     * the process; we don't bother unregistering since we always
     * want a live binding for as long as the app exists. */
    fun register(context: Context) {
        try {
            val cm = context.getSystemService(ConnectivityManager::class.java) ?: return
            val req = android.net.NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()
            cm.registerDefaultNetworkCallback(
                object : ConnectivityManager.NetworkCallback() {
                    override fun onAvailable(network: Network) {
                        val caps = cm.getNetworkCapabilities(network)
                        // Only adopt the network if it really isn't a
                        // VPN (registerDefaultNetworkCallback can
                        // surface VPN networks if our app provides
                        // one). Untagged-VPN sockets hit the trap.
                        val isVpn = caps?.hasTransport(
                            NetworkCapabilities.TRANSPORT_VPN) == true
                        if (!isVpn) {
                            active = network
                            Log.i("wgrtc-net",
                                "broker network pin: $network " +
                                "(transports=" +
                                "${transportNames(caps)})")
                        }
                    }
                    override fun onLost(network: Network) {
                        if (active == network) {
                            active = null
                            Log.i("wgrtc-net",
                                "broker network pin: lost $network, " +
                                "no fallback yet")
                        }
                    }
                })
        } catch (t: Throwable) {
            Log.w("wgrtc-net",
                "BrokerNetworkPin.register failed: " +
                "${t.javaClass.simpleName}: ${t.message}")
        }
    }

    private fun transportNames(caps: NetworkCapabilities?): String {
        if (caps == null) return "none"
        val out = mutableListOf<String>()
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) out.add("WIFI")
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) out.add("CELLULAR")
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) out.add("VPN")
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) out.add("ETHERNET")
        return out.joinToString("|").ifEmpty { "?" }
    }
}
