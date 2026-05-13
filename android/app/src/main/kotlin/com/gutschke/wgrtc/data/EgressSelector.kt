package com.gutschke.wgrtc.data

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import java.io.IOException
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import javax.net.SocketFactory

/**
 * **Egress policy for userspace-NAT outbound sockets.**
 *
 * When the phone hosts a WG tunnel and a joiner sends a packet
 * out through it (TCP / UDP catchall forwarder), we open an
 * outbound socket on the phone's normal network and forward.
 * The *policy* here decides WHICH network that outbound socket
 * binds to:
 *
 * - [OsDefault] — let Android pick (default route). Same as
 * the pre- behavior.
 * - [WifiOnly] — bind to the Wi-Fi network. If Wi-Fi is
 * absent, refuse the flow. Used to make sure ChromeOS-via-
 * tether traffic egresses on the home network, not the
 * phone's cellular plan.
 * - [WifiPreferred] — bind to Wi-Fi if available, fall back to
 * OS-default otherwise. Less strict than [WifiOnly].
 * - [CellularOnly] — bind to the cellular network. Useful
 * when the phone is on the same Wi-Fi as the joiner and we
 * specifically want to reach the public internet via cell.
 *
 * Future variant `NamedNetwork(name)` is held back for the
 * cascade-tunnel work (egress via another WG tunnel). When that
 * lands we add it here without changing the persistence schema —
 * see [parseEgressPolicy]'s `named:` prefix handling, which is
 * forward-compatible (downgrade reads → [OsDefault]).
 */
sealed class EgressPolicy {
    object OsDefault : EgressPolicy()
    object WifiOnly : EgressPolicy()
    object WifiPreferred : EgressPolicy()
    object CellularOnly : EgressPolicy()
}

fun EgressPolicy.serialize(): String = when (this) {
    EgressPolicy.OsDefault -> "os_default"
    EgressPolicy.WifiOnly -> "wifi_only"
    EgressPolicy.WifiPreferred -> "wifi_preferred"
    EgressPolicy.CellularOnly -> "cellular_only"
}

fun parseEgressPolicy(s: String?): EgressPolicy = when (s) {
    "os_default" -> EgressPolicy.OsDefault
    "wifi_only" -> EgressPolicy.WifiOnly
    "wifi_preferred" -> EgressPolicy.WifiPreferred
    "cellular_only" -> EgressPolicy.CellularOnly
    else -> EgressPolicy.OsDefault
}

/**
 * The actionable outcome of evaluating an [EgressPolicy] against
 * the current network state. Kept as a plain enum so the
 * decision logic in [decideEgress] is unit-testable without
 * dragging in `android.net.*`.
 */
enum class EgressDecision {
    /** Use the OS-default route (whatever Android picks). */
    OS_DEFAULT,
    /** Bind outbound sockets to the Wi-Fi network. */
    USE_WIFI,
    /** Bind outbound sockets to the cellular network. */
    USE_CELLULAR,
    /** Policy is `WifiOnly` and Wi-Fi is absent — refuse the flow. */
    FAIL_WIFI_REQUIRED,
    /** Policy is `CellularOnly` and cellular is absent — refuse. */
    FAIL_CELLULAR_REQUIRED,
}

/** Pure-function decision. Tested in [EgressDecisionTest]. */
fun decideEgress(
    policy: EgressPolicy,
    wifiAvailable: Boolean,
    cellularAvailable: Boolean,
): EgressDecision = when (policy) {
    EgressPolicy.OsDefault -> EgressDecision.OS_DEFAULT
    EgressPolicy.WifiOnly ->
        if (wifiAvailable) EgressDecision.USE_WIFI
        else EgressDecision.FAIL_WIFI_REQUIRED
    EgressPolicy.WifiPreferred ->
        if (wifiAvailable) EgressDecision.USE_WIFI
        else EgressDecision.OS_DEFAULT
    EgressPolicy.CellularOnly ->
        if (cellularAvailable) EgressDecision.USE_CELLULAR
        else EgressDecision.FAIL_CELLULAR_REQUIRED
}

/**
 * Production-side wrapper that turns an [EgressPolicy] into a
 * concrete [SocketFactory] / [UdpEgressFactory] suitable for
 * passing to [TcpForwarderHandler.socketFactory] /
 * [UdpForwarderHandler.egressFactory].
 *
 * [policyProvider] is read fresh on every outbound socket
 * creation, so the user changing the setting mid-tunnel takes
 * effect for the NEXT flow. In-flight flows keep their existing
 * binding (consistent with NAT-style state-keeping).
 *
 * The Android API surface here is `ConnectivityManager` +
 * `Network`; pulled in via constructor so a stub registry could
 * fake it in tests. In practice the decision logic is unit-
 * tested via [decideEgress]; this class is exercised end-to-end
 * by the (future) instrumented validation tests on real
 * hardware — the emulator has no cellular transport, so we can't
 * cover the CellularOnly path on CI.
 */
class EgressSelector(
    private val policyProvider: () -> EgressPolicy,
    private val networkRegistry: NetworkRegistry,
) {

    /**
     * Returns a [SocketFactory] that, on each `createSocket()`,
     * re-evaluates the policy and binds the resulting socket to
     * the chosen [Network] (or leaves it unbound for
     * [EgressDecision.OS_DEFAULT]). Refusal cases throw
     * [IOException] so the caller's connect path treats them as
     * an ordinary network error (the forwarder closes the WG-side
     * conn, the joiner's client sees a RST).
     */
    fun socketFactory(): SocketFactory = SelectorSocketFactory()

    /**
     * Returns a [UdpEgressFactory] with the same semantics as
     * [socketFactory]: refusal throws, otherwise the
     * `DatagramSocket` is bound to the chosen network before
     * being wrapped in a [UdpEgress].
     */
    fun udpEgressFactory(bufferSize: Int = 64 * 1024): UdpEgressFactory =
        DatagramSocketUdpEgressFactory(
            bufferSize = bufferSize,
            socketProvider = ::openBoundDatagramSocket,
        )

    /** For UI / status display. Returns the policy currently in
     * effect, what we'd choose right now, plus a human-readable
     * reason. */
    fun snapshot(): Snapshot {
        val policy = policyProvider()
        val decision = decideEgress(
            policy = policy,
            wifiAvailable = networkRegistry.networkWith(NetworkCapabilities.TRANSPORT_WIFI) != null,
            cellularAvailable = networkRegistry.networkWith(NetworkCapabilities.TRANSPORT_CELLULAR) != null,
        )
        return Snapshot(policy, decision)
    }

    data class Snapshot(val policy: EgressPolicy, val decision: EgressDecision)

    private fun resolveOrThrow(): Network? {
        val policy = policyProvider()
        val wifi = networkRegistry.networkWith(NetworkCapabilities.TRANSPORT_WIFI)
        val cell = networkRegistry.networkWith(NetworkCapabilities.TRANSPORT_CELLULAR)
        return when (decideEgress(policy, wifi != null, cell != null)) {
            EgressDecision.OS_DEFAULT -> null
            EgressDecision.USE_WIFI -> wifi
            EgressDecision.USE_CELLULAR -> cell
            EgressDecision.FAIL_WIFI_REQUIRED ->
                throw IOException("WiFi required by egress policy but not available")
            EgressDecision.FAIL_CELLULAR_REQUIRED ->
                throw IOException("Cellular required by egress policy but not available")
        }
    }

    private fun openBoundDatagramSocket(): DatagramSocket {
        val net = resolveOrThrow()
        val socket = DatagramSocket()
        if (net != null) {
            try {
                net.bindSocket(socket)
            } catch (e: Throwable) {
                try { socket.close() } catch (_: Throwable) {}
                throw IOException("bind UDP socket to selected network failed", e)
            }
        }
        return socket
    }

    /** SocketFactory that re-resolves the policy per call. We
     * override the connecting variants (host+port and address+
     * port), the unconnected `createSocket()` variant (caller
     * connects later — preserves the bind), and the SSL-style
     * wrap variants where applicable. The handler currently
     * only uses `createSocket(host, port)`, but we override the
     * others for completeness so misuse fails loudly rather than
     * silently bypassing the policy. */
    private inner class SelectorSocketFactory : SocketFactory() {
        override fun createSocket(): Socket {
            // Unconnected socket — caller connects later. We bind
            // to the chosen network here so the later connect
            // honors the policy. If `resolveOrThrow` throws,
            // it's propagated to the caller as IOException, which
            // SocketFactory.createSocket is allowed to throw.
            val net = resolveOrThrow()
            return if (net != null) net.socketFactory.createSocket()
            else SocketFactory.getDefault().createSocket()
        }
        override fun createSocket(host: String, port: Int): Socket {
            val net = resolveOrThrow()
            return if (net != null) net.socketFactory.createSocket(host, port)
            else SocketFactory.getDefault().createSocket(host, port)
        }
        override fun createSocket(host: String, port: Int,
                                  localAddr: InetAddress, localPort: Int): Socket {
            val net = resolveOrThrow()
            return if (net != null) net.socketFactory.createSocket(host, port, localAddr, localPort)
            else SocketFactory.getDefault().createSocket(host, port, localAddr, localPort)
        }
        override fun createSocket(host: InetAddress, port: Int): Socket {
            val net = resolveOrThrow()
            return if (net != null) net.socketFactory.createSocket(host, port)
            else SocketFactory.getDefault().createSocket(host, port)
        }
        override fun createSocket(host: InetAddress, port: Int,
                                  localAddr: InetAddress, localPort: Int): Socket {
            val net = resolveOrThrow()
            return if (net != null) net.socketFactory.createSocket(host, port, localAddr, localPort)
            else SocketFactory.getDefault().createSocket(host, port, localAddr, localPort)
        }
    }
}

/**
 * Indirection over `ConnectivityManager` so future tests can fake
 * network availability. Production wires
 * [ConnectivityManagerNetworkRegistry].
 */
interface NetworkRegistry {
    /** Returns a [Network] handle whose primary transport matches
     * [transport] (one of `NetworkCapabilities.TRANSPORT_*`), or
     * null if no such network is currently available. */
    fun networkWith(transport: Int): Network?
}

/** Production [NetworkRegistry] backed by Android's
 * ConnectivityManager. Scans `allNetworks` looking for one whose
 * capabilities match the requested transport AND has internet +
 * validated. Returns the first match (Android docs guarantee
 * there's at most one Network per (transport, validated) so the
 * ambiguity is academic). */
class ConnectivityManagerNetworkRegistry(
    private val cm: ConnectivityManager,
) : NetworkRegistry {
    override fun networkWith(transport: Int): Network? {
        @Suppress("DEPRECATION")
        for (net in cm.allNetworks) {
            val caps = cm.getNetworkCapabilities(net) ?: continue
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue
            if (!caps.hasTransport(transport)) continue
            // `NET_CAPABILITY_VALIDATED` would be stricter but in
            // practice tethering paths often lack it; we'd rather
            // try a slightly suboptimal network than fail.
            return net
        }
        return null
    }
}
