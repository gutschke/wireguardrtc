package com.gutschke.wgrtc.service

import android.app.Service
import android.content.Intent
import android.net.VpnService
import android.os.Binder
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.util.Log
import com.gutschke.wgrtc.data.JoinerEndpointReconfigurer
import com.gutschke.wgrtc.data.JoinerVpnConfig
import com.gutschke.wgrtc.data.JoinerWgRunner
import com.gutschke.wgrtc.data.RealWgBridgeBackendNative
import com.gutschke.wgrtc.data.UapiStats
import com.gutschke.wgrtc.data.VpnServiceFdProtector
import com.gutschke.wgrtc.data.WgFdProtector
import com.gutschke.wgrtc.data.asEndpointReconfigurer
import java.io.IOException

/**
 * Joiner-mode `VpnService`: parses a wg-quick config, calls
 * `Builder.addAddress / addRoute / setMtu / establish`, hands the
 * resulting TUN file descriptor to a [JoinerWgRunner], and lets
 * the runner drive wireguard-go via wgbridge_native's TUN-fd mode.
 *
 * **vs. [HostModeVpnService]:** that service doesn't call
 * `establish()` because host mode owns its cleartext side via a
 * userspace gvisor netstack; the VpnService is there only for
 * `protect()`. Joiner mode actually wants the kernel TUN.
 *
 * Lifecycle / IPC: the controller (typically `WgrtcViewModel`)
 * binds to this service via the [LocalBinder], calls [start], and
 * later calls [stop]. Standard one-VpnService-at-a-time semantics
 * — Android won't let two coexist.
 */
class JoinerVpnService : VpnService() {

    inner class LocalBinder : Binder() {
        fun getService(): JoinerVpnService = this@JoinerVpnService
    }

    private val binder = LocalBinder()
    @Volatile private var pfd: ParcelFileDescriptor? = null
    @Volatile private var runner: JoinerWgRunner? = null

    override fun onBind(intent: Intent?): IBinder? {
        // VpnService.SERVICE_INTERFACE is what the system uses to
        // bind this to the VPN-permission-grant flow; defer to the
        // parent for that. Our LocalBinder is for app-internal
        // use only.
        if (intent?.action == SERVICE_INTERFACE) return super.onBind(intent)
        return binder
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Bind-only service — nothing to do on startCommand. The
        // controller drives lifecycle through [start] / [stop] on
        // the bound LocalBinder.
        if (intent?.action == ACTION_STOP) {
            stop()
            stopSelf()
            return Service.START_NOT_STICKY
        }
        return Service.START_STICKY
    }

    /**
     * Build a TUN per [config], hand the fd to a fresh
     * [JoinerWgRunner], and apply the wg-quick config via UAPI.
     *
     * Returns a [JoinerEndpointReconfigurer] view of the live
     * runner — the controller uses this to issue endpoint updates
     * during the candidate race + read stats. Throws
     * [IllegalStateException] if a tunnel is already running on
     * this service instance (only one joiner tunnel at a time —
     * Android's VpnService lifecycle is singular anyway).
     */
    @Throws(Exception::class)
    fun start(config: JoinerVpnConfig, wgQuickText: String): JoinerEndpointReconfigurer {
        check(runner == null) { "another joiner tunnel is already running" }
        val builder = Builder()
            .setSession(SESSION_NAME)
            .setMtu(config.mtu)
        for (a in config.addresses) builder.addAddress(a.address, a.prefixLen)
        for (r in config.routes) builder.addRoute(r.address, r.prefixLen)
        // push the wg-quick `DNS = …` line(s) into the VPN
        // namespace via `addDnsServer`. Without this, ChromeOS (and any
        // OS that doesn't auto-discover DNS through a VPN) leaves the
        // resolver pointing at whatever the underlying network gave it,
        // which the VpnService then masks — name lookups silently fail
        // even though TCP/UDP/ICMP to literal addresses ride the tunnel
        // fine. Host advertises its WG-side IP as DNS (see
        // [buildHostTunnelSnapshot]); UDP/53 to that IP is intercepted
        // by the host's gvisor catchall and routed to [DnsProxy].
        for (d in config.dnsServers) {
            try {
                builder.addDnsServer(d)
            } catch (t: Throwable) {
                Log.w("wgrtc-joiner", "addDnsServer($d) refused: ${t.message}")
            }
        }
        val pfd = builder.establish()
            ?: throw IOException("VpnService.Builder.establish() returned null " +
                "— probably the user revoked VPN permission")
        this.pfd = pfd
        // detachFd transfers ownership: ParcelFileDescriptor stops
        // tracking the fd and the caller (wgbridge) is responsible
        // for closing it. Important: closing pfd on the JVM side
        // would race wireguard-go's own close.
        val fd = pfd.detachFd()
        // install the protector BEFORE the bridge opens — that
        // way wireguard-go's bind, which is created inside
        // RealWgBridgeBackendNative.openWithTunFd, sees the protector
        // when it calls back through WgBridgeNative.protectFd and
        // routes its UDP socket via VpnService.protect(fd) instead
        // of letting it be captured by the VPN's own AllowedIPs.
        val protector = makeFdProtector()
        com.gutschke.wgrtc.data.WgBridgeNative.installProtector(protector)
        // Joiner mode uses the cgo + //export libwgbridge_native.so
        // — validated end-to-end by WgBridgeNativeHandshakeTest on
        // the emulator + a Android phone spot-check.
        val r = JoinerWgRunner(
            backendFactory = { tunFd, mtu -> RealWgBridgeBackendNative.openWithTunFd(tunFd, mtu) },
            protector = protector,
        )
        try {
            r.start(fd, config.mtu, wgQuickText)
        } catch (t: Throwable) {
            try { r.close() } catch (_: Throwable) {}
            try { pfd.close() } catch (_: Throwable) {}
            this.pfd = null
            throw t
        }
        runner = r
        Log.i(TAG, "joiner tunnel up; mtu=${config.mtu} addrs=${config.addresses.size}")
        return r.asEndpointReconfigurer()
    }

    /** Tear down the joiner tunnel. Idempotent. */
    fun stop() {
        runner?.let {
            try { it.close() } catch (t: Throwable) {
                Log.w(TAG, "closing JoinerWgRunner failed", t)
            }
        }
        runner = null
        pfd?.let {
            try { it.close() } catch (_: Throwable) {}
        }
        pfd = null
    }

    /** Snapshot stats from the live runner. Returns null when
     * no tunnel is up. */
    fun snapshotStats(): UapiStats? = runner?.snapshotStats()

    /**
     * Re-issue the full UAPI in response to an OFFER-listener
     * roam. The new wg-quick replaces the live config in-place
     * (no DOWN+UP cycle — wireguard-go IpcSet handles
     * `replace_peers=true` / `replace_allowed_ips=true`). No-op
     * when no tunnel is up.
     */
    fun reconfigure(wgQuickText: String) {
        runner?.reconfigure(wgQuickText)
    }

    /**
     * Establish a TUN per [config] and return the
     * `ParcelFileDescriptor` to the caller — *without* starting
     * a [JoinerWgRunner] / configuring wireguard-go. Used by
     * the native-bridge handshake test
     * ([WgBridgeNativeHandshakeTest]) so it can pipe the fd into
     * `WgBridgeNative.nativeNewWithTunFd` instead of the
     * gomobile path.
     *
     * Visible-for-test only: production code uses [start].
     */
    fun establishTunForTest(config: JoinerVpnConfig): ParcelFileDescriptor? {
        val builder = Builder()
            .setSession(SESSION_NAME)
            .setMtu(config.mtu)
        for (a in config.addresses) builder.addAddress(a.address, a.prefixLen)
        for (r in config.routes) builder.addRoute(r.address, r.prefixLen)
        return builder.establish()
    }

    private fun makeFdProtector(): WgFdProtector =
        VpnServiceFdProtector { fd -> protect(fd) }

    override fun onDestroy() {
        stop()
        super.onDestroy()
    }

    companion object {
        private const val TAG = "JoinerVpnService"
        private const val SESSION_NAME = "wgrtc-joiner"
        const val ACTION_STOP = "com.gutschke.wgrtc.joiner.STOP"
    }
}
