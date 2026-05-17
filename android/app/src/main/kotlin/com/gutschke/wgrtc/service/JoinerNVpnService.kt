package com.gutschke.wgrtc.service

import android.content.Intent
import android.net.VpnService
import android.os.Binder
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.util.Log
import com.gutschke.wgrtc.data.Cidr
import com.gutschke.wgrtc.data.JoinerNController
import com.gutschke.wgrtc.data.JoinerStackBackend
import com.gutschke.wgrtc.data.RealJoinerStackNative
import com.gutschke.wgrtc.data.TunFdProvider
import com.gutschke.wgrtc.data.WgBridgeNative
import com.gutschke.wgrtc.data.WgFdProtector
import com.gutschke.wgrtc.data.VpnServiceFdProtector
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking

/**
 * VpnService that lets N joiner tunnels share one kernel
 * TUN via the shared-stack architecture (`docs/cascade-n-design.md`).
 * Parallel to the legacy [JoinerVpnService] for the single-joiner
 * case; the two coexist while the production code path is gated
 * behind a settings flag.
 *
 * **Why a separate service**: the legacy `JoinerVpnService.start`
 * surface hands a `JoinerWgRunner` back to the caller (a per-tunnel
 * object). Joiner-N is fundamentally multi-tunnel — there is one
 * shared backend, one kernel TUN, and N joiner bridges sharing it.
 * Trying to graft that shape onto the legacy single-tunnel API
 * would mean every caller branches on N; cleaner to introduce a
 * new service whose surface is N-tunnel-shaped from the start.
 *
 * **Lifecycle**:
 *   1. Bind via [LocalBinder]; the caller (typically
 *      `WgrtcViewModel` once joiner-N is enabled) calls
 *      [addJoiner] / [removeJoiner] as user-visible tunnels go
 *      up/down.
 *   2. The first [addJoiner] triggers `Builder.establish()` and
 *      hands the resulting fd into [JoinerStackBackend].
 *   3. Subsequent add/remove operations REBUILD the TUN — Android
 *      tolerates back-to-back `Builder.establish()` calls; in-flight
 *      kernel TCP survives (D4.P3 proof).
 *   4. The last [removeJoiner] closes the stack and detaches the
 *      TUN. The service itself stays alive until the caller
 *      sends [ACTION_STOP] (or the system kills it).
 *
 * **NOT registered in AndroidManifest yet** — D4.J4 only adds the
 * Kotlin class. The manifest entry + ViewModel wiring lands with
 * the feature-flag activation step.
 */
class JoinerNVpnService : VpnService() {

    inner class LocalBinder : Binder() {
        fun getService(): JoinerNVpnService = this@JoinerNVpnService
    }

    private val binder = LocalBinder()
    private val backend: JoinerStackBackend = JoinerStackBackend(RealJoinerStackNative)
    private val tunProvider = BuilderTunFdProvider()
    /** Forwards revoke/failure signals from the controller +
     *  service callbacks into the process-wide [TunnelStateRegistry].
     *  See `docs/ux-design-v2.md` §6.1 — establish-null is the
     *  ground-truth signal; onRevoke and prepare-resync are the
     *  belt-and-suspenders coverage. */
    private val stateSink: com.gutschke.wgrtc.data.JoinerStateSink =
        object : com.gutschke.wgrtc.data.JoinerStateSink {
            override fun onRevoke(
                affected: Set<String>,
                reason: com.gutschke.wgrtc.data.PauseReason,
                note: String?,
            ) {
                val registry = com.gutschke.wgrtc.data.TunnelStateRegistry
                    .getProcessSingleton()
                for (id in affected) {
                    registry.recordRevoke(id, reason, note)
                }
            }
        }
    private val controller = JoinerNController(backend, tunProvider, stateSink)

    /** Most-recent VpnService TUN ParcelFileDescriptor. Held here
     *  so we can close it on teardown without racing the JoinerN
     *  controller's own fd ownership (the controller hands the
     *  detached int fd to the backend, which owns it; we keep the
     *  PFD for symmetry but don't close it directly — that's the
     *  backend's job). */
    @Volatile private var pfd: ParcelFileDescriptor? = null

    override fun onBind(intent: Intent?): IBinder? {
        // VpnService.SERVICE_INTERFACE bind is the system's
        // consent-prep flow; defer to the parent. LocalBinder is
        // for app-internal use.
        if (intent?.action == SERVICE_INTERFACE) return super.onBind(intent)
        return binder
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopAll()
            stopSelf()
            return Service.START_NOT_STICKY
        }
        return Service.START_STICKY
    }

    /** Active joiner-tunnel ids. */
    val activeJoinerIds: Set<String> get() = controller.activeJoinerIds

    /**
     * Add or replace a joiner tunnel. Triggers a Builder rebuild
     * if the joiner set changed. Throws on consent revocation or
     * shared-stack open failure.
     */
    @Throws(Exception::class)
    fun addJoiner(cfg: JoinerNController.JoinerConfig) {
        // Install the global protect callback BEFORE the bridge
        // opens its UDP socket — protect() needs to fire before
        // the socket binds, else the encrypted UDP gets caught by
        // the VPN's own AllowedIPs route (the classic PS11 storm).
        WgBridgeNative.installProtector(makeFdProtector())
        runBlocking(Dispatchers.IO) { controller.addJoiner(cfg) }
    }

    /** Remove a joiner. Triggers a rebuild on the surviving set,
     *  or full teardown when the set becomes empty. */
    @Throws(Exception::class)
    fun removeJoiner(tunnelId: String) {
        runBlocking(Dispatchers.IO) { controller.removeJoiner(tunnelId) }
    }

    /** Push fresh UAPI for one joiner without rebuilding. Used by
     *  the endpoint-roam path. */
    fun reconfigure(tunnelId: String, wgQuickUapi: String) {
        runBlocking(Dispatchers.IO) { controller.reconfigure(tunnelId, wgQuickUapi) }
    }

    /** Snapshot wireguard-go's current state for one joiner.  Null
     *  when no slot exists or the snapshot call returned null. */
    fun snapshotUapi(tunnelId: String): String? = controller.snapshotUapi(tunnelId)

    /** Same as [snapshotUapi] but parses the UAPI text into the
     *  structured [UapiStats] the throughput sampler consumes.  The
     *  legacy single-joiner runner has the same shape on the
     *  non-shared-stack path; the sampler reads via this method for
     *  joiner-N tunnels.  Returns null when no slot exists for
     *  [tunnelId] or the snapshot was empty. */
    fun snapshotStats(tunnelId: String): com.gutschke.wgrtc.data.UapiStats? {
        val raw = controller.snapshotUapi(tunnelId) ?: return null
        if (raw.isEmpty()) return null
        return com.gutschke.wgrtc.data.UapiStatsParser.parse(raw)
    }

    /** Full teardown — close every joiner, close the shared stack,
     *  detach the kernel TUN. Idempotent. */
    fun stopAll() {
        runBlocking(Dispatchers.IO) { controller.closeAll() }
        pfd?.let {
            try { it.close() } catch (_: Throwable) {}
        }
        pfd = null
        // Clear the process-global protector callback so a stale
        // lambda doesn't survive the service instance.  This isn't
        // a correctness issue today (the lambda just captures `this`
        // and the destroyed service's `protect()` is a no-op), but
        // leaving a dangling reference around a `VpnService` after
        // its `onDestroy` is the kind of bug review #3 flagged
        // pre-emptively.
        WgBridgeNative.installProtector(null)
    }

    /**
     * VpnService.onRevoke fires when another VPN app takes over
     * the system VPN slot.  Distinct from "user toggled VPN
     * permission off in Settings" (which is caught via
     * Builder.establish() returning null on the next connect —
     * see JoinerNController.rebuildLocked).  Both paths emit to
     * the registry; this one catches the cheap competitor-VPN case
     * without waiting for a reconnect attempt.
     *
     * Per `docs/ux-design-v2.md` §6.1 signal 2.
     */
    override fun onRevoke() {
        val affected = controller.activeJoinerIds
        stateSink.onRevoke(
            affected,
            com.gutschke.wgrtc.data.PauseReason.AnotherVpnTookOver,
            note = "VpnService.onRevoke() fired",
        )
        super.onRevoke()
    }

    override fun onDestroy() {
        stopAll()
        super.onDestroy()
    }

    private fun makeFdProtector(): WgFdProtector =
        VpnServiceFdProtector { fd -> protect(fd) }

    /**
     * Adapts `VpnService.Builder.establish()` to the
     * [TunFdProvider] interface the controller uses. Holds a
     * reference to the most-recently-returned PFD so [stopAll]
     * can close it; the controller still owns the detached int
     * fd's lifecycle via the shared stack.
     */
    private inner class BuilderTunFdProvider : TunFdProvider {
        override fun openTunFd(
            addresses: List<Cidr>,
            routes: List<Cidr>,
            mtu: Int,
            dnsServers: List<String>,
        ): Int {
            // Close the previous PFD before establishing a new
            // one — Android tolerates back-to-back establish()
            // calls but the old PFD lingers as an open fd until
            // GC otherwise, and we don't want that pile-up.
            pfd?.let { old ->
                try { old.close() } catch (_: Throwable) {}
            }
            pfd = null

            val builder = Builder()
                .setSession(SESSION_NAME)
                .setMtu(mtu)
            for (a in addresses) builder.addAddress(a.address, a.prefixLen)
            for (r in routes) builder.addRoute(r.address, r.prefixLen)
            // If the config has v6 addresses but only v4 DNS, append
            // a synthesized v6 DNS so Android's resolver stops
            // filtering AAAA records via AI_ADDRCONFIG.  See
            // [JoinerVpnConfig.dnsWithV6Fallback] for the
            // rationale.
            val effectiveDns = com.gutschke.wgrtc.data.JoinerVpnConfig.dnsWithV6Fallback(
                addresses, dnsServers)
            if (effectiveDns.size != dnsServers.size) {
                Log.i(TAG, "synthesized v6 DNS for dual-stack VPN " +
                    "(original=$dnsServers effective=$effectiveDns)")
            }
            for (d in effectiveDns) {
                try {
                    builder.addDnsServer(d)
                } catch (t: Throwable) {
                    // ChromeOS / unusual DNS strings can throw; the
                    // tunnel is still useful without per-VPN DNS so
                    // we log+continue rather than abort.
                    Log.w(TAG, "addDnsServer($d) refused: ${t.message}")
                }
            }
            val newPfd = builder.establish() ?: return -1
            pfd = newPfd
            // detachFd transfers ownership — the kernel TUN fd is
            // now the controller's / backend's responsibility.
            return newPfd.detachFd()
        }
    }

    companion object {
        private const val TAG = "JoinerNVpnService"
        private const val SESSION_NAME = "wgrtc-joiner-n"
        const val ACTION_STOP = "com.gutschke.wgrtc.joiner_n.STOP"
    }
}

// Re-export android.app.Service constants since we're outside the
// `android.app` package and using START_STICKY / START_NOT_STICKY
// from the inherited `VpnService` Lint can't always resolve them
// via the parent.  Fully-qualifying inline:
private typealias Service = android.app.Service
