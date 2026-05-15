package com.gutschke.wgrtc.data

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * high-level orchestrator that drives [JoinerStackBackend]
 * across the active joiner-tunnel set. Bridges the shared-stack
 * Kotlin layer to Android's `VpnService.Builder.establish()`
 * lifecycle.
 *
 * **Behavior**:
 *
 *  - Holds the current set of active joiner configs keyed by
 *    tunnel id.
 *  - On every [addJoiner] / [removeJoiner] call, rebuilds the
 *    union of (addresses, routes, mtu floor), tears down the
 *    existing shared stack (which closes the existing kernel TUN
 *    fd and stops the pump), asks the injected [TunFdProvider]
 *    for a fresh fd against the union, and reopens every joiner
 *    on the new stack.
 *  - Apps' kernel TCP sockets survive the swap as long as their
 *    source addresses + routes stay in the new union
 *    confirmed the kernel-level behavior. wg-go handshake state
 *    does NOT survive (each rebuild reopens all bridges); the
 *    next handshake retransmit cycles bring tunnels back up
 *    within a few seconds.
 *
 * **Why no debounce yet**: the design doc proposes a 200 ms
 * coalesce window for rapid add/remove. Skipped for the first
 * cut — rebuild on every call is correct, just wasteful for the
 * "user taps Add three times" pathological case. Add as a small
 * follow-up once the UI flow lands.
 *
 * **Threading**: every method is `suspend` and serialized by
 * [mu]. The underlying backend's JNI calls already dispatch via
 * `Dispatchers.IO`; this class only adds orchestration above it.
 */
class JoinerNController(
    private val backend: JoinerStackBackend,
    private val tunFdProvider: TunFdProvider,
) {
    /** Per-joiner configuration the caller hands us.  Mirrors the
     *  fields the controller pulls from the wg-quick text +
     *  computed UAPI. */
    data class JoinerConfig(
        val tunnelId: String,
        val addresses: List<Cidr>,
        val routes: List<Cidr>,
        val mtu: Int,
        val wgQuickUapi: String,
        val dnsServers: List<String> = emptyList(),
    )

    private val mu = Mutex()
    // Mutable snapshot of the currently-active configs.  Reads
    // under [mu] only; concurrent readers see a coherent view of
    // either pre- or post-rebuild state.
    private val active = mutableMapOf<String, JoinerConfig>()

    /** Snapshot of currently-active joiner tunnel ids. */
    val activeJoinerIds: Set<String> get() = synchronized(active) { active.keys.toSet() }

    /** Number of currently-active joiners. */
    val activeJoinerCount: Int get() = synchronized(active) { active.size }

    /**
     * Add or replace the joiner with id [cfg.tunnelId]. Triggers a
     * full Builder.establish() rebuild against the new union of
     * routes + addresses. Throws [JoinerNException] if the
     * underlying TUN build fails or the shared stack can't be
     * brought up.
     */
    @Throws(JoinerNException::class)
    suspend fun addJoiner(cfg: JoinerConfig) {
        mu.withLock {
            val snapshot = synchronized(active) { active.toMap() } + (cfg.tunnelId to cfg)
            try {
                rebuildLocked(snapshot.values.toList())
            } catch (t: Throwable) {
                // rebuildLocked left the underlying stack closed —
                // mirror that in our local view so activeJoinerIds
                // doesn't lie about what's actually running.
                synchronized(active) { active.clear() }
                throw t
            }
            synchronized(active) {
                active.clear()
                active.putAll(snapshot)
            }
        }
    }

    /**
     * Remove the joiner with [tunnelId]. Triggers a full rebuild
     * against the remaining set, or tears the whole stack down if
     * the set becomes empty. Silent no-op when the id isn't
     * active.
     */
    @Throws(JoinerNException::class)
    suspend fun removeJoiner(tunnelId: String) {
        mu.withLock {
            val current = synchronized(active) { active.toMap() }
            if (tunnelId !in current) return
            val remaining = current.filterKeys { it != tunnelId }
            if (remaining.isEmpty()) {
                backend.closeAll()
                synchronized(active) { active.clear() }
                return
            }
            try {
                rebuildLocked(remaining.values.toList())
            } catch (t: Throwable) {
                synchronized(active) { active.clear() }
                throw t
            }
            synchronized(active) {
                active.clear()
                active.putAll(remaining)
            }
        }
    }

    /** Full shutdown — closes the shared stack, drops every active
     *  joiner.  Used on app exit / VpnService.onDestroy. */
    suspend fun closeAll() {
        mu.withLock {
            backend.closeAll()
            synchronized(active) { active.clear() }
        }
    }

    /** Re-issue UAPI for one joiner without a full rebuild.  Used
     *  by the candidate-race / endpoint-roam path that pushes a
     *  new `[Peer] Endpoint = ...` without changing routes.
     *
     *  Serialized through [mu] so that a `closeJoiner` /
     *  `closeAll` racing against the JNI configureUapi call can't
     *  free the bridge handle out from under us.  An earlier
     *  draft skipped the lock to allow concurrent roams during
     *  a rebuild, but review #4 caught the handle-reuse hazard.
     */
    suspend fun reconfigure(tunnelId: String, wgQuickUapi: String) {
        mu.withLock {
            val existing = synchronized(active) { active[tunnelId] } ?: return
            backend.reconfigure(tunnelId, wgQuickUapi)
            // Update the cached UAPI so the next rebuild uses it.
            synchronized(active) {
                if (active.containsKey(tunnelId)) {
                    active[tunnelId] = existing.copy(wgQuickUapi = wgQuickUapi)
                }
            }
        }
    }

    /** Snapshot wg-go state for [tunnelId] via the backend.  Null
     *  when no slot exists. */
    fun snapshotUapi(tunnelId: String): String? = backend.snapshotUapi(tunnelId)

    /**
     * Tear down the existing shared stack (if any), build a fresh
     * VpnService TUN against the union of [configs], bind it, and
     * reopen every joiner on the new stack.  All-or-nothing: any
     * error along the way leaves the controller in a fully closed
     * state.
     */
    private suspend fun rebuildLocked(configs: List<JoinerConfig>) {
        // Close any existing stack first.  If the caller is
        // calling for the first time, this is a no-op.
        backend.closeAll()
        if (configs.isEmpty()) return
        val addrs = configs.flatMap { it.addresses }.distinct()
        val routes = configs.flatMap { it.routes }.distinct()
        val mtu = configs.minOf { it.mtu }
        val dns = configs.flatMap { it.dnsServers }.distinct()
        val fd = try {
            tunFdProvider.openTunFd(
                addresses = addrs,
                routes = routes,
                mtu = mtu,
                dnsServers = dns,
            )
        } catch (t: Throwable) {
            throw JoinerNException("VpnService.Builder.establish failed: ${t.message}", t)
        }
        if (fd < 0) {
            throw JoinerNException(
                "VpnService.Builder.establish returned no fd " +
                "(consent revoked?)")
        }
        try {
            backend.bindKernelTun(fd, mtu)
        } catch (t: Throwable) {
            // bindKernelTun's error path closes the fd via the
            // shared-stack teardown.  Don't try to close again
            // here — risks double-close.
            throw JoinerNException("bindKernelTun failed: ${t.message}", t)
        }
        // Open each joiner; on first error, tear the whole
        // stack down so the caller doesn't see a half-built state.
        try {
            for (cfg in configs) {
                backend.openJoiner(
                    tunnelId = cfg.tunnelId,
                    peerAllowed = cfg.routes.map { "${it.address}/${it.prefixLen}" },
                    interfaceAddrs = cfg.addresses.map { "${it.address}/${it.prefixLen}" },
                    mtu = cfg.mtu,
                    wgQuickUapi = cfg.wgQuickUapi,
                )
            }
        } catch (t: Throwable) {
            backend.closeAll()
            throw JoinerNException("openJoiner failed: ${t.message}", t)
        }
    }
}

/** Typed exception for joiner-N controller failures. */
class JoinerNException(msg: String, cause: Throwable? = null) :
    RuntimeException(msg, cause)

/**
 * Abstraction over `VpnService.Builder.establish()` so the
 * controller can be tested without the Android framework.
 * Production wires this to a `VpnService.Builder` inside the
 * `JoinerNVpnService`; tests use an in-process fake that returns
 * pipe/socketpair fds.
 */
interface TunFdProvider {
    /**
     * Build a TUN with [addresses] + [routes] + [mtu] +
     * [dnsServers] applied, call `establish()`, and return the
     * detached fd.  Negative return signals "no fd available"
     * (typically VPN consent revoked).  Throws any underlying
     * `Builder` error verbatim — the controller wraps it.
     */
    fun openTunFd(
        addresses: List<Cidr>,
        routes: List<Cidr>,
        mtu: Int,
        dnsServers: List<String>,
    ): Int
}
