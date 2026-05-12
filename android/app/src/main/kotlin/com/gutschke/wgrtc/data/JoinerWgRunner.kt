package com.gutschke.wgrtc.data

import java.util.concurrent.atomic.AtomicReference

/**
 * Joiner-mode runner: drives `wgbridge` in TUN-fd mode for tunnels
 * where this device is the WireGuard CLIENT. Parallel to
 * [HostModeBackend]; both sit on top of [WgBridgeBackend], differ
 * in which mode of `wgbridge.New` they call:
 *
 * - **Host mode** ([HostModeBackend]): `wgbridge.New` with a
 * userspace gvisor netstack — the bridge owns its own
 * TCP/UDP listeners.
 * - **Joiner mode** (this class): `wgbridge.NewWithTunFd` with a
 * kernel TUN file descriptor from
 * `VpnService.Builder.establish()`. No userspace listeners;
 * the kernel routes decrypted traffic.
 *
 * **Why this exists:** runs the cgo + //export `wgbridge_native`
 * surface in TUN-fd mode. See
 * `docs/wireguard-runtime-architecture.md` for the full design.
 *
 * **Lifecycle.** Single-shot — one [start] per instance; reconfigure
 * is in-place via [reconfigure]. Closing the runner closes the
 * underlying backend (which closes the wrapped TUN fd). No
 * pause/resume here because the close+recreate panic doesn't
 * apply to TUN-fd mode (the same Bridge serves the tunnel for its
 * entire VpnService lifetime; on disconnect we tear down the whole
 * VpnService anyway).
 *
 * Threading: `start` / `reconfigure` / `close` are NOT thread-safe
 * relative to each other; the caller (typically a foreground
 * service) should serialise them through one supervisor coroutine.
 */
class JoinerWgRunner(
    private val backendFactory: (fd: Int, mtu: Int) -> WgBridgeBackend,
    private val protector: WgFdProtector? = null,
) : AutoCloseable {

    private val backendRef = AtomicReference<WgBridgeBackend?>(null)

    val isRunning: Boolean
        get() = backendRef.get() != null

    /**
     * Open the bridge against [tunFd] and apply [wgQuickConfig].
     *
     * The fd's ownership transfers to the bridge: [close] closes
     * it. If [start] throws, the bridge is closed before the
     * exception propagates so we don't leak the wireguard-go
     * device.
     *
     * Throws `IllegalStateException` if already running — caller
     * must [close] first. Throws `IllegalArgumentException` from
     * [WgQuickUapi.render] if the wg-quick text is malformed.
     */
    @Throws(Exception::class)
    fun start(tunFd: Int, mtu: Int, wgQuickConfig: String) {
        check(backendRef.get() == null) { "joiner runner already started" }
        val uapi = WgQuickUapi.render(wgQuickConfig)
        // the protector MUST be installed via
        // WgBridgeNative.installProtector BEFORE the factory call
        // because wireguard-go's bind opens its UDP socket inside
        // wgbridgeNewWithTunFd. Production callers (JoinerVpnService)
        // do that registration before instantiating the runner;
        // setFdProtector below is the legacy post-open notification
        // that keeps the runner's contract symmetric (and pins the
        // FakeBackend test).
        val backend = backendFactory(tunFd, mtu)
        try {
            protector?.let { backend.setFdProtector(it) }
            backend.configureUapi(uapi)
        } catch (t: Throwable) {
            try { backend.close() } catch (_: Throwable) {}
            throw t
        }
        backendRef.set(backend)
    }

    /**
     * Push a fresh wg-quick config (e.g. user edited Endpoint, or
     * the OFFER listener rewrote a roamed endpoint) into the
     * running bridge. No-op if not running — caller handles the
     * "deferred until next Connect" case. Replaces the entire
     * peer set + allowed-IP list (`replace_peers=true /
     * replace_allowed_ips=true` in the rendered UAPI).
     */
    @Throws(Exception::class)
    fun reconfigure(wgQuickConfig: String) {
        val backend = backendRef.get()
            ?: throw IllegalStateException("joiner runner not started")
        backend.configureUapi(WgQuickUapi.render(wgQuickConfig))
    }

    /**
     * Snapshot of wireguard-go's current state, parsed into
     * [UapiStats] for the same UI hooks the host-mode path uses
     * (per-peer rx/tx, last-handshake epoch). Returns null when
     * the runner isn't running or when the snapshot returned
     * empty.
     */
    fun snapshotStats(): UapiStats? {
        val backend = backendRef.get() ?: return null
        val raw = try { backend.snapshotUapi() } catch (_: Throwable) { return null }
        if (raw.isEmpty()) return null
        return UapiStatsParser.parse(raw)
    }

    /** Idempotent shutdown. Closes the backend (and the wrapped
     * TUN fd) on first call; subsequent calls are no-ops. */
    override fun close() {
        backendRef.getAndSet(null)?.let {
            try { it.close() } catch (_: Throwable) {}
        }
    }
}
