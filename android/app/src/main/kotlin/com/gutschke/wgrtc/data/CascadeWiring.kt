package com.gutschke.wgrtc.data

import android.util.Log
import com.gutschke.wgrtc.signalling.parseAllowedIps

/**
 * Process-singleton observer that bridges the joiner-N and
 * host-mode backends' lifecycle events to the wgbridge_native
 * cascade ferry registry.
 *
 * **Why this exists**: CASCADE-2 introduces a userspace
 * forwarding bridge between the two gvisor netstacks (one per
 * backend) so traffic decrypted by a host-mode tunnel can be
 * re-encrypted and sent out through a joiner-mode tunnel.  The
 * native-side registry maintains the (host bridge ↔ joiner
 * stack) wiring; this Kotlin class translates Android lifecycle
 * events into native calls.
 *
 * **Feature-gated by [SettingsStore.cascadeEnabled].**  When the
 * flag is off, every event is a no-op — the registry stays
 * empty and cascade traffic falls through to whatever non-cascade
 * routing the stacks have (typically the host's catchall).
 *
 * **Thread model**: all methods are synchronous and acquire
 * [mu] before touching state or making JNI calls.  Backends may
 * call from any thread.
 *
 * Concrete lifecycle wiring:
 *   - [JoinerStackBackend] calls [onJoinerStackUp] /
 *     [onJoinerStackDown] / [onJoinerAllowedIpsChanged].
 *   - [HostModeBackend] calls [onHostBridgeUp] /
 *     [onHostBridgeDown].
 *
 * Idempotent: the wiring tracks "have we already registered X
 * with the native side" and skips duplicate calls.
 */
object CascadeWiring {

    private const val TAG = "wgrtc-cascade"

    private val mu = Object()

    @Volatile private var enabled: Boolean = false

    /** Seam for tests — production delegates to [WgBridgeNative]
     *  (`RealBridge`); JVM tests inject a fake to avoid touching
     *  the .so. */
    interface Bridge {
        fun registerJoiner(stackHandle: Int, allowedIpsCsv: String?): Int
        fun unregisterJoiner()
        fun joinerAllowedIpsChanged(allowedIpsCsv: String?): Int
        fun joinerInterfaceAddrsChanged(addrsCsv: String?): Int
        fun registerHostBridge(bridgeHandle: Int, peerSubnetsCsv: String?): Int
        fun unregisterHostBridge(bridgeHandle: Int)
    }

    /** Production bridge — delegates to [WgBridgeNative]. */
    object RealBridge : Bridge {
        override fun registerJoiner(stackHandle: Int, allowedIpsCsv: String?): Int =
            WgBridgeNative.nativeCascadeRegisterJoiner(stackHandle, allowedIpsCsv)
        override fun unregisterJoiner() {
            WgBridgeNative.nativeCascadeUnregisterJoiner()
        }
        override fun joinerAllowedIpsChanged(allowedIpsCsv: String?): Int =
            WgBridgeNative.nativeCascadeOnAllowedIPsChanged(allowedIpsCsv)
        override fun joinerInterfaceAddrsChanged(addrsCsv: String?): Int =
            WgBridgeNative.nativeCascadeOnJoinerInterfaceAddrsChanged(addrsCsv)
        override fun registerHostBridge(bridgeHandle: Int, peerSubnetsCsv: String?): Int =
            WgBridgeNative.nativeCascadeRegisterHostBridge(bridgeHandle, peerSubnetsCsv)
        override fun unregisterHostBridge(bridgeHandle: Int) {
            WgBridgeNative.nativeCascadeUnregisterHostBridge(bridgeHandle)
        }
    }

    @Volatile private var bridge: Bridge = RealBridge

    /** Active joiner-N stack handle (null = none up). */
    private var joinerStackHandle: Int? = null
    /** Union of every active joiner peer's AllowedIPs. */
    private var joinerAllowedIps: Set<String> = emptySet()

    /** Host bridges currently registered with the registry,
     *  keyed by native bridge handle. */
    private val hostBridges = mutableMapOf<Int, Set<String>>()

    /**
     * Set by [SettingsStore].  When off, all on* hooks are no-ops
     * AND any currently-registered state is torn down.
     */
    fun setEnabled(value: Boolean) {
        synchronized(mu) {
            if (value == enabled) return
            enabled = value
            if (!value) {
                // Flag flipped off — tear down everything we have
                // registered with the native side.
                for (handle in hostBridges.keys.toList()) {
                    runCatching { bridge.unregisterHostBridge(handle) }
                }
                hostBridges.clear()
                if (joinerStackHandle != null) {
                    runCatching { bridge.unregisterJoiner() }
                    joinerStackHandle = null
                    joinerAllowedIps = emptySet()
                }
                Log.i(TAG, "cascade disabled; all native state torn down")
            } else {
                Log.i(TAG, "cascade enabled; awaiting backend lifecycle events")
            }
        }
    }

    /** Snapshot of the current flag for callers that want to gate
     *  their behaviour at the call site. */
    fun isEnabled(): Boolean = enabled

    fun onJoinerStackUp(stackHandle: Int, allowedIpsCsv: String) {
        synchronized(mu) {
            if (!enabled) return
            joinerStackHandle = stackHandle
            joinerAllowedIps = parseAllowedIpsCsv(allowedIpsCsv)
            val rc = bridge.registerJoiner(stackHandle, allowedIpsCsv)
            if (rc != 0) {
                Log.w(TAG, "nativeCascadeRegisterJoiner($stackHandle) rc=$rc")
            } else {
                Log.i(TAG, "joiner stack $stackHandle registered with ${joinerAllowedIps.size} cascade prefixes")
            }
        }
    }

    /**
     * Called BEFORE the joiner stack is destroyed.  Synchronous —
     * the registry installs drop-NIC routes on each host stack
     * before returning, so cascade traffic gets dropped (not
     * leaked) during the rebuild gap.
     */
    fun onJoinerStackDown() {
        synchronized(mu) {
            if (!enabled || joinerStackHandle == null) return
            runCatching { bridge.unregisterJoiner() }
                .onFailure { Log.w(TAG, "nativeCascadeUnregisterJoiner threw: $it") }
            joinerStackHandle = null
            joinerAllowedIps = emptySet()
            Log.i(TAG, "joiner stack unregistered; drop-NIC routes installed")
        }
    }

    fun onJoinerAllowedIpsChanged(allowedIpsCsv: String) {
        synchronized(mu) {
            if (!enabled || joinerStackHandle == null) return
            joinerAllowedIps = parseAllowedIpsCsv(allowedIpsCsv)
            val rc = bridge.joinerAllowedIpsChanged(allowedIpsCsv)
            if (rc != 0) {
                Log.w(TAG, "nativeCascadeOnAllowedIPsChanged rc=$rc csv=$allowedIpsCsv")
            } else {
                Log.i(TAG, "joiner AllowedIPs union updated: ${joinerAllowedIps.size} prefixes ($allowedIpsCsv)")
            }
        }
    }

    /**
     * Update the joiner's own assigned WG-side address(es) used as
     * the CASCADE-2 NAT source.  Bare addresses (no CIDR) joined by
     * commas, e.g. `"10.240.234.3,2001:db8::3"`.  Empty CSV
     * disables NAT for that family.
     *
     * Idempotent; safe to call when no joiner stack is up
     * (currently a no-op, but the registry caches the value for
     * the next ferry to use).
     */
    fun onJoinerInterfaceAddrsChanged(addrsCsv: String) {
        synchronized(mu) {
            if (!enabled) return
            val rc = bridge.joinerInterfaceAddrsChanged(addrsCsv)
            if (rc != 0) {
                Log.w(TAG, "nativeCascadeOnJoinerInterfaceAddrsChanged rc=$rc csv=$addrsCsv")
            } else {
                Log.i(TAG, "joiner interface addrs for NAT: $addrsCsv")
            }
        }
    }

    fun onHostBridgeUp(bridgeHandle: Int, peerSubnetsCsv: String) {
        synchronized(mu) {
            if (!enabled) return
            hostBridges[bridgeHandle] = parseAllowedIpsCsv(peerSubnetsCsv)
            val rc = bridge.registerHostBridge(bridgeHandle, peerSubnetsCsv)
            if (rc != 0) {
                Log.w(TAG, "nativeCascadeRegisterHostBridge($bridgeHandle) rc=$rc")
            } else {
                Log.i(TAG, "host bridge $bridgeHandle registered with $peerSubnetsCsv")
            }
        }
    }

    fun onHostBridgeDown(bridgeHandle: Int) {
        synchronized(mu) {
            if (!enabled) return
            if (hostBridges.remove(bridgeHandle) == null) return
            runCatching { bridge.unregisterHostBridge(bridgeHandle) }
                .onFailure { Log.w(TAG, "nativeCascadeUnregisterHostBridge threw: $it") }
            Log.i(TAG, "host bridge $bridgeHandle unregistered")
        }
    }

    /**
     * Compute the AllowedIPs union from a list of joiner UAPI
     * strings — extracts every `allowed_ip=` line and returns the
     * deduplicated CIDR set as a comma-separated string.  Suitable
     * to pass to [onJoinerStackUp] / [onJoinerAllowedIpsChanged].
     */
    fun unionAllowedIpsFromUapi(uapis: List<String>): String {
        val out = linkedSetOf<String>()
        for (uapi in uapis) {
            for (line in uapi.split('\n')) {
                val l = line.trim()
                if (!l.startsWith("allowed_ip=", ignoreCase = false)) continue
                val cidr = l.substringAfter("=").trim()
                if (cidr.isNotEmpty()) out.add(cidr)
            }
        }
        return out.joinToString(",")
    }

    /**
     * Compute the union AllowedIPs from a list of wg-quick
     * configs (the joiner side's source of truth).  Useful when
     * the controller has parsed configs but not yet rendered
     * UAPI.
     */
    fun unionAllowedIpsFromWgQuick(wgQuickTexts: List<String>): String {
        val out = linkedSetOf<String>()
        for (text in wgQuickTexts) {
            out.addAll(parseAllowedIps(text))
        }
        return out.joinToString(",")
    }

    /** Test seam — install [b], reset all state, return a closeable
     *  that restores the prior bridge and clears state.  Tests
     *  MUST use the returned restorer (`use {}`) so they don't
     *  leak fakes into sibling tests. */
    internal fun installBridgeForTest(b: Bridge): AutoCloseable {
        val prev: Bridge
        synchronized(mu) {
            prev = bridge
            bridge = b
            enabled = false
            joinerStackHandle = null
            joinerAllowedIps = emptySet()
            hostBridges.clear()
        }
        return AutoCloseable {
            synchronized(mu) {
                bridge = prev
                enabled = false
                joinerStackHandle = null
                joinerAllowedIps = emptySet()
                hostBridges.clear()
            }
        }
    }

    // For tests.
    internal fun snapshotState(): SnapshotState = synchronized(mu) {
        SnapshotState(
            enabled = enabled,
            joinerStackHandle = joinerStackHandle,
            joinerAllowedIps = joinerAllowedIps.toSet(),
            hostBridges = hostBridges.mapValues { it.value.toSet() },
        )
    }

    internal data class SnapshotState(
        val enabled: Boolean,
        val joinerStackHandle: Int?,
        val joinerAllowedIps: Set<String>,
        val hostBridges: Map<Int, Set<String>>,
    )

    private fun parseAllowedIpsCsv(csv: String): Set<String> {
        if (csv.isBlank()) return emptySet()
        return csv.split(',')
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .toSet()
    }
}
