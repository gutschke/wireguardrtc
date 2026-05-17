package com.gutschke.wgrtc.data

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap

/**
 * Kotlin controller for joiner-N's shared netstack.
 *
 * Parallel to [HostModeBackend] but for joiner tunnels: owns one
 * `sharedStackState` on the Go side (NIC 1 = kernel TUN; NIC 2+ =
 * joiner bridges) and a slot per active joiner.  Every lifecycle
 * entry point wraps its body in `withContext(Dispatchers.IO)`
 * because the underlying JNI calls block on wireguard-go's
 * device mutex — calling them from `Main` would ANR the UI
 * (per `feedback_jni_calls_off_main_thread.md`).
 *
 * **Why a separate class from [HostModeBackend].**  Host tunnels
 * run independently — each owns its own gvisor stack, no shared
 * resources.  Joiner-N is the opposite: one gvisor stack shared
 * across N joiners, with the kernel TUN as the single backplane.
 * The slot map and the shared-stack lifecycle are entangled in a
 * way host mode doesn't need, so keeping them in their own class
 * avoids the per-tunnel-shape branching that would otherwise
 * leak into every host-mode method.
 *
 * **Lifecycle order**:
 *
 *  1. [bindKernelTun] — exactly once before any joiners.  The
 *     caller has already done `VpnService.Builder.establish()`
 *     and detached the resulting fd.
 *  2. [openJoiner] — once per joiner tunnel.  Returns a bridge
 *     handle the caller uses with [reconfigure] / [snapshotStats] /
 *     [closeJoiner].
 *  3. [closeJoiner] — releases one joiner.  The rest stay live.
 *  4. [closeAll] — full teardown.  Stops the kernel-TUN pump,
 *     closes every joiner, destroys the shared stack.
 *
 * **Reconfigure model** (per `cascade-n-design.md`):  callers
 * that need to change AllowedIPs (the route table) recreate the
 * joiner via [closeJoiner] + [openJoiner].  Kernel TCP sockets
 * survive the swap because the address binding stays put
 * confirmed this empirically.
 */
class JoinerStackBackend(
    private val factory: JoinerStackNative,
) {
    /**
     * One slot per joiner tunnel.  Tracks the bridge handle the
     * JNI surface returned plus the last UAPI we applied (for
     * later reconfigure cycles).
     */
    private data class Slot(
        val bridgeHandle: Int,
        @Volatile var uapi: String,
        @Volatile var peerAllowed: List<String>,
    )

    private val slots: ConcurrentHashMap<String, Slot> = ConcurrentHashMap()
    private val mu = Mutex()

    /** Native handle of the shared netstack; 0 means "not bound yet". */
    @Volatile private var stackHandle: Int = 0
    @Volatile private var stackMtu: Int = 0

    private val _activeJoinerIds = MutableStateFlow<Set<String>>(emptySet())
    /** Set of joiner tunnel ids whose bridge is currently open. */
    val activeJoinerIds: StateFlow<Set<String>> = _activeJoinerIds.asStateFlow()

    /** True if a kernel TUN is currently bound to the shared stack. */
    val kernelTunBound: Boolean get() = stackHandle != 0

    /**
     * Bind [fd] as NIC 1 of a freshly-created shared netstack.
     * The stack TAKES OWNERSHIP of [fd]; the caller must not
     * close it manually — [closeAll] does that.
     *
     * Idempotent against repeated bind: if the stack already
     * exists, throws [IllegalStateException].  The caller's
     * `JoinerVpnService` rebuild path closes the old stack
     * (via [closeAll]) first.
     */
    @Throws(JoinerStackException::class)
    suspend fun bindKernelTun(fd: Int, mtu: Int) {
        mu.withLock {
            check(stackHandle == 0) {
                "shared stack already bound — closeAll first to rebuild"
            }
            withContext(Dispatchers.IO) {
                val handle = factory.sharedStackNew(mtu)
                if (handle <= 0) {
                    throw JoinerStackException(
                        "sharedStackNew(mtu=$mtu) failed with rc=$handle")
                }
                val rc = factory.sharedStackAttachKernelTun(handle, fd, mtu)
                if (rc != 0) {
                    factory.sharedStackClose(handle)
                    throw JoinerStackException(
                        "sharedStackAttachKernelTun(fd=$fd) failed with rc=$rc")
                }
                stackHandle = handle
                stackMtu = mtu
            }
            CascadeWiring.onJoinerStackUp(stackHandle, "")
        }
    }

    /**
     * Open a joiner bridge as a new NIC on the shared stack and
     * configure it with [wgQuickUapi] (typically rendered by
     * `JoinerWgRunner` from the wg-quick config).  Returns the
     * bridge handle the caller may pass to [reconfigure] /
     * [snapshotStats] etc.
     *
     * `peerAllowed` and `interfaceAddrs` are CIDR-string lists
     * shaped to match the wg-quick `[Peer] AllowedIPs` and
     * `[Interface] Address` semantics.  Either may be empty.
     */
    @Throws(JoinerStackException::class)
    suspend fun openJoiner(
        tunnelId: String,
        peerAllowed: List<String>,
        interfaceAddrs: List<String>,
        mtu: Int,
        wgQuickUapi: String,
    ): Int {
        mu.withLock {
            val sh = stackHandle
            if (sh == 0) {
                throw JoinerStackException(
                    "kernel TUN not bound — call bindKernelTun first")
            }
            if (slots.containsKey(tunnelId)) {
                throw JoinerStackException(
                    "joiner '$tunnelId' already open — closeJoiner first")
            }
            return withContext(Dispatchers.IO) {
                val bridgeHandle = factory.sharedStackOpenJoiner(
                    sh,
                    if (peerAllowed.isEmpty()) null else peerAllowed.joinToString(","),
                    if (interfaceAddrs.isEmpty()) null else interfaceAddrs.joinToString(","),
                    mtu,
                )
                if (bridgeHandle <= 0) {
                    throw JoinerStackException(
                        "sharedStackOpenJoiner('$tunnelId') failed with rc=$bridgeHandle")
                }
                val rc = factory.configureUapi(bridgeHandle, wgQuickUapi)
                if (rc != 0) {
                    factory.close(bridgeHandle)
                    throw JoinerStackException(
                        "configureUapi('$tunnelId') failed with rc=$rc")
                }
                slots[tunnelId] = Slot(
                    bridgeHandle = bridgeHandle,
                    uapi = wgQuickUapi,
                    peerAllowed = peerAllowed,
                )
                _activeJoinerIds.value = slots.keys.toSet()
                bridgeHandle
            }.also {
                CascadeWiring.onJoinerAllowedIpsChanged(unionAllowedIpsCsv())
            }
        }
    }

    /**
     * Re-issue UAPI for an existing joiner.  Used by the
     * candidate-race / endpoint-roam path that needs to push a
     * new `[Peer] Endpoint = ...` without rebuilding the bridge.
     * No-op if no slot exists for [tunnelId].
     */
    suspend fun reconfigure(tunnelId: String, wgQuickUapi: String) {
        val slot = slots[tunnelId] ?: return
        withContext(Dispatchers.IO) {
            val rc = factory.configureUapi(slot.bridgeHandle, wgQuickUapi)
            if (rc != 0) {
                throw JoinerStackException(
                    "reconfigure('$tunnelId') failed with rc=$rc")
            }
            slot.uapi = wgQuickUapi
        }
    }

    /**
     * Snapshot wireguard-go's current state for [tunnelId] as a
     * UAPI dump.  Returns null when no slot exists, or when the
     * JNI snapshot call returned null (transient: the caller
     * treats it as "skip this poll tick").
     */
    fun snapshotUapi(tunnelId: String): String? {
        val slot = slots[tunnelId] ?: return null
        return factory.snapshotUapi(slot.bridgeHandle)
    }

    /**
     * Close one joiner.  Detaches its NIC, drops routes pointing
     * at it (they become dead-letter), and removes the slot.
     * Idempotent.
     */
    suspend fun closeJoiner(tunnelId: String) {
        val slot = slots.remove(tunnelId) ?: return
        _activeJoinerIds.value = slots.keys.toSet()
        CascadeWiring.onJoinerAllowedIpsChanged(unionAllowedIpsCsv())
        withContext(Dispatchers.IO) {
            try { factory.close(slot.bridgeHandle) } catch (_: Throwable) {}
        }
    }

    /**
     * Full teardown.  Closes every joiner sequentially, then
     * tears down the shared stack (which stops the kernel-TUN
     * pump and closes the fd).  Idempotent: calling twice does
     * nothing the second time.
     */
    suspend fun closeAll() {
        mu.withLock {
            val ids = slots.keys.toList()
            for (id in ids) closeJoiner(id)
            val sh = stackHandle
            // Stack is about to go away — give cascade a chance to
            // install drop-NIC routes on each host stack BEFORE we
            // tear gvisor down.  CascadeWiring is a no-op when the
            // user hasn't enabled cascade.
            if (sh != 0) {
                CascadeWiring.onJoinerStackDown()
            }
            stackHandle = 0
            stackMtu = 0
            if (sh != 0) {
                withContext(Dispatchers.IO) {
                    factory.sharedStackClose(sh)
                }
            }
        }
    }

    /** Comma-separated union of every active slot's AllowedIPs.
     *  Empty string when no slot has any.  Used to keep the cascade
     *  registry in sync with the joiner-N slot map. */
    private fun unionAllowedIpsCsv(): String {
        val all = linkedSetOf<String>()
        for (slot in slots.values) all.addAll(slot.peerAllowed)
        return all.joinToString(",")
    }
}

/** Typed exception for joiner-stack lifecycle failures.  Lets
 *  the caller distinguish "VPN consent revoked" / "MTU bogus" /
 *  "duplicate joiner id" via the error message. */
class JoinerStackException(msg: String) : RuntimeException(msg)

/**
 * Testable seam over the JNI surface — production wires this to
 * [WgBridgeNative]'s `native*` methods; tests inject an in-process
 * fake to validate lifecycle without touching the .so.
 */
interface JoinerStackNative {
    fun sharedStackNew(mtu: Int): Int
    fun sharedStackClose(handle: Int)
    fun sharedStackAttachKernelTun(handle: Int, fd: Int, mtu: Int): Int
    fun sharedStackOpenJoiner(
        stackHandle: Int,
        peerAllowedCsv: String?,
        interfaceAddrsCsv: String?,
        mtu: Int,
    ): Int

    fun configureUapi(bridgeHandle: Int, uapi: String): Int
    fun snapshotUapi(bridgeHandle: Int): String?
    fun close(bridgeHandle: Int)
}

/**
 * Production implementation backed by [WgBridgeNative]'s static
 * native methods.  Pure passthrough — no logic beyond the JNI
 * crossing.
 */
object RealJoinerStackNative : JoinerStackNative {
    override fun sharedStackNew(mtu: Int): Int =
        WgBridgeNative.nativeSharedStackNew(mtu)

    override fun sharedStackClose(handle: Int) {
        WgBridgeNative.nativeSharedStackClose(handle)
    }

    override fun sharedStackAttachKernelTun(handle: Int, fd: Int, mtu: Int): Int =
        WgBridgeNative.nativeSharedStackAttachKernelTun(handle, fd, mtu)

    override fun sharedStackOpenJoiner(
        stackHandle: Int,
        peerAllowedCsv: String?,
        interfaceAddrsCsv: String?,
        mtu: Int,
    ): Int = WgBridgeNative.nativeSharedStackOpenJoiner(
        stackHandle, peerAllowedCsv, interfaceAddrsCsv, mtu)

    override fun configureUapi(bridgeHandle: Int, uapi: String): Int =
        WgBridgeNative.nativeConfigureUAPI(bridgeHandle, uapi)

    override fun snapshotUapi(bridgeHandle: Int): String? =
        WgBridgeNative.nativeSnapshotUAPI(bridgeHandle)

    override fun close(bridgeHandle: Int) {
        WgBridgeNative.nativeClose(bridgeHandle)
    }
}
