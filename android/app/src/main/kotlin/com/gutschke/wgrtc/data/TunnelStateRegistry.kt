package com.gutschke.wgrtc.data

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.concurrent.ConcurrentHashMap

/**
 * Process-wide registry of [TunnelState] per tunnel id.  See
 * `docs/ux-design-v2.md` §1.3 Invariant 1.
 *
 * Owned by the service layer (whichever bound service is alive —
 * typically `OfferListenerService` for the long-lived case, the
 * VpnServices while their tunnel is up).  Read-only from the
 * ViewModel.
 *
 * **The registry is the single source of truth for what the UI
 * draws.** Today the UI mutates `_activeJoinerNTunnelIds` directly
 * on user tap; that creates the phantom-active failure when the
 * system revokes consent (the service dies, the flow doesn't update,
 * the UI keeps lying).  After v2 lands the registry sits between
 * service-level signals and UI subscription: ViewModel observes
 * [stateOf]; service callsites call [transition] / [recordRevoke] /
 * [recordFailure] / [recordResume].
 *
 * **Threading**: this class is thread-safe.  Multiple service
 * callbacks may fire concurrently; transitions are atomic per
 * tunnel id and the emitted [StateFlow] guarantees the UI sees a
 * coherent sequence.  Callers are NOT required to hold a lock.
 *
 * **Transition log**: every state change appends an entry to a
 * fixed-size ring buffer per tunnel.  See [transitionLog] for the
 * read API; the buffer's size is [LOG_CAPACITY] (50 entries — large
 * enough to capture a full handshake cycle with retries, small
 * enough that all-tunnels-paused doesn't bloat memory).
 *
 * **State on registry-recovery (process restart)**: the registry is
 * in-memory only.  On process recreation the service rebuilds from
 * UAPI dumps + persisted [Tunnel.intent].  Tunnels with
 * `intent=WantsOn` start at [TunnelState.Arming] and re-derive
 * live; `intent=ExplicitlyOff` → [TunnelState.PausedUser];
 * `intent=NoIntentYet` → [TunnelState.Disabled].
 *
 * Two construction modes:
 *
 *   * [getProcessSingleton] — production.  One instance per
 *     process; survives `ViewModel` recreation across config
 *     changes.
 *   * direct construction (for tests).  Each test gets a fresh
 *     instance so state doesn't leak across `@Test` boundaries.
 */
class TunnelStateRegistry internal constructor(
    private val clock: () -> Long = System::currentTimeMillis,
) {

    private val states: MutableMap<String, MutableStateFlow<TunnelState>> = ConcurrentHashMap()
    private val logs: MutableMap<String, RingBuffer<TransitionEntry>> = ConcurrentHashMap()

    /**
     * One [TransitionEntry] per state change.  Order is insertion
     * order; oldest entries are dropped when the buffer overflows.
     * Each entry carries:
     *   - the timestamp (millis since epoch) at which the transition
     *     was recorded
     *   - the previous state (null on first entry)
     *   - the new state
     *   - an optional human-readable [note] (e.g.  "establish()
     *     returned null") — surfaced in the technical-details fold
     *     of the TunnelDetail screen
     */
    data class TransitionEntry(
        val timestampMs: Long,
        val from: TunnelState?,
        val to: TunnelState,
        val note: String?,
    )

    /**
     * Observable state for [tunnelId].  When the tunnel has not yet
     * been seen by the registry, returns a flow seeded with
     * [TunnelState.Disabled].  Both stateOf and transitionLog
     * upgrade the entry lazily on first observation.
     */
    fun stateOf(tunnelId: String): StateFlow<TunnelState> =
        flowFor(tunnelId).asStateFlow()

    /**
     * Snapshot of the transition log for [tunnelId].  Oldest first,
     * newest last.  Empty list when the tunnel hasn't been seen.
     */
    fun transitionLog(tunnelId: String): List<TransitionEntry> =
        logs[tunnelId]?.snapshot() ?: emptyList()

    /**
     * Record a transition to [newState].  Idempotent against a
     * no-op (same state, same payload): the registry skips both the
     * flow emit and the log append.  Equality is structural —
     * [TunnelState.PausedSystem] with different [PauseReason]s
     * counts as different states and is logged.
     */
    fun transition(tunnelId: String, newState: TunnelState, note: String? = null) {
        val flow = flowFor(tunnelId)
        val prev = flow.value
        if (prev == newState && note == null) return
        flow.value = newState
        logFor(tunnelId).add(TransitionEntry(
            timestampMs = clock(),
            from = prev,
            to = newState,
            note = note,
        ))
    }

    /**
     * Convenience for the "system revoked our consent" path.
     * Always transitions to [TunnelState.PausedSystem]; carries the
     * [reason] so the transition log reads as a story.
     */
    fun recordRevoke(tunnelId: String, reason: PauseReason, note: String? = null) {
        transition(tunnelId, TunnelState.PausedSystem(reason), note)
    }

    /**
     * Convenience for the "user un-paused" path.  Transitions to
     * [TunnelState.Arming] so the signal layer can re-derive
     * Connecting/Connected/etc.  No-op if the current state is
     * already Arming or beyond.
     */
    fun recordResume(tunnelId: String, note: String? = null) {
        val flow = flowFor(tunnelId)
        when (flow.value) {
            TunnelState.Arming, TunnelState.Connecting,
            TunnelState.Connected, TunnelState.Idle,
            TunnelState.Degraded -> return
            else -> transition(tunnelId, TunnelState.Arming, note)
        }
    }

    /**
     * Convenience for failure reporting.  [recoverable] decides
     * whether the next network event re-arms (true) or whether the
     * user must intervene (false).
     */
    fun recordFailure(
        tunnelId: String,
        cause: FailureCause,
        recoverable: Boolean,
        note: String? = null,
    ) {
        transition(tunnelId, TunnelState.Failed(cause, recoverable), note)
    }

    /** Forget all state for [tunnelId].  Used when the user deletes
     *  the tunnel.  After this, [stateOf] returns a fresh flow
     *  seeded with [TunnelState.Disabled]. */
    fun forget(tunnelId: String) {
        states.remove(tunnelId)
        logs.remove(tunnelId)
    }

    /** Forget every tunnel.  Used by tests to reset state between
     *  cases without recreating the registry. */
    internal fun forgetAll() {
        states.clear()
        logs.clear()
    }

    /** Set of tunnel ids the registry has seen.  Order is undefined. */
    val knownTunnelIds: Set<String> get() = states.keys.toSet()

    private fun flowFor(tunnelId: String): MutableStateFlow<TunnelState> =
        states.getOrPut(tunnelId) { MutableStateFlow(TunnelState.Disabled) }

    private fun logFor(tunnelId: String): RingBuffer<TransitionEntry> =
        logs.getOrPut(tunnelId) { RingBuffer(LOG_CAPACITY) }

    /** A small fixed-capacity ring buffer.  Append O(1);
     *  [snapshot] copies into a List with oldest-first order. */
    internal class RingBuffer<T>(private val capacity: Int) {
        private val items: ArrayList<T> = ArrayList(capacity)
        private val mu = Object()

        fun add(item: T) {
            synchronized(mu) {
                if (items.size == capacity) items.removeAt(0)
                items.add(item)
            }
        }

        fun snapshot(): List<T> = synchronized(mu) { items.toList() }
    }

    companion object {
        /** Capacity of the per-tunnel transition log.  50 entries
         *  covers a noisy handshake cycle (4-5 retries × 8-10
         *  intermediate states) with headroom for the bug-report
         *  copy/paste use case. */
        const val LOG_CAPACITY: Int = 50

        @Volatile private var instance: TunnelStateRegistry? = null

        /** Process-singleton accessor.  Production code calls this;
         *  tests construct fresh instances directly. */
        fun getProcessSingleton(): TunnelStateRegistry =
            instance ?: synchronized(this) {
                instance ?: TunnelStateRegistry().also { instance = it }
            }

        /** Test-only: replace the singleton.  Tests that bind via
         *  WgBridgeNative-style fakes need this to inject a fresh
         *  registry without recursing through the production
         *  factory. */
        internal fun setSingletonForTest(r: TunnelStateRegistry?) {
            synchronized(this) { instance = r }
        }
    }
}
