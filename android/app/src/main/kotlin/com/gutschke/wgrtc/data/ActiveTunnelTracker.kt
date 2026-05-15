package com.gutschke.wgrtc.data

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map

/**
 * Combines the two independent "what tunnels are running" sources of
 * truth into a single observable set.
 *
 * Two slot groups exist on Android:
 *   * **Joiner** — at most one tunnel at a time (Android's VpnService
 *     is a process-wide singleton).  Modeled as `StateFlow<String?>`.
 *   * **Host** — N concurrent tunnels.  Modeled as
 *     `StateFlow<Set<String>>` on `HostModeBackend.activeTunnelIds`.
 *
 * The UI wants one canonical answer to "is this tunnel up?", so this
 * helper merges them.  Kept as a tiny pure-Kotlin utility so it can
 * be unit-tested without an Android Context.
 */
object ActiveTunnelTracker {

    /** Snapshot helper: produces the union of `joinerId` (if any) and
     * `hostIds`.  Used at call-sites that need an immediate value
     * rather than collecting a flow. */
    fun union(joinerId: String?, hostIds: Set<String>): Set<String> =
        union(joinerId, hostIds, emptySet())

    /** Three-source union: legacy single-joiner slot, host set, and
     * the joiner-N shared-stack set.  All three are mutually exclusive
     * by design (the flag picks one joiner path), but we union
     * unconditionally so a half-rebuild state never claims more
     * tunnels are down than actually are. */
    fun union(
        joinerId: String?,
        hostIds: Set<String>,
        joinerNIds: Set<String>,
    ): Set<String> = buildSet {
        if (joinerId != null) add(joinerId)
        addAll(hostIds)
        addAll(joinerNIds)
    }

    /** Flow form of [union] — emits the merged set whenever either
     * input changes.  Distinct-by-value so identical re-emits from
     * either source don't churn downstream collectors. */
    fun combinedFlow(
        joiner: Flow<String?>,
        host: Flow<Set<String>>,
    ): Flow<Set<String>> =
        combine(joiner, host) { j, h -> union(j, h, emptySet()) }
            .distinctUntilChanged()

    /** Flow form including the joiner-N shared-stack set. */
    fun combinedFlow(
        joiner: Flow<String?>,
        host: Flow<Set<String>>,
        joinerN: Flow<Set<String>>,
    ): Flow<Set<String>> =
        combine(joiner, host, joinerN) { j, h, jn -> union(j, h, jn) }
            .distinctUntilChanged()

    /** Per-tunnel membership flow — emits true when [id] is in either
     * the joiner slot or the host set.  Distinct-by-value so
     * downstream Compose recompositions only fire on actual
     * transitions. */
    fun isActiveFlow(
        id: String,
        joiner: Flow<String?>,
        host: Flow<Set<String>>,
    ): Flow<Boolean> =
        combinedFlow(joiner, host)
            .map { it.contains(id) }
            .distinctUntilChanged()

    /** Per-tunnel membership flow including the joiner-N set. */
    fun isActiveFlow(
        id: String,
        joiner: Flow<String?>,
        host: Flow<Set<String>>,
        joinerN: Flow<Set<String>>,
    ): Flow<Boolean> =
        combinedFlow(joiner, host, joinerN)
            .map { it.contains(id) }
            .distinctUntilChanged()
}
