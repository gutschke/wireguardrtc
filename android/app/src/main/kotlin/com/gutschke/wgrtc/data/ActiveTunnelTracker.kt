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
 *   * **Host** — N concurrent tunnels since D4.H1.  Modeled as
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
        if (joinerId == null) hostIds
        else if (hostIds.isEmpty()) setOf(joinerId)
        else hostIds + joinerId

    /** Flow form of [union] — emits the merged set whenever either
     * input changes.  Distinct-by-value so identical re-emits from
     * either source don't churn downstream collectors. */
    fun combinedFlow(
        joiner: Flow<String?>,
        host: Flow<Set<String>>,
    ): Flow<Set<String>> =
        combine(joiner, host) { j, h -> union(j, h) }
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
}
