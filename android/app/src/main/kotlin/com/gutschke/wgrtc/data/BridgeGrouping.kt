package com.gutschke.wgrtc.data

/**
 * One row entry in the TunnelList — either a stand-alone [Tunnel] or
 * a [Bridge] formed by two tunnels that share a non-null
 * [Tunnel.groupId].  See `docs/ux-design-v2.md` §3.2.
 *
 * Group-of-one (a tunnel whose paired half was deleted) renders as
 * a normal single tunnel — the persisted `groupId` is left alone in
 * case the deleted half is later re-imported, but the UI doesn't
 * collapse a singleton group.  Group-of-three-or-more isn't a
 * supported state today; we still render every member as a single
 * row so misconfiguration is observable rather than silently
 * hidden.
 */
sealed class TunnelListEntry {
    /** A normal, stand-alone tunnel.  Either [Tunnel.groupId] is
     *  null or no sibling exists. */
    data class Single(val tunnel: Tunnel) : TunnelListEntry()

    /** A pair of tunnels intentionally created as a Bridge.  By
     *  invariant [first] and [second] share a non-null `groupId`
     *  and have different `id`s.  Ordering: host first when one
     *  half is host-mode and the other is joiner; otherwise
     *  preserve the original list order. */
    data class Bridge(
        val groupId: String,
        val first: Tunnel,
        val second: Tunnel,
    ) : TunnelListEntry() {
        /** Display name for the Bridge row.  Today: "first ↔ second".
         *  In the future we may persist a user-supplied label. */
        val displayName: String get() = "${first.name} ↔ ${second.name}"
    }
}

/**
 * Group a flat list of tunnels into a list of [TunnelListEntry]s.
 * Tunnels with a non-null `groupId` are paired with their sibling
 * (if present); singletons render as [TunnelListEntry.Single].
 * Order: the first tunnel of a group keeps its position; the
 * paired half is consumed at the same slot.  Tunnels without a
 * groupId appear in their original order.
 *
 * Pure function — call from Compose without worrying about side
 * effects.  See tests in `BridgeGroupingTest`.
 */
fun groupTunnels(tunnels: List<Tunnel>): List<TunnelListEntry> {
    if (tunnels.isEmpty()) return emptyList()
    // Index tunnels by groupId; later loop consumes pairs in
    // first-seen order.
    val byGroup = mutableMapOf<String, MutableList<Tunnel>>()
    for (t in tunnels) {
        val g = t.groupId ?: continue
        byGroup.getOrPut(g) { mutableListOf() }.add(t)
    }
    val consumed = mutableSetOf<String>()
    val out = mutableListOf<TunnelListEntry>()
    for (t in tunnels) {
        if (t.id in consumed) continue
        val g = t.groupId
        if (g != null) {
            val group = byGroup[g] ?: emptyList()
            // Two-member group: collapse.  Order: host first.
            if (group.size == 2) {
                val (a, b) = group[0] to group[1]
                val (first, second) = if (a.source == Tunnel.Source.HOST_MODE &&
                    b.source != Tunnel.Source.HOST_MODE) {
                    a to b
                } else if (b.source == Tunnel.Source.HOST_MODE &&
                    a.source != Tunnel.Source.HOST_MODE) {
                    b to a
                } else {
                    a to b
                }
                out.add(TunnelListEntry.Bridge(g, first, second))
                consumed += first.id
                consumed += second.id
                continue
            }
            // Group-of-one or group-of-three+: render every
            // member as a Single.  The persisted groupId is
            // preserved on disk but the UI is honest about the
            // mismatch.
        }
        out.add(TunnelListEntry.Single(t))
        consumed += t.id
    }
    return out
}
