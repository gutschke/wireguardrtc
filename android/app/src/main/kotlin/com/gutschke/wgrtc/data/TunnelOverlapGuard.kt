package com.gutschke.wgrtc.data

import com.gutschke.wgrtc.signalling.cidrsShareExactPrefix
import com.gutschke.wgrtc.signalling.parseAllowedIps

/**
 * Pre-Connect AllowedIPs overlap check for multi-tunnel scenarios.
 *
 * **Why this exists:** when more than one wgrtc tunnel is active on
 * the same device, two tunnels claiming the *same exact CIDR*
 * (e.g. both `10.99.0.0/24`) produce routing ambiguity that
 * kernel WG resolves arbitrarily and silently — much better to
 * refuse the second `Connect` and tell the user which tunnel
 * conflicts.
 *
 * **LPM-resolvable overlaps are NOT conflicts.**  Two tunnels with
 * `0.0.0.0/0` (full-tunnel joiner) and `10.99.0.0/24` (host-mode
 * subnet) coexist cleanly because kernel longest-prefix-match
 * picks the /24 for that subnet and the /0 catches the rest.  We
 * use [cidrsShareExactPrefix], which flags only identical-prefix
 * collisions, not subset/superset overlaps.  CASCADE-1 finding,
 * 2026-05-17.
 *
 * **Today** the [HostModeBackend] and [JoinerWgRunner] singletons
 * each enforce single-instance, so the guard is mostly a dormant
 * safety net.  When that restriction is lifted (task D4 — Generalize
 * app to support N simultaneous tunnels per device), this guard
 * becomes load-bearing.  Wiring it in now means the test surface +
 * the call site are stable before the single-instance checks come
 * out.
 *
 * Pure data → decision; no Android deps.  Kept tiny on purpose so
 * the entire policy is auditable at a glance.
 */
object TunnelOverlapGuard {

    /**
     * Return the first tunnel in [active] whose claimed address
     * ranges share an identical CIDR with [candidate]'s, or `null`
     * if [candidate] is safe to bring up.
     *
     * Identical CIDR = same network address AND same prefix length.
     * LPM-resolvable overlaps (e.g. `0.0.0.0/0` ∩ `10.99.0.0/24`)
     * are deliberately permitted — the kernel routes those
     * correctly.
     *
     * The candidate itself, if it appears in [active] (e.g.
     * re-activating a tunnel that's already up), is skipped — it
     * trivially shares its own ranges with itself and that's not a
     * conflict.
     */
    fun firstOverlap(candidate: Tunnel, active: List<Tunnel>): Tunnel? {
        val candidateRanges = claimedRanges(candidate)
        if (candidateRanges.isEmpty()) return null
        for (existing in active) {
            if (existing.id == candidate.id) continue
            val existingRanges = claimedRanges(existing)
            if (existingRanges.isEmpty()) continue
            if (cidrsShareExactPrefix(candidateRanges, existingRanges)) return existing
        }
        return null
    }

    /**
     * The CIDR set this tunnel "claims" — i.e. the ranges that other
     * tunnels mustn't also claim if they want to coexist:
     *
     * - **Host-mode tunnel**: just its [HostModeConfig.subnet].  The
     *   advertised AllowedIPs is what *joiners* route through; the
     *   host itself only needs the subnet so its WG-side address
     *   (subnet[1]) doesn't collide.
     * - **Joiner-mode tunnel**: the union of every
     *   `AllowedIPs = …` entry on every `[Peer]` block in its
     *   wg-quick text.  Those are the ranges the joiner's kernel
     *   would route through the WG interface; overlapping them with
     *   another tunnel produces routing ambiguity.
     *
     * A tunnel with no claimed ranges (malformed config, missing
     * hostMode) contributes nothing.
     */
    private fun claimedRanges(t: Tunnel): List<String> =
        if (t.source == Tunnel.Source.HOST_MODE) {
            listOfNotNull(t.hostMode?.subnet?.takeIf { it.isNotBlank() })
        } else {
            parseAllowedIps(t.configText)
        }
}
