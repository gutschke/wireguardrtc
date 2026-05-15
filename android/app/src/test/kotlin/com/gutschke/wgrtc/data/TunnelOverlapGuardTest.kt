package com.gutschke.wgrtc.data

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

/**
 * Unit tests for [TunnelOverlapGuard].
 *
 * The guard is the UI's pre-Connect check: before bringing tunnel X
 * up, ask "would X's claimed address range overlap any tunnel that's
 * already up?"  If yes, surface a user-visible error rather than
 * silently letting kernel routing pick a winner.
 *
 * Today only one tunnel can be active at a time (see
 * `HostModeBackend.start()`'s `check(activeId == null)` and
 * `JoinerWgRunner.start()`'s analogue) so this guard is mostly a
 * dormant safety net.  When that restriction is lifted (D4), the
 * guard becomes load-bearing.
 *
 * Pure-JVM tests — no Android context, no coroutines.  Just data
 * classes in, decision out.
 */
class TunnelOverlapGuardTest {

    private fun joinerTunnel(
        id: String, allowedIps: String,
    ): Tunnel = Tunnel(
        id = id,
        name = "joiner-$id",
        configText = """
            [Interface]
            PrivateKey = AAA
            Address = 10.0.0.2/32

            [Peer]
            PublicKey = BBB
            AllowedIPs = $allowedIps
        """.trimIndent(),
        source = Tunnel.Source.LEGACY,
    )

    private fun hostTunnel(
        id: String, subnet: String,
    ): Tunnel = Tunnel(
        id = id,
        name = "host-$id",
        configText = """
            [Interface]
            PrivateKey = AAA
            Address = ${subnet.substringBefore('/')}
            ListenPort = 51820
        """.trimIndent(),
        source = Tunnel.Source.HOST_MODE,
        hostMode = HostModeConfig(subnet = subnet),
    )

    @Test fun `empty active list never blocks`() {
        val cand = joinerTunnel("c", "10.0.0.0/24")
        assertNull(TunnelOverlapGuard.firstOverlap(cand, emptyList()))
    }

    @Test fun `the candidate matches itself in the list and is skipped`() {
        // Important: re-activating tunnel X must not be blocked by X
        // appearing in the "active" set with overlapping ranges.
        val cand = joinerTunnel("c", "10.0.0.0/24")
        assertNull(TunnelOverlapGuard.firstOverlap(cand, listOf(cand)))
    }

    @Test fun `two joiner tunnels with identical AllowedIPs overlap`() {
        val a = joinerTunnel("a", "10.0.0.0/24")
        val cand = joinerTunnel("c", "10.0.0.0/24")
        assertEquals(a, TunnelOverlapGuard.firstOverlap(cand, listOf(a)))
    }

    @Test fun `two joiner tunnels with subnet relationship overlap`() {
        val supernet = joinerTunnel("a", "10.0.0.0/16")
        val subnet = joinerTunnel("c", "10.0.5.0/24")
        assertEquals(supernet,
            TunnelOverlapGuard.firstOverlap(subnet, listOf(supernet)))
    }

    @Test fun `disjoint joiner tunnels don't block each other`() {
        val a = joinerTunnel("a", "10.0.0.0/24")
        val cand = joinerTunnel("c", "192.168.1.0/24")
        assertNull(TunnelOverlapGuard.firstOverlap(cand, listOf(a)))
    }

    @Test fun `D4_J6 — three-joiner scenario rejects the third whose AllowedIPs overlap the first`() {
        // The joiner-N production model lets a user keep many joiner
        // tunnels active simultaneously. The overlap guard is the
        // load-bearing piece that prevents the user from configuring
        // an ambiguous routing scenario — two joiners both claiming
        // 10.99.0.0/24 would force gvisor to pick one arbitrarily
        // per the longest-prefix-match rules, which the user has no
        // way to predict.
        //
        // This test pins the invariant against future regressions:
        // when N joiners are already active, the guard MUST iterate
        // every one of them, not just the most-recently-added.  The
        // production ViewModel passes `activeTunnelIds` (D4.H2's
        // unified flow) verbatim, so the guard sees them all.
        val home = joinerTunnel("home", "10.99.0.0/24")
        val work = joinerTunnel("work", "192.168.5.0/24")
        // A third tunnel that overlaps `home` but is disjoint from
        // `work` — the guard must still report `home` as the conflict,
        // not silently allow because `work` didn't overlap.
        val collidesWithHome = joinerTunnel("hotel", "10.99.0.128/25")
        assertEquals(home,
            TunnelOverlapGuard.firstOverlap(collidesWithHome, listOf(home, work)))
    }

    @Test fun `full-tunnel joiner blocks any other tunnel`() {
        val fullTunnel = joinerTunnel("full", "0.0.0.0/0,::/0")
        val cand = joinerTunnel("narrow", "10.0.0.0/24")
        assertEquals(fullTunnel,
            TunnelOverlapGuard.firstOverlap(cand, listOf(fullTunnel)))
        // Symmetric: the narrow tunnel is already up; bringing up a
        // full-tunnel joiner must also be blocked.
        assertEquals(cand,
            TunnelOverlapGuard.firstOverlap(fullTunnel, listOf(cand)))
    }

    @Test fun `two host tunnels with overlapping subnets are blocked`() {
        // Two hosts both claiming 10.99.0.0/24 would assign the same
        // host-side address (10.99.0.1) to each WG interface — kernel
        // address conflict.
        val a = hostTunnel("a", "10.99.0.0/24")
        val cand = hostTunnel("c", "10.99.0.0/24")
        assertEquals(a, TunnelOverlapGuard.firstOverlap(cand, listOf(a)))
    }

    @Test fun `two host tunnels with disjoint subnets are not blocked`() {
        val a = hostTunnel("a", "10.99.0.0/24")
        val cand = hostTunnel("c", "10.100.0.0/24")
        assertNull(TunnelOverlapGuard.firstOverlap(cand, listOf(a)))
    }

    @Test fun `joiner candidate overlaps active host subnet`() {
        // If a host is up on 10.99.0.0/24, a new joiner with
        // AllowedIPs covering that range would create routing
        // ambiguity (kernel would have two routes to 10.99.0.0/24:
        // through the WG joiner interface and through the WG host
        // interface).
        val host = hostTunnel("h", "10.99.0.0/24")
        val joiner = joinerTunnel("j", "10.99.0.0/24")
        assertEquals(host,
            TunnelOverlapGuard.firstOverlap(joiner, listOf(host)))
    }

    @Test fun `host candidate overlaps active joiner AllowedIPs`() {
        val joiner = joinerTunnel("j", "10.99.0.0/24")
        val host = hostTunnel("h", "10.99.0.0/24")
        assertEquals(joiner,
            TunnelOverlapGuard.firstOverlap(host, listOf(joiner)))
    }

    @Test fun `first matching overlap is reported when multiple active`() {
        // Order matters for the returned value — the guard surfaces
        // *which* existing tunnel to mention in the error.  Both
        // active tunnels overlap the candidate; the iteration order
        // of `active` is what the test expects.
        val first = joinerTunnel("a", "10.0.0.0/24")
        val second = joinerTunnel("b", "10.0.0.0/16")
        val cand = joinerTunnel("c", "10.0.0.5/32")
        assertEquals(first,
            TunnelOverlapGuard.firstOverlap(cand, listOf(first, second)))
        // Same active set, different iteration order → different
        // attribution.  Documents the contract rather than locking
        // in stability.
        assertEquals(second,
            TunnelOverlapGuard.firstOverlap(cand, listOf(second, first)))
    }

    @Test fun `host without subnet falls back to no claim`() {
        // Defensive: a HOST_MODE tunnel with a null hostMode (data
        // corruption) shouldn't crash the guard; it just contributes
        // no ranges.
        val malformed = Tunnel(
            id = "malformed", name = "malformed",
            configText = "[Interface]\nPrivateKey = AAA\n",
            source = Tunnel.Source.HOST_MODE,
            hostMode = null,
        )
        val cand = joinerTunnel("c", "10.0.0.0/24")
        assertNull(TunnelOverlapGuard.firstOverlap(cand, listOf(malformed)))
    }

    @Test fun `tunnel without AllowedIPs lines contributes no claim`() {
        // configText with [Interface] only (e.g. partial enrollment
        // state).  Should not block anything.
        val partial = Tunnel(
            id = "partial", name = "partial",
            configText = "[Interface]\nPrivateKey = AAA\nAddress = 10.0.0.2/32",
            source = Tunnel.Source.LEGACY,
        )
        val cand = joinerTunnel("c", "10.0.0.0/24")
        assertNull(TunnelOverlapGuard.firstOverlap(cand, listOf(partial)))
    }
}
