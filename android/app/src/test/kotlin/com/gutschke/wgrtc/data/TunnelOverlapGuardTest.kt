package com.gutschke.wgrtc.data

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

/**
 * Unit tests for [TunnelOverlapGuard].
 *
 * The guard is the UI's pre-Connect check: before bringing tunnel X
 * up, ask "would X's claimed address range share an identical CIDR
 * with any tunnel that's already up?"  If yes, surface a user-visible
 * error rather than silently letting kernel routing pick a winner.
 *
 * **CASCADE-1 (2026-05-17): LPM-resolvable overlaps are NOT
 * conflicts.**  Two tunnels with `0.0.0.0/0` (full-tunnel joiner)
 * and `10.99.0.0/24` (host-mode subnet) coexist cleanly because
 * kernel longest-prefix-match picks the /24 for that subnet and
 * the /0 catches the rest.  The guard refuses only
 * *identical-prefix* collisions (same network address AND same
 * prefix length).
 *
 * Today only one tunnel can be active at a time per source (see
 * `HostModeBackend.start()`'s `check(activeId == null)` and
 * `JoinerWgRunner.start()`'s analogue) so this guard is mostly a
 * dormant safety net.  Once those single-instance restrictions
 * fully come out and concurrent host + joiner is supported (D4
 * lifted that for joiner-N already; host-N is pending), the guard
 * becomes load-bearing for catching genuine config mistakes.
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

    // ----- baseline behavior --------------------------------------------

    @Test fun `empty active list never blocks`() {
        val cand = joinerTunnel("c", "10.0.0.0/24")
        assertNull(TunnelOverlapGuard.firstOverlap(cand, emptyList()))
    }

    @Test fun `the candidate matches itself in the list and is skipped`() {
        // Re-activating tunnel X must not be blocked by X appearing in
        // the "active" set with overlapping ranges.
        val cand = joinerTunnel("c", "10.0.0.0/24")
        assertNull(TunnelOverlapGuard.firstOverlap(cand, listOf(cand)))
    }

    @Test fun `disjoint joiner tunnels don't block each other`() {
        val a = joinerTunnel("a", "10.0.0.0/24")
        val cand = joinerTunnel("c", "192.168.1.0/24")
        assertNull(TunnelOverlapGuard.firstOverlap(cand, listOf(a)))
    }

    // ----- identical-prefix conflicts (the only real conflicts) ---------

    @Test fun `two joiner tunnels with identical AllowedIPs are blocked`() {
        val a = joinerTunnel("a", "10.0.0.0/24")
        val cand = joinerTunnel("c", "10.0.0.0/24")
        assertEquals(a, TunnelOverlapGuard.firstOverlap(cand, listOf(a)))
    }

    @Test fun `two host tunnels with identical subnets are blocked`() {
        // Two hosts both claiming 10.99.0.0/24 would assign the same
        // host-side address (10.99.0.1) to each WG interface — kernel
        // address conflict.
        val a = hostTunnel("a", "10.99.0.0/24")
        val cand = hostTunnel("c", "10.99.0.0/24")
        assertEquals(a, TunnelOverlapGuard.firstOverlap(cand, listOf(a)))
    }

    @Test fun `joiner candidate with identical CIDR as active host subnet blocked`() {
        // Host on 10.99.0.0/24, new joiner with AllowedIPs covering the
        // same /24 — identical claim, kernel would have two routes to
        // the same destination with no way to pick.
        val host = hostTunnel("h", "10.99.0.0/24")
        val joiner = joinerTunnel("j", "10.99.0.0/24")
        assertEquals(host,
            TunnelOverlapGuard.firstOverlap(joiner, listOf(host)))
    }

    @Test fun `host candidate with identical CIDR as active joiner AllowedIPs blocked`() {
        val joiner = joinerTunnel("j", "10.99.0.0/24")
        val host = hostTunnel("h", "10.99.0.0/24")
        assertEquals(joiner,
            TunnelOverlapGuard.firstOverlap(host, listOf(joiner)))
    }

    @Test fun `IPv6 identical-prefix collision blocked`() {
        val a = joinerTunnel("a", "fd00::/64")
        val cand = joinerTunnel("c", "fd00::/64")
        assertEquals(a, TunnelOverlapGuard.firstOverlap(cand, listOf(a)))
    }

    // ----- LPM-resolvable overlaps (NOT conflicts since CASCADE-1) ------

    @Test fun `CASCADE-1 — joiner full-tunnel and host subnet coexist`() {
        // The literal CASCADE-1 scenario reported 2026-05-17:
        //   wgrtc joiner-mode tunnel: AllowedIPs = 0.0.0.0/0, ::/0
        //     (outbound to external WG server)
        //   wgrtc host-mode tunnel:   subnet 10.99.0.0/24
        //     (accepts incoming WG joiners)
        // Pre-CASCADE-1 the guard refused this because 10.99.0.0/24
        // is *inside* 0.0.0.0/0 (range overlap).  Post-fix this is
        // a legitimate cascade configuration — kernel LPM routes
        // 10.99.0.x via the host tun, everything else via the joiner
        // tun.  No ambiguity.
        val outbound = joinerTunnel("out", "0.0.0.0/0, ::/0")
        val cascadeHost = hostTunnel("cascade", "10.99.0.0/24")
        assertNull(TunnelOverlapGuard.firstOverlap(cascadeHost, listOf(outbound)))
        assertNull(TunnelOverlapGuard.firstOverlap(outbound, listOf(cascadeHost)))
    }

    @Test fun `two joiner tunnels with subset relationship don't block (LPM resolves)`() {
        val supernet = joinerTunnel("a", "10.0.0.0/16")
        val subnet = joinerTunnel("c", "10.0.5.0/24")
        // /16 catches everything in 10.0.x.x EXCEPT 10.0.5.x, which
        // the /24 takes via LPM.  Both routes coexist deterministically.
        assertNull(TunnelOverlapGuard.firstOverlap(subnet, listOf(supernet)))
        assertNull(TunnelOverlapGuard.firstOverlap(supernet, listOf(subnet)))
    }

    @Test fun `host subnet inside joiner full-tunnel doesn't block`() {
        // Generalization of the CASCADE-1 case for arbitrary subnet
        // sizes — as long as the prefixes differ, LPM resolves.
        val fullTunnel = joinerTunnel("full", "0.0.0.0/0, ::/0")
        val host = hostTunnel("h", "10.99.0.0/24")
        assertNull(TunnelOverlapGuard.firstOverlap(host, listOf(fullTunnel)))
        assertNull(TunnelOverlapGuard.firstOverlap(fullTunnel, listOf(host)))
    }

    @Test fun `IPv6 LPM-resolvable overlap doesn't block`() {
        // Same as the v4 case but for v6: joiner advertises ::/0,
        // host claims fd00::/64.  LPM resolves.
        val v6FullTunnel = joinerTunnel("v6full", "::/0")
        val v6Host = hostTunnel("v6host", "fd00::/64")
        assertNull(TunnelOverlapGuard.firstOverlap(v6Host, listOf(v6FullTunnel)))
        assertNull(TunnelOverlapGuard.firstOverlap(v6FullTunnel, listOf(v6Host)))
    }

    @Test fun `joiner host-route inside joiner subnet doesn't block`() {
        // /32 (host route) inside a /24 — different prefix lengths,
        // LPM picks /32 for that one address, /24 for the rest.
        val subnet = joinerTunnel("net", "10.99.0.0/24")
        val hostRoute = joinerTunnel("host", "10.99.0.5/32")
        assertNull(TunnelOverlapGuard.firstOverlap(hostRoute, listOf(subnet)))
        assertNull(TunnelOverlapGuard.firstOverlap(subnet, listOf(hostRoute)))
    }

    // ----- multi-active iteration ---------------------------------------

    @Test fun `multiple actives — first identical-prefix match is reported`() {
        val first = joinerTunnel("a", "10.99.0.0/24")
        val second = joinerTunnel("b", "10.99.0.0/24")
        val cand = joinerTunnel("c", "10.99.0.0/24")
        // Both `first` and `second` collide.  Iteration order picks first.
        assertEquals(first,
            TunnelOverlapGuard.firstOverlap(cand, listOf(first, second)))
        assertEquals(second,
            TunnelOverlapGuard.firstOverlap(cand, listOf(second, first)))
    }

    @Test fun `multiple actives — LPM-resolvable overlap with one, identical-prefix with another`() {
        // `wide` (10.0.0.0/16) and `cand` (10.0.5.0/24) are LPM-resolvable.
        // `narrow` (10.0.5.0/24) and `cand` are identical-prefix.
        // Guard must skip past `wide` to find the actual conflict.
        val wide = joinerTunnel("wide", "10.0.0.0/16")
        val narrow = joinerTunnel("narrow", "10.0.5.0/24")
        val cand = joinerTunnel("cand", "10.0.5.0/24")
        assertEquals(narrow,
            TunnelOverlapGuard.firstOverlap(cand, listOf(wide, narrow)))
    }

    @Test fun `disjoint host plus full-tunnel joiner — neither blocks new joiner`() {
        // Realistic concurrent-tunnel scenario: a host on 10.99.0.0/24
        // accepts incoming joiners, a full-tunnel joiner provides
        // outbound, and we want to bring up a *third* joiner targeting
        // a different LAN (10.50.0.0/24).  Nothing should be blocked.
        val host = hostTunnel("host", "10.99.0.0/24")
        val outbound = joinerTunnel("out", "0.0.0.0/0, ::/0")
        val newJoiner = joinerTunnel("lan", "10.50.0.0/24")
        assertNull(
            TunnelOverlapGuard.firstOverlap(newJoiner, listOf(host, outbound)))
    }

    // ----- defensive: malformed input never crashes ---------------------

    @Test fun `host without subnet falls back to no claim`() {
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
        val partial = Tunnel(
            id = "partial", name = "partial",
            configText = "[Interface]\nPrivateKey = AAA\nAddress = 10.0.0.2/32",
            source = Tunnel.Source.LEGACY,
        )
        val cand = joinerTunnel("c", "10.0.0.0/24")
        assertNull(TunnelOverlapGuard.firstOverlap(cand, listOf(partial)))
    }
}
