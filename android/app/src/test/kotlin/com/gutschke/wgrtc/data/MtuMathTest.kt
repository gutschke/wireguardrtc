package com.gutschke.wgrtc.data

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

/**
 * Pins the WireGuard MTU math. Every number in this file is
 * load-bearing for real deployments — the user's stated PMTU
 * pain ("had to tweak firewall rules a few times to make PMTU
 * work reliably for other types of tunnels") translates here as
 * "don't get any of these constants wrong, and don't rely on
 * runtime PMTU discovery." Conservative defaults + MSS clamping
 * are our defense against silent fragmentation black holes.
 *
 * See also `docs/wireguard-runtime-architecture.md` §5 for the
 * conceptual notes; this test pins the concrete numbers.
 */
class MtuMathTest {

    // ── Overhead constants ────────────────────────────────────

    @Test fun `WG overhead over IPv4 outer is 60 bytes`() {
        // 20 (IP) + 8 (UDP) + 32 (WG transport header + AEAD tag)
        //
        // The WG transport-data header is 16 bytes (type, reserved,
        // receiver index, counter); the Poly1305 authenticator
        // adds another 16. Numbers checked against
        // golang.zx2c4.com/wireguard/conn/Bind.MTU computation.
        assertEquals(60, MtuMath.wgOverhead(MtuMath.OuterFamily.IPV4))
    }

    @Test fun `WG overhead over IPv6 outer is 80 bytes`() {
        // 40 (IPv6 header) + 8 (UDP) + 32 (WG framing + auth)
        assertEquals(80, MtuMath.wgOverhead(MtuMath.OuterFamily.IPV6))
    }

    // ── safeWgMtu — the inner MTU we tell apps to use ────────

    @Test fun `physical 1500 with IPv4 outer leaves 1440 - clamped to 1420 by safety margin`() {
        // 1500 - 60 = 1440 mathematically possible. We subtract
        // an additional 20-byte safety margin to dodge:
        // - 8-byte PPPoE overhead some carriers add silently
        // - Path-private GRE wrappers on enterprise links
        // - Carrier-level NAT64 introducing v6 outer encap
        // mid-path (10-20 byte hit)
        // 1420 is what every published WG guide recommends. We
        // pin it here so a future "let's bump it" change has to
        // delete the test and re-justify.
        assertEquals(1420, MtuMath.safeWgMtu(physicalMtu = 1500, outer = MtuMath.OuterFamily.IPV4))
    }

    @Test fun `physical 1500 with IPv6 outer is 1400`() {
        // 1500 - 80 = 1420 raw; minus the 20-byte margin = 1400.
        assertEquals(1400, MtuMath.safeWgMtu(physicalMtu = 1500, outer = MtuMath.OuterFamily.IPV6))
    }

    @Test fun `pessimistic cellular 1280 with IPv6 outer is 1180`() {
        // RFC 8200 guarantees IPv6 path MTU >= 1280. Cellular
        // networks often sit exactly at 1280 for IPv6. Raw
        // computation: 1280 - 80 (overhead) - 20 (safety margin)
        // = 1180. We deliberately KEEP the safety margin even
        // at the IPv6 floor — operators have surprised us with
        // PPPoE-style headers below the guaranteed minimum more
        // than once; consistency beats squeezing the last 20
        // bytes. An app that needs to push large payloads
        // through here will pay in throughput; nothing we can
        // do at this layer.
        assertEquals(1180, MtuMath.safeWgMtu(physicalMtu = 1280, outer = MtuMath.OuterFamily.IPV6))
    }

    @Test fun `tiny physical MTU near or below overhead returns the floor`() {
        // 100-byte physical with 60-byte overhead would compute
        // to 20 — below sensible. We refuse to go below
        // [MtuMath.MIN_USEFUL_MTU] (576, the IPv4 minimum
        // re-assembly buffer guarantee). Returning a too-small
        // MTU silently is worse than failing loudly; we surface
        // this as an exception to the caller, who can decide:
        // refuse the deployment, warn the user, fall back to a
        // different egress.
        assertThrows(IllegalArgumentException::class.java) {
            MtuMath.safeWgMtu(physicalMtu = 100, outer = MtuMath.OuterFamily.IPV4)
        }
    }

    // ── tcpMssClamp — what we put in the SYN's MSS option ────

    @Test fun `TCP MSS for wgMtu 1420 IPv4 inner is 1380`() {
        // MSS = inner MTU - 20 (IPv4 inner header) - 20 (TCP
        // header). This is what we'd splice into a SYN before
        // forwarding it. If gvisor's TCP forwarder doesn't
        // honor PMTU+MSS-clamping on its own, we override.
        assertEquals(1380, MtuMath.tcpMssClamp(wgMtu = 1420, innerFamily = MtuMath.InnerFamily.IPV4))
    }

    @Test fun `TCP MSS for wgMtu 1420 IPv6 inner is 1360`() {
        // 1420 - 40 (IPv6 header) - 20 (TCP) = 1360.
        assertEquals(1360, MtuMath.tcpMssClamp(wgMtu = 1420, innerFamily = MtuMath.InnerFamily.IPV6))
    }

    @Test fun `TCP MSS clamping floor protects against pathological inputs`() {
        // Inner MTU smaller than (20 + 20 + 1) — the smallest
        // useful TCP segment is 1 byte of payload — would yield
        // an absurd MSS. Clamp to the IPv4 default-MSS floor
        // (536 — RFC 1122 mandated minimum that all IPv4
        // implementations must support without negotiation).
        assertEquals(536, MtuMath.tcpMssClamp(wgMtu = 100, innerFamily = MtuMath.InnerFamily.IPV4))
    }

    @Test fun `negative or zero inputs are rejected at the boundary`() {
        assertThrows(IllegalArgumentException::class.java) {
            MtuMath.safeWgMtu(physicalMtu = 0, outer = MtuMath.OuterFamily.IPV4)
        }
        assertThrows(IllegalArgumentException::class.java) {
            MtuMath.tcpMssClamp(wgMtu = 0, innerFamily = MtuMath.InnerFamily.IPV4)
        }
    }

    // ── Default policy ────────────────────────────────────────

    @Test fun `DEFAULT_WG_MTU matches what the conservative path produces`() {
        // The single most-used MTU constant in the codebase. If
        // a future review nudges this, all downstream tests +
        // user-visible defaults move with it; pin both endpoints
        // here so the change is loud.
        assertEquals(1420, MtuMath.DEFAULT_WG_MTU)
        assertEquals(
            MtuMath.DEFAULT_WG_MTU,
            MtuMath.safeWgMtu(physicalMtu = 1500, outer = MtuMath.OuterFamily.IPV4),
            "DEFAULT_WG_MTU drifted from safeWgMtu(1500, v4) — pick one place to change."
        )
    }
}
