package com.gutschke.wgrtc.data

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * V6.A3 — outer-family-aware MTU defaults.
 *
 * The existing `MtuMathTest` pins the arithmetic for both families
 * (`safeWgMtu(1500, IPv4) = 1420`, `safeWgMtu(1500, IPv6) = 1400`,
 * `safeWgMtu(1280, IPv6) = 1180`, etc.).  What was missing prior to
 * V6.A3 is an *API-level* knob that lets the joiner / host pick the
 * right default at runtime based on the *actual* endpoint family —
 * the old `DEFAULT_WG_MTU` constant baked in the v4 answer.
 *
 * Why this matters: a wg-quick config that omits `MTU = …` and
 * names a v6 Endpoint (`[2001:db8::1]:51820`) needs 1400, not 1420
 * — otherwise a 1500-byte path-MTU has zero safety margin and the
 * 20-byte allowance against PPPoE / GRE / mid-path NAT64 is gone.
 * See `docs/wireguard-runtime-architecture.md` §5.
 *
 * These tests pin:
 *
 * 1. `defaultWgMtu(IPv4) == 1420` (= existing `DEFAULT_WG_MTU`).
 * 2. `defaultWgMtu(IPv6) == 1400`.
 * 3. The defaults match what `safeWgMtu(1500, …)` produces for
 *    each family — the redundancy catches drift if someone bumps
 *    SAFETY_MARGIN in one place but not the other.
 * 4. `inferOuterFamily` correctly classifies bracketed v6, bare v6,
 *    dotted-quad v4, and tolerates `host:port` strings.
 */
class MtuMathV6Test {

    @Test fun `defaultWgMtu(v4) is 1420`() {
        assertEquals(1420, MtuMath.defaultWgMtu(MtuMath.OuterFamily.IPV4))
    }

    @Test fun `defaultWgMtu(v6) is 1400`() {
        assertEquals(1400, MtuMath.defaultWgMtu(MtuMath.OuterFamily.IPV6))
    }

    @Test fun `defaultWgMtu(v4) agrees with safeWgMtu(1500, v4)`() {
        assertEquals(
            MtuMath.defaultWgMtu(MtuMath.OuterFamily.IPV4),
            MtuMath.safeWgMtu(physicalMtu = 1500, outer = MtuMath.OuterFamily.IPV4),
            "v4 default drifted from safeWgMtu(1500, v4)",
        )
    }

    @Test fun `defaultWgMtu(v6) agrees with safeWgMtu(1500, v6)`() {
        assertEquals(
            MtuMath.defaultWgMtu(MtuMath.OuterFamily.IPV6),
            MtuMath.safeWgMtu(physicalMtu = 1500, outer = MtuMath.OuterFamily.IPV6),
            "v6 default drifted from safeWgMtu(1500, v6) — drop SAFETY_MARGIN " +
                "in one place but not the other?",
        )
    }

    @Test fun `DEFAULT_WG_MTU constant matches defaultWgMtu(v4)`() {
        // Both `DEFAULT_WG_MTU` and `defaultWgMtu(IPV4)` live in
        // MtuMath; pin the equivalence so a v6-aware refactor that
        // changes one but not the other fails loudly.
        assertEquals(MtuMath.DEFAULT_WG_MTU, MtuMath.defaultWgMtu(MtuMath.OuterFamily.IPV4))
    }

    // ── inferOuterFamily — endpoint-family classifier ────────

    @Test fun `inferOuterFamily classifies bare dotted-quad as v4`() {
        assertEquals(MtuMath.OuterFamily.IPV4, MtuMath.inferOuterFamily("203.0.113.5"))
    }

    @Test fun `inferOuterFamily classifies host_port as v4`() {
        // Real wg-quick lines have `host:port`; we still want
        // v4 (the colon isn't a hex group, it's the port separator).
        assertEquals(MtuMath.OuterFamily.IPV4, MtuMath.inferOuterFamily("203.0.113.5:51820"))
    }

    @Test fun `inferOuterFamily classifies bare v6 as v6`() {
        assertEquals(MtuMath.OuterFamily.IPV6, MtuMath.inferOuterFamily("2001:db8::5"))
        assertEquals(MtuMath.OuterFamily.IPV6, MtuMath.inferOuterFamily("fd00::1"))
        assertEquals(MtuMath.OuterFamily.IPV6, MtuMath.inferOuterFamily("::1"))
    }

    @Test fun `inferOuterFamily classifies bracketed v6 with port as v6`() {
        assertEquals(MtuMath.OuterFamily.IPV6, MtuMath.inferOuterFamily("[2001:db8::5]:51820"))
        assertEquals(MtuMath.OuterFamily.IPV6, MtuMath.inferOuterFamily("[fd00::1]:51820"))
    }

    @Test fun `inferOuterFamily defaults to v4 on malformed input`() {
        // A garbage string with no colon AND no dots — we have no
        // basis to classify.  Defaulting to v4 means a future bug
        // produces 1420 (v4 default, safe for v4-outer or v6-outer
        // since the 20-byte margin is wider than the v6 vs. v4
        // overhead delta of 20).  Safer than crashing the parser.
        assertEquals(MtuMath.OuterFamily.IPV4, MtuMath.inferOuterFamily("not-an-endpoint"))
        assertEquals(MtuMath.OuterFamily.IPV4, MtuMath.inferOuterFamily(""))
    }

    @Test fun `inferOuterFamily handles DNS-style hostnames as v4`() {
        // wg-quick allows `Endpoint = vpn.example.org:51820`; the
        // family is only known at resolve-time.  Defaulting to v4
        // is the safest choice — see comment on the malformed case
        // above.  This will eventually be revisited when joiner
        // resolves the host (V6.5).
        assertEquals(MtuMath.OuterFamily.IPV4,
            MtuMath.inferOuterFamily("vpn.example.org:51820"))
    }
}
