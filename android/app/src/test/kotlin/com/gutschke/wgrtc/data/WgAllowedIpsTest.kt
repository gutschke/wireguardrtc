package com.gutschke.wgrtc.data

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * **canonicalizer tests.**
 *
 * The cases below pin both the happy path (what most users type)
 * AND the adversarial-input cases (the user pastes a config with
 * mixed whitespace, our prior defaults with spaces, etc.).
 */
class WgAllowedIpsTest {

    @Test fun singleEntryPassesThrough() {
        assertEquals("10.0.0.0/24",
            WgAllowedIps.canonicalize("10.0.0.0/24"))
    }

    @Test fun stripsSpaceAfterComma() {
        assertEquals("10.0.0.0/24,192.168.1.0/24",
            WgAllowedIps.canonicalize("10.0.0.0/24, 192.168.1.0/24"))
    }

    @Test fun stripsMultipleSpaces() {
        assertEquals("0.0.0.0/0,::/0",
            WgAllowedIps.canonicalize("0.0.0.0/0, ::/0"))
    }

    @Test fun stripsSpaceBeforeComma() {
        assertEquals("10.0.0.0/24,192.168.1.0/24",
            WgAllowedIps.canonicalize("10.0.0.0/24 ,192.168.1.0/24"))
    }

    @Test fun stripsLeadingAndTrailingWhitespace() {
        assertEquals("10.0.0.0/24,192.168.1.0/24",
            WgAllowedIps.canonicalize(" 10.0.0.0/24 , 192.168.1.0/24 "))
    }

    @Test fun stripsTabsAndOtherWhitespace() {
        assertEquals("10.0.0.0/24,::/0",
            WgAllowedIps.canonicalize("10.0.0.0/24,\t::/0"))
    }

    @Test fun emptyStaysEmpty() {
        // Caller decides whether empty AllowedIPs is an error — we
        // just return what we got.
        assertEquals("", WgAllowedIps.canonicalize(""))
    }

    @Test fun onlySeparatorsCollapseToEmpty() {
        assertEquals("", WgAllowedIps.canonicalize(","))
        assertEquals("", WgAllowedIps.canonicalize(", , ,"))
    }

    @Test fun dropsEmptyEntriesFromBadInput() {
        // Trailing comma after good input — sometimes happens when
        // a user copy-pastes.
        assertEquals("10.0.0.0/24,192.168.1.0/24",
            WgAllowedIps.canonicalize("10.0.0.0/24,,192.168.1.0/24,"))
    }

    @Test fun dualStackFullTunnelDefaultIsCanonical() {
        // The compiled-in default is what we'll most often emit —
        // pin it explicitly so a future "let's pretty-print this"
        // refactor can't silently re-introduce a space.
        assertEquals("0.0.0.0/0,::/0", WgAllowedIps.FULL_TUNNEL)
        // Re-canonicalize the canonical form to confirm idempotence.
        assertEquals(WgAllowedIps.FULL_TUNNEL,
            WgAllowedIps.canonicalize(WgAllowedIps.FULL_TUNNEL))
    }

    @Test fun ipv6PassesThrough() {
        assertEquals("fd00::/8,2001:db8::/32",
            WgAllowedIps.canonicalize("fd00::/8, 2001:db8::/32"))
    }

    @Test fun mixedV4AndV6PassesThrough() {
        assertEquals("10.0.0.0/8,fd00::/8,192.168.0.0/16",
            WgAllowedIps.canonicalize("10.0.0.0/8, fd00::/8, 192.168.0.0/16"))
    }
}
