package com.gutschke.wgrtc.data

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Pin the contract of [shouldPersistRaceWinner]: same-subnet (LAN)
 * race winners must NOT be persisted to the wg-quick config; non-
 * same-subnet winners (typically public/STUN addresses) MUST be.
 *
 * The "must not persist LAN" half is load-bearing: persisting a LAN
 * endpoint bricks the tunnel after the user moves to a different
 * network — the persisted address becomes unreachable, the listener
 * cache starts empty after process restart, and there's no public-IP
 * fallback. Caught a hard deadlock during the 2026-05-08 debug
 * session.
 *
 * The "must persist universal" half preserves the original behavior:
 * after a public-IP race wins, the persisted Endpoint reflects the
 * working address so the next process startup can connect even with
 * an empty cache.
 */
class ShouldPersistRaceWinnerTest {

    @Test fun `null egressInterface (universal address) is persisted`() {
        assertTrue(shouldPersistRaceWinner(null),
            "candidate with no local-interface match should be persisted " +
            "as the next-startup fallback")
    }

    @Test fun `non-null egressInterface (LAN match) is NOT persisted`() {
        assertFalse(shouldPersistRaceWinner("wlan0"),
            "candidate that matched a local interface is environment-" +
            "specific; persisting it bricks the tunnel after network change")
    }

    @Test fun `empty-string egressInterface is treated as same-subnet`() {
        // Defensive: an empty string is non-null. If the picker ever
        // returns "" (it shouldn't), still treat as "matched a local
        // interface, don't persist."
        assertFalse(shouldPersistRaceWinner(""))
    }

    @Test fun `interface name with non-wlan prefix still suppresses persist`() {
        // Picker may name the iface anything (eth0, ap0, rmnet, etc.).
        // The decision is purely "is it null", not name-pattern based.
        assertFalse(shouldPersistRaceWinner("eth0"))
        assertFalse(shouldPersistRaceWinner("rmnet0"))
        assertFalse(shouldPersistRaceWinner("ap0"))
    }
}
