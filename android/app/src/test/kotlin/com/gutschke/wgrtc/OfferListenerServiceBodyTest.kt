package com.gutschke.wgrtc

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * D4.H3 — pure-text helpers used by the FGS notification body. Kept
 * separate from any Android / Notification builder code so a JVM unit
 * test can pin the wording without spinning up Robolectric.
 */
class OfferListenerServiceBodyTest {

    // ───────────────────── collapsedBodyText ─────────────────────

    @Test
    fun `count zero collapsed says listening for endpoint updates`() {
        assertEquals(
            "wgrtc — listening for endpoint updates",
            OfferListenerService.collapsedBodyText(0),
        )
    }

    @Test
    fun `count one collapsed is singular tunnel`() {
        assertEquals(
            "wgrtc — tracking 1 tunnel",
            OfferListenerService.collapsedBodyText(1),
        )
    }

    @Test
    fun `count many collapsed is plural tunnels`() {
        assertEquals(
            "wgrtc — tracking 3 tunnels",
            OfferListenerService.collapsedBodyText(3),
        )
    }

    // ───────────────────── expandedBodyText ─────────────────────

    @Test
    fun `expanded with no listeners matches collapsed`() {
        // count=0 → no point in a separate expanded body even if the
        // caller passed names by accident.
        assertEquals(
            OfferListenerService.collapsedBodyText(0),
            OfferListenerService.expandedBodyText(0, listOf("Home")),
        )
    }

    @Test
    fun `expanded with empty names matches collapsed`() {
        // Before the store loads, the service falls through with an
        // empty list — the expanded body should then match the
        // collapsed line so callers can skip BigText entirely.
        assertEquals(
            OfferListenerService.collapsedBodyText(2),
            OfferListenerService.expandedBodyText(2, emptyList()),
        )
    }

    @Test
    fun `expanded with two names lists both comma-separated`() {
        val body = OfferListenerService.expandedBodyText(2, listOf("Home", "Office"))
        assertEquals(
            "wgrtc — tracking 2 tunnels\nHome, Office",
            body,
        )
    }

    @Test
    fun `expanded caps the visible list at five and trails plus-K-more`() {
        // Seven tunnels → first five shown, "+2 more" trailing so the
        // grand total stays legible.
        val names = (1..7).map { "T$it" }
        val body = OfferListenerService.expandedBodyText(7, names)
        assertEquals(
            "wgrtc — tracking 7 tunnels\nT1, T2, T3, T4, T5, +2 more",
            body,
        )
    }

    @Test
    fun `expanded at exactly the cap does not show plus-zero-more`() {
        val names = (1..5).map { "T$it" }
        val body = OfferListenerService.expandedBodyText(5, names)
        // Trailing "+0 more" would be ugly; the boundary case sticks
        // to the plain comma list.
        assertEquals(
            "wgrtc — tracking 5 tunnels\nT1, T2, T3, T4, T5",
            body,
        )
    }
}
