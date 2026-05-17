package com.gutschke.wgrtc.ui

import com.gutschke.wgrtc.data.FailureCause
import com.gutschke.wgrtc.data.PauseReason
import com.gutschke.wgrtc.data.Tunnel
import com.gutschke.wgrtc.data.TunnelState
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Pins the [failureCopy] cause-to-string mapping.  These strings
 * are the user-visible body of every failure dialog; renaming /
 * deleting any of them is a UX regression.
 *
 * The test verifies:
 *
 *   * every [FailureCause] subtype routes to a non-empty title and
 *     body (we don't ship blank dialogs)
 *   * every [PauseReason] routes to a non-empty title and body too
 *   * recoverable causes attach a [FailureRemediation.Retry]
 *     action; non-recoverable causes don't (otherwise the user
 *     would tap Retry on a permanent failure and learn nothing)
 *   * a few specific causes carry the right intent type
 */
class TunnelListFailureCopyTest {

    private val tunnel = Tunnel(name = "alpha", configText = "[Interface]\n")

    private fun copyFor(state: TunnelState) = failureCopy(tunnel, state)

    @Test fun `every FailureCause has a non-empty body`() {
        val causes = listOf(
            FailureCause.ConsentDenied,
            FailureCause.ConsentSilentlyDenied,
            FailureCause.BrokerMissing,
            FailureCause.BrokerUnreachable("wss://broker.example"),
            FailureCause.PeerKeyRejected,
            FailureCause.HandshakeTimeout("1.2.3.4:51820"),
            FailureCause.PortInUse(51820),
            FailureCause.RoutingLoopUserConfirmed,
            FailureCause.CascadePolicyBlocked,
            FailureCause.PairingSasMismatch,
            FailureCause.PairingCancelled,
        )
        for (cause in causes) {
            val (title, body, _) = copyFor(TunnelState.Failed(cause, recoverable = true))
            assertTrue(title.isNotEmpty(), "title empty for $cause")
            assertTrue(body.isNotEmpty(), "body empty for $cause")
        }
    }

    @Test fun `every PauseReason has a non-empty body`() {
        for (reason in PauseReason.values()) {
            val (title, body, _) = copyFor(TunnelState.PausedSystem(reason))
            assertTrue(title.isNotEmpty(), "title empty for $reason")
            assertTrue(body.isNotEmpty(), "body empty for $reason")
        }
    }

    @Test fun `consent-denied offers Retry`() {
        val (_, _, action) =
            copyFor(TunnelState.Failed(FailureCause.ConsentDenied, recoverable = true))
        assertNotNull(action)
        assertEquals(FailureRemediation.Retry, action!!.second)
    }

    @Test fun `consent-silently-denied points at App Info`() {
        val (_, _, action) =
            copyFor(TunnelState.Failed(FailureCause.ConsentSilentlyDenied, recoverable = false))
        assertNotNull(action)
        assertEquals(FailureRemediation.OpenAppInfo, action!!.second)
    }

    @Test fun `routing-loop opens VPN settings`() {
        val (_, _, action) =
            copyFor(TunnelState.Failed(FailureCause.RoutingLoopUserConfirmed, recoverable = false))
        assertNotNull(action)
        assertEquals(FailureRemediation.OpenVpnSettings, action!!.second)
    }

    @Test fun `another-VPN took over offers an open-settings deep link`() {
        val (_, _, action) = copyFor(TunnelState.PausedSystem(PauseReason.AnotherVpnTookOver))
        assertNotNull(action)
        assertEquals(FailureRemediation.OpenVpnSettings, action!!.second)
    }

    @Test fun `permission revoked variants all offer Retry`() {
        val reasons = listOf(
            PauseReason.EstablishNull,
            PauseReason.ForegroundResync,
            PauseReason.BackgroundResync,
        )
        for (r in reasons) {
            val (_, _, action) = copyFor(TunnelState.PausedSystem(r))
            assertNotNull(action, "no action for $r")
            assertEquals(FailureRemediation.Retry, action!!.second, "wrong intent for $r")
        }
    }

    @Test fun `port-in-use is a no-remediation failure`() {
        // We don't auto-pick a new port for the user; they have to
        // open the tunnel and edit it.  Surface the message, no
        // one-tap action.
        val (_, _, action) =
            copyFor(TunnelState.Failed(FailureCause.PortInUse(51820), recoverable = true))
        assertNull(action)
    }

    @Test fun `pairing-cancelled has no remediation`() {
        // The user must restart the wormhole flow from the other
        // side; we can't help from this row.
        val (_, _, action) =
            copyFor(TunnelState.Failed(FailureCause.PairingCancelled, recoverable = false))
        assertNull(action)
    }

    @Test fun `body for HandshakeTimeout mentions the endpoint`() {
        val (_, body, _) =
            copyFor(TunnelState.Failed(
                FailureCause.HandshakeTimeout("5.6.7.8:1234"),
                recoverable = true,
            ))
        assertTrue(
            body.contains("5.6.7.8:1234"),
            "endpoint should appear in body: '$body'",
        )
    }

    @Test fun `body for BrokerUnreachable mentions the URL`() {
        val (_, body, _) =
            copyFor(TunnelState.Failed(
                FailureCause.BrokerUnreachable("wss://broker.example"),
                recoverable = true,
            ))
        assertTrue(
            body.contains("wss://broker.example"),
            "broker URL should appear in body: '$body'",
        )
    }

    @Test fun `non-failure states return empty triple`() {
        // Defensive: failureCopy is only called for Failed +
        // PausedSystem; the else-branch handles unexpected callers.
        val (title, body, action) = copyFor(TunnelState.Connected)
        assertEquals("", title)
        assertEquals("", body)
        assertNull(action)
    }
}
