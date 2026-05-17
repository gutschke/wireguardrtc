package com.gutschke.wgrtc.data

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class TunnelStateRegistryTest {

    /** A registry whose clock returns a predictable sequence so
     *  TransitionEntry.timestampMs is reproducible across runs. */
    private class FakeClock {
        private var t = 1_000L
        val source: () -> Long = { t++ }
        fun advance(by: Long) { t += by }
    }

    @Test fun `freshly-seen tunnel starts in Disabled`() {
        val r = TunnelStateRegistry()
        val s = r.stateOf("alpha")
        assertEquals(TunnelState.Disabled, s.value)
        // Reading state should not produce a transition log entry —
        // the log is for actual transitions only.
        assertTrue(r.transitionLog("alpha").isEmpty())
    }

    @Test fun `transition emits and logs`() {
        val clock = FakeClock()
        val r = TunnelStateRegistry(clock = clock.source)
        r.transition("alpha", TunnelState.Arming, note = "user tapped Connect")
        val s = r.stateOf("alpha")
        assertEquals(TunnelState.Arming, s.value)
        val log = r.transitionLog("alpha")
        assertEquals(1, log.size)
        val e = log[0]
        assertEquals(TunnelState.Disabled, e.from)
        assertEquals(TunnelState.Arming, e.to)
        assertEquals("user tapped Connect", e.note)
        assertEquals(1_000L, e.timestampMs)
    }

    @Test fun `transition is idempotent for same state + null note`() {
        val r = TunnelStateRegistry()
        r.transition("alpha", TunnelState.Connected)
        r.transition("alpha", TunnelState.Connected)
        r.transition("alpha", TunnelState.Connected)
        assertEquals(1, r.transitionLog("alpha").size)
    }

    @Test fun `transition records non-null note even when state unchanged`() {
        val r = TunnelStateRegistry()
        r.transition("alpha", TunnelState.Connected)
        r.transition("alpha", TunnelState.Connected, note = "handshake refreshed")
        // The note carries diagnostic information the operator wants
        // to see; same-state-with-note is a legitimate log entry.
        assertEquals(2, r.transitionLog("alpha").size)
        assertEquals("handshake refreshed", r.transitionLog("alpha")[1].note)
    }

    @Test fun `PausedSystem with different reasons are distinct transitions`() {
        val r = TunnelStateRegistry()
        r.transition("alpha", TunnelState.PausedSystem(PauseReason.EstablishNull))
        r.transition("alpha", TunnelState.PausedSystem(PauseReason.AnotherVpnTookOver))
        assertEquals(2, r.transitionLog("alpha").size)
        assertNotEquals(r.transitionLog("alpha")[0].to, r.transitionLog("alpha")[1].to)
    }

    @Test fun `recordRevoke is shorthand for transition to PausedSystem`() {
        val r = TunnelStateRegistry()
        r.recordRevoke("alpha", PauseReason.EstablishNull, note = "next establish() returned null")
        val state = r.stateOf("alpha").value
        assertTrue(state is TunnelState.PausedSystem)
        assertEquals(PauseReason.EstablishNull, (state as TunnelState.PausedSystem).reason)
        assertEquals("next establish() returned null", r.transitionLog("alpha").last().note)
    }

    @Test fun `recordFailure stores cause and recoverability`() {
        val r = TunnelStateRegistry()
        r.recordFailure(
            "alpha",
            FailureCause.HandshakeTimeout("1.2.3.4:51820"),
            recoverable = true,
            note = "5 retries",
        )
        val state = r.stateOf("alpha").value
        assertTrue(state is TunnelState.Failed)
        val failed = state as TunnelState.Failed
        assertEquals(true, failed.recoverable)
        assertEquals(FailureCause.HandshakeTimeout("1.2.3.4:51820"), failed.cause)
    }

    @Test fun `recordResume from PausedUser transitions to Arming`() {
        val r = TunnelStateRegistry()
        r.transition("alpha", TunnelState.PausedUser)
        r.recordResume("alpha")
        assertEquals(TunnelState.Arming, r.stateOf("alpha").value)
    }

    @Test fun `recordResume from PausedSystem transitions to Arming`() {
        val r = TunnelStateRegistry()
        r.recordRevoke("alpha", PauseReason.EstablishNull)
        r.recordResume("alpha")
        assertEquals(TunnelState.Arming, r.stateOf("alpha").value)
    }

    @Test fun `recordResume from Connected is no-op`() {
        val r = TunnelStateRegistry()
        r.transition("alpha", TunnelState.Connected)
        r.recordResume("alpha")
        assertEquals(TunnelState.Connected, r.stateOf("alpha").value)
        // Connected → Arming would lose a working session;
        // recordResume must not regress an active tunnel.
        assertEquals(1, r.transitionLog("alpha").size)
    }

    @Test fun `transition log respects LOG_CAPACITY`() {
        val r = TunnelStateRegistry()
        repeat(TunnelStateRegistry.LOG_CAPACITY + 10) { i ->
            // Alternate so transitions actually fire.
            val next = if (i % 2 == 0) TunnelState.Arming else TunnelState.Connecting
            r.transition("alpha", next)
        }
        val log = r.transitionLog("alpha")
        assertEquals(TunnelStateRegistry.LOG_CAPACITY, log.size)
        // Oldest entries dropped; the newest entry should reflect the
        // last transition we made.
        val expectedLast = if ((TunnelStateRegistry.LOG_CAPACITY + 9) % 2 == 0)
            TunnelState.Arming else TunnelState.Connecting
        assertEquals(expectedLast, log.last().to)
    }

    @Test fun `forget clears state and log`() {
        val r = TunnelStateRegistry()
        r.transition("alpha", TunnelState.Connected)
        r.transition("alpha", TunnelState.Idle)
        r.forget("alpha")
        // After forget, the tunnel is unknown again.
        assertTrue(r.transitionLog("alpha").isEmpty())
        // stateOf re-creates the flow with the Disabled seed.
        assertEquals(TunnelState.Disabled, r.stateOf("alpha").value)
        // The old log is gone too — re-reading after forget shows
        // only the freshly-seeded state.
        assertTrue(r.transitionLog("alpha").isEmpty())
    }

    @Test fun `knownTunnelIds reflects insertion`() {
        val r = TunnelStateRegistry()
        assertTrue(r.knownTunnelIds.isEmpty())
        r.transition("alpha", TunnelState.Arming)
        r.transition("beta", TunnelState.Connected)
        assertEquals(setOf("alpha", "beta"), r.knownTunnelIds)
        r.forget("alpha")
        assertEquals(setOf("beta"), r.knownTunnelIds)
    }

    @Test fun `independent tunnels do not cross-pollute`() {
        val r = TunnelStateRegistry()
        r.transition("alpha", TunnelState.Connected)
        r.transition("beta", TunnelState.PausedUser)
        assertEquals(TunnelState.Connected, r.stateOf("alpha").value)
        assertEquals(TunnelState.PausedUser, r.stateOf("beta").value)
        assertEquals(1, r.transitionLog("alpha").size)
        assertEquals(1, r.transitionLog("beta").size)
    }

    @Test fun `getProcessSingleton returns the same instance`() {
        TunnelStateRegistry.setSingletonForTest(null)
        try {
            val a = TunnelStateRegistry.getProcessSingleton()
            val b = TunnelStateRegistry.getProcessSingleton()
            assertEquals(a, b)
            // Mutation through one is observable through the other —
            // confirms identity, not just equality.
            a.transition("alpha", TunnelState.Connected)
            assertEquals(TunnelState.Connected, b.stateOf("alpha").value)
        } finally {
            TunnelStateRegistry.setSingletonForTest(null)
        }
    }

    @Test fun `setSingletonForTest replaces the production instance`() {
        val a = TunnelStateRegistry()
        TunnelStateRegistry.setSingletonForTest(a)
        try {
            assertEquals(a, TunnelStateRegistry.getProcessSingleton())
        } finally {
            TunnelStateRegistry.setSingletonForTest(null)
        }
    }

    @Test fun `TunnelIntent values are stable enum names`() {
        // §12 schema migration depends on these literal strings as
        // serialised values; renaming breaks user prefs on upgrade.
        assertEquals("NoIntentYet", TunnelIntent.NoIntentYet.name)
        assertEquals("WantsOn", TunnelIntent.WantsOn.name)
        assertEquals("ExplicitlyOff", TunnelIntent.ExplicitlyOff.name)
        assertEquals(3, TunnelIntent.values().size)
    }

    @Test fun `transition log entries preserve order across mixed transitions`() {
        val clock = FakeClock()
        val r = TunnelStateRegistry(clock = clock.source)
        r.transition("alpha", TunnelState.Arming)
        r.transition("alpha", TunnelState.Connecting)
        r.transition("alpha", TunnelState.Connected)
        clock.advance(1_000)
        r.transition("alpha", TunnelState.Idle)
        r.recordRevoke("alpha", PauseReason.AnotherVpnTookOver)
        val log = r.transitionLog("alpha")
        assertEquals(
            listOf<TunnelState>(
                TunnelState.Arming,
                TunnelState.Connecting,
                TunnelState.Connected,
                TunnelState.Idle,
                TunnelState.PausedSystem(PauseReason.AnotherVpnTookOver),
            ),
            log.map { it.to },
        )
        // Timestamps are non-decreasing.
        val timestamps = log.map { it.timestampMs }
        assertEquals(timestamps, timestamps.sorted())
    }

    @Test fun `forget makes transitionLog return empty without resurrecting the seeded state`() {
        val r = TunnelStateRegistry()
        r.transition("alpha", TunnelState.Connected)
        r.forget("alpha")
        // Confirm log is empty BEFORE we observe state (which
        // implicitly recreates the flow).
        assertTrue(r.transitionLog("alpha").isEmpty())
    }

    @Test fun `failure cause data classes implement structural equality`() {
        // Important: matching on cause in UI dispatch relies on
        // structural equality of FailureCause payloads.
        val a = TunnelState.Failed(FailureCause.HandshakeTimeout("1.2.3.4:51820"), recoverable = true)
        val b = TunnelState.Failed(FailureCause.HandshakeTimeout("1.2.3.4:51820"), recoverable = true)
        assertEquals(a, b)
        val c = TunnelState.Failed(FailureCause.HandshakeTimeout("1.2.3.4:51820"), recoverable = false)
        assertNotEquals(a, c)
        val d = TunnelState.Failed(FailureCause.PortInUse(51820), recoverable = true)
        assertNotEquals(a, d)
    }
}
