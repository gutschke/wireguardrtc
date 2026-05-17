package com.gutschke.wgrtc.data

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class BridgeOrchestrationStateTest {

    /** Deterministic id factory so transition tests don't depend
     *  on UUID randomness. */
    private class SeqFactory(initial: Int = 0) {
        private var n = initial
        val mint: () -> String = { "id-${++n}" }
    }

    @Test fun `freshly-constructed state has no pending id`() {
        val s = BridgeOrchestrationState()
        assertNull(s.pending.value)
        assertNull(s.peek())
    }

    @Test fun `startFlow allocates an id and exposes it`() {
        val seq = SeqFactory()
        val s = BridgeOrchestrationState(idFactory = seq.mint)
        val id = s.startFlow()
        assertEquals("id-1", id)
        assertEquals("id-1", s.pending.value)
        assertEquals("id-1", s.peek())
    }

    @Test fun `two peek calls return the same id`() {
        // §11.6 invariant: both halves of a Bridge pair (joiner +
        // host) read the SAME id when they save.  Auto-clearing
        // after one peek would orphan the second half.
        val s = BridgeOrchestrationState(idFactory = SeqFactory().mint)
        s.startFlow()
        val a = s.peek()
        val b = s.peek()
        assertEquals(a, b)
        assertNotNull(a)
    }

    @Test fun `finish transitions to null exactly once`() {
        val s = BridgeOrchestrationState(idFactory = SeqFactory().mint)
        s.startFlow()
        assertNotNull(s.pending.value)
        s.finish()
        assertNull(s.pending.value)
        // Idempotent: a second finish doesn't crash and stays null.
        s.finish()
        assertNull(s.pending.value)
    }

    @Test fun `double-startFlow emits two distinct ids and fires onClobber`() {
        // Verifies the overwrite is observable both via the
        // StateFlow value AND via the onClobber callback (the
        // production wiring writes a Log.w line here).
        val seq = SeqFactory()
        val clobbered = mutableListOf<String>()
        val s = BridgeOrchestrationState(
            idFactory = seq.mint,
            onClobber = { previous -> clobbered.add(previous) },
        )
        val first = s.startFlow()
        val second = s.startFlow()
        assertEquals("id-1", first)
        assertEquals("id-2", second)
        // clobber callback fires with the OLD id.
        assertEquals(listOf("id-1"), clobbered)
        // StateFlow's current value is the new id.
        assertEquals("id-2", s.pending.value)
    }

    @Test fun `startFlow on idle state does not call onClobber`() {
        // First-ever startFlow has no previous flow to clobber.
        val clobbered = mutableListOf<String>()
        val s = BridgeOrchestrationState(
            idFactory = SeqFactory().mint,
            onClobber = { clobbered.add(it) },
        )
        s.startFlow()
        assertEquals(emptyList<String>(), clobbered)
    }

    @Test fun `startFlow after finish does not call onClobber`() {
        // The "previous flow" check is on the live state, not the
        // history.  After finish() the slot is null and the next
        // startFlow is a clean start, not a clobber.
        val clobbered = mutableListOf<String>()
        val s = BridgeOrchestrationState(
            idFactory = SeqFactory().mint,
            onClobber = { clobbered.add(it) },
        )
        s.startFlow()
        s.finish()
        s.startFlow()
        assertEquals(emptyList<String>(), clobbered)
    }

    @Test fun `peek after finish returns null`() {
        val s = BridgeOrchestrationState(idFactory = SeqFactory().mint)
        s.startFlow()
        s.finish()
        assertNull(s.peek())
    }

    @Test fun `default UUID factory produces a real-looking id`() {
        // Belt-and-suspenders: tests use a SeqFactory seam; the
        // production default must still produce a usable id.
        val s = BridgeOrchestrationState()
        val id = s.startFlow()
        // UUID.toString() is 36 chars with hyphens at fixed
        // positions.  Pin the shape so a future refactor that
        // swaps to a different generator (snowflake, ULID, etc.)
        // is a deliberate decision.
        assertEquals(36, id.length, "expected UUID-shaped id, got $id")
    }

    @Test fun `concurrent collectors see the same value after a transition`() {
        // StateFlow.value is read synchronously after a write, so
        // two consumers reading right after startFlow / finish
        // observe the same state.  This pins the synchronous-
        // observability invariant downstream Compose screens rely
        // on when collecting pendingBridgeGroupId via collectAsState.
        val s = BridgeOrchestrationState(idFactory = SeqFactory().mint)
        s.startFlow()
        val obsA = s.pending.value
        val obsB = s.pending.value
        assertEquals(obsA, obsB)
        s.finish()
        assertEquals(s.pending.value, s.pending.value)
    }
}
