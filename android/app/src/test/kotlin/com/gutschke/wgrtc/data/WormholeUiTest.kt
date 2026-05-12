package com.gutschke.wgrtc.data

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class WormholeUiTest {

    // ─── Initiator (join) ─────────────────────────────────────────

    @Test fun `join — typing accumulates in EnteringCode state`() {
        val s0 = WormholeJoinUiState.EnteringCode()
        val s1 = reduceJoin(s0, WormholeJoinUiEvent.CodeChanged("a"))
        val s2 = reduceJoin(s1, WormholeJoinUiEvent.CodeChanged("ab"))
        assertEquals(WormholeJoinUiState.EnteringCode("ab"), s2)
    }

    @Test fun `join — Submit with valid code transitions to WaitingForResponder`() {
        val s0 = WormholeJoinUiState.EnteringCode("ab-cdef")
        val s1 = reduceJoin(s0, WormholeJoinUiEvent.Submit)
        assertEquals(WormholeJoinUiState.WaitingForResponder("ABCDEF"), s1)
    }

    @Test fun `join — Submit with too-short code stays in EnteringCode`() {
        val s0 = WormholeJoinUiState.EnteringCode("AB")
        val s1 = reduceJoin(s0, WormholeJoinUiEvent.Submit)
        assertEquals(s0, s1)
    }

    @Test fun `join — SasComputed transitions WaitingForResponder to ConfirmingSas`() {
        val s0 = WormholeJoinUiState.WaitingForResponder("ABCDEF")
        val s1 = reduceJoin(s0, WormholeJoinUiEvent.SasComputed("apple bear cat dove"))
        assertEquals(
            WormholeJoinUiState.ConfirmingSas("ABCDEF", "apple bear cat dove"),
            s1,
        )
    }

    @Test fun `join — UserConfirm transitions ConfirmingSas to AwaitingPeerConfirm`() {
        val s0 = WormholeJoinUiState.ConfirmingSas("ABCDEF", "apple bear cat dove")
        val s1 = reduceJoin(s0, WormholeJoinUiEvent.UserConfirm)
        assertEquals(WormholeJoinUiState.AwaitingPeerConfirm("ABCDEF"), s1)
    }

    @Test fun `join — PeerConfirmed transitions AwaitingPeerConfirm to Succeeded`() {
        val s0 = WormholeJoinUiState.AwaitingPeerConfirm("ABCDEF")
        val s1 = reduceJoin(s0, WormholeJoinUiEvent.PeerConfirmed)
        assertEquals(WormholeJoinUiState.Succeeded, s1)
    }

    @Test fun `join — Cancel from any non-terminal state moves to Failed`() {
        val states = listOf<WormholeJoinUiState>(
            WormholeJoinUiState.EnteringCode("AB"),
            WormholeJoinUiState.WaitingForResponder("ABCDEF"),
            WormholeJoinUiState.ConfirmingSas("ABCDEF", "sas"),
            WormholeJoinUiState.AwaitingPeerConfirm("ABCDEF"),
        )
        for (s in states) {
            val next = reduceJoin(s, WormholeJoinUiEvent.Cancel)
            assertTrue(next is WormholeJoinUiState.Failed,
                "Cancel from $s should yield Failed, got $next")
            assertEquals("cancelled", (next as WormholeJoinUiState.Failed).reason)
        }
    }

    @Test fun `join — Cancel after Succeed is a no-op`() {
        val s0 = WormholeJoinUiState.Succeeded
        assertEquals(s0, reduceJoin(s0, WormholeJoinUiEvent.Cancel))
    }

    @Test fun `join — Fail from non-terminal state preserves reason`() {
        val s0 = WormholeJoinUiState.WaitingForResponder("AB")
        val s1 = reduceJoin(s0, WormholeJoinUiEvent.Fail("broker offline"))
        assertEquals(WormholeJoinUiState.Failed("broker offline"), s1)
    }

    @Test fun `join — Fail after Succeed is a no-op`() {
        val s0 = WormholeJoinUiState.Succeeded
        val s1 = reduceJoin(s0, WormholeJoinUiEvent.Fail("ignored"))
        assertEquals(s0, s1)
    }

    @Test fun `join — out-of-order events are no-ops`() {
        // SasComputed in EnteringCode shouldn't break the world.
        val s0 = WormholeJoinUiState.EnteringCode("AB")
        val s1 = reduceJoin(s0, WormholeJoinUiEvent.SasComputed("ignored"))
        assertEquals(s0, s1)

        // PeerConfirmed in ConfirmingSas shouldn't skip the user.
        val s2 = WormholeJoinUiState.ConfirmingSas("AB", "sas")
        val s3 = reduceJoin(s2, WormholeJoinUiEvent.PeerConfirmed)
        assertEquals(s2, s3)
    }

    @Test fun `join — full happy path runs through every state`() {
        var s: WormholeJoinUiState = WormholeJoinUiState.EnteringCode()
        s = reduceJoin(s, WormholeJoinUiEvent.CodeChanged("ABCDEF"))
        s = reduceJoin(s, WormholeJoinUiEvent.Submit)
        assertEquals(WormholeJoinUiState.WaitingForResponder("ABCDEF"), s)
        s = reduceJoin(s, WormholeJoinUiEvent.SasComputed("apple bear cat dove"))
        s = reduceJoin(s, WormholeJoinUiEvent.UserConfirm)
        assertEquals(WormholeJoinUiState.AwaitingPeerConfirm("ABCDEF"), s)
        s = reduceJoin(s, WormholeJoinUiEvent.PeerConfirmed)
        assertEquals(WormholeJoinUiState.Succeeded, s)
    }

    // ─── Responder (host) ─────────────────────────────────────────

    @Test fun `host — SasComputed transitions ShowingCode to ConfirmingSas`() {
        val s0 = WormholeHostUiState.ShowingCode("ABCDEF")
        val s1 = reduceHost(s0, WormholeHostUiEvent.SasComputed("apple bear"))
        assertEquals(
            WormholeHostUiState.ConfirmingSas("ABCDEF", "apple bear"),
            s1,
        )
    }

    @Test fun `host — UserConfirm transitions ConfirmingSas to AwaitingPeerConfirm`() {
        val s0 = WormholeHostUiState.ConfirmingSas("ABCDEF", "sas")
        val s1 = reduceHost(s0, WormholeHostUiEvent.UserConfirm)
        assertEquals(WormholeHostUiState.AwaitingPeerConfirm("ABCDEF"), s1)
    }

    @Test fun `host — PeerConfirmed transitions AwaitingPeerConfirm to Succeeded`() {
        val s0 = WormholeHostUiState.AwaitingPeerConfirm("ABCDEF")
        val s1 = reduceHost(s0, WormholeHostUiEvent.PeerConfirmed)
        assertEquals(WormholeHostUiState.Succeeded, s1)
    }

    @Test fun `host — Cancel from any non-terminal state moves to Failed`() {
        val states = listOf<WormholeHostUiState>(
            WormholeHostUiState.ShowingCode("AB"),
            WormholeHostUiState.ConfirmingSas("AB", "sas"),
            WormholeHostUiState.AwaitingPeerConfirm("AB"),
        )
        for (s in states) {
            val next = reduceHost(s, WormholeHostUiEvent.Cancel)
            assertTrue(next is WormholeHostUiState.Failed,
                "Cancel from $s should yield Failed, got $next")
        }
    }

    @Test fun `host — Fail and Cancel after Succeed are no-ops`() {
        val s0 = WormholeHostUiState.Succeeded
        assertEquals(s0, reduceHost(s0, WormholeHostUiEvent.Cancel))
        assertEquals(s0, reduceHost(s0, WormholeHostUiEvent.Fail("ignored")))
    }

    @Test fun `host — out-of-order PeerConfirmed in ShowingCode is a no-op`() {
        val s0 = WormholeHostUiState.ShowingCode("AB")
        val s1 = reduceHost(s0, WormholeHostUiEvent.PeerConfirmed)
        assertEquals(s0, s1)
    }

    @Test fun `host — full happy path runs through every state`() {
        var s: WormholeHostUiState = WormholeHostUiState.ShowingCode("ABCDEF")
        s = reduceHost(s, WormholeHostUiEvent.SasComputed("apple bear cat dove"))
        s = reduceHost(s, WormholeHostUiEvent.UserConfirm)
        assertEquals(WormholeHostUiState.AwaitingPeerConfirm("ABCDEF"), s)
        s = reduceHost(s, WormholeHostUiEvent.PeerConfirmed)
        assertEquals(WormholeHostUiState.Succeeded, s)
    }
}
