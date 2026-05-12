package com.gutschke.wgrtc.data

/**
 * UI state machines for the wormhole-code enrolment screens
 *. Two parallel state machines — one for the joining client
 * (initiator) and one for the host (responder) — sharing the same
 * shape but driven by different events.
 *
 * Each is implemented as a pure-functional [reduceJoin] / [reduceHost]
 * function: `(state, event) -> state`. No I/O, no coroutines, no
 * Android — so the state transitions are unit-tested in isolation.
 *
 * The future broker-network controller (one per session) drives the
 * reducer by:
 * - handing it user events from the screen (text input, button taps,
 * cancel),
 * - handing it network events when an inbound SPAKE2 message or a
 * transport failure arrives,
 * - emitting outbound network events when the new state demands it
 * (e.g. transitioning to [WormholeJoinUiState.WaitingForResponder]
 * means the controller has to send a SAS_STEP_1 envelope).
 *
 * The screens themselves observe a [kotlinx.coroutines.flow.StateFlow]
 * of the state and render off it; they don't own transitions.
 */

// ─── Initiator ────────────────────────────────────────────────────

/** Initiator (joining client) UI state. */
sealed class WormholeJoinUiState {
    /** First screen: text field for the wormhole code, "Connect"
     * button enabled iff the typed code is well-formed. */
    data class EnteringCode(val typed: String = "") : WormholeJoinUiState()

    /** Code accepted; SPAKE2 step-1 dispatched. Show a spinner +
     * the code so the user can read it back to the host if they're
     * in the same room. */
    data class WaitingForResponder(val code: String) : WormholeJoinUiState()

    /** SAS displayed. User must visually compare this string with
     * what shows on the host's screen, then tap "Confirm". */
    data class ConfirmingSas(val code: String, val sas: String) : WormholeJoinUiState()

    /** User confirmed. We sent our [SAS_CONFIRM] envelope; waiting
     * for the responder's MAC. */
    data class AwaitingPeerConfirm(val code: String) : WormholeJoinUiState()

    /** Both sides confirmed. The screen typically navigates away
     * immediately and the controller is closed. */
    object Succeeded : WormholeJoinUiState()

    /** Any error (transport, SPAKE2, MAC mismatch, user cancel). */
    data class Failed(val reason: String) : WormholeJoinUiState()
}

/** Events the initiator screen + controller can fire. */
sealed class WormholeJoinUiEvent {
    /** User typed; UI normalises before storing in state. */
    data class CodeChanged(val typed: String) : WormholeJoinUiEvent()

    /** User pressed "Connect" — the typed code was well-formed. */
    object Submit : WormholeJoinUiEvent()

    /** Broker delivered the responder's SPAKE2 step-2; the
     * controller has run finish() and derived the SAS. */
    data class SasComputed(val sas: String) : WormholeJoinUiEvent()

    /** User tapped the "Confirm match" button on the SAS screen. */
    object UserConfirm : WormholeJoinUiEvent()

    /** Responder's confirm-MAC verified. Transition to Succeeded. */
    object PeerConfirmed : WormholeJoinUiEvent()

    /** Anything went wrong — surface a one-line reason. */
    data class Fail(val reason: String) : WormholeJoinUiEvent()

    /** User pressed back / cancel — destroy the session. */
    object Cancel : WormholeJoinUiEvent()
}

/**
 * Pure transition function. Unknown event-from-state combinations
 * are no-ops — out-of-order broker messages can't drive the state
 * backward, and a Cancel-after-Succeed shouldn't undo success.
 */
fun reduceJoin(
    state: WormholeJoinUiState,
    event: WormholeJoinUiEvent,
): WormholeJoinUiState {
    // Cancel and Fail are global — accept from any state except a
    // terminal one, where they're a no-op.
    if (event is WormholeJoinUiEvent.Cancel) {
        return when (state) {
            is WormholeJoinUiState.Succeeded, is WormholeJoinUiState.Failed -> state
            else -> WormholeJoinUiState.Failed("cancelled")
        }
    }
    if (event is WormholeJoinUiEvent.Fail) {
        return when (state) {
            is WormholeJoinUiState.Succeeded -> state
            else -> WormholeJoinUiState.Failed(event.reason)
        }
    }
    return when (state) {
        is WormholeJoinUiState.EnteringCode -> when (event) {
            is WormholeJoinUiEvent.CodeChanged -> state.copy(typed = event.typed)
            WormholeJoinUiEvent.Submit -> {
                // Submit only fires from a well-formed code per the
                // UI's enable-button rule, but defend against
                // out-of-band invocation.
                if (com.gutschke.wgrtc.signalling.WormholeCode.isValid(state.typed)) {
                    val canon = com.gutschke.wgrtc.signalling.WormholeCode.normalise(state.typed)
                    WormholeJoinUiState.WaitingForResponder(canon)
                } else state
            }
            else -> state
        }
        is WormholeJoinUiState.WaitingForResponder -> when (event) {
            is WormholeJoinUiEvent.SasComputed ->
                WormholeJoinUiState.ConfirmingSas(state.code, event.sas)
            else -> state
        }
        is WormholeJoinUiState.ConfirmingSas -> when (event) {
            WormholeJoinUiEvent.UserConfirm ->
                WormholeJoinUiState.AwaitingPeerConfirm(state.code)
            else -> state
        }
        is WormholeJoinUiState.AwaitingPeerConfirm -> when (event) {
            WormholeJoinUiEvent.PeerConfirmed -> WormholeJoinUiState.Succeeded
            else -> state
        }
        is WormholeJoinUiState.Succeeded, is WormholeJoinUiState.Failed -> state
    }
}

// ─── Responder ────────────────────────────────────────────────────

/** Responder (host) UI state. */
sealed class WormholeHostUiState {
    /** Code minted; show it to the user and wait for the joining
     * client to deliver SAS_STEP_1. Also covers "still typing /
     * waiting" — the screen renders the code in big letters. */
    data class ShowingCode(val code: String) : WormholeHostUiState()

    /** Step-1 received, step-2 sent, SAS computed. */
    data class ConfirmingSas(val code: String, val sas: String) : WormholeHostUiState()

    /** User confirmed; sent our MAC; waiting for theirs. */
    data class AwaitingPeerConfirm(val code: String) : WormholeHostUiState()

    /** Mutual confirm: peer is enrolled. Caller can persist the
     * new peer + navigate away. */
    object Succeeded : WormholeHostUiState()

    /** Any error. */
    data class Failed(val reason: String) : WormholeHostUiState()
}

sealed class WormholeHostUiEvent {
    /** Controller has run finish() and derived the SAS. */
    data class SasComputed(val sas: String) : WormholeHostUiEvent()

    /** Host operator tapped "Confirm". */
    object UserConfirm : WormholeHostUiEvent()

    /** Joining client's confirm-MAC verified. */
    object PeerConfirmed : WormholeHostUiEvent()

    /** Surface an error. */
    data class Fail(val reason: String) : WormholeHostUiEvent()

    /** User cancelled. */
    object Cancel : WormholeHostUiEvent()
}

fun reduceHost(
    state: WormholeHostUiState,
    event: WormholeHostUiEvent,
): WormholeHostUiState {
    if (event is WormholeHostUiEvent.Cancel) {
        return when (state) {
            is WormholeHostUiState.Succeeded, is WormholeHostUiState.Failed -> state
            else -> WormholeHostUiState.Failed("cancelled")
        }
    }
    if (event is WormholeHostUiEvent.Fail) {
        return when (state) {
            is WormholeHostUiState.Succeeded -> state
            else -> WormholeHostUiState.Failed(event.reason)
        }
    }
    return when (state) {
        is WormholeHostUiState.ShowingCode -> when (event) {
            is WormholeHostUiEvent.SasComputed ->
                WormholeHostUiState.ConfirmingSas(state.code, event.sas)
            else -> state
        }
        is WormholeHostUiState.ConfirmingSas -> when (event) {
            WormholeHostUiEvent.UserConfirm ->
                WormholeHostUiState.AwaitingPeerConfirm(state.code)
            else -> state
        }
        is WormholeHostUiState.AwaitingPeerConfirm -> when (event) {
            WormholeHostUiEvent.PeerConfirmed -> WormholeHostUiState.Succeeded
            else -> state
        }
        is WormholeHostUiState.Succeeded, is WormholeHostUiState.Failed -> state
    }
}
