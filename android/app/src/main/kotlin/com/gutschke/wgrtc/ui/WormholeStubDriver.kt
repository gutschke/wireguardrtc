package com.gutschke.wgrtc.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.MutableState
import com.gutschke.wgrtc.data.WormholeHostUiEvent
import com.gutschke.wgrtc.data.WormholeHostUiState
import com.gutschke.wgrtc.data.WormholeJoinUiEvent
import com.gutschke.wgrtc.data.WormholeJoinUiState
import com.gutschke.wgrtc.data.reduceHost
import com.gutschke.wgrtc.data.reduceJoin
import kotlinx.coroutines.delay

/**
 * Dev-mode auto-advance driver for the wormhole screens. Lets the
 * user preview the full UX flow (enter code → wait → SAS → confirm
 * → success) without the broker wired up.
 *
 * Replaces with a real controller in a follow-up commit; the
 * controller will:
 * 1. Connect to the broker WSS using
 * [com.gutschke.wgrtc.signalling.sasRoutingIdInitiator] /
 * Responder for its inbox subscription.
 * 2. Emit [com.gutschke.wgrtc.signalling.buildSasStep1Envelope] /
 * Step2 / Confirm at the right moments.
 * 3. Surface inbound [com.gutschke.wgrtc.signalling.extractSasStep2]
 * / Confirm parses as
 * [WormholeJoinUiEvent.SasComputed] / PeerConfirmed, etc.
 *
 * The dev driver below produces visually-similar timing — meant only
 * for evaluating ergonomics, NOT for any kind of integration.
 */

/** Demo SAS phrase shown when the dev stub fires SasComputed. */
private const val DEMO_SAS_PHRASE = "apple bear cat dove"

/** Initiator-side dev stub. Drives the state machine via reduce(). */
@Composable
fun launchJoinDevStub(state: MutableState<WormholeJoinUiState>) {
    LaunchedEffect(state.value::class) {
        when (state.value) {
            is WormholeJoinUiState.WaitingForResponder -> {
                // Simulate broker delivering Step2 + computing SAS.
                delay(1_500)
                state.value = reduceJoin(state.value,
                    WormholeJoinUiEvent.SasComputed(DEMO_SAS_PHRASE))
            }
            is WormholeJoinUiState.AwaitingPeerConfirm -> {
                // Simulate peer responding with their MAC.
                delay(800)
                state.value = reduceJoin(state.value,
                    WormholeJoinUiEvent.PeerConfirmed)
            }
            else -> Unit
        }
    }
}

/** Responder-side dev stub. */
@Composable
fun launchHostDevStub(state: MutableState<WormholeHostUiState>) {
    LaunchedEffect(state.value::class) {
        when (state.value) {
            is WormholeHostUiState.ShowingCode -> {
                // Simulate Step1 arrival → finish() → SAS.
                delay(2_000)
                state.value = reduceHost(state.value,
                    WormholeHostUiEvent.SasComputed(DEMO_SAS_PHRASE))
            }
            is WormholeHostUiState.AwaitingPeerConfirm -> {
                delay(800)
                state.value = reduceHost(state.value,
                    WormholeHostUiEvent.PeerConfirmed)
            }
            else -> Unit
        }
    }
}
