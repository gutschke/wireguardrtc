package com.gutschke.wgrtc.data

import android.util.Log
import com.gutschke.wgrtc.signalling.extractInboundEnroll
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import kotlinx.serialization.json.JsonElement

/**
 * host-mode dispatcher: takes raw frames from the host's
 * broker WSS (via [com.gutschke.wgrtc.signalling.OfferListener.startHostMode]),
 * extracts [com.gutschke.wgrtc.signalling.InboundEnrollEnvelope]s,
 * and runs them through [InboundEnrollHandler] — then persists the
 * enrolled peer (if any) and sends the response envelope back over
 * the same WSS.
 *
 * Sequencing on a successful enrolment is **persist-then-send**:
 *
 * 1. [applyEnrollment] writes the new peer to tunnels.json AND
 * reconfigures wg-go (DOWN+UP) so by the time the client
 * receives ENROLL_OK, the host's wg-go already accepts its
 * handshake. Median 57 ms cycle on real hardware (per
 * ``) — well under
 * the WSS round-trip latency a client would observe anyway.
 * 2. Once apply returns, [sendVia] delivers the envelope.
 *
 * On apply failure we DO NOT send the OK response; the client will
 * time out and retry, by which point the host operator will have
 * surfaced the persistence error and (presumably) recovered.
 *
 * On `Ignore` (mismatched src, no matching token, stale ts, etc.)
 * we drop silently — the threat model in the internal design doc wants no
 * step-distinguishing observable behaviour.
 *
 * On authenticated `enroll_err` (TOKEN_USED, PROVISION_FAILED) we
 * send the response without persisting any peer.
 */
class HostModeDispatcher(
 private val handler: InboundEnrollHandler,
 private val hostStateProvider: () -> InboundEnrollHandler.HostState,
 private val applyEnrollment: suspend (InboundEnrollHandler.NewPeer) -> Unit,
 private val sendVia: suspend (envelope: String) -> Boolean,
 private val scope: CoroutineScope,
) {

 /** Invoked from [com.gutschke.wgrtc.signalling.OfferListener]'s WS
 * reader thread; non-suspending. All actual work runs on
 * [scope] to keep the WS reader unblocked. Production callers
 * pass an IO-backed scope; tests use `Dispatchers.Unconfined`
 * so call ordering is observable synchronously. */
 fun onMessage(message: JsonElement) {
 val env = extractInboundEnroll(message) ?: return
 scope.launch {
 handleSuspending(env)
 }
 }

 private suspend fun handleSuspending(env: com.gutschke.wgrtc.signalling.InboundEnrollEnvelope) {
 val state = hostStateProvider()
 val result = handler.handle(env, state)
 when (result) {
 is InboundEnrollHandler.Result.Ignore -> {
 // Threat-model: don't echo back which step failed.
 // Log at debug for our own diagnostics.
 Log.d(TAG, "host-mode: dropping inbound enroll: ${result.reason}")
 }
 is InboundEnrollHandler.Result.Reply -> {
 if (result.newPeer != null) {
 // Persist + reconfigure wg-go BEFORE responding.
 // If apply throws, swallow + log + don't send the
 // OK envelope — the client will retry.
 try {
 applyEnrollment(result.newPeer)
 } catch (t: Throwable) {
 Log.e(TAG,
 "host-mode: applyEnrollment failed for " +
 "${result.newPeer.pubkeyB64.take(12)}…; " +
 "suppressing OK response so client will retry", t)
 return
 }
 }
 val ok = sendVia(result.envelopeJson)
 if (!ok) {
 Log.w(TAG, "host-mode: sendVia returned false " +
 "(listener offline?); client will retry on its own")
 }
 }
 }
 }

 companion object {
 private const val TAG = "wgrtc-host"
 }
}
