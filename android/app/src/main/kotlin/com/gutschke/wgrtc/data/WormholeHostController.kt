package com.gutschke.wgrtc.data

import com.gutschke.wgrtc.signalling.HostEnrolInfo
import com.gutschke.wgrtc.signalling.OfferListenerWormholeTransport
import com.gutschke.wgrtc.signalling.SasConfirmRole
import com.gutschke.wgrtc.signalling.SasInbound
import com.gutschke.wgrtc.signalling.Spake2
import com.gutschke.wgrtc.signalling.WormholeBrokerSession
import com.gutschke.wgrtc.signalling.WormholeCode
import com.gutschke.wgrtc.signalling.WormholeTransport
import com.gutschke.wgrtc.signalling.buildSasConfirmMac
import com.gutschke.wgrtc.signalling.decodeJoinerInfo
import com.gutschke.wgrtc.signalling.deriveSas
import com.gutschke.wgrtc.signalling.encodeHostInfo
import com.gutschke.wgrtc.signalling.verifySasConfirmMac
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * Real broker-driven controller for the wormhole-code responder
 * (host) side. Replaces [com.gutschke.wgrtc.ui.launchHostDevStub].
 *
 * Differs from [WormholeJoinController] in two ways:
 * 1. The code is *minted by the controller at construction*
 * (responder owns the secret), and the screen displays it
 * verbatim while waiting for the joiner.
 * 2. The first inbound event is the joiner's [SasInbound.Step1]
 * — that's when the responder runs SPAKE2 [Spake2.start] +
 * [Spake2.finish] together (rather than [Spake2.start] before
 * send, [Spake2.finish] after receive as the initiator does).
 *
 * Threading + lifecycle: same as [WormholeJoinController].
 */
class WormholeHostController(
    private val brokerWss: String,
    private val brokerKey: String,
    private val parentScope: CoroutineScope,
    /** Optional pre-minted code (for tests + scenarios that want to
     * reuse the same code across sessions). Default mints fresh
     * via [WormholeCode.generate]. */
    code: String = WormholeCode.generate(),
    /** Snapshot of the host tunnel the joiner is being enrolled into.
     * When present, the controller sends a [HostEnrolInfo] payload
     * in its SAS_CONFIRM and exposes a [HostWormholeResult] on
     * Succeeded. When null, the legacy mac-only flow runs (kept
     * so the dev preview / era code paths still work). */
    private val tunnelSnapshot: HostTunnelSnapshot? = null,
    private val transportFactory: (CoroutineScope) -> WormholeTransport =
        { scope -> OfferListenerWormholeTransport(brokerWss, brokerKey, scope) },
) {
    private val ownJob = SupervisorJob(parentScope.coroutineContext[Job])
    private val ownScope = CoroutineScope(parentScope.coroutineContext + ownJob)

    private val _state = MutableStateFlow<WormholeHostUiState>(
        WormholeHostUiState.ShowingCode(code))
    val state: StateFlow<WormholeHostUiState> = _state.asStateFlow()

    private val codeBytes: ByteArray = WormholeCode.toBytes(code)

    @Volatile private var session: WormholeBrokerSession? = null
    @Volatile private var spake2: Spake2? = null
    @Volatile private var sharedKey: ByteArray? = null

    /** Peer-confirm buffered when it arrives in ConfirmingSas state.
     * See [WormholeJoinController.pendingPeerMac]. */
    @Volatile private var pendingPeerMac: ByteArray? = null
    @Volatile private var pendingPeerInfoBlob: ByteArray? = null

    /** After Succeeded, the data the UI needs to add the new peer
     * to the host's tunnel via the existing
     * [applyEnrollmentToTunnel] path. Null until then or when
     * [tunnelSnapshot] was null. */
    private val _wormholeResult = MutableStateFlow<HostWormholeResult?>(null)
    val wormholeResult: StateFlow<HostWormholeResult?> = _wormholeResult.asStateFlow()

    /** Open the broker subscription so we receive an inbound Step-1
     * whenever the joining client sends one. Call this after
     * construction (typically from a `LaunchedEffect`). */
    fun start() {
        if (session != null) return
        val transport = transportFactory(ownScope)
        val s = WormholeBrokerSession(SasConfirmRole.RESPONDER, codeBytes, transport)
        session = s
        spake2 = Spake2(Spake2.Role.BOB, codeBytes)
        ownScope.launch {
            try {
                s.start { event -> onInbound(event) }
            } catch (t: Throwable) {
                failNow("broker session failed: ${t.javaClass.simpleName}: ${t.message}")
            }
        }
    }

    fun userConfirm() {
        val s = _state.value as? WormholeHostUiState.ConfirmingSas ?: return
        val key = sharedKey ?: return failNow("internal: no shared key")
        _state.value = WormholeHostUiState.AwaitingPeerConfirm(s.code)
        val mac = buildSasConfirmMac(SasConfirmRole.RESPONDER, key)
        // If we have a tunnel snapshot, send our HostEnrolInfo
        // alongside the mac. Without it we fall back to the legacy
        // mac-only confirm — joiner will fail to construct a tunnel
        // and surface "peer didn't send enrolment info" — the
        // failure shape is intentional, not silent.
        val sendOk = if (tunnelSnapshot != null) {
            val info = HostEnrolInfo(
                timestamp = System.currentTimeMillis() / 1000,
                wgPubkeyB64 = tunnelSnapshot.pubKeyB64,
                wgEndpoint = tunnelSnapshot.wgEndpoint,
                assignedAddress = tunnelSnapshot.assignedAddress,
                allowedIps = tunnelSnapshot.allowedIps,
                brokerWss = tunnelSnapshot.brokerWss,
                brokerKey = tunnelSnapshot.brokerKey,
                saltB64 = tunnelSnapshot.saltB64,
                dns = tunnelSnapshot.dns,
                mtu = tunnelSnapshot.mtu,
                keepalive = tunnelSnapshot.keepalive,
                hostName = tunnelSnapshot.hostName,
            )
            val infoBlob = encodeHostInfo(info, key)
            session?.sendConfirmWithInfo(mac, infoBlob) ?: false
        } else {
            session?.sendConfirm(mac) ?: false
        }
        if (!sendOk) {
            return failNow("broker refused the confirm message")
        }
        pendingPeerMac?.let { peerMac ->
            val peerInfoBlob = pendingPeerInfoBlob
            pendingPeerMac = null
            pendingPeerInfoBlob = null
            verifyAndAdvance(peerMac, peerInfoBlob, key)
        }
    }

    fun cancel() {
        if (terminal()) return
        _state.value = WormholeHostUiState.Failed("cancelled")
        teardown()
    }

    fun dispose() {
        teardown()
        ownJob.cancel()
    }

    private fun onInbound(event: SasInbound) {
        when (event) {
            is SasInbound.Step1 -> {
                val s = _state.value as? WormholeHostUiState.ShowingCode ?: return
                val sp = spake2 ?: return
                val msgR = sp.start()
                val key = try { sp.finish(event.parsed.pakeMsg) }
                          catch (t: Throwable) {
                              return failNow("PAKE finish failed: ${t.message}")
                          }
                if (session?.sendStep2(msgR) != true) {
                    return failNow("broker dropped the session before step 2 could send")
                }
                sharedKey = key
                val sas = deriveSas(key)
                _state.value = WormholeHostUiState.ConfirmingSas(s.code, sas)
            }
            is SasInbound.Confirm -> {
                val key = sharedKey ?: return // not ready yet, drop
                when (_state.value) {
                    is WormholeHostUiState.AwaitingPeerConfirm ->
                        verifyAndAdvance(event.parsed.mac,
                            event.parsed.encryptedInfo, key)
                    is WormholeHostUiState.ConfirmingSas -> {
                        // Peer raced us to the confirm step. Buffer.
                        pendingPeerMac = event.parsed.mac
                        pendingPeerInfoBlob = event.parsed.encryptedInfo
                    }
                    else -> { /* terminal or earlier; drop */ }
                }
            }
            is SasInbound.Step2 -> {
                // Responder never receives Step2. Drop silently.
            }
        }
    }

    private fun verifyAndAdvance(
        peerMac: ByteArray,
        peerInfoBlob: ByteArray?,
        key: ByteArray,
    ) {
        val macOk = verifySasConfirmMac(SasConfirmRole.INITIATOR, key, peerMac)
        if (!macOk) {
            return failNow("peer MAC verification failed — possible MITM")
        }
        // If a tunnel snapshot AND the joiner sent enrolment info,
        // produce a [HostWormholeResult] for the UI to persist.
        // Both missing → legacy mac-only flow (Succeeded with no
        // result). Snapshot present but info missing IS a hard
        // error — we have an IP earmarked and would otherwise lose
        // it without crediting the joiner.
        if (tunnelSnapshot != null) {
            if (peerInfoBlob == null) {
                return failNow("joiner didn't send enrolment info")
            }
            val joinerInfo = decodeJoinerInfo(peerInfoBlob, key)
                ?: return failNow("joiner info decode failed — wrong key or stale ts")
            val ip = tunnelSnapshot.assignedAddress.substringBefore('/')
            _wormholeResult.value = HostWormholeResult(
                tunnelId = tunnelSnapshot.tunnelId,
                joinerPubkeyB64 = joinerInfo.wgPubkeyB64,
                joinerIp = ip,
                joinerNameHint = joinerInfo.deviceName ?: "wormhole-peer",
            )
        }
        _state.value = WormholeHostUiState.Succeeded
        teardown()
    }

    private fun failNow(reason: String) {
        if (terminal()) return
        _state.value = WormholeHostUiState.Failed(reason)
        teardown()
    }

    private fun terminal(): Boolean = _state.value is WormholeHostUiState.Succeeded ||
        _state.value is WormholeHostUiState.Failed

    private fun teardown() {
        val s = session
        session = null
        if (s != null) {
            // See WormholeJoinController.teardown — launch on
            // parentScope so close() survives ownJob cancellation.
            parentScope.launch {
                try { s.close() } catch (_: Throwable) {}
            }
        }
    }
}
