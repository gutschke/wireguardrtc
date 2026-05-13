package com.gutschke.wgrtc.data

import com.gutschke.wgrtc.signalling.HostEnrollInfo
import com.gutschke.wgrtc.signalling.JoinerEnrollInfo
import com.gutschke.wgrtc.signalling.OfferListenerWormholeTransport
import com.gutschke.wgrtc.signalling.SasConfirmRole
import com.gutschke.wgrtc.signalling.SasInbound
import com.gutschke.wgrtc.signalling.Spake2
import com.gutschke.wgrtc.signalling.WormholeBrokerSession
import com.gutschke.wgrtc.signalling.WormholeCode
import com.gutschke.wgrtc.signalling.WormholeTransport
import com.gutschke.wgrtc.signalling.buildSasConfirmMac
import com.gutschke.wgrtc.signalling.decodeHostInfo
import com.gutschke.wgrtc.signalling.deriveSas
import com.gutschke.wgrtc.signalling.encodeJoinerInfo
import com.gutschke.wgrtc.signalling.pubKeyFromPrivate
import com.gutschke.wgrtc.signalling.verifySasConfirmMac
import java.security.SecureRandom
import java.util.Base64
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
// Re-import: brought in via `import com.gutschke.wgrtc.signalling.*` lower
// in the file; kept explicit for clarity.

/**
 * Real broker-driven controller for the wormhole-code initiator side.
 * Replaces the dev-mode [com.gutschke.wgrtc.ui.launchJoinDevStub].
 *
 * Responsibilities:
 * 1. Hold the [WormholeJoinUiState] as a [StateFlow] for the screen.
 * 2. Translate user events ([onTyped] / [submit] / [userConfirm] /
 * [cancel]) into state transitions plus the right broker side-
 * effects (open subscription, send step-1, send confirm-MAC).
 * 3. Translate broker events ([SasInbound]) into state transitions
 * (compute SAS on Step2, verify MAC on Confirm).
 *
 * Threading: state is a [MutableStateFlow] (thread-safe). Side-effect
 * methods on [session] are called from the broker thread (inside the
 * inbound handler) and from arbitrary UI threads (user events).
 * [WormholeBrokerSession.send*] is fire-and-forget through
 * okhttp's WS queue — safe from any thread.
 *
 * Lifecycle: construct with a `parentScope` (typically the screen's
 * CoroutineScope from `rememberCoroutineScope()`); call [dispose]
 * when the screen closes.
 */
class WormholeJoinController(
    private val brokerWss: String,
    private val brokerKey: String,
    private val parentScope: CoroutineScope,
    /** Optional human-readable device name (e.g. `Build.MODEL`).
     * Carried in [JoinerEnrollInfo.deviceName] so the host's UI can
     * show "Android phone" rather than just a base64 pubkey. */
    private val deviceName: String? = null,
    /** Test seam: skip real keypair generation by injecting a
     * pre-built (privB64, pubB64) pair. Production callers leave
     * this null. */
    private val keypairOverride: Pair<String, String>? = null,
    private val transportFactory: (CoroutineScope) -> WormholeTransport =
        { scope -> OfferListenerWormholeTransport(brokerWss, brokerKey, scope) },
) {
    private val ownJob = SupervisorJob(parentScope.coroutineContext[Job])
    private val ownScope = CoroutineScope(parentScope.coroutineContext + ownJob)

    private val _state = MutableStateFlow<WormholeJoinUiState>(
        WormholeJoinUiState.EnteringCode())
    val state: StateFlow<WormholeJoinUiState> = _state.asStateFlow()

    @Volatile private var session: WormholeBrokerSession? = null
    @Volatile private var spake2: Spake2? = null
    @Volatile private var sharedKey: ByteArray? = null

    /** A peer-confirm (mac + optional encrypted info) that arrived
     * while we were still in ConfirmingSas (before the user tapped
     * our Confirm button). Buffered here so [userConfirm] can act
     * on it instead of hanging forever waiting for a re-send. */
    @Volatile private var pendingPeerMac: ByteArray? = null
    @Volatile private var pendingPeerInfoBlob: ByteArray? = null

    /** Joiner's own WG keypair (privB64, pubB64). Generated lazily
     * on submit so [keypairOverride] can pin it for tests. */
    @Volatile private var joinerPriv: String? = null
    @Volatile private var joinerPub: String? = null

    /** After [WormholeJoinUiState.Succeeded], the [Tunnel] the UI
     * should persist. Null until then. */
    private val _resultingTunnel = MutableStateFlow<Tunnel?>(null)
    val resultingTunnel: StateFlow<Tunnel?> = _resultingTunnel.asStateFlow()

    fun onTyped(input: String) {
        val s = _state.value
        if (s is WormholeJoinUiState.EnteringCode) {
            _state.value = s.copy(typed = input)
        }
    }

    /** User pressed Connect. No-op if the typed code is malformed
     * (the UI's button-enabled rule should already prevent this). */
    fun submit() {
        val s = _state.value as? WormholeJoinUiState.EnteringCode ?: return
        if (!WormholeCode.isValid(s.typed)) return
        val canonical = WormholeCode.normalize(s.typed)
        _state.value = WormholeJoinUiState.WaitingForResponder(canonical)
        startProtocol(canonical)
    }

    /** User confirmed the SAS phrase matches. Sends our role-MAC
     * and waits for the peer's. */
    fun userConfirm() {
        val s = _state.value as? WormholeJoinUiState.ConfirmingSas ?: return
        val key = sharedKey ?: return failNow("internal: no shared key")
        _state.value = WormholeJoinUiState.AwaitingPeerConfirm(s.code)
        val mac = buildSasConfirmMac(SasConfirmRole.INITIATOR, key)
        // Encrypted enrollment info: our pubkey + device name.
        val joinerInfo = JoinerEnrollInfo(
            timestamp = System.currentTimeMillis() / 1000,
            wgPubkeyB64 = joinerPub ?: return failNow("internal: keypair missing"),
            deviceName = deviceName,
        )
        val infoBlob = encodeJoinerInfo(joinerInfo, key)
        val sendOk = session?.let { it.sendConfirmWithInfo(mac, infoBlob) } ?: false
        if (!sendOk) {
            return failNow("broker refused the confirm message")
        }
        // If the peer's MAC already arrived (race against
        // user-confirm), process it now.
        pendingPeerMac?.let { peerMac ->
            val peerInfoBlob = pendingPeerInfoBlob
            pendingPeerMac = null
            pendingPeerInfoBlob = null
            verifyAndAdvance(peerMac, peerInfoBlob, key, s.code)
        }
    }

    /** User pressed back / aborted. Best-effort teardown. */
    fun cancel() {
        if (terminal()) return
        _state.value = WormholeJoinUiState.Failed("cancelled")
        teardown()
    }

    /** Final teardown when the screen leaves. */
    fun dispose() {
        teardown()
        ownJob.cancel()
    }

    private fun startProtocol(code: String) {
        val codeBytes = WormholeCode.toBytes(code)
        // Generate (or accept overridden) WG keypair for the joiner.
        val (privB64, pubB64) = keypairOverride ?: generateWgKeypair()
        joinerPriv = privB64
        joinerPub = pubB64
        val transport = transportFactory(ownScope)
        val s = WormholeBrokerSession(SasConfirmRole.INITIATOR, codeBytes, transport)
        session = s
        spake2 = Spake2(Spake2.Role.ALICE, codeBytes)
        ownScope.launch {
            try {
                s.start { event -> onInbound(event, code) }
                val msgI = spake2!!.start()
                if (!s.sendStep1(msgI)) {
                    failNow("broker dropped the session before step 1 could send")
                }
            } catch (t: java.io.IOException) {
                failNow("couldn't reach the signaling broker (${t.message})")
            } catch (t: Throwable) {
                failNow("wormhole session failed: ${t.javaClass.simpleName}: ${t.message}")
            }
        }
    }

    private fun onInbound(event: SasInbound, code: String) {
        when (event) {
            is SasInbound.Step2 -> {
                val sp = spake2 ?: return
                val key = try { sp.finish(event.parsed.pakeMsg) }
                          catch (t: Throwable) {
                              return failNow("PAKE finish failed: ${t.message}")
                          }
                sharedKey = key
                val sas = deriveSas(key)
                _state.value = WormholeJoinUiState.ConfirmingSas(code, sas)
            }
            is SasInbound.Confirm -> {
                val key = sharedKey
                if (key == null) {
                    // Confirm arrived before SAS computed (impossibly
                    // out of order from a well-behaved peer). Drop.
                    return
                }
                when (val st = _state.value) {
                    is WormholeJoinUiState.AwaitingPeerConfirm ->
                        verifyAndAdvance(event.parsed.mac,
                            event.parsed.encryptedInfo, key, st.code)
                    is WormholeJoinUiState.ConfirmingSas -> {
                        // Peer beat us to the confirm step — buffer
                        // the MAC + info so userConfirm can act on
                        // them as a unit.
                        pendingPeerMac = event.parsed.mac
                        pendingPeerInfoBlob = event.parsed.encryptedInfo
                    }
                    else -> { /* terminal or earlier; drop */ }
                }
            }
            is SasInbound.Step1 -> {
                // Initiator never receives Step1. Probably a stray
                // broker delivery — drop silently.
            }
        }
    }

    private fun verifyAndAdvance(
        peerMac: ByteArray,
        peerInfoBlob: ByteArray?,
        key: ByteArray,
        code: String,
    ) {
        val macOk = verifySasConfirmMac(SasConfirmRole.RESPONDER, key, peerMac)
        if (!macOk) {
            return failNow("peer MAC verification failed — possible MITM")
        }
        // If the host sent enrollment info, decode it + build
        // a usable tunnel for the UI to persist. Missing info is
        // tolerated (legacy mac-only confirm path) — Succeeded
        // fires without a [resultingTunnel]. Decoding failure when
        // info IS present is a hard error: the only reason valid
        // ciphertext fails to decode is a key mismatch (= MITM).
        if (peerInfoBlob != null) {
            val hostInfo = decodeHostInfo(peerInfoBlob, key)
                ?: return failNow("peer info decode failed — wrong key or stale ts")
            val priv = joinerPriv ?: return failNow("internal: no priv key")
            _resultingTunnel.value = buildJoinerTunnel(priv, hostInfo)
        }
        _state.value = WormholeJoinUiState.Succeeded
        teardown()
    }

    private fun buildJoinerTunnel(privB64: String, host: HostEnrollInfo): Tunnel {
        val configText = buildString {
            append("[Interface]\n")
            append("PrivateKey = ").append(privB64).append('\n')
            append("Address = ").append(host.assignedAddress).append('\n')
            host.dns?.let { append("DNS = ").append(it).append('\n') }
            host.mtu?.let { append("MTU = ").append(it).append('\n') }
            append("\n[Peer]\n")
            append("PublicKey = ").append(host.wgPubkeyB64).append('\n')
            append("Endpoint = ").append(host.wgEndpoint).append('\n')
            // Canonicalize — see WgAllowedIps. Even though the host
            // is our own code, the field traversed a user textbox at
            // some point + we don't want a fixable mistake on the
            // host side to cripple the joiner's tunnel on import.
            append("AllowedIPs = ")
                .append(WgAllowedIps.canonicalize(host.allowedIps))
                .append('\n')
            host.keepalive?.let {
                append("PersistentKeepalive = ").append(it).append('\n')
            }
        }.trimEnd('\n')
        val name = host.hostName?.let { "wormhole-$it" } ?: "wormhole-tunnel"
        return Tunnel(
            name = name,
            configText = configText,
            // ENROLL is the closest existing source. Adding a new
            // WORMHOLE source would force every Source switch to
            // grow a branch; not worth the churn for an origin tag.
            source = Tunnel.Source.ENROLL,
            brokerWss = host.brokerWss,
            brokerKey = host.brokerKey,
            saltB64 = host.saltB64,
        )
    }

    private fun failNow(reason: String) {
        if (terminal()) return
        _state.value = WormholeJoinUiState.Failed(reason)
        teardown()
    }

    private fun terminal(): Boolean = _state.value is WormholeJoinUiState.Succeeded ||
        _state.value is WormholeJoinUiState.Failed

    private fun generateWgKeypair(): Pair<String, String> {
        val priv = ByteArray(32).also { SecureRandom().nextBytes(it) }
        // Standard X25519 / WG clamping. wireguard-go accepts
        // unclamped keys (it clamps internally), but we write the
        // post-clamp value to disk so wg-quick parsers don't trip
        // up on the raw bytes.
        priv[0] = (priv[0].toInt() and 0xf8).toByte()
        priv[31] = ((priv[31].toInt() and 0x7f) or 0x40).toByte()
        val pub = pubKeyFromPrivate(priv)
        return Base64.getEncoder().encodeToString(priv) to
            Base64.getEncoder().encodeToString(pub)
    }

    private fun teardown() {
        val s = session
        session = null
        if (s != null) {
            // Launch on parentScope so the close survives ownJob's
            // cancellation in [dispose] — otherwise the broker
            // subscription leaks (the OfferListener's stop()
            // never gets to run before the scope dies).
            parentScope.launch {
                try { s.close() } catch (_: Throwable) {}
            }
        }
    }
}
