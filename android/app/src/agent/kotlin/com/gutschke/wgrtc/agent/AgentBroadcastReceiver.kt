package com.gutschke.wgrtc.agent

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import com.gutschke.wgrtc.data.Tunnel
import com.gutschke.wgrtc.data.TunnelStore
import java.util.Base64
import java.util.UUID

/**
 * Entry point for adb-driven instrumentation of wgrtc.
 *
 * Only compiled into the `agent` buildType (applicationId
 * `com.gutschke.wgrtc.agent`). The src/main/ AndroidManifest does
 * not reference it, and the source file lives in `src/agent/kotlin/`
 * — so it's physically absent from the standard debug + release APKs
 * that get distributed.
 *
 * Smoke-test invocation from a connected adb host:
 *
 * ```
 * adb shell am broadcast \
 *   -n com.gutschke.wgrtc.agent/com.gutschke.wgrtc.agent.AgentBroadcastReceiver \
 *   -a com.gutschke.wgrtc.agent.ADD_TUNNEL \
 *   --es name 'smoke-test' \
 *   --es config '[Interface]\nPrivateKey = ...\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = ...\nEndpoint = host:51820\nAllowedIPs = 10.0.0.0/24\n'
 * ```
 *
 * Result is delivered via the broadcast result protocol — capture
 * with `am broadcast … -W` and look at the `Broadcast completed:`
 * line for result code + data.
 *
 * Additional actions (TOGGLE, MINT_WORMHOLE, REVOKE_PEER, …) follow
 * the same pattern: extend the [onReceive] switch, register the
 * action in `src/agent/AndroidManifest.xml`, document it here.
 */
class AgentBroadcastReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            ACTION_ADD_TUNNEL -> handleAddTunnel(context, intent)
            else -> {
                Log.w(TAG, "unknown action: ${intent.action}")
                resultCode = RESULT_BAD_REQUEST
                resultData = "unknown action: ${intent.action}"
            }
        }
    }

    private fun handleAddTunnel(context: Context, intent: Intent) {
        // Two ways to pass the wg-quick text: literal (single-line
        // configs only — the shell mangles embedded newlines on the
        // `am broadcast --es config '…'` path) or base64-encoded
        // (always safe). Callers that build the intent programmatically
        // can use either.
        val literal = intent.getStringExtra(EXTRA_CONFIG)?.trim()
        val b64 = intent.getStringExtra(EXTRA_CONFIG_B64)?.trim()
        val config: String? = when {
            !literal.isNullOrEmpty() -> literal
            !b64.isNullOrEmpty() -> try {
                String(Base64.getDecoder().decode(b64), Charsets.UTF_8).trim()
            } catch (_: IllegalArgumentException) {
                resultCode = RESULT_BAD_REQUEST
                resultData = "bad base64 in --es $EXTRA_CONFIG_B64"
                return
            }
            else -> null
        }
        if (config.isNullOrEmpty()) {
            resultCode = RESULT_BAD_REQUEST
            resultData = "missing --es $EXTRA_CONFIG or --es $EXTRA_CONFIG_B64"
            Log.w(TAG, "ADD_TUNNEL rejected: empty config")
            return
        }
        val name = intent.getStringExtra(EXTRA_NAME)?.takeIf { it.isNotBlank() }
            ?: "agent-${UUID.randomUUID().toString().take(8)}"
        val sourceTag = intent.getStringExtra(EXTRA_SOURCE)?.uppercase()
        val source = when (sourceTag) {
            "LEGACY" -> Tunnel.Source.LEGACY
            "ENROLL" -> Tunnel.Source.ENROLL
            "HOST_MODE" -> Tunnel.Source.HOST_MODE
            null, "MANUAL" -> Tunnel.Source.MANUAL
            else -> {
                resultCode = RESULT_BAD_REQUEST
                resultData = "bad $EXTRA_SOURCE: $sourceTag"
                return
            }
        }

        val store = TunnelStore(context.applicationContext)
        val before = store.load()
        if (before.any { it.name == name }) {
            resultCode = RESULT_NAME_CLASH
            resultData = "name already in use: $name"
            Log.w(TAG, "ADD_TUNNEL rejected: name clash on $name")
            return
        }
        val tunnel = Tunnel(
            name = name,
            configText = config,
            source = source,
        )
        store.save(before + tunnel)
        Log.i(TAG, "ADD_TUNNEL added id=${tunnel.id} name=$name source=$source")
        resultCode = RESULT_OK
        resultData = tunnel.id
    }

    companion object {
        const val ACTION_ADD_TUNNEL = "com.gutschke.wgrtc.agent.ADD_TUNNEL"

        const val EXTRA_NAME = "name"
        const val EXTRA_CONFIG = "config"
        const val EXTRA_CONFIG_B64 = "configB64"
        const val EXTRA_SOURCE = "source"

        // Activity.RESULT_OK is 0; broadcast result conventions reuse it.
        const val RESULT_OK = 0
        const val RESULT_BAD_REQUEST = 1
        const val RESULT_NAME_CLASH = 2

        private const val TAG = "wgrtc-agent"
    }
}
