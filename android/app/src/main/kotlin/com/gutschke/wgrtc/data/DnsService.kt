package com.gutschke.wgrtc.data

import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * Glue between [DnsProxy] (pure wire-format logic) and the
 * WG-side UDP listener machinery in [WgBridgeBackend]. When
 * started, opens a UDP listener on port 53 of the host's gvisor
 * netstack; every inbound query is dispatched to a coroutine on
 * [scope] (so the listener callback returns instantly + slow
 * upstream resolution doesn't block the netstack reader).
 *
 * The Android resolver call (`InetAddress.getAllByName`) can
 * take up to a few seconds in pathological cases; doing it
 * synchronously in the UDP callback would back up the netstack's
 * inbound queue and stall every concurrent query. The
 * supervisor-job scope here means a single bad lookup doesn't
 * tear down the rest.
 *
 * **Lifecycle.** Call [start] once when the host bridge comes
 * up; call [stop] on teardown. Idempotent both ways. Owns its
 * own scope so the consumer doesn't have to thread one through.
 */
class DnsService(
    private val proxy: DnsProxy,
    parent: CoroutineScope,
    private val tag: String = "wgrtc-dns",
) {
    private val job = SupervisorJob(parent.coroutineContext[Job])
    private val scope = CoroutineScope(parent.coroutineContext + job + Dispatchers.IO)
    private var sink: WgUdpSink? = null
    @Volatile private var started = false

    /**
     * Bind UDP:53 on [backend]'s netstack and start receiving.
     * Throws if the bind itself fails (e.g., port collision —
     * shouldn't happen on a fresh netstack but we surface
     * cleanly).
     */
    fun start(backend: WgBridgeBackend) {
        check(!started) { "DnsService already started" }
        started = true
        sink = backend.listenUdp(53, object : WgUdpReceiver {
            override fun onDatagram(peerAddr: String, listenAddr: String, data: ByteArray) {
                // Hand off to a coroutine so the netstack reader
                // doesn't wait for our resolver call to return.
                scope.launch {
                    try {
                        val reply = proxy.handle(data)
                        if (reply != null) {
                            sink?.sendTo(peerAddr, reply)
                        }
                    } catch (t: Throwable) {
                        Log.w(tag, "DNS handle from $peerAddr failed", t)
                    }
                }
            }
        })
        Log.i(tag, "DNS proxy listening on udp:53")
    }

    /** Stop accepting queries. Idempotent. */
    fun stop() {
        if (!started) return
        started = false
        try { sink?.close() } catch (_: Throwable) {}
        sink = null
        // Cancel in-flight resolutions. Each launch{} is its
        // own coroutine; cancelling the parent job cancels them
        // all without affecting the consumer's parent scope.
        scope.cancel()
    }
}
