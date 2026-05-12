package com.gutschke.wgrtc.data

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import com.gutschke.wgrtc.service.JoinerVpnService
import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * One bound connection to a [JoinerVpnService]. Owns the
 * [ServiceConnection] so the caller can [unbind] symmetrically
 * with [bindJoinerVpnService]. Without this, holding a reference
 * to the service alone leaks the binding.
 */
class JoinerVpnBinding internal constructor(
    private val context: Context,
    private val connection: ServiceConnection,
    val service: JoinerVpnService,
) {
    @Volatile private var unbound = false

    /** Idempotent unbind. After this, [service] is no longer
     * guaranteed to be reachable — the system can stop the
     * service if no other binders / startService remain. */
    fun unbind() {
        if (unbound) return
        unbound = true
        try { context.unbindService(connection) } catch (_: Throwable) {}
    }
}

/**
 * Bind to [JoinerVpnService] and suspend until its [LocalBinder]
 * fires. `Context.BIND_AUTO_CREATE` ensures the system creates
 * the service if it isn't already running — typical for the first
 * Connect of a joiner tunnel.
 *
 * Throws [IllegalStateException] if the bind fails synchronously.
 * If the binder never fires (e.g. process death between bind and
 * connect), cancellation propagates through the coroutine and the
 * connection is unbound on the way out.
 */
suspend fun bindJoinerVpnService(context: Context): JoinerVpnBinding =
    suspendCancellableCoroutine { cont: CancellableContinuation<JoinerVpnBinding> ->
        val intent = Intent(context, JoinerVpnService::class.java)
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, b: IBinder?) {
                val binder = b as? JoinerVpnService.LocalBinder
                if (binder != null) {
                    cont.resume(JoinerVpnBinding(context, this, binder.getService()))
                } else {
                    try { context.unbindService(this) } catch (_: Throwable) {}
                    cont.resumeWithException(IllegalStateException(
                        "JoinerVpnService didn't return a LocalBinder"))
                }
            }
            override fun onServiceDisconnected(name: ComponentName?) {
                // System killed the service; nothing graceful to do here.
                // The bound caller's next service call will fail; let
                // the existing error-propagation path handle it.
            }
        }
        val ok = try {
            context.bindService(intent, connection, Context.BIND_AUTO_CREATE)
        } catch (t: Throwable) {
            cont.resumeWithException(t)
            return@suspendCancellableCoroutine
        }
        if (!ok) {
            try { context.unbindService(connection) } catch (_: Throwable) {}
            cont.resumeWithException(IllegalStateException(
                "bindService(JoinerVpnService) returned false"))
            return@suspendCancellableCoroutine
        }
        cont.invokeOnCancellation {
            try { context.unbindService(connection) } catch (_: Throwable) {}
        }
    }
