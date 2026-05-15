package com.gutschke.wgrtc.data

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import com.gutschke.wgrtc.service.JoinerNVpnService
import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Bound connection to the shared [JoinerNVpnService]. Mirrors
 * [JoinerVpnBinding] for the multi-joiner case. The service is a
 * singleton (Android's per-process VpnService rule); the ViewModel
 * caches the binding across joiner add/remove cycles so the kernel
 * TUN survives the swap.
 */
class JoinerNVpnBinding internal constructor(
    private val context: Context,
    private val connection: ServiceConnection,
    val service: JoinerNVpnService,
) {
    @Volatile private var unbound = false

    fun unbind() {
        if (unbound) return
        unbound = true
        try { context.unbindService(connection) } catch (_: Throwable) {}
    }
}

/**
 * Bind to [JoinerNVpnService] and suspend until its [LocalBinder]
 * fires. `BIND_AUTO_CREATE` starts the service on first bind so the
 * caller can `addJoiner` immediately after the suspend resumes.
 *
 * Throws on synchronous bind failure; propagates cancellation
 * cleanly when the coroutine is canceled before the binder fires.
 */
suspend fun bindJoinerNVpnService(context: Context): JoinerNVpnBinding =
    suspendCancellableCoroutine { cont: CancellableContinuation<JoinerNVpnBinding> ->
        val intent = Intent(context, JoinerNVpnService::class.java)
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, b: IBinder?) {
                val binder = b as? JoinerNVpnService.LocalBinder
                if (binder != null) {
                    cont.resume(JoinerNVpnBinding(context, this, binder.getService()))
                } else {
                    try { context.unbindService(this) } catch (_: Throwable) {}
                    cont.resumeWithException(IllegalStateException(
                        "JoinerNVpnService didn't return a LocalBinder"))
                }
            }
            override fun onServiceDisconnected(name: ComponentName?) {
                // Killed by the system; the next addJoiner call will
                // raise an error through the existing error path.
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
                "bindService(JoinerNVpnService) returned false"))
            return@suspendCancellableCoroutine
        }
        cont.invokeOnCancellation {
            try { context.unbindService(connection) } catch (_: Throwable) {}
        }
    }
