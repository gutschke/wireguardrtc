package com.gutschke.wgrtc.service

import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.net.VpnService
import android.os.Binder
import android.os.IBinder
import android.util.Log
import com.gutschke.wgrtc.data.VpnServiceFdProtector
import com.gutschke.wgrtc.data.WgFdProtector

/**
 * host-mode [VpnService] skeleton. The role is narrow:
 *
 * 1. Be a registered VpnService so [protect] is callable on its
 * file descriptors — the only way to make the wire-side WG
 * socket bypass any OTHER active VPN that the user has on the
 * device (Cloudflare WARP, NordVPN, etc.).
 * 2. Provide an in-process [LocalBinder] so the foreground
 * controller can fetch a [WgFdProtector] adapter and pass it
 * to [com.gutschke.wgrtc.data.UserspaceWgEndpoint.setProtector].
 *
 * What this class deliberately does NOT do (yet):
 * - It does NOT call [Builder.establish]. doesn't need a
 * captive TUN — every accepted peer connection is forwarded via
 * the phone's app uid as a regular socket, and protect() works
 * on a started VpnService even without an established tunnel.
 * (Cascade mode in a later iteration would call establish().)
 * - It does NOT manage the WG endpoint lifecycle. That'll be
 * wired in by: the host-mode controller
 * constructs a [com.gutschke.wgrtc.data.UserspaceWgEndpoint],
 * hands `service.makeFdProtector()` to it, and starts the
 * listeners.
 *
 * Lifecycle: started via the standard `VpnService.prepare(ctx)` →
 * `startService(intent)` flow. Stopped via the action [ACTION_STOP].
 *
 * NOTE: not registered in AndroidManifest.xml here — the manifest
 * change lands together with to avoid shipping a half-wired
 * service in intermediate alpha builds. The class is fully
 * compilable on its own; verifying it with a unit test for the
 * adapter (see [VpnServiceFdProtectorTest]) is the testable seam.
 */
class HostModeVpnService : VpnService() {

 /**
 * In-process binder — clients call [getService] to access the
 * [HostModeVpnService] instance directly. Out-of-process IPC
 * isn't needed; both the controller (foreground service) and
 * this VpnService run in the app's main process.
 */
 inner class LocalBinder : Binder() {
 fun getService(): HostModeVpnService = this@HostModeVpnService
 }

 private val binder = LocalBinder()

 override fun onBind(intent: Intent?): IBinder? {
 // Android calls onBind with VpnService.SERVICE_INTERFACE
 // when the system performs the prepare() handshake. Defer
 // to the parent for those, return our LocalBinder for any
 // app-internal bind.
 if (intent?.action == SERVICE_INTERFACE) return super.onBind(intent)
 return binder
 }

 override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
 when (intent?.action) {
 ACTION_STOP -> {
 Log.i(TAG, "stop requested")
 stopSelf()
 return Service.START_NOT_STICKY
 }
 else -> {
 Log.i(TAG, "started (no-op skeleton — full wiring lands with )")
 }
 }
 return Service.START_STICKY
 }

 /**
 * Build a [WgFdProtector] backed by this service's
 * [VpnService.protect]. The protector is safe to share across
 * threads — `protect(int)` is documented as thread-safe.
 */
 fun makeFdProtector(): WgFdProtector =
 VpnServiceFdProtector { fd -> protect(fd) }

 /**
 * Build the [PendingIntent] used to bring the user back to the
 * controller activity from the system VPN status bar. Stub
 * for now; the real implementation lives in the foreground
 * service that starts us.
 */
 @Suppress("unused")
 fun makeConfigureIntent(): PendingIntent? = null

 companion object {
 private const val TAG = "HostModeVpnService"
 const val ACTION_STOP = "com.gutschke.wgrtc.host.STOP"
 }
}
