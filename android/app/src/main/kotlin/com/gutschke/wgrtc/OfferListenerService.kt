package com.gutschke.wgrtc

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

/**
 * Foreground service whose sole job is to keep the application
 * process alive while at least one [com.gutschke.wgrtc.data.ListenerHub]
 * OFFER listener is running, so the listener (and the Endpoint = `
 * line in tunnels.json) keeps following the daemon's roaming
 * STUN-discovered IP across activity backgrounding.
 *
 * Modern Android (12+) will aggressively suspend long-lived network
 * sockets when the owning process has no foreground component. A
 * foreground service with `foregroundServiceType="specialUse"` is
 * the documented path for "ongoing background data exchange that
 * doesn't fit into the dataSync / mediaPlayback / location buckets."
 *
 * Intentionally a *started* service (not bound). ViewModel sends
 * an Intent; Application.onCreate sends an Intent; the service
 * outlives both because Android holds a reference until we call
 * `stopSelf()`. We `stopSelf()` once the hub's `activeCount` drops
 * to zero (e.g. user deletes the last ENROLL tunnel).
 *
 * We do NOT inflate the joiner / host VpnService here — those are
 * separate foreground responsibilities ([JoinerVpnService] for
 * client tunnels, [HostModeVpnService] for hosted ones) and only
 * run while the user has a tunnel UP.
 */
class OfferListenerService : Service() {

    private val scope = CoroutineScope(Dispatchers.Default + SupervisorJob())
    private var watchJob: Job? = null

    override fun onCreate() {
        super.onCreate()
        ensureChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Foreground promotion must happen within ~5 s of
        // startForegroundService(); doing it unconditionally on
        // every start keeps the contract simple. Re-issuing the
        // notification with the latest count is a no-op when the
        // listener count hasn't changed (Android dedupes by
        // (notificationId, channelId)).
        val count = WgrtcApp.instance.listenerHub.activeCount
        if (count == 0) {
            // No listeners to keep alive. Start foreground to
            // satisfy the system contract, then immediately stop.
            startForegroundCompat(buildNotification(0))
            stopSelf(startId)
            return START_NOT_STICKY
        }
        startForegroundCompat(buildNotification(count))

        // Watch the hub's active-count flow: when it goes to zero
        // (last ENROLL tunnel removed) we tear ourselves down
        // proactively rather than waiting for an explicit STOP
        // intent. collectLatest cancels the previous collector
        // when restarted; idempotent across multiple onStartCommand.
        watchJob?.cancel()
        watchJob = scope.launch {
            WgrtcApp.instance.listenerHub.activeCountFlow.collectLatest { n ->
                if (n == 0) {
                    Log.i(TAG, "no listeners left; stopping service")
                    stopSelf()
                } else {
                    notificationManager.notify(NOTIFICATION_ID, buildNotification(n))
                }
            }
        }

        // START_STICKY: the system will recreate us with a null
        // intent if the process is killed, and onStartCommand will
        // re-evaluate. WgrtcApp.onCreate runs first on recreate
        // and re-attaches listeners from disk, so our re-evaluation
        // sees the right activeCount.
        return START_STICKY
    }

    override fun onDestroy() {
        super.onDestroy()
        scope.cancel()
    }

    /** Started service, no IPC clients. */
    override fun onBind(intent: Intent?): IBinder? = null

    private fun startForegroundCompat(notif: Notification) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            // Android 14+ requires a type matching the manifest's
            // foregroundServiceType attribute. We use specialUse
            // because no narrower bucket fits "long-lived
            // signalling websocket that doesn't move user data."
            startForeground(NOTIFICATION_ID, notif,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notif)
        }
    }

    private fun buildNotification(count: Int): Notification {
        val openApp = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val hidden = WgrtcApp.instance.settings.hideListenerNotification
        val channel = if (hidden) CHANNEL_ID_HIDDEN else CHANNEL_ID
        val text = if (count == 0)
            "wgrtc — listening for endpoint updates"
        else
            "wgrtc — tracking $count tunnel${if (count == 1) "" else "s"}"
        return NotificationCompat.Builder(this, channel)
            .setContentTitle("wgrtc")
            .setContentText(text)
            // stat_sys_vpn_ic is not in the public android.R; use a
            // stable system fallback that always renders.
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(openApp)
            .setOngoing(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(
                if (hidden) NotificationCompat.PRIORITY_MIN
                else NotificationCompat.PRIORITY_LOW
            )
            .build()
    }

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val normal = NotificationChannel(
            CHANNEL_ID, "Endpoint tracking",
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description =
                "Ongoing notification while wgrtc keeps your " +
                "enrolled tunnels' server endpoints up to date."
            setShowBadge(false)
        }
        // Min-importance channel for the hide-notification advanced
        // setting. Android still requires a foreground-service to
        // post *some* notification; this one's IMPORTANCE_MIN keeps
        // it out of the shade. Users who care can re-enable from
        // Settings inside the app or via Android's per-channel
        // notification controls.
        val hidden = NotificationChannel(
            CHANNEL_ID_HIDDEN, "Endpoint tracking (hidden)",
            NotificationManager.IMPORTANCE_MIN,
        ).apply {
            description =
                "Minimum-importance version of the endpoint-tracking " +
                "notification. Used when the in-app 'Hide listener " +
                "notification' advanced setting is enabled."
            setShowBadge(false)
        }
        notificationManager.createNotificationChannel(normal)
        notificationManager.createNotificationChannel(hidden)
    }

    private val notificationManager: NotificationManager
        get() = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

    companion object {
        const val CHANNEL_ID = "wgrtc.listener"
        const val CHANNEL_ID_HIDDEN = "wgrtc.listener.hidden"
        const val NOTIFICATION_ID = 1
        const val TAG = "wgrtc-svc"

        fun startIntent(context: Context): Intent =
            Intent(context, OfferListenerService::class.java)
    }
}
