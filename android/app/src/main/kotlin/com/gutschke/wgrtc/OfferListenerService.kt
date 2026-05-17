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
    /**
     * Periodic VPN-consent re-check.  See `docs/ux-design-v2.md`
     * §6.1 step 4 (round-2 amendment A1).  Closes the
     * phantom-active blind window for users who never re-foreground
     * the app — the dominant phantom-active cohort.
     *
     * Cadence: every 30 minutes while the FGS is alive.  A `Service`
     * can call `VpnService.prepare(this)` to DETECT consent loss
     * (non-null Intent return value); it can't launch the consent
     * UI (Activity-only) but detection is all we need to fire
     * registry.recordRevoke(BackgroundResync).
     */
    private var consentRecheckJob: Job? = null

    override fun onCreate() {
        super.onCreate()
        ensureChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // a user tapping the notification's "Stop tracking"
        // action delivers an Intent with action ACTION_DISMISS back
        // to us.  We must still call startForeground() within the
        // 5-second window before bailing — Android enforces it for
        // EVERY startForegroundService delivery, including the
        // sticky-redelivery case where the system recreates the
        // process and re-runs us with the dismiss intent before we
        // ever ran the normal start path.  Without this we'd hit
        // ForegroundServiceDidNotStartInTimeException → ANR.
        if (intent?.action == ACTION_DISMISS) {
            Log.i(TAG, "ACTION_DISMISS received; stopping FGS")
            startForegroundCompat(buildNotification(0))
            // Cancel the activeCountFlow collector explicitly —
            // otherwise it can keep running long enough to fire a
            // new notify() AFTER we've canceled the notification,
            // creating a brief flicker / re-post race.  scope.cancel
            // in onDestroy only runs after stopSelf's async teardown.
            watchJob?.cancel()
            watchJob = null
            stopForegroundCompat(removeNotification = true)
            stopSelf(startId)
            return START_NOT_STICKY
        }
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
        consentRecheckJob?.cancel()
        consentRecheckJob = scope.launch { runConsentRecheckLoop() }

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

    /**
     * Background phantom-active detector.  Every
     * [CONSENT_RECHECK_PERIOD_MS] we ask Android whether the VPN
     * permission is still granted; if not, we mark every currently-
     * active joiner as `Paused (system, BackgroundResync)` in the
     * registry.  The signal-1-2-3 path (establish-null, onRevoke,
     * MainActivity.onResume) catches the dominant cases; this loop
     * catches the user-never-foregrounds-the-app case where none of
     * those fire and the UI would otherwise lie indefinitely.
     *
     * Gating: skip the prepare() call entirely when no joiner has
     * `intent=WantsOn`.  Reading [WgrtcApp.listenerHub] tunnels lets
     * us check without binding to the joiner service.  Prepare's
     * cost is ~a millisecond; this is more about not waking
     * anything we don't have to.
     */
    private suspend fun runConsentRecheckLoop() {
        while (true) {
            kotlinx.coroutines.delay(CONSENT_RECHECK_PERIOD_MS)
            try {
                val tunnels = WgrtcApp.instance.listenerHub.loadTunnels()
                val joinerWantsOnIds = tunnels
                    .filter {
                        it.source != com.gutschke.wgrtc.data.Tunnel.Source.HOST_MODE &&
                            it.intent == com.gutschke.wgrtc.data.TunnelIntent.WantsOn
                    }
                    .map { it.id }
                if (joinerWantsOnIds.isEmpty()) continue
                val consent = android.net.VpnService.prepare(this)
                if (consent != null) {
                    val registry = com.gutschke.wgrtc.data.TunnelStateRegistry
                        .getProcessSingleton()
                    for (id in joinerWantsOnIds) {
                        registry.recordRevoke(
                            id,
                            com.gutschke.wgrtc.data.PauseReason.BackgroundResync,
                            note = "FGS periodic re-prepare returned non-null Intent",
                        )
                    }
                    Log.i(TAG,
                        "background re-prepare detected consent loss for $joinerWantsOnIds")
                }
            } catch (t: Throwable) {
                // Re-prepare itself shouldn't fail, but if anything
                // along the path throws (tunnel-store I/O, registry
                // mutation, framework error) we don't want the loop
                // to die.  Log and continue.
                Log.w(TAG, "consent recheck threw: ${t.message}", t)
            }
        }
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

    @Suppress("DEPRECATION")
    private fun stopForegroundCompat(removeNotification: Boolean) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(
                if (removeNotification) STOP_FOREGROUND_REMOVE
                else STOP_FOREGROUND_DETACH)
        } else {
            stopForeground(removeNotification)
        }
        if (removeNotification) {
            // Belt-and-suspenders: also cancel the notification by
            // id.  Without this the FGS notification can briefly
            // linger on some Android builds because
            // stopForeground(REMOVE) and the underlying service
            // teardown race each other.
            notificationManager.cancel(NOTIFICATION_ID)
        }
    }

    private fun buildNotification(count: Int): Notification {
        val hidden = WgrtcApp.instance.settings.hideListenerNotification
        val names = try {
            WgrtcApp.instance.listenerHub.activeTunnelNames()
        } catch (_: Throwable) {
            // Defensive: TunnelStore.load() may fail on a corrupt
            // store.  Fall back to a count-only body rather than
            // breaking the FGS-must-post-a-notification contract.
            emptyList()
        }
        return buildNotificationFor(this, count, hidden, names)
    }

    private fun ensureChannel() {
        ensureChannelsOn(notificationManager)
    }

    private val notificationManager: NotificationManager
        get() = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

    companion object {
        const val CHANNEL_ID = "wgrtc.listener"
        const val CHANNEL_ID_HIDDEN = "wgrtc.listener.hidden"
        const val NOTIFICATION_ID = 1
        const val TAG = "wgrtc-svc"

        /** 30 min cadence for the background consent re-check.
         *  See [runConsentRecheckLoop] kdoc + `docs/ux-design-v2.md`
         *  §6.1 step 4.  Long enough to be invisible in battery
         *  stats; short enough to catch the "user revoked an hour
         *  ago and never reopened the app" case before they hit
         *  Reconnect and get a confused-looking error. */
        const val CONSENT_RECHECK_PERIOD_MS = 30L * 60L * 1_000L

        // notification action that the user can tap to stop
        // the FGS without going to Settings.  Routed back to
        // [onStartCommand] which calls stopForeground(REMOVE) +
        // stopSelf().  Choosing a service-targeted intent (rather
        // than a BroadcastReceiver hop) avoids a separate
        // <receiver> in the manifest and matches what the system
        // FGS lifecycle wants — the dismiss is a single-shot,
        // start-then-stop command.
        const val ACTION_DISMISS = "com.gutschke.wgrtc.OFFER_LISTENER_DISMISS"

        // Action label exposed in the notification + asserted by
        // the unit-style test.  Visible to the user.  "Stop
        // tracking" leads with the verb users expect for "I want
        // this off" — tapping it actually stops the endpoint-
        // following work, not just the visual.  Parenthetical
        // clarifies the side-effect.
        const val ACTION_DISMISS_LABEL = "Stop tracking (dismiss)"

        // Distinct PendingIntent request codes so the two getService
        // / getActivity slots don't collide in the PendingIntent
        // cache (Android keys reused PendingIntents by
        // (Component, requestCode, Intent#filterEquals)).  Public
        // constants so any other code touching the same intents
        // hits the same slot — accidental collision would clobber
        // one or the other.
        const val REQ_OPEN_APP = 0
        const val REQ_DISMISS = 1

        fun startIntent(context: Context): Intent =
            Intent(context, OfferListenerService::class.java)

        fun dismissIntent(context: Context): Intent =
            Intent(context, OfferListenerService::class.java)
                .setAction(ACTION_DISMISS)

        /**
         * Create the notification channels on first launch.
         * Idempotent — Android dedupes by channel id, so calling
         * this multiple times is safe.  Exposed at the companion
         * level so tests can prime the channels before posting a
         * notification directly via NotificationManager.notify
         * (without spinning up the whole service).
         */
        fun ensureChannelsOn(notificationManager: NotificationManager) {
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
            // Min-importance channel for the hide-notification
            // advanced setting.  Android still requires a foreground
            // service to post SOME notification; IMPORTANCE_MIN keeps
            // it out of the shade.  Users can re-enable from in-app
            // settings or per-channel system controls.
            val hidden = NotificationChannel(
                CHANNEL_ID_HIDDEN, "Endpoint tracking (hidden)",
                NotificationManager.IMPORTANCE_MIN,
            ).apply {
                description =
                    "Minimum-importance version of the endpoint-" +
                    "tracking notification.  Used when the in-app " +
                    "'Hide listener notification' advanced setting " +
                    "is enabled."
                setShowBadge(false)
            }
            notificationManager.createNotificationChannel(normal)
            notificationManager.createNotificationChannel(hidden)
        }

        /**
         * Build the FGS notification.  Pure-ish factory that takes
         * the [hidden] choice and tunnel-name list as parameters so
         * tests don't have to wire up [WgrtcApp] / [SettingsStore] /
         * [com.gutschke.wgrtc.data.TunnelStore] to exercise it.
         *
         * [tunnelNames] is rendered into the BigText expanded body
         * for the host-N case — collapsed line still shows
         * the count.  Pass an empty list when names aren't available
         * (e.g. before the store has loaded); the expanded body then
         * matches the collapsed contentText.
         */
        fun buildNotificationFor(
            context: Context,
            count: Int,
            hidden: Boolean,
            tunnelNames: List<String> = emptyList(),
        ): Notification {
            val openApp = PendingIntent.getActivity(
                context, REQ_OPEN_APP,
                Intent(context, MainActivity::class.java)
                    .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
                PendingIntent.FLAG_IMMUTABLE
                    or PendingIntent.FLAG_UPDATE_CURRENT,
            )
            val dismiss = PendingIntent.getService(
                context, REQ_DISMISS,
                dismissIntent(context),
                PendingIntent.FLAG_IMMUTABLE
                    or PendingIntent.FLAG_UPDATE_CURRENT,
            )
            val channel = if (hidden) CHANNEL_ID_HIDDEN else CHANNEL_ID
            val collapsedText = collapsedBodyText(count)
            val expandedText = expandedBodyText(count, tunnelNames)
            val builder = NotificationCompat.Builder(context, channel)
                .setContentTitle("wgrtc")
                .setContentText(collapsedText)
                // stat_sys_vpn_ic is not in the public android.R;
                // use a stable system fallback that always renders.
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setContentIntent(openApp)
                .setOngoing(true)
                .setCategory(NotificationCompat.CATEGORY_SERVICE)
                .setPriority(
                    if (hidden) NotificationCompat.PRIORITY_MIN
                    else NotificationCompat.PRIORITY_LOW
                )
                .addAction(
                    // ic_menu_close_clear_cancel is in android.R and
                    // therefore always available; no extra resource
                    // baked into the APK.
                    android.R.drawable.ic_menu_close_clear_cancel,
                    ACTION_DISMISS_LABEL,
                    dismiss,
                )
            // BigText only adds value when expanded text differs from
            // the collapsed line.  Skip the style when there's nothing
            // extra to show (count == 0 or names is empty) so we don't
            // inflate the inflated-shade footprint for no reason.
            if (expandedText != collapsedText) {
                builder.setStyle(
                    NotificationCompat.BigTextStyle().bigText(expandedText)
                )
            }
            return builder.build()
        }

        /** Single-line body text shown when the notification is
         * collapsed in the shade.  Counts tunnels but doesn't enumerate
         * them — the count is the load-bearing signal at a glance. */
        internal fun collapsedBodyText(count: Int): String =
            if (count == 0)
                "wgrtc — listening for endpoint updates"
            else
                "wgrtc — tracking $count tunnel${if (count == 1) "" else "s"}"

        /** Expanded BigText body that adds the tunnel-name list under
         * the count header — useful in the host-N case where the user
         * wants to see *which* tunnels are tracked without opening the
         * app.  Returns the same string as [collapsedBodyText] when
         * there's nothing extra to render so callers can skip the
         * BigText style. */
        internal fun expandedBodyText(count: Int, tunnelNames: List<String>): String {
            val header = collapsedBodyText(count)
            if (count == 0 || tunnelNames.isEmpty()) return header
            // Cap at five so very-large-N users don't blow out the
            // expanded body; the trailing "+K more" preserves the
            // total count signal.
            val cap = 5
            val shown = tunnelNames.take(cap)
            val remainder = tunnelNames.size - shown.size
            val list = if (remainder > 0)
                shown.joinToString(", ") + ", +$remainder more"
            else
                shown.joinToString(", ")
            return "$header\n$list"
        }
    }
}
