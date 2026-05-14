package com.gutschke.wgrtc

import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * UX1 — integration coverage for the FGS notification's manual
 * dismiss path.  Skips the service-lifecycle dance (which would
 * require a fully-wired [WgrtcApp] + a HOST_MODE or ENROLL tunnel
 * to keep the service from auto-stopping with activeCount=0) and
 * instead posts the notification directly to NotificationManager,
 * then verifies the dismiss-action's PendingIntent actually cancels
 * it.  The factory itself is unit-tested in
 * [OfferListenerNotificationTest]; here we're proving that the
 * end-to-end notify → tap-dismiss-action → cancel cycle works on
 * the device.
 */
@RunWith(AndroidJUnit4::class)
class OfferListenerNotificationIntegrationTest {

    private val ctx: Context =
        InstrumentationRegistry.getInstrumentation().targetContext
    private val nm: NotificationManager =
        ctx.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

    private fun ourActiveNotification(): android.service.notification.StatusBarNotification? =
        nm.activeNotifications.firstOrNull {
            it.id == OfferListenerService.NOTIFICATION_ID &&
                it.packageName == ctx.packageName
        }

    @After
    fun teardown() {
        nm.cancel(OfferListenerService.NOTIFICATION_ID)
        Thread.sleep(200)
    }

    @org.junit.Before
    fun setUp() {
        // POST_NOTIFICATIONS is API 33+ runtime-permission.  Without
        // it, the app's notify() silently drops the post and
        // activeNotifications returns empty.  Grant via the
        // instrumentation shell so the test is self-sufficient.
        if (android.os.Build.VERSION.SDK_INT >= 33) {
            val auto = InstrumentationRegistry.getInstrumentation().uiAutomation
            auto.grantRuntimePermission(
                ctx.packageName,
                android.Manifest.permission.POST_NOTIFICATIONS,
            )
            // appops needs an explicit set in addition to the
            // runtime grant on some Android variants — the runtime
            // permission turns it from "ignore" to "default", but
            // the test framework grants extras as "allow".
            auto.executeShellCommand(
                "cmd appops set ${ctx.packageName} POST_NOTIFICATION allow"
            ).close()
        }
        // The service's onCreate normally creates these.  Tests post
        // straight to NotificationManager, so we have to prime them
        // ourselves — otherwise notify() silently drops the post
        // on API 26+.
        OfferListenerService.ensureChannelsOn(nm)
    }

    @Test
    fun posted_notification_appears_with_dismiss_action() {
        val n = OfferListenerService.buildNotificationFor(
            ctx, count = 1, hidden = false,
        )
        nm.notify(OfferListenerService.NOTIFICATION_ID, n)
        val sbn = waitForNotificationVisible(timeoutMs = 3000)
        assertNotNull("notification should be visible after notify()", sbn)
        val titles = sbn!!.notification.actions?.map { it.title.toString() }.orEmpty()
        assertTrue(
            "expected a Dismiss action; got $titles",
            titles.any { it.contains("Dismiss", ignoreCase = true) }
        )
    }

    @Test
    fun firing_dismiss_pending_intent_cancels_the_notification() {
        val n = OfferListenerService.buildNotificationFor(
            ctx, count = 1, hidden = false,
        )
        nm.notify(OfferListenerService.NOTIFICATION_ID, n)
        val sbn = waitForNotificationVisible(timeoutMs = 3000)
        assertNotNull("precondition: notification should be posted", sbn)

        // Find the Dismiss action's PendingIntent and fire it,
        // which is exactly what tapping the action in the system
        // shade would do.  The service-side handler then calls
        // stopForeground(REMOVE) + cancel(id) + stopSelf().
        val dismiss = sbn!!.notification.actions?.firstOrNull {
            it.title?.toString()?.contains("Dismiss", ignoreCase = true) == true
        }
        assertNotNull("dismiss action missing", dismiss)
        dismiss!!.actionIntent.send()

        val gone = waitForNotificationGone(timeoutMs = 5000)
        assertTrue(
            "notification should be gone after dismiss action fires; "
            + "still visible after 5 s",
            gone
        )

        // Additional check: a buggy dismiss handler that just calls
        // notificationManager.cancel() without stopSelf() would
        // pass the "notification gone" check above but leave the
        // service running forever.  Wait for the service to
        // actually disappear from getRunningServices to catch that.
        val serviceStopped = waitForServiceGone(timeoutMs = 5000)
        assertTrue(
            "OfferListenerService should have stopped itself in "
            + "addition to clearing the notification; still listed "
            + "in getRunningServices after 5 s",
            serviceStopped
        )
    }

    private fun waitForServiceGone(timeoutMs: Long): Boolean {
        val am = ctx.getSystemService(Context.ACTIVITY_SERVICE)
            as android.app.ActivityManager
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            @Suppress("DEPRECATION")
            val running = am.getRunningServices(Int.MAX_VALUE)
            val ours = running.any {
                it.service.className == OfferListenerService::class.java.name
            }
            if (!ours) return true
            Thread.sleep(100)
        }
        return false
    }

    private fun waitForNotificationVisible(timeoutMs: Long): android.service.notification.StatusBarNotification? {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            val sbn = ourActiveNotification()
            if (sbn != null) return sbn
            Thread.sleep(100)
        }
        return null
    }

    private fun waitForNotificationGone(timeoutMs: Long): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (ourActiveNotification() == null) return true
            Thread.sleep(100)
        }
        return false
    }
}
