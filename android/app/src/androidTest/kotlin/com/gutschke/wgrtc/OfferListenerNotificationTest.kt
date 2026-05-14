package com.gutschke.wgrtc

import android.app.NotificationManager
import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * UX1 — manual-dismiss + auto-dismiss on the OfferListenerService
 * foreground notification.
 *
 * Tests target the pure-ish [OfferListenerService.buildNotificationFor]
 * factory rather than the live service so we don't have to spin up
 * the whole [WgrtcApp] dependency tree for each test.  Companion
 * integration coverage (the dismiss action actually stops the
 * service) is in [OfferListenerNotificationIntegrationTest] which
 * does drive the real service.
 */
@RunWith(AndroidJUnit4::class)
class OfferListenerNotificationTest {

    private val ctx: Context =
        InstrumentationRegistry.getInstrumentation().targetContext

    private fun titles(n: android.app.Notification): List<String> =
        n.actions?.mapNotNull { it.title?.toString() } ?: emptyList()

    @Test
    fun notification_includes_a_dismiss_action() {
        // Visible (normal-importance) channel: must offer the user a
        // way to stop the FGS without going to system settings.
        val n = OfferListenerService.buildNotificationFor(
            ctx, count = 1, hidden = false,
        )
        val labels = titles(n)
        assertTrue(
            "expected a 'Dismiss' action; got $labels",
            labels.any { it.contains("Dismiss", ignoreCase = true) }
        )
    }

    @Test
    fun hidden_channel_still_includes_dismiss_action() {
        // Even when the admin has min-importance hidden the
        // notification, the action must still be present so the
        // dismiss path is reachable via Settings → Notifications.
        val n = OfferListenerService.buildNotificationFor(
            ctx, count = 2, hidden = true,
        )
        val labels = titles(n)
        assertTrue(
            "hidden-channel notification should still have a Dismiss "
            + "action; got $labels",
            labels.any { it.contains("Dismiss", ignoreCase = true) }
        )
    }

    @Test
    fun hidden_flag_routes_to_the_hidden_channel() {
        // Belt to the previous test's suspenders: prove the boolean
        // actually changes the channel id, not just an unrelated
        // priority field.  Without this assertion a bug that
        // ignored `hidden` would silently pass the
        // includes_dismiss_action tests.
        val normal = OfferListenerService.buildNotificationFor(
            ctx, count = 1, hidden = false,
        )
        val hidden = OfferListenerService.buildNotificationFor(
            ctx, count = 1, hidden = true,
        )
        // Notification.getChannelId is API 26+ which we require
        // (minSdk = 26).
        assertEquals(
            "hidden=false should land on the visible channel",
            OfferListenerService.CHANNEL_ID,
            normal.channelId,
        )
        assertEquals(
            "hidden=true should land on the min-importance channel",
            OfferListenerService.CHANNEL_ID_HIDDEN,
            hidden.channelId,
        )
    }

    @Test
    fun dismiss_action_carries_a_pending_intent() {
        val n = OfferListenerService.buildNotificationFor(
            ctx, count = 1, hidden = false,
        )
        val dismiss = n.actions?.firstOrNull {
            it.title?.toString()?.contains("Dismiss", ignoreCase = true) == true
        }
        assertNotNull(
            "dismiss action must exist", dismiss
        )
        assertNotNull(
            "dismiss action must carry a PendingIntent so taps fire it",
            dismiss?.actionIntent
        )
    }

    @Test
    fun zero_count_still_renders_a_complete_notification() {
        // Edge case: service starts, count is briefly zero, we still
        // post a notification to satisfy the FGS contract.  It must
        // include the dismiss action, otherwise the user might be
        // stuck with a stale "tracking 0 tunnels" notification they
        // can't get rid of.
        val n = OfferListenerService.buildNotificationFor(
            ctx, count = 0, hidden = false,
        )
        val labels = titles(n)
        assertTrue(
            "zero-count notification must still have a Dismiss "
            + "action; got $labels",
            labels.any { it.contains("Dismiss", ignoreCase = true) }
        )
    }

    @Test
    fun notification_text_reflects_listener_count() {
        // Light contract test: the body string mentions the count so
        // the user can confirm at a glance which path the dismiss
        // refers to.
        val one = OfferListenerService.buildNotificationFor(
            ctx, count = 1, hidden = false,
        )
        val many = OfferListenerService.buildNotificationFor(
            ctx, count = 3, hidden = false,
        )
        val oneText = one.extras.getCharSequence(
            android.app.Notification.EXTRA_TEXT)?.toString().orEmpty()
        val manyText = many.extras.getCharSequence(
            android.app.Notification.EXTRA_TEXT)?.toString().orEmpty()
        assertTrue(
            "single-listener text should say '1'; got '$oneText'",
            oneText.contains("1"))
        assertTrue(
            "multi-listener text should say '3'; got '$manyText'",
            manyText.contains("3"))
    }
}
