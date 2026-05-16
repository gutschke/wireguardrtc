package com.gutschke.wgrtc.testing

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.util.Log
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until

/**
 * Best-effort one-shot grant of the VPN consent dialog for the
 * current application id. After this returns, subsequent
 * `VpnService.Builder.establish()` calls succeed without prompting.
 *
 * The consent dialog (`com.android.vpndialogs/.ConfirmDialog`) only
 * appears when `VpnService.prepare(ctx)` returns a non-null Intent
 * — i.e. consent isn't yet granted for the calling applicationId.
 * The state persists per applicationId across reinstalls and
 * across reboots until the user revokes via system Settings.
 *
 * **Why a helper**: `appops set ACTIVATE_VPN allow` is ineffective
 * on Android 14+; the ConnectivityService gates VPN consent
 * separately and only accepts the system dialog flow. UI Automator
 * is the standard test-side workaround.
 *
 * **Idempotency**: calling once consent is already granted is a
 * no-op. The function uses `Until.findObject` with a short timeout
 * so it doesn't hang if the dialog never appears.
 */
object VpnConsentHelper {
    private const val TAG = "VpnConsentHelper"
    // Emulator can take 15+ s to display the consent dialog after
    // a fresh install, especially when ConnectivityService is
    // still cleaning up a prior session.  Pick a generous timeout
    // so we don't fall through to the "no dialog" assumption when
    // the dialog really IS on its way.
    private const val DIALOG_TIMEOUT_MS = 20_000L

    /** Cap on how long we wait for a previously-active VPN session
     * to drain out of ConnectivityService before firing the
     * consent Intent. The 200 ms ACTION_STOP sleep most tests use
     * isn't enough; the system can take 5+ s to fully release. */
    private const val PRE_DIALOG_SETTLE_MS = 15_000L

    /**
     * Trigger and dismiss the consent dialog if it appears. Returns
     * true when consent ends up granted (either because we tapped
     * OK or because it was already granted); false if we couldn't
     * find a dialog to dismiss AND prepare still returns non-null
     * after the wait.
     */
    fun grantConsentIfNeeded(context: Context): Boolean {
        // Quick path: consent already granted, no other VPN in
        // the way. The common case once the dialog has been
        // dismissed at least once for this applicationId.
        if (VpnService.prepare(context) == null) {
            Log.i(TAG, "consent already granted for ${context.packageName}")
            return true
        }
        // A non-null prepare() return can mean either:
        //   (a) consent has never been granted → dialog needed
        //   (b) consent IS granted but a prior VpnService session
        //       (e.g. from the previous test's @After ACTION_STOP)
        //       is still winding down inside ConnectivityService
        // Wait briefly for (b) to clear before launching the
        // dialog. Most teardowns settle within 5 s; we cap the
        // poll at PRE_DIALOG_SETTLE_MS so case (a) doesn't pay
        // the full price unnecessarily.
        val settleDeadline = System.currentTimeMillis() + PRE_DIALOG_SETTLE_MS
        while (System.currentTimeMillis() < settleDeadline) {
            if (VpnService.prepare(context) == null) {
                Log.i(TAG, "consent cleared during settle wait")
                return true
            }
            Thread.sleep(250)
        }
        // The consent dialog reliably appears only when launched
        // from a foreground Activity context. Bring the launcher
        // Activity to the front first; without this, Android 14
        // silently drops `context.startActivity(consent)` calls
        // from background instrumentation contexts.
        val launchIntent = context.packageManager
            .getLaunchIntentForPackage(context.packageName)
        if (launchIntent != null) {
            launchIntent.addFlags(
                Intent.FLAG_ACTIVITY_NEW_TASK or
                    Intent.FLAG_ACTIVITY_CLEAR_TOP
            )
            context.startActivity(launchIntent)
            Thread.sleep(1_000) // Wait for the Activity to come up.
        }
        val consent = VpnService.prepare(context) ?: return true
        consent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        context.startActivity(consent)

        val device = UiDevice.getInstance(
            InstrumentationRegistry.getInstrumentation()
        )

        // The dialog has an OK button labelled "OK" (English locale)
        // and a Cancel button. Resource id is
        // `android:id/button1` on AOSP / vendor builds. Try both.
        val okById = device.wait(
            Until.findObject(By.res("android:id/button1")),
            DIALOG_TIMEOUT_MS,
        )
        if (okById != null) {
            Log.i(TAG, "found consent OK button by id, clicking")
            okById.click()
            // Give the dialog a moment to dismiss + the call back
            // to the ConnectivityService to persist consent.
            Thread.sleep(500)
        } else {
            val okByText = device.wait(
                Until.findObject(By.text("OK")),
                4_000L,
            )
            if (okByText != null) {
                Log.i(TAG, "found consent OK button by text, clicking")
                okByText.click()
                Thread.sleep(500)
            } else {
                // No "OK" button under the standard id OR text.
                // Some emulator/vendor builds label the button
                // differently ("Allow", localized strings, custom
                // resource ids). Fall back to sending KEYCODE_ENTER
                // to whichever dialog is focused — if the consent
                // dialog is up, ENTER hits its default (OK) button.
                Log.w(TAG, "no consent dialog found by id/text — " +
                    "falling back to KEYCODE_ENTER")
                device.pressEnter()
                Thread.sleep(500)
            }
        }
        // Final settle: it can take another second for ConnectivityService
        // to commit the grant after the dialog is dismissed.
        val grantDeadline = System.currentTimeMillis() + 3_000
        while (System.currentTimeMillis() < grantDeadline) {
            if (VpnService.prepare(context) == null) return true
            Thread.sleep(200)
        }
        val granted = VpnService.prepare(context) == null
        Log.i(TAG, "after dialog dismiss: granted=$granted")
        return granted
    }
}
