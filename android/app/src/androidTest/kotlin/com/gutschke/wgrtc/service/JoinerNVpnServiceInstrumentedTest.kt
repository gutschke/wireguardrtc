package com.gutschke.wgrtc.service

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.gutschke.wgrtc.data.Cidr
import com.gutschke.wgrtc.data.JoinerNController
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeFalse
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * D4.J5 — instrumented end-to-end test for [JoinerNVpnService].
 * Validates that:
 *
 *   1. Two joiner tunnels with disjoint AllowedIPs can be brought
 *      up via a single `Builder.establish()` call.
 *   2. `activeJoinerIds` reflects both ids after the second add.
 *   3. Removing one joiner triggers a rebuild without disturbing
 *      the other.
 *
 * **Consent caveat** (per `feedback_vpn_consent_per_buildtype.md`):
 * `appops set ACTIVATE_VPN allow` is ineffective on Android 14+
 * for granting VPN consent.  The test uses `assumeFalse` to skip
 * cleanly when the first `Builder.establish()` returns null —
 * the consent dialog needs to be tapped manually on the test
 * device beforehand.  Once granted on a device, consent persists
 * across `install -r` for the same applicationId.
 *
 * Run via:
 * ```
 * ANDROID_ADB_SERVER_ADDRESS=10.10.0.118 \
 *   ./gradlew :app:connectedDebugAndroidTest \
 *   --tests com.gutschke.wgrtc.service.JoinerNVpnServiceInstrumentedTest
 * ```
 *
 * Per `feedback_arc_vpn_affects_chromeos.md`, this test MUST NOT
 * run on ARC ChromeOS — it can disrupt host ChromeOS networking.
 * The runner has no programmatic way to skip on ARC (no env hint),
 * so any future "run on every connected device" invocation should
 * filter ARC out manually.
 */
@RunWith(AndroidJUnit4::class)
class JoinerNVpnServiceInstrumentedTest {

    private val ctx: Context get() = ApplicationProvider.getApplicationContext()
    private val privKey1 = ByteArray(32) { (it + 1).toByte() }
    private val privKey2 = ByteArray(32) { (it + 2).toByte() }

    @Before
    fun grantVpnConsentBestEffort() {
        // The appops set is INEFFECTIVE on Android 14+ (consent
        // model changed) but harmless on earlier APIs. Still call
        // it as a documentation hint of intent + so older builds
        // keep working.  On API 34+ the user must tap the dialog
        // manually once per applicationId.
        val auto = InstrumentationRegistry.getInstrumentation().uiAutomation
        auto.executeShellCommand(
            "appops set com.gutschke.wgrtc.debug ACTIVATE_VPN allow"
        ).close()
    }

    @After
    fun tearDown() {
        val intent = Intent(ctx, JoinerNVpnService::class.java)
        intent.action = JoinerNVpnService.ACTION_STOP
        ctx.startService(intent)
        Thread.sleep(200)
    }

    @Test
    fun twoJoinersCoexistOnSharedStack() {
        val service = bindAndAwait()

        val cfg1 = JoinerNController.JoinerConfig(
            tunnelId = "t1",
            addresses = listOf(Cidr("10.250.0.1", 32)),
            routes = listOf(Cidr("10.250.0.0", 24)),
            mtu = 1420,
            wgQuickUapi = renderMinimalUapi(privKey1),
        )
        val cfg2 = JoinerNController.JoinerConfig(
            tunnelId = "t2",
            addresses = listOf(Cidr("10.251.0.1", 32)),
            routes = listOf(Cidr("10.251.0.0", 24)),
            mtu = 1420,
            wgQuickUapi = renderMinimalUapi(privKey2),
        )

        // Try the first add.  If consent isn't granted (Android 14+
        // requires a manual tap), `Builder.establish()` returns null
        // and the controller wraps that as JoinerNException.  Skip
        // cleanly — this isn't a regression in the controller code.
        try {
            service.addJoiner(cfg1)
        } catch (t: Throwable) {
            val msg = t.message ?: ""
            assumeFalse(
                "VPN consent unavailable — grant on the test device " +
                "manually and re-run.  Original error: $msg",
                msg.contains("consent revoked", ignoreCase = true) ||
                    msg.contains("returned no fd", ignoreCase = true)
            )
            throw t
        }

        // First add succeeded → consent is fine. Add second.
        service.addJoiner(cfg2)
        assertEquals(
            "both joiners should be active after the second add",
            setOf("t1", "t2"),
            service.activeJoinerIds,
        )

        // Remove t1 → only t2 survives.  This triggers a full
        // Builder.establish rebuild against just t2's address.
        service.removeJoiner("t1")
        assertEquals(setOf("t2"), service.activeJoinerIds)

        // Removing the last joiner closes the stack entirely.
        service.removeJoiner("t2")
        assertTrue("active set should be empty after final remove",
            service.activeJoinerIds.isEmpty())
    }

    private fun renderMinimalUapi(privKey: ByteArray): String {
        // Hex-encoded private key — UAPI format expects 64 hex chars.
        val hex = privKey.joinToString("") { "%02x".format(it) }
        return "private_key=$hex\nlisten_port=0\n"
    }

    private fun bindAndAwait(): JoinerNVpnService {
        val latch = CountDownLatch(1)
        var binder: JoinerNVpnService.LocalBinder? = null
        val conn = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, b: IBinder?) {
                binder = b as JoinerNVpnService.LocalBinder
                latch.countDown()
            }
            override fun onServiceDisconnected(name: ComponentName?) {}
        }
        val intent = Intent(ctx, JoinerNVpnService::class.java)
        check(ctx.bindService(intent, conn, Context.BIND_AUTO_CREATE)) {
            "bindService(JoinerNVpnService) returned false — check the " +
            "manifest entry"
        }
        check(latch.await(5, TimeUnit.SECONDS)) {
            "JoinerNVpnService LocalBinder never fired"
        }
        return binder!!.getService()
    }
}
