package com.gutschke.wgrtc.data

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.gutschke.wgrtc.service.JoinerVpnService
import org.junit.After
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * end-to-end test: drive [JoinerVpnService] against a REAL
 * WireGuard peer (the kernel-WG server in
 * `dev-env/sandbox-wg-server.sh`'s `unshare -Urn` netns) and
 * verify a handshake actually completes.
 *
 * The wg-quick config is supplied via instrumentation arguments
 * (so the orchestrator script can plug in the freshly generated
 * keys + the relay address). Without `cfg` the test [skips]
 * itself — running this directly under `am instrument` without
 * the orchestrator would otherwise produce noise. The
 * orchestrator is `dev-env/run-c1d-handshake-test.sh`.
 *
 * Pass via:
 * ```
 * adb shell am instrument -w \
 * -e class com.gutschke.wgrtc.data.JoinerHandshakeInstrumentedTest \
 * -e cfg "$(cat /tmp/c1d-wg-quick.txt)" \
 * com.gutschke.wgrtc.debug.test/androidx.test.runner.AndroidJUnitRunner
 * ```
 *
 * (`am instrument -e` values can include newlines as long as the
 * shell passes the argument as a single token. Confirmed working
 * on Android 14 emulator.)
 */
@RunWith(AndroidJUnit4::class)
class JoinerHandshakeInstrumentedTest {

    private val ctx: Context get() = ApplicationProvider.getApplicationContext()

    @Before
    fun grantVpnConsentViaAppops() {
        Runtime.getRuntime().exec(arrayOf(
            "sh", "-c",
            "appops set com.gutschke.wgrtc.debug ACTIVATE_VPN allow"
        )).waitFor()
    }

    @After
    fun tearDown() {
        val intent = Intent(ctx, JoinerVpnService::class.java)
        intent.action = JoinerVpnService.ACTION_STOP
        ctx.startService(intent)
        Thread.sleep(200)
    }

    @Test
    fun handshakeCompletesAgainstSandboxWgServer() {
        // Multi-line `am instrument -e cfg "..."` gets newline-
        // mangled by adb's shell before reaching us. Orchestrator
        // base64-encodes the config; we decode here. See
        // `dev-env/run-c1d-handshake-test.sh`.
        val cfgB64 = InstrumentationRegistry.getArguments().getString("cfgB64")
        assumeTrue(
            "Skipping — pass `-e cfgB64 <base64>` from the orchestrator",
            !cfgB64.isNullOrBlank())
        val cfg = String(android.util.Base64.decode(cfgB64,
            android.util.Base64.DEFAULT))

        val service = bindAndAwait()
        val parsed = JoinerVpnConfig.parse(cfg)
        val recfg = service.start(parsed, cfg)
        assertNotNull("start() returned null reconfigurer", recfg)

        // Wait up to 15 s for a handshake. The sandbox is on the
        // dev host's LAN, ~60 ms away; first init typically lands in
        // 1-3 s. Failure here means either the wgbridge bind is
        // wrong, the relay isn't forwarding, or wireguard-go's
        // own state is stuck.
        var stats = service.snapshotStats()
        val deadline = System.currentTimeMillis() + 15_000
        var handshakeMs: Long? = stats?.mostRecentHandshakeEpochMs
        while (handshakeMs == null && System.currentTimeMillis() < deadline) {
            Thread.sleep(250)
            stats = service.snapshotStats()
            handshakeMs = stats?.mostRecentHandshakeEpochMs
        }
        assertNotNull(
            "no handshake within 15 s — wireguard-go didn't reach the sandbox peer.\n" +
                "last snapshot: peers=${stats?.peers?.keys?.toList()}\n" +
                "rx=${stats?.totalRxBytes} tx=${stats?.totalTxBytes}",
            handshakeMs)

        // Tear down cleanly.
        service.stop()
    }

    private fun bindAndAwait(): JoinerVpnService {
        val latch = CountDownLatch(1)
        var binder: JoinerVpnService.LocalBinder? = null
        val conn = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, b: IBinder?) {
                binder = b as JoinerVpnService.LocalBinder
                latch.countDown()
            }
            override fun onServiceDisconnected(name: ComponentName?) {}
        }
        val intent = Intent(ctx, JoinerVpnService::class.java)
        check(ctx.bindService(intent, conn, Context.BIND_AUTO_CREATE))
        check(latch.await(5, TimeUnit.SECONDS))
        return binder!!.getService()
    }
}
