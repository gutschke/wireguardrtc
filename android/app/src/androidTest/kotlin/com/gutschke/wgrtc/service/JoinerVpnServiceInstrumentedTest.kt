package com.gutschke.wgrtc.service

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.gutschke.wgrtc.data.JoinerVpnConfig
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Instrumented end-to-end test for [JoinerVpnService] — drives the
 * full path (Builder.addAddress → addRoute → establish → wgbridge
 * TUN-fd mode → wireguard-go) on the emulator without a real WG
 * peer. No handshake completes (no peer is reachable) but the
 * test asserts:
 *
 * - VPN consent doesn't block (granted at setUp via `appops`).
 * - `Builder.establish()` returns a usable fd.
 * - `wgbridge.NewWithTunFd` accepts the fd + JNI is reachable.
 * - UAPI configure succeeds with a real wg-quick → UAPI render.
 * - Stop tears everything down cleanly.
 *
 * **** will extend this with a real WG server peer (kernel WG
 * inside `unshare -Urn` netns via `dev-env/sandbox-wg-server.sh`)
 * so the handshake actually completes. This test validates the
 * Android side of that loop.
 *
 * Run via the existing `am instrument` invocation:
 * ```
 * adb shell am instrument -w \
 * -e class com.gutschke.wgrtc.service.JoinerVpnServiceInstrumentedTest \
 * com.gutschke.wgrtc.debug.test/androidx.test.runner.AndroidJUnitRunner
 * ```
 */
@RunWith(AndroidJUnit4::class)
class JoinerVpnServiceInstrumentedTest {

    private val ctx: Context get() = ApplicationProvider.getApplicationContext()
    private val privKey = ByteArray(32) { (it + 1).toByte() }
    private val privB64 = Base64.getEncoder().encodeToString(privKey)
    private val pubB64 = Base64.getEncoder().encodeToString(ByteArray(32) { 0xAA.toByte() })

    private fun sampleConfig(endpoint: String = "192.0.2.1:51820") = """
        [Interface]
        PrivateKey = $privB64
        Address = 10.99.0.2/24

        [Peer]
        PublicKey = $pubB64
        AllowedIPs = 10.99.0.0/24
        Endpoint = $endpoint
        PersistentKeepalive = 25
    """.trimIndent()

    @Before
    fun grantVpnConsentViaAppops() {
        // VpnService.prepare() returns null if VPN is allowed.
        // The shell command `appops set <pkg> ACTIVATE_VPN allow`
        // bypasses the consent dialog. Requires the test process
        // to be running as the app — `am instrument` already
        // satisfies that.
        Runtime.getRuntime().exec(arrayOf(
            "sh", "-c",
            "appops set com.gutschke.wgrtc.debug ACTIVATE_VPN allow"
        )).waitFor()
    }

    @After
    fun tearDown() {
        // Belt-and-braces: stop any service the test left behind.
        val intent = Intent(ctx, JoinerVpnService::class.java)
        intent.action = JoinerVpnService.ACTION_STOP
        ctx.startService(intent)
        Thread.sleep(200)
    }

    @Test
    fun bindStartStopRoundtrip() = runBlocking<Unit> {
        val service = bindAndAwait()

        // Build TUN, hand fd to wgbridge, configure UAPI.
        val parsed = JoinerVpnConfig.parse(sampleConfig())
        val recfg = service.start(parsed, sampleConfig())
        assertNotNull("start() should return a non-null reconfigurer", recfg)

        // Snapshot stats — no handshake yet but the device should
        // exist + report the configured peer. null is also
        // acceptable (the very first snapshot after IpcSet may be
        // empty until wireguard-go's goroutines settle).
        val stats = service.snapshotStats()
        // Either null (just-started) or contains our peer. Not
        // strictly an assertion failure either way — what matters
        // is the call didn't crash.
        if (stats != null) {
            assertTrue("expected our peer key in snapshot, got ${stats.peers.keys}",
                stats.peers.containsKey(pubB64))
        }

        // Tear down. After this, snapshotStats should report null.
        service.stop()
        // Give wireguard-go's goroutines a beat to drain.
        Thread.sleep(50)
        assertNull(service.snapshotStats())
    }

    /** Bind to the service and block until the LocalBinder fires. */
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
        // Some VpnServices won't bind to a non-system intent; ours
        // accepts both flavours via onBind's action check.
        check(ctx.bindService(intent, conn, Context.BIND_AUTO_CREATE)) {
            "bindService returned false for JoinerVpnService"
        }
        check(latch.await(5, TimeUnit.SECONDS)) {
            "JoinerVpnService LocalBinder never connected"
        }
        return binder!!.getService()
    }
}
