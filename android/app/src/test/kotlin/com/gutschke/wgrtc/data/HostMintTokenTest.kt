package com.gutschke.wgrtc.data

import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava
import com.gutschke.wgrtc.signalling.EnrollUri
import com.gutschke.wgrtc.signalling.OfferSender
import com.gutschke.wgrtc.signalling.SignalWakeSender
import com.gutschke.wgrtc.signalling.Sodium
import com.gutschke.wgrtc.signalling.pubKeyFromPrivate
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.nio.file.Path
import java.security.SecureRandom
import java.util.Base64

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class HostMintTokenTest {

    @BeforeAll fun installJvmSodium() {
        Sodium.setForTest(LazySodiumJava(SodiumJava()))
    }
    @AfterAll fun restoreSodium() { Sodium.setForTest(null) }

    private val rng = SecureRandom()

    /** Stub that records nothing — hub doesn't fire wakes during a token mint. */
    private class FakeWake : SignalWakeSender {
        override suspend fun sendWake(
            sendVia: suspend (String) -> Boolean,
            sigboxKey: ByteArray, dstRoutingId: String,
        ): Boolean = false
    }

    private fun newHub(dir: Path) = ListenerHub(
        store = TunnelStore(File(dir.toFile(), "tunnels.json")),
        wakeSender = FakeWake(),
        nowMs = { 1_000_000L },
    )

    @Test fun `mint returns parseable URI for a HOST_MODE tunnel`(@TempDir dir: Path) {
        val hub = newHub(dir)
        val t = HostModeFactory.newTunnel(
            name = "host", subnet = "10.99.0.0/24",
            hostIp = "10.99.0.1", listenPort = 51820,
            brokerWss = "wss://b.example/peerjs",
            brokerKey = "demo", rng = rng,
        )
        hub.saveTunnels(listOf(t))

        val uri = hub.mintHostEnrollToken(
            tunnelId = t.id,
            nameHint = "alice-laptop",
            ttlMs = 600_000L,
        )
        assertNotNull(uri)
        // Parses cleanly.
        val parsed = EnrollUri.parse(uri!!)
        assertEquals("wss://b.example/peerjs", parsed.brokerWss)
        assertEquals("demo", parsed.brokerKey)
        // Salt and server-pub round-trip back to the host's known values.
        val expectedPriv = Base64.getDecoder().decode(
            t.configText.lineSequence().first { it.contains("PrivateKey") }
                .substringAfter("=").trim()
        )
        val expectedPub = pubKeyFromPrivate(expectedPriv)
        assertArrayEquals(expectedPub, parsed.serverPub)
        // Salt should match what HostModeFactory put on the tunnel.
        val saltB64 = t.saltB64!!
        val padded = saltB64 + when (saltB64.length % 4) { 2 -> "=="; 3 -> "="; else -> "" }
        val expectedSalt = Base64.getUrlDecoder().decode(padded)
        assertArrayEquals(expectedSalt, parsed.salt)
        // Token is 32 fresh bytes.
        assertEquals(32, parsed.token.size)
        assertEquals("host", parsed.serverName)
    }

    @Test fun `minted token is in the per-tunnel pending store`(@TempDir dir: Path) {
        val hub = newHub(dir)
        val t = HostModeFactory.newTunnel(
            name = "h", subnet = "10.99.0.0/24",
            hostIp = "10.99.0.1", listenPort = 51820,
            brokerWss = "wss://x/y", brokerKey = "k", rng = rng,
        )
        hub.saveTunnels(listOf(t))
        val uri = hub.mintHostEnrollToken(t.id, nameHint = "bob", ttlMs = 600_000L)
        val parsed = EnrollUri.parse(uri!!)
        // The token should be retrievable from the per-tunnel pending
        // store — the hub put it there alongside the URI.
        val tokensFile = File(dir.toFile(), "host-tokens-${t.id}.json")
        assertTrue(tokensFile.exists(),
            "expected pending-tokens file at $tokensFile")
        val store = PendingTokensStore(tokensFile)
        assertNotNull(store.lookup(parsed.token, now = 1_000_000L))
    }

    @Test fun `mint returns null for non-host-mode tunnel`(@TempDir dir: Path) {
        val hub = newHub(dir)
        val client = Tunnel(
            name = "client", configText = "[Interface]\nKey=X\n",
            source = Tunnel.Source.LEGACY,
        )
        hub.saveTunnels(listOf(client))
        assertNull(hub.mintHostEnrollToken(client.id, "hint", 600_000L))
    }

    @Test fun `mint returns null for unknown tunnel id`(@TempDir dir: Path) {
        val hub = newHub(dir)
        assertNull(hub.mintHostEnrollToken("not-an-id", "hint", 600_000L))
    }

    @Test fun `mint returns null when broker fields are missing`(@TempDir dir: Path) {
        val hub = newHub(dir)
        // Hand-built host-mode tunnel without broker info — shouldn't
        // happen via HostModeFactory but defensive.
        val t = Tunnel(
            name = "broken", configText = "[Interface]\n",
            source = Tunnel.Source.HOST_MODE,
            brokerWss = null, brokerKey = null, saltB64 = null,
            hostMode = HostModeConfig(subnet = "10.99.0.0/24"),
        )
        hub.saveTunnels(listOf(t))
        assertNull(hub.mintHostEnrollToken(t.id, "hint", 600_000L))
    }
}
