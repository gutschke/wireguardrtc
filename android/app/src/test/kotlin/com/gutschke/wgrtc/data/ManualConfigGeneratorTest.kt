package com.gutschke.wgrtc.data

import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava
import com.gutschke.wgrtc.signalling.Sodium
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.security.SecureRandom
import java.util.Base64

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ManualConfigGeneratorTest {

    @BeforeAll fun installJvmSodium() {
        Sodium.setForTest(LazySodiumJava(SodiumJava()))
    }
    @AfterAll fun restoreSodium() { Sodium.setForTest(null) }

    private val snapshot = HostTunnelSnapshot(
        tunnelId = "tun-abc",
        privKeyB64 = Base64.getEncoder().encodeToString(ByteArray(32) { 1 }),
        pubKeyB64 = Base64.getEncoder().encodeToString(ByteArray(32) { 2 }),
        wgEndpoint = "203.0.113.5:51820",
        allowedIps = "10.99.0.0/24",
        assignedAddress = "10.99.0.7/32",
        brokerWss = "wss://example/peerjs",
        brokerKey = "k",
        saltB64 = "salt",
        hostName = "host",
        keepalive = 25,
        dns = "1.1.1.1",
        mtu = 1420,
    )

    @Test fun `produces a parseable wg-quick block with the host's pubkey + endpoint`() {
        val r = ManualConfigGenerator.generate(snapshot)
        val text = r.wgQuickText
        assertTrue(text.contains("[Interface]"))
        assertTrue(text.contains("PrivateKey = "))
        assertTrue(text.contains("Address = 10.99.0.7/32"))
        assertTrue(text.contains("DNS = 1.1.1.1"))
        assertTrue(text.contains("MTU = 1420"))
        assertTrue(text.contains("[Peer]"))
        assertTrue(text.contains("PublicKey = ${snapshot.pubKeyB64}"))
        assertTrue(text.contains("Endpoint = 203.0.113.5:51820"))
        assertTrue(text.contains("AllowedIPs = 10.99.0.0/24"))
        assertTrue(text.contains("PersistentKeepalive = 25"))
    }

    @Test fun `joinerPeer carries the new pubkey and pre-allocated IP`() {
        val r = ManualConfigGenerator.generate(snapshot, deviceLabel = "chromebook-1")
        assertEquals("tun-abc", r.joinerPeer.tunnelId)
        assertEquals("10.99.0.7", r.joinerPeer.joinerIp) // /32 stripped
        assertEquals("chromebook-1", r.joinerPeer.joinerNameHint)
        // Pubkey is fresh, not the host's.
        assertNotEquals(snapshot.pubKeyB64, r.joinerPeer.joinerPubkeyB64)
    }

    @Test fun `each generation produces a fresh keypair`() {
        val r1 = ManualConfigGenerator.generate(snapshot)
        val r2 = ManualConfigGenerator.generate(snapshot)
        assertNotEquals(r1.joinerPeer.joinerPubkeyB64, r2.joinerPeer.joinerPubkeyB64)
    }

    @Test fun `optional fields are omitted when null`() {
        val minimal = snapshot.copy(dns = null, mtu = null, keepalive = null)
        val r = ManualConfigGenerator.generate(minimal)
        val text = r.wgQuickText
        assertTrue(!text.contains("DNS = "))
        assertTrue(!text.contains("MTU = "))
        assertTrue(!text.contains("PersistentKeepalive"))
    }

    @Test fun `seeded RNG produces deterministic output`() {
        val rng1 = SecureRandom.getInstance("SHA1PRNG").also { it.setSeed(42) }
        val rng2 = SecureRandom.getInstance("SHA1PRNG").also { it.setSeed(42) }
        val r1 = ManualConfigGenerator.generate(snapshot, rng = rng1)
        val r2 = ManualConfigGenerator.generate(snapshot, rng = rng2)
        assertEquals(r1.wgQuickText, r2.wgQuickText)
    }
}
