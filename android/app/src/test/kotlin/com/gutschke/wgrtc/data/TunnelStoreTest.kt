package com.gutschke.wgrtc.data

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.nio.file.Path

class TunnelStoreTest {

    private fun store(dir: Path) = TunnelStore(File(dir.toFile(), "tunnels.json"))

    @Test fun `load on missing file returns empty list`(@TempDir dir: Path) {
        assertTrue(store(dir).load().isEmpty())
    }

    @Test fun `save then load round-trips identically`(@TempDir dir: Path) {
        val s = store(dir)
        val a = Tunnel(name = "alpha", configText = "[Interface]\nPrivateKey=AAA\n")
        val b = Tunnel(name = "beta", configText = "[Interface]\nPrivateKey=BBB\n",
                       source = Tunnel.Source.ENROLL)
        s.save(listOf(a, b))
        val loaded = s.load()
        assertEquals(2, loaded.size)
        assertEquals(a, loaded[0])
        assertEquals(b, loaded[1])
        // Ordering is preserved (List, not Set).
        assertEquals(listOf("alpha", "beta"), loaded.map { it.name })
    }

    @Test fun `save uses temp+rename atomic write (tmp file does not survive)`(@TempDir dir: Path) {
        val s = store(dir)
        s.save(listOf(Tunnel(name = "x", configText = "")))
        // After save, only tunnels.json exists — no .tmp.
        val files = dir.toFile().listFiles()?.map { it.name }?.toSet().orEmpty()
        assertTrue("tunnels.json" in files, "saved file missing: $files")
        assertFalse(files.any { it.endsWith(".tmp") }, "stale .tmp left behind: $files")
    }

    @Test fun `corrupt JSON does not crash and load returns empty`(@TempDir dir: Path) {
        val f = File(dir.toFile(), "tunnels.json")
        f.writeText("{ not valid json")
        // Must not throw. TunnelStore swallows the parse failure and
        // returns empty so the user can recover by re-adding tunnels.
        // (Production would also Log.w, but the JVM-test path's stub
        // throws — TunnelStore wraps that throw in its own try/catch.)
        val loaded = store(dir).load()
        assertTrue(loaded.isEmpty(), "expected empty, got $loaded")
    }

    @Test fun `Tunnel ids are unique by default`() {
        val a = Tunnel(name = "a", configText = "")
        val b = Tunnel(name = "b", configText = "")
        assertNotEquals(a.id, b.id)
    }

    @Test fun `save overwrites previous content`(@TempDir dir: Path) {
        val s = store(dir)
        s.save(listOf(Tunnel(name = "first", configText = "")))
        s.save(listOf(Tunnel(name = "second", configText = "")))
        val loaded = s.load()
        assertEquals(1, loaded.size)
        assertEquals("second", loaded[0].name)
    }

    @Test fun `Source enum round-trips through JSON`(@TempDir dir: Path) {
        val s = store(dir)
        val originals = Tunnel.Source.values().map {
            Tunnel(name = it.name, configText = "", source = it)
        }
        s.save(originals)
        val loaded = s.load()
        assertEquals(originals.map { it.source }, loaded.map { it.source })
    }
}
