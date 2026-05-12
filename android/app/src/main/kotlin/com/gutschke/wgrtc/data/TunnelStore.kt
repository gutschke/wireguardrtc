package com.gutschke.wgrtc.data

import android.content.Context
import android.util.Log
import kotlinx.serialization.json.Json
import java.io.File

/**
 * On-disk storage for the tunnel list. Single JSON blob; small enough
 * that we read/write it whole.
 *
 * Atomic write goes via a temp file + rename so a kill mid-write
 * doesn't leave a partial JSON that fails to parse on next launch.
 *
 * The primary constructor takes a [File] so pure-JVM unit tests can
 * exercise it without an Android Context; the secondary constructor is
 * the production convenience that anchors the file at
 * `context.filesDir/tunnels.json`.
 */
class TunnelStore(private val file: File) {

    constructor(context: Context) :
        this(File(context.filesDir, FILENAME))

    private val json = Json { prettyPrint = true; ignoreUnknownKeys = true }

    fun load(): List<Tunnel> {
        if (!file.exists()) return emptyList()
        return try {
            json.decodeFromString(SERIALIZER, file.readText())
        } catch (t: Throwable) {
            // Production runs on Android where Log is real; unit tests
            // run on a JVM where android.util.Log is a no-op stub when
            // isReturnDefaultValues = true. Either way we recover by
            // returning empty rather than crashing.
            try { Log.w(TAG, "tunnels.json parse failed; starting empty", t) }
            catch (_: Throwable) { /* JVM-test path with no Log impl */ }
            emptyList()
        }
    }

    fun save(tunnels: List<Tunnel>) {
        val tmp = File(file.parentFile, file.name + ".tmp")
        tmp.writeText(json.encodeToString(SERIALIZER, tunnels))
        if (!tmp.renameTo(file)) {
            // Some Android FS quirks reject rename-over-existing on first try.
            file.delete()
            check(tmp.renameTo(file)) { "tunnel store rename failed" }
        }
    }

    companion object {
        private const val TAG = "wgrtc-store"
        private const val FILENAME = "tunnels.json"
        private val SERIALIZER =
            kotlinx.serialization.builtins.ListSerializer(Tunnel.serializer())
    }
}
