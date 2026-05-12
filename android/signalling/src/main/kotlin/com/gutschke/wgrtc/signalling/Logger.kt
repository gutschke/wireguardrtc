package com.gutschke.wgrtc.signalling

/**
 * Tiny logger abstraction so the signalling module doesn't import
 * `android.util.Log` directly. Without this, every `Log.i(...)` in
 * EnrollClient/OfferListener/OfferSender/BrokerNetworkPin would force
 * unit tests to either mock `android.util.Log` or use Robolectric —
 * neither of which are wanted here, since the signalling module is
 * meant to be testable on the host JVM (see this module's
 * `build.gradle.kts` header comment).
 *
 * Usage:
 * - Production code in the `app` module installs a real hook by
 * setting [SignallingLogger.hook] to forward to `android.util.Log`.
 * - Unit tests don't install anything; the default is a no-op so
 * `Log.i` / `Log.w` calls disappear silently.
 * - Library code calls [Log.i] / [Log.w] freely without worrying
 * about Android-availability.
 *
 * Intentionally global mutable state — there's exactly one logger
 * instance per process, and threading the logger through every class
 * just for this would be more invasive than the test isolation
 * benefit.
 */
object SignallingLogger {
    /** A logger function takes (priority, tag, message). Priority
     * matches the android.util.Log constants: 4=INFO, 5=WARN, 6=ERROR. */
    fun interface Hook {
        fun log(priority: Int, tag: String, message: String)
    }

    /** No-op default — swallows all log calls. Tests run with this. */
    private val noOp = Hook { _, _, _ -> }

    @Volatile var hook: Hook = noOp

    /** Reset to the no-op hook. Test cleanup helper. */
    fun reset() { hook = noOp }
}

/** Module-internal log helpers. Pattern mirrors `android.util.Log`
 * so call sites read identically. */
internal object Log {
    fun i(tag: String, message: String) {
        SignallingLogger.hook.log(4, tag, message)
    }
    fun w(tag: String, message: String) {
        SignallingLogger.hook.log(5, tag, message)
    }
    fun e(tag: String, message: String) {
        SignallingLogger.hook.log(6, tag, message)
    }
}
