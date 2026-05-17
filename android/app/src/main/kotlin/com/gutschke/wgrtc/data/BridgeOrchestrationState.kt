package com.gutschke.wgrtc.data

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.UUID

/**
 * Pure data holder for the §11.6 Tile-#3 Bridge flow.  Extracted
 * from `WgrtcViewModel` so the state transitions can be unit-tested
 * without bootstrapping a full `AndroidViewModel`.
 *
 * Lifecycle:
 *
 *   null → "uuid"   : [startFlow]
 *   "uuid" → null   : [finish]
 *   "uuid" → "uuid'": [startFlow] called while in-flight
 *                     (the previous flow's id is replaced — see
 *                     [onClobber] callback)
 *
 * Both halves of a Bridge pair consume the SAME id via [peek];
 * the first save reads it, the second reads it again, and the
 * wizard calls [finish] after the second save.  Auto-clearing
 * after one [peek] would orphan the second half.
 *
 * Thread-safe by virtue of [MutableStateFlow].  The [idFactory]
 * seam is for tests that want deterministic ids.
 */
class BridgeOrchestrationState(
    private val idFactory: () -> String = { UUID.randomUUID().toString() },
    /** Invoked when [startFlow] is called while another flow is
     *  in-flight.  Production wires this to a Log.w line so a
     *  confusing "where did my first Bridge go?" report is
     *  traceable.  Tests pass a recording lambda. */
    private val onClobber: (previousId: String) -> Unit = {},
) {
    private val _pending = MutableStateFlow<String?>(null)
    val pending: StateFlow<String?> = _pending.asStateFlow()

    /** Allocate a fresh groupId, expose it via [pending], return
     *  it.  When a previous flow was in-flight, calls [onClobber]
     *  with that id before overwriting. */
    fun startFlow(): String {
        val previous = _pending.value
        if (previous != null) onClobber(previous)
        val id = idFactory()
        _pending.value = id
        return id
    }

    /** Peek at the pending id without clearing it.  Both halves
     *  of the pair read the same value. */
    fun peek(): String? = _pending.value

    /** Clear the flow.  Idempotent — clearing-when-already-clear
     *  is a no-op.  Called after the second-half save, or by the
     *  wizard's lifecycle teardown when the user backs out. */
    fun finish() {
        _pending.value = null
    }
}
