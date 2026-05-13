package com.gutschke.wgrtc.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.HelpOutline
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RichTooltip
import androidx.compose.material3.Text
import androidx.compose.material3.TooltipBox
import androidx.compose.material3.TooltipDefaults
import androidx.compose.material3.rememberTooltipState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch

/**
 * Inline help affordance — a small "?" icon button + a Material 3
 * [RichTooltip] with optional title + body text. Use next to
 * field labels (or any UI element) where a non-technical user
 * might benefit from a sentence of explanation.
 *
 * Usage pattern in a form:
 * ```
 * FieldLabelWithHelp(
 * label = "Address pool",
 * hintTitle = "What's an address pool?",
 * hintBody = "A range of IP addresses the host hands out " +
 * "to joining devices. 10.99.0.0/24 fits up to " +
 * "254 peers — fine for a typical home or office.",
 * )
 * OutlinedTextField(...)
 * ```
 *
 * Tooltip behavior: tap the "?" to open; tap outside or the
 * tooltip itself to dismiss. Works under TalkBack — the icon
 * button announces "Help" by default; the tooltip body is read
 * when shown.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HelpHint(
    title: String? = null,
    body: String,
    contentDescription: String = "Help",
    iconSize: Int = 18,
) {
    val state = rememberTooltipState(isPersistent = true)
    val scope = rememberCoroutineScope()

    TooltipBox(
        positionProvider = TooltipDefaults.rememberRichTooltipPositionProvider(),
        tooltip = {
            RichTooltip(
                title = if (title != null) {{ Text(title) }} else null,
                colors = TooltipDefaults.richTooltipColors(
                    containerColor = MaterialTheme.colorScheme.inverseSurface,
                    contentColor = MaterialTheme.colorScheme.inverseOnSurface,
                ),
            ) {
                Text(body, style = MaterialTheme.typography.bodyMedium)
            }
        },
        state = state,
    ) {
        IconButton(
            onClick = { scope.launch { state.show() } },
            modifier = Modifier.size((iconSize + 16).dp),
        ) {
            Icon(
                Icons.Outlined.HelpOutline,
                contentDescription = contentDescription,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(iconSize.dp),
            )
        }
    }
}

/**
 * Convenience pairing: a row containing [label] + a [HelpHint].
 * Place above an [OutlinedTextField] (or any input) when the field
 * itself needs a label *outside* its container — Material 3
 * `OutlinedTextField`'s built-in label slot is great for the field
 * name itself; this composable is for cases where you also want a
 * sub-header above a group of fields, or a label-with-help where
 * the explanation is too long for the supporting-text slot.
 */
@Composable
fun FieldLabelWithHelp(
    label: String,
    hintBody: String,
    hintTitle: String? = null,
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.Start,
    ) {
        Text(
            label,
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.onSurface,
        )
        Spacer(Modifier.width(2.dp))
        HelpHint(title = hintTitle, body = hintBody, iconSize = 16)
    }
}
