package com.gutschke.wgrtc.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.gutschke.wgrtc.data.WormholeJoinUiEvent
import com.gutschke.wgrtc.data.WormholeJoinUiState
import com.gutschke.wgrtc.signalling.WormholeCode
import com.gutschke.wgrtc.ui.theme.BrandMark

/**
 * wormhole-code join screen (initiator side). Polished
 * pass: brand mark on Succeeded, bigger SAS card, calmer waiting
 * states. Stateless w.r.t. the protocol — receives [state] from
 * the caller's controller.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WormholeJoinScreen(
    state: WormholeJoinUiState,
    onEvent: (WormholeJoinUiEvent) -> Unit,
    onBack: () -> Unit,
    onSucceeded: () -> Unit,
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Join with a code") },
                navigationIcon = {
                    IconButton(onClick = {
                        onEvent(WormholeJoinUiEvent.Cancel)
                        onBack()
                    }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                ),
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier.fillMaxSize().padding(padding).padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(20.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            when (state) {
                is WormholeJoinUiState.EnteringCode -> EnterCodeStep(state, onEvent)
                is WormholeJoinUiState.WaitingForResponder ->
                    WaitingStep(
                        title = "Reaching the host",
                        body = "Both screens will show the same confirmation " +
                            "phrase in a moment.",
                        codeShown = state.code,
                    )
                is WormholeJoinUiState.ConfirmingSas ->
                    ConfirmSasStep(state.sas) {
                        onEvent(WormholeJoinUiEvent.UserConfirm)
                    }
                is WormholeJoinUiState.AwaitingPeerConfirm ->
                    WaitingStep(
                        title = "Almost there",
                        body = "Waiting for the host to tap Confirm too.",
                        codeShown = state.code,
                    )
                WormholeJoinUiState.Succeeded -> SucceededStep(onSucceeded)
                is WormholeJoinUiState.Failed ->
                    FailedStep(reason = state.reason, onBack = onBack)
            }
        }
    }
}

@Composable
private fun EnterCodeStep(
    state: WormholeJoinUiState.EnteringCode,
    onEvent: (WormholeJoinUiEvent) -> Unit,
) {
    val canSubmit = WormholeCode.isValid(state.typed)
    Spacer(Modifier.height(8.dp))
    BrandMark(size = 56.dp)
    Spacer(Modifier.height(8.dp))
    Text(
        "Type the code shown on the host device",
        style = MaterialTheme.typography.headlineSmall,
        textAlign = TextAlign.Center,
    )
    Text(
        "${WormholeCode.DEFAULT_LENGTH} letters. Spaces and dashes are " +
            "ignored — type whatever's easiest to read.",
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        textAlign = TextAlign.Center,
    )
    OutlinedTextField(
        value = state.typed,
        // Codes are emitted upper-case; accept lowercase input but
        // upper-case on the way in so what the user sees matches
        // what the host showed them.
        onValueChange = { onEvent(WormholeJoinUiEvent.CodeChanged(it.uppercase())) },
        label = { Text("Wormhole code") },
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
    )
    Button(
        onClick = { onEvent(WormholeJoinUiEvent.Submit) },
        enabled = canSubmit,
        modifier = Modifier.fillMaxWidth(),
    ) { Text("Connect") }
    if (state.typed.isNotEmpty() && !canSubmit) {
        Text(
            "Keep typing — that's not enough yet.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun WaitingStep(title: String, body: String, codeShown: String) {
    Spacer(Modifier.height(24.dp))
    CircularProgressIndicator(modifier = Modifier.padding(8.dp))
    Spacer(Modifier.height(8.dp))
    Text(title, style = MaterialTheme.typography.headlineSmall)
    Text(
        body,
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        textAlign = TextAlign.Center,
    )
    Spacer(Modifier.height(16.dp))
    Card(
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant,
        ),
    ) {
        Text(
            codeShown,
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.Bold,
            fontSize = 32.sp,
            modifier = Modifier.padding(horizontal = 24.dp, vertical = 12.dp),
        )
    }
}

@Composable
private fun ConfirmSasStep(sas: String, onConfirm: () -> Unit) {
    Spacer(Modifier.height(8.dp))
    Text(
        "Compare these words",
        style = MaterialTheme.typography.headlineSmall,
        textAlign = TextAlign.Center,
    )
    Text(
        "The host's screen should show the exact same phrase. " +
            "If it does, tap Confirm. If anything is different, tap " +
            "Back and try again.",
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        textAlign = TextAlign.Center,
    )
    Spacer(Modifier.height(8.dp))
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.primaryContainer,
            contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
    ) {
        Box(
            modifier = Modifier.fillMaxWidth().padding(20.dp),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                sas,
                fontFamily = FontFamily.Monospace,
                fontSize = 26.sp,
                fontWeight = FontWeight.SemiBold,
                textAlign = TextAlign.Center,
            )
        }
    }
    Button(onClick = onConfirm, modifier = Modifier.fillMaxWidth()) {
        Text("Confirm — phrases match")
    }
}

@Composable
private fun SucceededStep(onSucceeded: () -> Unit) {
    Spacer(Modifier.height(24.dp))
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(48.dp))
            .background(MaterialTheme.colorScheme.primaryContainer)
            .padding(20.dp),
    ) {
        Icon(
            Icons.Filled.CheckCircle,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.padding(2.dp),
        )
    }
    Spacer(Modifier.height(8.dp))
    Text("Joined!", style = MaterialTheme.typography.headlineMedium)
    Text(
        "The new tunnel is in your list. Tap Continue to take a look.",
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        textAlign = TextAlign.Center,
    )
    Button(onClick = onSucceeded, modifier = Modifier.fillMaxWidth()) {
        Text("Continue")
    }
}

@Composable
private fun FailedStep(reason: String, onBack: () -> Unit) {
    Spacer(Modifier.height(24.dp))
    Icon(
        Icons.Outlined.ErrorOutline,
        contentDescription = null,
        tint = MaterialTheme.colorScheme.error,
    )
    Spacer(Modifier.height(8.dp))
    Text("Couldn't connect",
        style = MaterialTheme.typography.headlineSmall,
        color = MaterialTheme.colorScheme.error)
    Text(
        reason,
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        textAlign = TextAlign.Center,
    )
    OutlinedButton(onClick = onBack, modifier = Modifier.fillMaxWidth()) {
        Text("Back")
    }
}
