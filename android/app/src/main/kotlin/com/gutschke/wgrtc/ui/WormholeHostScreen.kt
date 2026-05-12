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
import com.gutschke.wgrtc.data.WormholeHostUiEvent
import com.gutschke.wgrtc.data.WormholeHostUiState

/**
 * wormhole-code host screen (responder side). Polished
 * pass: prominent code card, brand-tinted SAS, success state.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WormholeHostScreen(
    state: WormholeHostUiState,
    onEvent: (WormholeHostUiEvent) -> Unit,
    onBack: () -> Unit,
    onSucceeded: () -> Unit,
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Invitation code") },
                navigationIcon = {
                    IconButton(onClick = {
                        onEvent(WormholeHostUiEvent.Cancel)
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
                is WormholeHostUiState.ShowingCode -> ShowingCodeStep(state.code)
                is WormholeHostUiState.ConfirmingSas ->
                    ConfirmSasStep(state.sas) {
                        onEvent(WormholeHostUiEvent.UserConfirm)
                    }
                is WormholeHostUiState.AwaitingPeerConfirm ->
                    AwaitingConfirmStep(state.code)
                WormholeHostUiState.Succeeded -> SucceededStep(onSucceeded)
                is WormholeHostUiState.Failed ->
                    FailedStep(state.reason, onBack)
            }
        }
    }
}

@Composable
private fun ShowingCodeStep(code: String) {
    Text(
        "Share this code",
        style = MaterialTheme.typography.headlineSmall,
        textAlign = TextAlign.Center,
    )
    Text(
        "Read it aloud, hand the device over, or let the joiner type " +
            "it themselves.",
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
            modifier = Modifier.fillMaxWidth().padding(28.dp),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                code,
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Bold,
                fontSize = 56.sp,
                textAlign = TextAlign.Center,
            )
        }
    }
    Spacer(Modifier.height(8.dp))
    CircularProgressIndicator()
    Text(
        "Waiting for the joining device…",
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
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
        "The joining device's screen should show the exact same phrase. " +
            "Confirm only if they match.",
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
private fun AwaitingConfirmStep(code: String) {
    Spacer(Modifier.height(24.dp))
    CircularProgressIndicator()
    Spacer(Modifier.height(8.dp))
    Text(
        "Almost there",
        style = MaterialTheme.typography.headlineSmall,
    )
    Text(
        "Waiting for the joining device to tap Confirm.",
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    Spacer(Modifier.height(16.dp))
    Card(
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant,
        ),
    ) {
        Text(
            code,
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.Bold,
            fontSize = 32.sp,
            modifier = Modifier.padding(horizontal = 24.dp, vertical = 12.dp),
        )
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
    Text("Peer added", style = MaterialTheme.typography.headlineMedium)
    Text(
        "The new device shows up in your hosting list.",
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        textAlign = TextAlign.Center,
    )
    Button(onClick = onSucceeded, modifier = Modifier.fillMaxWidth()) {
        Text("Done")
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
    Text("Couldn't enrol",
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
