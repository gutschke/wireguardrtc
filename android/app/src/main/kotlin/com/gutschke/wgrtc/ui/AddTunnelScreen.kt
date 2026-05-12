package com.gutschke.wgrtc.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Login
import androidx.compose.material.icons.outlined.WifiTethering
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp

/**
 * Top-level "Add a tunnel" intent picker.
 *
 * Two outcomes the user might want, framed in their language:
 *
 * 1. **Join** an existing tunnel (typical path — the host hands
 * them a QR code, a wormhole code, or a wg-quick block).
 * 2. **Host** a new tunnel (less common — set up the network
 * yourself, hand out invitations).
 *
 * The previous version of this screen flattened both intents into
 * five sibling cards mixing "Scan QR / Paste / Manual / Wormhole"
 * (all join-side) with "Host a tunnel" — which forced new users
 * to read every card before they could decide. Two-card structure
 * mirrors the actual mental model and makes the rare host-side
 * path discoverable without crowding the common join-side one.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AddTunnelScreen(
    onBack: () -> Unit,
    onJoin: () -> Unit,
    onHost: () -> Unit,
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Add a tunnel") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
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
            modifier = Modifier.fillMaxSize().padding(padding).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(
                "What are you trying to do?",
                style = MaterialTheme.typography.titleLarge,
            )
            Spacer(Modifier.height(4.dp))
            IntentCard(
                icon = Icons.Outlined.Login,
                title = "Join a tunnel",
                body = "Connect to a network someone else has set up. " +
                    "You'll need a QR code, a wormhole code, or a config " +
                    "block from the host.",
                tint = MaterialTheme.colorScheme.primary,
                onClick = onJoin,
            )
            IntentCard(
                icon = Icons.Outlined.WifiTethering,
                title = "Host a tunnel",
                body = "Set up a private network on this device. Other " +
                    "phones, laptops, or routers can join with a code or " +
                    "QR you generate here.",
                tint = MaterialTheme.colorScheme.tertiary,
                onClick = onHost,
            )
        }
    }
}

/**
 * Large square-corner intent card with an icon "tile" on the left
 * and title/body stacked on the right. Visually heavier than the
 * old MethodCard so the two top-level intents read as the primary
 * affordances on the screen rather than items in a long list.
 */
@Composable
private fun IntentCard(
    icon: ImageVector,
    title: String,
    body: String,
    tint: Color,
    onClick: () -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface,
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
    ) {
        Box(modifier = Modifier.padding(16.dp)) {
            androidx.compose.foundation.layout.Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.Top,
                horizontalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Box(
                    modifier = Modifier
                        .size(56.dp)
                        .clip(RoundedCornerShape(12.dp))
                        .background(tint.copy(alpha = 0.12f)),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        icon,
                        contentDescription = null,
                        tint = tint,
                        modifier = Modifier.size(28.dp),
                    )
                }
                Column(modifier = Modifier.weight(1f)) {
                    Text(title, style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.height(4.dp))
                    Text(
                        body,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}
