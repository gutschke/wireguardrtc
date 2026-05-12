package com.gutschke.wgrtc.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.gutschke.wgrtc.WgrtcViewModel
import com.gutschke.wgrtc.signalling.EnrollUri
import com.gutschke.wgrtc.ui.components.HelpHint
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PasteTunnelScreen(
    onBack: () -> Unit,
    onAdded: () -> Unit,
    vm: WgrtcViewModel = viewModel(),
) {
    val initialText = remember { vm.consumePendingPaste() }
    var text by remember { mutableStateOf(initialText) }
    var name by remember { mutableStateOf("") }
    val nameFallback = remember(text) {
        val raw = text.trim()
        if (raw.startsWith("wgrtc-enroll://")) {
            try {
                EnrollUri.parse(raw).serverName?.takeIf { it.isNotBlank() }
                    ?: vm.defaultName()
            } catch (_: Throwable) { vm.defaultName() }
        } else vm.defaultName()
    }
    var deviceLabel by remember {
        mutableStateOf(android.os.Build.MODEL ?: "android device")
    }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Paste a config") },
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
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                "Paste either a standard WireGuard config block or a " +
                    "wgrtc invitation URI from the clipboard.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedTextField(
                value = text,
                onValueChange = { text = it },
                label = { Text("Configuration text") },
                placeholder = { Text("[Interface]… or wgrtc-enroll://…") },
                trailingIcon = {
                    HelpHint(
                        title = "What goes here?",
                        body = "Either:\n\n" +
                            " • A wg-quick block — the [Interface] / " +
                            "[Peer] sections you'd save as a .conf file.\n\n" +
                            " • A wgrtc-enroll:// URI — the auto-onboarding " +
                            "link a host might send you.",
                    )
                },
                modifier = Modifier.fillMaxWidth(),
                maxLines = 12,
                textStyle = MaterialTheme.typography.bodySmall.copy(
                    fontFamily = FontFamily.Monospace,
                ),
            )
            OutlinedTextField(
                value = name,
                onValueChange = { name = it },
                label = { Text("Tunnel name") },
                placeholder = { Text(nameFallback) },
                trailingIcon = {
                    HelpHint(
                        body = "How this tunnel appears in your list. " +
                            "Leave blank to use the host's suggested name.",
                    )
                },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
            OutlinedTextField(
                value = deviceLabel,
                onValueChange = { deviceLabel = it },
                label = { Text("Device label") },
                trailingIcon = {
                    HelpHint(
                        title = "What's a device label?",
                        body = "A short name the host sees in their peer " +
                            "list — usually your phone model. Helps " +
                            "the host recognise who's joining. Only " +
                            "used during enrolment.",
                    )
                },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )

            error?.let {
                Text(it, color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall)
            }
            Spacer(Modifier.height(8.dp))
            Button(
                onClick = {
                    val raw = text.trim()
                    if (raw.isEmpty()) {
                        error = "Paste a config first."; return@Button
                    }
                    busy = true; error = null
                    scope.launch {
                        try {
                            when {
                                raw.startsWith("wgrtc-enroll://") -> {
                                    val uri = EnrollUri.parse(raw)
                                    vm.enrollAndAdd(uri, deviceLabel,
                                        name.takeIf { it.isNotBlank() })
                                    onAdded()
                                }
                                raw.startsWith("[Interface]") -> {
                                    vm.addLegacyTunnel(name, raw)
                                    onAdded()
                                }
                                else -> error =
                                    "Doesn't look like a WireGuard config " +
                                    "or a wgrtc-enroll URI."
                            }
                        } catch (t: Throwable) {
                            error = t.message ?: t.javaClass.simpleName
                        } finally {
                            busy = false
                        }
                    }
                },
                enabled = !busy,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(if (busy) "Working…" else "Add tunnel")
            }
        }
    }
}
