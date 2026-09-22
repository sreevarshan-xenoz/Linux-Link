package dev.linuxlink.android.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import dev.linuxlink.android.R

/**
 * The session's command centre: everything the old 16-button bottom bar did,
 * grouped in one dismissable sheet so the remote desktop itself stays clean.
 * Toggle rows keep the sheet open (the state flips in place); rows that lead
 * elsewhere (pickers, pairing, blackout, PiP) dismiss first.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun QuickSettingsSheet(
    onDismiss: () -> Unit,
    inputModeValue: String,
    onCycleInputMode: () -> Unit,
    viewOnly: Boolean,
    onSetViewOnly: (Boolean) -> Unit,
    qualityValue: String,
    onCycleQuality: () -> Unit,
    windowValue: String,
    onPickWindow: () -> Unit,
    monitorValue: String,
    onPickMonitor: () -> Unit,
    paneValue: String,
    onCyclePane: () -> Unit,
    clipboardSync: Boolean,
    onSetClipboardSync: (Boolean) -> Unit,
    onOpenHistory: () -> Unit,
    onOpenAudio: () -> Unit,
    micOn: Boolean,
    onSetMic: (Boolean) -> Unit,
    privacyGrab: Boolean,
    onSetPrivacy: (Boolean) -> Unit,
    paired: Boolean,
    onOpenPairing: () -> Unit,
    onRing: () -> Unit,
    onLock: () -> Unit,
    onBlackout: () -> Unit,
    onPip: () -> Unit,
) {
    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp)
                .padding(bottom = 24.dp),
        ) {
            Text(
                stringResource(R.string.quick_settings_title),
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.padding(bottom = 8.dp),
            )

            GroupHeader(stringResource(R.string.group_input))
            ValueRow(stringResource(R.string.row_input_mode), inputModeValue, onCycleInputMode)
            ToggleRow(stringResource(R.string.row_view_only), viewOnly, onSetViewOnly)

            GroupHeader(stringResource(R.string.group_stream))
            ValueRow(stringResource(R.string.row_quality), qualityValue, onCycleQuality)
            ValueRow(stringResource(R.string.row_window), windowValue, onPickWindow)
            ValueRow(stringResource(R.string.row_monitor), monitorValue, onPickMonitor)
            ValueRow(stringResource(R.string.row_pane), paneValue, onCyclePane)

            GroupHeader(stringResource(R.string.group_desktop))
            ToggleRow(stringResource(R.string.row_clipboard), clipboardSync, onSetClipboardSync)
            ActionRow(stringResource(R.string.row_history), onOpenHistory)
            ActionRow(stringResource(R.string.row_audio), onOpenAudio)
            ToggleRow(stringResource(R.string.row_mic), micOn, onSetMic)
            ToggleRow(stringResource(R.string.row_privacy), privacyGrab, onSetPrivacy)
            ValueRow(
                stringResource(R.string.row_pairing),
                stringResource(if (paired) R.string.value_paired else R.string.value_unpaired),
                onOpenPairing,
            )
            ActionRow(stringResource(R.string.ring_pc), onRing)
            ActionRow(stringResource(R.string.lock_pc), onLock)
            ActionRow(stringResource(R.string.blackout), onBlackout)
            ActionRow(stringResource(R.string.pip), onPip)
        }
    }
}

@Composable
private fun GroupHeader(label: String) {
    Text(
        label,
        style = MaterialTheme.typography.labelLarge,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(top = 14.dp, bottom = 2.dp),
    )
}

@Composable
private fun ToggleRow(label: String, checked: Boolean, onToggle: (Boolean) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onToggle(!checked) }
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(label, style = MaterialTheme.typography.bodyLarge)
        Switch(checked = checked, onCheckedChange = onToggle)
    }
}

@Composable
private fun ValueRow(label: String, value: String, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(label, style = MaterialTheme.typography.bodyLarge)
        Text(
            value,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 1,
            overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
            modifier = Modifier.padding(start = 12.dp),
        )
    }
}

@Composable
private fun ActionRow(label: String, onClick: () -> Unit) {
    Text(
        label,
        style = MaterialTheme.typography.bodyLarge,
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(vertical = 12.dp),
    )
    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
    Spacer(Modifier.height(0.dp))
}
