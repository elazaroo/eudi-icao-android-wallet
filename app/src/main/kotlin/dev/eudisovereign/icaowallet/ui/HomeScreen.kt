package dev.eudisovereign.icaowallet.ui

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.os.Build
import android.provider.Settings
import androidx.biometric.BiometricManager
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.eudisovereign.icaowallet.R
import dev.eudisovereign.icaowallet.protocol.Binding
import dev.eudisovereign.icaowallet.ui.theme.Mono
import dev.eudisovereign.icaowallet.ui.theme.StatusColors

@Composable
fun HomeScreen(viewModel: WalletViewModel, onEnrol: () -> Unit, onTechnical: () -> Unit, onScan: () -> Unit) {
    val store by viewModel.storeState.collectAsStateWithLifecycle()
    val readiness by viewModel.readiness.collectAsStateWithLifecycle()
    var confirmDelete by rememberSaveable { mutableStateOf(false) }

    ScreenScaffold(title = stringResource(R.string.app_name), onBack = null) {
        when (val state = store) {
            StoreState.Loading -> LinearProgressIndicator(Modifier.fillMaxWidth())
            StoreState.Empty -> {
                Body(stringResource(R.string.home_empty_text))
                PrimaryAction(stringResource(R.string.home_add_document), onClick = onEnrol)
                TextButton(onClick = onTechnical) { Text(stringResource(R.string.home_technical_view)) }
            }
            is StoreState.Failed -> {
                ProblemCard(state.failure)
                PrimaryAction(stringResource(R.string.home_add_document), onClick = onEnrol)
                SecondaryAction(stringResource(R.string.home_remove_document)) { confirmDelete = true }
            }
            is StoreState.Loaded -> {
                DocumentSummary(state.overview)
                val camera = readiness?.camera == true
                PrimaryAction(stringResource(R.string.home_scan_code), enabled = camera, onClick = onScan)
                if (readiness != null && !camera) Note(stringResource(R.string.home_no_camera), color = StatusColors.fail)
                SecondaryAction(stringResource(R.string.home_technical_view), onClick = onTechnical)
                SecondaryAction(stringResource(R.string.home_read_again), onClick = onEnrol)
                SecondaryAction(stringResource(R.string.home_remove_document)) { confirmDelete = true }
            }
        }
    }

    if (confirmDelete) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text(stringResource(R.string.remove_title)) },
            text = { Text(stringResource(R.string.remove_text)) },
            confirmButton = {
                TextButton(onClick = {
                    confirmDelete = false
                    viewModel.deleteEnrollment()
                }) { Text(stringResource(R.string.remove_confirm)) }
            },
            dismissButton = {
                TextButton(onClick = { confirmDelete = false }) { Text(stringResource(R.string.action_cancel)) }
            },
        )
    }
}

@Composable
private fun DocumentSummary(overview: EnrollmentOverview) {
    val locale = currentLocale()
    val mrz = overview.mrz
    val kind = mrz?.let { ReadProgress.documentKind(it.documentCode, it.issuingState) } ?: DocumentKind.OTHER
    val number = mrz?.documentNumber?.let { Masking.keepLast(it, 3) }
    val expiry = overview.attestationExpiry
    val expired = expiry?.isExpired(System.currentTimeMillis()) == true

    MessageCard(title = stringResource(kind.labelRes()), text = null, warning = false) {
        if (number != null) {
            Text(stringResource(R.string.home_document_number), style = MaterialTheme.typography.labelMedium)
            Text(number, style = Mono.copy(fontSize = MaterialTheme.typography.titleMedium.fontSize))
        }
        when {
            expiry == null -> Unit
            expired -> Text(
                stringResource(R.string.home_validity_expired, formatDate(expiry.notAfterMillis, locale)),
                style = MaterialTheme.typography.bodyMedium,
                color = if (overview.enrollment.binding == Binding.CA_ATTESTATION) StatusColors.fail else StatusColors.warn,
            )
            else -> Text(
                stringResource(R.string.home_validity, formatDate(expiry.notAfterMillis, locale)),
                style = MaterialTheme.typography.bodyMedium,
            )
        }
        if (overview.attestationError != null) {
            Text(stringResource(R.string.home_validity_unknown), style = MaterialTheme.typography.bodyMedium)
        }
    }
    // With binding aa the chip signature carries the binding; only ca-attestation depends on the chain.
    if (expired && overview.enrollment.binding == Binding.CA_ATTESTATION) {
        MessageCard(
            title = stringResource(R.string.home_expired_title),
            text = stringResource(R.string.home_expired_text),
            warning = true,
        )
    }
    if (!overview.keyStatus.usable) {
        MessageCard(
            title = stringResource(R.string.problem_key_unusable),
            text = stringResource(R.string.hint_key_unusable),
            warning = true,
        )
    }
}

internal fun biometricEnrollIntent(): Intent =
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        Intent(Settings.ACTION_BIOMETRIC_ENROLL).putExtra(
            Settings.EXTRA_BIOMETRIC_AUTHENTICATORS_ALLOWED,
            BiometricManager.Authenticators.BIOMETRIC_STRONG,
        )
    } else {
        Intent(Settings.ACTION_SECURITY_SETTINGS)
    }

internal fun openSettings(context: Context, intent: Intent) {
    try {
        context.startActivity(intent)
    } catch (e: ActivityNotFoundException) {
        context.startActivity(Intent(Settings.ACTION_SETTINGS))
    }
}
