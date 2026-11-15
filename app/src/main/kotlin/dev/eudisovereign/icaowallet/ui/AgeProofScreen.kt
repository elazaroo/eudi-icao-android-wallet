package dev.eudisovereign.icaowallet.ui

import androidx.activity.compose.BackHandler
import androidx.activity.compose.LocalActivity
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.eudisovereign.icaowallet.R
import dev.eudisovereign.icaowallet.protocol.AgeProofChecks
import dev.eudisovereign.icaowallet.protocol.CheckResult
import dev.eudisovereign.icaowallet.protocol.ResultFrame
import dev.eudisovereign.icaowallet.protocol.SessionDescriptor
import dev.eudisovereign.icaowallet.ui.theme.Mono
import dev.eudisovereign.icaowallet.ui.theme.StatusColors

@Composable
fun AgeProofScreen(viewModel: WalletViewModel, onBack: () -> Unit, onScanAgain: () -> Unit, onTechnical: () -> Unit) {
    val state by viewModel.ageProof.collectAsStateWithLifecycle()
    val store by viewModel.storeState.collectAsStateWithLifecycle()
    val readiness by viewModel.readiness.collectAsStateWithLifecycle()
    val key by viewModel.provingKey.collectAsStateWithLifecycle()
    val activity = LocalActivity.current as? FragmentActivity
    val running = state.phase == PresentationPhase.RUNNING
    val leave: () -> Unit = {
        viewModel.cancelAgeProof()
        onBack()
    }
    BackHandler(enabled = running, onBack = leave)

    val result = state.result
    ScreenScaffold(title = stringResource(if (result != null) R.string.result_title else R.string.confirm_title), onBack = leave) {
        val descriptor = state.descriptor
        when {
            descriptor == null -> {
                Body(stringResource(R.string.confirm_no_session))
                PrimaryAction(stringResource(R.string.home_scan_code), onClick = onScanAgain)
            }
            running -> {
                Body(stringResource(R.string.age_running_text, descriptor.origin))
                LinearProgressIndicator(Modifier.fillMaxWidth())
                AgeProgressRows(state)
                AgeDetails(state)
                SecondaryAction(stringResource(R.string.action_cancel), onClick = viewModel::cancelAgeProof)
            }
            result != null -> AgeResultContent(state, result, onDone = leave, onScanAgain = onScanAgain)
            state.consumed -> {
                state.failure?.let { ProblemCard(it, details = { AgeDetailLines(state) }) }
                PrimaryAction(stringResource(R.string.action_scan_new), onClick = onScanAgain)
                SecondaryAction(stringResource(R.string.action_done), onClick = leave)
            }
            else -> {
                val overview = (store as? StoreState.Loaded)?.overview
                val biometric = readiness?.biometric
                val keyInstalled = key.status == ProvingKeyStatus.INSTALLED
                AgeConfirmContent(state, descriptor, overview != null, biometric, keyInstalled, key.status, onTechnical)
                PrimaryAction(
                    text = stringResource(R.string.confirm_action),
                    enabled = activity != null && overview != null && biometric == BiometricReadiness.READY &&
                        keyInstalled && state.eligibilityChecked && state.notProvable == null,
                    onClick = { activity?.let(viewModel::proveAge) },
                )
                AgeAdvancedOptions(state, descriptor, viewModel)
            }
        }
    }
}

@Composable
private fun AgeConfirmContent(
    state: AgeProofState,
    descriptor: SessionDescriptor,
    hasDocument: Boolean,
    biometric: BiometricReadiness?,
    keyInstalled: Boolean,
    keyStatus: ProvingKeyStatus,
    onTechnical: () -> Unit,
) {
    state.failure?.let { ProblemCard(it, details = { AgeDetailLines(state) }) }
    Text(stringResource(R.string.age_site_label), style = MaterialTheme.typography.labelLarge)
    SelectionContainer {
        Text(
            text = descriptor.origin,
            style = Mono.copy(fontSize = 22.sp, lineHeight = 28.sp, fontWeight = FontWeight.SemiBold),
        )
    }
    Body(stringResource(R.string.confirm_check_origin))
    if (!descriptor.origin.startsWith("https://")) {
        MessageCard(
            title = stringResource(R.string.confirm_insecure_title),
            text = stringResource(R.string.confirm_insecure_text),
            warning = true,
        )
    }

    Section(stringResource(R.string.age_sent_title)) {
        ageSentCategories.forEach { Bullet(stringResource(it)) }
        Note(stringResource(R.string.age_sent_note))
    }
    Section(stringResource(R.string.age_kept_title)) {
        ageKeptCategories.forEach { Bullet(stringResource(it)) }
    }

    when {
        !hasDocument -> Note(stringResource(R.string.problem_no_document), color = StatusColors.fail)
        state.notProvable != null -> ProblemCard(state.notProvable)
        !state.eligibilityChecked -> Note(stringResource(R.string.age_checking_document))
    }
    if (!keyInstalled) {
        MessageCard(
            title = stringResource(R.string.problem_proving_key_missing),
            text = stringResource(
                if (keyStatus == ProvingKeyStatus.IMPORTING) R.string.age_key_importing else R.string.age_key_missing_text,
            ),
            warning = true,
        ) {
            SecondaryAction(stringResource(R.string.age_open_technical), onClick = onTechnical)
        }
    }
    if (biometric != null && biometric != BiometricReadiness.READY) {
        val problem = Problems.ofBiometric(biometric) ?: Problem.BIOMETRIC_UNAVAILABLE
        ProblemCard(Failure(problem, "BiometricManager BIOMETRIC_STRONG: $biometric"))
    }
}

@Composable
private fun Bullet(text: String) {
    Row(verticalAlignment = Alignment.Top) {
        Text("•", style = MaterialTheme.typography.bodyLarge, modifier = Modifier.padding(end = 12.dp))
        Text(text, style = MaterialTheme.typography.bodyLarge)
    }
}

@Composable
private fun AgeAdvancedOptions(state: AgeProofState, descriptor: SessionDescriptor, viewModel: WalletViewModel) {
    var expanded by rememberSaveable { mutableStateOf(false) }
    TextButton(onClick = { expanded = !expanded }) {
        Text(stringResource(if (expanded) R.string.advanced_hide else R.string.advanced_show))
    }
    if (!expanded) return
    val editable = state.phase != PresentationPhase.RUNNING && !state.consumed
    Section(stringResource(R.string.advanced_transport_title)) {
        Column(Modifier.selectableGroup()) {
            AgeTransportOption(TransportChoice.PEERJS, state.transport, editable) { viewModel.selectAgeTransport(it) }
            AgeTransportOption(TransportChoice.RELAY, state.transport, editable && descriptor.relay != null) {
                viewModel.selectAgeTransport(it)
            }
        }
        if (descriptor.relay == null) Note(stringResource(R.string.advanced_no_relay))
    }
    Section(stringResource(R.string.advanced_session_title)) {
        Field(stringResource(R.string.session_nonce), descriptor.nonce, mono = true)
        Field(stringResource(R.string.session_issued), formatUtc(descriptor.timestamp), mono = true)
        Field(stringResource(R.string.session_peer_id), descriptor.peerId, mono = true)
        Field(stringResource(R.string.age_request_label), "age-over-18", mono = true)
        Field(stringResource(R.string.advanced_files_sent), stringResource(R.string.age_files_sent), mono = true)
    }
}

@Composable
private fun AgeTransportOption(
    choice: TransportChoice,
    selected: TransportChoice,
    enabled: Boolean,
    onSelect: (TransportChoice) -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .selectable(selected = choice == selected, enabled = enabled, role = Role.RadioButton) { onSelect(choice) }
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        RadioButton(selected = choice == selected, onClick = null, enabled = enabled)
        Text(
            text = stringResource(choice.labelRes()),
            style = MaterialTheme.typography.bodyMedium,
            color = if (enabled) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(start = 12.dp),
        )
    }
}

@Composable
private fun AgeProgressRows(state: AgeProofState) {
    val current = state.currentProgress
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        AgeProgress.entries.forEach { progress ->
            val entries = state.stages.filter { it.stage.progress == progress }
            val done = entries.isNotEmpty() && entries.all { it.status == StageStatus.DONE }
            val (mark, description) = when {
                done -> Mark.PASS to R.string.mark_done
                progress == current -> Mark.ACTIVE to R.string.mark_in_progress
                else -> Mark.PENDING to R.string.mark_pending
            }
            MarkedRow(mark, stringResource(description), stringResource(progress.labelRes()), emphasised = progress == current)
        }
    }
}

@Composable
private fun AgeResultContent(state: AgeProofState, result: ResultFrame, onDone: () -> Unit, onScanAgain: () -> Unit) {
    val verified = result.ok
    val verdict = stringResource(if (verified) R.string.result_verified else R.string.result_not_verified)
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        StatusMark(if (verified) Mark.PASS else Mark.FAIL, verdict, size = 48.dp)
        Text(
            text = verdict,
            style = MaterialTheme.typography.headlineMedium,
            color = if (verified) StatusColors.pass else StatusColors.fail,
        )
    }
    state.descriptor?.let { Note(it.origin) }

    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        AgeProofChecks.IDS.forEach { id -> AgeCheckRow(id, result.checks.firstOrNull { it.id == id }) }
        result.checks.filter { it.id !in AgeProofChecks.IDS }.forEach { AgeCheckRow(it.id, it) }
    }
    if (result.ok != AgeProofChecks.allPass(result)) Note(stringResource(R.string.result_inconsistent), color = StatusColors.fail)

    var expanded by rememberSaveable { mutableStateOf(false) }
    DetailsToggle(expanded) { expanded = !expanded }
    if (expanded) {
        AgeDetailLines(state)
        MonoBlock(
            "ok = ${result.ok}\n" + result.checks.joinToString("\n") { "${it.id}: ${it.status}" },
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
    PrimaryAction(stringResource(R.string.action_done), onClick = onDone)
    SecondaryAction(stringResource(R.string.action_scan_another), onClick = onScanAgain)
}

@Composable
private fun AgeCheckRow(id: String, check: CheckResult?) {
    val (mark, description) = when (check?.status) {
        CheckResult.STATUS_PASS -> Mark.PASS to R.string.mark_passed
        CheckResult.STATUS_FAIL -> Mark.FAIL to R.string.mark_failed
        CheckResult.STATUS_SKIPPED -> Mark.PENDING to R.string.mark_skipped
        else -> Mark.FAIL to R.string.mark_not_reported
    }
    MarkedRow(mark, stringResource(description), checkTitleRes(id)?.let { stringResource(it) } ?: id)
}

@Composable
private fun AgeDetails(state: AgeProofState) {
    var expanded by rememberSaveable { mutableStateOf(false) }
    DetailsToggle(expanded) { expanded = !expanded }
    if (expanded) AgeDetailLines(state)
}

@Composable
private fun AgeDetailLines(state: AgeProofState) {
    state.stages.forEach { entry ->
        val (label, color) = when (entry.status) {
            StageStatus.PENDING -> "WAIT" to StatusColors.neutral
            StageStatus.RUNNING -> "RUN" to StatusColors.warn
            StageStatus.DONE -> "OK" to StatusColors.pass
            StageStatus.FAILED -> "FAIL" to StatusColors.fail
            StageStatus.CANCELLED -> "STOP" to StatusColors.fail
        }
        val stageLabel = if (entry.stage == AgeStage.DELIVERY) {
            "${entry.stage.label} (${if (state.transport == TransportChoice.RELAY) "relay" else "PeerJS"})"
        } else {
            entry.stage.label
        }
        StepRow(stageLabel, label, color, entry.durationMillis, entry.detail)
    }
    val total = state.stages.mapNotNull { it.durationMillis }.sum()
    if (state.stages.isNotEmpty()) MonoBlock("total $total ms", color = MaterialTheme.colorScheme.onSurfaceVariant)
    state.failureTrace?.let { MonoBlock(it, color = MaterialTheme.colorScheme.error) }
}
