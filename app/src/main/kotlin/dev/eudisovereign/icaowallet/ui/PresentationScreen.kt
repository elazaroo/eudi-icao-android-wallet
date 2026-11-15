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
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
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
import dev.eudisovereign.icaowallet.crypto.Codec
import dev.eudisovereign.icaowallet.protocol.Binding
import dev.eudisovereign.icaowallet.protocol.CheckResult
import dev.eudisovereign.icaowallet.protocol.ResultFrame
import dev.eudisovereign.icaowallet.protocol.SessionDescriptor
import dev.eudisovereign.icaowallet.ui.theme.Mono
import dev.eudisovereign.icaowallet.ui.theme.StatusColors
import kotlinx.coroutines.delay

private const val VERIFIER_SESSION_TTL_S = 180L

@Composable
fun PresentationScreen(viewModel: WalletViewModel, onBack: () -> Unit, onScanAgain: () -> Unit) {
    val state by viewModel.presentation.collectAsStateWithLifecycle()
    val store by viewModel.storeState.collectAsStateWithLifecycle()
    val readiness by viewModel.readiness.collectAsStateWithLifecycle()
    val activity = LocalActivity.current as? FragmentActivity
    val running = state.phase == PresentationPhase.RUNNING
    val leave: () -> Unit = {
        viewModel.cancelPresentation()
        onBack()
    }
    BackHandler(enabled = running, onBack = leave)

    val result = state.result
    val title = if (result != null) R.string.result_title else R.string.confirm_title
    ScreenScaffold(title = stringResource(title), onBack = leave) {
        val descriptor = state.descriptor
        when {
            descriptor == null -> {
                Body(stringResource(R.string.confirm_no_session))
                PrimaryAction(stringResource(R.string.home_scan_code), onClick = onScanAgain)
            }
            running -> {
                Body(stringResource(R.string.sending_text, descriptor.origin))
                LinearProgressIndicator(Modifier.fillMaxWidth())
                StageDetails(state)
                SecondaryAction(stringResource(R.string.action_cancel), onClick = viewModel::cancelPresentation)
            }
            result != null -> ResultContent(state, result, onDone = leave, onScanAgain = onScanAgain)
            state.consumed -> {
                state.failure?.let { ProblemCard(it, details = { StageLines(state) }) }
                PrimaryAction(stringResource(R.string.action_scan_new), onClick = onScanAgain)
                SecondaryAction(stringResource(R.string.action_done), onClick = leave)
            }
            else -> {
                val overview = (store as? StoreState.Loaded)?.overview
                val biometric = readiness?.biometric
                ConfirmContent(
                    state = state,
                    descriptor = descriptor,
                    overview = overview,
                    biometric = biometric,
                )
                PrimaryAction(
                    text = stringResource(R.string.confirm_action),
                    enabled = activity != null && overview != null && biometric == BiometricReadiness.READY,
                    onClick = { activity?.let(viewModel::present) },
                )
                AdvancedOptions(state, descriptor, overview, viewModel)
            }
        }
    }
}

@Composable
private fun ConfirmContent(
    state: PresentationState,
    descriptor: SessionDescriptor,
    overview: EnrollmentOverview?,
    biometric: BiometricReadiness?,
) {
    state.failure?.let { ProblemCard(it, details = { StageLines(state) }) }
    Text(stringResource(R.string.confirm_site_label), style = MaterialTheme.typography.labelLarge)
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

    Section(stringResource(R.string.confirm_data_title)) {
        sharedDataCategories.forEach { category ->
            Row(verticalAlignment = Alignment.Top) {
                Text("•", style = MaterialTheme.typography.bodyLarge, modifier = Modifier.padding(end = 12.dp))
                Text(stringResource(category), style = MaterialTheme.typography.bodyLarge)
            }
        }
        Note(stringResource(R.string.confirm_data_note))
    }

    val enrollment = overview?.enrollment
    if (enrollment == null) {
        Note(stringResource(R.string.problem_no_document), color = StatusColors.fail)
    } else {
        val expiry = overview.attestationExpiry
        if (enrollment.binding == Binding.CA_ATTESTATION && expiry != null && expiry.isExpired(System.currentTimeMillis())) {
            MessageCard(
                title = stringResource(R.string.home_expired_title),
                text = stringResource(R.string.home_expired_text),
                warning = true,
            )
        }
    }
    if (biometric != null && biometric != BiometricReadiness.READY) {
        val problem = Problems.ofBiometric(biometric) ?: Problem.BIOMETRIC_UNAVAILABLE
        ProblemCard(Failure(problem, "BiometricManager BIOMETRIC_STRONG: $biometric"))
    }
    if (state.alterDg1) Note(stringResource(R.string.advanced_alter_dg1_active), color = StatusColors.warn)
}

@Composable
private fun AdvancedOptions(
    state: PresentationState,
    descriptor: SessionDescriptor,
    overview: EnrollmentOverview?,
    viewModel: WalletViewModel,
) {
    var expanded by rememberSaveable { mutableStateOf(false) }
    TextButton(onClick = { expanded = !expanded }) {
        Text(stringResource(if (expanded) R.string.advanced_hide else R.string.advanced_show))
    }
    if (!expanded) return
    val editable = state.phase != PresentationPhase.RUNNING && !state.consumed

    Section(stringResource(R.string.advanced_demo_title)) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .toggleable(value = state.alterDg1, enabled = editable, role = Role.Switch) { viewModel.setAlterDg1(it) },
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                stringResource(R.string.advanced_alter_dg1),
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.weight(1f).padding(end = 12.dp),
            )
            Switch(checked = state.alterDg1, onCheckedChange = null, enabled = editable)
        }
        Note(stringResource(R.string.advanced_alter_dg1_note), color = if (state.alterDg1) StatusColors.warn else MaterialTheme.colorScheme.onSurfaceVariant)
    }

    Section(stringResource(R.string.advanced_transport_title)) {
        Column(Modifier.selectableGroup()) {
            TransportOption(TransportChoice.PEERJS, state.transport, editable) { viewModel.selectTransport(it) }
            TransportOption(TransportChoice.RELAY, state.transport, editable && descriptor.relay != null) {
                viewModel.selectTransport(it)
            }
        }
        if (descriptor.relay == null) Note(stringResource(R.string.advanced_no_relay))
    }

    Section(stringResource(R.string.advanced_session_title)) {
        SessionDetails(descriptor)
        val enrollment = overview?.enrollment
        if (enrollment != null) {
            Field(stringResource(R.string.tech_binding_mode), enrollment.binding.wireName, mono = true)
            Field(
                label = stringResource(R.string.advanced_files_sent),
                value = listOfNotNull(
                    "EF.DG1",
                    "EF.DG14".takeIf { enrollment.dg14 != null },
                    "EF.DG15".takeIf { enrollment.dg15 != null },
                    "EF.SOD",
                ).joinToString(", "),
                mono = true,
            )
        }
    }
}

@Composable
private fun ResultContent(state: PresentationState, result: ResultFrame, onDone: () -> Unit, onScanAgain: () -> Unit) {
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
        ResultFrame.CHECK_IDS.forEach { id -> CheckRow(id, result.checks.firstOrNull { it.id == id }) }
        result.checks.filter { it.id !in ResultFrame.CHECK_IDS }.forEach { CheckRow(it.id, it) }
    }
    val allPass = ResultFrame.CHECK_IDS.all { id -> result.checks.any { it.id == id && it.passed } }
    if (result.ok != allPass) Note(stringResource(R.string.result_inconsistent), color = StatusColors.fail)
    if (state.alterDg1) Note(stringResource(R.string.result_altered_note), color = StatusColors.warn)

    var expanded by rememberSaveable { mutableStateOf(false) }
    DetailsToggle(expanded) { expanded = !expanded }
    if (expanded) {
        StageLines(state)
        MonoBlock(
            "ok = ${result.ok}\n" + result.checks.joinToString("\n") { "${it.id}: ${it.status}" },
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
    PrimaryAction(stringResource(R.string.action_done), onClick = onDone)
    SecondaryAction(stringResource(R.string.action_scan_another), onClick = onScanAgain)
}

@Composable
private fun CheckRow(id: String, check: CheckResult?) {
    val (mark, description) = when (check?.status) {
        CheckResult.STATUS_PASS -> Mark.PASS to R.string.mark_passed
        CheckResult.STATUS_FAIL -> Mark.FAIL to R.string.mark_failed
        CheckResult.STATUS_SKIPPED -> Mark.PENDING to R.string.mark_skipped
        else -> Mark.FAIL to R.string.mark_not_reported
    }
    val title = checkTitleRes(id)?.let { stringResource(it) } ?: id
    MarkedRow(mark, stringResource(description), title)
}

@Composable
private fun StageDetails(state: PresentationState) {
    var expanded by rememberSaveable { mutableStateOf(false) }
    DetailsToggle(expanded) { expanded = !expanded }
    if (expanded) StageLines(state)
}

@Composable
private fun StageLines(state: PresentationState) {
    state.stages.forEach { entry ->
        val (label, color) = when (entry.status) {
            StageStatus.PENDING -> "WAIT" to StatusColors.neutral
            StageStatus.RUNNING -> "RUN" to StatusColors.warn
            StageStatus.DONE -> "OK" to StatusColors.pass
            StageStatus.FAILED -> "FAIL" to StatusColors.fail
            StageStatus.CANCELLED -> "STOP" to StatusColors.fail
        }
        val stageLabel = if (entry.stage == PresentationStage.DELIVERY) {
            "${entry.stage.label} (${if (state.transport == TransportChoice.RELAY) "relay" else "PeerJS"})"
        } else {
            entry.stage.label
        }
        StepRow(stageLabel, label, color, entry.durationMillis, entry.detail)
    }
}

@Composable
private fun SessionDetails(descriptor: SessionDescriptor) {
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(descriptor) {
        while (true) {
            now = System.currentTimeMillis()
            delay(1_000)
        }
    }
    val ekDigest = remember(descriptor) { Codec.hex(Codec.sha256(descriptor.ek)) }
    val ageSeconds = (now - descriptor.timestamp) / 1000
    val (age, ageColor) = when {
        ageSeconds < 0 -> stringResource(R.string.session_age_future, -ageSeconds) to StatusColors.warn
        ageSeconds > VERIFIER_SESSION_TTL_S ->
            stringResource(R.string.session_age_old, ageSeconds, VERIFIER_SESSION_TTL_S) to StatusColors.fail
        else -> stringResource(R.string.session_age, ageSeconds) to StatusColors.pass
    }
    Field(stringResource(R.string.session_nonce), descriptor.nonce, mono = true)
    Field(stringResource(R.string.session_nonce_age), age, mono = true, valueColor = ageColor)
    Field(stringResource(R.string.session_issued), formatUtc(descriptor.timestamp), mono = true)
    Field(stringResource(R.string.session_peer_id), descriptor.peerId, mono = true)
    Field(stringResource(R.string.session_ek), ekDigest, mono = true)
    descriptor.relay?.let { Field(stringResource(R.string.session_relay), it, mono = true) }
}

@Composable
private fun TransportOption(
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
