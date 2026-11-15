package dev.eudisovereign.icaowallet.ui

import android.content.Intent
import android.provider.Settings
import androidx.activity.compose.LocalActivity
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.OffsetMapping
import androidx.compose.ui.text.input.TransformedText
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.eudisovereign.icaowallet.R
import dev.eudisovereign.icaowallet.nfc.AccessKeyRules
import dev.eudisovereign.icaowallet.nfc.StepStatus
import dev.eudisovereign.icaowallet.ui.theme.Mono
import dev.eudisovereign.icaowallet.ui.theme.StatusColors
import java.time.LocalDate

@Composable
fun EnrolmentScreen(viewModel: WalletViewModel, onBack: () -> Unit) {
    val state by viewModel.enrolment.collectAsStateWithLifecycle()
    val form by viewModel.accessKeyForm.collectAsStateWithLifecycle()
    val readiness by viewModel.readiness.collectAsStateWithLifecycle()
    val store by viewModel.storeState.collectAsStateWithLifecycle()
    val activity = LocalActivity.current
    var editing by rememberSaveable { mutableStateOf(true) }

    DisposableEffect(Unit) {
        onDispose {
            if (activity?.isChangingConfigurations != true) viewModel.cancelEnrolment()
        }
    }

    val phase = state.phase
    val showForm = phase == EnrolmentPhase.IDLE ||
        (editing && (phase == EnrolmentPhase.FAILED || phase == EnrolmentPhase.CANCELLED))
    val start: () -> Unit = {
        editing = false
        viewModel.armEnrolment()
    }

    ScreenScaffold(
        title = stringResource(if (showForm) R.string.enrol_title else R.string.read_title),
        onBack = onBack,
    ) {
        if (showForm) {
            DocumentForm(
                form = form,
                readiness = readiness,
                replacing = store is StoreState.Loaded,
                viewModel = viewModel,
                onStart = start,
            )
        } else {
            ReadContent(
                state = state,
                canRetry = form.problems().isEmpty(),
                onCancel = viewModel::cancelEnrolment,
                onRetry = start,
                onEdit = { editing = true },
                onDone = onBack,
            )
        }
    }
}

@Composable
private fun DocumentForm(
    form: AccessKeyForm,
    readiness: Readiness?,
    replacing: Boolean,
    viewModel: WalletViewModel,
    onStart: () -> Unit,
) {
    val readinessProblems = readiness?.let(Problems::ofReadiness).orEmpty()

    Text(stringResource(R.string.enrol_choose), style = MaterialTheme.typography.titleMedium)
    Column(Modifier.selectableGroup()) {
        ModeOption(AccessKeyMode.CAN, form.mode, stringResource(R.string.enrol_mode_dni), viewModel::setAccessKeyMode)
        ModeOption(AccessKeyMode.MRZ, form.mode, stringResource(R.string.enrol_mode_passport), viewModel::setAccessKeyMode)
    }

    when (form.mode) {
        AccessKeyMode.CAN -> {
            OutlinedTextField(
                value = form.can,
                onValueChange = viewModel::setCan,
                label = { Text(stringResource(R.string.enrol_can_label)) },
                supportingText = { Text(stringResource(R.string.enrol_can_help)) },
                singleLine = true,
                textStyle = Mono.copy(fontSize = MaterialTheme.typography.bodyLarge.fontSize),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                modifier = Modifier.fillMaxWidth(),
            )
        }
        AccessKeyMode.MRZ -> {
            val numberInvalid = form.documentNumber.isNotEmpty() &&
                AccessKeyRules.documentNumberProblem(form.documentNumber) != null
            OutlinedTextField(
                value = form.documentNumber,
                onValueChange = viewModel::setDocumentNumber,
                label = { Text(stringResource(R.string.enrol_document_number_label)) },
                supportingText = {
                    Text(
                        stringResource(
                            if (numberInvalid) R.string.enrol_document_number_invalid else R.string.enrol_document_number_help,
                        ),
                    )
                },
                isError = numberInvalid,
                singleLine = true,
                textStyle = Mono.copy(fontSize = MaterialTheme.typography.bodyLarge.fontSize),
                keyboardOptions = KeyboardOptions(
                    capitalization = KeyboardCapitalization.Characters,
                    keyboardType = KeyboardType.Password,
                ),
                modifier = Modifier.fillMaxWidth(),
            )
            DateField(
                digits = form.birthInput,
                label = stringResource(R.string.enrol_birth_label),
                problem = DateInput.parse(form.birthInput, LocalDate.now()).problemOrNull(),
                onValueChange = viewModel::setDateOfBirth,
            )
            DateField(
                digits = form.expiryInput,
                label = stringResource(R.string.enrol_expiry_label),
                problem = DateInput.parse(form.expiryInput).problemOrNull(),
                onValueChange = viewModel::setDateOfExpiry,
            )
        }
    }
    Note(stringResource(R.string.enrol_not_stored))

    readinessProblems.forEach { problem ->
        ProblemCard(Failure(problem, "NFC ${readiness?.nfc}, biometric ${readiness?.biometric}")) {
            SettingsAction(problem)
        }
    }
    if (replacing) {
        MessageCard(
            title = stringResource(R.string.enrol_replace_title),
            text = stringResource(R.string.enrol_replace_text),
            warning = true,
        )
    }
    PrimaryAction(
        text = stringResource(R.string.enrol_start),
        enabled = form.problems().isEmpty() && readiness != null && readinessProblems.isEmpty(),
        onClick = onStart,
    )
}

@Composable
private fun ReadContent(
    state: EnrolmentState,
    canRetry: Boolean,
    onCancel: () -> Unit,
    onRetry: () -> Unit,
    onEdit: () -> Unit,
    onDone: () -> Unit,
) {
    when (state.phase) {
        EnrolmentPhase.WAITING -> {
            Body(stringResource(R.string.read_hold))
            LinearProgressIndicator(Modifier.fillMaxWidth())
            Note(stringResource(R.string.read_hold_hint))
            SecondaryAction(stringResource(R.string.action_cancel), onClick = onCancel)
        }
        EnrolmentPhase.READING, EnrolmentPhase.SAVING -> {
            Body(stringResource(R.string.read_keep_still))
            val statuses = ReadProgress.statuses(state.log, state.phase)
            LinearProgressIndicator(progress = { ReadProgress.fraction(statuses) }, modifier = Modifier.fillMaxWidth())
            PhaseList(statuses)
            if (state.phase == EnrolmentPhase.READING) {
                SecondaryAction(stringResource(R.string.action_cancel), onClick = onCancel)
            }
        }
        EnrolmentPhase.DONE -> {
            MarkedRow(Mark.PASS, stringResource(R.string.mark_done), stringResource(R.string.read_done), emphasised = true)
            Body(stringResource(R.string.read_done_text))
            PrimaryAction(stringResource(R.string.action_done), onClick = onDone)
        }
        EnrolmentPhase.FAILED, EnrolmentPhase.CANCELLED, EnrolmentPhase.IDLE -> {
            val failure = state.failure
            if (failure != null) {
                ProblemCard(failure, details = { ReaderLog(state) }) { SettingsAction(failure.problem) }
            }
            state.notice?.let { notice ->
                MessageCard(title = stringResource(notice.textRes()), text = null, warning = true)
            }
            val needsEdit = failure != null &&
                failure.problem in setOf(Problem.WRONG_CAN, Problem.WRONG_DOCUMENT_DATA, Problem.INVALID_INPUT)
            if (needsEdit || !canRetry) {
                PrimaryAction(stringResource(R.string.read_edit), onClick = onEdit)
            } else {
                PrimaryAction(stringResource(R.string.read_retry), onClick = onRetry)
                SecondaryAction(stringResource(R.string.read_edit), onClick = onEdit)
            }
        }
    }
}

@Composable
private fun ColumnScope.ReaderLog(state: EnrolmentState) {
    state.noticeDetail?.let { MonoBlock(it) }
    state.log.forEach { entry ->
        val (label, color) = stepStatus(entry.status)
        StepRow(entry.step.label, label, color, entry.durationMillis, entry.detail)
    }
}

@Composable
private fun PhaseList(statuses: Map<ReadPhase, PhaseStatus>) {
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        ReadPhase.entries.forEach { phase ->
            val status = statuses[phase] ?: PhaseStatus.PENDING
            val (mark, description) = when (status) {
                PhaseStatus.DONE -> Mark.PASS to R.string.mark_done
                PhaseStatus.ACTIVE -> Mark.ACTIVE to R.string.mark_in_progress
                PhaseStatus.FAILED -> Mark.FAIL to R.string.mark_failed
                PhaseStatus.PENDING -> Mark.PENDING to R.string.mark_pending
            }
            MarkedRow(mark, stringResource(description), stringResource(phase.labelRes()))
        }
    }
}

@Composable
private fun SettingsAction(problem: Problem) {
    val context = LocalContext.current
    when (problem) {
        Problem.NFC_OFF -> SecondaryAction(stringResource(R.string.action_nfc_settings)) {
            openSettings(context, Intent(Settings.ACTION_NFC_SETTINGS))
        }
        Problem.NO_STRONG_BIOMETRIC -> SecondaryAction(stringResource(R.string.action_biometric_settings)) {
            openSettings(context, biometricEnrollIntent())
        }
        else -> Unit
    }
}

@Composable
private fun ModeOption(mode: AccessKeyMode, selected: AccessKeyMode, label: String, onSelect: (AccessKeyMode) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .selectable(selected = mode == selected, role = Role.RadioButton) { onSelect(mode) }
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        RadioButton(selected = mode == selected, onClick = null)
        Text(label, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.padding(start = 12.dp))
    }
}

@Composable
private fun DateField(digits: String, label: String, problem: DateProblem?, onValueChange: (String) -> Unit) {
    val error = when (problem) {
        DateProblem.NOT_A_DATE -> R.string.date_not_a_date
        DateProblem.OUT_OF_RANGE -> R.string.date_out_of_range
        DateProblem.IN_FUTURE -> R.string.date_in_future
        DateProblem.INCOMPLETE, null -> null
    }
    OutlinedTextField(
        value = digits,
        onValueChange = onValueChange,
        label = { Text(label) },
        placeholder = { Text(stringResource(R.string.date_placeholder)) },
        supportingText = { Text(stringResource(error ?: R.string.date_help)) },
        isError = error != null,
        singleLine = true,
        textStyle = Mono.copy(fontSize = MaterialTheme.typography.bodyLarge.fontSize),
        visualTransformation = DateTransformation,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
        modifier = Modifier.fillMaxWidth(),
    )
}

/** Only complete entries are reported, so the field does not turn red while the user is typing. */
private fun DateParse.problemOrNull(): DateProblem? =
    (this as? DateParse.Invalid)?.problem?.takeIf { it != DateProblem.INCOMPLETE }

private object DateTransformation : VisualTransformation {
    override fun filter(text: AnnotatedString): TransformedText {
        val digits = text.text
        return TransformedText(
            AnnotatedString(DateInput.display(digits)),
            object : OffsetMapping {
                override fun originalToTransformed(offset: Int): Int = DateInput.displayOffset(offset, digits.length)
                override fun transformedToOriginal(offset: Int): Int = DateInput.originalOffset(offset, digits.length)
            },
        )
    }
}

internal fun stepStatus(status: StepStatus): Pair<String, Color> = when (status) {
    StepStatus.STARTED -> "RUN" to StatusColors.warn
    StepStatus.DONE -> "OK" to StatusColors.pass
    StepStatus.SKIPPED -> "SKIP" to StatusColors.neutral
    StepStatus.FAILED -> "FAIL" to StatusColors.fail
}
