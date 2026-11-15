package dev.eudisovereign.icaowallet.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.eudisovereign.icaowallet.R
import dev.eudisovereign.icaowallet.crypto.Codec
import dev.eudisovereign.icaowallet.nfc.AccessKeyKind
import dev.eudisovereign.icaowallet.nfc.NfcAvailability
import dev.eudisovereign.icaowallet.protocol.Binding
import dev.eudisovereign.icaowallet.report.Attestation
import dev.eudisovereign.icaowallet.report.AttestationSummary
import dev.eudisovereign.icaowallet.report.BuildIdentity
import dev.eudisovereign.icaowallet.report.Mrz
import dev.eudisovereign.icaowallet.report.MrzFieldId
import dev.eudisovereign.icaowallet.report.SodCoverage
import dev.eudisovereign.icaowallet.report.TechnicalReport
import dev.eudisovereign.icaowallet.ui.theme.Mono
import dev.eudisovereign.icaowallet.ui.theme.StatusColors

@Composable
fun TechnicalScreen(viewModel: WalletViewModel, onBack: () -> Unit) {
    val state by viewModel.technical.collectAsStateWithLifecycle()
    val identity by viewModel.identity.collectAsStateWithLifecycle()
    val readiness by viewModel.readiness.collectAsStateWithLifecycle()
    // Not saved: personal data is hidden again whenever the screen is recreated.
    var revealed by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) { viewModel.loadTechnical() }

    ScreenScaffold(title = stringResource(R.string.tech_title), onBack = onBack) {
        when (val current = state) {
            TechnicalState.Loading -> Note(stringResource(R.string.tech_loading))
            is TechnicalState.Failed -> ProblemCard(current.failure)
            is TechnicalState.Ready -> {
                SecondaryAction(stringResource(if (revealed) R.string.tech_hide_personal else R.string.tech_show_personal)) {
                    revealed = !revealed
                }
                TechnicalContent(current, identity, revealed)
            }
        }
        Section(stringResource(R.string.tech_section_readiness)) { ReadinessContent(readiness) }
        Section(stringResource(R.string.tech_section_identity)) { BuildIdentityContent(identity, showPolicyEntry = true) }
    }
}

@Composable
private fun ReadinessContent(readiness: Readiness?) {
    if (readiness == null) {
        Note(stringResource(R.string.tech_readiness_checking))
        return
    }
    Field(
        label = "NFC",
        value = stringResource(readiness.nfc.descriptionRes()),
        valueColor = checkColor(readiness.nfc == NfcAvailability.READY),
    )
    Field(
        label = stringResource(R.string.tech_strong_biometric),
        value = stringResource(readiness.biometric.descriptionRes()),
        valueColor = checkColor(readiness.biometric == BiometricReadiness.READY),
    )
    Field(
        label = stringResource(R.string.tech_camera),
        value = stringResource(if (readiness.camera) R.string.tech_camera_present else R.string.home_no_camera),
        valueColor = checkColor(readiness.camera),
    )
}

@Composable
private fun TechnicalContent(state: TechnicalState.Ready, identity: IdentityState, revealed: Boolean) {
    val report = state.report
    val enrollment = report.enrollment
    val notReported = stringResource(R.string.tech_not_reported)
    val noDs = stringResource(R.string.tech_no_ds)
    val none = stringResource(R.string.tech_none)

    Section("MRZ (EF.DG1)") {
        val mrz = report.mrz
        if (mrz == null) {
            ErrorPanel(stringResource(R.string.tech_mrz_error), report.mrzError ?: "unknown error")
        } else {
            MrzContent(mrz, revealed)
        }
    }

    Section(stringResource(R.string.tech_section_files)) {
        Note(stringResource(R.string.tech_digest_algorithm, enrollment.sodSummary.ldsHashAlgorithm))
        report.filesError?.let { ErrorPanel(stringResource(R.string.tech_sod_error), it) }
        report.files.forEach { row ->
            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(stringResource(R.string.tech_file_size, row.name, row.size), style = MaterialTheme.typography.titleSmall)
                MonoBlock(row.digestHex)
                Text(
                    text = stringResource(row.coverage.labelRes()),
                    style = Mono,
                    color = when (row.coverage) {
                        SodCoverage.MATCH -> StatusColors.pass
                        SodCoverage.MISMATCH, SodCoverage.NOT_LISTED -> StatusColors.fail
                        SodCoverage.NOT_COVERED -> StatusColors.neutral
                    },
                )
            }
        }
    }

    Section("EF.SOD") {
        val sod = enrollment.sodSummary
        Field(stringResource(R.string.tech_lds_hash), sod.ldsHashAlgorithm, mono = true)
        Field(stringResource(R.string.tech_data_groups), sod.dataGroups.joinToString(", ") { "DG$it" }, mono = true)
        sod.ldsVersion?.let { Field(stringResource(R.string.tech_lds_version), it, mono = true) }
        Field(stringResource(R.string.tech_signer_digest), sod.signerDigestAlgorithm ?: notReported, mono = true)
        Field(stringResource(R.string.tech_signature_algorithm), sod.signatureAlgorithm ?: notReported, mono = true)
        Field(stringResource(R.string.tech_ds_subject), sod.dsSubject ?: noDs, mono = true)
        Field(stringResource(R.string.tech_ds_issuer), sod.dsIssuer ?: noDs, mono = true)
        sod.dsSerialHex?.let { Field(stringResource(R.string.tech_ds_serial), it, mono = true) }
        if (sod.dsNotBeforeMillis != null && sod.dsNotAfterMillis != null) {
            Field(
                stringResource(R.string.tech_ds_validity),
                stringResource(R.string.tech_range, formatUtc(sod.dsNotBeforeMillis), formatUtc(sod.dsNotAfterMillis)),
                mono = true,
            )
        }
        Note(stringResource(R.string.tech_pa_note))
    }

    Section(stringResource(R.string.tech_section_access)) {
        val pace = enrollment.pace
        val protocol = stringResource(R.string.tech_protocol)
        val password = stringResource(R.string.tech_password)
        if (pace == null) {
            Field(protocol, "BAC (Basic Access Control)", mono = true)
            Field(password, stringResource(AccessKeyKind.MRZ.labelRes()))
            Note(
                stringResource(
                    if (enrollment.cardAccess == null) R.string.tech_bac_no_card_access else R.string.tech_bac_no_pace_info,
                ),
            )
        } else {
            Field(protocol, "PACE ${pace.protocol}", mono = true)
            Field("OID", pace.oid, mono = true)
            Field(stringResource(R.string.tech_parameter_id), pace.parameterId?.toString() ?: none, mono = true)
            Field(password, pace.password?.let { stringResource(it.labelRes()) } ?: stringResource(R.string.tech_not_recorded))
        }
    }

    Section("Chip Authentication") {
        val ca = enrollment.chipAuthentication
        if (ca == null) {
            Note(stringResource(if (enrollment.dg14 == null) R.string.tech_ca_no_dg14 else R.string.tech_ca_no_key))
        } else {
            Field(stringResource(R.string.tech_protocol), ca.protocol, mono = true)
            Field(
                label = stringResource(R.string.tech_protocol_oid),
                value = ca.protocolOid + if (ca.protocolOidInferred) " " + stringResource(R.string.tech_oid_inferred) else "",
                mono = true,
                valueColor = if (ca.protocolOidInferred) StatusColors.warn else Color.Unspecified,
            )
            Field(stringResource(R.string.tech_public_key_oid), ca.publicKeyOid, mono = true)
            Field(stringResource(R.string.tech_key_id), ca.keyId ?: none, mono = true)
            Field(stringResource(R.string.tech_chip_public_key), ca.publicKey, mono = true)
            Note(stringResource(R.string.tech_ca_done))
        }
    }

    Section(stringResource(R.string.tech_section_binding)) {
        Field(stringResource(R.string.tech_mode), enrollment.binding.wireName, mono = true)
        if (enrollment.binding == Binding.AA) {
            enrollment.activeAuthentication?.let { aa ->
                Field(stringResource(R.string.tech_aa_key), aa.key, mono = true)
                Field(
                    label = stringResource(R.string.tech_digest),
                    value = aa.digestAlgorithm + if (aa.digestAssumed) " " + stringResource(R.string.tech_digest_assumed) else "",
                    mono = true,
                )
                Field(stringResource(R.string.tech_signature_scheme), aa.signatureAlgorithm, mono = true)
            }
            report.aaChallengeHex?.let { Field("RND.IFD = SHA-256(device SPKI)[0..8]", it, mono = true) }
            enrollment.aaResponse?.let {
                Field(stringResource(R.string.tech_aa_response, it.size), Codec.hex(it), mono = true)
            }
        }
        if (enrollment.keyAttestation.isEmpty()) {
            Note(stringResource(R.string.tech_no_attestation))
        } else {
            report.attestationError?.let { ErrorPanel(stringResource(R.string.tech_attestation_error), it) }
            report.attestation?.let {
                AttestationContent(it, report, (identity as? IdentityState.Ready)?.identity, enrollment.binding)
            }
        }
    }

    Section(stringResource(R.string.tech_section_device_key)) {
        Field("SPKI SHA-256", report.deviceKeySha256Hex, mono = true)
        Field(stringResource(R.string.tech_storage), enrollment.keyStorage.label)
        val keyStatus = state.keyStatus
        Field(
            label = "AndroidKeyStore",
            value = if (keyStatus is DeviceKeyStatus.Unreadable) {
                stringResource(keyStatus.descriptionRes(), keyStatus.detail)
            } else {
                stringResource(keyStatus.descriptionRes())
            },
            valueColor = checkColor(keyStatus.usable),
        )
        Field(stringResource(R.string.tech_expected_challenge), report.attestationChallengeHex, mono = true)
        Field(
            stringResource(R.string.tech_enrolled),
            stringResource(
                R.string.tech_enrolled_value,
                formatLocal(enrollment.enrolledAtMillis),
                enrollment.deviceModel,
                enrollment.osVersion,
            ),
        )
    }

    Section(stringResource(R.string.tech_section_log)) {
        enrollment.steps.forEach { step ->
            val (label, color) = stepStatus(step.status)
            StepRow(step.step.label, label, color, step.durationMillis.takeIf { it > 0 }, step.detail)
        }
    }
}

@Composable
private fun MrzContent(mrz: Mrz, revealed: Boolean) {
    MonoBlock(Masking.maskLines(mrz.lines, revealed))
    Field(
        stringResource(R.string.tech_format),
        "${mrz.documentCode} ${mrz.format.name}, ${mrz.format.lineCount} x ${mrz.format.lineLength}",
    )
    val empty = stringResource(R.string.tech_empty)
    val valid = stringResource(R.string.tech_check_valid)
    val invalid = stringResource(R.string.tech_check_invalid)
    mrz.fields().forEach { field ->
        val check = when (field.checkValid) {
            true -> valid
            false -> invalid
            null -> null
        }
        val value = when {
            field.id == MrzFieldId.COMPOSITE_CHECK -> check.orEmpty()
            Masking.isPersonal(field.id) -> Masking.mask(field.value.ifEmpty { empty }, revealed) +
                (check?.let { "  [$it]" } ?: "")
            else -> field.value.ifEmpty { empty } + (check?.let { "  [$it]" } ?: "")
        }
        Field(stringResource(field.id.labelRes()), value, mono = true, valueColor = checkColor(field.checkValid))
    }
}

@Composable
private fun AttestationContent(
    summary: AttestationSummary,
    report: TechnicalReport,
    identity: BuildIdentity?,
    binding: Binding,
) {
    Field(stringResource(R.string.tech_attestation_chain), stringResource(R.string.tech_attestation_chain_value, summary.certificates.size))
    summary.expiry?.let { AttestationExpiryField(it, binding, showSubject = true) }
    summary.certificates.forEachIndexed { index, cert ->
        Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text("[$index] ${cert.publicKey}", style = MaterialTheme.typography.titleSmall)
            MonoBlock("subject ${cert.subject}\nissuer  ${cert.issuer}\nserial  ${cert.serialHex}")
            MonoBlock("valid   ${formatUtc(cert.notBeforeMillis)} to ${formatUtc(cert.notAfterMillis)}")
            Text(
                text = stringResource(if (cert.hasKeyDescription) R.string.tech_key_description_present else R.string.tech_key_description_absent),
                style = Mono,
                color = when {
                    index == 0 && cert.hasKeyDescription -> StatusColors.pass
                    index == 0 || cert.hasKeyDescription -> StatusColors.fail
                    else -> StatusColors.neutral
                },
            )
        }
    }
    summary.keyDescriptionError?.let { ErrorPanel("KeyDescription", it) }
    val description = summary.keyDescription ?: return
    Field("attestationVersion", description.attestationVersion.toString(), mono = true)
    Field("attestationSecurityLevel", Attestation.securityLevelName(description.attestationSecurityLevel), mono = true)
    Field("keyMintVersion", description.keyMintVersion.toString(), mono = true)
    Field("keyMintSecurityLevel", Attestation.securityLevelName(description.keyMintSecurityLevel), mono = true)
    val challengeHex = Codec.hex(description.attestationChallenge)
    val challengeMatches = challengeHex == report.attestationChallengeHex
    Field(
        label = "attestationChallenge",
        value = challengeHex + "  [" + stringResource(
            if (challengeMatches) R.string.tech_challenge_matches else R.string.tech_challenge_differs,
        ) + "]",
        mono = true,
        valueColor = checkColor(challengeMatches),
    )
    description.rootOfTrust?.let { root ->
        Field(
            label = "RootOfTrust",
            value = "verifiedBootState ${Attestation.verifiedBootStateName(root.verifiedBootState)}, " +
                "deviceLocked ${root.deviceLocked}",
            mono = true,
            valueColor = checkColor(root.verifiedBootState == 0 && root.deviceLocked),
        )
    }
    val applicationId = description.applicationId
    if (applicationId == null) {
        Note(stringResource(R.string.tech_no_application_id), color = StatusColors.fail)
    } else {
        val packages = applicationId.packages.joinToString("\n") { (name, version) -> "$name (version $version)" }
        val digests = applicationId.signatureDigests.map(Codec::hex)
        Field("attestationApplicationId packages", packages, mono = true)
        Field("attestationApplicationId signatureDigests", digests.joinToString("\n"), mono = true)
        if (identity != null) {
            val matches = applicationId.packages.size == 1 &&
                applicationId.packages.single().first == identity.packageName &&
                digests.any { it in identity.signingCertSha256 }
            Field(
                label = stringResource(R.string.tech_build_comparison),
                value = stringResource(if (matches) R.string.tech_build_matches else R.string.tech_build_differs),
                valueColor = checkColor(matches),
            )
        }
    }
}
