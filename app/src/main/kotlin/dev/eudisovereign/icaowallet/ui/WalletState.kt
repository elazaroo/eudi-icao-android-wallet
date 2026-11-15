package dev.eudisovereign.icaowallet.ui

import androidx.biometric.BiometricManager
import dev.eudisovereign.icaowallet.crypto.KeyStorage
import dev.eudisovereign.icaowallet.data.Enrollment
import dev.eudisovereign.icaowallet.nfc.AccessKey
import dev.eudisovereign.icaowallet.nfc.AccessKeyRules
import dev.eudisovereign.icaowallet.nfc.NfcAvailability
import dev.eudisovereign.icaowallet.nfc.ReadStep
import dev.eudisovereign.icaowallet.nfc.StepStatus
import dev.eudisovereign.icaowallet.protocol.Binding
import dev.eudisovereign.icaowallet.protocol.ResultFrame
import dev.eudisovereign.icaowallet.protocol.SessionDescriptor
import dev.eudisovereign.icaowallet.report.BuildIdentity
import dev.eudisovereign.icaowallet.report.ChainExpiry
import dev.eudisovereign.icaowallet.report.Mrz
import dev.eudisovereign.icaowallet.report.TechnicalReport

enum class BiometricReadiness {
    READY,
    NONE_ENROLLED,
    NO_HARDWARE,
    HW_UNAVAILABLE,
    SECURITY_UPDATE_REQUIRED,
    UNSUPPORTED,
    UNKNOWN,
    ;

    companion object {
        fun of(code: Int): BiometricReadiness = when (code) {
            BiometricManager.BIOMETRIC_SUCCESS -> READY
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> NONE_ENROLLED
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> NO_HARDWARE
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> HW_UNAVAILABLE
            BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> SECURITY_UPDATE_REQUIRED
            BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED -> UNSUPPORTED
            else -> UNKNOWN
        }
    }
}

class Readiness(val nfc: NfcAvailability, val biometric: BiometricReadiness, val camera: Boolean)

sealed class DeviceKeyStatus(val usable: Boolean) {
    object Matches : DeviceKeyStatus(true)
    object Missing : DeviceKeyStatus(false)
    object Different : DeviceKeyStatus(false)
    class Unreadable(val detail: String) : DeviceKeyStatus(false)
}

class EnrollmentOverview(
    val enrollment: Enrollment,
    val mrz: Mrz?,
    val keyStatus: DeviceKeyStatus,
    val attestationExpiry: ChainExpiry?,
    val attestationError: String?,
)

sealed interface IdentityState {
    object Loading : IdentityState
    class Ready(val identity: BuildIdentity) : IdentityState
    class Failed(val detail: String) : IdentityState
}

enum class AccessKeyMode { CAN, MRZ }

/** [dateOfBirth] and [dateOfExpiry] hold YYMMDD; [birthInput] and [expiryInput] hold the typed DDMMYYYY digits. */
data class AccessKeyForm(
    val mode: AccessKeyMode = AccessKeyMode.CAN,
    val can: String = "",
    val documentNumber: String = "",
    val dateOfBirth: String = "",
    val dateOfExpiry: String = "",
    val birthInput: String = "",
    val expiryInput: String = "",
) {
    fun problems(): List<String> = when (mode) {
        AccessKeyMode.CAN -> listOfNotNull(AccessKeyRules.canProblem(can))
        AccessKeyMode.MRZ -> AccessKeyRules.mrzProblems(documentNumber, dateOfBirth, dateOfExpiry)
    }

    fun toAccessKey(): AccessKey = when (mode) {
        AccessKeyMode.CAN -> AccessKey.Can(can)
        AccessKeyMode.MRZ -> AccessKey.Mrz(documentNumber, dateOfBirth, dateOfExpiry)
    }

    // The data class toString would print the access key.
    override fun toString(): String = "AccessKeyForm($mode)"
}

sealed interface StoreState {
    object Loading : StoreState
    object Empty : StoreState
    class Loaded(val overview: EnrollmentOverview) : StoreState
    class Failed(val failure: Failure) : StoreState
}

enum class EnrolmentPhase {
    IDLE, WAITING, READING, SAVING, DONE, FAILED, CANCELLED;

    val busy: Boolean get() = this == WAITING || this == READING || this == SAVING
    val acceptsTag: Boolean get() = this == WAITING || this == READING
}

class LogEntry(val step: ReadStep, val status: StepStatus, val durationMillis: Long?, val detail: String?)

data class EnrolmentState(
    val phase: EnrolmentPhase = EnrolmentPhase.IDLE,
    val log: List<LogEntry> = emptyList(),
    val failure: Failure? = null,
    val notice: EnrolmentNotice? = null,
    val noticeDetail: String? = null,
)

sealed interface TechnicalState {
    object Loading : TechnicalState
    class Ready(val report: TechnicalReport, val keyStatus: DeviceKeyStatus) : TechnicalState
    class Failed(val failure: Failure) : TechnicalState
}

data class ScannerState(val rejection: Failure? = null)

enum class TransportChoice { PEERJS, RELAY }

enum class PresentationStage(val label: String) {
    TRANSCRIPT("Transcript: eudi-icao-auth-v1, nonce, origin"),
    SIGNATURE("BiometricPrompt and ECDSA P-256 signature over the transcript"),
    PRESENTATION("Presentation JSON"),
    ENVELOPE("HPKE seal: DHKEM(P-256), HKDF-SHA256, AES-128-GCM"),
    DELIVERY("Delivery and verifier result"),
}

enum class StageStatus { PENDING, RUNNING, DONE, FAILED, CANCELLED }

class StageEntry(val stage: PresentationStage, val status: StageStatus, val durationMillis: Long?, val detail: String?)

enum class PresentationPhase { IDLE, RUNNING, FINISHED, FAILED }

data class PresentationState(
    val descriptor: SessionDescriptor? = null,
    val transport: TransportChoice = TransportChoice.PEERJS,
    val alterDg1: Boolean = false,
    val phase: PresentationPhase = PresentationPhase.IDLE,
    val stages: List<StageEntry> = emptyList(),
    val result: ResultFrame? = null,
    val failure: Failure? = null,
    val consumed: Boolean = false,
)

enum class AgeProgress { PREPARING, COMPUTING, PROVING, SENDING }

enum class AgeStage(val label: String, val progress: AgeProgress) {
    CONFIRMATION("BiometricPrompt (class 3) user confirmation", AgeProgress.PREPARING),
    INPUTS("Witness inputs from EF.DG1 and EF.SOD", AgeProgress.PREPARING),
    WITNESS("Witness: age_proof.wasm in an off-screen WebView", AgeProgress.COMPUTING),
    PROOF("Groth16 proof: rapidsnark with age_proof.zkey", AgeProgress.PROVING),
    ENVELOPE("Plaintext age-at-least and HPKE seal", AgeProgress.SENDING),
    DELIVERY("Delivery and verifier result", AgeProgress.SENDING),
}

class AgeStageEntry(val stage: AgeStage, val status: StageStatus, val durationMillis: Long?, val detail: String?)

/** [notProvable] holds the reason when the stored document cannot satisfy the statement; null while unchecked. */
data class AgeProofState(
    val descriptor: SessionDescriptor? = null,
    val transport: TransportChoice = TransportChoice.PEERJS,
    val eligibilityChecked: Boolean = false,
    val notProvable: Failure? = null,
    val phase: PresentationPhase = PresentationPhase.IDLE,
    val stages: List<AgeStageEntry> = emptyList(),
    val result: ResultFrame? = null,
    val failure: Failure? = null,
    val failureTrace: String? = null,
    val consumed: Boolean = false,
) {
    val currentProgress: AgeProgress?
        get() = stages.firstOrNull { it.status == StageStatus.RUNNING }?.stage?.progress
}

enum class ProvingKeyStatus { CHECKING, MISSING, INSTALLED, IMPORTING }

data class ProvingKeyState(
    val status: ProvingKeyStatus = ProvingKeyStatus.CHECKING,
    val copiedBytes: Long = 0,
    val failure: Failure? = null,
)

val Binding.wireName: String
    get() = when (this) {
        Binding.AA -> "aa"
        Binding.CA_ATTESTATION -> "ca-attestation"
    }

val KeyStorage.label: String
    get() = when (this) {
        KeyStorage.STRONGBOX -> "StrongBox"
        KeyStorage.TEE -> "TEE"
        KeyStorage.SOFTWARE -> "software"
    }
