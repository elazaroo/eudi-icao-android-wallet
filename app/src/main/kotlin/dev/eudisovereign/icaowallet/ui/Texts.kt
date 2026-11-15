package dev.eudisovereign.icaowallet.ui

import androidx.annotation.StringRes
import dev.eudisovereign.icaowallet.R
import dev.eudisovereign.icaowallet.nfc.AccessKeyKind
import dev.eudisovereign.icaowallet.nfc.NfcAvailability
import dev.eudisovereign.icaowallet.report.MrzFieldId
import dev.eudisovereign.icaowallet.report.SodCoverage

@StringRes
fun Problem.titleRes(): Int = when (this) {
    Problem.WRONG_CAN -> R.string.problem_wrong_can
    Problem.WRONG_DOCUMENT_DATA -> R.string.problem_wrong_document_data
    Problem.CONTACT_LOST -> R.string.problem_contact_lost
    Problem.NFC_OFF -> R.string.problem_nfc_off
    Problem.NFC_MISSING -> R.string.problem_nfc_missing
    Problem.NO_STRONG_BIOMETRIC -> R.string.problem_no_strong_biometric
    Problem.BIOMETRIC_UNAVAILABLE -> R.string.problem_biometric_unavailable
    Problem.INVALID_INPUT -> R.string.problem_invalid_input
    Problem.BUSY -> R.string.problem_busy
    Problem.UNSUPPORTED_DOCUMENT -> R.string.problem_unsupported_document
    Problem.CHIP_CHECK_FAILED -> R.string.problem_chip_check_failed
    Problem.SECURE_KEY_FAILED -> R.string.problem_secure_key_failed
    Problem.READ_FAILED -> R.string.problem_read_failed
    Problem.SAVE_FAILED -> R.string.problem_save_failed
    Problem.READ_CANCELLED -> R.string.problem_read_cancelled
    Problem.NO_DOCUMENT -> R.string.problem_no_document
    Problem.STORE_UNREADABLE -> R.string.problem_store_unreadable
    Problem.DELETE_FAILED -> R.string.problem_delete_failed
    Problem.TECHNICAL_UNAVAILABLE -> R.string.problem_technical_unavailable
    Problem.INVALID_CODE -> R.string.problem_invalid_code
    Problem.SESSION_EXPIRED -> R.string.problem_session_expired
    Problem.KEY_UNUSABLE -> R.string.problem_key_unusable
    Problem.KEY_INVALIDATED -> R.string.problem_key_invalidated
    Problem.BIOMETRIC_CANCELLED -> R.string.problem_biometric_cancelled
    Problem.BIOMETRIC_LOCKED -> R.string.problem_biometric_locked
    Problem.SIGNING_FAILED -> R.string.problem_signing_failed
    Problem.VERIFIER_UNREACHABLE -> R.string.problem_verifier_unreachable
    Problem.DELIVERY_TIMEOUT -> R.string.problem_delivery_timeout
    Problem.DELIVERY_FAILED -> R.string.problem_delivery_failed
    Problem.CANCELLED_BEFORE_SEND -> R.string.problem_cancelled_before_send
    Problem.CANCELLED_AFTER_SEND -> R.string.problem_cancelled_after_send
    Problem.UNEXPECTED -> R.string.problem_unexpected
}

@StringRes
fun Problem.hintRes(): Int? = when (this) {
    Problem.WRONG_CAN -> R.string.hint_wrong_can
    Problem.WRONG_DOCUMENT_DATA -> R.string.hint_wrong_document_data
    Problem.CONTACT_LOST -> R.string.hint_contact_lost
    Problem.NFC_OFF -> R.string.hint_nfc_off
    Problem.NFC_MISSING -> R.string.hint_nfc_missing
    Problem.NO_STRONG_BIOMETRIC -> R.string.hint_no_strong_biometric
    Problem.BIOMETRIC_UNAVAILABLE -> R.string.hint_biometric_unavailable
    Problem.INVALID_INPUT -> R.string.hint_invalid_input
    Problem.UNSUPPORTED_DOCUMENT -> R.string.hint_unsupported_document
    Problem.CHIP_CHECK_FAILED -> R.string.hint_chip_check_failed
    Problem.SECURE_KEY_FAILED, Problem.READ_FAILED, Problem.SAVE_FAILED, Problem.UNEXPECTED -> R.string.hint_try_again
    Problem.STORE_UNREADABLE -> R.string.hint_store_unreadable
    Problem.INVALID_CODE -> R.string.hint_invalid_code
    Problem.SESSION_EXPIRED -> R.string.hint_session_expired
    Problem.KEY_UNUSABLE -> R.string.hint_key_unusable
    Problem.KEY_INVALIDATED -> R.string.hint_key_invalidated
    Problem.BIOMETRIC_LOCKED -> R.string.hint_biometric_locked
    Problem.VERIFIER_UNREACHABLE -> R.string.hint_verifier_unreachable
    Problem.DELIVERY_TIMEOUT, Problem.DELIVERY_FAILED, Problem.CANCELLED_AFTER_SEND -> R.string.hint_new_code
    Problem.BUSY, Problem.READ_CANCELLED, Problem.NO_DOCUMENT, Problem.DELETE_FAILED, Problem.TECHNICAL_UNAVAILABLE,
    Problem.BIOMETRIC_CANCELLED, Problem.SIGNING_FAILED, Problem.CANCELLED_BEFORE_SEND,
    -> null
}

@StringRes
fun EnrolmentNotice.textRes(): Int = when (this) {
    EnrolmentNotice.NEW_KEY_DELETED -> R.string.notice_new_key_deleted
    EnrolmentNotice.PREVIOUS_DELETED -> R.string.notice_previous_deleted
    EnrolmentNotice.CLEANUP_FAILED -> R.string.notice_cleanup_failed
}

@StringRes
fun ReadPhase.labelRes(): Int = when (this) {
    ReadPhase.CONNECTING -> R.string.phase_connecting
    ReadPhase.UNLOCKING -> R.string.phase_unlocking
    ReadPhase.READING -> R.string.phase_reading
    ReadPhase.CHECKING -> R.string.phase_checking
    ReadPhase.SECURE_KEY -> R.string.phase_secure_key
}

@StringRes
fun DocumentKind.labelRes(): Int = when (this) {
    DocumentKind.DNI -> R.string.document_dni
    DocumentKind.IDENTITY_CARD -> R.string.document_identity_card
    DocumentKind.PASSPORT -> R.string.document_passport
    DocumentKind.VISA -> R.string.document_visa
    DocumentKind.OTHER -> R.string.document_other
}

/** Titles of the verifier checks; unknown identifiers return null and are shown as received. */
@StringRes
fun checkTitleRes(id: String): Int? = when (id) {
    "passive-authentication" -> R.string.check_passive_authentication
    "data-integrity" -> R.string.check_data_integrity
    "chip-binding" -> R.string.check_chip_binding
    "nonce-proof" -> R.string.check_nonce_proof
    else -> null
}

@StringRes
fun NfcAvailability.descriptionRes(): Int = when (this) {
    NfcAvailability.READY -> R.string.readiness_nfc_ready
    NfcAvailability.DISABLED -> R.string.readiness_nfc_disabled
    NfcAvailability.NO_HARDWARE -> R.string.readiness_nfc_missing
}

@StringRes
fun BiometricReadiness.descriptionRes(): Int = when (this) {
    BiometricReadiness.READY -> R.string.readiness_biometric_ready
    BiometricReadiness.NONE_ENROLLED -> R.string.readiness_biometric_none
    BiometricReadiness.NO_HARDWARE -> R.string.readiness_biometric_no_hardware
    BiometricReadiness.HW_UNAVAILABLE -> R.string.readiness_biometric_hw_unavailable
    BiometricReadiness.SECURITY_UPDATE_REQUIRED -> R.string.readiness_biometric_update
    BiometricReadiness.UNSUPPORTED -> R.string.readiness_biometric_unsupported
    BiometricReadiness.UNKNOWN -> R.string.readiness_biometric_unknown
}

@StringRes
fun DeviceKeyStatus.descriptionRes(): Int = when (this) {
    DeviceKeyStatus.Matches -> R.string.key_status_matches
    DeviceKeyStatus.Missing -> R.string.key_status_missing
    DeviceKeyStatus.Different -> R.string.key_status_different
    is DeviceKeyStatus.Unreadable -> R.string.key_status_unreadable
}

@StringRes
fun TransportChoice.labelRes(): Int = when (this) {
    TransportChoice.PEERJS -> R.string.transport_peerjs
    TransportChoice.RELAY -> R.string.transport_relay
}

@StringRes
fun AccessKeyKind.labelRes(): Int = when (this) {
    AccessKeyKind.CAN -> R.string.tech_password_can
    AccessKeyKind.MRZ -> R.string.tech_password_mrz
}

@StringRes
fun SodCoverage.labelRes(): Int = when (this) {
    SodCoverage.MATCH -> R.string.tech_coverage_match
    SodCoverage.MISMATCH -> R.string.tech_coverage_mismatch
    SodCoverage.NOT_LISTED -> R.string.tech_coverage_not_listed
    SodCoverage.NOT_COVERED -> R.string.tech_coverage_not_covered
}

@StringRes
fun MrzFieldId.labelRes(): Int = when (this) {
    MrzFieldId.DOCUMENT_CODE -> R.string.mrz_document_code
    MrzFieldId.ISSUING_STATE -> R.string.mrz_issuing_state
    MrzFieldId.DOCUMENT_NUMBER -> R.string.mrz_document_number
    MrzFieldId.PERSONAL_NUMBER -> R.string.mrz_personal_number
    MrzFieldId.OPTIONAL_DATA_1 -> R.string.mrz_optional_data_1
    MrzFieldId.OPTIONAL_DATA_2 -> R.string.mrz_optional_data_2
    MrzFieldId.DATE_OF_BIRTH -> R.string.mrz_date_of_birth
    MrzFieldId.SEX -> R.string.mrz_sex
    MrzFieldId.DATE_OF_EXPIRY -> R.string.mrz_date_of_expiry
    MrzFieldId.NATIONALITY -> R.string.mrz_nationality
    MrzFieldId.PRIMARY_IDENTIFIER -> R.string.mrz_primary_identifier
    MrzFieldId.SECONDARY_IDENTIFIER -> R.string.mrz_secondary_identifier
    MrzFieldId.COMPOSITE_CHECK -> R.string.mrz_composite_check
}

/** The data categories every presentation carries, in display order; values are never shown. */
val sharedDataCategories: List<Int> = listOf(
    R.string.data_full_name,
    R.string.data_document_number,
    R.string.data_personal_number,
    R.string.data_date_of_birth,
    R.string.data_sex,
    R.string.data_nationality,
    R.string.data_expiry_date,
)
