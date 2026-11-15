package dev.eudisovereign.icaowallet.ui

import dev.eudisovereign.icaowallet.crypto.HpkeException
import dev.eudisovereign.icaowallet.crypto.KeystoreException
import dev.eudisovereign.icaowallet.crypto.SigningException
import dev.eudisovereign.icaowallet.data.EnrollmentStoreException
import dev.eudisovereign.icaowallet.nfc.AccessKeyKind
import dev.eudisovereign.icaowallet.nfc.NfcAvailability
import dev.eudisovereign.icaowallet.nfc.ReadException
import dev.eudisovereign.icaowallet.protocol.DescriptorException
import dev.eudisovereign.icaowallet.transport.TransportException

enum class Problem {
    WRONG_CAN,
    WRONG_DOCUMENT_DATA,
    CONTACT_LOST,
    NFC_OFF,
    NFC_MISSING,
    NO_STRONG_BIOMETRIC,
    BIOMETRIC_UNAVAILABLE,
    INVALID_INPUT,
    BUSY,
    UNSUPPORTED_DOCUMENT,
    CHIP_CHECK_FAILED,
    SECURE_KEY_FAILED,
    READ_FAILED,
    SAVE_FAILED,
    READ_CANCELLED,
    NO_DOCUMENT,
    STORE_UNREADABLE,
    DELETE_FAILED,
    TECHNICAL_UNAVAILABLE,
    INVALID_CODE,
    SESSION_EXPIRED,
    KEY_UNUSABLE,
    KEY_INVALIDATED,
    BIOMETRIC_CANCELLED,
    BIOMETRIC_LOCKED,
    SIGNING_FAILED,
    VERIFIER_UNREACHABLE,
    DELIVERY_TIMEOUT,
    DELIVERY_FAILED,
    CANCELLED_BEFORE_SEND,
    CANCELLED_AFTER_SEND,
    UNEXPECTED,
}

/** A categorised failure; [detail] is the untranslated technical text shown only in detail views. */
class Failure(val problem: Problem, val detail: String)

enum class EnrolmentNotice { NEW_KEY_DELETED, PREVIOUS_DELETED, CLEANUP_FAILED }

object Problems {

    fun ofEnrolment(e: Throwable): Problem = when (e) {
        is ReadException.WrongAccessKey -> if (e.kind == AccessKeyKind.CAN) Problem.WRONG_CAN else Problem.WRONG_DOCUMENT_DATA
        is ReadException.TagLost, is ReadException.Timeout -> Problem.CONTACT_LOST
        is ReadException.UnsupportedDocument -> Problem.UNSUPPORTED_DOCUMENT
        is ReadException.IntegrityMismatch,
        is ReadException.ChipAuthenticationFailed,
        is ReadException.ActiveAuthenticationFailed,
        -> Problem.CHIP_CHECK_FAILED
        is ReadException.DeviceKeyFailed, is KeystoreException -> Problem.SECURE_KEY_FAILED
        is ReadException.ProtocolError -> Problem.READ_FAILED
        is EnrollmentStoreException -> Problem.SAVE_FAILED
        else -> Problem.UNEXPECTED
    }

    fun ofPresentation(e: Throwable): Problem = when (e) {
        is SigningException.Cancelled -> Problem.BIOMETRIC_CANCELLED
        is SigningException.Lockout -> Problem.BIOMETRIC_LOCKED
        is SigningException.BiometricUnavailable -> Problem.BIOMETRIC_UNAVAILABLE
        is SigningException.KeyInvalidated, is SigningException.KeyMissing -> Problem.KEY_INVALIDATED
        is SigningException -> Problem.SIGNING_FAILED
        is DescriptorException -> Problem.SESSION_EXPIRED
        is TransportException.PeerUnavailable, is TransportException.Connection -> Problem.VERIFIER_UNREACHABLE
        is TransportException.Timeout -> Problem.DELIVERY_TIMEOUT
        is TransportException, is HpkeException -> Problem.DELIVERY_FAILED
        else -> Problem.UNEXPECTED
    }

    fun ofNfc(nfc: NfcAvailability): Problem? = when (nfc) {
        NfcAvailability.READY -> null
        NfcAvailability.DISABLED -> Problem.NFC_OFF
        NfcAvailability.NO_HARDWARE -> Problem.NFC_MISSING
    }

    fun ofBiometric(biometric: BiometricReadiness): Problem? = when (biometric) {
        BiometricReadiness.READY -> null
        BiometricReadiness.NONE_ENROLLED -> Problem.NO_STRONG_BIOMETRIC
        else -> Problem.BIOMETRIC_UNAVAILABLE
    }

    fun ofReadiness(readiness: Readiness): List<Problem> =
        listOfNotNull(ofNfc(readiness.nfc), ofBiometric(readiness.biometric))

    fun detail(e: Throwable): String {
        val message = e.message ?: e.javaClass.simpleName
        return when (e) {
            is ReadException.WrongAccessKey -> message
            is ReadException.ChipAuthenticationFailed -> message + statusWord(e.statusWord)
            is ReadException.ActiveAuthenticationFailed -> message + statusWord(e.statusWord)
            is ReadException, is KeystoreException, is SigningException, is DescriptorException, is HpkeException,
            is IllegalArgumentException,
            -> message
            is EnrollmentStoreException, is TransportException -> withCause(e)
            else -> "${e.javaClass.simpleName}: $message"
        }
    }

    private fun statusWord(sw: Int?): String = sw?.let { " (SW %04X)".format(it) } ?: ""

    private fun withCause(e: Throwable): String {
        val cause = e.cause?.let { c -> c.message ?: c.javaClass.simpleName }
        return listOfNotNull(e.message, cause).joinToString(": ")
    }
}
