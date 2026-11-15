package dev.eudisovereign.icaowallet.ui

import dev.eudisovereign.icaowallet.crypto.HpkeException
import dev.eudisovereign.icaowallet.crypto.KeystoreException
import dev.eudisovereign.icaowallet.crypto.SigningException
import dev.eudisovereign.icaowallet.data.EnrollmentStoreException
import dev.eudisovereign.icaowallet.nfc.AccessKeyKind
import dev.eudisovereign.icaowallet.nfc.AccessProtocol
import dev.eudisovereign.icaowallet.nfc.NfcAvailability
import dev.eudisovereign.icaowallet.nfc.ReadException
import dev.eudisovereign.icaowallet.nfc.ReadStep
import dev.eudisovereign.icaowallet.protocol.DescriptorException
import dev.eudisovereign.icaowallet.protocol.ResultFrame
import dev.eudisovereign.icaowallet.transport.TransportException
import dev.eudisovereign.icaowallet.zk.KeyDownloadException
import java.io.IOException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ProblemsTest {

    @Test
    fun wrongAccessKeyNamesTheKeyThatWasRejected() {
        val can = ReadException.WrongAccessKey(AccessKeyKind.CAN, AccessProtocol.PACE, 0x63C2)
        val mrz = ReadException.WrongAccessKey(AccessKeyKind.MRZ, AccessProtocol.BAC, 0x6982)
        assertEquals(Problem.WRONG_CAN, Problems.ofEnrolment(can))
        assertEquals(Problem.WRONG_DOCUMENT_DATA, Problems.ofEnrolment(mrz))
        assertEquals("PACE rejected the CAN (SW 63C2), 2 attempts left", Problems.detail(can))
    }

    @Test
    fun lostContactAndTimeoutAskTheUserToKeepTheDocumentStill() {
        assertEquals(Problem.CONTACT_LOST, Problems.ofEnrolment(ReadException.TagLost(ReadStep.READ_DG1, IOException("Tag was lost."))))
        assertEquals(Problem.CONTACT_LOST, Problems.ofEnrolment(ReadException.Timeout(ReadStep.PACE)))
    }

    @Test
    fun chipFailuresAreCategorised() {
        assertEquals(Problem.UNSUPPORTED_DOCUMENT, Problems.ofEnrolment(ReadException.UnsupportedDocument("no EF.DG14")))
        assertEquals(Problem.CHIP_CHECK_FAILED, Problems.ofEnrolment(ReadException.IntegrityMismatch(1, "SHA-256")))
        val ca = ReadException.ChipAuthenticationFailed("card error", 0x6982)
        assertEquals(Problem.CHIP_CHECK_FAILED, Problems.ofEnrolment(ca))
        assertEquals("Chip Authentication failed: card error (SW 6982)", Problems.detail(ca))
        val aa = ReadException.ActiveAuthenticationFailed("the chip returned no signature", null)
        assertEquals(Problem.CHIP_CHECK_FAILED, Problems.ofEnrolment(aa))
        assertEquals("Active Authentication failed: the chip returned no signature", Problems.detail(aa))
        assertEquals(
            Problem.READ_FAILED,
            Problems.ofEnrolment(ReadException.ProtocolError(ReadStep.READ_SOD, "wrong length", 0x6700)),
        )
    }

    @Test
    fun keyAndStorageFailuresAreCategorised() {
        assertEquals(Problem.SECURE_KEY_FAILED, Problems.ofEnrolment(ReadException.DeviceKeyFailed(KeystoreException("no TEE"))))
        assertEquals(Problem.SECURE_KEY_FAILED, Problems.ofEnrolment(KeystoreException("no attestation chain")))
        val store = EnrollmentStoreException("Enrollment file cannot be written", IOException("disk full"))
        assertEquals(Problem.SAVE_FAILED, Problems.ofEnrolment(store))
        assertEquals("Enrollment file cannot be written: disk full", Problems.detail(store))
    }

    @Test
    fun unknownExceptionsKeepTheirTypeInTheDetail() {
        val e = IllegalStateException("unexpected state")
        assertEquals(Problem.UNEXPECTED, Problems.ofEnrolment(e))
        assertEquals(Problem.UNEXPECTED, Problems.ofPresentation(e))
        assertEquals("IllegalStateException: unexpected state", Problems.detail(e))
    }

    @Test
    fun signingFailuresAreCategorised() {
        assertEquals(Problem.BIOMETRIC_CANCELLED, Problems.ofPresentation(SigningException.Cancelled(10)))
        assertEquals(Problem.BIOMETRIC_LOCKED, Problems.ofPresentation(SigningException.Lockout(permanent = false)))
        assertEquals(Problem.BIOMETRIC_LOCKED, Problems.ofPresentation(SigningException.Lockout(permanent = true)))
        assertEquals(Problem.BIOMETRIC_UNAVAILABLE, Problems.ofPresentation(SigningException.BiometricUnavailable(1, "hw")))
        assertEquals(Problem.KEY_INVALIDATED, Problems.ofPresentation(SigningException.KeyMissing()))
        assertEquals(Problem.KEY_INVALIDATED, Problems.ofPresentation(SigningException.KeyInvalidated(RuntimeException())))
        assertEquals(Problem.SIGNING_FAILED, Problems.ofPresentation(SigningException.Failed("Keystore refused the signature")))
    }

    @Test
    fun deliveryFailuresAreCategorised() {
        assertEquals(Problem.SESSION_EXPIRED, Problems.ofPresentation(DescriptorException("timestamp too old")))
        assertEquals(Problem.VERIFIER_UNREACHABLE, Problems.ofPresentation(TransportException.PeerUnavailable("peer-unavailable")))
        assertEquals(Problem.VERIFIER_UNREACHABLE, Problems.ofPresentation(TransportException.Connection("reset")))
        assertEquals(Problem.DELIVERY_TIMEOUT, Problems.ofPresentation(TransportException.Timeout("waiting for the result")))
        assertEquals(Problem.DELIVERY_FAILED, Problems.ofPresentation(TransportException.Http(500, "sending")))
        assertEquals(Problem.DELIVERY_FAILED, Problems.ofPresentation(TransportException.TooLarge(70_000, 65_536)))
        assertEquals(Problem.DELIVERY_FAILED, Problems.ofPresentation(HpkeException("invalid key")))
        val connection = TransportException.Connection("reset", IOException("socket closed"))
        assertEquals("Connection failed: reset: socket closed", Problems.detail(connection))
    }

    @Test
    fun readinessMapsToSpecificProblems() {
        assertEquals(emptyList<Problem>(), Problems.ofReadiness(Readiness(NfcAvailability.READY, BiometricReadiness.READY, true)))
        assertEquals(
            listOf(Problem.NFC_OFF, Problem.NO_STRONG_BIOMETRIC),
            Problems.ofReadiness(Readiness(NfcAvailability.DISABLED, BiometricReadiness.NONE_ENROLLED, true)),
        )
        assertEquals(
            listOf(Problem.NFC_MISSING, Problem.BIOMETRIC_UNAVAILABLE),
            Problems.ofReadiness(Readiness(NfcAvailability.NO_HARDWARE, BiometricReadiness.HW_UNAVAILABLE, false)),
        )
        BiometricReadiness.entries.filter { it != BiometricReadiness.READY && it != BiometricReadiness.NONE_ENROLLED }
            .forEach { assertEquals(Problem.BIOMETRIC_UNAVAILABLE, Problems.ofBiometric(it)) }
    }

    @Test
    fun keyDownloadFailuresAreCategorised() {
        val http = Problems.ofKeyDownload(KeyDownloadException.Http(404, "github.com"))
        assertEquals(Problem.KEY_DOWNLOAD_HTTP, http.problem)
        assertEquals(404L, http.number)
        assertEquals("HTTP 404 from github.com", http.detail)
        val space = Problems.ofKeyDownload(KeyDownloadException.InsufficientSpace(1_000, 310_463_742))
        assertEquals(Problem.KEY_DOWNLOAD_NO_SPACE, space.problem)
        assertEquals(311L, space.number)
        assertEquals(Problem.KEY_DOWNLOAD_NO_NETWORK, Problems.ofKeyDownload(KeyDownloadException.NoNetwork("unreachable")).problem)
        assertEquals(Problem.KEY_DOWNLOAD_NO_NETWORK, Problems.ofKeyDownload(KeyDownloadException.Interrupted("ended")).problem)
        assertEquals(Problem.KEY_DOWNLOAD_MISMATCH, Problems.ofKeyDownload(KeyDownloadException.Mismatch("sha")).problem)
        assertEquals(Problem.KEY_DOWNLOAD_FAILED, Problems.ofKeyDownload(KeyDownloadException.Storage("disk")).problem)
    }

    @Test
    fun everyProblemHasItsOwnTitle() {
        val titles = Problem.entries.map { it.titleRes() }
        assertEquals(titles.size, titles.toSet().size)
        assertTrue(titles.all { it != 0 })
    }

    @Test
    fun everyVerifierCheckHasATitle() {
        ResultFrame.CHECK_IDS.forEach { assertNotNull(checkTitleRes(it)) }
        assertEquals(null, checkTitleRes("unknown-check"))
        assertEquals(7, sharedDataCategories.toSet().size)
    }
}
