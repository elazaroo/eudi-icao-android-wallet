package dev.eudisovereign.icaowallet.data

import dev.eudisovereign.icaowallet.crypto.KeyStorage
import dev.eudisovereign.icaowallet.nfc.AccessKeyKind
import dev.eudisovereign.icaowallet.nfc.ChipAuthenticationDetails
import dev.eudisovereign.icaowallet.nfc.PaceDetails
import dev.eudisovereign.icaowallet.nfc.ReadStep
import dev.eudisovereign.icaowallet.nfc.SodSummary
import dev.eudisovereign.icaowallet.nfc.StepStatus
import dev.eudisovereign.icaowallet.nfc.TimedStep
import dev.eudisovereign.icaowallet.protocol.Binding
import javax.crypto.AEADBadTagException
import javax.crypto.KeyGenerator
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class EnrollmentTest {

    private fun sample(pace: PaceDetails = PaceDetails("0.4.0.127.0.7.2.2.4.2.2", "ECDH-GM AES-128", 13)) = Enrollment(
        cardAccess = byteArrayOf(0x31, 0x00),
        sod = byteArrayOf(0x77, 0x01, 0x00),
        dg1 = byteArrayOf(0x61, 0x00),
        dg14 = byteArrayOf(0x6E, 0x00),
        binding = Binding.CA_ATTESTATION,
        devicePublicKey = byteArrayOf(0x30, 0x59),
        keyAttestation = listOf(byteArrayOf(1), byteArrayOf(2, 3)),
        keyStorage = KeyStorage.STRONGBOX,
        chipAuthentication = ChipAuthenticationDetails(
            "0.4.0.127.0.7.2.2.3.2.2", "ECDH AES-128", false, "0.4.0.127.0.7.2.2.1.2", "1", "EC brainpoolP256r1",
        ),
        pace = pace,
        sodSummary = SodSummary("SHA-1", listOf(1, 14), "SHA-256", "SHA256withRSA", null, "CN=DS", "CN=CSCA", "1f", 1L, 2L),
        steps = listOf(TimedStep(ReadStep.PACE, StepStatus.DONE, 812, "ECDH-GM AES-128")),
        enrolledAtMillis = 1_763_000_000_000L,
        deviceModel = "Test Device",
        osVersion = "Android 16 (API 36)",
    )

    @Test
    fun jsonRoundTripKeepsBytesAndDetails() {
        val restored = Enrollment.fromJson(sample().toJson())
        assertArrayEquals(sample().sod, restored.sod)
        assertArrayEquals(sample().dg14, restored.dg14)
        assertNull(restored.dg15)
        assertNull(restored.aaResponse)
        assertEquals(2, restored.keyAttestation.size)
        assertArrayEquals(byteArrayOf(2, 3), restored.keyAttestation[1])
        assertEquals(Binding.CA_ATTESTATION, restored.binding)
        assertEquals(KeyStorage.STRONGBOX, restored.deviceInfo().keyStorage)
        assertEquals(13, restored.pace?.parameterId)
        assertEquals(ReadStep.PACE, restored.steps.single().step)
    }

    @Test
    fun bacEnrolmentWithoutCardAccessRoundTrips() {
        val bac = Enrollment(
            sod = byteArrayOf(0x77, 0x01, 0x00),
            dg1 = byteArrayOf(0x61, 0x00),
            dg15 = byteArrayOf(0x6F, 0x00),
            binding = Binding.AA,
            devicePublicKey = byteArrayOf(0x30, 0x59),
            aaResponse = byteArrayOf(1, 2),
            keyAttestation = emptyList(),
            keyStorage = KeyStorage.TEE,
            sodSummary = SodSummary("SHA-256", listOf(1, 15), null, null, null, null, null, null, null, null),
            steps = listOf(TimedStep(ReadStep.BAC, StepStatus.DONE, 300, "3DES secure messaging")),
            enrolledAtMillis = 1_763_000_000_000L,
            deviceModel = "Test Device",
            osVersion = "Android 16 (API 36)",
        )
        val json = bac.toJson()
        val restored = Enrollment.fromJson(json)
        assertNull(restored.cardAccess)
        assertNull(restored.pace)
        assertFalse(json.contains("cardAccess"))
        assertEquals(ReadStep.BAC, restored.steps.single().step)
    }

    @Test
    fun pacePasswordIsStoredAndOptional() {
        val mrzPace = PaceDetails("0.4.0.127.0.7.2.2.4.2.2", "ECDH-GM AES-128", 13, AccessKeyKind.MRZ)
        assertEquals(AccessKeyKind.MRZ, Enrollment.fromJson(sample(mrzPace).toJson()).pace?.password)
        assertNull(Enrollment.fromJson(sample().toJson()).pace?.password)
    }

    @Test
    fun sealedBlobRoundTripAndTamperDetection() {
        val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        val plaintext = sample().toJson().toByteArray()

        val blob = SealedBlob.seal(key, plaintext)
        assertEquals(12 + plaintext.size + 16, blob.size)
        assertArrayEquals(plaintext, SealedBlob.open(key, blob))

        val tampered = blob.copyOf().also { it[20] = (it[20].toInt() xor 1).toByte() }
        assertThrows(AEADBadTagException::class.java) { SealedBlob.open(key, tampered) }
        assertThrows(IllegalArgumentException::class.java) { SealedBlob.open(key, blob.copyOf(20)) }
    }
}
