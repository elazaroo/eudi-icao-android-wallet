package dev.eudisovereign.icaowallet.protocol

import dev.eudisovereign.icaowallet.TestKeys
import dev.eudisovereign.icaowallet.crypto.Codec
import dev.eudisovereign.icaowallet.crypto.Hpke
import dev.eudisovereign.icaowallet.crypto.KeyStorage
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class PresentationTest {

    private val abc = "abc".toByteArray(Charsets.US_ASCII)

    // FIPS 180-2 Appendix B.1: SHA-256("abc")
    private val sha256Abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

    @Test
    fun derivedValuesMatchIndependentComputation() {
        assertEquals("ba7816bf8f01cfea", Codec.hex(Derivation.aaChallenge(abc)))
        assertEquals(sha256Abc, Codec.hex(Derivation.attestationChallenge(abc)))
        val expectedTranscript = "657564692d6963616f2d617574682d7631" + "0a" + "41414141" + "0a" +
            "68747470733a2f2f612e62"
        assertEquals(expectedTranscript, Codec.hex(Derivation.transcript("AAAA", "https://a.b")))
    }

    private fun presentation(binding: Binding): JsonObject {
        val built = when (binding) {
            Binding.AA -> Presentation.build(
                nonce = "N", origin = "https://v.example", dg1 = byteArrayOf(1), dg14 = null, dg15 = byteArrayOf(15),
                sod = byteArrayOf(0x77), devicePublicKey = byteArrayOf(9), binding = Binding.AA,
                chipSignatureOverDeviceKey = byteArrayOf(5, 5), keyAttestation = emptyList(),
                deviceSignatureOverNonce = byteArrayOf(0x30), device = null,
            )
            Binding.CA_ATTESTATION -> Presentation.build(
                nonce = "N", origin = "https://v.example", dg1 = byteArrayOf(1), dg14 = byteArrayOf(14), dg15 = null,
                sod = byteArrayOf(0x77), devicePublicKey = byteArrayOf(9), binding = Binding.CA_ATTESTATION,
                chipSignatureOverDeviceKey = null, keyAttestation = listOf(byteArrayOf(1, 2), byteArrayOf(3)),
                deviceSignatureOverNonce = byteArrayOf(0x30), device = DeviceInfo("Pixel 9", "Android 16", KeyStorage.TEE),
            )
        }
        return Json.parseToJsonElement(built.toJson()).jsonObject
    }

    @Test
    fun aaPresentationHasExactlyTheSpecifiedMembers() {
        val json = presentation(Binding.AA)
        assertEquals(
            listOf("v", "nonce", "origin", "dg1", "dg15", "sod", "devicePublicKey", "binding",
                "chipSignatureOverDeviceKey", "deviceSignatureOverNonce"),
            json.keys.toList(),
        )
        assertEquals(1, json.getValue("v").jsonPrimitive.int)
        assertEquals("aa", json.getValue("binding").jsonPrimitive.content)
        assertEquals(Codec.b64(byteArrayOf(5, 5)), json.getValue("chipSignatureOverDeviceKey").jsonPrimitive.content)
        assertEquals("dw==", json.getValue("sod").jsonPrimitive.content)
    }

    @Test
    fun caAttestationPresentationHasExactlyTheSpecifiedMembers() {
        val json = presentation(Binding.CA_ATTESTATION)
        assertEquals(
            listOf("v", "nonce", "origin", "dg1", "dg14", "sod", "devicePublicKey", "binding", "keyAttestation",
                "deviceSignatureOverNonce", "device"),
            json.keys.toList(),
        )
        assertEquals("ca-attestation", json.getValue("binding").jsonPrimitive.content)
        assertEquals(listOf("AQI=", "Aw=="), json.getValue("keyAttestation").jsonArray.map { it.jsonPrimitive.content })
        val device = json.getValue("device").jsonObject
        assertEquals(listOf("model", "os", "keyStorage"), device.keys.toList())
        assertEquals("tee", device.getValue("keyStorage").jsonPrimitive.content)
    }

    @Test
    fun presenceRulesAreEnforced() {
        assertThrows(IllegalArgumentException::class.java) {
            Presentation.build("N", "https://v", byteArrayOf(1), null, byteArrayOf(15), byteArrayOf(0x77), byteArrayOf(9),
                Binding.AA, null, emptyList(), byteArrayOf(0x30), null)
        }
        assertThrows(IllegalArgumentException::class.java) {
            Presentation.build("N", "https://v", byteArrayOf(1), byteArrayOf(14), null, byteArrayOf(0x77), byteArrayOf(9),
                Binding.CA_ATTESTATION, null, emptyList(), byteArrayOf(0x30), null)
        }
        assertThrows(IllegalArgumentException::class.java) {
            Presentation.build("N", "https://v", byteArrayOf(1), byteArrayOf(14), null, byteArrayOf(0x77), byteArrayOf(9),
                Binding.CA_ATTESTATION, byteArrayOf(1), listOf(byteArrayOf(1)), byteArrayOf(0x30), null)
        }
        assertThrows(IllegalArgumentException::class.java) {
            Presentation.build("N", "https://v", byteArrayOf(1), null, null, byteArrayOf(0x77), byteArrayOf(9),
                Binding.CA_ATTESTATION, null, listOf(byteArrayOf(1)), byteArrayOf(0x30), null)
        }
    }

    private fun dg1(mrz: String): ByteArray {
        val value = mrz.toByteArray(Charsets.US_ASCII)
        val inner = byteArrayOf(0x5F, 0x1F, value.size.toByte()) + value
        return byteArrayOf(0x61, inner.size.toByte()) + inner
    }

    private val td1 = "IDESPBAA000589599999999D<<<<<<" + "8001014F3106028ESP<<<<<<<<<<<1" + "ESPANOLA<ESPANOLA<<CARMEN<<<<<"
    private val td3 = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<" + "L898902C36UTO7408122F1204159ZE184226B<<<<<10"

    @Test
    fun tamperDg1ChangesExactlyOneMrzByte() {
        for ((mrz, offset) in listOf(td1 to 5, td3 to 44)) {
            val original = dg1(mrz)
            val tampered = tamperDg1(original)
            assertEquals(original.size, tampered.size)
            val diffs = original.indices.filter { original[it] != tampered[it] }
            assertEquals(1, diffs.size)
            val headerLength = original.size - mrz.length
            assertEquals(headerLength + offset, diffs.single())
            assertArrayEquals(original.copyOf(headerLength), tampered.copyOf(headerLength))
            val changed = tampered[diffs.single()].toInt().toChar()
            assertTrue(changed in 'A'..'Z' || changed in '0'..'9' || changed == '<')
            assertEquals(mrz.length, mrzOf(tampered).length)
            assertEquals(mrz, mrzOf(original))
        }
    }

    @Test
    fun tamperDg1RejectsMalformedInput() {
        assertThrows(IllegalArgumentException::class.java) { tamperDg1(byteArrayOf(0x61, 0x01, 0x00)) }
        assertThrows(IllegalArgumentException::class.java) { tamperDg1(dg1("SHORT")) }
        assertThrows(IllegalArgumentException::class.java) { tamperDg1(dg1(td1).copyOf(50)) }
    }

    @Test
    fun partFramingSplitsAndReassembles() {
        val envelope = buildString { repeat(20_001) { append(('a' + it % 26)) } }
        val frames = PartFrame.split(envelope)
        assertEquals(3, frames.size)
        assertTrue(frames[0].startsWith("""{"t":"part","i":0,"n":3,"d":""""))
        val parsed = frames.map { Json.parseToJsonElement(it).jsonObject }
        parsed.forEachIndexed { index, frame ->
            assertEquals("part", frame.getValue("t").jsonPrimitive.content)
            assertEquals(index, frame.getValue("i").jsonPrimitive.int)
            assertEquals(3, frame.getValue("n").jsonPrimitive.int)
            assertTrue(frame.getValue("d").jsonPrimitive.content.length <= PartFrame.MAX_PART_CHARS)
        }
        val reassembled = parsed.shuffled().sortedBy { it.getValue("i").jsonPrimitive.int }
            .joinToString("") { it.getValue("d").jsonPrimitive.content }
        assertEquals(envelope, reassembled)
        assertEquals(1, PartFrame.split("{}").size)
    }

    @Test
    fun resultFrameParsing() {
        val frame = ResultFrame.decode(
            """{"t":"result","ok":false,"checks":[{"id":"passive-authentication","status":"pass"},""" +
                """{"id":"data-integrity","status":"fail"},{"id":"chip-binding","status":"skipped"},""" +
                """{"id":"nonce-proof","status":"pass"}],"extra":1}""",
        )
        assertNotNull(frame)
        frame!!
        assertFalse(frame.ok)
        assertEquals(ResultFrame.CHECK_IDS, frame.checks.map { it.id })
        assertEquals(listOf(true, false, false, true), frame.checks.map { it.passed })

        assertNull(ResultFrame.decode("""{"t":"part","i":0,"n":1,"d":"x"}"""))
        assertThrows(FrameException::class.java) { ResultFrame.decode("""{"t":"result","checks":[]}""") }
        assertThrows(FrameException::class.java) {
            ResultFrame.decode("""{"t":"result","ok":true,"checks":[{"id":"nonce-proof","status":"maybe"}]}""")
        }
        assertThrows(FrameException::class.java) { ResultFrame.decode("[1,2]") }
        assertThrows(FrameException::class.java) { ResultFrame.decode("{oops") }
    }

    @Test
    fun sealedEnvelopeOpensWithVerifierKey() {
        val key = TestKeys.p256()
        val nonce = Codec.b64url(ByteArray(32) { 3 })
        val descriptor = SessionDescriptor.parse(
            """{"v":1,"peerId":"p","nonce":"$nonce","timestamp":1000,"origin":"https://v.example",""" +
                """"ek":"${Codec.b64url(key.publicPoint)}"}""",
            1000,
        )
        val presentationJson = presentation(Binding.AA).toString()

        val envelope = Json.parseToJsonElement(SealedEnvelope.seal(descriptor, presentationJson)).jsonObject

        assertEquals(listOf("v", "type", "enc", "ct"), envelope.keys.toList())
        assertEquals(1, envelope.getValue("v").jsonPrimitive.int)
        assertEquals("sealed", envelope.getValue("type").jsonPrimitive.content)
        val enc = Codec.unb64(envelope.getValue("enc").jsonPrimitive.content)
        val ct = Codec.unb64(envelope.getValue("ct").jsonPrimitive.content)
        assertEquals(65, enc.size)
        val opened = Hpke.open(
            key.privateScalar, enc, "eudi-icao-presentation-v1".toByteArray(), nonce.toByteArray(), ct,
        )
        assertEquals(presentationJson, opened.toString(Charsets.UTF_8))
    }
}
