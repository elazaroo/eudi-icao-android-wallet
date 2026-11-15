package dev.eudisovereign.icaowallet.zk

import dev.eudisovereign.icaowallet.crypto.Codec
import java.io.File
import java.math.BigInteger
import java.time.Instant
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

class AgeProofInputsTest {

    private class Vector(val json: JsonObject) {
        val profile = json.getValue("profile").jsonPrimitive.content
        val dg1 = Codec.unb64(json.getValue("dg1").jsonPrimitive.content)
        val sod = Codec.unb64(json.getValue("sod").jsonPrimitive.content)
        val nonce = json.getValue("nonce").jsonPrimitive.content
        val origin = json.getValue("origin").jsonPrimitive.content
        val now = json.getValue("now").jsonPrimitive.content
        val currentDate = json.getValue("currentDate").jsonPrimitive.int
        val ageThreshold = json.getValue("ageThreshold").jsonPrimitive.int
        val challenge = BigInteger(json.getValue("challenge").jsonPrimitive.content)
        val dsCertificate = Codec.unb64(json.getValue("dsCertificate").jsonPrimitive.content)
        val inputs = json.getValue("inputs").jsonObject
        val publicSignals = json.getValue("publicSignals").jsonArray.map { it.jsonPrimitive.content }

        fun statement() = AgeProofStatement(currentDate, ageThreshold, challenge)
        fun strings(name: String): List<String> = inputs.getValue(name).jsonArray.map { it.jsonPrimitive.content }
        fun string(name: String): String = inputs.getValue(name).jsonPrimitive.content
    }

    private val vectors: List<Vector> by lazy {
        val text = javaClass.getResourceAsStream("/zk/age-proof-vectors.json")!!.use { it.readBytes().toString(Charsets.UTF_8) }
        Json.parseToJsonElement(text).jsonObject.getValue("vectors").jsonArray.map { Vector(it.jsonObject) }
    }

    private fun vector(profile: String) = vectors.single { it.profile == profile }

    @Test
    fun vectorsCoverBothProfiles() {
        assertEquals(setOf("dnie-td1", "passport-td3"), vectors.map { it.profile }.toSet())
    }

    @Test
    fun dnieTd1MatchesTheVectorInEveryField() = assertMatches(vector("dnie-td1"), MrzProfile.TD1)

    @Test
    fun passportTd3MatchesTheVectorInEveryField() = assertMatches(vector("passport-td3"), MrzProfile.TD3)

    private fun assertMatches(vector: Vector, profile: MrzProfile) {
        val prepared = prepareAgeProofInputs(vector.dg1, vector.sod, vector.statement())
        val inputs = prepared.inputs
        val label = vector.profile
        assertEquals(label, profile, prepared.profile)
        assertEquals(label, vector.strings("signedAttrs"), inputs.signedAttrs)
        assertEquals(label, vector.string("signedAttrsLength"), inputs.signedAttrsLength)
        assertEquals(label, vector.string("contentTypeOffset"), inputs.contentTypeOffset)
        assertEquals(label, vector.string("messageDigestOffset"), inputs.messageDigestOffset)
        assertEquals(label, vector.strings("eContent"), inputs.eContent)
        assertEquals(label, vector.string("eContentLength"), inputs.eContentLength)
        assertEquals(label, vector.strings("dg1"), inputs.dg1)
        assertEquals(label, vector.strings("signature"), inputs.signature)
        assertEquals(label, vector.strings("modulus"), inputs.modulus)
        assertEquals(label, vector.string("currentDate"), inputs.currentDate)
        assertEquals(label, vector.string("ageThreshold"), inputs.ageThreshold)
        assertEquals(label, vector.string("challenge"), inputs.challenge)
        assertEquals(label, vector.inputs, Json.parseToJsonElement(inputs.toJson()).jsonObject)
        assertArrayEquals(label, vector.dsCertificate, prepared.dsCertificate)
        assertEquals(
            label,
            vector.publicSignals,
            AgeStatement.publicSignals(prepared.modulus, vector.currentDate, vector.ageThreshold, vector.challenge),
        )
        assertEquals(label, AgeStatement.PUBLIC_SIGNAL_COUNT, vector.publicSignals.size)
    }

    @Test
    fun challengeAndDateDeriveFromTheSessionOfEachVector() {
        vectors.forEach { vector ->
            assertEquals(vector.profile, vector.challenge, AgeStatement.challenge(vector.nonce, vector.origin))
            assertEquals(vector.profile, vector.currentDate, AgeStatement.dateNumber(Instant.parse(vector.now).toEpochMilli()))
            assertEquals(vector.profile, AgeStatement.AGE_THRESHOLD, vector.ageThreshold)
        }
    }

    @Test
    fun paddedArraysKeepTheMessageAndItsLength() {
        val vector = vector("dnie-td1")
        val inputs = prepareAgeProofInputs(vector.dg1, vector.sod, vector.statement()).inputs
        assertEquals(AgeStatement.SIGNED_ATTRS_BLOCKS * 64, inputs.signedAttrs.size)
        assertEquals(AgeStatement.ECONTENT_BLOCKS * 64, inputs.eContent.size)
        assertEquals(AgeStatement.DG1_BLOCKS * 64, inputs.dg1.size)
        assertEquals(vector.dg1.map { (it.toInt() and 0xFF).toString() }, inputs.dg1.take(vector.dg1.size))
        assertEquals("49", inputs.signedAttrs[0])
        assertEquals("128", inputs.dg1[vector.dg1.size])
    }

    @Test
    fun shaPadFollowsFips180() {
        val padded = shaPad(ByteArray(55), 2)
        assertEquals(128, padded.size)
        assertEquals(0x80, padded[55].toInt() and 0xFF)
        assertEquals(55 * 8 - 256, padded[63].toInt() and 0xFF)
        assertEquals(1, padded[62].toInt())
        assertTrue(padded.copyOfRange(64, 128).all { it == 0.toByte() })
        val two = shaPad(ByteArray(56), 2)
        assertEquals(0x80, two[56].toInt() and 0xFF)
        assertTrue(two.copyOfRange(57, 126).all { it == 0.toByte() })
        assertEquals(listOf(0x01, 0xc0), listOf(two[126].toInt() and 0xFF, two[127].toInt() and 0xFF))
        val e = assertThrows(AgeProofInputException::class.java) { shaPad(ByteArray(120), 2) }
        assertTrue(e.message!!, e.message!!.contains("3 SHA blocks"))
    }

    @Test
    fun refusesDocumentsOutsideTheStatement() {
        val vector = vector("dnie-td1")
        expectFailure("neither a 95-byte TD1") { prepareAgeProofInputs(vector.dg1.copyOf(90), vector.sod, vector.statement()) }
        expectFailure("field element") {
            prepareAgeProofInputs(vector.dg1, vector.sod, AgeProofStatement(vector.currentDate, 18, BigInteger.ONE.negate()))
        }
        expectFailure("field element") {
            prepareAgeProofInputs(vector.dg1, vector.sod, AgeProofStatement(vector.currentDate, 18, AgeStatement.FIELD_ORDER))
        }
        val sha1 = Codec.unhex("06052b0e03021a")
        val otherHash = vector.sod.copyOf().also { it[indexOf(it, sha1) + sha1.size - 1] = 0x1b }
        expectFailure("SHA-1 data group hashes") { prepareAgeProofInputs(vector.dg1, otherHash, vector.statement()) }

        val rsaFamily = Codec.unhex("06092a864886f70d0101")
        val signerAlgorithm = lastIndexOf(vector.sod, rsaFamily) + rsaFamily.size
        val sha384 = vector.sod.copyOf().also { it[signerAlgorithm] = 0x0c }
        expectFailure("RSASSA-PKCS1-v1_5 with SHA-256") { prepareAgeProofInputs(vector.dg1, sha384, vector.statement()) }

        val wrongTag = vector.sod.copyOf().also { it[0] = 0x30 }
        expectFailure("EF.SOD must start with tag 0x77") { prepareAgeProofInputs(vector.dg1, wrongTag, vector.statement()) }
        expectFailure("trailing bytes") { prepareAgeProofInputs(vector.dg1, vector.sod + 0.toByte(), vector.statement()) }
    }

    @Test
    fun specimenEContentHasTheLayoutTheCircuitAccepts() {
        val specimen = File("src/test/resources/external/SOD_ESPECIMEN.der")
        assumeTrue("specimen not reachable from the test working directory", specimen.isFile)
        val sod = AgeProofSodParser.parse(specimen.readBytes())
        assertEquals(209, sod.eContent.size)
        assertEquals(HashParameters.NULL, eContentLayout(sod.eContent))
        assertTrue((sod.eContent.size + 8) / 64 + 1 <= AgeStatement.ECONTENT_BLOCKS)
        assertTrue((sod.signedAttrs!!.size + 8) / 64 + 1 <= AgeStatement.SIGNED_ATTRS_BLOCKS)
        assertTrue(sod.dsCertificateIssue, sod.dsCertificate != null)
    }

    private fun expectFailure(fragment: String, block: () -> Unit) {
        val e = assertThrows(AgeProofInputException::class.java) { block() }
        assertTrue("\"${e.message}\" lacks \"$fragment\"", e.message!!.contains(fragment))
    }

    private fun indexOf(haystack: ByteArray, needle: ByteArray): Int = AgeProofSodParser.indexOf(haystack, needle).also {
        check(it >= 0) { "pattern not found" }
    }

    private fun lastIndexOf(haystack: ByteArray, needle: ByteArray): Int =
        (haystack.size - needle.size downTo 0).first { offset -> needle.indices.all { haystack[offset + it] == needle[it] } }
}
