package dev.eudisovereign.icaowallet.protocol

import dev.eudisovereign.icaowallet.TestKeys
import dev.eudisovereign.icaowallet.crypto.Codec
import dev.eudisovereign.icaowallet.crypto.Hpke
import dev.eudisovereign.icaowallet.ui.checkTitleRes
import dev.eudisovereign.icaowallet.zk.AgeStatement
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class AgeProofPresentationTest {

    private val field = "21888242871839275222246405745257275088548364400416034343698204186575808495616"
    private val proverProof = """{"pi_a":["1","2","1"],"pi_b":[["3","4"],["5","6"],["1","0"]],"pi_c":["7","$field","1"],""" +
        """"protocol":"groth16"}"""
    private val signals = (1..AgeStatement.PUBLIC_SIGNAL_COUNT).map { (it * 1000).toString() }
    private val certificate = ByteArray(40) { (it + 1).toByte() }

    @Test
    fun plaintextHasExactlyTheMembersOfSection82() {
        val json = AgeProofPresentation.build(certificate, Groth16Proof.parse(proverProof), signals).toJson()
        val obj = Json.parseToJsonElement(json).jsonObject
        assertEquals(listOf("v", "type", "dsCertificate", "proof", "publicSignals"), obj.keys.toList())
        assertEquals(1, obj.getValue("v").jsonPrimitive.int)
        assertEquals("age-at-least", obj.getValue("type").jsonPrimitive.content)
        assertArrayEquals(certificate, Codec.unb64(obj.getValue("dsCertificate").jsonPrimitive.content))
        assertEquals(signals, obj.getValue("publicSignals").jsonArray.map { it.jsonPrimitive.content })
        assertTrue(obj.getValue("publicSignals").jsonArray.all { (it as JsonPrimitive).isString })

        val proof = obj.getValue("proof").jsonObject
        assertEquals(listOf("pi_a", "pi_b", "pi_c", "protocol", "curve"), proof.keys.toList())
        assertEquals(listOf("1", "2", "1"), proof.getValue("pi_a").jsonArray.map { it.jsonPrimitive.content })
        assertEquals(
            listOf(listOf("3", "4"), listOf("5", "6"), listOf("1", "0")),
            proof.getValue("pi_b").jsonArray.map { pair -> pair.jsonArray.map { it.jsonPrimitive.content } },
        )
        assertEquals(listOf("7", field, "1"), proof.getValue("pi_c").jsonArray.map { it.jsonPrimitive.content })
        assertEquals("groth16", proof.getValue("protocol").jsonPrimitive.content)
        assertEquals("bn128", proof.getValue("curve").jsonPrimitive.content)
        listOf("dg1", "sod", "devicePublicKey", "keyAttestation", "deviceSignatureOverNonce", "nonce", "origin")
            .forEach { assertFalse(it, json.contains("\"$it\"")) }
    }

    @Test
    fun plaintextIsSealedLikeAPresentation() {
        val key = TestKeys.p256()
        val nonce = Codec.b64url(ByteArray(32) { it.toByte() })
        val descriptor = SessionDescriptor.parse(
            """{"v":1,"peerId":"p","nonce":"$nonce","timestamp":${System.currentTimeMillis()},""" +
                """"origin":"https://verifier.example","ek":"${Codec.b64url(key.publicPoint)}","request":"age-over-18"}""",
        )
        val plaintext = AgeProofPresentation.build(certificate, Groth16Proof.parse(proverProof), signals).toJson()
        val envelope = Json.parseToJsonElement(SealedEnvelope.seal(descriptor, plaintext)).jsonObject
        assertEquals("sealed", envelope.getValue("type").jsonPrimitive.content)
        val opened = Hpke.open(
            key.privateScalar,
            Codec.unb64(envelope.getValue("enc").jsonPrimitive.content),
            "eudi-icao-presentation-v1".toByteArray(),
            nonce.toByteArray(),
            Codec.unb64(envelope.getValue("ct").jsonPrimitive.content),
        )
        assertEquals(plaintext, opened.toString(Charsets.UTF_8))
    }

    @Test
    fun proverOutputIsValidated() {
        assertEquals("bn128", Groth16Proof.parse(proverProof.replace("}", ""","curve":"bn128"}""")).curve)
        assertThrows(ProofFormatException::class.java) { Groth16Proof.parse(proverProof.replace("groth16", "plonk")) }
        assertThrows(ProofFormatException::class.java) { Groth16Proof.parse(proverProof.replace("}", ""","curve":"bls12381"}""")) }
        assertThrows(ProofFormatException::class.java) { Groth16Proof.parse(proverProof.replace("[\"1\",\"0\"]", "[\"1\"]")) }
        assertThrows(ProofFormatException::class.java) { Groth16Proof.parse(proverProof.replace("\"7\"", "\"07\"")) }
        assertThrows(ProofFormatException::class.java) { Groth16Proof.parse(proverProof.replace("\"7\"", "7")) }
        assertThrows(ProofFormatException::class.java) { Groth16Proof.parse("not json") }

        val text = signals.joinToString(",", "[", "]") { "\"$it\"" }
        assertEquals(signals, Groth16Proof.parsePublicSignals(text))
        assertThrows(ProofFormatException::class.java) { Groth16Proof.parsePublicSignals(signals.drop(1).joinToString(",", "[", "]") { "\"$it\"" }) }
        assertThrows(IllegalArgumentException::class.java) {
            AgeProofPresentation.build(certificate, Groth16Proof.parse(proverProof), signals.drop(1))
        }
    }

    @Test
    fun resultFrameCarriesTheThreeAgeChecks() {
        val passing = ResultFrame.decode(
            """{"t":"result","ok":true,"checks":[{"id":"document-signer","status":"pass"},""" +
                """{"id":"public-statement","status":"pass"},{"id":"zero-knowledge-proof","status":"pass"}]}""",
        )!!
        assertEquals(listOf("document-signer", "public-statement", "zero-knowledge-proof"), AgeProofChecks.IDS)
        assertEquals(AgeProofChecks.IDS, passing.checks.map { it.id })
        assertTrue(passing.ok)
        assertTrue(AgeProofChecks.allPass(passing))

        val failing = ResultFrame.decode(
            """{"t":"result","ok":false,"checks":[{"id":"document-signer","status":"pass"},""" +
                """{"id":"public-statement","status":"fail"},{"id":"zero-knowledge-proof","status":"skipped"}]}""",
        )!!
        assertFalse(AgeProofChecks.allPass(failing))
        assertEquals(listOf("pass", "fail", "skipped"), failing.checks.map { it.status })
        AgeProofChecks.IDS.forEach { assertNotNull(it, checkTitleRes(it)) }
    }
}
