package dev.eudisovereign.icaowallet.protocol

import dev.eudisovereign.icaowallet.crypto.Codec
import dev.eudisovereign.icaowallet.zk.AgeStatement
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class ProofFormatException(message: String, cause: Throwable? = null) : Exception(message, cause)

/** Groth16 proof as snarkjs prints it (spec 8.2). */
@Serializable
class Groth16Proof(
    @SerialName("pi_a") val piA: List<String>,
    @SerialName("pi_b") val piB: List<List<String>>,
    @SerialName("pi_c") val piC: List<String>,
    val protocol: String,
    val curve: String,
) {
    companion object {
        const val PROTOCOL = "groth16"
        const val CURVE = "bn128"

        private val DECIMAL = Regex("^(0|[1-9][0-9]{0,77})$")

        /** Reads the proof JSON of the prover and normalises it to the snarkjs shape. */
        fun parse(text: String): Groth16Proof {
            val obj = parseJson(text) as? JsonObject ?: throw ProofFormatException("proof is not a JSON object")
            (obj["protocol"] as? JsonPrimitive)?.let {
                if (!it.isString || it.content != PROTOCOL) throw ProofFormatException("proof protocol is ${it.content}, expected $PROTOCOL")
            }
            (obj["curve"] as? JsonPrimitive)?.let {
                if (!it.isString || it.content != CURVE) throw ProofFormatException("proof curve is ${it.content}, expected $CURVE")
            }
            val piB = obj["pi_b"] as? JsonArray
            if (piB == null || piB.size != 3) throw ProofFormatException("pi_b must hold three pairs")
            return Groth16Proof(
                piA = decimals(obj["pi_a"], 3, "pi_a"),
                piB = piB.mapIndexed { index, pair -> decimals(pair, 2, "pi_b[$index]") },
                piC = decimals(obj["pi_c"], 3, "pi_c"),
                protocol = PROTOCOL,
                curve = CURVE,
            )
        }

        fun parsePublicSignals(text: String): List<String> =
            decimals(parseJson(text), AgeStatement.PUBLIC_SIGNAL_COUNT, "publicSignals")

        private fun parseJson(text: String): JsonElement = try {
            protocolJson.parseToJsonElement(text)
        } catch (e: SerializationException) {
            throw ProofFormatException("prover output is not JSON", e)
        }

        internal fun decimals(value: JsonElement?, length: Int, what: String): List<String> {
            val items = (value as? JsonArray)?.map { (it as? JsonPrimitive)?.takeIf(JsonPrimitive::isString)?.content }
            if (items == null || items.size != length || items.any { it == null || !DECIMAL.matches(it) }) {
                throw ProofFormatException("$what must be an array of $length decimal strings")
            }
            return items.map { it!! }
        }
    }
}

/** Spec 8.2: the plaintext of an age-over-18 session; nothing from EF.DG1, EF.SOD or the device key. */
@Serializable
class AgeProofPresentation private constructor(
    val v: Int,
    val type: String,
    val dsCertificate: String,
    val proof: Groth16Proof,
    val publicSignals: List<String>,
) {
    fun toJson(): String = protocolJson.encodeToString(serializer(), this)

    companion object {
        const val VERSION = 1
        const val TYPE = "age-at-least"

        fun build(dsCertificate: ByteArray, proof: Groth16Proof, publicSignals: List<String>): AgeProofPresentation {
            require(dsCertificate.isNotEmpty()) { "The Document Signer certificate is required" }
            require(publicSignals.size == AgeStatement.PUBLIC_SIGNAL_COUNT) {
                "Expected ${AgeStatement.PUBLIC_SIGNAL_COUNT} public signals, got ${publicSignals.size}"
            }
            require(proof.protocol == Groth16Proof.PROTOCOL && proof.curve == Groth16Proof.CURVE) {
                "The proof must be Groth16 on bn128"
            }
            return AgeProofPresentation(VERSION, TYPE, Codec.b64(dsCertificate), proof, publicSignals)
        }
    }
}

/** Spec 8.4: check identifiers of the result frame of an age-over-18 session, in order. */
object AgeProofChecks {
    const val DOCUMENT_SIGNER = "document-signer"
    const val PUBLIC_STATEMENT = "public-statement"
    const val ZERO_KNOWLEDGE_PROOF = "zero-knowledge-proof"
    val IDS = listOf(DOCUMENT_SIGNER, PUBLIC_STATEMENT, ZERO_KNOWLEDGE_PROOF)

    fun allPass(frame: ResultFrame): Boolean = IDS.all { id -> frame.checks.any { it.id == id && it.passed } }
}
