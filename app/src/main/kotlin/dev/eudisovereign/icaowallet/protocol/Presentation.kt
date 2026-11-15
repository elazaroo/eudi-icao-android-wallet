package dev.eudisovereign.icaowallet.protocol

import dev.eudisovereign.icaowallet.crypto.Codec
import dev.eudisovereign.icaowallet.crypto.Hpke
import dev.eudisovereign.icaowallet.crypto.KeyStorage
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

internal val protocolJson = Json {
    encodeDefaults = true
    explicitNulls = false
    ignoreUnknownKeys = true
}

@Serializable
enum class Binding {
    @SerialName("aa") AA,
    @SerialName("ca-attestation") CA_ATTESTATION,
}

object Derivation {
    private const val TRANSCRIPT_LABEL = "eudi-icao-auth-v1"

    fun aaChallenge(devicePublicKeySpki: ByteArray): ByteArray = Codec.sha256(devicePublicKeySpki).copyOf(8)

    fun attestationChallenge(sodBytes: ByteArray): ByteArray = Codec.sha256(sodBytes)

    fun transcript(nonce: String, origin: String): ByteArray =
        "$TRANSCRIPT_LABEL\n$nonce\n$origin".toByteArray(Charsets.UTF_8)
}

@Serializable
class DeviceInfo(val model: String, val os: String, val keyStorage: KeyStorage)

@Serializable
class Presentation private constructor(
    val v: Int,
    val nonce: String,
    val origin: String,
    val dg1: String,
    val dg14: String? = null,
    val dg15: String? = null,
    val sod: String,
    val devicePublicKey: String,
    val binding: Binding,
    val chipSignatureOverDeviceKey: String? = null,
    val keyAttestation: List<String>? = null,
    val deviceSignatureOverNonce: String,
    val device: DeviceInfo? = null,
) {
    fun toJson(): String = protocolJson.encodeToString(serializer(), this)

    companion object {
        const val VERSION = 1

        fun build(
            nonce: String,
            origin: String,
            dg1: ByteArray,
            dg14: ByteArray?,
            dg15: ByteArray?,
            sod: ByteArray,
            devicePublicKey: ByteArray,
            binding: Binding,
            chipSignatureOverDeviceKey: ByteArray?,
            keyAttestation: List<ByteArray>,
            deviceSignatureOverNonce: ByteArray,
            device: DeviceInfo?,
        ): Presentation {
            require(dg1.isNotEmpty() && sod.isNotEmpty()) { "EF.DG1 and EF.SOD are required" }
            require(devicePublicKey.isNotEmpty()) { "Device public key is required" }
            require(deviceSignatureOverNonce.isNotEmpty()) { "Device signature over the transcript is required" }
            when (binding) {
                Binding.AA -> {
                    require(dg15 != null) { "Binding aa requires EF.DG15" }
                    require(chipSignatureOverDeviceKey != null && chipSignatureOverDeviceKey.isNotEmpty()) {
                        "Binding aa requires the INTERNAL AUTHENTICATE response"
                    }
                }
                Binding.CA_ATTESTATION -> {
                    require(dg14 != null) { "Binding ca-attestation requires EF.DG14" }
                    require(keyAttestation.isNotEmpty()) { "Binding ca-attestation requires a key attestation chain" }
                    require(chipSignatureOverDeviceKey == null) {
                        "chipSignatureOverDeviceKey is only sent with binding aa"
                    }
                }
            }
            return Presentation(
                v = VERSION,
                nonce = nonce,
                origin = origin,
                dg1 = Codec.b64(dg1),
                dg14 = dg14?.let(Codec::b64),
                dg15 = dg15?.let(Codec::b64),
                sod = Codec.b64(sod),
                devicePublicKey = Codec.b64(devicePublicKey),
                binding = binding,
                chipSignatureOverDeviceKey = chipSignatureOverDeviceKey?.let(Codec::b64),
                keyAttestation = keyAttestation.takeIf { it.isNotEmpty() }?.map(Codec::b64),
                deviceSignatureOverNonce = Codec.b64(deviceSignatureOverNonce),
                device = device,
            )
        }
    }
}

@Serializable
class SealedEnvelope(val v: Int, val type: String, val enc: String, val ct: String) {
    companion object {
        const val TYPE = "sealed"
        const val HPKE_INFO = "eudi-icao-presentation-v1"

        fun seal(descriptor: SessionDescriptor, presentationJson: String): String {
            val sealed = Hpke.seal(
                recipientPublicKey65 = descriptor.ek,
                info = HPKE_INFO.toByteArray(Charsets.UTF_8),
                aad = descriptor.nonce.toByteArray(Charsets.UTF_8),
                plaintext = presentationJson.toByteArray(Charsets.UTF_8),
            )
            val envelope = SealedEnvelope(Presentation.VERSION, TYPE, Codec.b64(sealed.enc), Codec.b64(sealed.ct))
            return protocolJson.encodeToString(serializer(), envelope)
        }
    }
}

@Serializable
class PartFrame(val t: String, val i: Int, val n: Int, val d: String) {
    companion object {
        const val TYPE = "part"
        const val MAX_PART_CHARS = 8000

        fun split(envelopeJson: String, maxChars: Int = MAX_PART_CHARS): List<String> {
            require(envelopeJson.isNotEmpty()) { "Envelope is empty" }
            require(maxChars > 0) { "Part size must be positive" }
            val chunks = envelopeJson.chunked(maxChars)
            return chunks.mapIndexed { index, chunk ->
                protocolJson.encodeToString(serializer(), PartFrame(TYPE, index, chunks.size, chunk))
            }
        }
    }
}

class FrameException(message: String, cause: Throwable? = null) : Exception(message, cause)

@Serializable
class CheckResult(val id: String, val status: String) {
    val passed: Boolean get() = status == STATUS_PASS

    companion object {
        const val STATUS_PASS = "pass"
        const val STATUS_FAIL = "fail"
        const val STATUS_SKIPPED = "skipped"
        val STATUSES = setOf(STATUS_PASS, STATUS_FAIL, STATUS_SKIPPED)
    }
}

@Serializable
class ResultFrame(val t: String, val ok: Boolean, val checks: List<CheckResult>) {
    companion object {
        const val TYPE = "result"
        val CHECK_IDS = listOf("passive-authentication", "data-integrity", "chip-binding", "nonce-proof")

        /** Returns null for a well-formed frame of another type. */
        fun decode(text: String): ResultFrame? {
            val element = try {
                protocolJson.parseToJsonElement(text)
            } catch (e: SerializationException) {
                throw FrameException("Frame is not JSON", e)
            }
            val obj = element as? JsonObject ?: throw FrameException("Frame is not a JSON object")
            val type = (obj["t"] as? JsonPrimitive)?.takeIf { it.isString }?.content
            if (type != TYPE) return null
            val frame = try {
                protocolJson.decodeFromJsonElement(serializer(), obj)
            } catch (e: SerializationException) {
                throw FrameException("Malformed result frame: ${e.message}", e)
            } catch (e: IllegalArgumentException) {
                throw FrameException("Malformed result frame: ${e.message}", e)
            }
            frame.checks.firstOrNull { it.status !in CheckResult.STATUSES }?.let {
                throw FrameException("Unknown check status \"${it.status}\" for ${it.id}")
            }
            return frame
        }
    }
}

private const val TAG_DG1 = 0x61
private const val MRZ_ALPHABET_ERROR = "MRZ contains a character outside A-Z, 0-9 and <"

private class TlvValue(val offset: Int, val length: Int)

private fun readLength(bytes: ByteArray, offset: Int): Pair<Int, Int> {
    require(offset < bytes.size) { "Truncated TLV length" }
    val first = bytes[offset].toInt() and 0xFF
    return when {
        first < 0x80 -> first to offset + 1
        first == 0x81 -> {
            require(offset + 1 < bytes.size) { "Truncated TLV length" }
            (bytes[offset + 1].toInt() and 0xFF) to offset + 2
        }
        first == 0x82 -> {
            require(offset + 2 < bytes.size) { "Truncated TLV length" }
            (((bytes[offset + 1].toInt() and 0xFF) shl 8) or (bytes[offset + 2].toInt() and 0xFF)) to offset + 3
        }
        else -> throw IllegalArgumentException("Unsupported TLV length encoding")
    }
}

// ICAO 9303-10 4.7.1: EF.DG1 = '61' L ( '5F1F' L MRZ )
private fun locateMrz(dg1: ByteArray): TlvValue {
    require(dg1.isNotEmpty() && (dg1[0].toInt() and 0xFF) == TAG_DG1) { "EF.DG1 does not start with tag 61" }
    val (outerLength, inner) = readLength(dg1, 1)
    require(inner + outerLength == dg1.size) { "EF.DG1 length does not match its TLV header" }
    require(inner + 1 < dg1.size && dg1[inner] == 0x5F.toByte() && dg1[inner + 1] == 0x1F.toByte()) {
        "EF.DG1 does not contain tag 5F1F"
    }
    val (mrzLength, valueOffset) = readLength(dg1, inner + 2)
    require(valueOffset + mrzLength <= dg1.size) { "MRZ value exceeds EF.DG1" }
    return TlvValue(valueOffset, mrzLength)
}

fun mrzOf(dg1: ByteArray): String {
    val mrz = locateMrz(dg1)
    return String(dg1, mrz.offset, mrz.length, Charsets.US_ASCII)
}

// ICAO 9303-5 (TD1), 9303-6 (TD2), 9303-4 (TD3): the document number starts at MRZ offset 5, 36 or 44.
internal fun documentNumberOffset(mrzLength: Int): Int = when (mrzLength) {
    90 -> 5
    72 -> 36
    88 -> 44
    else -> throw IllegalArgumentException("MRZ length $mrzLength is not TD1, TD2 or TD3")
}

internal fun nextMrzCharacter(c: Char): Char = when (c) {
    in '0'..'8', in 'A'..'Y' -> c + 1
    '9' -> '0'
    'Z' -> 'A'
    '<' -> '0'
    else -> throw IllegalArgumentException(MRZ_ALPHABET_ERROR)
}

/**
 * Changes the first character of the document number to another legal MRZ character. The TLV structure and all
 * lengths stay intact, so only the EF.SOD hash comparison can reveal the change.
 */
fun tamperDg1(dg1: ByteArray): ByteArray {
    val mrz = locateMrz(dg1)
    val index = mrz.offset + documentNumberOffset(mrz.length)
    val tampered = dg1.copyOf()
    tampered[index] = nextMrzCharacter((dg1[index].toInt() and 0xFF).toChar()).code.toByte()
    return tampered
}
