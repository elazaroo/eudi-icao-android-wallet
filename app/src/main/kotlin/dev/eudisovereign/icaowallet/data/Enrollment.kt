package dev.eudisovereign.icaowallet.data

import dev.eudisovereign.icaowallet.crypto.Codec
import dev.eudisovereign.icaowallet.crypto.KeyStorage
import dev.eudisovereign.icaowallet.nfc.ActiveAuthenticationDetails
import dev.eudisovereign.icaowallet.nfc.ChipAuthenticationDetails
import dev.eudisovereign.icaowallet.nfc.PaceDetails
import dev.eudisovereign.icaowallet.nfc.ReadResult
import dev.eudisovereign.icaowallet.nfc.SodSummary
import dev.eudisovereign.icaowallet.nfc.TimedStep
import dev.eudisovereign.icaowallet.protocol.Binding
import dev.eudisovereign.icaowallet.protocol.DeviceInfo
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.Json

internal object Base64Bytes : KSerializer<ByteArray> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("dev.eudisovereign.icaowallet.data.Base64Bytes", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: ByteArray) = encoder.encodeString(Codec.b64(value))

    override fun deserialize(decoder: Decoder): ByteArray = Codec.unb64(decoder.decodeString())
}

@Serializable
class Enrollment(
    val version: Int = VERSION,
    @Serializable(with = Base64Bytes::class) val cardAccess: ByteArray? = null,
    @Serializable(with = Base64Bytes::class) val sod: ByteArray,
    @Serializable(with = Base64Bytes::class) val dg1: ByteArray,
    @Serializable(with = Base64Bytes::class) val dg14: ByteArray? = null,
    @Serializable(with = Base64Bytes::class) val dg15: ByteArray? = null,
    val binding: Binding,
    @Serializable(with = Base64Bytes::class) val devicePublicKey: ByteArray,
    @Serializable(with = Base64Bytes::class) val aaResponse: ByteArray? = null,
    val keyAttestation: List<@Serializable(with = Base64Bytes::class) ByteArray>,
    val keyStorage: KeyStorage,
    val activeAuthentication: ActiveAuthenticationDetails? = null,
    val chipAuthentication: ChipAuthenticationDetails? = null,
    val pace: PaceDetails? = null,
    val sodSummary: SodSummary,
    val steps: List<TimedStep>,
    val enrolledAtMillis: Long,
    val deviceModel: String,
    val osVersion: String,
) {
    fun deviceInfo(): DeviceInfo = DeviceInfo(model = deviceModel, os = osVersion, keyStorage = keyStorage)

    fun toJson(): String = json.encodeToString(serializer(), this)

    companion object {
        const val VERSION = 1

        private val json = Json {
            ignoreUnknownKeys = true
            explicitNulls = false
            encodeDefaults = true
        }

        fun fromJson(text: String): Enrollment = json.decodeFromString(serializer(), text)

        fun from(
            result: ReadResult,
            keyAttestation: List<ByteArray>,
            keyStorage: KeyStorage,
            enrolledAtMillis: Long,
            deviceModel: String,
            osVersion: String,
        ): Enrollment {
            require(result.binding != Binding.CA_ATTESTATION || keyAttestation.isNotEmpty()) {
                "Binding ca-attestation requires a key attestation chain"
            }
            return Enrollment(
                cardAccess = result.cardAccess,
                sod = result.sod,
                dg1 = result.dg1,
                dg14 = result.dg14,
                dg15 = result.dg15,
                binding = result.binding,
                devicePublicKey = result.devicePublicKey,
                aaResponse = result.aaResponse,
                keyAttestation = keyAttestation,
                keyStorage = keyStorage,
                activeAuthentication = result.activeAuthentication,
                chipAuthentication = result.chipAuthentication,
                pace = result.pace,
                sodSummary = result.sodSummary,
                steps = result.steps,
                enrolledAtMillis = enrolledAtMillis,
                deviceModel = deviceModel,
                osVersion = osVersion,
            )
        }
    }
}
