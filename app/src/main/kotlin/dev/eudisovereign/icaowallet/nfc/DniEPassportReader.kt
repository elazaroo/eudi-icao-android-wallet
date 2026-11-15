package dev.eudisovereign.icaowallet.nfc

import android.nfc.tech.IsoDep
import dev.eudisovereign.icaowallet.protocol.Binding
import dev.eudisovereign.icaowallet.protocol.Derivation
import java.io.ByteArrayInputStream
import java.io.EOFException
import java.io.IOException
import java.math.BigInteger
import java.security.GeneralSecurityException
import java.security.PublicKey
import java.security.spec.AlgorithmParameterSpec
import java.util.concurrent.atomic.AtomicBoolean
import java.util.logging.Level
import java.util.logging.Logger
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import net.sf.scuba.smartcards.CardFileInputStream
import net.sf.scuba.smartcards.CardServiceException
import net.sf.scuba.smartcards.FileSystemStructured
import net.sf.scuba.smartcards.IsoDepCardService
import org.jmrtd.CardServiceProtocolException
import org.jmrtd.DefaultFileSystem
import org.jmrtd.PassportService
import org.jmrtd.lds.CardAccessFile
import org.jmrtd.lds.PACEDomainParameterInfo
import org.jmrtd.lds.PACEInfo
import org.jmrtd.lds.SecurityInfo
import org.jmrtd.lds.icao.DG14File
import org.jmrtd.lds.icao.DG15File
import org.jmrtd.protocol.ReadBinaryAPDUSender

enum class ReadStep(val label: String) {
    CONNECT("Connect to chip"),
    CARD_ACCESS("Read EF.CardAccess"),
    PACE("PACE"),
    BAC("Basic Access Control"),
    SELECT_APPLET("Select eMRTD application"),
    READ_SOD("Read EF.SOD"),
    READ_DG1("Read EF.DG1"),
    READ_DG14("Read EF.DG14"),
    READ_DG15("Read EF.DG15"),
    INTEGRITY("Compare data group hashes with EF.SOD"),
    CHIP_AUTHENTICATION("Chip Authentication"),
    CA_PROOF("Re-read EF.DG1 under Chip Authentication keys"),
    DEVICE_KEY("Generate device binding key"),
    ACTIVE_AUTHENTICATION("Active Authentication"),
}

enum class StepStatus { STARTED, DONE, SKIPPED, FAILED }

@Serializable
class TimedStep(val step: ReadStep, val status: StepStatus, val durationMillis: Long, val detail: String?)

@Serializable
class PaceDetails(val oid: String, val protocol: String, val parameterId: Int?, val password: AccessKeyKind? = null)

enum class AccessProtocol { PACE, BAC }

@Serializable
class ChipAuthenticationDetails(
    val protocolOid: String,
    val protocol: String,
    val protocolOidInferred: Boolean,
    val publicKeyOid: String,
    val keyId: String?,
    val publicKey: String,
)

@Serializable
class ActiveAuthenticationDetails(
    val key: String,
    val digestAlgorithm: String,
    val signatureAlgorithm: String,
    val digestAssumed: Boolean,
)

class ReadResult(
    val cardAccess: ByteArray?,
    val sod: ByteArray,
    val dg1: ByteArray,
    val dg14: ByteArray?,
    val dg15: ByteArray?,
    val binding: Binding,
    val devicePublicKey: ByteArray,
    val aaResponse: ByteArray?,
    val activeAuthentication: ActiveAuthenticationDetails?,
    val chipAuthentication: ChipAuthenticationDetails?,
    val pace: PaceDetails?,
    val sodSummary: SodSummary,
    val steps: List<TimedStep>,
)

sealed class ReadException(message: String, cause: Throwable? = null) : Exception(message, cause) {
    class WrongAccessKey(val kind: AccessKeyKind, val protocol: AccessProtocol, val statusWord: Int) : ReadException(
        "${protocol.name} rejected the ${kind.label} (SW %04X)%s".format(
            statusWord,
            if ((statusWord and 0xFFF0) == 0x63C0) ", ${statusWord and 0x0F} attempts left" else "",
        ),
    ) {
        val title: String get() = "Wrong ${kind.label}"

        val hint: String
            get() = when (kind) {
                AccessKeyKind.CAN -> "Enter the 6-digit CAN printed on the document."
                AccessKeyKind.MRZ ->
                    "Check the document number, date of birth and date of expiry against the MRZ of the document."
            }

        companion object {
            const val PACE_MUTUAL_AUTH_STEP = 4

            // A failed mutual authentication is 6300 or 63CX (BSI TR-03110-3: X tries left); BAC chips also use 6982
            fun isRejection(protocol: AccessProtocol, statusWord: Int?, step: Int? = null): Boolean = when {
                statusWord == null -> false
                statusWord == 0x6300 || (statusWord and 0xFFF0) == 0x63C0 -> true
                protocol == AccessProtocol.BAC -> statusWord == 0x6982
                // A Spanish passport answers 6988 at the PACE mutual authentication step when the password is wrong
                else -> step == PACE_MUTUAL_AUTH_STEP && statusWord == 0x6988
            }
        }
    }
    class TagLost(val step: ReadStep, cause: Throwable?) :
        ReadException("Document left the NFC field during: ${step.label}", cause)
    class Timeout(val step: ReadStep) : ReadException("Read timed out during: ${step.label}")
    class UnsupportedDocument(detail: String, cause: Throwable? = null) : ReadException(detail, cause)
    class IntegrityMismatch(val dataGroup: Int, val algorithm: String) :
        ReadException("EF.DG$dataGroup does not match its $algorithm hash in EF.SOD")
    class ChipAuthenticationFailed(detail: String, val statusWord: Int?, cause: Throwable? = null) :
        ReadException("Chip Authentication failed: $detail", cause)
    class ActiveAuthenticationFailed(detail: String, val statusWord: Int?, cause: Throwable? = null) :
        ReadException("Active Authentication failed: $detail", cause)
    class DeviceKeyFailed(cause: Throwable) :
        ReadException("Device binding key generation failed: ${cause.message}", cause)
    class ProtocolError(val step: ReadStep, detail: String, val statusWord: Int?, cause: Throwable? = null) :
        ReadException(
            "${step.label} failed" + (statusWord?.let { " (SW %04X)".format(it) } ?: "") + ": $detail",
            cause,
        )
}

class DniEPassportReader(
    private val timeoutMillis: Long = DEFAULT_TIMEOUT_MS,
) {

    init {
        libraryLoggers.forEach { it.level = Level.OFF }
    }

    suspend fun read(
        isoDep: IsoDep,
        accessKey: AccessKey,
        bindDeviceKey: suspend (sodBytes: ByteArray) -> ByteArray,
        onProgress: (ReadStep, StepStatus) -> Unit,
    ): ReadResult {
        return withContext(Dispatchers.IO) {
            val timedOut = AtomicBoolean(false)
            // A blocked transceive only returns when the tag is closed from another thread.
            val watchdog = launch {
                try {
                    delay(timeoutMillis)
                    timedOut.set(true)
                } finally {
                    closeQuietly(isoDep)
                }
            }
            val session = Session(isoDep, accessKey, onProgress)
            try {
                session.run(bindDeviceKey)
            } catch (e: CancellationException) {
                throw e
            } catch (e: ReadException) {
                if (timedOut.get()) throw ReadException.Timeout(session.currentStep) else throw e
            } finally {
                watchdog.cancel()
                closeQuietly(isoDep)
            }
        }
    }

    private class AaOutcome(val response: ByteArray, val details: ActiveAuthenticationDetails)

    private class Session(
        private val isoDep: IsoDep,
        private val accessKey: AccessKey,
        private val onProgress: (ReadStep, StepStatus) -> Unit,
    ) {
        private val cardService = IsoDepCardService(isoDep)
        private val service = PassportService(
            cardService,
            PassportService.NORMAL_MAX_TRANCEIVE_LENGTH,
            PassportService.DEFAULT_MAX_BLOCKSIZE,
            false,
            true,
        )
        private val steps = mutableListOf<TimedStep>()
        var currentStep = ReadStep.CONNECT
            private set

        suspend fun run(bindDeviceKey: suspend (ByteArray) -> ByteArray): ReadResult {
            step(ReadStep.CONNECT) {
                service.open()
                isoDep.timeout = ISO_DEP_TIMEOUT_MS
                null
            }

            var securityInfos: Collection<SecurityInfo> = emptyList()
            val cardAccess = step(ReadStep.CARD_ACCESS) {
                readCardAccess()?.also { securityInfos = parseCardAccess(it) }
            }
            val offersPace = securityInfos.any { it is PACEInfo }

            val pace = if (offersPace || accessKey !is AccessKey.Mrz) {
                val details = step(ReadStep.PACE) { doPace(securityInfos) }
                skip(ReadStep.BAC)
                step(ReadStep.SELECT_APPLET) {
                    service.sendSelectApplet(true)
                    null
                }
                details
            } else {
                // ICAO 9303-11 4.2: a chip without PACEInfo in EF.CardAccess is accessed with BAC
                skip(ReadStep.PACE)
                step(ReadStep.SELECT_APPLET) {
                    service.sendSelectApplet(false)
                    null
                }
                step(ReadStep.BAC) {
                    doBac(accessKey, if (cardAccess == null) "EF.CardAccess absent" else "EF.CardAccess has no PACEInfo")
                }
                null
            }

            lateinit var parsedSod: ParsedSod
            val sod = step(ReadStep.READ_SOD) {
                val bytes = readFile(service, PassportService.EF_SOD)
                parsedSod = try {
                    DocumentSecurity.parseSod(bytes)
                } catch (e: IllegalArgumentException) {
                    throw ReadException.UnsupportedDocument(e.message ?: "EF.SOD cannot be parsed", e)
                }
                if (1 !in parsedSod.dataGroupHashes) {
                    throw ReadException.UnsupportedDocument("EF.SOD has no hash for EF.DG1")
                }
                bytes
            }
            val listed = parsedSod.dataGroupHashes.keys

            val dg1 = step(ReadStep.READ_DG1) { readFile(service, PassportService.EF_DG1) }
            val dg14 = optionalStep(ReadStep.READ_DG14, 14 in listed) { readFile(service, PassportService.EF_DG14) }
            val dg15 = optionalStep(ReadStep.READ_DG15, 15 in listed) { readFile(service, PassportService.EF_DG15) }

            step(ReadStep.INTEGRITY) {
                val algorithm = parsedSod.summary.ldsHashAlgorithm
                val files = listOfNotNull(1 to dg1, dg14?.let { 14 to it }, dg15?.let { 15 to it })
                for ((number, bytes) in files) {
                    val expected = parsedSod.dataGroupHashes.getValue(number)
                    val matches = try {
                        DocumentSecurity.hashMatches(algorithm, bytes, expected)
                    } catch (e: IllegalArgumentException) {
                        throw ReadException.UnsupportedDocument(e.message ?: "Unsupported LDS hash algorithm", e)
                    }
                    if (!matches) throw ReadException.IntegrityMismatch(number, algorithm)
                }
                "$algorithm, ${files.size} files"
            }

            val dg14Infos: Collection<SecurityInfo> = dg14?.let {
                try {
                    DG14File(ByteArrayInputStream(it)).securityInfos
                } catch (e: Exception) {
                    throw ReadException.UnsupportedDocument("EF.DG14 cannot be parsed: ${e.message}", e)
                }
            } ?: emptyList()
            val caParameters = dg14Infos.takeIf { it.isNotEmpty() }?.let {
                try {
                    DocumentSecurity.chipAuthenticationParameters(it)
                } catch (e: IllegalArgumentException) {
                    throw ReadException.UnsupportedDocument(e.message ?: "Unsupported EF.DG14", e)
                }
            }
            if (caParameters == null && dg15 == null) {
                throw ReadException.UnsupportedDocument(
                    "The document offers neither Active Authentication (EF.DG15) nor Chip Authentication (EF.DG14)",
                )
            }

            val chipAuthentication = if (caParameters != null) {
                step(ReadStep.CHIP_AUTHENTICATION) {
                    doChipAuthentication(caParameters)
                    DocumentSecurity.describeChipAuthenticationOid(caParameters.protocolOid)
                }
                step(ReadStep.CA_PROOF) {
                    val reread = try {
                        readFileUncached(PassportService.EF_DG1)
                    } catch (e: CardServiceException) {
                        if (cardService.isConnectionLost(e)) throw e
                        throw ReadException.ChipAuthenticationFailed(
                            "EF.DG1 cannot be read under the new secure messaging keys",
                            statusWordOf(e),
                            e,
                        )
                    } catch (e: IOException) {
                        // CardFileInputStream.read reports READ BINARY failures after the first block as IOException
                        if (cardService.isConnectionLost(e)) throw e
                        throw ReadException.ChipAuthenticationFailed(
                            "EF.DG1 cannot be read under the new secure messaging keys",
                            statusWordOf(e),
                            e,
                        )
                    }
                    if (!reread.contentEquals(dg1)) {
                        throw ReadException.ChipAuthenticationFailed(
                            "EF.DG1 read under the new keys differs from the first read",
                            null,
                        )
                    }
                    "${reread.size} bytes identical"
                }
                ChipAuthenticationDetails(
                    protocolOid = caParameters.protocolOid,
                    protocol = DocumentSecurity.describeChipAuthenticationOid(caParameters.protocolOid),
                    protocolOidInferred = caParameters.protocolOidInferred,
                    publicKeyOid = caParameters.publicKeyOid,
                    keyId = caParameters.keyId?.toString(),
                    publicKey = DocumentSecurity.describeKey(caParameters.publicKey),
                )
            } else {
                skip(ReadStep.CHIP_AUTHENTICATION)
                skip(ReadStep.CA_PROOF)
                null
            }

            // Spec 4.2: the device key is generated only after the integrity check and Chip Authentication.
            val devicePublicKey = suspendStep(ReadStep.DEVICE_KEY) {
                try {
                    bindDeviceKey(sod.copyOf()).also { check(it.isNotEmpty()) { "the key callback returned no SPKI" } }
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    throw ReadException.DeviceKeyFailed(e)
                }
            }

            val aa = if (dg15 != null) {
                step(ReadStep.ACTIVE_AUTHENTICATION) {
                    doActiveAuthentication(dg15, dg14Infos, Derivation.aaChallenge(devicePublicKey))
                }
            } else {
                skip(ReadStep.ACTIVE_AUTHENTICATION)
                null
            }

            return ReadResult(
                cardAccess = cardAccess,
                sod = sod,
                dg1 = dg1,
                dg14 = dg14,
                dg15 = dg15,
                binding = if (aa != null) Binding.AA else Binding.CA_ATTESTATION,
                devicePublicKey = devicePublicKey,
                aaResponse = aa?.response,
                activeAuthentication = aa?.details,
                chipAuthentication = chipAuthentication,
                pace = pace,
                sodSummary = parsedSod.summary,
                steps = steps.toList(),
            )
        }

        // Returns null when the chip has no EF.CardAccess, which only a BAC document with MRZ data may lack.
        private fun readCardAccess(): ByteArray? = try {
            readFile(service, PassportService.EF_CARD_ACCESS)
        } catch (e: CardServiceException) {
            if (statusWordOf(e) != SW_FILE_NOT_FOUND) throw e
            if (accessKey !is AccessKey.Mrz) {
                throw ReadException.UnsupportedDocument(
                    "No EF.CardAccess: the document does not support PACE, which access with a CAN requires",
                )
            }
            null
        }

        private fun parseCardAccess(bytes: ByteArray): Collection<SecurityInfo> = try {
            CardAccessFile(ByteArrayInputStream(bytes)).securityInfos
        } catch (e: Exception) {
            throw ReadException.UnsupportedDocument("EF.CardAccess cannot be parsed: ${e.message}", e)
        }

        private fun doPace(securityInfos: Collection<SecurityInfo>): PaceDetails {
            val paceInfos = securityInfos.filterIsInstance<PACEInfo>()
            val paceInfo = paceInfos.minByOrNull(::pacePreference)
                ?: throw ReadException.UnsupportedDocument(
                    "EF.CardAccess contains no PACEInfo: the document does not support PACE, " +
                        "which access with a CAN requires",
                )
            val oid = paceInfo.objectIdentifier
            val parameterId: BigInteger? = paceInfo.parameterId
            val domainParameters = resolveDomainParameters(securityInfos, parameterId)
                ?: throw ReadException.UnsupportedDocument("No usable PACE domain parameters (id $parameterId)")
            // ICAO 9303-11 PACE, MSE:Set AT: DO'84' is required only when several domain parameter sets exist
            val ambiguous = paceInfos.map { it.parameterId }.distinct().size > 1
            val paceKey = try {
                accessKey.paceKey()
            } catch (e: GeneralSecurityException) {
                throw ReadException.ProtocolError(ReadStep.PACE, "PACE key derivation failed: ${e.message}", null, e)
            }
            try {
                service.doPACE(paceKey, oid, domainParameters, if (ambiguous) parameterId else null)
            } catch (e: CardServiceProtocolException) {
                val sw = statusWordOf(e)
                if (ReadException.WrongAccessKey.isRejection(AccessProtocol.PACE, sw, e.step)) {
                    throw ReadException.WrongAccessKey(accessKey.kind, AccessProtocol.PACE, requireNotNull(sw))
                }
                throw e
            }
            return PaceDetails(
                oid = oid,
                protocol = DocumentSecurity.describePaceOid(oid),
                parameterId = parameterId?.takeIf { it.signum() >= 0 }?.toInt(),
                password = accessKey.kind,
            )
        }

        private fun doBac(key: AccessKey.Mrz, reason: String): String {
            try {
                service.doBAC(key.bacKey())
            } catch (e: CardServiceException) {
                if (cardService.isConnectionLost(e)) throw e
                val sw = statusWordOf(e)
                // JMRTD BACProtocol reports a failed EXTERNAL AUTHENTICATE as protocol step 2
                val mutualAuthentication = (e as? CardServiceProtocolException)?.step == BAC_MUTUAL_AUTH_STEP
                if (mutualAuthentication && ReadException.WrongAccessKey.isRejection(AccessProtocol.BAC, sw)) {
                    throw ReadException.WrongAccessKey(AccessKeyKind.MRZ, AccessProtocol.BAC, requireNotNull(sw))
                }
                throw e
            }
            return "3DES secure messaging, $reason"
        }

        private fun doChipAuthentication(parameters: ChipAuthenticationParameters) {
            try {
                service.doEACCA(
                    parameters.keyId,
                    parameters.protocolOid,
                    parameters.publicKeyOid,
                    parameters.publicKey,
                )
            } catch (e: CardServiceException) {
                if (cardService.isConnectionLost(e)) throw e
                throw ReadException.ChipAuthenticationFailed(e.message ?: "card error", statusWordOf(e), e)
            } catch (e: IllegalArgumentException) {
                throw ReadException.ChipAuthenticationFailed(e.message ?: "unsupported parameters", null, e)
            } catch (e: ClassCastException) {
                throw ReadException.ChipAuthenticationFailed("key type does not match the protocol OID", null, e)
            }
        }

        private fun doActiveAuthentication(
            dg15: ByteArray,
            dg14Infos: Collection<SecurityInfo>,
            challenge: ByteArray,
        ): AaOutcome {
            val key: PublicKey = try {
                DG15File(ByteArrayInputStream(dg15)).publicKey
            } catch (e: Exception) {
                null
            } ?: throw ReadException.UnsupportedDocument("EF.DG15 public key cannot be decoded")
            val algorithms = try {
                DocumentSecurity.aaAlgorithms(key, DocumentSecurity.activeAuthenticationSignatureOid(dg14Infos))
            } catch (e: IllegalArgumentException) {
                throw ReadException.UnsupportedDocument(e.message ?: "Unsupported EF.DG15 key", e)
            }
            val response = try {
                service.doAA(key, algorithms.digest, algorithms.signature, challenge).response
            } catch (e: CardServiceException) {
                if (cardService.isConnectionLost(e)) throw e
                throw ReadException.ActiveAuthenticationFailed(e.message ?: "card error", statusWordOf(e), e)
            }
            // JMRTD AAAPDUSender returns an empty array instead of throwing when the chip answers with an error
            val expectedLength = DocumentSecurity.expectedAaResponseLength(key)
            if (response == null || response.isEmpty()) {
                throw ReadException.ActiveAuthenticationFailed("the chip returned no signature", null)
            }
            if (response.size != expectedLength) {
                throw ReadException.ActiveAuthenticationFailed(
                    "response is ${response.size} bytes, expected $expectedLength",
                    null,
                )
            }
            val details = ActiveAuthenticationDetails(
                key = DocumentSecurity.describeKey(key),
                digestAlgorithm = algorithms.digest,
                signatureAlgorithm = algorithms.signature,
                digestAssumed = algorithms.digestAssumed,
            )
            return AaOutcome(response, details)
        }

        // PassportService caches file contents; a fresh file system forces real APDUs under the current wrapper.
        private fun readFileUncached(fid: Short): ByteArray = guardAllocation(fid) {
            val fileSystem = DefaultFileSystem(ReadBinaryAPDUSender(service.secureMessagingAPDUSender), false)
            fileSystem.setWrapper(service.wrapper)
            fileSystem.selectFile(fid)
            readAll(fileSystem, fid)
        }

        private inline fun <T> step(step: ReadStep, block: () -> T): T {
            val started = begin(step)
            val value = try {
                block()
            } catch (e: Throwable) {
                fail(step, started, e)
            }
            finish(step, started, value)
            return value
        }

        private suspend fun <T> suspendStep(step: ReadStep, block: suspend () -> T): T {
            val started = begin(step)
            val value = try {
                block()
            } catch (e: Throwable) {
                fail(step, started, e)
            }
            finish(step, started, value)
            return value
        }

        private inline fun optionalStep(step: ReadStep, listed: Boolean, block: () -> ByteArray): ByteArray? {
            if (!listed) {
                skip(step)
                return null
            }
            return step(step, block)
        }

        private fun begin(step: ReadStep): Long {
            currentStep = step
            onProgress(step, StepStatus.STARTED)
            return System.nanoTime()
        }

        private fun finish(step: ReadStep, started: Long, value: Any?) {
            val detail = when (value) {
                is ByteArray -> "${value.size} bytes"
                is String -> value
                is PaceDetails ->
                    "${value.protocol}, parameter id ${value.parameterId ?: "none"}, password ${value.password?.label}"
                is AaOutcome -> "${value.details.key}, ${value.response.size}-byte response"
                else -> null
            }
            steps += TimedStep(step, StepStatus.DONE, elapsedMillis(started), detail)
            onProgress(step, StepStatus.DONE)
        }

        private fun skip(step: ReadStep) {
            steps += TimedStep(step, StepStatus.SKIPPED, 0, null)
            onProgress(step, StepStatus.SKIPPED)
        }

        private fun fail(step: ReadStep, started: Long, error: Throwable): Nothing {
            val mapped = when (error) {
                is CancellationException -> error
                is ReadException -> error
                is Exception -> classify(step, error)
                else -> error
            }
            steps += TimedStep(step, StepStatus.FAILED, elapsedMillis(started), mapped.message)
            onProgress(step, StepStatus.FAILED)
            throw mapped
        }

        private fun classify(step: ReadStep, error: Exception): ReadException {
            if (cardService.isConnectionLost(error)) return ReadException.TagLost(step, error)
            val sw = statusWordOf(error)
            return ReadException.ProtocolError(step, error.message ?: error.javaClass.simpleName, sw, error)
        }

        private fun elapsedMillis(started: Long) = (System.nanoTime() - started) / 1_000_000
    }

    companion object {
        const val DEFAULT_TIMEOUT_MS = 60_000L
        private const val ISO_DEP_TIMEOUT_MS = 10_000
        private const val SW_FILE_NOT_FOUND = 0x6A82
        private const val BAC_MUTUAL_AUTH_STEP = 2

        // Only EF.CardAccess, EF.SOD, EF.DG1, EF.DG14 and EF.DG15 are read; each is a few kilobytes at most.
        internal const val MAX_FILE_LENGTH = 65_536

        private fun fidName(fid: Short): String = "%04X".format(fid.toInt() and 0xFFFF)

        // Held strongly: java.util.logging keeps only weak references, and both libraries log APDUs.
        private val libraryLoggers = listOf(Logger.getLogger("org.jmrtd"), Logger.getLogger("net.sf.scuba"))

        private fun closeQuietly(isoDep: IsoDep) {
            try {
                isoDep.close()
            } catch (e: IOException) {
                return
            } catch (e: SecurityException) {
                return
            }
        }

        private fun readFile(service: PassportService, fid: Short): ByteArray = guardAllocation(fid) {
            readAll(service.getInputStream(fid, PassportService.DEFAULT_MAX_BLOCKSIZE), fid)
        }

        // JMRTD DefaultFileSystem allocates a buffer of the length the chip declares before any content is read.
        private fun <T> guardAllocation(fid: Short, block: () -> T): T = try {
            block()
        } catch (e: OutOfMemoryError) {
            throw IOException("EF ${fidName(fid)}: declared length is implausible")
        }

        internal fun readAll(fileSystem: FileSystemStructured, fid: Short): ByteArray =
            readAll(CardFileInputStream(PassportService.DEFAULT_MAX_BLOCKSIZE, fileSystem), fid)

        private fun readAll(input: CardFileInputStream, fid: Short): ByteArray {
            val name = fidName(fid)
            val length = input.length
            if (length <= 0) throw IOException("EF $name: length cannot be determined")
            if (length > MAX_FILE_LENGTH) throw IOException("EF $name: declared length is implausible")
            val out = ByteArray(length)
            var offset = 0
            // InputStream.read(byte[], int, int) swallows an IOException after the first byte; loop until full.
            while (offset < length) {
                val n = input.read(out, offset, length - offset)
                if (n < 0) throw EOFException("EF $name: premature end of file at $offset of $length bytes")
                offset += n
            }
            return out
        }

        private fun pacePreference(info: PACEInfo): Int {
            val oid = info.objectIdentifier
            val agreement = if (PACEInfo.toKeyAgreementAlgorithm(oid) == "ECDH") 0 else 1
            val cipher = if (PACEInfo.toCipherAlgorithm(oid) == "AES") 0 else 1
            val mapping = when (PACEInfo.toMappingType(oid)) {
                PACEInfo.MappingType.GM -> 0
                PACEInfo.MappingType.CAM -> 1
                PACEInfo.MappingType.IM -> 2
                else -> 3
            }
            val keyLengthRank = (256 - PACEInfo.toKeyLength(oid)) / 64
            return agreement * 1000 + cipher * 100 + mapping * 10 + keyLengthRank
        }

        private fun resolveDomainParameters(
            securityInfos: Collection<SecurityInfo>,
            parameterId: BigInteger?,
        ): AlgorithmParameterSpec? {
            if (parameterId != null && parameterId.signum() >= 0) {
                try {
                    return PACEInfo.toParameterSpec(parameterId)
                } catch (e: NumberFormatException) {
                    // Not a standardized id (ICAO 9303-11 9.5.1); look for explicit parameters below.
                }
            }
            val explicit = securityInfos.filterIsInstance<PACEDomainParameterInfo>()
            val match = explicit.firstOrNull { it.parameterId != null && it.parameterId == parameterId }
                ?: explicit.singleOrNull()
            return match?.parameters
        }

        private fun statusWordOf(error: Throwable): Int? {
            var current: Throwable? = error
            var depth = 0
            while (current != null && depth < 16) {
                if (current is CardServiceException && current.sw != CardServiceException.SW_NONE) {
                    return current.sw and 0xFFFF
                }
                current = current.cause
                depth++
            }
            return null
        }
    }
}
