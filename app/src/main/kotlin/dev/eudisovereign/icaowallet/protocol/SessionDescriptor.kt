package dev.eudisovereign.icaowallet.protocol

import dev.eudisovereign.icaowallet.crypto.Codec
import dev.eudisovereign.icaowallet.crypto.Hpke
import java.net.URI
import java.net.URISyntaxException
import kotlinx.serialization.SerializationException
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

open class DescriptorException(message: String, cause: Throwable? = null) : Exception(message, cause)

class UnsupportedRequestException(val request: String) : DescriptorException(
    "The session asks for \"$request\", which this wallet does not provide; " +
        "it answers the full presentation or \"${SessionRequest.AGE_OVER_18.wire}\"",
)

/** Spec 8.1: the optional `request` member; absent means the full presentation of section 4. */
enum class SessionRequest(val wire: String) {
    AGE_OVER_18("age-over-18"),
}

class SessionDescriptor private constructor(
    val peerId: String,
    val nonce: String,
    val nonceBytes: ByteArray,
    val timestamp: Long,
    val origin: String,
    val ek: ByteArray,
    val relay: String?,
    val request: SessionRequest?,
) {
    fun isFresh(nowMillis: Long): Boolean = withinSkew(timestamp, nowMillis)

    companion object {
        const val VERSION = 1
        const val MAX_CLOCK_SKEW_MS = 5 * 60 * 1000L

        private val json = Json { ignoreUnknownKeys = true }

        fun parse(text: String, nowMillis: Long = System.currentTimeMillis()): SessionDescriptor {
            val wire = try {
                json.decodeFromString(Wire.serializer(), text.trim())
            } catch (e: SerializationException) {
                throw DescriptorException("Session descriptor is not valid JSON for protocol v1: ${e.message}", e)
            } catch (e: IllegalArgumentException) {
                throw DescriptorException("Session descriptor is not valid JSON: ${e.message}", e)
            }
            if (wire.v != VERSION) throw DescriptorException("Unsupported descriptor version ${wire.v}")
            val request = wire.request?.let { value ->
                SessionRequest.entries.firstOrNull { it.wire == value } ?: throw UnsupportedRequestException(value)
            }
            if (wire.peerId.isBlank()) throw DescriptorException("peerId is empty")

            val nonceBytes = try {
                Codec.unb64url(wire.nonce)
            } catch (e: IllegalArgumentException) {
                throw DescriptorException("nonce is not base64url", e)
            }
            if (nonceBytes.size != 32) throw DescriptorException("nonce decodes to ${nonceBytes.size} bytes, expected 32")

            val ek = try {
                Codec.unb64url(wire.ek)
            } catch (e: IllegalArgumentException) {
                throw DescriptorException("ek is not base64url", e)
            }
            if (!Hpke.isValidP256Point(ek)) throw DescriptorException("ek is not an uncompressed P-256 point on the curve")

            if (!withinSkew(wire.timestamp, nowMillis)) {
                throw DescriptorException("Descriptor timestamp is more than 5 minutes away from the device clock")
            }

            if (!isOrigin(wire.origin)) throw DescriptorException("origin is not an http or https origin")
            val relay = wire.relay
            if (relay != null) {
                val uri = httpUri(relay) ?: throw DescriptorException("relay is not an http or https URL")
                // Spec 6.2: the result URL is the text "{relay}/result", which only a bare path keeps unambiguous
                if (uri.rawQuery != null || uri.rawFragment != null || uri.rawPath.orEmpty().endsWith("/")) {
                    throw DescriptorException("relay must not carry a query, a fragment or a trailing slash")
                }
            }

            return SessionDescriptor(wire.peerId, wire.nonce, nonceBytes, wire.timestamp, wire.origin, ek, relay, request)
        }

        // Written without subtraction of the untrusted timestamp, which could overflow.
        private fun withinSkew(timestamp: Long, nowMillis: Long): Boolean =
            timestamp >= nowMillis - MAX_CLOCK_SKEW_MS && timestamp <= nowMillis + MAX_CLOCK_SKEW_MS

        internal fun isOrigin(value: String): Boolean {
            val uri = httpUri(value) ?: return false
            return uri.rawPath.isNullOrEmpty() && uri.rawQuery == null && uri.rawFragment == null
        }

        private fun httpUri(value: String): URI? {
            val uri = try {
                URI(value)
            } catch (e: URISyntaxException) {
                return null
            }
            val scheme = uri.scheme?.lowercase() ?: return null
            if (scheme != "http" && scheme != "https") return null
            if (uri.host.isNullOrEmpty() || uri.rawUserInfo != null) return null
            return uri
        }
    }

    @Serializable
    private class Wire(
        val v: Int,
        val peerId: String,
        val nonce: String,
        val timestamp: Long,
        val origin: String,
        val ek: String,
        val relay: String? = null,
        val request: String? = null,
    )
}
