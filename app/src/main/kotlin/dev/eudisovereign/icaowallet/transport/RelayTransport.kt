package dev.eudisovereign.icaowallet.transport

import dev.eudisovereign.icaowallet.protocol.FrameException
import dev.eudisovereign.icaowallet.protocol.ResultFrame
import dev.eudisovereign.icaowallet.protocol.SessionDescriptor
import java.io.IOException
import java.util.concurrent.TimeUnit
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import okhttp3.Call
import okhttp3.Callback
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response

/** Spec 6.2: PUT the envelope into the session mailbox, then long-poll {relay}/result. */
class RelayTransport(
    private val client: OkHttpClient = defaultClient(),
    private val resultWaitMillis: Long = DEFAULT_RESULT_WAIT_MS,
) : Transport {

    override suspend fun deliver(descriptor: SessionDescriptor, envelopeJson: String): ResultFrame =
        withContext(Dispatchers.IO) {
            val relay = descriptor.relay ?: throw TransportException.Protocol("The session descriptor has no relay URL")
            val mailbox = relay.toHttpUrlOrNull() ?: throw TransportException.Protocol("The relay URL is not valid")
            val body = envelopeJson.toByteArray(Charsets.UTF_8)
            if (body.size > MAX_ENVELOPE_BYTES) throw TransportException.TooLarge(body.size, MAX_ENVELOPE_BYTES)

            val upload = Request.Builder().url(mailbox).put(body.toRequestBody(JSON)).build()
            execute(upload, "uploading the envelope").use { response ->
                if (!response.isSuccessful) throw TransportException.Http(response.code, "uploading the envelope")
            }

            withTimeoutOrNull(resultWaitMillis) { pollResult(resultUrl(mailbox)) }
                ?: throw TransportException.Timeout("waiting for the verification result on the relay")
        }

    private suspend fun pollResult(url: HttpUrl): ResultFrame {
        val request = Request.Builder().url(url).get().build()
        while (true) {
            val started = System.nanoTime()
            execute(request, "waiting for the verification result").use { response ->
                when (response.code) {
                    200 -> return parseResult(response)
                    204 -> Unit
                    else -> throw TransportException.Http(response.code, "waiting for the verification result")
                }
            }
            // A relay that ignores wait= and answers 204 at once must not be polled in a tight loop.
            val elapsedMillis = (System.nanoTime() - started) / 1_000_000
            if (elapsedMillis < MIN_POLL_INTERVAL_MS) delay(MIN_POLL_INTERVAL_MS - elapsedMillis)
        }
    }

    private fun parseResult(response: Response): ResultFrame {
        val source = response.body.source()
        if (source.request(MAX_RESULT_BYTES + 1L)) {
            throw TransportException.Protocol("Relay result exceeds $MAX_RESULT_BYTES bytes")
        }
        val text = source.buffer.readUtf8()
        return try {
            ResultFrame.decode(text) ?: throw TransportException.Protocol("Relay returned a frame that is not a result")
        } catch (e: FrameException) {
            throw TransportException.Protocol(e.message ?: "Malformed result frame", e)
        }
    }

    private suspend fun execute(request: Request, stage: String): Response = try {
        client.newCall(request).await()
    } catch (e: IOException) {
        throw TransportException.Connection("relay unreachable while $stage: ${e.message}", e)
    }

    private suspend fun Call.await(): Response = suspendCancellableCoroutine { continuation ->
        continuation.invokeOnCancellation { cancel() }
        enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                continuation.resumeWithException(e)
            }

            override fun onResponse(call: Call, response: Response) {
                continuation.resume(response) { _, value, _ -> value.close() }
            }
        })
    }

    companion object {
        const val DEFAULT_RESULT_WAIT_MS = 60_000L
        const val MAX_ENVELOPE_BYTES = 262_144
        private const val MAX_RESULT_BYTES = 65_536
        private const val MIN_POLL_INTERVAL_MS = 1_000L
        private const val LONG_POLL_SECONDS = "25"
        private val JSON = "application/json".toMediaType()

        internal fun resultUrl(mailbox: HttpUrl): HttpUrl =
            mailbox.newBuilder().addPathSegment("result").addQueryParameter("wait", LONG_POLL_SECONDS).build()

        fun defaultClient(): OkHttpClient = OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .writeTimeout(15, TimeUnit.SECONDS)
            .readTimeout(35, TimeUnit.SECONDS)
            .callTimeout(40, TimeUnit.SECONDS)
            .build()
    }
}
