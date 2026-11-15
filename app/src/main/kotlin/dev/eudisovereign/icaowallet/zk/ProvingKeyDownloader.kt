package dev.eudisovereign.icaowallet.zk

import dev.eudisovereign.icaowallet.BuildConfig
import dev.eudisovereign.icaowallet.crypto.Codec
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.Call
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.ResponseBody

sealed class KeyDownloadException(message: String, cause: Throwable? = null) : Exception(message, cause) {
    class NoNetwork(detail: String, cause: Throwable? = null) : KeyDownloadException(detail, cause)
    class Interrupted(detail: String, cause: Throwable? = null) : KeyDownloadException(detail, cause)
    class Http(val status: Int, host: String) : KeyDownloadException("HTTP $status from $host")
    class InsufficientSpace(val available: Long, val required: Long) :
        KeyDownloadException("Not enough free storage: $available bytes free, $required needed")
    class Mismatch(detail: String) : KeyDownloadException(detail)
    class Protocol(detail: String) : KeyDownloadException(detail)
    class Storage(detail: String, cause: Throwable? = null) : KeyDownloadException(detail, cause)
}

class ProvingKeySource(val url: String, val size: Long, val sha256: String) {
    companion object {
        val PUBLISHED = ProvingKeySource(BuildConfig.PROVING_KEY_URL, BuildConfig.PROVING_KEY_SIZE, BuildConfig.PROVING_KEY_SHA256)
    }
}

/**
 * Streams the proving key over https into a temporary file next to [download]'s target while hashing it, and moves
 * it into place only on an exact size and SHA-256 match. The temporary file is removed on every other outcome.
 */
class ProvingKeyDownloader(
    client: OkHttpClient,
    private val source: ProvingKeySource,
    private val freeSpace: (File) -> Long = File::getUsableSpace,
    private val progressStep: Long = PROGRESS_STEP,
) {
    // Redirects are followed here so that every hop can be required to stay on https.
    private val client = client.newBuilder().followRedirects(false).followSslRedirects(false).build()

    suspend fun download(target: File, onProgress: (Long) -> Unit): Unit = withContext(Dispatchers.IO) {
        val directory = target.absoluteFile.parentFile ?: throw KeyDownloadException.Storage("${target.path} has no parent directory")
        if (!directory.isDirectory && !directory.mkdirs()) throw KeyDownloadException.Storage("Cannot create ${directory.path}")
        val required = source.size + SPACE_MARGIN
        val available = freeSpace(directory)
        if (available < required) throw KeyDownloadException.InsufficientSpace(available, required)

        val temporary = try {
            File.createTempFile(target.name + ".", TEMP_SUFFIX, directory)
        } catch (e: IOException) {
            throw KeyDownloadException.Storage("Cannot create a temporary file in ${directory.path}: ${e.message}", e)
        }
        try {
            val digest = fetch(temporary, onProgress)
            if (!digest.equals(source.sha256, ignoreCase = true)) {
                throw KeyDownloadException.Mismatch("SHA-256 $digest differs from ${source.sha256}")
            }
            try {
                Files.move(temporary.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } catch (e: IOException) {
                throw KeyDownloadException.Storage("Cannot move the verified key into place: ${e.message}", e)
            }
        } finally {
            if (temporary.exists()) temporary.delete()
        }
    }

    private suspend fun fetch(temporary: File, onProgress: (Long) -> Unit): String {
        var url = source.url.toHttpUrl()
        repeat(MAX_REDIRECTS + 1) {
            if (!url.isHttps) throw KeyDownloadException.Protocol("Refusing $url: the proving key is downloaded only over https")
            val call = client.newCall(Request.Builder().url(url).get().build())
            val outcome = cancelOnCancellation(call) {
                val response = try {
                    call.execute()
                } catch (e: IOException) {
                    currentCoroutineContext().ensureActive()
                    throw KeyDownloadException.NoNetwork("${url.host} unreachable: ${e.message ?: e.javaClass.simpleName}", e)
                }
                response.use {
                    when {
                        it.isRedirect -> Hop.Next(redirectTarget(url, it.header("Location")))
                        it.code != 200 -> throw KeyDownloadException.Http(it.code, url.host)
                        else -> Hop.Done(save(it.body, temporary, onProgress))
                    }
                }
            }
            when (outcome) {
                is Hop.Done -> return outcome.digest
                is Hop.Next -> url = outcome.url
            }
        }
        throw KeyDownloadException.Protocol("More than $MAX_REDIRECTS redirects")
    }

    private fun redirectTarget(from: HttpUrl, location: String?): HttpUrl {
        if (location.isNullOrEmpty()) throw KeyDownloadException.Protocol("Redirect from ${from.host} without a Location header")
        return from.resolve(location) ?: throw KeyDownloadException.Protocol("Redirect from ${from.host} to an invalid location")
    }

    private suspend fun save(body: ResponseBody, temporary: File, onProgress: (Long) -> Unit): String {
        val expected = source.size
        val declared = body.contentLength()
        if (declared >= 0 && declared != expected) {
            throw KeyDownloadException.Mismatch("The server announced $declared bytes, the proving key has $expected")
        }
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(BUFFER_BYTES)
        var total = 0L
        var reported = 0L
        val input = body.byteStream()
        try {
            FileOutputStream(temporary).use { output ->
                while (true) {
                    currentCoroutineContext().ensureActive()
                    val read = try {
                        input.read(buffer)
                    } catch (e: IOException) {
                        currentCoroutineContext().ensureActive()
                        throw KeyDownloadException.Interrupted("Connection lost after $total of $expected bytes: ${e.message}", e)
                    }
                    if (read < 0) break
                    total += read
                    if (total > expected) throw KeyDownloadException.Mismatch("The server sent more than $expected bytes")
                    digest.update(buffer, 0, read)
                    output.write(buffer, 0, read)
                    if (total - reported >= progressStep) {
                        reported = total
                        onProgress(total)
                    }
                }
                output.fd.sync()
            }
        } catch (e: IOException) {
            throw KeyDownloadException.Storage("Writing ${temporary.name} failed after $total bytes: ${e.message}", e)
        }
        onProgress(total)
        if (total < expected) throw KeyDownloadException.Interrupted("The connection ended after $total of $expected bytes")
        return Codec.hex(digest.digest())
    }

    // A blocking read does not observe coroutine cancellation; cancelling the call makes it fail at once.
    private suspend fun <T> cancelOnCancellation(call: Call, block: suspend () -> T): T = coroutineScope {
        val watcher = launch(start = CoroutineStart.UNDISPATCHED) {
            try {
                awaitCancellation()
            } finally {
                call.cancel()
            }
        }
        try {
            block()
        } finally {
            watcher.cancel()
        }
    }

    private sealed interface Hop {
        class Next(val url: HttpUrl) : Hop
        class Done(val digest: String) : Hop
    }

    companion object {
        const val TEMP_SUFFIX = ".download"
        const val SPACE_MARGIN = 64L shl 20
        private const val MAX_REDIRECTS = 5
        private const val BUFFER_BYTES = 256 * 1024
        private const val PROGRESS_STEP = 1L shl 20

        fun defaultClient(): OkHttpClient = OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .build()
    }
}
