package dev.eudisovereign.icaowallet.zk

import android.content.Context
import android.net.Uri
import dev.eudisovereign.icaowallet.crypto.Codec
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.security.MessageDigest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext

sealed class ProvingKeyException(message: String, cause: Throwable? = null) : Exception(message, cause) {
    class Missing : ProvingKeyException("The proving key age_proof.zkey is not installed")
    class WrongFile(detail: String) : ProvingKeyException(detail)
    class Io(detail: String, cause: Throwable? = null) : ProvingKeyException(detail, cause)
}

/**
 * The Groth16 proving key is not part of the APK. It is downloaded once, or imported through the system file picker,
 * into app-private storage and accepted only when its length and SHA-256 are those of the published artefact.
 */
class ProvingKeyStore(context: Context) {

    private val appContext = context.applicationContext
    private val downloader = ProvingKeyDownloader(ProvingKeyDownloader.defaultClient(), ProvingKeySource.PUBLISHED)
    private val directory = File(appContext.noBackupFilesDir, "zk")
    val file = File(directory, FILE_NAME)
    private val partial = File(directory, "$FILE_NAME.part")

    /** Verified when it was stored; afterwards only its length is checked. */
    fun isInstalled(): Boolean = file.isFile && file.length() == EXPECTED_SIZE

    fun requireInstalled(): File {
        if (!isInstalled()) throw ProvingKeyException.Missing()
        return file
    }

    suspend fun download(onProgress: (Long) -> Unit) = downloader.download(file, onProgress)

    fun remove() {
        discardLeftovers()
        if (file.exists() && !file.delete()) throw ProvingKeyException.Io("Cannot delete ${file.path}")
    }

    /** Temporary files of a copy or download that the process did not live to finish. */
    fun discardLeftovers() {
        if (partial.exists()) partial.delete()
        directory.listFiles { candidate -> candidate.name.endsWith(ProvingKeyDownloader.TEMP_SUFFIX) }?.forEach { it.delete() }
    }

    suspend fun import(uri: Uri, onProgress: (Long) -> Unit): Unit = withContext(Dispatchers.IO) {
        if (!directory.isDirectory && !directory.mkdirs()) throw ProvingKeyException.Io("Cannot create ${directory.path}")
        val needed = EXPECTED_SIZE - (if (file.isFile) file.length() else 0)
        if (directory.usableSpace < needed) {
            throw ProvingKeyException.Io("Not enough free storage: ${directory.usableSpace} bytes free, $EXPECTED_SIZE needed")
        }
        try {
            val stream = appContext.contentResolver.openInputStream(uri)
                ?: throw ProvingKeyException.Io("The selected document cannot be opened")
            val digest = stream.use { copyHashing(it, partial, onProgress) }
            val size = partial.length()
            if (size != EXPECTED_SIZE) {
                throw ProvingKeyException.WrongFile("The file has $size bytes, the proving key has $EXPECTED_SIZE")
            }
            if (digest != EXPECTED_SHA256) {
                throw ProvingKeyException.WrongFile("SHA-256 $digest differs from $EXPECTED_SHA256")
            }
            if (file.exists() && !file.delete()) throw ProvingKeyException.Io("Cannot replace ${file.path}")
            if (!partial.renameTo(file)) throw ProvingKeyException.Io("Cannot move the verified key into place")
        } catch (e: IOException) {
            throw ProvingKeyException.Io("Copy failed: ${e.message ?: e.javaClass.simpleName}", e)
        } catch (e: SecurityException) {
            throw ProvingKeyException.Io("The selected document cannot be read: ${e.message}", e)
        } finally {
            if (partial.exists()) partial.delete()
        }
    }

    private suspend fun copyHashing(input: InputStream, target: File, onProgress: (Long) -> Unit): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(BUFFER_BYTES)
        var total = 0L
        var reported = 0L
        target.outputStream().use { output ->
            while (true) {
                currentCoroutineContext().ensureActive()
                val read = input.read(buffer)
                if (read < 0) break
                total += read
                if (total > EXPECTED_SIZE) {
                    throw ProvingKeyException.WrongFile("The file is larger than the proving key ($EXPECTED_SIZE bytes)")
                }
                digest.update(buffer, 0, read)
                output.write(buffer, 0, read)
                if (total - reported >= PROGRESS_STEP) {
                    reported = total
                    onProgress(total)
                }
            }
            output.fd.sync()
        }
        onProgress(total)
        return Codec.hex(digest.digest())
    }

    companion object {
        const val FILE_NAME = "age_proof.zkey"
        val EXPECTED_SIZE = ProvingKeySource.PUBLISHED.size
        val EXPECTED_SHA256 = ProvingKeySource.PUBLISHED.sha256
        val DOWNLOAD_URL = ProvingKeySource.PUBLISHED.url
        private const val BUFFER_BYTES = 1 shl 20
        private const val PROGRESS_STEP = 8L shl 20
    }
}
