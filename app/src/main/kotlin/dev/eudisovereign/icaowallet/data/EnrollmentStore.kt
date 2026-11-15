package dev.eudisovereign.icaowallet.data

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.ProviderException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerializationException

class EnrollmentStoreException(message: String, cause: Throwable? = null) : Exception(message, cause)

/** AES-256-GCM container: IV (12 bytes) || ciphertext || tag (16 bytes), with a fixed associated label. */
internal object SealedBlob {
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val IV_LENGTH = 12
    private const val TAG_BITS = 128
    private val AAD = "eudi-icao-enrollment-v1".toByteArray(Charsets.US_ASCII)

    fun seal(key: SecretKey, plaintext: ByteArray): ByteArray {
        // The keystore generates the IV itself: AndroidKeyStore keys require randomized encryption.
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        cipher.updateAAD(AAD)
        val iv = cipher.iv
        check(iv.size == IV_LENGTH) { "Unexpected GCM IV length ${iv.size}" }
        return iv + cipher.doFinal(plaintext)
    }

    fun open(key: SecretKey, blob: ByteArray): ByteArray {
        require(blob.size > IV_LENGTH + TAG_BITS / 8) { "Sealed blob is truncated" }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, blob, 0, IV_LENGTH))
        cipher.updateAAD(AAD)
        return cipher.doFinal(blob, IV_LENGTH, blob.size - IV_LENGTH)
    }
}

class EnrollmentStore(context: Context) {

    private val file = AtomicFile(File(context.applicationContext.noBackupFilesDir, FILE_NAME))

    suspend fun load(): Enrollment? = withContext(Dispatchers.IO) {
        val blob = try {
            file.readFully()
        } catch (e: FileNotFoundException) {
            return@withContext null
        } catch (e: IOException) {
            throw EnrollmentStoreException("Enrollment file cannot be read", e)
        }
        val key = try {
            existingKey()
        } catch (e: GeneralSecurityException) {
            throw EnrollmentStoreException("Enrollment storage key cannot be read", e)
        } catch (e: IOException) {
            throw EnrollmentStoreException("Enrollment storage key cannot be read", e)
        } catch (e: ProviderException) {
            throw EnrollmentStoreException("Enrollment storage key cannot be read", e)
        } ?: throw EnrollmentStoreException("Enrollment file exists but its storage key is gone")
        val plaintext = try {
            SealedBlob.open(key, blob)
        } catch (e: GeneralSecurityException) {
            throw EnrollmentStoreException("Enrollment file failed authenticated decryption", e)
        } catch (e: ProviderException) {
            throw EnrollmentStoreException("Enrollment file failed authenticated decryption", e)
        } catch (e: IllegalArgumentException) {
            throw EnrollmentStoreException("Enrollment file is truncated", e)
        }
        try {
            Enrollment.fromJson(plaintext.toString(Charsets.UTF_8))
        } catch (e: SerializationException) {
            throw EnrollmentStoreException("Enrollment file has an unexpected format", e)
        } catch (e: IllegalArgumentException) {
            throw EnrollmentStoreException("Enrollment file has an unexpected format", e)
        }
    }

    suspend fun save(enrollment: Enrollment) = withContext(Dispatchers.IO) {
        val blob = try {
            SealedBlob.seal(existingKey() ?: createKey(), enrollment.toJson().toByteArray(Charsets.UTF_8))
        } catch (e: GeneralSecurityException) {
            throw EnrollmentStoreException("Enrollment encryption failed", e)
        } catch (e: IOException) {
            throw EnrollmentStoreException("Enrollment storage key cannot be read", e)
        } catch (e: ProviderException) {
            throw EnrollmentStoreException("Enrollment encryption failed", e)
        }
        val out = try {
            file.startWrite()
        } catch (e: IOException) {
            throw EnrollmentStoreException("Enrollment file cannot be created", e)
        }
        try {
            out.write(blob)
            file.finishWrite(out)
        } catch (e: IOException) {
            file.failWrite(out)
            throw EnrollmentStoreException("Enrollment file cannot be written", e)
        }
    }

    suspend fun clear() = withContext(Dispatchers.IO) {
        file.delete()
        try {
            val store = keyStore()
            if (store.containsAlias(KEY_ALIAS)) store.deleteEntry(KEY_ALIAS)
        } catch (e: GeneralSecurityException) {
            throw EnrollmentStoreException("Enrollment storage key cannot be deleted", e)
        } catch (e: IOException) {
            throw EnrollmentStoreException("Enrollment storage key cannot be deleted", e)
        } catch (e: ProviderException) {
            throw EnrollmentStoreException("Enrollment storage key cannot be deleted", e)
        }
    }

    private fun existingKey(): SecretKey? = keyStore().getKey(KEY_ALIAS, null) as? SecretKey

    private fun createKey(): SecretKey {
        val spec = KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(false)
            .build()
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(spec)
        return generator.generateKey()
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val KEY_ALIAS = "enrollment-store"
        const val FILE_NAME = "enrollment.bin"
    }
}
