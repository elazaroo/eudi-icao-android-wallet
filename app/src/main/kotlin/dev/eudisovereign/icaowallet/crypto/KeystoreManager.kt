package dev.eudisovereign.icaowallet.crypto

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import androidx.annotation.RequiresApi
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import java.io.ByteArrayInputStream
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.ProviderException
import java.security.Signature
import java.security.UnrecoverableKeyException
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
enum class KeyStorage {
    @SerialName("strongbox") STRONGBOX,
    @SerialName("tee") TEE,
    @SerialName("software") SOFTWARE,
}

class DeviceKeyMaterial(
    val spki: ByteArray,
    val attestationChain: List<ByteArray>,
    val storage: KeyStorage,
)

class KeystoreException(message: String, cause: Throwable? = null) : Exception(message, cause)

sealed class SigningException(message: String, cause: Throwable? = null) : Exception(message, cause) {
    class KeyMissing : SigningException("The device binding key does not exist")
    class KeyInvalidated(cause: Throwable) : SigningException(
        "The device binding key was permanently invalidated (biometric enrollment changed or lock screen removed)",
        cause,
    )
    class Cancelled(val code: Int) : SigningException("Biometric authentication was cancelled")
    class Lockout(val permanent: Boolean) : SigningException(
        if (permanent) {
            "Biometric authentication is locked; unlock the device with its credential first"
        } else {
            "Too many failed attempts; biometric authentication is temporarily locked"
        },
    )
    class BiometricUnavailable(val code: Int, detail: String) : SigningException("Strong biometric unavailable: $detail")
    class Failed(detail: String, cause: Throwable? = null) : SigningException(detail, cause)
}

private const val ANDROID_KEYSTORE = "AndroidKeyStore"

// Android Key Attestation: KeyDescription extension of the leaf certificate
private const val KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17"

/** Keeps a chain only when it is a real key attestation: at least two certificates and a KeyDescription leaf. */
internal fun attestationChainOrEmpty(chain: List<ByteArray>): List<ByteArray> {
    if (chain.size < 2) return emptyList()
    val leaf = try {
        CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(chain[0])) as X509Certificate
    } catch (e: CertificateException) {
        return emptyList()
    }
    return if (leaf.getExtensionValue(KEY_DESCRIPTION_OID) != null) chain else emptyList()
}

class KeystoreManager(context: Context, private val alias: String = DEFAULT_ALIAS) {

    private val appContext = context.applicationContext

    fun exists(): Boolean = keyStore().containsAlias(alias)

    fun delete() {
        val store = keyStore()
        if (store.containsAlias(alias)) store.deleteEntry(alias)
    }

    fun publicKeySpki(): ByteArray =
        keyStore().getCertificate(alias)?.publicKey?.encoded ?: throw KeystoreException("Device binding key not found")

    fun generate(attestationChallenge: ByteArray?): DeviceKeyMaterial {
        require(attestationChallenge == null || attestationChallenge.size <= 128) {
            "Attestation challenge exceeds 128 bytes"
        }
        delete()
        val strongBox = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
                appContext.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
            ) {
                Api28.generatePreferringStrongBox(this, attestationChallenge)
            } else {
                generateKeyPair(strongBox = false, attestationChallenge = attestationChallenge)
                false
            }
        } catch (e: GeneralSecurityException) {
            throw KeystoreException("Device key generation failed: ${e.message}", e)
        } catch (e: ProviderException) {
            throw KeystoreException("Device key generation failed in the keystore: ${e.message}", e)
        }

        val store = keyStore()
        val chain = store.getCertificateChain(alias)?.map { it.encoded }
            ?: throw KeystoreException("Generated key has no certificate chain")
        val privateKey = store.getKey(alias, null) as? PrivateKey
            ?: throw KeystoreException("Generated key is not readable from the keystore")
        return DeviceKeyMaterial(
            spki = store.getCertificate(alias).publicKey.encoded,
            attestationChain = attestationChainOrEmpty(chain),
            storage = storageOf(privateKey, strongBox),
        )
    }

    suspend fun sign(
        activity: FragmentActivity,
        data: ByteArray,
        title: String,
        subtitle: String,
        negativeButtonText: String,
    ): ByteArray {
        val signature = withContext(Dispatchers.IO) { initSignature() }
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setNegativeButtonText(negativeButtonText)
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setConfirmationRequired(true)
            .build()
        val authorised = withContext(Dispatchers.Main) { authenticate(activity, promptInfo, signature) }
        return withContext(Dispatchers.IO) {
            try {
                authorised.update(data)
                authorised.sign()
            } catch (e: GeneralSecurityException) {
                throw SigningException.Failed("Keystore refused the signature: ${e.message}", e)
            } catch (e: ProviderException) {
                throw SigningException.Failed("Keystore refused the signature: ${e.message}", e)
            }
        }
    }

    private fun initSignature(): Signature {
        val privateKey = try {
            keyStore().getKey(alias, null) as? PrivateKey
        } catch (e: UnrecoverableKeyException) {
            throw SigningException.KeyInvalidated(e)
        } catch (e: GeneralSecurityException) {
            throw SigningException.Failed("Cannot load the device key: ${e.message}", e)
        } catch (e: IOException) {
            throw SigningException.Failed("Cannot load the device key: ${e.message}", e)
        } catch (e: ProviderException) {
            throw SigningException.Failed("Cannot load the device key: ${e.message}", e)
        } ?: throw SigningException.KeyMissing()
        return try {
            Signature.getInstance("SHA256withECDSA").apply { initSign(privateKey) }
        } catch (e: KeyPermanentlyInvalidatedException) {
            throw SigningException.KeyInvalidated(e)
        } catch (e: GeneralSecurityException) {
            throw SigningException.Failed("Cannot initialise the device signature: ${e.message}", e)
        } catch (e: ProviderException) {
            throw SigningException.Failed("Cannot initialise the device signature: ${e.message}", e)
        }
    }

    private suspend fun authenticate(
        activity: FragmentActivity,
        promptInfo: BiometricPrompt.PromptInfo,
        signature: Signature,
    ): Signature {
        // biometric 1.1.0 BiometricPrompt.authenticate returns without any callback once the fragment state is saved
        if (!activity.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED) ||
            activity.supportFragmentManager.isStateSaved
        ) {
            throw SigningException.Failed("The activity is not in the foreground")
        }
        return suspendCancellableCoroutine { continuation ->
            val callback = object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    if (!continuation.isActive) return
                    val authorised = result.cryptoObject?.signature
                    if (authorised == null) {
                        continuation.resumeWithException(
                            SigningException.Failed("Biometric result carries no authorised signature"),
                        )
                    } else {
                        continuation.resume(authorised)
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    if (continuation.isActive) continuation.resumeWithException(mapBiometricError(errorCode, errString))
                }
            }
            val prompt = BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), callback)
            continuation.invokeOnCancellation { activity.runOnUiThread { prompt.cancelAuthentication() } }
            prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(signature))
        }
    }

    private fun mapBiometricError(code: Int, message: CharSequence): SigningException = when (code) {
        BiometricPrompt.ERROR_USER_CANCELED,
        BiometricPrompt.ERROR_NEGATIVE_BUTTON,
        BiometricPrompt.ERROR_CANCELED -> SigningException.Cancelled(code)
        BiometricPrompt.ERROR_LOCKOUT -> SigningException.Lockout(permanent = false)
        BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> SigningException.Lockout(permanent = true)
        BiometricPrompt.ERROR_HW_UNAVAILABLE,
        BiometricPrompt.ERROR_HW_NOT_PRESENT,
        BiometricPrompt.ERROR_NO_BIOMETRICS,
        BiometricPrompt.ERROR_SECURITY_UPDATE_REQUIRED -> SigningException.BiometricUnavailable(code, message.toString())
        else -> SigningException.Failed("Biometric authentication failed ($code): $message")
    }

    private fun generateKeyPair(strongBox: Boolean, attestationChallenge: ByteArray?) {
        val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        } else {
            // API 23-29: a validity of -1 requires biometric authentication for every use
            @Suppress("DEPRECATION")
            builder.setUserAuthenticationValidityDurationSeconds(-1)
        }
        if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) builder.setIsStrongBoxBacked(true)
        if (attestationChallenge != null) builder.setAttestationChallenge(attestationChallenge)

        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        generator.initialize(builder.build())
        generator.generateKeyPair()
    }

    private fun storageOf(privateKey: PrivateKey, strongBoxRequested: Boolean): KeyStorage {
        val info = KeyFactory.getInstance(privateKey.algorithm, ANDROID_KEYSTORE)
            .getKeySpec(privateKey, KeyInfo::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            return when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> KeyStorage.STRONGBOX
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
                KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE -> KeyStorage.TEE
                else -> KeyStorage.SOFTWARE
            }
        }
        @Suppress("DEPRECATION")
        val secureHardware = info.isInsideSecureHardware
        return when {
            !secureHardware -> KeyStorage.SOFTWARE
            strongBoxRequested -> KeyStorage.STRONGBOX
            else -> KeyStorage.TEE
        }
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    @RequiresApi(Build.VERSION_CODES.P)
    private object Api28 {
        fun generatePreferringStrongBox(manager: KeystoreManager, attestationChallenge: ByteArray?): Boolean =
            try {
                manager.generateKeyPair(strongBox = true, attestationChallenge = attestationChallenge)
                true
            } catch (e: StrongBoxUnavailableException) {
                manager.delete()
                manager.generateKeyPair(strongBox = false, attestationChallenge = attestationChallenge)
                false
            }
    }

    companion object {
        const val DEFAULT_ALIAS = "device-binding"
    }
}
