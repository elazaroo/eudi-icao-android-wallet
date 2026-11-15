package dev.eudisovereign.icaowallet.crypto

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext

/** A class 3 biometric confirmation by the user, without a crypto object: no key is unlocked by it. */
object BiometricConfirmation {

    suspend fun confirm(activity: FragmentActivity, title: String, subtitle: String, negativeButtonText: String) {
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setNegativeButtonText(negativeButtonText)
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setConfirmationRequired(true)
            .build()
        withContext(Dispatchers.Main) {
            // biometric 1.1.0 BiometricPrompt.authenticate returns without any callback once the fragment state is saved
            if (!activity.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED) ||
                activity.supportFragmentManager.isStateSaved
            ) {
                throw SigningException.Failed("The activity is not in the foreground")
            }
            suspendCancellableCoroutine<Unit> { continuation ->
                val callback = object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        if (continuation.isActive) continuation.resume(Unit)
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        if (continuation.isActive) continuation.resumeWithException(errorOf(errorCode, errString))
                    }
                }
                val prompt = BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), callback)
                continuation.invokeOnCancellation { activity.runOnUiThread { prompt.cancelAuthentication() } }
                prompt.authenticate(promptInfo)
            }
        }
    }

    private fun errorOf(code: Int, message: CharSequence): SigningException = when (code) {
        BiometricPrompt.ERROR_USER_CANCELED,
        BiometricPrompt.ERROR_NEGATIVE_BUTTON,
        BiometricPrompt.ERROR_CANCELED -> SigningException.Cancelled(code)
        BiometricPrompt.ERROR_LOCKOUT -> SigningException.Lockout(permanent = false)
        BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> SigningException.Lockout(permanent = true)
        BiometricPrompt.ERROR_HW_UNAVAILABLE,
        BiometricPrompt.ERROR_HW_NOT_PRESENT,
        BiometricPrompt.ERROR_NO_BIOMETRICS,
        BiometricPrompt.ERROR_SECURITY_UPDATE_REQUIRED -> SigningException.BiometricUnavailable(code, message.toString())
        else -> SigningException.Failed("Biometric confirmation failed ($code): $message")
    }
}
