package dev.eudisovereign.icaowallet.nfc

import android.app.Activity
import android.nfc.NfcAdapter
import android.nfc.tech.IsoDep
import android.os.Bundle
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner

enum class NfcAvailability { NO_HARDWARE, DISABLED, READY }

object NfcReaderMode {

    // eMRTDs are ISO/IEC 14443-4 type A or B; skipping the NDEF check avoids extra APDUs before the callback.
    private const val FLAGS =
        NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_NFC_B or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK

    private const val PRESENCE_CHECK_DELAY_MS = 1000

    /** [onIsoDep] runs on a binder thread; tags without ISO-DEP are ignored. */
    fun enable(activity: Activity, onIsoDep: (IsoDep) -> Unit): Boolean {
        val adapter = NfcAdapter.getDefaultAdapter(activity) ?: return false
        val extras = Bundle().apply { putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, PRESENCE_CHECK_DELAY_MS) }
        adapter.enableReaderMode(activity, { tag -> IsoDep.get(tag)?.let(onIsoDep) }, FLAGS, extras)
        return true
    }

    fun disable(activity: Activity) {
        NfcAdapter.getDefaultAdapter(activity)?.disableReaderMode(activity)
    }
}

/** Keeps reader mode on while this composable is composed, [enabled] is true and the activity is resumed. */
@Composable
fun NfcReaderModeEffect(enabled: Boolean, onIsoDep: (IsoDep) -> Unit) {
    val activity = LocalContext.current as? Activity ?: return
    val lifecycleOwner = LocalLifecycleOwner.current
    val currentOnIsoDep by rememberUpdatedState(onIsoDep)

    DisposableEffect(activity, lifecycleOwner, enabled) {
        if (!enabled) return@DisposableEffect onDispose { }
        val observer = LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_RESUME -> NfcReaderMode.enable(activity) { currentOnIsoDep(it) }
                Lifecycle.Event.ON_PAUSE -> NfcReaderMode.disable(activity)
                else -> Unit
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        if (lifecycleOwner.lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) {
            NfcReaderMode.enable(activity) { currentOnIsoDep(it) }
        }
        onDispose {
            lifecycleOwner.lifecycle.removeObserver(observer)
            NfcReaderMode.disable(activity)
        }
    }
}
