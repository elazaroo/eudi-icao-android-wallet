package dev.eudisovereign.icaowallet

import android.content.pm.ApplicationInfo
import android.graphics.Color
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.getValue
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.eudisovereign.icaowallet.nfc.NfcReaderModeEffect
import dev.eudisovereign.icaowallet.ui.WalletApp
import dev.eudisovereign.icaowallet.ui.WalletViewModel
import dev.eudisovereign.icaowallet.ui.theme.WalletTheme

// androidx.biometric 1.1.0 hosts its prompt in a fragment, so the activity must be a FragmentActivity.
class MainActivity : FragmentActivity() {

    private lateinit var viewModel: WalletViewModel

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.dark(Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.dark(Color.TRANSPARENT),
        )
        super.onCreate(savedInstanceState)
        // MRZ and personal data stay out of screenshots and the recents thumbnail. Debug builds and builds made
        // with -PwalletAllowScreenCapture=true stay capturable.
        val debuggable = (applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        if (!debuggable && !BuildConfig.ALLOW_SCREEN_CAPTURE) {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
        viewModel = ViewModelProvider(this)[WalletViewModel::class.java]
        setContent {
            val enrolment by viewModel.enrolment.collectAsStateWithLifecycle()
            // Reader mode is armed only while an enrolment waits for or reads a document; it follows the resume state.
            NfcReaderModeEffect(enabled = enrolment.phase.acceptsTag, onIsoDep = viewModel::onTagDiscovered)
            WalletTheme {
                WalletApp(viewModel)
            }
        }
    }

    override fun onResume() {
        super.onResume()
        viewModel.refreshReadiness()
    }
}
