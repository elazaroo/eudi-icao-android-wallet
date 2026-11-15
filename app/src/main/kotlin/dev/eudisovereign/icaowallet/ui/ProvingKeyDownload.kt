package dev.eudisovereign.icaowallet.ui

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Handler
import android.os.Looper
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import dev.eudisovereign.icaowallet.R
import dev.eudisovereign.icaowallet.ui.theme.StatusColors
import dev.eudisovereign.icaowallet.zk.ProvingKeyStore

/** Decimal megabyte, the unit in which the proving key is announced as 243 MB. */
const val MEGABYTE = 1_000_000L

enum class NetworkKind { NONE, METERED, UNMETERED }

@Composable
fun rememberNetworkKind(): NetworkKind {
    val context = LocalContext.current
    val manager = remember(context) { context.getSystemService(ConnectivityManager::class.java) }
    var kind by remember(manager) { mutableStateOf(currentNetworkKind(manager)) }
    DisposableEffect(manager) {
        if (manager == null) return@DisposableEffect onDispose {}
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
                kind = networkKind(capabilities)
            }

            override fun onLost(network: Network) {
                kind = NetworkKind.NONE
            }
        }
        manager.registerDefaultNetworkCallback(callback, Handler(Looper.getMainLooper()))
        onDispose { manager.unregisterNetworkCallback(callback) }
    }
    return kind
}

private fun currentNetworkKind(manager: ConnectivityManager?): NetworkKind {
    if (manager == null) return NetworkKind.UNMETERED
    val capabilities = manager.activeNetwork?.let(manager::getNetworkCapabilities) ?: return NetworkKind.NONE
    return networkKind(capabilities)
}

private fun networkKind(capabilities: NetworkCapabilities): NetworkKind {
    if (!capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return NetworkKind.NONE
    val unmetered = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) ||
        (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R &&
            capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_TEMPORARILY_NOT_METERED))
    return if (unmetered) NetworkKind.UNMETERED else NetworkKind.METERED
}

@Composable
fun NetworkNote(kind: NetworkKind) {
    when (kind) {
        NetworkKind.METERED -> Note(stringResource(R.string.key_download_metered), color = StatusColors.warn)
        NetworkKind.NONE -> Note(stringResource(R.string.key_download_offline), color = StatusColors.warn)
        NetworkKind.UNMETERED -> Unit
    }
}

@Composable
fun downloadProgressText(received: Long): String = stringResource(
    R.string.key_download_progress,
    received / MEGABYTE,
    provingKeyMegabytes,
    (received * 100 / ProvingKeyStore.EXPECTED_SIZE).coerceIn(0, 100),
)

@Composable
fun ProvingKeyProgressBar(received: Long) {
    LinearProgressIndicator(
        progress = { (received.toFloat() / ProvingKeyStore.EXPECTED_SIZE).coerceIn(0f, 1f) },
        modifier = Modifier.fillMaxWidth(),
    )
}

val provingKeyMegabytes: Long get() = (ProvingKeyStore.EXPECTED_SIZE + MEGABYTE / 2) / MEGABYTE
