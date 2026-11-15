package dev.eudisovereign.icaowallet.ui

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.ImageAnalysis
import androidx.camera.mlkit.vision.MlKitAnalyzer
import androidx.camera.view.CameraController
import androidx.camera.view.LifecycleCameraController
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LifecycleResumeEffect
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.google.mlkit.vision.barcode.BarcodeScannerOptions
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import dev.eudisovereign.icaowallet.R

@Composable
fun ScannerScreen(viewModel: WalletViewModel, onBack: () -> Unit, onAccepted: () -> Unit) {
    val context = LocalContext.current
    val scanner by viewModel.scanner.collectAsStateWithLifecycle()
    var granted by remember { mutableStateOf(hasCameraPermission(context)) }
    var requested by rememberSaveable { mutableStateOf(false) }
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { result ->
        granted = result
        requested = true
    }
    val currentOnAccepted by rememberUpdatedState(onAccepted)
    val cameraDescription = stringResource(R.string.scan_camera_description)

    LifecycleResumeEffect(Unit) {
        granted = hasCameraPermission(context)
        onPauseOrDispose { }
    }
    LaunchedEffect(Unit) {
        if (!granted && !requested) launcher.launch(Manifest.permission.CAMERA)
    }
    LaunchedEffect(viewModel) {
        viewModel.descriptorAccepted.collect { currentOnAccepted() }
    }

    ScreenScaffold(title = stringResource(R.string.scan_title), onBack = onBack) {
        if (granted) {
            Box(
                Modifier
                    .fillMaxWidth()
                    .aspectRatio(1f)
                    .semantics { contentDescription = cameraDescription },
            ) {
                QrCameraPreview(onText = viewModel::onQrScanned)
            }
            Body(stringResource(R.string.scan_instructions))
        } else {
            Body(stringResource(R.string.scan_permission_text))
            PrimaryAction(stringResource(R.string.scan_permission_request)) { launcher.launch(Manifest.permission.CAMERA) }
            if (requested) {
                SecondaryAction(stringResource(R.string.scan_open_app_settings)) {
                    openSettings(
                        context,
                        Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", context.packageName, null)),
                    )
                }
            }
        }
        scanner.rejection?.let {
            ProblemCard(it)
            Note(stringResource(R.string.scan_continues))
        }
    }
}

@Composable
private fun QrCameraPreview(onText: (String) -> Unit) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val currentOnText by rememberUpdatedState(onText)
    val controller = remember(context) {
        LifecycleCameraController(context).apply { setEnabledUseCases(CameraController.IMAGE_ANALYSIS) }
    }

    DisposableEffect(controller, lifecycleOwner) {
        val options = BarcodeScannerOptions.Builder().setBarcodeFormats(Barcode.FORMAT_QR_CODE).build()
        val barcodeScanner = BarcodeScanning.getClient(options)
        val executor = ContextCompat.getMainExecutor(context)
        val analyzer = MlKitAnalyzer(listOf(barcodeScanner), ImageAnalysis.COORDINATE_SYSTEM_ORIGINAL, executor) { result ->
            result.getValue(barcodeScanner)?.firstNotNullOfOrNull { it.rawValue }?.let { currentOnText(it) }
        }
        controller.setImageAnalysisAnalyzer(executor, analyzer)
        controller.bindToLifecycle(lifecycleOwner)
        onDispose {
            controller.clearImageAnalysisAnalyzer()
            controller.unbind()
            barcodeScanner.close()
        }
    }

    AndroidView(
        factory = { viewContext ->
            PreviewView(viewContext).apply {
                scaleType = PreviewView.ScaleType.FILL_CENTER
                this.controller = controller
            }
        },
        modifier = Modifier.fillMaxSize(),
    )
}

private fun hasCameraPermission(context: Context): Boolean =
    ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED
