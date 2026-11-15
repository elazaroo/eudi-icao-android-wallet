package dev.eudisovereign.icaowallet.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import kotlinx.serialization.Serializable

@Serializable
internal object HomeRoute

@Serializable
internal object EnrolmentRoute

@Serializable
internal object TechnicalRoute

@Serializable
internal object ScannerRoute

@Serializable
internal object PresentationRoute

@Composable
fun WalletApp(viewModel: WalletViewModel) {
    val nav = rememberNavController()
    val back: () -> Unit = { nav.popBackStack() }
    val openScanner: () -> Unit = {
        viewModel.resetScanner()
        nav.navigate(ScannerRoute) {
            popUpTo(HomeRoute)
            launchSingleTop = true
        }
    }

    NavHost(navController = nav, startDestination = HomeRoute) {
        composable<HomeRoute> {
            HomeScreen(
                viewModel = viewModel,
                onEnrol = {
                    viewModel.prepareEnrolment()
                    nav.navigate(EnrolmentRoute) { launchSingleTop = true }
                },
                onTechnical = { nav.navigate(TechnicalRoute) { launchSingleTop = true } },
                onScan = openScanner,
            )
        }
        composable<EnrolmentRoute> {
            EnrolmentScreen(viewModel = viewModel, onBack = back)
        }
        composable<TechnicalRoute> {
            TechnicalScreen(viewModel = viewModel, onBack = back)
        }
        composable<ScannerRoute> {
            ScannerScreen(
                viewModel = viewModel,
                onBack = back,
                onAccepted = {
                    nav.navigate(PresentationRoute) {
                        popUpTo(HomeRoute)
                        launchSingleTop = true
                    }
                },
            )
        }
        composable<PresentationRoute> {
            val age by viewModel.ageProof.collectAsStateWithLifecycle()
            if (age.descriptor != null) {
                AgeProofScreen(
                    viewModel = viewModel,
                    onBack = back,
                    onScanAgain = openScanner,
                    onTechnical = { nav.navigate(TechnicalRoute) { launchSingleTop = true } },
                )
            } else {
                PresentationScreen(viewModel = viewModel, onBack = back, onScanAgain = openScanner)
            }
        }
    }
}
