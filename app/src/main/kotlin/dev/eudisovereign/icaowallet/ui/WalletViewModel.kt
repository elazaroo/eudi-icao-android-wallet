package dev.eudisovereign.icaowallet.ui

import android.app.Application
import android.content.pm.PackageManager
import android.nfc.NfcAdapter
import android.nfc.tech.IsoDep
import android.os.Build
import android.os.SystemClock
import androidx.biometric.BiometricManager
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.eudisovereign.icaowallet.R
import dev.eudisovereign.icaowallet.crypto.DeviceKeyMaterial
import dev.eudisovereign.icaowallet.crypto.KeystoreException
import dev.eudisovereign.icaowallet.crypto.KeystoreManager
import dev.eudisovereign.icaowallet.crypto.SigningException
import dev.eudisovereign.icaowallet.data.Enrollment
import dev.eudisovereign.icaowallet.data.EnrollmentStore
import dev.eudisovereign.icaowallet.data.EnrollmentStoreException
import dev.eudisovereign.icaowallet.nfc.AccessKey
import dev.eudisovereign.icaowallet.nfc.AccessKeyRules
import dev.eudisovereign.icaowallet.nfc.DniEPassportReader
import dev.eudisovereign.icaowallet.nfc.NfcAvailability
import dev.eudisovereign.icaowallet.nfc.ReadStep
import dev.eudisovereign.icaowallet.nfc.StepStatus
import dev.eudisovereign.icaowallet.nfc.TimedStep
import dev.eudisovereign.icaowallet.protocol.Binding
import dev.eudisovereign.icaowallet.protocol.DescriptorException
import dev.eudisovereign.icaowallet.protocol.Derivation
import dev.eudisovereign.icaowallet.protocol.PartFrame
import dev.eudisovereign.icaowallet.protocol.Presentation
import dev.eudisovereign.icaowallet.protocol.SealedEnvelope
import dev.eudisovereign.icaowallet.protocol.SessionDescriptor
import dev.eudisovereign.icaowallet.protocol.mrzOf
import dev.eudisovereign.icaowallet.protocol.tamperDg1
import dev.eudisovereign.icaowallet.report.Attestation
import dev.eudisovereign.icaowallet.report.BuildIdentity
import dev.eudisovereign.icaowallet.report.DocumentReport
import dev.eudisovereign.icaowallet.report.Mrz
import dev.eudisovereign.icaowallet.transport.PeerJsTransport
import dev.eudisovereign.icaowallet.transport.RelayTransport
import dev.eudisovereign.icaowallet.transport.Transport
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.ProviderException
import java.time.LocalDate
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class WalletViewModel(application: Application) : AndroidViewModel(application) {

    private val keystore = KeystoreManager(application)
    private val store = EnrollmentStore(application)
    private val reader = DniEPassportReader()

    private val _storeState = MutableStateFlow<StoreState>(StoreState.Loading)
    val storeState: StateFlow<StoreState> = _storeState.asStateFlow()

    private val _readiness = MutableStateFlow<Readiness?>(null)
    val readiness: StateFlow<Readiness?> = _readiness.asStateFlow()

    private val _accessKeyForm = MutableStateFlow(AccessKeyForm())
    val accessKeyForm: StateFlow<AccessKeyForm> = _accessKeyForm.asStateFlow()

    private val _identity = MutableStateFlow<IdentityState>(IdentityState.Loading)
    val identity: StateFlow<IdentityState> = _identity.asStateFlow()

    private val _enrolment = MutableStateFlow(EnrolmentState())
    val enrolment: StateFlow<EnrolmentState> = _enrolment.asStateFlow()

    private val _technical = MutableStateFlow<TechnicalState>(TechnicalState.Loading)
    val technical: StateFlow<TechnicalState> = _technical.asStateFlow()

    private val _scanner = MutableStateFlow(ScannerState())
    val scanner: StateFlow<ScannerState> = _scanner.asStateFlow()

    private val _presentation = MutableStateFlow(PresentationState())
    val presentation: StateFlow<PresentationState> = _presentation.asStateFlow()

    private val accepted = Channel<Unit>(Channel.CONFLATED)
    val descriptorAccepted: Flow<Unit> = accepted.receiveAsFlow()

    @Volatile private var enrolmentJob: Job? = null
    private val enrolmentLock = Any()
    private var armedKey: AccessKey? = null
    private var presentationJob: Job? = null
    private var technicalJob: Job? = null
    private val tagClaimed = AtomicBoolean(false)
    private val scanInFlight = AtomicBoolean(false)
    private var lastScanned: String? = null

    init {
        refreshReadiness()
        viewModelScope.launch {
            val state = readStore()
            if (state is StoreState.Empty) deleteOrphanKey()
            _storeState.value = state
        }
        viewModelScope.launch { _identity.value = withContext(Dispatchers.IO) { loadIdentity() } }
    }

    private fun loadIdentity(): IdentityState = try {
        IdentityState.Ready(BuildIdentity.of(getApplication()))
    } catch (e: PackageManager.NameNotFoundException) {
        IdentityState.Failed("Package not found: ${e.message}")
    } catch (e: IllegalStateException) {
        IdentityState.Failed(e.message ?: "PackageManager reports no signing certificate")
    }

    // A process killed during enrolment can leave a device key without a stored enrolment.
    private suspend fun deleteOrphanKey() {
        if (enrolmentJob?.isActive == true) return
        withContext(Dispatchers.IO) {
            // Best effort: a key left behind is unusable without an enrolment and the next enrolment replaces it.
            runCatching { if (keystore.exists()) keystore.delete() }
        }
    }

    // Returns null on success, otherwise the failure detail; the store state is refreshed either way.
    private suspend fun wipeEnrollment(): String? {
        val error = try {
            withContext(Dispatchers.IO) { keystore.delete() }
            store.clear()
            null
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Problems.detail(e)
        }
        _storeState.value = if (error == null) StoreState.Empty else readStore()
        return error
    }

    fun refreshReadiness() {
        viewModelScope.launch {
            _readiness.value = withContext(Dispatchers.IO) {
                val app = getApplication<Application>()
                val adapter = NfcAdapter.getDefaultAdapter(app)
                val nfc = when {
                    adapter == null -> NfcAvailability.NO_HARDWARE
                    adapter.isEnabled -> NfcAvailability.READY
                    else -> NfcAvailability.DISABLED
                }
                val biometric = BiometricReadiness.of(
                    BiometricManager.from(app).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG),
                )
                val camera = app.packageManager.hasSystemFeature(PackageManager.FEATURE_CAMERA_ANY)
                Readiness(nfc, biometric, camera)
            }
        }
    }

    fun deleteEnrollment() {
        if (enrolmentJob?.isActive == true || presentationJob?.isActive == true) return
        viewModelScope.launch {
            wipeEnrollment()?.let { _storeState.value = StoreState.Failed(Failure(Problem.DELETE_FAILED, it)) }
            _presentation.value = PresentationState()
        }
    }

    private fun editAccessKey(change: (AccessKeyForm) -> AccessKeyForm) {
        if (_enrolment.value.phase.busy) return
        _accessKeyForm.update(change)
    }

    fun setAccessKeyMode(mode: AccessKeyMode) = editAccessKey { it.copy(mode = mode) }

    fun setCan(value: String) = editAccessKey { it.copy(can = AccessKeyRules.filterCan(value)) }

    fun setDocumentNumber(value: String) =
        editAccessKey { it.copy(documentNumber = AccessKeyRules.filterDocumentNumber(value)) }

    // A date of birth after today cannot be on a document; the expiry date may lie in either direction.
    fun setDateOfBirth(value: String) = editAccessKey {
        val digits = DateInput.filter(value)
        it.copy(birthInput = digits, dateOfBirth = DateInput.toYymmdd(digits, LocalDate.now()).orEmpty())
    }

    fun setDateOfExpiry(value: String) = editAccessKey {
        val digits = DateInput.filter(value)
        it.copy(expiryInput = digits, dateOfExpiry = DateInput.toYymmdd(digits).orEmpty())
    }

    fun prepareEnrolment() {
        if (_enrolment.value.phase.busy) return
        _enrolment.value = EnrolmentState()
    }

    fun armEnrolment() {
        if (_enrolment.value.phase.busy) return
        val form = _accessKeyForm.value
        val readiness = _readiness.value
        val formProblems = form.problems()
        val readinessProblems = readiness?.let(Problems::ofReadiness).orEmpty()
        val blocker = when {
            presentationJob?.isActive == true -> Failure(Problem.BUSY, "A presentation is in progress")
            readinessProblems.isNotEmpty() ->
                Failure(readinessProblems.first(), "NFC ${readiness?.nfc}, biometric ${readiness?.biometric}")
            readiness == null -> Failure(Problem.BUSY, "Device readiness has not been determined yet")
            formProblems.isNotEmpty() -> Failure(Problem.INVALID_INPUT, formProblems.joinToString("\n"))
            else -> null
        }
        if (blocker != null) {
            _enrolment.value = EnrolmentState(phase = EnrolmentPhase.FAILED, failure = blocker)
            return
        }
        synchronized(enrolmentLock) {
            armedKey = form.toAccessKey()
            tagClaimed.set(false)
            _enrolment.value = EnrolmentState(phase = EnrolmentPhase.WAITING)
        }
    }

    fun cancelEnrolment() {
        synchronized(enrolmentLock) {
            val job = enrolmentJob
            if (job?.isActive == true) {
                job.cancel()
            } else if (_enrolment.value.phase == EnrolmentPhase.WAITING) {
                armedKey = null
                _enrolment.value = EnrolmentState(phase = EnrolmentPhase.IDLE)
            }
        }
    }

    // Called by NFC reader mode on a binder thread.
    fun onTagDiscovered(isoDep: IsoDep) {
        synchronized(enrolmentLock) {
            if (_enrolment.value.phase != EnrolmentPhase.WAITING || !tagClaimed.compareAndSet(false, true)) return
            val accessKey = armedKey ?: return
            armedKey = null
            _enrolment.update { it.copy(phase = EnrolmentPhase.READING) }
            // UNDISPATCHED: a job cancelled before its first dispatch would skip runEnrolment and stay READING.
            enrolmentJob = viewModelScope.launch(start = CoroutineStart.UNDISPATCHED) { runEnrolment(isoDep, accessKey) }
        }
    }

    private suspend fun runEnrolment(isoDep: IsoDep, accessKey: AccessKey) {
        val started = ConcurrentHashMap<ReadStep, Long>()
        var key: DeviceKeyMaterial? = null
        var keyReplaced = false
        val hadEnrollment = _storeState.value is StoreState.Loaded
        try {
            val result = reader.read(
                isoDep = isoDep,
                accessKey = accessKey,
                bindDeviceKey = { sod ->
                    keyReplaced = true
                    // The old enrolment goes before its key, so no kill point leaves a document with a foreign key.
                    store.clear()
                    _storeState.value = StoreState.Empty
                    val material = withContext(Dispatchers.IO) {
                        keystore.generate(Derivation.attestationChallenge(sod))
                    }
                    key = material
                    material.spki
                },
                onProgress = { step, status -> onReadProgress(step, status, started) },
            )
            _enrolment.update { it.copy(phase = EnrolmentPhase.SAVING) }
            val material = key ?: throw IllegalStateException("The reader finished without generating a device key")
            if (result.binding == Binding.CA_ATTESTATION && material.attestationChain.isEmpty()) {
                throw KeystoreException(
                    "AndroidKeyStore returned no key attestation chain; " +
                        "binding ca-attestation cannot be used on this device",
                )
            }
            val enrollment = Enrollment.from(
                result = result,
                keyAttestation = material.attestationChain,
                keyStorage = material.storage,
                enrolledAtMillis = System.currentTimeMillis(),
                deviceModel = "${Build.MANUFACTURER} ${Build.MODEL}",
                osVersion = "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})",
            )
            store.save(enrollment)
            _accessKeyForm.update { AccessKeyForm(mode = it.mode) }
            _storeState.value = StoreState.Loaded(overview(enrollment))
            _enrolment.update { it.copy(phase = EnrolmentPhase.DONE, log = finalLog(result.steps, material)) }
        } catch (e: CancellationException) {
            val notice = withContext(NonCancellable) { discardKey(keyReplaced, hadEnrollment) }
            _enrolment.update {
                it.copy(
                    phase = EnrolmentPhase.CANCELLED,
                    failure = Failure(Problem.READ_CANCELLED, "The read was cancelled before it completed."),
                    notice = notice?.first,
                    noticeDetail = notice?.second,
                )
            }
            throw e
        } catch (e: Exception) {
            val notice = withContext(NonCancellable) { discardKey(keyReplaced, hadEnrollment) }
            _enrolment.update {
                it.copy(
                    phase = EnrolmentPhase.FAILED,
                    failure = Failure(Problems.ofEnrolment(e), Problems.detail(e)),
                    notice = notice?.first,
                    noticeDetail = notice?.second,
                )
            }
        }
    }

    private fun onReadProgress(step: ReadStep, status: StepStatus, started: MutableMap<ReadStep, Long>) {
        val now = SystemClock.elapsedRealtime()
        if (status == StepStatus.STARTED) started[step] = now
        val duration = if (status == StepStatus.DONE || status == StepStatus.FAILED) started[step]?.let { now - it } else null
        val entry = LogEntry(step, status, duration, null)
        _enrolment.update { state ->
            val index = state.log.indexOfFirst { it.step == step }
            val log = if (index >= 0) state.log.toMutableList().also { it[index] = entry } else state.log + entry
            state.copy(log = log)
        }
    }

    private fun finalLog(steps: List<TimedStep>, material: DeviceKeyMaterial): List<LogEntry> = steps.map { step ->
        val detail = if (step.step == ReadStep.DEVICE_KEY && step.status == StepStatus.DONE) {
            val chain = material.attestationChain.size
            "EC P-256 in ${material.storage.label}, attestation challenge SHA-256(EF.SOD), " +
                if (chain > 0) "attestation chain of $chain certificates" else "no attestation chain"
        } else {
            step.detail
        }
        val duration = step.durationMillis.takeIf { step.status != StepStatus.SKIPPED }
        LogEntry(step.step, step.status, duration, detail)
    }

    // Once DEVICE_KEY has started the previous enrolment is already deleted and its key is being replaced.
    private suspend fun discardKey(keyReplaced: Boolean, hadEnrollment: Boolean): Pair<EnrolmentNotice, String?>? {
        if (!keyReplaced) return null
        val error = wipeEnrollment()
        return when {
            error != null -> EnrolmentNotice.CLEANUP_FAILED to "Cleanup of the device key failed: $error"
            hadEnrollment -> EnrolmentNotice.PREVIOUS_DELETED to null
            else -> EnrolmentNotice.NEW_KEY_DELETED to null
        }
    }

    fun loadTechnical() {
        val loaded = _storeState.value as? StoreState.Loaded
        if (loaded == null) {
            technicalJob?.cancel()
            _technical.value = TechnicalState.Failed(
                Failure(Problem.NO_DOCUMENT, "There is no enrolled document to inspect."),
            )
            return
        }
        technicalJob?.cancel()
        _technical.value = TechnicalState.Loading
        technicalJob = viewModelScope.launch {
            val enrollment = loaded.overview.enrollment
            _technical.value = try {
                val report = withContext(Dispatchers.Default) { DocumentReport.build(enrollment) }
                TechnicalState.Ready(report, keyStatus(enrollment))
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                TechnicalState.Failed(Failure(Problem.TECHNICAL_UNAVAILABLE, "${e.javaClass.simpleName}: ${e.message}"))
            }
        }
    }

    fun resetScanner() {
        // A conflated channel holds at most one pending element.
        accepted.tryReceive()
        lastScanned = null
        _scanner.value = ScannerState()
    }

    // Called on the main thread by the barcode analyzer for every frame that contains a QR code.
    fun onQrScanned(text: String) {
        if (text == lastScanned || presentationJob?.isActive == true || !scanInFlight.compareAndSet(false, true)) return
        lastScanned = text
        viewModelScope.launch {
            try {
                val descriptor = withContext(Dispatchers.Default) { SessionDescriptor.parse(text) }
                _presentation.value = PresentationState(descriptor = descriptor)
                _scanner.value = ScannerState()
                accepted.trySend(Unit)
            } catch (e: DescriptorException) {
                _scanner.value = ScannerState(Failure(Problem.INVALID_CODE, e.message ?: "invalid descriptor"))
            } finally {
                scanInFlight.set(false)
            }
        }
    }

    fun selectTransport(choice: TransportChoice) {
        _presentation.update { state ->
            val allowed = state.phase != PresentationPhase.RUNNING && !state.consumed &&
                (choice == TransportChoice.PEERJS || state.descriptor?.relay != null)
            if (allowed) state.copy(transport = choice) else state
        }
    }

    fun setAlterDg1(enabled: Boolean) {
        _presentation.update { state ->
            if (state.phase != PresentationPhase.RUNNING && !state.consumed) state.copy(alterDg1 = enabled) else state
        }
    }

    fun cancelPresentation() {
        presentationJob?.cancel()
    }

    fun present(activity: FragmentActivity) {
        val state = _presentation.value
        val descriptor = state.descriptor ?: return
        if (presentationJob?.isActive == true || state.consumed) return
        val overview = (_storeState.value as? StoreState.Loaded)?.overview
        val biometric = _readiness.value?.biometric
        val blocker = when {
            enrolmentJob?.isActive == true || _enrolment.value.phase.busy ->
                Failure(Problem.BUSY, "Signing is not possible while an enrolment read is running.")
            overview == null -> Failure(Problem.NO_DOCUMENT, "Enrol a document before presenting it.")
            !overview.keyStatus.usable -> Failure(Problem.KEY_UNUSABLE, keyStatusDetail(overview.keyStatus))
            biometric != BiometricReadiness.READY -> Failure(
                biometric?.let(Problems::ofBiometric) ?: Problem.BIOMETRIC_UNAVAILABLE,
                "BiometricManager BIOMETRIC_STRONG: ${biometric ?: "status unknown"}",
            )
            else -> null
        }
        if (blocker != null || overview == null) {
            _presentation.update { it.copy(phase = PresentationPhase.FAILED, failure = blocker) }
            return
        }
        val enrollment = overview.enrollment
        val transportChoice = state.transport
        val alterDg1 = state.alterDg1
        val promptTitle = activity.getString(R.string.biometric_title)
        val promptCancel = activity.getString(R.string.action_cancel)
        _presentation.update {
            it.copy(
                phase = PresentationPhase.RUNNING,
                stages = PresentationStage.entries.map { stage -> StageEntry(stage, StageStatus.PENDING, null, null) },
                result = null,
                failure = null,
            )
        }
        presentationJob = viewModelScope.launch {
            try {
                requireFresh(descriptor)
                val transcript = stage(PresentationStage.TRANSCRIPT, { "${it.size} bytes" }) {
                    Derivation.transcript(descriptor.nonce, descriptor.origin)
                }
                val signature = stage(PresentationStage.SIGNATURE, { "${it.size}-byte DER ECDSA-Sig-Value" }) {
                    keystore.sign(activity, transcript, promptTitle, descriptor.origin, promptCancel)
                }
                requireFresh(descriptor)
                val presentationJson = stage(
                    PresentationStage.PRESENTATION,
                    { "${it.toByteArray(Charsets.UTF_8).size} bytes, binding ${enrollment.binding.wireName}, " +
                        if (alterDg1) "EF.DG1 altered" else "EF.DG1 as read" },
                ) {
                    withContext(Dispatchers.Default) { buildPresentation(descriptor, enrollment, signature, alterDg1) }
                }
                val envelope = stage(
                    PresentationStage.ENVELOPE,
                    { envelopeDetail(it, transportChoice) },
                ) {
                    withContext(Dispatchers.Default) { SealedEnvelope.seal(descriptor, presentationJson) }
                }
                // Spec 2: the verifier consumes the session on the first presentation it receives.
                _presentation.update { it.copy(consumed = true) }
                val result = stage(PresentationStage.DELIVERY, { "result frame received, ok=${it.ok}" }) {
                    transportFor(transportChoice).deliver(descriptor, envelope)
                }
                _presentation.update { it.copy(phase = PresentationPhase.FINISHED, result = result) }
            } catch (e: CancellationException) {
                _presentation.update {
                    val failure = if (it.consumed) {
                        Failure(
                            Problem.CANCELLED_AFTER_SEND,
                            "Cancelled after delivery started; the verifier session may already be consumed.",
                        )
                    } else {
                        Failure(Problem.CANCELLED_BEFORE_SEND, "Cancelled before anything was sent to the verifier.")
                    }
                    it.copy(phase = PresentationPhase.FAILED, failure = failure)
                }
                throw e
            } catch (e: Exception) {
                val failure = if (e is SigningException.KeyInvalidated || e is SigningException.KeyMissing) {
                    withContext(NonCancellable) { discardDeadEnrollment(e) }
                } else {
                    Failure(Problems.ofPresentation(e), Problems.detail(e))
                }
                _presentation.update { it.copy(phase = PresentationPhase.FAILED, failure = failure) }
            }
        }
    }

    // A key that can never sign again makes the stored enrolment useless; keeping it only retains personal data.
    private suspend fun discardDeadEnrollment(e: SigningException): Failure {
        val error = wipeEnrollment()
        val detail = if (error == null) {
            "${e.message}. The enrolment was deleted; enrol the document again."
        } else {
            "${e.message}. Deleting the enrolment failed: $error"
        }
        return Failure(Problems.ofPresentation(e), detail)
    }

    private fun buildPresentation(
        descriptor: SessionDescriptor,
        enrollment: Enrollment,
        signature: ByteArray,
        alterDg1: Boolean,
    ): String = Presentation.build(
        nonce = descriptor.nonce,
        origin = descriptor.origin,
        dg1 = if (alterDg1) tamperDg1(enrollment.dg1) else enrollment.dg1,
        dg14 = enrollment.dg14,
        dg15 = enrollment.dg15,
        sod = enrollment.sod,
        devicePublicKey = enrollment.devicePublicKey,
        binding = enrollment.binding,
        chipSignatureOverDeviceKey = enrollment.aaResponse.takeIf { enrollment.binding == Binding.AA },
        keyAttestation = enrollment.keyAttestation,
        deviceSignatureOverNonce = signature,
        device = enrollment.deviceInfo(),
    ).toJson()

    private fun envelopeDetail(envelope: String, transport: TransportChoice): String {
        val size = envelope.toByteArray(Charsets.UTF_8).size
        return when (transport) {
            TransportChoice.PEERJS -> "$size bytes, ${PartFrame.split(envelope).size} part frame(s)"
            TransportChoice.RELAY -> "$size bytes, one PUT to the relay mailbox"
        }
    }

    private fun transportFor(choice: TransportChoice): Transport = when (choice) {
        TransportChoice.PEERJS -> PeerJsTransport(getApplication())
        TransportChoice.RELAY -> RelayTransport()
    }

    private fun requireFresh(descriptor: SessionDescriptor) {
        if (!descriptor.isFresh(System.currentTimeMillis())) {
            throw DescriptorException("The descriptor timestamp is now more than 5 minutes away from the device clock")
        }
    }

    private suspend fun <T> stage(stage: PresentationStage, describe: (T) -> String, block: suspend () -> T): T {
        val started = SystemClock.elapsedRealtime()
        setStage(stage, StageStatus.RUNNING, null, null)
        val value = try {
            block()
        } catch (e: CancellationException) {
            setStage(stage, StageStatus.CANCELLED, SystemClock.elapsedRealtime() - started, null)
            throw e
        } catch (e: Exception) {
            setStage(stage, StageStatus.FAILED, SystemClock.elapsedRealtime() - started, e.message)
            throw e
        }
        setStage(stage, StageStatus.DONE, SystemClock.elapsedRealtime() - started, describe(value))
        return value
    }

    private fun setStage(stage: PresentationStage, status: StageStatus, durationMillis: Long?, detail: String?) {
        _presentation.update { state ->
            state.copy(stages = state.stages.map { if (it.stage == stage) StageEntry(stage, status, durationMillis, detail) else it })
        }
    }

    private suspend fun readStore(): StoreState = try {
        val enrollment = store.load()
        if (enrollment == null) StoreState.Empty else StoreState.Loaded(overview(enrollment))
    } catch (e: EnrollmentStoreException) {
        StoreState.Failed(Failure(Problem.STORE_UNREADABLE, Problems.detail(e)))
    }

    private suspend fun overview(enrollment: Enrollment): EnrollmentOverview {
        val mrz = withContext(Dispatchers.Default) {
            try {
                Mrz.parse(mrzOf(enrollment.dg1))
            } catch (e: IllegalArgumentException) {
                null
            }
        }
        var attestationError: String? = null
        val attestationExpiry = withContext(Dispatchers.Default) {
            try {
                Attestation.chainExpiry(enrollment.keyAttestation)
            } catch (e: IllegalArgumentException) {
                attestationError = e.message ?: "the key attestation chain cannot be parsed"
                null
            }
        }
        return EnrollmentOverview(enrollment, mrz, keyStatus(enrollment), attestationExpiry, attestationError)
    }

    private suspend fun keyStatus(enrollment: Enrollment): DeviceKeyStatus = withContext(Dispatchers.IO) {
        try {
            when {
                !keystore.exists() -> DeviceKeyStatus.Missing
                keystore.publicKeySpki().contentEquals(enrollment.devicePublicKey) -> DeviceKeyStatus.Matches
                else -> DeviceKeyStatus.Different
            }
        } catch (e: GeneralSecurityException) {
            DeviceKeyStatus.Unreadable(e.message ?: e.javaClass.simpleName)
        } catch (e: IOException) {
            DeviceKeyStatus.Unreadable(e.message ?: e.javaClass.simpleName)
        } catch (e: KeystoreException) {
            DeviceKeyStatus.Unreadable(e.message ?: e.javaClass.simpleName)
        } catch (e: ProviderException) {
            DeviceKeyStatus.Unreadable(e.message ?: e.javaClass.simpleName)
        }
    }

    private fun keyStatusDetail(status: DeviceKeyStatus): String = when (status) {
        DeviceKeyStatus.Matches -> "AndroidKeyStore key matches the enrolment"
        DeviceKeyStatus.Missing -> "AndroidKeyStore has no device key"
        DeviceKeyStatus.Different -> "AndroidKeyStore holds a different key"
        is DeviceKeyStatus.Unreadable -> "AndroidKeyStore cannot be read: ${status.detail}"
    }
}
