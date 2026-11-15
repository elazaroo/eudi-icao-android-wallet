package dev.eudisovereign.icaowallet.ui

import android.app.Application
import android.content.pm.PackageManager
import android.net.Uri
import android.nfc.NfcAdapter
import android.nfc.tech.IsoDep
import android.os.Build
import android.os.SystemClock
import androidx.biometric.BiometricManager
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.eudisovereign.icaowallet.R
import dev.eudisovereign.icaowallet.crypto.BiometricConfirmation
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
import dev.eudisovereign.icaowallet.protocol.AgeProofPresentation
import dev.eudisovereign.icaowallet.protocol.Binding
import dev.eudisovereign.icaowallet.protocol.DescriptorException
import dev.eudisovereign.icaowallet.protocol.Derivation
import dev.eudisovereign.icaowallet.protocol.Groth16Proof
import dev.eudisovereign.icaowallet.protocol.PartFrame
import dev.eudisovereign.icaowallet.protocol.Presentation
import dev.eudisovereign.icaowallet.protocol.SealedEnvelope
import dev.eudisovereign.icaowallet.protocol.SessionDescriptor
import dev.eudisovereign.icaowallet.protocol.SessionRequest
import dev.eudisovereign.icaowallet.protocol.UnsupportedRequestException
import dev.eudisovereign.icaowallet.protocol.mrzOf
import dev.eudisovereign.icaowallet.protocol.tamperDg1
import dev.eudisovereign.icaowallet.report.Attestation
import dev.eudisovereign.icaowallet.report.BuildIdentity
import dev.eudisovereign.icaowallet.report.DocumentReport
import dev.eudisovereign.icaowallet.report.Mrz
import dev.eudisovereign.icaowallet.transport.PeerJsTransport
import dev.eudisovereign.icaowallet.transport.RelayTransport
import dev.eudisovereign.icaowallet.transport.Transport
import dev.eudisovereign.icaowallet.zk.AgeProofStatement
import dev.eudisovereign.icaowallet.zk.AgeStatement
import dev.eudisovereign.icaowallet.zk.Groth16Prover
import dev.eudisovereign.icaowallet.zk.PreparedAgeProof
import dev.eudisovereign.icaowallet.zk.ProverException
import dev.eudisovereign.icaowallet.zk.ProvingKeyException
import dev.eudisovereign.icaowallet.zk.ProvingKeyStore
import dev.eudisovereign.icaowallet.zk.Witness
import dev.eudisovereign.icaowallet.zk.WitnessCalculator
import dev.eudisovereign.icaowallet.zk.prepareAgeProofInputs
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

private const val MAX_TRACE_CAUSES = 6

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

    private val provingKeys = ProvingKeyStore(application)

    private val _ageProof = MutableStateFlow(AgeProofState())
    val ageProof: StateFlow<AgeProofState> = _ageProof.asStateFlow()

    private val _provingKey = MutableStateFlow(ProvingKeyState())
    val provingKey: StateFlow<ProvingKeyState> = _provingKey.asStateFlow()

    private val accepted = Channel<Unit>(Channel.CONFLATED)
    val descriptorAccepted: Flow<Unit> = accepted.receiveAsFlow()

    @Volatile private var enrolmentJob: Job? = null
    private val enrolmentLock = Any()
    private var armedKey: AccessKey? = null
    private var presentationJob: Job? = null
    private var ageJob: Job? = null
    private var eligibilityJob: Job? = null
    private var keyImportJob: Job? = null
    private var keyDownloadJob: Job? = null
    private var keyRemoveJob: Job? = null
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
        viewModelScope.launch {
            _provingKey.value = ProvingKeyState(
                withContext(Dispatchers.IO) {
                    provingKeys.discardLeftovers()
                    provingKeyStatus()
                },
            )
        }
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
        if (enrolmentJob?.isActive == true || presentationJob?.isActive == true || ageJob?.isActive == true) return
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
            presentationJob?.isActive == true || ageJob?.isActive == true ->
                Failure(Problem.BUSY, "A presentation is in progress")
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
        if (text == lastScanned || presentationJob?.isActive == true || ageJob?.isActive == true ||
            !scanInFlight.compareAndSet(false, true)
        ) {
            return
        }
        lastScanned = text
        viewModelScope.launch {
            try {
                val descriptor = withContext(Dispatchers.Default) { SessionDescriptor.parse(text) }
                if (descriptor.request == SessionRequest.AGE_OVER_18) {
                    _presentation.value = PresentationState()
                    openAgeSession(descriptor)
                } else {
                    _ageProof.value = AgeProofState()
                    _presentation.value = PresentationState(descriptor = descriptor)
                }
                _scanner.value = ScannerState()
                accepted.trySend(Unit)
            } catch (e: DescriptorException) {
                val problem = if (e is UnsupportedRequestException) Problem.UNSUPPORTED_REQUEST else Problem.INVALID_CODE
                _scanner.value = ScannerState(Failure(problem, e.message ?: "invalid descriptor"))
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

    private fun provingKeyStatus(): ProvingKeyStatus =
        if (provingKeys.isInstalled()) ProvingKeyStatus.INSTALLED else ProvingKeyStatus.MISSING

    private val provingKeyBusy: Boolean
        get() = keyImportJob?.isActive == true || keyDownloadJob?.isActive == true || keyRemoveJob?.isActive == true ||
            ageJob?.isActive == true

    fun downloadProvingKey() {
        val current = _provingKey.value.status
        if (provingKeyBusy || current == ProvingKeyStatus.INSTALLED || current == ProvingKeyStatus.CHECKING) return
        _provingKey.value = ProvingKeyState(ProvingKeyStatus.DOWNLOADING)
        keyDownloadJob = viewModelScope.launch {
            val failure = try {
                provingKeys.download { received -> _provingKey.update { it.copy(copiedBytes = received) } }
                null
            } catch (e: CancellationException) {
                _provingKey.value = ProvingKeyState(
                    ProvingKeyStatus.MISSING,
                    failure = Failure(Problem.KEY_DOWNLOAD_CANCELLED, "The download was cancelled; the partial file was deleted."),
                )
                throw e
            } catch (e: Exception) {
                Problems.ofKeyDownload(e)
            }
            val status = withContext(Dispatchers.IO) { provingKeyStatus() }
            _provingKey.value = ProvingKeyState(status, failure = failure)
            if (status == ProvingKeyStatus.INSTALLED) expireStaleAgeSession()
        }
    }

    fun cancelProvingKeyDownload() {
        keyDownloadJob?.cancel()
    }

    fun removeProvingKey() {
        if (provingKeyBusy || _provingKey.value.status != ProvingKeyStatus.INSTALLED) return
        keyRemoveJob = viewModelScope.launch {
            val failure = withContext(Dispatchers.IO) {
                try {
                    provingKeys.remove()
                    null
                } catch (e: ProvingKeyException) {
                    Failure(Problem.KEY_REMOVE_FAILED, Problems.detail(e))
                }
            }
            _provingKey.value = ProvingKeyState(withContext(Dispatchers.IO) { provingKeyStatus() }, failure = failure)
        }
    }

    // A session that went stale during the download cannot be answered; the verifier needs a new code.
    private fun expireStaleAgeSession() {
        _ageProof.update { state ->
            val descriptor = state.descriptor
            val settled = state.consumed || state.result != null || state.phase == PresentationPhase.RUNNING
            if (descriptor == null || settled || descriptor.isFresh(System.currentTimeMillis())) {
                state
            } else {
                state.copy(
                    expired = true,
                    failure = Failure(
                        Problem.SESSION_EXPIRED,
                        "The session descriptor is more than 5 minutes old; it expired while the proving key was downloading.",
                    ),
                    failureTrace = null,
                )
            }
        }
    }

    fun importProvingKey(uri: Uri) {
        if (provingKeyBusy) return
        _provingKey.value = ProvingKeyState(ProvingKeyStatus.IMPORTING)
        keyImportJob = viewModelScope.launch {
            val failure = try {
                provingKeys.import(uri) { copied -> _provingKey.update { it.copy(copiedBytes = copied) } }
                null
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Failure(Problems.ofKeyImport(e), Problems.detail(e))
            }
            _provingKey.value = ProvingKeyState(withContext(Dispatchers.IO) { provingKeyStatus() }, failure = failure)
        }
    }

    private fun openAgeSession(descriptor: SessionDescriptor) {
        eligibilityJob?.cancel()
        _ageProof.value = AgeProofState(descriptor = descriptor)
        val enrollment = (_storeState.value as? StoreState.Loaded)?.overview?.enrollment ?: return
        eligibilityJob = viewModelScope.launch {
            val failure = withContext(Dispatchers.Default) {
                try {
                    prepareAgeProofInputs(enrollment.dg1, enrollment.sod, ageStatement(descriptor))
                    null
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    Failure(Problems.ofAgeProof(e), Problems.detail(e))
                }
            }
            _ageProof.update {
                if (it.descriptor === descriptor) it.copy(eligibilityChecked = true, notProvable = failure) else it
            }
        }
    }

    private fun ageStatement(descriptor: SessionDescriptor): AgeProofStatement = AgeProofStatement(
        currentDate = AgeStatement.dateNumber(System.currentTimeMillis()),
        ageThreshold = AgeStatement.AGE_THRESHOLD,
        challenge = AgeStatement.challenge(descriptor.nonce, descriptor.origin),
    )

    fun selectAgeTransport(choice: TransportChoice) {
        _ageProof.update { state ->
            val allowed = state.phase != PresentationPhase.RUNNING && !state.consumed &&
                (choice == TransportChoice.PEERJS || state.descriptor?.relay != null)
            if (allowed) state.copy(transport = choice) else state
        }
    }

    fun cancelAgeProof() {
        ageJob?.cancel()
    }

    fun proveAge(activity: FragmentActivity) {
        val state = _ageProof.value
        val descriptor = state.descriptor ?: return
        if (ageJob?.isActive == true || state.consumed) return
        val enrollment = (_storeState.value as? StoreState.Loaded)?.overview?.enrollment
        val biometric = _readiness.value?.biometric
        val blocker = when {
            enrolmentJob?.isActive == true || _enrolment.value.phase.busy ->
                Failure(Problem.BUSY, "The age proof is not possible while an enrolment read is running.")
            presentationJob?.isActive == true -> Failure(Problem.BUSY, "A presentation is in progress")
            keyImportJob?.isActive == true -> Failure(Problem.BUSY, "The proving key is being imported")
            keyDownloadJob?.isActive == true -> Failure(Problem.BUSY, "The proving key is being downloaded")
            enrollment == null -> Failure(Problem.NO_DOCUMENT, "Enrol a document before proving its holder's age.")
            !provingKeys.isInstalled() ->
                Failure(Problem.PROVING_KEY_MISSING, "${ProvingKeyStore.FILE_NAME} is not in the app storage")
            biometric != BiometricReadiness.READY -> Failure(
                biometric?.let(Problems::ofBiometric) ?: Problem.BIOMETRIC_UNAVAILABLE,
                "BiometricManager BIOMETRIC_STRONG: ${biometric ?: "status unknown"}",
            )
            else -> null
        }
        if (blocker != null || enrollment == null) {
            _ageProof.update { it.copy(phase = PresentationPhase.FAILED, failure = blocker, failureTrace = null) }
            return
        }
        val transportChoice = state.transport
        val promptTitle = activity.getString(R.string.age_biometric_title)
        val promptCancel = activity.getString(R.string.action_cancel)
        _ageProof.update {
            it.copy(
                phase = PresentationPhase.RUNNING,
                stages = AgeStage.entries.map { stage -> AgeStageEntry(stage, StageStatus.PENDING, null, null) },
                result = null,
                failure = null,
                failureTrace = null,
            )
        }
        ageJob = viewModelScope.launch {
            try {
                requireFresh(descriptor)
                ageStage(AgeStage.CONFIRMATION, { "confirmed; no device key is used" }) {
                    BiometricConfirmation.confirm(activity, promptTitle, descriptor.origin, promptCancel)
                }
                val keyFile = provingKeys.requireInstalled()
                val statement = ageStatement(descriptor)
                val (prepared, inputsJson) = ageStage(AgeStage.INPUTS, ::describeInputs) {
                    withContext(Dispatchers.Default) {
                        val prepared = prepareAgeProofInputs(enrollment.dg1, enrollment.sod, statement)
                        prepared to prepared.inputs.toJson()
                    }
                }
                val output = run {
                    val witness = ageStage(AgeStage.WITNESS, ::describeWitness) {
                        WitnessCalculator(getApplication()).calculate(inputsJson)
                    }
                    ageStage(AgeStage.PROOF, { "proof ${it.first.length} bytes, public signals ${it.second.length} bytes" }) {
                        val raw = withContext(Dispatchers.Default) { Groth16Prover.prove(keyFile, witness.bytes) }
                        raw.proofJson to raw.publicSignalsJson
                    }
                }
                val envelope = ageStage(AgeStage.ENVELOPE, { it.second }) {
                    withContext(Dispatchers.Default) {
                        val proof = Groth16Proof.parse(output.first)
                        val signals = Groth16Proof.parsePublicSignals(output.second)
                        val expected = AgeStatement.publicSignals(
                            prepared.modulus,
                            statement.currentDate,
                            statement.ageThreshold,
                            statement.challenge,
                        )
                        val mismatch = expected.indices.firstOrNull { signals[it] != expected[it] }
                        if (mismatch != null) {
                            throw ProverException("public signal $mismatch is ${signals[mismatch]}, the statement has ${expected[mismatch]}")
                        }
                        val plaintext = AgeProofPresentation.build(prepared.dsCertificate, proof, signals).toJson()
                        requireFresh(descriptor)
                        val sealed = SealedEnvelope.seal(descriptor, plaintext)
                        val ageSeconds = (System.currentTimeMillis() - descriptor.timestamp) / 1000
                        sealed to "plaintext ${plaintext.toByteArray(Charsets.UTF_8).size} bytes " +
                            "(dsCertificate ${prepared.dsCertificate.size} bytes), envelope: " +
                            envelopeDetail(sealed, transportChoice) + "; session age $ageSeconds s"
                    }
                }.first
                _ageProof.update { it.copy(consumed = true) }
                val result = ageStage(AgeStage.DELIVERY, { "result frame received, ok=${it.ok}" }) {
                    transportFor(transportChoice).deliver(descriptor, envelope)
                }
                _ageProof.update { it.copy(phase = PresentationPhase.FINISHED, result = result) }
            } catch (e: CancellationException) {
                _ageProof.update {
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
                _ageProof.update {
                    it.copy(
                        phase = PresentationPhase.FAILED,
                        failure = Failure(Problems.ofAgeProof(e), Problems.detail(e)),
                        failureTrace = failureTrace(e),
                    )
                }
            }
        }
    }

    private fun describeInputs(value: Pair<PreparedAgeProof, String>): String {
        val prepared = value.first
        return "${prepared.profile}, hash parameters ${prepared.hashParameters.name.lowercase()}, " +
            "signedAttrs ${prepared.signedAttrsLength} bytes, eContent ${prepared.eContentLength} bytes, " +
            "inputs JSON ${value.second.length} bytes"
    }

    private fun describeWitness(witness: Witness): String =
        "${witness.bytes.size} bytes; wasm load and compile ${witness.loadMillis} ms, " +
            "calculation ${witness.computeMillis} ms, transfer ${witness.transferMillis} ms"

    private fun failureTrace(e: Throwable): String = generateSequence(e) { it.cause }
        .take(MAX_TRACE_CAUSES)
        .joinToString("\ncaused by ") { "${it.javaClass.name}: ${it.message}" }

    private suspend fun <T> ageStage(stage: AgeStage, describe: (T) -> String, block: suspend () -> T): T {
        val started = SystemClock.elapsedRealtime()
        setAgeStage(stage, StageStatus.RUNNING, null, null)
        val value = try {
            block()
        } catch (e: CancellationException) {
            setAgeStage(stage, StageStatus.CANCELLED, SystemClock.elapsedRealtime() - started, null)
            throw e
        } catch (e: Exception) {
            setAgeStage(stage, StageStatus.FAILED, SystemClock.elapsedRealtime() - started, "${e.javaClass.simpleName}: ${e.message}")
            throw e
        }
        setAgeStage(stage, StageStatus.DONE, SystemClock.elapsedRealtime() - started, describe(value))
        return value
    }

    private fun setAgeStage(stage: AgeStage, status: StageStatus, durationMillis: Long?, detail: String?) {
        _ageProof.update { state ->
            state.copy(stages = state.stages.map { if (it.stage == stage) AgeStageEntry(stage, status, durationMillis, detail) else it })
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
