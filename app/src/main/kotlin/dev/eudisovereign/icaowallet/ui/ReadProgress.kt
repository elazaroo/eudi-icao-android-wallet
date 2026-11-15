package dev.eudisovereign.icaowallet.ui

import dev.eudisovereign.icaowallet.nfc.ReadStep
import dev.eudisovereign.icaowallet.nfc.StepStatus

enum class ReadPhase { CONNECTING, UNLOCKING, READING, CHECKING, SECURE_KEY }

enum class PhaseStatus { PENDING, ACTIVE, DONE, FAILED }

enum class DocumentKind { DNI, IDENTITY_CARD, PASSPORT, VISA, OTHER }

object ReadProgress {

    fun phaseOf(step: ReadStep): ReadPhase = when (step) {
        ReadStep.CONNECT, ReadStep.CARD_ACCESS -> ReadPhase.CONNECTING
        ReadStep.PACE, ReadStep.BAC, ReadStep.SELECT_APPLET -> ReadPhase.UNLOCKING
        ReadStep.READ_SOD, ReadStep.READ_DG1, ReadStep.READ_DG14, ReadStep.READ_DG15 -> ReadPhase.READING
        ReadStep.INTEGRITY, ReadStep.CHIP_AUTHENTICATION, ReadStep.CA_PROOF -> ReadPhase.CHECKING
        // Active Authentication signs a challenge derived from the new device key.
        ReadStep.DEVICE_KEY, ReadStep.ACTIVE_AUTHENTICATION -> ReadPhase.SECURE_KEY
    }

    /** One status per [ReadPhase], derived from the live reader log of the current attempt. */
    fun statuses(log: List<LogEntry>, phase: EnrolmentPhase): Map<ReadPhase, PhaseStatus> {
        if (phase == EnrolmentPhase.DONE) return ReadPhase.entries.associateWith { PhaseStatus.DONE }
        val last = log.lastOrNull { it.status != StepStatus.SKIPPED }
        val current = last?.let { phaseOf(it.step) }
        val failed = last?.status == StepStatus.FAILED
        return ReadPhase.entries.associateWith { p ->
            when {
                current == null -> if (p == ReadPhase.CONNECTING && phase == EnrolmentPhase.READING) PhaseStatus.ACTIVE else PhaseStatus.PENDING
                p.ordinal < current.ordinal -> PhaseStatus.DONE
                p.ordinal > current.ordinal -> PhaseStatus.PENDING
                failed -> PhaseStatus.FAILED
                else -> PhaseStatus.ACTIVE
            }
        }
    }

    fun fraction(statuses: Map<ReadPhase, PhaseStatus>): Float =
        statuses.values.count { it == PhaseStatus.DONE }.toFloat() / ReadPhase.entries.size

    fun documentKind(documentCode: String, issuingState: String): DocumentKind = when (documentCode.firstOrNull()) {
        'P' -> DocumentKind.PASSPORT
        'I', 'A', 'C' -> if (issuingState == "ESP") DocumentKind.DNI else DocumentKind.IDENTITY_CARD
        'V' -> DocumentKind.VISA
        else -> DocumentKind.OTHER
    }
}
