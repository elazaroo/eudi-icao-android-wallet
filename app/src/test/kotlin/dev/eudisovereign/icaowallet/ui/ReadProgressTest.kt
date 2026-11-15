package dev.eudisovereign.icaowallet.ui

import dev.eudisovereign.icaowallet.nfc.ReadStep
import dev.eudisovereign.icaowallet.nfc.StepStatus
import org.junit.Assert.assertEquals
import org.junit.Test

class ReadProgressTest {

    private fun entry(step: ReadStep, status: StepStatus) = LogEntry(step, status, null, null)

    private fun statuses(vararg entries: LogEntry, phase: EnrolmentPhase = EnrolmentPhase.READING) =
        ReadProgress.statuses(entries.toList(), phase)

    @Test
    fun everyReaderStepBelongsToAPlainPhase() {
        assertEquals(ReadPhase.CONNECTING, ReadProgress.phaseOf(ReadStep.CONNECT))
        assertEquals(ReadPhase.UNLOCKING, ReadProgress.phaseOf(ReadStep.PACE))
        assertEquals(ReadPhase.UNLOCKING, ReadProgress.phaseOf(ReadStep.BAC))
        assertEquals(ReadPhase.READING, ReadProgress.phaseOf(ReadStep.READ_DG14))
        assertEquals(ReadPhase.CHECKING, ReadProgress.phaseOf(ReadStep.CHIP_AUTHENTICATION))
        assertEquals(ReadPhase.SECURE_KEY, ReadProgress.phaseOf(ReadStep.DEVICE_KEY))
        assertEquals(ReadPhase.SECURE_KEY, ReadProgress.phaseOf(ReadStep.ACTIVE_AUTHENTICATION))
        val phases = ReadStep.entries.map(ReadProgress::phaseOf)
        assertEquals(phases.sortedBy { it.ordinal }, phases)
    }

    @Test
    fun waitingShowsNothingActive() {
        assertEquals(setOf(PhaseStatus.PENDING), statuses(phase = EnrolmentPhase.WAITING).values.toSet())
    }

    @Test
    fun readingWithoutStepsShowsConnecting() {
        val result = statuses()
        assertEquals(PhaseStatus.ACTIVE, result[ReadPhase.CONNECTING])
        assertEquals(PhaseStatus.PENDING, result[ReadPhase.UNLOCKING])
    }

    @Test
    fun earlierPhasesAreDoneAndLaterPhasesPending() {
        val result = statuses(
            entry(ReadStep.CONNECT, StepStatus.DONE),
            entry(ReadStep.CARD_ACCESS, StepStatus.DONE),
            entry(ReadStep.PACE, StepStatus.DONE),
            entry(ReadStep.BAC, StepStatus.SKIPPED),
            entry(ReadStep.SELECT_APPLET, StepStatus.DONE),
            entry(ReadStep.READ_SOD, StepStatus.STARTED),
        )
        assertEquals(PhaseStatus.DONE, result[ReadPhase.CONNECTING])
        assertEquals(PhaseStatus.DONE, result[ReadPhase.UNLOCKING])
        assertEquals(PhaseStatus.ACTIVE, result[ReadPhase.READING])
        assertEquals(PhaseStatus.PENDING, result[ReadPhase.CHECKING])
        assertEquals(PhaseStatus.PENDING, result[ReadPhase.SECURE_KEY])
        assertEquals(0.4f, ReadProgress.fraction(result), 0.0001f)
    }

    @Test
    fun skippedStepsDoNotAdvanceThePhase() {
        val result = statuses(
            entry(ReadStep.CONNECT, StepStatus.DONE),
            entry(ReadStep.CARD_ACCESS, StepStatus.DONE),
            entry(ReadStep.PACE, StepStatus.SKIPPED),
        )
        assertEquals(PhaseStatus.ACTIVE, result[ReadPhase.CONNECTING])
        assertEquals(PhaseStatus.PENDING, result[ReadPhase.UNLOCKING])
    }

    @Test
    fun aFailedStepMarksItsPhase() {
        val result = statuses(
            entry(ReadStep.CONNECT, StepStatus.DONE),
            entry(ReadStep.CARD_ACCESS, StepStatus.DONE),
            entry(ReadStep.PACE, StepStatus.FAILED),
            phase = EnrolmentPhase.FAILED,
        )
        assertEquals(PhaseStatus.DONE, result[ReadPhase.CONNECTING])
        assertEquals(PhaseStatus.FAILED, result[ReadPhase.UNLOCKING])
        assertEquals(PhaseStatus.PENDING, result[ReadPhase.READING])
    }

    @Test
    fun doneCompletesEveryPhase() {
        val result = statuses(phase = EnrolmentPhase.DONE)
        assertEquals(setOf(PhaseStatus.DONE), result.values.toSet())
        assertEquals(1f, ReadProgress.fraction(result), 0f)
    }

    @Test
    fun documentKindFollowsTheDocumentCode() {
        assertEquals(DocumentKind.PASSPORT, ReadProgress.documentKind("P", "ESP"))
        assertEquals(DocumentKind.DNI, ReadProgress.documentKind("ID", "ESP"))
        assertEquals(DocumentKind.IDENTITY_CARD, ReadProgress.documentKind("I", "UTO"))
        assertEquals(DocumentKind.VISA, ReadProgress.documentKind("V", "UTO"))
        assertEquals(DocumentKind.OTHER, ReadProgress.documentKind("", ""))
    }
}
