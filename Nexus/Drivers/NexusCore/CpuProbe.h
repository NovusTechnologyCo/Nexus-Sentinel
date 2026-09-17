/**
 * @file CpuProbe.h
 * @brief Per-logical-processor trace-capability probe. Read-only: CPUID and MSR reads, nothing armed.
 *
 * ============================================================================================
 * WHY THIS IS BUILT BEFORE ANY TRACING, NOT ALONGSIDE IT
 * ============================================================================================
 *
 * Phase 4 has to choose between LBR and Intel PT and then size buffers, pick MSR ranges and decide
 * what a "branch record" even looks like. Every one of those choices is made FROM the values here.
 * Designing them against assumptions and probing afterwards means discovering the assumption was
 * wrong once the code already depends on it.
 *
 * ============================================================================================
 * ⚠ PER-CORE-TYPE, AND THAT IS THE ENTIRE POINT
 * ============================================================================================
 *
 * This machine is Arrow Lake-HX: HYBRID. P-cores and E-cores are different microarchitectures with
 * different PMU capabilities and, critically, different LBR DEPTHS. A single system-wide answer is
 * not merely imprecise, it is WRONG BY CONSTRUCTION -- it would be whichever core the probing thread
 * happened to be scheduled on.
 *
 * A tracer sized from a P-core's LBR depth and then run on an E-core reads entries that do not
 * exist. So every field here is collected ON EVERY LOGICAL PROCESSOR, via KeIpiGenericCall, and
 * reported per-CPU rather than reduced to one row.
 *
 * ============================================================================================
 * ⚠ READ-ONLY, AND DELIBERATELY SO
 * ============================================================================================
 *
 * Nothing here writes an MSR. Not one WRMSR, not even to a facility we intend to use. A probe that
 * enables things is not a probe -- it is the tracer, arriving early and untested. The write path
 * gets built once this has said what exists, and gets to be reviewed on its own terms.
 *
 * ⚠ AND RDMSR ON AN UNIMPLEMENTED MSR RAISES #GP, which this driver cannot catch (no SEH). So every
 * MSR read below is gated on the CPUID bit that guarantees the MSR exists. That gating is not
 * defensive style; an ungated read is a bugcheck on the first machine that lacks the feature.
 */

#pragma once

#include <ntddk.h>
#include "../../Include/NexusCommand.h"

/**
 * Probe every logical processor.
 *
 * @param Out    receives up to @p Cap entries, one per logical processor, indexed by CPU number
 * @param Got    entries written
 * @param Total  logical processors that exist -- separate from Got so truncation cannot read as
 *               completeness
 */
NTSTATUS NxcCpuProbe(
	_Out_writes_(Cap) NXCMD_CPU_TRACE_CAPS* Out,
	_In_ UINT32 Cap,
	_Out_ UINT32* Got,
	_Out_ UINT32* Total
	);
