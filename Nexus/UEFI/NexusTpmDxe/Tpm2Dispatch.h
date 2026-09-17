/**
 * @file Tpm2Dispatch.h
 * @brief The TPM command dispatcher, shared by the DXE and the kernel-side CRB servicer.
 *
 * WHY IT IS ITS OWN FILE. The dispatch logic lived inside `Tcg2SubmitCommand`, wrapped in
 * `EFI_STATUS` returns. G1 needs the SAME logic running after `ExitBootServices`, where there is
 * no EFI at all — and two copies of a TPM command dispatcher is how a TPM starts answering one
 * thing to the boot loader and another to the OS.
 *
 * ⚠ DEPENDENCY-FREE, AND THAT IS WHAT MAKES G1 POSSIBLE. Like `Tpm2Core.c` and `Tpm2Hash.c`, this
 * includes nothing but its own headers: no EFI, no WDK, no CRT. That property was adopted so the
 * code could be validated on the host with no reboot; it turns out to be the reason the same
 * object can compile into a UEFI driver AND a Windows kernel driver.
 *
 * ⚠ IT ALWAYS PRODUCES A WELL-FORMED RESPONSE. There is no failure path that leaves the output
 * buffer untouched (given room for a 10-byte header). A caller that cannot tell "the TPM refused"
 * from "the transport broke" will misdiagnose every failure, and a CRB peer polling for a response
 * that never arrives just times out with no information.
 *
 * ⚠ AND IT REPORTS WHAT IT WAS ASKED, via TPM2_DISPATCH_INFO. That is not instrumentation for its
 * own sake: we do not yet know which commands Windows sends after it takes the TPM out of Idle,
 * and guessing the list is how this project has wasted reboots before. The servicer publishes the
 * trace; the next build implements exactly what turned up in it.
 */

#pragma once

#include "Tpm2Core.h"

/**
 * What a dispatch actually did. Filled in even for malformed input, so a trace records the
 * refusals as faithfully as the successes -- a command we rejected is the most interesting kind.
 */
typedef struct _TPM2_DISPATCH_INFO {
	UINT16 Tag;              // as parsed from the command; 0 if it could not be parsed
	UINT32 CommandSize;      // as DECLARED by the command header
	UINT32 CommandCode;      // 0 if the header was unusable
	UINT32 ResponseCode;     // the TPM_RC we answered with
	UINT32 ResponseSize;     // bytes written to Out
	UINT32 InputSize;        // bytes we were actually handed, which may differ from CommandSize
} TPM2_DISPATCH_INFO;

/**
 * A source of real entropy, installed by the platform.
 *
 * ⚠ THE DISPATCHER CANNOT PRODUCE THIS ITSELF. It includes nothing but its own headers -- no
 * RDRAND intrinsic, no EFI, no WDK -- which is the property that lets one dispatcher serve the
 * DXE, the kernel and the host harness. Entropy is therefore injected, and each environment
 * installs whatever it genuinely has.
 *
 * @return TRUE only if Bytes bytes of real entropy were written. A partial fill is a failure,
 *         not a partial success: half a random buffer is a fully predictable one.
 */
typedef BOOLEAN (*TPM2_ENTROPY_FN)(OUT UINT8* Out, IN UINT32 Bytes);

/**
 * Install the entropy source. Passing NULL removes it.
 *
 * ⚠ WITH NO SOURCE INSTALLED, TPM2_GetRandom ANSWERS TPM_RC_FAILURE. It does not fall back to
 * a counter or a TSC hash. A TPM handing out predictable bytes labelled random is worse than
 * one that refuses: the caller cannot tell, and every key derived from them is compromised
 * silently.
 */
VOID Tpm2SetEntropySource(IN TPM2_ENTROPY_FN Fn);

/**
 * A monotonic millisecond clock, installed by the platform.
 *
 * ⚠ INJECTED FOR THE SAME REASON AS ENTROPY: the dispatcher includes nothing but its own
 * headers, so it cannot reach a timer in either environment. NexusCore installs one built on
 * KeQueryPerformanceCounter, which reports its own frequency -- a TSC delta over an assumed
 * "3 GHz" was measured swinging 6x across boots on this machine, which is why that source is
 * not used anywhere here.
 *
 * @return TRUE only if a real elapsed time was written.
 */
typedef BOOLEAN (*TPM2_TIME_FN)(OUT UINT64* Milliseconds);

/**
 * Install the clock. Passing NULL removes it.
 *
 * ⚠ WITH NO CLOCK INSTALLED, TPM2_ReadClock ANSWERS TPM_RC_FAILURE, for the same reason
 * GetRandom does: an invented time is indistinguishable from a real one to the caller, and
 * Clock is used in attestation structures where a wrong value is a wrong signature.
 */
VOID Tpm2SetTimeSource(IN TPM2_TIME_FN Fn);

/**
 * Execute one TPM command.
 *
 * @param Bank      the PCR bank to operate on. May be NULL only if no PCR command arrives, and a
 *                  PCR command with a NULL bank answers TPM_RC_FAILURE rather than dereferencing.
 * @param In        the command buffer, big-endian TPM wire format
 * @param InSize    bytes available in In
 * @param Out       the response buffer
 * @param OutSize   bytes available in Out; must be >= TPM2_HEADER_SIZE for anything to be written
 * @param Info      optional; filled with what happened
 *
 * @return the number of bytes written to Out, or 0 if OutSize was too small for even a header.
 */
UINT32
Tpm2Dispatch(
	IN OUT TPM2_PCR_BANK*     Bank,
	IN     CONST UINT8*       In,
	IN     UINT32             InSize,
	OUT    UINT8*             Out,
	IN     UINT32             OutSize,
	OUT    TPM2_DISPATCH_INFO* Info
	);
