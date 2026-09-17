/**
 * @file TcgLogSanitize.h
 * @brief Tier 3 of the Secure Boot spoof: rewrite the TCG event log IN PLACE at its ACPI address.
 *
 * Read the design notes (including the DISPROVED banner) before changing this.
 *
 * WHY IT EXISTS. Tier 1 (the gRT->GetVariable hook) makes the `SecureBoot` variable and the kernel's
 * own belief report enabled, but it cannot touch PCR[7] -- MEASURED: the firmware extended events
 * 18-22 during DXE dispatch, before any ESP-loaded image runs, and extends are one-way. A checker
 * that walks the TCG event log therefore still sees the truth. Worse, UEFI measures every loaded
 * image's DEVICE PATH IN PLAINTEXT, so our own filenames appear in a log Windows serves to any
 * caller via TBS, MeasuredBoot\*.log and WMI. Such a checker never has to defeat Tier 1 at all.
 *
 * ⚠ WHY NOT A GetEventLog HOOK -- this was tried and MEASURED to do nothing.
 * The first design hooked EFI_TCG2_PROTOCOL.GetEventLog on the premise that Windows obtains the log
 * once through that protocol. The hook installed and reported success on a real boot, and the log
 * Windows ended up with was COMPLETELY UNSANITIZED. Cause: the ACPI TPM2 table (revision 4)
 * publishes the log's physical address directly --
 *
 *     LAML (log area length)  : 65536 bytes
 *     LASA (log area address) : 0x000000003DC70000
 *
 * -- so a reader takes the log straight from memory and never calls the protocol. Hooking an
 * ACCESSOR can never be sufficient when the underlying buffer's address is published. The hook code
 * was deleted rather than kept "in case someone uses the protocol": it was dead BY MEASUREMENT, and
 * git holds it if a protocol-using reader ever turns up.
 *
 * The single point is therefore the BUFFER, not the accessor. Patching bytes in place at LASA makes
 * every reader consistent by construction.
 *
 * ⚠ CALL SITE: EXITBOOTSERVICES, and getting here cost two hung boots.
 *
 * ATTEMPT 1 was HookedOslFwpKernelSetupPhase1, chosen as "the latest point we control". It hung the
 * machine at a black screen BEFORE Windows even reached its boot spinner. Cause: that hook runs
 * after winload has installed ITS OWN PAGE TABLES. ACPI hands out PHYSICAL addresses, and under UEFI
 * boot services those work only because everything is identity-mapped -- inside winload they are
 * not mapped at all, so walking the XSDT faults. Every other thing that hook touches (the loader
 * block, the kernel image) is winload-mapped; the ACPI walk was the odd one out. The tell was there
 * before the boot and I did not read it.
 *
 * ATTEMPT 2 is the ExitBootServices callback:
 *   - still UEFI context, so still IDENTITY-MAPPED (the existing EBS callback prints to gST->ConOut,
 *     which proves the environment is intact there);
 *   - AFTER every firmware measurement, which solves the append problem outright -- nothing further
 *     is measured, so nothing can overwrite our edits;
 *   - NO ALLOCATION IS PERMITTED during EBS, hence InitTcgLogSanitizer() below reserving the work
 *     buffer earlier, while allocation is still legal.
 *
 * The remaining unknown is whether Windows has already taken its copy of the log by then. If it has,
 * this is a harmless no-op rather than a hang -- a far better failure mode than either attempt above,
 * and one the three gates will detect directly.
 *
 * FIDELITY: level B2 (§4) -- content edited AND digests correctly recomputed. B1 (stale digests) is
 * explicitly worse than not spoofing at all, because a self-inconsistent log is a stronger signal
 * than an honest one. Hence every failure path leaves the log completely untouched.
 *
 * WHAT IT CANNOT DO: the real PCR[7] register still holds the honest values. A verifier that
 * recomputes the log's hash chain against the TPM (scope §3 rung C) or takes a TPM2_Quote (rung D)
 * defeats this. Those are ACCEPTED STRUCTURAL LIMITS, not TODOs.
 */

#pragma once

#include <Uefi.h>

//
// ============================================================================
// EFI_TCG2_PROTOCOL -- minimal local declaration
// ============================================================================
//
// ⚠ RESTORED, having been deleted the same day. Recording why, because deleting it was a
// reasoning error worth not repeating.
//
// It was removed on the grounds that the GetEventLog hook was "dead by measurement": the hook
// installed, the log came back unsanitized, and ACPI was found to publish the log's physical address
// (LASA). But that only proved a BYPASS PATH EXISTS -- not that winload uses it. And the transform
// was independently BROKEN at the time (every emitted record was missing its digest count, see
// TcgLogTransform.c), so the hook failing to produce a sanitized log is equally explained by the
// transform refusing. The evidence was deleted on the strength of an inference.
//
// Now that the transform is proven correct on the host, both paths run and REPORT which one lands.
// That is one boot to settle a question two boots of guessing did not.
//
// THE MEMBER ORDER IS LOAD-BEARING, copied verbatim from
// VisualUefi/edk2/MdePkg/Include/Protocol/Tcg2Protocol.h. GetEventLog is the SECOND slot. Getting it
// wrong compiles fine and calls GetCapability with GetEventLog's arguments. Only GetEventLog is
// typed; the rest are VOID* because a wrong signature on an uncalled member is a trap for the next
// reader.
//
typedef struct _EFI_TCG2_PROTOCOL EFI_TCG2_PROTOCOL;

typedef UINT32 EFI_TCG2_EVENT_LOG_FORMAT;

#define EFI_TCG2_EVENT_LOG_FORMAT_TCG_1_2   0x00000001
#define EFI_TCG2_EVENT_LOG_FORMAT_TCG_2     0x00000002

typedef
EFI_STATUS
(EFIAPI*
EFI_TCG2_GET_EVENT_LOG)(
	IN EFI_TCG2_PROTOCOL* This,
	IN EFI_TCG2_EVENT_LOG_FORMAT EventLogFormat,
	OUT EFI_PHYSICAL_ADDRESS* EventLogLocation,
	OUT EFI_PHYSICAL_ADDRESS* EventLogLastEntry,
	OUT BOOLEAN* EventLogTruncated
	);

//
// SubmitCommand -- added for the platformAuth probe (TpmPlatformAuthProbe.c). Same
// pointer width as the VOID* it replaces, so the vtable layout is unchanged; this only gives the
// slot a real signature so callers are type-checked instead of casting.
//
typedef
EFI_STATUS
(EFIAPI*
EFI_TCG2_SUBMIT_COMMAND)(
	IN EFI_TCG2_PROTOCOL* This,
	IN UINT32 InputParameterBlockSize,
	IN UINT8* InputParameterBlock,
	IN UINT32 OutputParameterBlockSize,
	IN UINT8* OutputParameterBlock
	);

struct _EFI_TCG2_PROTOCOL {
	VOID* GetCapability;                    // slot 0
	EFI_TCG2_GET_EVENT_LOG GetEventLog;     // slot 1  <== hooked (Tier 3)
	VOID* HashLogExtendEvent;               // slot 2
	EFI_TCG2_SUBMIT_COMMAND SubmitCommand;  // slot 3  <== called, never hooked
	VOID* GetActivePcrBanks;                // slot 4
	VOID* SetActivePcrBanks;                // slot 5
	VOID* GetResultOfSetActivePcrBanks;     // slot 6
};

extern EFI_GUID gEfiTcg2ProtocolGuid;

/**
 * Diagnostics for the GetEventLog hook, read at ExitBootServices so ONE boot distinguishes
 * "winload never called the protocol" from "it called and our transform refused".
 *
 * Those two look identical from the outside -- an unsanitized log -- and confusing them is what cost
 * the previous attempts.
 */
VOID
EFIAPI
GetTcgHookDiagnostics(
	OUT UINT32* CallCount,
	OUT EFI_STATUS* LastStatus,
	OUT UINT32* SubstitutedBytes
	);

/**
 * Locate the TCG event log via the ACPI TPM2 table and sanitize it IN PLACE.
 *
 * Idempotent by construction: the transform refuses if the authority record it would insert is
 * already present, so calling twice cannot double-insert.
 *
 * On ANY failure the log is left byte-for-byte untouched -- see the B1 note above.
 *
 * ⚠ THIS FUNCTION MUST NOT PRINT. It is called from HookedOslFwpKernelSetupPhase1, i.e. WINLOAD
 * context, where raw Print() writes to gST->ConOut -- a console Windows has already taken over for
 * the boot spinner. Doing so HUNG the machine at a black screen after handoff, the same
 * family as the BlStatusPrint incident that cost 9 BSODs. Diagnostics come back through the OUT
 * params so the CALLER can report them with the output mechanism appropriate to ITS context
 * (PRINT_KERNEL_PATCH_MSG in winload, Print at DXE time).
 *
 * Reporting still matters -- a silent no-op is indistinguishable from success, which is exactly how
 * the GetEventLog attempt wasted a boot -- it just cannot happen from in here.
 *
 * @retval EFI_SUCCESS        log patched
 * @retval EFI_NOT_FOUND      no TPM2 table, or it publishes no log address
 * @retval EFI_ABORTED        a mandatory edit target was missing; nothing written
 * @retval EFI_BUFFER_TOO_SMALL  the sanitized log would exceed LAML; nothing written
 */
/**
 * Called at DXE entry, while allocation is still legal and ACPI is identity-mapped. Locates the TPM2
 * table, caches LASA/LAML, and reserves the work buffer that PatchTcgEventLogInPlace() will use.
 *
 * Safe and quiet on a machine with no TPM2 table: there is no log to sanitize and nothing hides in
 * one that does not exist.
 */
EFI_STATUS
EFIAPI
InitTcgLogSanitizer(
	VOID
	);

EFI_STATUS
EFIAPI
PatchTcgEventLogInPlace(
	OUT UINT32* OldSize OPTIONAL,
	OUT UINT32* NewSize OPTIONAL,
	OUT UINT32* Capacity OPTIONAL
	);

//
// The transform itself now lives in TcgLogTransform.h -- split out so it can be compiled
// and tested on the HOST against tools/wbcl_sanitize.py, which no code in THIS file can be (it needs
// protocols, ACPI and physical memory). Three boots were spent on Tier 3 without ever establishing
// whether the transform was correct; that question does not belong on hardware.
//
