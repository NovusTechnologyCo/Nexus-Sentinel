#pragma once

//
// NexusPgLocate -- find the PatchGuard initialisation routines in a mapped ntoskrnl.
//
// ---------------------------------------------------------------------------------------
// WHY THIS IS NOT A SIGNATURE SCAN
//
// The patches themselves are trivial: five three-byte stubs, eleven NOPs, and one pointer.
// ALL of the engineering is in locating the targets, so that is the part worth getting
// right. The approach this replaces used four byte signatures totalling 57 bytes -- 57 bytes
// that decide whether the machine boots.
//
// Here, targets are identified by what their code MEANS: a distinctive 64-bit constant, an
// instruction sequence that performs a recognisable computation, a call to an EXPORTED
// routine, position and size within a section. Those survive a recompile; a byte encoding
// does not.
//
// (!) HONEST CAVEAT, because it would be easy to oversell this. Measured across four kernel
// builds spanning two Windows releases (26100.9457/.9444/.9278 and 19041.7417), the semantic
// locator and the old byte scanner agreed on every target, 16/16 -- but the byte signatures
// also survived all four. EfiGuard's signatures are heavily wildcarded and were written to
// span Win7-Win11, so they encode roughly the same skeleton. What is DEMONSTRATED is
// correctness across a release boundary. Durability is an argument, not a measurement.
//
// What the rewrite does buy, measurably:
//   * no ordinal dependency between CcInitializeBcbProfiler and ExpLicenseWatchInitWorker
//     (see the discriminator note in the .c), and
//   * a validated write target for g_PgContext rather than an unvalidated one.
//
// Host prototype, cross-build results and the mutation tests that establish fail-closed
// behaviour: a host-side prototype.
// ---------------------------------------------------------------------------------------
//

#include "NexusPe.h"

//
// Everything the caller needs to patch. A NULL member means "not found"; the caller decides
// which of those are fatal, because they are not equally so.
//
typedef struct _NEXUS_PG_TARGETS
{
	// Stubbed with 'xor eax,eax; ret'.
	UINT8* KeInitAmd64SpecificState;
	UINT8* ExpLicenseWatchInitWorker;
	UINT8* KiVerifyScopesExecute;

	// The two routines that CALL KiMcaDeferredRecoveryService, not the routine itself.
	UINT8* KiMcaDeferredRecoveryServiceCallers[2];

	// Stubbed with 'mov al,1; ret' -- this one has to return TRUE, not FALSE.
	UINT8* CcInitializeBcbProfiler;

	// The 'sti; lea; call; cli' site inside KiSwInterrupt. The call is NOPped out.
	UINT8* KiSwInterruptPatchSite;
	UINT32 KiSwInterruptPatchLength;

	// Resolved from the call at that site, and the global it loads.
	UINT8* KiSwInterruptDispatch;
	UINT8* PgContext;
} NEXUS_PG_TARGETS;

//
// Locate everything in a MAPPED ntoskrnl image.
//
// Returns EFI_SUCCESS when the targets the caller cannot proceed without were all found.
// Members that are merely optional may still be NULL on success.
//
EFI_STATUS
EFIAPI
NexusPgLocateTargets(
	IN CONST UINT8* ImageBase,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders,
	OUT NEXUS_PG_TARGETS* Targets
	);
