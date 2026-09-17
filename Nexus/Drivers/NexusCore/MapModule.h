/**
 * @file MapModule.h
 * @brief NexusCore's runtime mapper. Rationale and ordering constraints live in MapModule.c.
 */

#pragma once

#include <ntddk.h>

/* For NXCMD_U32 and the NXCMD_SCRUB / NXCMD_MAP bits returned by NxcMapLastDiagFlags. Included here
 * rather than relied upon transitively: this header is included BEFORE NexusCoreBoot.h in MapModule.c,
 * so the type would not yet exist. */
#include "../../Include/NexusCommand.h"

/* For NXH_COMMAND_FN, the module-owned command handler type. Same reasoning as the include above:
 * stated explicitly rather than relied on transitively, so this header stands alone. */
#include "../../Include/NexusHost.h"

/*
 * Concurrent resident modules. The real workload is the hypervisor plus a couple of helpers; a
 * static table keeps the bookkeeping out of pool, same reasoning as the arena's extent table.
 */
#define NXC_MAX_MODULES   8u
#define NXC_MODULE_NONE   0xFFFFFFFFu

/** Bind the mapper to ntoskrnl, from the boot block's ABI-3 fields. Call once from DriverEntry. */
void
NxcMapInit(
	_In_opt_ void* NtBase,
	_In_ ULONG NtSize
	);

/**
 * Map a raw PE image into the arena and call its entry point.
 *
 * REFUSES, before running any module code, any image that: is not x64 PE32+, has no base
 * relocations, imports from anything but ntoskrnl, imports by ordinal, or -- critically -- does not
 * export a valid NexusModuleDescriptor. See the gate note in MapModule.c: a module that cannot be
 * torn down must never become resident.
 *
 * @param RawImage     the .sys file bytes, as on disk
 * @param ImageBytes   their length
 * @param OutModuleId  receives the handle used by unmap
 *
 * @retval STATUS_SUCCESS               mapped and its entry returned success
 * @retval STATUS_INVALID_IMAGE_FORMAT  refused; nothing was left resident
 * @retval STATUS_INSUFFICIENT_RESOURCES  no arena extent large enough, or the module table is full
 * @retval STATUS_DEVICE_NOT_READY             no ntoskrnl base was published (stale DXE)
 * @retval other                        the module's OWN entry status; it is left RESIDENT in this
 *                                      case and must be torn down via unmap, never freed directly
 */
NTSTATUS
NxcMapModule(
	_In_reads_bytes_(ImageBytes) const void* RawImage,
	_In_ ULONG ImageBytes,
	_Out_ ULONG* OutModuleId
	);

/**
 * Source line of the LAST refusal inside the mapper, or 0 if it has not refused anything.
 *
 * NxcMapModule returns STATUS_INVALID_IMAGE_FORMAT from seventeen different checks, so the status
 * alone says only "something about the image was wrong". This names the exact check. Read it
 * immediately after a failing NxcMapModule -- it is overwritten by the next refusal, which is fine
 * because the only consumer answers one command at a time.
 *
 * Line numbers move when the file is edited. That is acceptable BECAUSE the value is always read
 * against the build that produced it and is never stored; the alternative, a named enum, is one more
 * thing to keep in sync with the checks it describes.
 */
ULONG
NxcMapLastRefusalLine(
	void
	);

/** NXCMD_SCRUB / NXCMD_MAP diagnostic bits from the most recent map. Reset per map, not cumulative. */
NXCMD_U32
NxcMapLastDiagFlags(
	void
	);

/**
 * Find the module-registered handler for an opcode, or NULL.
 *
 * Returns NULL for every Core opcode without searching -- the split at NXCMD_OP_MODULE_FIRST is
 * enforced on lookup as well as on registration, so a table corrupted into holding a Core opcode
 * still cannot shadow one.
 */
NXH_COMMAND_FN
NxcCommandLookup(
	_In_ ULONG Opcode
	);

/**
 * Retire every opcode registered by a module. Called during unmap, immediately after PREPARE.
 *
 * ⚠ MUST happen before the module's memory is poisoned. A surviving entry would point into an arena
 * extent that gets reused, so a usermode command would execute whatever the next module put there.
 *
 * @return how many registrations were cleared
 */
ULONG
NxcCommandUnregisterOwner(
	_In_ ULONG Owner
	);

/** Number of resident mapped modules, for the status report. */
ULONG
NxcMapCount(
	void
	);

/**
 * Resolve any export from ntoskrnl by name, CODE OR DATA.
 *
 * An export is an RVA; the export table does not care what lives at it. That is what lets this
 * reach `PsLoadedModuleList` and `PsProcessType` -- data exports our function-only NXC_NT_API table
 * structurally cannot carry.
 *
 * The alternative for each such symbol is a hardcoded offset, which is a per-build treadmill. This
 * resolves by name against the ntoskrnl the DXE measured, so it survives every kernel update that
 * does not remove the export.
 *
 * @return the export's address, or NULL if ntoskrnl was never bound or the name is absent
 */
void*
NxcResolveNtExport(
	_In_z_ CONST CHAR* Name
	);

/**
 * The running ntoskrnl's base and size, for code that must SCAN the image rather than look a name
 * up in it. Returns FALSE if ntoskrnl was never bound.
 */
BOOLEAN
NxcGetNtImage(
	_Out_ UINT64* OutBase,
	_Out_ UINT32* OutSize
	);

/**
 * Resolve a loaded KERNEL module name to its base and SizeOfImage, by walking PsLoadedModuleList.
 *
 * By NAME rather than address because an address is meaningless across boots under KASLR, and the
 * caller has no other way to learn it. Matching is case-insensitive against BaseDllName.
 *
 * ⚠ The loader-entry offsets it reads are undocumented Windows internals, so the walk PROVES them
 * before trusting them: ntoskrnl's base is known independently from the boot block and must appear
 * in the list. If it does not, this refuses rather than returning a plausible wrong base.
 *
 * @retval STATUS_SUCCESS              found; OutBase/OutSize valid
 * @retval STATUS_NOT_FOUND            no module by that name is loaded
 * @retval STATUS_INVALID_IMAGE_FORMAT the walk failed its self-check -- LDR layout likely changed
 * @retval STATUS_PROCEDURE_NOT_FOUND  PsLoadedModuleList is not exported (should be impossible)
 * @retval STATUS_NOT_READY            ntoskrnl base/size were never bound
 */
NTSTATUS
NxcFindKernelModule(
	_In_z_ CONST CHAR* Name,
	_Out_ UINT64* OutBase,
	_Out_ ULONG* OutSize
	);

/**
 * ENUMERATE every loaded kernel module -- the kernel counterpart to `modules <pid>`.
 *
 * Closes a kernel/usermode parity gap: the kernel side could previously only look a module up BY
 * NAME, so it could inspect a driver it was told about but never say what is loaded. Also the
 * prerequisite for detecting an UNLINKED driver, which needs the set of legitimate ranges to
 * subtract.
 *
 * Shares NxcFindKernelModule's self-check: refuses unless the walk encounters ntoskrnl, whose base
 * came from the DXE rather than from this structure.
 *
 * @param FirstIndex  zero-based module index to start at (paging; a big list exceeds one buffer)
 * @param OutWritten  records actually written -- what was PRODUCED
 * @param OutTotal    modules in the list -- what EXISTS, so truncation is visible
 *
 * @retval STATUS_SUCCESS              walk completed and self-verified
 * @retval STATUS_INVALID_IMAGE_FORMAT self-check failed -- LDR layout likely changed
 * @retval STATUS_PROCEDURE_NOT_FOUND  PsLoadedModuleList is not exported
 * @retval STATUS_INVALID_DEVICE_STATE ntoskrnl base/size were never bound
 */
NTSTATUS
NxcEnumKernelModules(
	_In_ UINT32 FirstIndex,
	_Out_writes_(Capacity) NXCMD_KMODULE* Out,
	_In_ UINT32 Capacity,
	_Out_ UINT32* OutWritten,
	_Out_ UINT32* OutTotal
	);

/**
 * Tear down and reclaim a mapped module: the six steps of NexusModule.h's teardown contract.
 *
 * MUST be called at PASSIVE_LEVEL -- the module's Prepare/Commit run at the caller's IRQL, and the
 * drain sleeps.
 *
 * ⚠ STATUS_DEVICE_BUSY IS NOT AN ERROR. It means the module refused teardown (PREPARE said no) or did
 * not drain, and in the refusal case the module is left mapped, running and completely intact. That
 * is the designed outcome of asking a module that cannot unload -- a refused unmap is recoverable, a
 * partial one is a bugcheck later. Callers must not retry it as though it were a transient.
 *
 * On any failure AFTER commit begins, the extent is deliberately LEAKED and the slot is marked a
 * zombie: never reclaimed, never reused, never torn down again. See NXC_MODULE_SLOT::Zombie.
 *
 * @param ModuleId  slot id from NxcMapModule, which is also the arena owner id
 * @return STATUS_SUCCESS reclaimed; STATUS_DEVICE_BUSY refused/busy (see above); otherwise failed,
 *         with NxcMapLastRefusalLine() naming the exact check.
 */
NTSTATUS
NxcMapUnmap(
	_In_ ULONG ModuleId
	);
