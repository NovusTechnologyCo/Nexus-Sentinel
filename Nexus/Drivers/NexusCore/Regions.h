/**
 * @file Regions.h
 * @brief Enumerate a process's user-mode VA regions. THE mechanism that sees MANUAL MAPS.
 *
 * ============================================================================================
 * WHY THIS EXISTS ALONGSIDE THE IMAGE-LOAD NOTIFY
 * ============================================================================================
 *
 * The notify (Capture.h) asks the LOADER, so it sees exactly what the loader mapped -- and
 * structurally cannot see anything else. measured: a NexusCore-mapped module produces no
 * notify at all.
 *
 * This asks the MEMORY MANAGER instead. It therefore sees manually mapped code, injected shellcode,
 * MEM_PRIVATE executable regions -- anything that exists as memory regardless of how it got there.
 * v1's equivalent is how `gameservicelauncher.dll` was captured, and its own header put it plainly:
 * "unlike MODLIST (PEB.Ldr only), this exposes manually-mapped shellcode, MEM_PRIVATE PAGE_EXECUTE
 * regions, and anything not registered with the loader."
 *
 * The two are complementary, not redundant. Neither replaces the other.
 *
 * ============================================================================================
 * ⚠ METADATA ONLY. THE WALK NEVER TOUCHES A TARGET PAGE.
 * ============================================================================================
 *
 * Everything reported comes from ZwQueryVirtualMemory, which returns NTSTATUS and does not raise.
 * That is what makes this surface buildable at all in an image where SEH is inert -- there is no
 * faulting operation to guard, by construction rather than by care.
 *
 * If a future change wants region CONTENTS, it must go through the read path's MmCopyMemory, which
 * is partial-aware and status-returning. Do not add a direct copy here.
 *
 * ============================================================================================
 * ENUMERATE AND DUMP ARE SEPARATE, DELIBERATELY
 * ============================================================================================
 *
 * v1 fused them -- `--dump-hidden-vad` decided which region was interesting AND dumped it. Splitting
 * puts the "interesting" heuristic in usermode, where it can be changed without a kernel deploy, and
 * leaves the kernel a mechanism rather than a policy. The kernel reports facts; usermode decides
 * what they mean.
 */

#pragma once

#include <ntddk.h>

/*
 * MEM_* and PROCESS_* are Win32 constants. `ntddk.h` does not define them, and pulling in the SDK
 * headers that do would change what else is visible in a payload translation unit -- so they are
 * declared here, once, in the file whose contract already carries State/Protect/Type to usermode.
 *
 * The values are the architectural ones and are stable; usermode compares against its own SDK
 * definitions of the same names, so a mismatch would surface immediately as nonsense region types
 * rather than hiding.
 */
/*
 * ⚠ GUARDED INDIVIDUALLY, NOT AS A BLOCK. First cut wrapped all six in `#ifndef MEM_COMMIT` and the
 * build failed on MEM_IMAGE alone: ntddk's include chain defines MEM_COMMIT but NOT MEM_IMAGE, so
 * one member being present suppressed the definitions of the five that were missing.
 *
 * A group guard asserts "these always travel together". When they do not, it fails in the least
 * obvious way -- the guard reads as protective and is the thing removing the definition.
 */
#ifndef MEM_COMMIT
#define MEM_COMMIT                 0x00001000u
#endif
#ifndef MEM_RESERVE
#define MEM_RESERVE                0x00002000u
#endif
#ifndef MEM_FREE
#define MEM_FREE                   0x00010000u
#endif
#ifndef MEM_PRIVATE
#define MEM_PRIVATE                0x00020000u
#endif
#ifndef MEM_MAPPED
#define MEM_MAPPED                 0x00040000u
#endif
#ifndef MEM_IMAGE
#define MEM_IMAGE                  0x01000000u
#endif
#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION  0x0400u
#endif

/*
 * One region, as reported to usermode. Fixed layout: this crosses the command channel.
 *
 * Deliberately NOT a verdict -- no "suspicious" bit. The caller gets the EVIDENCE (state, protection,
 * type, whether a backing file exists) and applies its own rule. A verdict without its basis is the
 * failure mode this codebase keeps having to fix.
 */
#pragma pack(push, 1)
typedef struct _NXC_REGION
{
	UINT64 BaseAddress;
	/*
	 * ⚠ THE FIELD THAT MAKES THE MANUAL-MAP DETECTOR CORRECT. Added after `--hidden`
	 * reported 4 hits on a target with 1 real one.
	 *
	 * A region belonging to a mapped image carries that image's base here, EVEN WHEN THE REGION
	 * FALLS OUTSIDE [DllBase, DllBase + SizeOfImage). Windows maps an image view that can extend
	 * past SizeOfImage, so the trailing page of ntdll, kernel32 and KernelBase all sat outside the
	 * loader-reported range and were flagged as unclaimed executable memory -- three false positives
	 * on an ordinary process.
	 *
	 * Matching on this does NOT weaken detection, which is the point: a real manual map allocates
	 * its own memory, so its AllocationBase is its own base and matches no module. Even a phantom
	 * DLL mapped with NtMapViewOfSection(SEC_IMAGE) gets its own view base, absent from the PEB
	 * list. Only pages that genuinely belong to a loaded image stop being reported.
	 */
	UINT64 AllocationBase;
	UINT64 RegionSize;
	UINT32 State;        /* MEM_COMMIT / MEM_RESERVE / MEM_FREE                       */
	UINT32 Protect;      /* PAGE_*                                                     */
	UINT32 Type;         /* MEM_IMAGE / MEM_MAPPED / MEM_PRIVATE                       */
	UINT32 Flags;        /* NXC_REGION_FLAG_*                                          */
	/*
	 * ---- WHAT THE CPU ACTUALLY ENFORCES, beside what the VAD ASKED FOR ------------------
	 *
	 * `Protect` above is the PAGE_* the memory manager RECORDED. This is NXCMD_XLAT_* read out
	 * of the live PTE for the region's first page, walked from the target's own CR3.
	 *
	 * ⚠ THEY CAN DISAGREE, AND THE DISAGREEMENT IS THE WHOLE POINT. A VAD is a record of a
	 * request; a PTE is what the processor will honour.
	 *
	 * The motivating target, from the archived captures (`ec0251c63a`,
	 * a committed baselinereadtrap_gslexe_20260630_141505/_vads.txt): gsl.dll is mapped THREE
	 * times in one process -- a MEM_IMAGE copy plus two 0x2E2C000 MEM_PRIVATE mirrors, all three
	 * absent from the loader list -- and its cipher phase issues 2787 NtProtectVirtualMemory
	 * calls, running each protected region decrypt -> RX -> exec -> re-encrypt -> RW. A page
	 * observed non-executable there may have executed microseconds earlier.
	 *
	 * So a protection READING IS A SAMPLE, not a property, and the two sources sample different
	 * things: the VAD is what the MM was last told, the PTE is what the CPU is enforcing right
	 * now. Reporting both means a disagreement shows up as a disagreement instead of one number
	 * quietly winning.
	 *
	 * ⚠ AND IT DOES NOT SETTLE "DID CODE RUN HERE?" -- NEITHER SOURCE CAN. That needs the flip
	 * OBSERVED, not sampled. Do not let this field grow into an execution verdict (D6).
	 *
	 * 0 means NOT TRANSLATED -- the region was not probed, or the walk failed. It does NOT mean
	 * "no rights"; NXCMD_XLAT_PRESENT is the bit that says the walk succeeded.
	 */
	UINT32 PteFlags;
} NXC_REGION;
#pragma pack(pop)

/*
 * PlatformCtl MIRRORS this (it cannot include ntddk), so the layout is pinned on BOTH sides.
 * Added with AllocationBase: the mirror's own assert had caught a 32-byte struct, and growing one
 * side of a mirrored pair without the other is how a caller starts reading fields at the wrong
 * offsets while everything still compiles.
 */
/* 40 -> 44: PteFlags, what the CPU enforces beside what the VAD recorded. The mirrored assert in
 * PlatformCtl.c moved with it -- this comment block exists because updating one and not the other
 * is how a caller starts reading fields at the wrong offsets while everything still compiles. */
C_ASSERT(sizeof(NXC_REGION) == 44);
C_ASSERT(FIELD_OFFSET(NXC_REGION, AllocationBase) == 8);
C_ASSERT(FIELD_OFFSET(NXC_REGION, RegionSize)     == 16);
C_ASSERT(FIELD_OFFSET(NXC_REGION, State)          == 24);

/*
 * Has a backing file. Its ABSENCE on an executable committed region is the manual-map signal --
 * code that exists in memory but belongs to no file on disk.
 *
 * A flag rather than the path itself: paths are variable-length and would dominate the transfer,
 * and the presence/absence is what the heuristic actually needs. A caller wanting the path can ask
 * for that region specifically once it has decided the region matters.
 */
#define NXC_REGION_FLAG_HAS_FILE   0x00000001u

/* The walk stopped at the cap rather than at the end of the address space -- results are TRUNCATED. */
#define NXC_REGION_FLAG_TRUNCATED  0x00000002u

/**
 * Enumerate committed/reserved regions in a process's user VA space.
 *
 * @param ProcessId  target pid
 * @param Out        caller's buffer (kernel memory), filled with NXC_REGION entries
 * @param MaxCount   how many entries fit
 * @param OutCount   receives how many were written
 * @param OutTotal   receives how many EXIST -- may exceed MaxCount, so a caller can tell a full
 *                   answer from a truncated one rather than silently believing a short list
 *
 * @retval STATUS_SUCCESS        walked; OutCount/OutTotal valid
 * @retval STATUS_NOT_FOUND      no such process
 * @retval STATUS_INVALID_DEVICE_STATE  not at PASSIVE_LEVEL
 */
NTSTATUS
NxcEnumRegions(
	_In_ ULONG ProcessId,
	_Out_writes_(MaxCount) NXC_REGION* Out,
	_In_ ULONG MaxCount,
	_Out_ ULONG* OutCount,
	_Out_ ULONG* OutTotal
	);

/*
 * One loaded module, as the LOADER sees it.
 *
 * ⚠ THE POINT OF THIS IS THE DIFFERENCE FROM NxcEnumRegions, NOT THE LIST ITSELF. The loader's view
 * omits anything it did not map — manually mapped DLLs, injected shellcode. A region that is
 * committed and executable and appears in NO module here is the manual-map signature. v1's
 * `--list-launcher-modules` is exactly this subtraction, and it is why both commands exist.
 */
#pragma pack(push, 1)
typedef struct _NXC_MODULE_ENTRY
{
	UINT64 DllBase;
	UINT32 SizeOfImage;
	UINT32 Reserved0;
	UINT8  Name[64];     /* ASCII, NUL-padded, from BaseDllName; truncated rather than dropped */
} NXC_MODULE_ENTRY;
#pragma pack(pop)

/**
 * Enumerate a process's LOADER module list (`PEB.Ldr.InLoadOrderModuleList`).
 *
 * ⚠ EVERY FIELD READ IS A CROSS-PROCESS READ. The PEB and everything reachable from it are usermode
 * addresses in the TARGET, so this is a pointer chase with one `MmCopyVirtualMemory` per hop —
 * never `KeStackAttachProcess` (D1). Slower by a few calls, and it removes the failure mode where a
 * missed detach leaves this thread running in another process's address space.
 *
 * @retval STATUS_SUCCESS               walked; OutCount/OutTotal valid
 * @retval STATUS_NOT_FOUND             no such process
 * @retval STATUS_INVALID_ADDRESS       the PEB chain did not read — a 32-bit process, or the target
 *                                      exited mid-walk. Distinguished from "no modules" deliberately
 * @retval STATUS_INVALID_DEVICE_STATE  not at PASSIVE_LEVEL
 */
/**
 * The path of the file behind ONE mapped region.
 *
 * ⚠ ONE REGION AT A TIME, and that is the design rather than a limitation -- see
 * NXC_REGION_FLAG_HAS_FILE above, which derives file-backedness from Type precisely so the walk
 * never pays a filename query per region. This answers "WHICH file" once a caller has decided a
 * region matters.
 *
 * @param Address   any VA inside the region
 * @param Out       receives the path as raw UTF-16, NOT NUL-terminated
 * @param OutBytes  BYTES written -- halve it for the character count
 *
 * @retval STATUS_SUCCESS       Out/OutBytes valid
 * @retval STATUS_FILE_INVALID  mapped, but backed by the PAGEFILE rather than a file. A REAL
 *                              ANSWER: an executable MEM_MAPPED region with no file behind it is
 *                              closer to allocated code than to a DLL
 * @retval STATUS_NOT_FOUND     no such process, or the region has no name
 * @retval STATUS_INVALID_DEVICE_STATE  not at PASSIVE_LEVEL
 */
NTSTATUS
NxcRegionFile(
	_In_  ULONG   ProcessId,
	_In_  UINT64  Address,
	_Out_writes_bytes_(MaxBytes) VOID* Out,
	_In_  ULONG   MaxBytes,
	_Out_ ULONG*  OutBytes
	);

NTSTATUS
NxcEnumModules(
	_In_ ULONG ProcessId,
	_Out_writes_(MaxCount) NXC_MODULE_ENTRY* Out,
	_In_ ULONG MaxCount,
	_Out_ ULONG* OutCount,
	_Out_ ULONG* OutTotal
	);
