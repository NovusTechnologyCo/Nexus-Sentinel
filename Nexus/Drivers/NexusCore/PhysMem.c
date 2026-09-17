/**
 * @file PhysMem.c
 * @brief Physical reads gated on the RAM map. The reasoning lives in PhysMem.h -- read it first.
 */

#pragma runtime_checks("", off)
#pragma check_stack(off)
#pragma strict_gs_check(off)

#include <ntddk.h>

#include "PhysMem.h"
#include "../../Include/NexusCoreBoot.h"
#define NXC_NT_API_TYPED
#include "../../Include/NexusNtApi.h"

extern volatile NXC_NT_API NexusNtApi;
#include "../../Include/NexusNtApiRedirect.h"

extern volatile NEXUS_CORE_BOOT_BLOCK* NexusCoreBootSlot;
extern void NxcLogExt(_In_z_ PCSTR Format, ...);
#define PhysLog NxcLogExt

/*
 * ⚠ NOT CACHED, deliberately, even though this is called once per page-table level.
 *
 * The obvious optimisation is to snapshot the RAM map at init and check against the copy. It is
 * rejected because a stale safety gate is worse than a slow one: memory hot-add and firmware
 * runtime reservations both change this map, and a cached copy that has gone stale fails in the ONE
 * direction that matters -- it would call a newly-non-RAM address RAM.
 *
 * The cost is a paged-pool allocation per call at PASSIVE_LEVEL, on a path that is a diagnostic read
 * and never a hot loop. Measure before trading that for a cache; do not trade it on instinct.
 */
BOOLEAN
NxcPhysIsRam(
	_In_ UINT64 Pa,
	_In_ UINT64 Len,
	_Out_opt_ UINT64* RangeBase,
	_Out_opt_ UINT64* RangeSize
	)
{
	if (RangeBase != NULL) *RangeBase = 0;
	if (RangeSize != NULL) *RangeSize = 0;

	if (Len == 0)
		return FALSE;

	CONST UINT64 Last = Pa + Len;
	if (Last <= Pa)          /* wrap */
		return FALSE;

	PPHYSICAL_MEMORY_RANGE CONST Ranges = MmGetPhysicalMemoryRanges();
	if (Ranges == NULL)
	{
		/* FAIL CLOSED -- see the header. Without the map, RAM and MMIO are indistinguishable. */
		PhysLog("phys: RAM map unavailable, refusing 0x%llX +%llu (fail-closed)\n", Pa, Len);
		return FALSE;
	}

	BOOLEAN Found = FALSE;
	for (ULONG i = 0; Ranges[i].BaseAddress.QuadPart != 0 ||
	                  Ranges[i].NumberOfBytes.QuadPart != 0; i++)
	{
		CONST UINT64 Base = (UINT64)Ranges[i].BaseAddress.QuadPart;
		CONST UINT64 Size = (UINT64)Ranges[i].NumberOfBytes.QuadPart;

		if (Pa >= Base && Last <= Base + Size)
		{
			if (RangeBase != NULL) *RangeBase = Base;
			if (RangeSize != NULL) *RangeSize = Size;
			Found = TRUE;
			break;
		}
	}

	/* Tag 0: ntoskrnl allocated this block with its own tag, and ExFreePoolWithTag bugchecks 0xC2 on
	 * a NON-ZERO tag mismatch. Tag 0 is the documented skip-the-check value ExFreePool passes. */
	ExFreePoolWithTag(Ranges, 0);
	return Found;
}

/*
 * ============================================================================================
 * THE ONE EXCEPTION TO THE RAM-MAP RULE: the two regions the DXE allocated for the software TPM.
 * ============================================================================================
 *
 * (!) READ NxcPhysIsRam ABOVE FIRST. That gate exists because two host freezes
 * came from mapping an address BELIEVED to be RAM that was a device register, where a read is
 * not a read -- it can clear a status bit, pop a FIFO, or hang on an unpopulated bus address.
 * That rule is unchanged and still applies to every caller-supplied address.
 *
 * The software-TPM regions are EfiACPIMemoryNVS, which Windows does NOT report as system RAM,
 * so MmGetPhysicalMemoryRanges leaves them in a hole and NxcPhysIsRam refuses them. It is right
 * to, on the evidence available to it: from the RAM map alone our own DRAM and a device BAR are
 * indistinguishable.
 *
 * This inverts every property that made the case dangerous:
 *
 *   - the address is NOT arbitrary. The DXE allocated these regions itself, with
 *     AllocateAnyPages, and published the extents in the boot block. No caller chooses them.
 *   - they are KNOWN to be ordinary DRAM, not device registers. That is the whole point.
 *   - a read has no side effects, because there is no device behind it.
 *   - the allowance is CONTAINMENT-CHECKED against the published extents, so it cannot be
 *     walked outward one page at a time.
 *
 * (!) IT IS A WHITELIST OF MEMORY WE ALLOCATED, NOT A RELAXATION OF THE RULE. If the boot block
 * is absent, or the extents are zero, or the epoch is zero, nothing is allowed -- every one of
 * those means the DXE did not allocate a region this boot, which is a legitimate state because
 * transport init is non-fatal by design.
 */
BOOLEAN
NxcPhysIsPublishedTpmRegion(
	_In_ UINT64 Pa,
	_In_ UINT64 Len,
	_Out_opt_ UINT64* RangeBase,
	_Out_opt_ UINT64* RangeSize
	)
{
	if (RangeBase != NULL) *RangeBase = 0;
	if (RangeSize != NULL) *RangeSize = 0;

	volatile NEXUS_CORE_BOOT_BLOCK* CONST Block = NexusCoreBootSlot;

	if (Block == NULL || Len == 0)
		return FALSE;

	CONST UINT64 Last = Pa + Len;
	if (Last <= Pa)                     /* wrap */
		return FALSE;

	/*
	 * A zero epoch means no region was allocated this boot. Checked BEFORE the extents so that a
	 * stale non-zero base left in a block that failed to allocate cannot open a hole.
	 */
	if (Block->TpmBootEpoch == 0)
		return FALSE;

	CONST UINT64 XBase = Block->TpmTransportBase;
	CONST UINT64 XSize = (UINT64)Block->TpmTransportSize;
	CONST UINT64 SBase = Block->TpmStateBase;
	CONST UINT64 SSize = (UINT64)Block->TpmStateSize;
	CONST UINT64 LBase = Block->TpmEventLogBase;
	CONST UINT64 LSize = (UINT64)Block->TpmEventLogSize;

	/* FULLY inside one region. A read may not span the two, nor run off the end of either. */
	if (XBase != 0 && XSize != 0 && Pa >= XBase && Last <= XBase + XSize)
	{
		if (RangeBase != NULL) *RangeBase = XBase;
		if (RangeSize != NULL) *RangeSize = XSize;
		return TRUE;
	}
	if (SBase != 0 && SSize != 0 && Pa >= SBase && Last <= SBase + SSize)
	{
		if (RangeBase != NULL) *RangeBase = SBase;
		if (RangeSize != NULL) *RangeSize = SSize;
		return TRUE;
	}

	/*
	 * ABI 19 -- the TCG2 event log. Allocated by the DXE with AllocateAnyPages exactly like the
	 * other two, published the same way, and subject to the same containment check.
	 *
	 * (!) READING IT IS THE POINT OF PUBLISHING IT. The log entry count is the only direct
	 * evidence of whether the boot loader measured through our EFI_TCG2_PROTOCOL -- TpmPresent
	 * and the MeasuredBoot log are both downstream of G1 and cannot tell the two cases apart.
	 */
	if (LBase != 0 && LSize != 0 && Pa >= LBase && Last <= LBase + LSize)
	{
		if (RangeBase != NULL) *RangeBase = LBase;
		if (RangeSize != NULL) *RangeSize = LSize;
		return TRUE;
	}

	return FALSE;
}

/*
 * Read one of the published TPM regions.
 *
 * (!) MmCopyMemory CANNOT DO THIS, and that is settled prior art in this codebase, not a guess.
 * Capture.h records the same failure for the arena: EFI-allocated memory has no frames in
 * Windows' PFN database, so the validation that makes MmCopyMemory safe for foreign memory has
 * nothing to consult and it returns STATUS_INVALID_ADDRESS every time. Whitelisting the address
 * alone would have produced a gate that says ALLOWED and a read that always fails.
 *
 * (!) MmNonCached, DELIBERATELY. This memory is shared with whatever bound to the ACPI device --
 * tpm.sys maps the same locality through its _CRS resource. The entire purpose of reading it is
 * to see writes made by that other mapping, and a cached read could satisfy itself from a stale
 * line and report "no writes" when there were writes. A false negative here would be read as a
 * measurement, which is worse than an error.
 *
 * Caveat recorded rather than hidden: mapping a page with a cache attribute different from
 * another live mapping of the same page is architecturally undefined on x86. Uncached is the
 * conventional attribute for shared register memory and the one a CRB consumer uses, so this
 * matches rather than conflicts -- but if a future read returns implausible values, THIS is the
 * first thing to suspect.
 */
static NTSTATUS
NxcPhysReadTpmRegion(
	_In_ UINT64 Pa,
	_Out_writes_bytes_(Len) void* Buffer,
	_In_ UINT32 Len,
	_Out_ SIZE_T* Transferred
	)
{
	PHYSICAL_ADDRESS Addr;
	Addr.QuadPart = (LONGLONG)Pa;

	void* CONST Va = MmMapIoSpace(Addr, (SIZE_T)Len, MmNonCached);
	if (Va == NULL)
	{
		PhysLog("phys: TPM region 0x%llX +%u -- MmMapIoSpace FAILED\n", Pa, Len);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlCopyMemory(Buffer, Va, Len);
	MmUnmapIoSpace(Va, (SIZE_T)Len);

	*Transferred = Len;
	return STATUS_SUCCESS;
}

NTSTATUS
NxcPhysRead(
	_In_ UINT64 Pa,
	_Out_writes_bytes_(Len) void* Buffer,
	_In_ UINT32 Len,
	_Out_ SIZE_T* Transferred
	)
{
	*Transferred = 0;

	if (Buffer == NULL || Len == 0)
		return STATUS_INVALID_PARAMETER;

	if (!NxcPhysIsRam(Pa, Len, NULL, NULL))
	{
		/*
		 * Not system RAM. Before refusing, check the ONE exception: memory the DXE allocated for
		 * the software TPM and published in the boot block. See the block comment above.
		 */
		if (NxcPhysIsPublishedTpmRegion(Pa, Len, NULL, NULL))
		{
			PhysLog("phys: 0x%llX +%u is a published TPM region -- allowed\n", Pa, Len);
			return NxcPhysReadTpmRegion(Pa, Buffer, Len, Transferred);
		}

		PhysLog("phys: 0x%llX +%u is NOT SYSTEM RAM -- REFUSED\n", Pa, Len);
		return STATUS_INVALID_ADDRESS;
	}

	MM_COPY_ADDRESS Src;
	Src.PhysicalAddress.QuadPart = (LONGLONG)Pa;

	return MmCopyMemory(Buffer, Src, Len, MM_COPY_MEMORY_PHYSICAL, Transferred);
}

NTSTATUS
NxcPhysRanges(
	_Out_writes_(Cap) NXCMD_PHYS_RANGE* Out,
	_In_ UINT32 Cap,
	_Out_ UINT32* Got,
	_Out_ UINT32* Total
	)
{
	*Got   = 0;
	*Total = 0;

	if (Out == NULL || Cap == 0)
		return STATUS_INVALID_PARAMETER;

	PPHYSICAL_MEMORY_RANGE CONST Ranges = MmGetPhysicalMemoryRanges();
	if (Ranges == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	/*
	 * Count the whole list before emitting any of it. The caller gets BOTH numbers even when its
	 * buffer is too small, because "how many I gave you" and "how many exist" are different facts --
	 * and a caller that only sees the first cannot tell a complete answer from a truncated one.
	 */
	UINT32 n = 0;
	while (Ranges[n].BaseAddress.QuadPart != 0 || Ranges[n].NumberOfBytes.QuadPart != 0)
		n++;
	*Total = n;

	CONST UINT32 Emit = (n < Cap) ? n : Cap;
	for (UINT32 i = 0; i < Emit; i++)
	{
		Out[i].BaseAddress   = (NXCMD_U64)Ranges[i].BaseAddress.QuadPart;
		Out[i].NumberOfBytes = (NXCMD_U64)Ranges[i].NumberOfBytes.QuadPart;
	}
	*Got = Emit;

	ExFreePoolWithTag(Ranges, 0);
	return STATUS_SUCCESS;
}
