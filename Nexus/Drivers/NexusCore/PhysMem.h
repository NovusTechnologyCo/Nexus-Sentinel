/**
 * @file PhysMem.h
 * @brief Physical memory reads, gated on the machine's RAM map.
 *
 * ============================================================================================
 * WHY THIS FILE EXISTS AS A SEPARATE GATE
 * ============================================================================================
 *
 * `MmCopyMemory` with `MM_COPY_MEMORY_PHYSICAL` maps and reads WHATEVER physical address it is
 * handed. It does not know, and cannot know, whether that address is RAM or a device register.
 *
 * Reading a device register is not a read. It can clear a status bit, pop a FIFO, acknowledge an
 * interrupt, or hang on an unpopulated bus address. On THIS machine that class of access froze the
 * host TWICE via `MmMapIoSpace`, which is why v1's physical-read implementation is not
 * being ported and why this one is gated.
 *
 * Every physical read here is checked for full containment in ONE range from
 * `MmGetPhysicalMemoryRanges` before it is issued.
 *
 * ============================================================================================
 * ⚠ WHY THE GATE LIVES HERE AND NOT AT THE CALL SITES
 * ============================================================================================
 *
 * It started at the call site, in NXCMD_OP_READ_PHYS, where the address comes from a human typing a
 * command -- a mistyped digit, at worst. It was moved here the moment the SECOND caller appeared,
 * and that second caller is the reason the gate is load-bearing rather than tidy:
 *
 *   NxcTranslate walks a TARGET PROCESS's page tables. Every table address after CR3 is read OUT OF
 *   THE TARGET'S OWN PAGE TABLES -- memory the target can write. A process that puts an MMIO address
 *   in a PDPTE entry hands us a device register to read, and we would read it while believing we
 *   were reading a page table.
 *
 * So the input is not merely untrusted, it is ATTACKER-INFLUENCED, and one gate every path must pass
 * through is the only version of this that stays true as callers are added. Two copies of a safety
 * check is one copy that gets forgotten.
 *
 * (Recorded because the reasoning is not visible from either call site: at the call site the address
 * looks like it came from a page table, which sounds trustworthy. It is not -- the page table is the
 * target's.)
 */

#pragma once

#include <ntddk.h>
#include "../../Include/NexusCommand.h"

/**
 * Is [Pa, Pa+Len) entirely inside ONE system RAM range?
 *
 * Full containment in a SINGLE range, deliberately. The gap between two RAM ranges is not memory,
 * and a read that quietly stopped at the boundary would read as "memory ends here" when the truth is
 * "you asked for a hole".
 *
 * FAILS CLOSED. If the RAM map cannot be obtained this returns FALSE, because without it there is no
 * way to tell RAM from MMIO -- and the unchecked read is the one that freezes the host. Refusing
 * loses a diagnostic; guessing loses the machine.
 *
 * @param RangeBase  optional; on TRUE, the base of the enclosing range
 * @param RangeSize  optional; on TRUE, the size of the enclosing range
 */
BOOLEAN NxcPhysIsRam(
	_In_ UINT64 Pa,
	_In_ UINT64 Len,
	_Out_opt_ UINT64* RangeBase,
	_Out_opt_ UINT64* RangeSize
	);

/**
 * Read physical memory into a KERNEL buffer, refusing anything that is not RAM.
 *
 * ⚠ THE DESTINATION MUST BE KERNEL MEMORY. MmCopyMemory writes to its destination directly, with no
 * probe, and there is no SEH in this driver to catch a fault -- so it must never be pointed at a
 * usermode buffer. Callers serving a usermode caller stage into pool and make the second hop with
 * MmCopyVirtualMemory, which returns a status instead of raising.
 *
 * @param Transferred  bytes actually read; MAY BE LESS THAN Len and that is not a failure. Callers
 *                     are required to inspect it rather than assume Len.
 * @return the MmCopyMemory status, or STATUS_INVALID_ADDRESS if the range is not RAM.
 */
/**
 * TRUE if [Pa, Pa+Len) lies wholly inside one of the two software-TPM regions the DXE published
 * in the boot block (ABI 17).
 *
 * (!) THE ONE EXCEPTION TO THE RAM-MAP RULE, and it is narrow on purpose. Those regions are
 * EfiACPIMemoryNVS, which Windows does not report as system RAM, so NxcPhysIsRam refuses them --
 * correctly, since from the RAM map alone our own DRAM and a device BAR look identical.
 *
 * The allowance is safe for reasons that invert the freezes: the address is not
 * caller-chosen but one the DXE allocated and published, it is known DRAM rather than device
 * registers, a read has no side effects, and containment is checked so it cannot be walked
 * outward. Returns FALSE if the boot block is absent, the extents are zero, or the epoch is zero.
 *
 * (!) MUST BE CHECKED AT EVERY GATE, not just inside NxcPhysRead. Command.c refuses non-RAM
 * addresses EARLY, before allocating a staging buffer, and that gate is deliberately a second
 * copy -- so a whitelist applied to only one of them is silently ineffective. That shipped once
 * and cost a reboot: PlatformCtl still reported "NOT SYSTEM RAM" while the read path would have
 * allowed it.
 *
 * @param RangeBase  the enclosing region base on a hit, so a caller can report the bounds
 * @param RangeSize  that region size
 */
BOOLEAN NxcPhysIsPublishedTpmRegion(
	_In_ UINT64 Pa,
	_In_ UINT64 Len,
	_Out_opt_ UINT64* RangeBase,
	_Out_opt_ UINT64* RangeSize
	);

NTSTATUS NxcPhysRead(
	_In_ UINT64 Pa,
	_Out_writes_bytes_(Len) void* Buffer,
	_In_ UINT32 Len,
	_Out_ SIZE_T* Transferred
	);

/**
 * Copy the RAM map into @p Out.
 *
 * @param Got    entries written (<= Cap)
 * @param Total  entries that EXIST. Separate from Got on purpose: truncation must never be able to
 *               read as completeness.
 */
NTSTATUS NxcPhysRanges(
	_Out_writes_(Cap) NXCMD_PHYS_RANGE* Out,
	_In_ UINT32 Cap,
	_Out_ UINT32* Got,
	_Out_ UINT32* Total
	);
