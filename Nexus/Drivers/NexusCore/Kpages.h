/**
 * @file Kpages.h
 * @brief Per-page PTE facts for a LOADED KERNEL IMAGE, checked against its own section headers.
 *
 * Plan item 7.5, `the design notes` D13. READ ONLY -- no PTE is written.
 *
 * ============================================================================================
 * WHY THIS EXISTS: `regions --hidden` HAS NO KERNEL-SIDE EQUIVALENT
 * ============================================================================================
 *
 * `regions --hidden` finds a usermode manual map by SET SUBTRACTION -- committed memory the loader
 * does not claim. The kernel-side techniques produce nothing to subtract, because the VA range IS
 * claimed, by a signed driver, at the address the loader chose. Nobody is hiding in unclaimed space;
 * they are living inside someone else's.
 *
 * So the evidence has to be structural, and it is: **a page's PTE and the image's own section
 * headers are two independent statements about what that page is allowed to do.** The loader derived
 * the protections from the headers. If they now disagree, something rewrote one of them after load.
 *
 * ⚠ AND THE HIJACKED PTE CANNOT BE CONCEALED, EVEN BY A HYPERVISOR (D13). A guest page-table walk is
 * itself nested-translated, so cloaking the page holding a driver's PTEs would make the CPU's own
 * walker read the ORIGINAL entries -- and the hijacked code would never execute. The rewritten entry
 * has to be visible to the guest for the attack to work at all. That makes this the one artefact
 * SLAT cannot take away (an earlier finding).
 *
 * ============================================================================================
 * ⚠ THE THREE TECHNIQUES THIS IS AIMED AT -- all read out of `reference material/`, not guessed
 * ============================================================================================
 *
 * **1. GhostMapperUM** (`GhostMapperUM/pte.cpp`, in the reference tree). Marks a signed "ghost"
 * driver's whole range RWX by writing PTEs through a vulnerable Intel driver's read/write primitive,
 * copies an UNSIGNED driver over it, then tidies up in `AvoidRWXPtes`: clear `rw` on the pages it
 * classified executable, set `nx` on the ones it classified writable.
 *
 * ⚠ THE TIDY-UP IS WHAT MAKES IT FINDABLE. Those protections are derived from the layout of the
 * driver being SMUGGLED IN, not from the ghost image's own headers -- so afterwards the PTEs describe
 * a different program from the one the section table describes. A page that is writable where the
 * carrier's `.text` says it should not be is exactly that disagreement. (It also resolves
 * `MiGetPteAddress` by byte signature and takes the SECOND match, which is its own fragility, but not
 * one this command can observe.)
 *
 * **2. NX-bit swapping / VAD hiding** (charliewolfe, "Stealthy-Kernelmode-Injector"). Same family:
 * the PTE is made to say something other than what is true.
 *
 * **3. LargePageDrivers** (VollRagm). `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory
 * Management\LargePageDrivers` makes Windows map a driver on 2 MB pages, and protection applies to
 * the whole 2 MB. `.text` and `.data` then share one mapping and it must be **writable AND
 * executable**. Shellcode written into a legitimate driver's read-only data then executes, from
 * inside a valid module's range, defeating every "is this address in a loaded driver?" check.
 *
 * ⚠⚠ AND THAT LAST ONE IS ALSO THIS COMMAND'S FALSE-POSITIVE TRAP. **Windows maps `ntoskrnl.exe` and
 * `hal.dll` on large pages BY DEFAULT.** W+X across their whole range is normal, expected, and
 * present on every healthy machine. A W+X count reported without the mapping level would light up
 * ntoskrnl on the first run and teach the reader to ignore the number -- the same way `procs
 * --hidden` produced seven false positives before terminating processes were separated out. So W+X
 * is reported SPLIT: on a large page (structural, expected) versus on a 4 KB page (nothing forces it,
 * and the loader would not have chosen it).
 *
 * ============================================================================================
 * EVIDENCE, NEVER A VERDICT (D6)
 * ============================================================================================
 *
 * Every disagreement below has an innocent explanation available -- a driver that legitimately calls
 * `MmProtectDriverSection`, a page Patchguard is mid-verification of, a section whose characteristics
 * the loader deliberately widened. This command reports WHAT IT SAW and WHAT WAS EXPECTED, side by
 * side, and leaves the judgement where it belongs.
 */

#pragma once

#include <ntddk.h>
#include "../../Include/NexusCommand.h"

/**
 * Walk a loaded kernel image page by page.
 *
 * ⚠ READS ONLY, INCLUDING THE HEADERS. The section table comes from the image AS MAPPED, which is
 * the only copy that matters: comparing against the on-disk file would answer a different question
 * (has the file changed?) and would require I/O this driver cannot do.
 *
 * ⚠ THE EXPECTATION IS DERIVED PER PAGE, NOT PER SECTION, because a page can straddle a section
 * boundary when sections are not page-aligned in memory. A straddling page is reported as covered by
 * the section that CONTAINS ITS START and marked as straddling, rather than being silently
 * attributed to one of them -- a mismatch on a straddling page is an artefact of the boundary, not
 * evidence, and conflating the two would manufacture findings.
 *
 * @param Name      module name as `PsLoadedModuleList` spells it, e.g. "ntoskrnl.exe"
 * @param Got       pages written
 * @param Total     pages the image HAS, so truncation cannot read as completeness (D3)
 * @param OutBase   where the image was found
 * @param OutSize   its SizeOfImage
 */
NTSTATUS NxcKpages(
	_In_z_ CONST CHAR* Name,
	_Out_writes_(Cap) NXCMD_KPAGE* Out,
	_In_ UINT32 Cap,
	_In_ UINT32 SkipPages,
	_Out_ UINT32* Got,
	_Out_ UINT32* Total,
	_Out_ UINT64* OutBase,
	_Out_ UINT32* OutSize
	);
