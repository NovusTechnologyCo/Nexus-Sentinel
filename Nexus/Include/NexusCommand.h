/**
 * @file NexusCommand.h
 * @brief The command protocol PlatformCtl uses to drive NexusCore. Shared by all three components.
 *
 * Travels over the EXISTING backdoor channel -- SetVariable on L"BootOrderCacheV2" under
 * gEfiGlobalVariableGuid -- so commands add no new artifact. Status is read back through
 * GetVariable on the same name: one non-standard variable name serves both directions, because a
 * second name would be a second thing to find.
 *
 * Compiles under the UEFI toolchain, the WDK and a host compiler, so it uses only locally declared
 * fixed-width types. Add nothing here that pulls in <Uefi.h> or <ntddk.h>.
 *
 * ============================================================================================
 * WHY A POINTER AND NOT THE IMAGE BYTES -- settled by all three research tiers
 * ============================================================================================
 *
 * TIER 3 (v1): MAPPER_LOAD_REQUEST carried the image INLINE via a trailing flexible array
 *   (`sizeof(req) - 1 + ImageSize`). That couples the maximum driver size to the channel's size
 *   limit, and our backdoor caps at 64 KB while SentinelHV is 100 KB on disk. Does not scale.
 *
 * TIER 1: BOTH usermode references pass a POINTER, independently of each other and of us --
 *   BlackAlien's redlotus client keeps `PVOID DriverBuffer; ULONG DriverSize`, and GhostMapperUM
 *   reads into a std::vector and passes `RawImage.data()`. GhostMapperUM also answers the buffer
 *   LIFETIME question: the vector stays in scope across a SYNCHRONOUS call, so the caller simply
 *   must not free until the kernel returns. Our SetVariable call is synchronous, so that holds by
 *   construction.
 *   They DIFFER on pre-validation: redlotus checks the PE headers in usermode first, GhostMapperUM
 *   does not. Redlotus is right -- it keeps malformed files out of the kernel path entirely for the
 *   cost of a header read.
 *
 * TIER 2: ProbeForRead gives "no guarantees that this address will remain valid after the probe",
 *   so its correct use REQUIRES try/except against another thread freeing or re-protecting the
 *   range. We cannot use SEH at all in a mapped driver (see NexusModule.h), which makes ProbeForRead
 *   not merely inferior but UNUSABLE here. MmCopyVirtualMemory returns NTSTATUS instead of raising,
 *   which is why it is the only correct choice -- and it requires PASSIVE_LEVEL, so the CR8 gate
 *   already in the DXE hook is mandatory rather than defensive.
 */

#pragma once

typedef unsigned char      NXCMD_U8;
/* Added for NXCMD_CALL_ENTRY. A UTF-16 code unit is 16 bits and storing it in anything
 * wider would double the size of every captured path for no information gained -- and `wchar_t` is
 * not usable here, because this header is shared with kernel code compiled without it. */
typedef unsigned short     NXCMD_U16;
typedef unsigned int       NXCMD_U32;
typedef unsigned long long NXCMD_U64;

/* 'NXCC' -- validated before any other field is trusted, on both sides. */
#define NEXUS_CMD_MAGIC   0x4343584EULL
#define NEXUS_CMD_ABI     6u   /* 6: NXCMD_OP_READ -- read a live kernel module by name.
                                * 2: DiagCallerPid. 3: DiagRefusalLine. 4: DiagFlags.
                                * 5: TargetModuleId -- the first CALLER-written field added
                                *    since ABI 1; see the note on it for why the existing
                                *    ModuleId could not carry an input. */

/* Command codes. Only MAP exists today; the rest are added when they are REAL, never before. */
#define NXCMD_OP_NOP      0u   /* liveness probe: validates the channel without doing anything */
#define NXCMD_OP_MAP      1u   /* map the image at ImageBuffer/ImageSize                        */
#define NXCMD_OP_UNMAP    2u   /* tear down + reclaim the module in TargetModuleId               */
#define NXCMD_OP_READ     3u   /* read TargetName+ReadOffset into OutBuffer; see the ABI 6 block */
#define NXCMD_OP_WATCH    4u   /* capture TargetName's PRISTINE image at its next load            */
#define NXCMD_OP_REGIONS  5u   /* enumerate a process's user VA regions into OutBuffer            */
#define NXCMD_OP_MODULES  6u   /* enumerate a process's LOADER module list into OutBuffer         */

/*
 * Read from a PROCESS's virtual address space. TargetModuleId = pid, ReadOffset = ABSOLUTE VA.
 *
 * ⚠ SEPARATE FROM NXCMD_OP_READ ON PURPOSE. That one resolves a KERNEL MODULE BY NAME and reads at
 * an offset within it; this reads an absolute VA inside a target process. Different addressing,
 * different target, different failure modes — and v1 kept them separate too
 * (`IOCTL_NEXUS_KERNEL_READ` vs `IOCTL_NEXUS_READ_MEMORY`).
 *
 * Folding them into one opcode with a mode flag would put two problems behind one name, which is
 * exactly the merge this project's redevelopment rules forbid.
 */
#define NXCMD_OP_READ_PROC 7u

/*
 * Read PHYSICAL memory. ReadOffset = physical address, OutBuffer/ReadLength as usual.
 *
 * Solves a distinct problem from either read above: it reads memory whose VIRTUAL mapping is absent
 * or is LYING. A target that unmaps a page after decrypting it, or hooks the page tables so a VA
 * resolves somewhere harmless, is still holding physical pages that contain the real bytes.
 *
 * ⚠ REFUSES ANY ADDRESS THAT IS NOT SYSTEM RAM, and that gate is the feature, not a formality.
 * MM_COPY_MEMORY_PHYSICAL maps whatever it is handed, including device MMIO -- where a "read" can
 * clear a status bit, pop a FIFO or hang on an unpopulated bus address. That is what froze this host
 * twice under v1's MmMapIoSpace-based implementation. Full containment in ONE range from
 * MmGetPhysicalMemoryRanges is required, so the failure mode is unreachable rather than avoided.
 *
 * Spanning two ranges is refused rather than clamped: the gap between two RAM ranges is not memory,
 * and a read that quietly stopped at one would read as "memory ends here" when the truth is "you
 * asked for a hole". Issue two reads.
 */
#define NXCMD_OP_READ_PHYS 8u

/*
 * Enumerate the machine's physical RAM ranges into OutBuffer, as NXCMD_PHYS_RANGE entries.
 *
 * Exists because NXCMD_OP_READ_PHYS's safety gate would otherwise be a black box -- a caller told
 * only "that is not RAM" cannot tell whether they mistyped an address or whether the machine simply
 * has a hole there. Enumeration turns the refusal into something actionable.
 *
 * Independently useful: the RAM map is the ground truth for where anything can physically be, and
 * on this machine it is not derivable from the total memory size (firmware reservations put real
 * holes in it).
 */
#define NXCMD_OP_PHYS_RANGES 9u

/*
 * Translate a VA in a target process to a physical address. TargetModuleId = pid,
 * ReadOffset = the VA, OutBuffer receives an NXC_XLAT.
 *
 * Answers WHERE so NXCMD_OP_READ_PHYS can answer WHAT. Together they read memory a target has
 * unmapped, or is lying about through its own page tables.
 *
 * ⚠ A NOT-PRESENT VA IS AN ANSWER, NOT AN ERROR. The struct comes back either way, carrying the
 * level the walk stopped at -- a region the loader still reports as committed whose PDE is absent
 * has been unmapped underneath the reported state, and that IS the finding.
 */
#define NXCMD_OP_VA2PA 10u

/*
 * Enumerate BIG-pool allocations into OutBuffer as NXCMD_POOL_ENTRY records.
 * TargetModuleId = tag filter as a ULONG (0 = every tag); ReadOffset = minimum size (0 = any).
 *
 * Finds a driver's RUNTIME state -- decrypted tables, resolved pointers, scan results -- which
 * belongs to no image and appears in no module list.
 *
 * ⚠⚠ IT ONLY SEES *BIG* POOL: allocations that got their own page(s), roughly >= PAGE_SIZE. Smaller
 * allocations are subdivided out of pool pages and DO NOT APPEAR AT ALL. An empty result therefore
 * means "no BIG allocation carries that tag" -- NOT that the tag is unused and NOT that the driver
 * allocated nothing. The enumeration looks exhaustive and is not, which is why the reporting side
 * states this on every empty result rather than only in a comment.
 */
#define NXCMD_OP_POOL_LIST 22u

#define NXCMD_POOL_NONPAGED 0x00000001u

/*
 * Plant bait allocations (23) and release them (24).
 * TargetModuleId = tag, ReadOffset = size in bytes, and the COUNT is however many
 * NXCMD_POOL_ENTRY records fit in OutBuffer.
 *
 * ⚠ THE COUNT IS THE BUFFER CAPACITY BY DESIGN. It was briefly passed in Flags, which is exactly the
 * alternative this file's own ABI note records as rejected ("an id is not a flag, and the name would
 * mislead every future reader") -- a count is not a flag for the same reason. Using the capacity
 * needs no new field and is honest: bait we cannot describe back is bait the caller has no address
 * for, and since this driver never unloads, an unreportable block is a permanent leak with no handle.
 *
 * A GENERAL scanner-characterisation primitive: plant allocations a pool scanner can see, then
 * observe whether and how it reacts. v1's version was written for one target and documented in its
 * terms; the technique is not target-specific.
 *
 * ⚠ THE REACTION IS READ IN USERMODE. Without a hypervisor there is no way to trap the READ of a
 * bait block, so the kernel plants and reports — it cannot observe the scan. Claiming otherwise
 * would be inventing a signal we do not have.
 *
 * ⚠ DELIBERATE EXCEPTION TO D4 ("storage from the arena, never pool"). D4 exists because pool
 * allocations are tagged and enumerable — which is exactly what bait needs to be. An arena block
 * would never appear in SystemBigPoolInformation and no scanner would ever see it.
 *
 * ⚠ BAIT OUTLIVES THE COMMAND AND THIS DRIVER NEVER UNLOADS. A plant with no matching free is a
 * permanent non-paged leak, so planting while a set is outstanding is REFUSED rather than added to.
 */
#define NXCMD_OP_POOL_BAIT      23u
#define NXCMD_OP_POOL_BAIT_FREE 24u

/*
 * PROVE the writable-alias primitive against a page NexusCore allocated itself (25).
 *
 * Stage 1 of the inline hook. An inline hook must write to a page mapped R-X, and CR0.WP is banned
 * here -- the window is preemptible and already caused a 0xEF, with CET active on top. So the write
 * goes through a SECOND VA mapping the same frames, created writable, while the executable mapping
 * is never touched.
 *
 * ⚠ THE CALLS SUCCEEDING PROVES NOTHING. A mapping that quietly pointed at DIFFERENT frames would
 * also "succeed". What this checks is that a write through the ALIAS is visible through the ORIGINAL
 * address -- the premise every inline hook rests on, and the one thing that cannot be inferred from
 * a status code. It installs no hook and touches nothing but its own scratch page.
 */
#define NXCMD_OP_ALIAS_TEST 25u

/*
 * Drain the event log ring (26). ReadOffset = the highest sequence the caller already has
 * (0 = everything still resident).
 *
 * ⚠ LOST IS REPORTED SEPARATELY FROM GOT. The ring overwrites its oldest entries rather than
 * stopping -- the interesting moment is almost always the most recent. But a log that silently drops
 * entries is worse than no log, so every entry carries a monotonic sequence and a reader that fell
 * behind is told exactly how many it missed. Truncation must never read as completeness.
 */
#define NXCMD_OP_LOG_DRAIN 26u

#define NXCMD_LOG_KIND_COMMAND  1u   /* a command was serviced          */
#define NXCMD_LOG_KIND_HOOK     2u   /* reserved for the inline hook    */

#pragma pack(push, 1)
typedef struct _NXCMD_LOG_ENTRY
{
	NXCMD_U64 Sequence;    /* monotonic; written LAST so a torn slot is detectable */
	NXCMD_U64 Timestamp;   /* raw TSC                                              */
	NXCMD_U64 A;
	NXCMD_U64 B;
	NXCMD_U64 C;
	NXCMD_U32 Kind;        /* NXCMD_LOG_KIND_*                                     */
	NXCMD_U32 Cpu;
	NXCMD_U32 ProcessId;
	NXCMD_U32 Reserved0;
} NXCMD_LOG_ENTRY;
#pragma pack(pop)

#pragma pack(push, 1)
/*
 * PatchGuard context scan -- NXCMD_OP_PG_SCAN. See Drivers/NexusCore/PgScan.h.
 *
 * (!) A ZERO RESULT IS NOT PROOF PATCHGUARD IS ABSENT. It means no big-pool allocation carried
 * these signatures, and it is worthless until the detector has been seen to FIND a context on a
 * boot with PG patching disabled. The reporting side must say so on every empty result.
 */
#define NXCMD_OP_PG_SCAN 81u

/*
 * (!) 0x01 and 0x02 ARE RETIRED, NOT FREE. They were SIZE (~1 MB) and UNALIGNED (base not
 * 16-byte aligned). Both were measured WRONG against a real context and removed;
 * the values are left unused so a stale PlatformCtl cannot light up a bit that now means
 * something else. See Drivers/NexusCore/PgScan.h for the measurement.
 */
#define NXCMD_PGSIG_CONST_A    0x04u  /* 0x5C5FC0A76E374B18 in plaintext -- NOT SEEN in practice */
#define NXCMD_PGSIG_CONST_B    0x08u  /* 0x4C48B4211BBACBEB in plaintext -- NOT SEEN in practice */
#define NXCMD_PGSIG_RWX        0x10u  /* writable AND executable. MEASURED: PG's pages are NX,   */
                                      /* so this is a NEGATIVE indicator. Reported, never strong */
#define NXCMD_PGSIG_STUB       0x20u  /* PG's unrolled XOR decryption loop -- the real signature */

#pragma pack(push, 1)
typedef struct _NXCMD_PG_CANDIDATE
{
	NXCMD_U64 Address;
	NXCMD_U64 SizeInBytes;
	NXCMD_U32 TagUlong;
	NXCMD_U32 Signatures;   /* NXCMD_PGSIG_* */
	NXCMD_U64 HitOffset;
} NXCMD_PG_CANDIDATE;
#pragma pack(pop)

/*
 * ============================================================================================
 * BOOT CONTROL ONE-SHOT -- the positive control NXCMD_OP_PG_SCAN needs to mean anything
 * ============================================================================================
 *
 * pgscan is UNVALIDATED until it has been seen to FIND a PatchGuard context. A detector that has
 * only ever returned zero is indistinguishable from a detector that is broken, and zero is
 * precisely the answer the operator WANTS -- which is the worst possible combination. So there
 * has to be a boot on which a context MUST exist, and something has to arrange one.
 *
 * The boot menu cannot: its only escape hatch is `[C] Boot clean`, which skips NexusBootDxe
 * ENTIRELY -- and the DXE is what maps NexusCore, so a clean boot has no pgscan to run. Clean
 * boot answers "does the machine boot without us", not "does PatchGuard look like this". They
 * are different questions and only one of them needs a control.
 *
 * So: a variable written from Windows, read once by the DXE at entry, and DELETED THERE AND THEN.
 *
 * (!) ONE-SHOT IS THE WHOLE SAFETY PROPERTY, not a convenience. This flag leaves PatchGuard LIVE
 * for a boot, on a machine carrying a manually-mapped driver. If it persisted, forgetting to
 * clear it would leave every later boot in that state -- silently, because the symptom is a
 * bugcheck minutes or hours later that looks like any other instability. Consuming it at entry
 * makes "armed" a property of exactly one boot, and makes a forgotten flag impossible rather
 * than merely unlikely.
 *
 * NAMED FOR THE SAME REASON THE BACKDOOR VARIABLE IS (see Protocol/NexusBoot.h): UEFI variable
 * names are readable by anything with the privilege to enumerate them, so it does not announce
 * the project.
 *
 * ============================================================================================
 * ⚠⚠ A PRIVATE VENDOR GUID, *NOT* EFI_GLOBAL_VARIABLE. measured -- DO NOT "FIX" THIS
 * ============================================================================================
 *
 * This variable does NOT share the command channel's GUID, and the reason is not stylistic. The
 * first version used EFI_GLOBAL_VARIABLE for consistency with L"BootOrderCacheV2" and failed on
 * the first write with ERROR_INVALID_PARAMETER (87). A probe over four combinations settled it:
 *
 *     name under EFI_GLOBAL_VARIABLE, non-volatile   -> 87
 *     name under EFI_GLOBAL_VARIABLE, volatile       -> 87
 *     L"BootOrderCacheV2" itself, under that GUID    -> 87      <-- the control
 *     same name under a private vendor GUID          -> writes, reads back, deletes
 *
 * UEFI s3.3 reserves the EFI_GLOBAL_VARIABLE namespace for the specification, and this firmware
 * enforces it: an unrecognised name there cannot be CREATED at all.
 *
 * (!) AND THE CONTROL CASE IS THE INTERESTING ONE. L"BootOrderCacheV2" fails too -- so the
 * command channel has never written a UEFI variable in its life. HookedSetVariable intercepts
 * that name and returns EFI_SUCCESS itself ("this variable does not exist there"). Every
 * PlatformCtl command that has ever "worked" proved the HOOK works, and proved nothing whatever
 * about NVRAM. Anything that needs to survive a reboot -- which is exactly what this one-shot is
 * -- must use a private GUID and must be tested against real firmware, because the channel we
 * use every day silently does not touch it.
 */
#define NXCMD_BOOTCTL_VAR_NAME      L"BootOrderCacheV3"
#define NXCMD_BOOTCTL_COOKIE        0x9E17C7A1u

/*
 * The same GUID in the two spellings the two ends need: Windows takes it as a bracketed string,
 * EDK2 as an EFI_GUID initializer. Kept adjacent so they cannot drift -- there is no compiler
 * that would catch a mismatch here, and the symptom would be the DXE finding no variable while
 * PlatformCtl reports it wrote one.
 */
#define NXCMD_BOOTCTL_VAR_GUID_STR  L"{6F3B1A2C-9D74-4C51-8E0A-3C7D5B2E41F9}"
#define NXCMD_BOOTCTL_VAR_GUID_INIT \
	{ 0x6F3B1A2C, 0x9D74, 0x4C51, { 0x8E, 0x0A, 0x3C, 0x7D, 0x5B, 0x2E, 0x41, 0xF9 } }

/*
 * (!) BOTH ENDS READ THESE DEFINITIONS. The DXE compiles this header, and so does PlatformCtl --
 * deliberately, because the cookie, the size and the flag bits are a WIRE FORMAT, and this
 * project has been bitten repeatedly by two lists that must agree. There is one list.
 */
#define NXCMD_BOOTCTL_SKIP_PG       0x00000001u  /* do NOT defuse PatchGuard on the next boot */

#pragma pack(push, 1)
typedef struct _NXCMD_BOOT_CONTROL
{
	NXCMD_U32 Cookie;   /* NXCMD_BOOTCTL_COOKIE, or the DXE ignores the whole variable */
	NXCMD_U32 Flags;    /* NXCMD_BOOTCTL_* */
} NXCMD_BOOT_CONTROL;
#pragma pack(pop)

typedef struct _NXCMD_POOL_ENTRY
{
	NXCMD_U64 VirtualAddress;   /* bit 0 ALREADY MASKED OFF -- it is the NonPaged flag, not address */
	NXCMD_U64 SizeInBytes;
	NXCMD_U32 TagUlong;
	NXCMD_U32 Flags;            /* NXCMD_POOL_* */
} NXCMD_POOL_ENTRY;
#pragma pack(pop)

/*
 * Intel PT buffers: allocate (19), free (20), report (21).
 *
 * ⚠ STAGE 1 ALLOCATES ONLY. No MSR is written and no trace can start. The split is deliberate: the
 * allocation is verifiable by inspection (physical addresses, alignment, did the contiguous
 * allocation succeed), whereas arming is not -- a wrong ToPA entry handed to enabled hardware is the
 * CPU writing to a physical address we chose. Proving the addresses with nothing enabled is the only
 * order in which a mistake is cheap.
 */
#define NXCMD_OP_TRACE_ALLOC  19u
#define NXCMD_OP_TRACE_FREE   20u
#define NXCMD_OP_TRACE_STATUS 21u

/*
 * STAGE 2: arm (27) and disarm (28) Intel PT.
 * TargetModuleId = pid to scope to via CR3 filtering (0 = unfiltered); Flags = a single CPU index
 * plus 1, or 0 for all cores.
 *
 * ⚠ SCOPING TO A PID IS THE NORMAL USE, not an option. Unfiltered tracing on 24 cores fills a
 * 256 KB per-core buffer in well under a second, so an unscoped trace answers "what did the whole
 * machine just do" -- which is almost never the question and destroys the window that was wanted.
 *
 * ⚠ ARMING RE-CHECKS EVERYTHING cpuprobe ALREADY REPORTED, on the arming core itself: PT presence,
 * ToPA support, CR3-filter support, and whether TraceEn is already set. A probe result is a
 * measurement from the past, this machine is hybrid so another core's answer is not this core's,
 * and Ipt.sys can claim PT in between. Arming over a live tracer would silently steal it.
 */
#define NXCMD_OP_TRACE_ARM    27u
#define NXCMD_OP_TRACE_DISARM 28u

/*
 * ============================================================================================
 * INLINE HOOK (build-plan item 21, decision D14). ONE aligned 8-byte store, or nothing.
 * ============================================================================================
 *
 * `hook <va>`   NXCMD_OP_HOOK_INSTALL, ReadOffset = the kernel VA to patch,
 *               TargetModuleId = PID FILTER (0 = every process). Only hits taken by that process
 *               are RECORDED; the target still runs identically for everyone else, and the skipped
 *               hits are counted and reported by CALLS_READ in ModuleId. measured:
 *               NtProtectVirtualMemory takes ~500 hits/sec on an idle desktop, so an unfiltered
 *               ring wraps in about a second and a hot syscall is not capturable without this.
 * `unhook <va>` NXCMD_OP_HOOK_REMOVE,  ReadOffset = the same VA
 * `hook list`   NXCMD_OP_HOOK_LIST,    OutBuffer receives NXCMD_HOOK_INFO records
 *
 * ⚠ THE PATCH IS FIVE BYTES (`E9 rel32`) SPLICED INTO ONE ALIGNED QWORD AND STORED ONCE, not a
 * 14-byte `FF 25` detour. x86 guarantees a naturally aligned store of <= 8 bytes is atomic; there is
 * no such guarantee for 14, and v1's 14-byte version was 2-3 separate stores that another core could
 * catch mid-write. The store happens inside a KeIpiGenericCall broadcast, which is what satisfies the
 * SDM's OTHER requirement -- that the processors which will execute the changed bytes serialize.
 *
 * ⚠ IT REFUSES RATHER THAN FALLING BACK, and `BytesRead` carries NXCMD_HOOK_* naming which check
 * said no. v1 tried MDL, then MmMapIoSpace, then CR0.WP=0, stopping at whichever appeared to stick;
 * on this machine the second froze the host twice and the third caused a 0xEF. There is one write
 * path here (the writable alias) and no second attempt.
 *
 * ⚠ AND STAGE 1'S DETOUR IS A NO-OP -- it jumps to a stub that jumps to the trampoline that returns
 * to the target. The hooked function behaves identically, which is the point: every hard part is
 * exercised while the code at the patched address touches no register.
 *
 * `ModuleBase` returns the measured handler-target displacement on EVERY outcome, success or not.
 * Out-of-range by 40 bytes and out-of-range by 4 GB call for completely different work.
 */
#define NXCMD_OP_HOOK_INSTALL 29u
#define NXCMD_OP_HOOK_REMOVE  30u
#define NXCMD_OP_HOOK_LIST    31u

/*
 * `hook selftest` -- install, CALL, remove, and check the bytes came back, on a function inside
 * NexusCore whose only caller is the test.
 *
 * ⚠ EXISTS BECAUSE EVERY OTHER HOOK CHECK IS A REFUSAL. The harness deliberately never patches
 * anything: a suite that patches live kernel code and relies on its own assertions to take the
 * patch back out is one failed assertion from leaving a jump into freed memory. So the entire
 * INSTALL side had never executed, and a mechanism only ever observed saying no is not one anyone
 * has evidence works.
 *
 * The detour is a no-op, so the original answer can only come back if the patched jump reached the
 * stub, the stub reached the trampoline, the stolen instructions ran correctly at their NEW
 * address, and the jump back landed exactly at target+N. `BytesRead` is the step that failed
 * (NXCMD_HOOK_ST_*) and `ModuleSize` the NXCMD_HOOK_* reason when that step was an install or a
 * removal.
 */
#define NXCMD_OP_HOOK_SELFTEST 32u

/*
 * `trace dump --cpu N` -- copy RAW trace bytes out of one CPU's output region.
 * TargetModuleId = cpu, ReadOffset = byte offset within the region, OutBuffer/ReadLength as usual.
 *
 * ⚠ RAW BYTES, NO INTERPRETATION -- D5. The kernel reports facts and usermode decides. An Intel PT
 * packet decoder inside a manually mapped image with no SEH, run against a region hardware may still
 * be writing, would be the most fragile code in this project and would buy nothing: the bytes are
 * identical either side of the channel.
 *
 * TIER 1 arrives at the same split independently -- Cheat Engine's ultimap2 does not decode in the
 * kernel either; it maps the ToPA buffer into the waiting usermode process.
 *
 * ⚠ OFFSET 0 IS NOT THE START OF ANYTHING once the region has wrapped. Byte 0 is then whatever the
 * writer last put there, almost certainly mid-packet. Decoding must begin at a PSB, which is exactly
 * what PSB is for. Nothing here guesses a start point: guessing and being wrong yields a decode that
 * looks successful and is fiction.
 *
 * `BytesRead` is what was ACTUALLY copied (D3) -- a request past the end of the region is clamped
 * rather than refused, because walking a buffer in chunks should not need a special last case.
 */
#define NXCMD_OP_TRACE_DUMP 33u

/*
 * `idt <vector>` -- READ the IDT gate and derive its handler's direct call targets.
 * TargetModuleId = vector; OutBuffer receives one NXCMD_IDT_PROBE.
 *
 * ⚠ READ-ONLY, AND THAT IS THE WHOLE DESIGN (the design notes D15). The plan called item 15
 * "idt hook <vector>" and treated intercepting the vector as the hard part. It is not: a FUNCTION
 * hook on the exception dispatcher reaches the same events and beats a gate rewrite on every axis
 * here -- one patch instead of 24 per-CPU IDTs that must agree, an `unhook` that exists, and it is
 * not what PatchGuard checks. So the IDT keeps the one property that made it attractive (the CPU
 * itself must keep it correct, making it version-independent where a byte signature is not) and
 * loses the part that made it dangerous.
 *
 * ⚠ THE REAL PROBLEM IS RESOLUTION. Measured off this machine's ntoskrnl: `KiDispatchException` and
 * `KdTrap` are NOT exported. So the dispatcher must be derived, and this is the derivation's first
 * half -- `__sidt`, then the gate, then `RtlLookupFunctionEntry` for exact bounds, then a decode of
 * the body, keeping call targets that are themselves .pdata function STARTS.
 *
 * ⚠ IT REPORTS CANDIDATES AND EVIDENCE, NEVER A PICK (D6). Deciding which target is the dispatcher
 * is a judgement, and a wrong one would put a hook on a function nobody intended.
 */
#define NXCMD_OP_IDT_PROBE 34u

/*
 * `threads <pid>` -- enumerate a process's threads FROM THE KERNEL, by CID sweep.
 * TargetModuleId = pid; OutBuffer receives NXCMD_THREAD_ENTRY records.
 *
 * ⚠ NOT `ZwQuerySystemInformation`, WHICH IS WHAT v1 USED. That is the usermode-visible snapshot --
 * the same source Toolhelp reads, and precisely the one anything concealed would be absent from.
 * v2 already treats it as a thing to check AGAINST rather than trust: `procs --hidden` is a CID
 * sweep MINUS that snapshot. Enumerating threads from it would inherit the blind spot the rest of
 * this phase exists to close.
 *
 * ⚠ EXISTS BECAUSE `bp set` NEEDS IT. A hardware breakpoint "on a process" is a debug-register write
 * on EVERY thread, because Windows keeps debug registers as per-thread context restored across a
 * context switch. Found by mapping v1's ioctl surface (D20), not by hitting the wall mid-build.
 *
 * ⚠ `PsGetNextProcessThread` -- the obvious way to walk one process's threads -- is NOT EXPORTED on
 * this machine (measured). Hence the sweep. `Terminating` is reported rather than filtered, because
 * a terminated-but-referenced thread stays in the CID table and vanishes from the snapshot: exactly
 * the shape that gave `procs --hidden` seven false positives on its first run.
 */
#define NXCMD_OP_THREADS 35u

/*
 * `bp list [pid]` -- read the debug registers. STAGE 1: nothing is ever armed.
 * TargetModuleId = pid for the per-thread view; 0 for the per-CPU view only.
 *
 * ⚠ TWO VIEWS BECAUSE THERE ARE TWO TRUTHS. The PER-CPU view is what is physically in DR0-3/DR7 on
 * each core -- the CONTENTION check, same discipline `trace arm` applies before touching PT. The
 * PER-THREAD view is each thread's SAVED context, which is what a breakpoint actually IS on Windows:
 * the registers are per-thread state restored across a context switch, so a raw driver write to a
 * CPU's DRs is transient and would work only sometimes (the design notes D22).
 *
 * ⚠⚠ THE PER-THREAD VIEW REFUSES A FROZEN PROCESS. PsGetContextThread on a non-current thread queues
 * an APC and WAITS, and a suspended thread never delivers it -- so inspecting a frozen target would
 * block the command path forever. The machine would look healthy while the command never returned.
 * Set breakpoints first, then freeze.
 */
#define NXCMD_OP_BP_LIST 36u

/*
 * `lbr read` -- the Last Branch Record ring on every logical processor. STAGE 1: READS ONLY.
 * OutBuffer receives NXCMD_LBR_CPU records, one per core.
 *
 * ⚠ ARCHITECTURAL LBR ONLY, AND FAIL-CLOSED. Enable moved to IA32_LBR_CTL[0], there is no TOS, and
 * there is no LBR_SELECT -- so v1's reader (TOS at 0x1C9, entries at 0x680/0x6C0) describes a
 * DIFFERENT device, and on this machine those MSRs are not implemented. RDMSR of an absent MSR is a
 * #GP, which without SEH is a bugcheck, so every read is gated on CPUID.1CH first (D23).
 *
 * ⚠ WITH NOTHING ARMED, WHAT COMES BACK IS WHATEVER LAST RAN ON THAT CORE. That is reported as the
 * result rather than dressed up: `Enabled` says whether LBR_CTL.EN was set by somebody, and an empty
 * ring on a core where it is clear is the expected, correct answer -- not a failure.
 */
#define NXCMD_OP_LBR_READ 37u

#pragma pack(push, 1)
typedef struct _NXCMD_LBR_ENTRY
{
	NXCMD_U64 From;         /* branch source IP                                            */
	NXCMD_U64 To;           /* branch target IP                                            */
	NXCMD_U64 Info;         /* IA32_LBR_x_INFO raw; 0 when the part does not provide it     */
} NXCMD_LBR_ENTRY;
#pragma pack(pop)

/* 32 is this machine's measured depth; the ceiling is the architectural maximum CPUID can report
 * (EAX[7:0] bit 7 => 8*8). Sized to the ARCHITECTURE, not to what one machine happens to have. */
#define NXCMD_LBR_MAX_ENTRIES 64u

#pragma pack(push, 1)
typedef struct _NXCMD_LBR_CPU
{
	NXCMD_U32 CpuNumber;
	NXCMD_U32 Flags;        /* NXCMD_LBR_F_*                                               */
	NXCMD_U64 Ctl;          /* IA32_LBR_CTL raw, 0 when arch LBR is absent                  */
	NXCMD_U32 Depth;        /* IA32_LBR_DEPTH -- entries the ring is CONFIGURED for         */
	NXCMD_U32 Valid;        /* entries actually filled: the walk stops at the first From==0 */
	NXCMD_LBR_ENTRY Entry[NXCMD_LBR_MAX_ENTRIES];
} NXCMD_LBR_CPU;
#pragma pack(pop)

/*
 * `lbr arm` / `lbr disarm` -- STAGE 2. These WRITE IA32_LBR_CTL on every core.
 *
 * ⚠ ARM REFUSES A CONTENDED FACILITY. LBR is one ring per core and anything can own it; if
 * LBR_CTL.EN is already set anywhere, arming would steal it as silently as arming PT over Ipt.sys
 * would have. Refused, with the core count, rather than won.
 *
 * ⚠ THE DEPTH IS DERIVED, NEVER PASSED. CPUID.1CH:EAX[7:0] enumerates the supported depths and
 * writing an UNSUPPORTED value to IA32_LBR_DEPTH is a #GP -- a bugcheck here. So each core picks its
 * own deepest supported depth from its own CPUID, which is both what we want and one fewer way for
 * a caller to crash the machine. (Writing the depth also resets every entry, which is why it is
 * written while EN is clear and before enabling, never after.)
 */
#define NXCMD_OP_LBR_ARM     38u
#define NXCMD_OP_LBR_DISARM  39u

/*
 * `lbr selftest` -- ASK THE SILICON whether ring-3-only recording really excludes ring 0.
 *
 * ⚠ THE WHOLE LBR DESIGN RESTS ON A CLAIM THAT WAS ONLY EVER REASONING. Four sources agree that
 * IA32_LBR_CTL.USR without .OS means ring-0 branches are not recorded, and that is what retired the
 * plan's reason for gating LBR behind a #DB handler (D23). It is still a claim about THIS silicon
 * until this silicon is asked, and every other decision here is downstream of it.
 *
 * ⚠⚠ TWO PHASES, BECAUSE THE INTERESTING RESULT IS A ZERO AND A ZERO PROVES NOTHING ALONE. The same
 * kernel branch generator runs armed ring-3-only (kernel-sourced entries MUST be 0) and armed with
 * ring 0 included (they MUST be nonzero). Phase 2 is the positive control: without it, "no kernel
 * branches" is equally consistent with the filter working and with LBR recording nothing at all.
 *
 * BytesRead = ring-3-only kernel hits, ModuleSize = ring-0-included kernel hits,
 * ModuleBase = cores tested.
 */
#define NXCMD_OP_LBR_SELFTEST 40u

/*
 * NEXUS_COMMAND::Flags for NXCMD_OP_LBR_ARM. Bits, as that field requires.
 *
 * ⚠ DEFAULT IS USER-ONLY, AND THAT IS THE LOAD-BEARING CHOICE (D23). With .USR set and .OS clear,
 * ring-0 branches are not recorded at all -- so our own kernel-side read cannot appear in the ring
 * it is reading. That is what retires the plan's reason for gating LBR behind a #DB handler.
 * KERNEL is opt-in and documented as self-polluting, because sometimes that is what you want.
 */
#define NXCMD_LBR_ARM_KERNEL     0x00000001u  /* also record ring 0 -- POLLUTES with our own path */
#define NXCMD_LBR_ARM_CALLS_ONLY 0x00000002u  /* branch filter: calls and returns only            */
#define NXCMD_LBR_ARM_CALL_STACK 0x00000004u  /* IA32_LBR_CTL[3] call-stack mode                  */
/*
 * DIAGNOSTIC ONLY -- arm the ring but do NOT record it in our armed mask, so the core looks EXACTLY
 * like one a FOREIGN owner enabled.
 *
 * This exists because the contention check had no known-bad. `lbr read` used to shout "ARMED BY
 * SOMETHING ELSE" on every run (it inferred a foreign owner from EN alone); that was fixed by
 * consulting the mask, and the fix was then unprovable -- nothing on this machine arms LBR without
 * going through us. Verifying only the "ours" half leaves the half that matters asserted.
 *
 * With this flag the checker sees EN set and the mask clear, which is precisely a contender. If it
 * does not say so, the fix is wrong.
 */
#define NXCMD_LBR_ARM_FAKE_FOREIGN 0x00000008u

/*
 * ONE SNAPSHOT OF A CORE'S RING, taken inside a hook on the TARGET'S OWN THREAD.
 *
 * ⚠ THIS IS THE RECORD THAT IS ATTRIBUTABLE, and the reason the whole LBR surface is worth having.
 * A ring read from a command thread holds whichever process last ran on that core -- LBR has no CR3
 * filter. A ring read from a hook stub holds the path INTO the hook, on the thread that took it.
 * With LBR armed ring-3-only that path is the target's USER-MODE call chain into the syscall that
 * reached the hooked function: exactly what Intel PT cannot reconstruct without the target's image.
 */
#pragma pack(push, 1)
typedef struct _NXCMD_LBR_SNAPSHOT
{
	NXCMD_U64 TargetVa;     /* the hooked function, so a drained record says what it is about  */
	NXCMD_U64 Timestamp;    /* rdtsc at capture -- ordering, never wall-clock                  */
	NXCMD_U32 ProcessId;    /* whose thread took the hit. THE attribution this exists for      */
	NXCMD_U32 ThreadId;
	NXCMD_U32 CpuNumber;
	NXCMD_U32 Valid;        /* entries filled; the walk stops at the first From == 0           */
	NXCMD_LBR_ENTRY Entry[NXCMD_LBR_MAX_ENTRIES];

	/*
	 * ---- THE LAST EVENT RECORD (LER) --------------------------------------------------------
	 *
	 * ⚠⚠ THE ONE READING LBR STRUCTURALLY CANNOT GIVE. LBR keeps recording THROUGH exception
	 * dispatch, so by the time anything in a handler reads the ring, the dispatch path has already
	 * overwritten the entries that mattered. LER holds the branch taken immediately BEFORE the last
	 * exception, hardware interrupt, or software interrupt, and survives that.
	 *
	 * SDM Vol 3 Section 20.1 (verified against the local corpus, not recalled):
	 *   "In addition to the LBRs, there is a single Last Event Record (LER). It records the last
	 *    taken branch preceding the last exception, hardware interrupt, or software interrupt.
	 *    Like LBRs, the LER is comprised of three MSRs (IA32_LER_FROM_IP, IA32_LER_TO_IP,
	 *    IA32_LER_INFO), and is subject to the same dependencies on enabling and filtering."
	 *
	 * ⚠ SO IT COSTS NO NEW ENABLE PATH AND NO NEW CAPABILITY PROBE. "Same dependencies" means
	 * IA32_LBR_CTL.LBREn -- the bit `lbr arm` already sets -- and its presence is architectural-LBR
	 * presence, which cpuprobe already measures per core type. Three RDMSRs, nothing else.
	 *
	 * ⚠ Info uses the SAME layout as NXCMD_LBR_ENTRY.Info, including BR_TYPE at 59:56 and CYC_CNT
	 * at 15:0 (Vol 3 Table 19-3 states the BR_TYPE encodings are shared), so it renders through the
	 * same decoder rather than a second one that would have to be kept in agreement.
	 *
	 * ⚠ ZERO IS "NO EVENT RECORDED", not "an event at address 0". The MSRs reset to 0 and are only
	 * written when an event actually occurs, so a snapshot taken on a thread that has not faulted
	 * carries zeros -- which is a real answer and must not be rendered as a branch.
	 *
	 * APPENDED after Entry[] so every existing field keeps its offset; the drain reports the record
	 * size so a mixed-build pair is caught rather than silently misparsed.
	 */
	NXCMD_U64 LerFrom;
	NXCMD_U64 LerTo;
	NXCMD_U64 LerInfo;
} NXCMD_LBR_SNAPSHOT;
#pragma pack(pop)

/*
 * `lbr snap init <slots>` / `lbr snap drain` / `lbr snap free`.
 *
 * ⚠ SLOTS ARE THE COST BOUND, NOT A BUFFER SIZE. A snapshot is ~96 RDMSRs on the target's own
 * thread; a hook on a hot function would pay that on every call forever. Capture STOPS when the
 * slots are full and hit counting continues, so the cost is bounded by construction rather than by
 * remembering to unhook. It also keeps the FIRST snapshots rather than the most recent, which for a
 * newly installed hook are the ones worth having.
 */
/*
 * `kpages <module>` -- per-page PTE facts for a LOADED KERNEL IMAGE, checked against its own
 * section headers. Plan item 7.5 (D13). READ ONLY -- no PTE is written.
 *
 * ⚠ THE KERNEL-SIDE COUNTERPART TO `regions --hidden`, and it needs a different mechanism because
 * the kernel techniques leave NOTHING TO SUBTRACT: the VA range is claimed, by a signed driver, at
 * the address the loader chose. The evidence is that a page's PTE and the image's section table are
 * two independent statements about what that page may do, and the loader derived one from the other.
 * A disagreement means something rewrote one of them after load.
 *
 * ⚠ AND IT SURVIVES A HYPERVISOR (D13). A guest page-table walk is itself nested-translated, so
 * cloaking the page holding a driver's PTEs would make the CPU's own walker read the ORIGINAL
 * entries and the hijacked code would never run. The rewritten entry must be guest-visible for the
 * attack to work at all.
 *
 * TargetName = module name; ReadOffset = first page index (paging, since a big driver exceeds one
 * buffer). OutBuffer receives NXCMD_KPAGE records.
 */
#define NXCMD_OP_KPAGES 44u

/*
 * `modules --kernel` -- ENUMERATE every loaded kernel module. Item 3a (kernel/usermode parity).
 *
 * ⚠ THE PARITY GAP THIS CLOSES. `modules <pid>` walks the PEB and is usermode-only; the kernel side
 * could only ever look a module up BY NAME (NxcFindKernelModule), which means it could inspect a
 * driver it was told about and never tell you what is loaded. `kpages <module>` has the same
 * dependency -- it takes a name, so it cannot be pointed at something not already known.
 *
 * (kernel capture must match ALL usermode capture. A target may load a ~70 MB driver
 * and that is reportedly where the interesting behaviour is.)
 *
 * ⚠ AND IT IS THE PREREQUISITE FOR FINDING AN UNLINKED DRIVER. A module that removes itself from
 * PsLoadedModuleList cannot be named, so it cannot be kpages'd. Finding one means walking kernel VA
 * space for executable pages and SUBTRACTING the ranges of everything legitimately loaded -- and
 * this command produces that subtrahend. It is deliberately built and verified first, on its own,
 * because the walk that consumes it touches page tables and this project has bugchecked there.
 *
 * The walk REFUSES unless it encounters ntoskrnl, whose base the DXE measured independently. An
 * undocumented offset checked against a value from another source, rather than trusted.
 *
 * ReadOffset = first index (paging). OutBuffer receives NXCMD_KMODULE records. Reports count AND
 * total, per D3 -- so a truncated page is visibly truncated.
 */
#define NXCMD_OP_KMODULES 70u

/*
 * `modules --hidden` -- EXECUTABLE KERNEL PAGES THAT BELONG TO NO LOADED MODULE.
 *
 * The kernel counterpart to `regions <pid> --hidden`, and the last of the three parity gaps. A
 * driver that unlinks itself from PsLoadedModuleList cannot be NAMED, so it cannot be `kpages`'d
 * and cannot be `read` -- both take a name. It is invisible to every existing kernel command. What
 * it CANNOT hide is that its code must be mapped executable to run.
 *
 * So: walk kernel VA for present, executable pages, and SUBTRACT every range in the module list.
 * `modules --kernel` produces the subtrahend; `NXC_PTE_INFO.MissingLevel` makes the walk feasible
 * (128 TB at 4 KB granularity would be 34 billion probes; skipping an absent PML4E covers 512 GB).
 *
 * ⚠⚠ THIS REPORTS EVIDENCE, NOT A VERDICT (D6). "Executable and unlisted" is NOT "malicious" -- on
 * this machine NexusCore itself is exactly that, deliberately, and so is any legitimately
 * manually-mapped image. The command's job is to say WHAT IS THERE. Deciding what it means is the
 * operator's.
 *
 * ⚠ AND IT MUST FIND US. NexusCore is manually mapped and absent from PsLoadedModuleList by design,
 * so a scan that reports nothing is BROKEN, not clean. That is the known answer this was verified
 * against before it was trusted on anything else.
 *
 * READ ONLY -- no PTE is written, and the descent (PRESENT before descending, PS before treating an
 * entry as a table) is the proven one from NxcPteQuery, unchanged.
 *
 * ReadOffset = first region index (paging). OutBuffer receives NXCMD_KEXEC records.
 */
#define NXCMD_OP_KSCAN 71u

/*
 * ==================================================================================================
 * WHICH FILE IS BEHIND THIS MAPPING? TargetModuleId = pid, ReadOffset = a VA inside the region.
 * OutBuffer receives the path as raw UTF-16; BytesRead says how many BYTES were written.
 * ==================================================================================================
 *
 * ⚠ ONE REGION AT A TIME, ON PURPOSE, AND Regions.h ALREADY SAID SO. `regions` derives its
 * HAS_FILE bit from Type alone (MEM_IMAGE / MEM_MAPPED are file-backed by definition) precisely so
 * the walk does not make a filename query per region -- thousands of extra kernel calls to answer a
 * question Type already settles. Its comment ends "a caller wanting the path can ask for that
 * region specifically once it has decided the region matters." This is that command.
 *
 * ⚠ IT EXISTS BECAUSE THE FILE-BACKED BUCKET POSES A QUESTION THE TOOL COULD NOT ANSWER. Splitting
 * `regions --hidden` into allocated-code and phantom-DLL shapes  left 91 file-backed
 * executable regions in one ordinary .NET process -- each one a PE mapped as a section the loader
 * never registered. "WHICH FILE" is the only question that triages that list, and a HAS_FILE BIT
 * cannot answer it. With the path, a candidate can be diffed against the file on disk; without it,
 * 91 hits are 91 hits.
 *
 * ⚠ A REGION CAN BE FILE-BACKED AND STILL HAVE NO NAME. MemoryMappedFilenameInformation returns
 * STATUS_FILE_INVALID for a pagefile-backed section -- which is a REAL ANSWER ("mapped, but from no
 * file on disk") and is reported as such rather than as a failure. That case is itself interesting:
 * a MEM_MAPPED executable region with no backing file is closer to allocated code than to a DLL.
 */
#define NXCMD_OP_REGION_FILE 72u

#pragma pack(push, 1)
typedef struct _NXCMD_KEXEC
{
	NXCMD_U64 Base;     /* first VA of the contiguous executable run                       */
	NXCMD_U64 Size;     /* bytes -- contiguous pages are COALESCED into one region         */
	NXCMD_U32 Pages;    /* how many page mappings the run covers                           */
	NXCMD_U32 Flags;    /* NXCMD_KEXEC_* below                                             */
} NXCMD_KEXEC;
#pragma pack(pop)

#define NXCMD_KEXEC_WRITABLE   0x00000001u  /* W AND X -- worth seeing; normal images are not  */
#define NXCMD_KEXEC_LARGE      0x00000002u  /* run includes a 2 MB or 1 GB mapping             */
#define NXCMD_KEXEC_IS_SELF    0x00000004u  /* NexusCore's own mapped image -- expected        */
#define NXCMD_KEXEC_IS_ARENA   0x00000008u  /* NexusCore's own arena -- expected               */
/*
 * A PE HEADER sits on the page immediately BELOW this region -- so it is a MAPPED IMAGE rather
 * than an executable pool allocation.
 *
 * (!) THE PAGE BELOW, NOT THE REGION BASE, AND THE SCAN ITSELF TAUGHT US WHY. A loaded image's
 * header page is R-- and therefore NOT executable, so it is correctly absent from the scan and
 * the executable run starts one page later. NexusCore reports at image base + 0x1000. Checking
 * for MZ at the region base would find nothing on every real image.
 *
 * This is the difference between a driver and a slab of executable pool, which is what makes the
 * ORPHANED list readable.
 */
#define NXCMD_KEXEC_PE_IMAGE   0x00000010u

#pragma pack(push, 1)
typedef struct _NXCMD_KMODULE
{
	NXCMD_U64 Base;          /* DllBase                                                       */
	NXCMD_U64 EntryPoint;    /* 0 for modules that have none recorded                         */
	NXCMD_U32 SizeOfImage;
	NXCMD_U32 Flags;         /* NXCMD_KMOD_* below                                            */
	/* BaseDllName, ASCII, truncated. UNICODE_STRING is not NUL-terminated and its Buffer is a
	 * separate allocation, so it is COPIED here rather than pointed at -- a pointer would be a
	 * kernel VA the caller cannot read, which is the "captured pointer is not the fact" shape. */
	char      Name[64];
} NXCMD_KMODULE;
#pragma pack(pop)

#define NXCMD_KMOD_IS_NTOSKRNL  0x00000001u  /* the module the walk verifies itself against */
#define NXCMD_KMOD_NAME_TRUNC   0x00000002u  /* BaseDllName was longer than Name[]          */
#define NXCMD_KMOD_NAME_UNREAD  0x00000004u  /* Buffer was not readable -- Name is empty    */

/*
 * `bp classify` -- prove the "is this #DB ours?" decision against synthetic inputs.
 *
 * ⚠ ITEM 15'S HARD PART, AND IT NEEDS NO PATCH. The hooking needed a measurement (answered: rel32
 * reaches the dispatcher) and needs a DECISION. The CLASSIFIER needs neither -- it is pure logic,
 * and it is where a mistake is worst: claim somebody else's exception and we SWALLOW it, silently,
 * breaking a debugger or a component waiting on STATUS_SINGLE_STEP. Reject our own and the target
 * dies, which is the failure bp set exists to prevent.
 *
 * BytesRead = cases run, ModuleSize = cases failed, ModuleBase = index of the first failure.
 */
#define NXCMD_OP_BP_CLASSIFY 45u

/*
 * `bp set <pid> <va> [--write|--rw] [--len N]` / `bp clear <slot>`.
 *
 * ⚠⚠ REFUSES WHILE NO #DB HANDLER IS INSTALLED, AND THE REFUSAL IS THE FEATURE. When DR0-3 match,
 * the CPU raises #DB; with nothing intercepting it the target receives STATUS_SINGLE_STEP and
 * DIES, on the FIRST hit, looking exactly like the target crashing on its own. Bp.h has said so in
 * prose since the file was created -- prose is not an interlock, and this is.
 *
 * TargetModuleId = pid, ReadOffset = address, Flags = NXCMD_BP_SET_* for type/length.
 * BytesRead = slot, ModuleSize = threads armed (POINT-IN-TIME: later threads are NOT covered).
 */
/*
 * `bp dispatch status` -- what the exception observer has SEEN. Counters, never a verdict.
 *
 * BytesRead = dispatched exceptions seen, ModuleSize = of those, #DB, ModuleBase = int3,
 * ReadOffset(out) = records refused as non-canonical.
 */
#define NXCMD_OP_BP_DISPATCH_STATUS 48u

#define NXCMD_OP_BP_SET   46u
#define NXCMD_OP_BP_CLEAR 47u

/*
 * PsGetContextThread POSITIVE CONTROL. measured: it refuses EVERY thread of a live
 * usermode process with STATUS_UNSUCCESSFUL, and `bp list`'s per-thread view has therefore been
 * reading 0 contexts of N threads since stage 1 -- while printing "no thread has a debug register
 * set", a verdict its own count never supported.
 *
 * Windows takes a COMPLETELY DIFFERENT PATH for the current thread (direct capture) than for any
 * other (queue a special kernel APC and wait). One run of all three cases says which half is
 * broken, where four hardware runs of guessing did not:
 *
 *   ReadOffset = 0 -> probe the CURRENT thread, the caller's own          -> ModuleBase
 *   the caller's OTHER threads, same process                             -> ModuleSize
 *   TargetModuleId = pid -> a thread in THAT process, cross-process       -> ReadOffset (out)
 *
 * Reads only; nothing is armed and no context is written.
 */
#define NXCMD_OP_BP_CTXPROBE 49u

/*
 * GLOBAL ARMING and the claim switch. The per-thread route is measurably unavailable (D54), so
 * these are the working path: arm DR7's GLOBAL bit on every core and attribute hits by CR3 in the
 * dispatcher observer -- CE's architecture, with the attribution half already built.
 *
 * ⚠ BP_CLAIM_ENABLE IS SEPARATE AND MUST COME FIRST. A global DR fires in EVERY process at that
 * linear address, so arming without a claimer would kill unrelated processes. NXCMD_OP_BP_GSET
 * REFUSES while claiming is off -- the ordering is an interlock, not advice.
 */
/*
 * `bp hits` -- the EVIDENCE a breakpoint produced, as opposed to the count that proves the
 * mechanism. One record per CLAIMED trap: the IRET tail (located by the proven matcher, never read
 * at an assumed offset), Dr6, CR3, slot, address, processor and a monotonic sequence.
 *
 * ⚠ EACH RECORD SAYS WHICH FIELDS ARE REAL (NXC_BPD_PRESENT_*). R12-R15 live in KEXCEPTION_FRAME and
 * the volatile set sits at KTRAP_FRAME offsets that have NOT been derived, so they are absent rather
 * than zero-filled -- "not captured" and "was zero" must never render alike.
 *
 * BytesRead = records returned, ModuleSize = total offered, ModuleBase = DROPPED (ring full).
 */
#define NXCMD_OP_BP_HITS 53u

/*
 * `bp hits --clear`. Flags bit, not a separate opcode: it is the same surface answering "and start
 * over", not a different question.
 *
 * ⚠ WHY IT EXISTS. The ring is cumulative and had no reset, so every test inherited the previous
 * one's records. On a data-breakpoint run reported "records returned: 2" that were
 * entirely stale -- the previous execute test's hits, with a different armed address and a different
 * pid -- and read exactly like a result. Stale evidence that looks current is worse than none.
 */
#define NXCMD_BP_HITS_CLEAR  0x00000001u

#define NXCMD_OP_BP_CLAIM_ENABLE 50u
#define NXCMD_OP_BP_GSET         51u
#define NXCMD_OP_BP_GCLEAR       52u

/*
 * `bp fork <pid> <va0> <va1>` -- build-plan item 14, v1's `--fork-cap`.
 *
 * WHAT PROBLEM IT SOLVES, AND WHY IT IS NOT TWO `bp gset` CALLS. A fork capture wants the state at
 * TWO code sites belonging to one event (v1 used two gsl.dll DllMain sites). Issuing two separate
 * arms leaves a window in which only the first is live, and a hit taken in that window is real
 * evidence of an UNPAIRED event that reads exactly like half of a paired one. Usermode cannot close
 * that window from outside -- two IOCTLs cannot be made one -- so the pairing belongs here.
 *
 * ⚠ AND IT ROLLS BACK. If the second site refuses, the first is DISARMED before returning, so the
 * caller never inherits a half-armed capture from a command that reported failure. That is the
 * install/remove-must-share-one-expression rule applied to arming.
 *
 * ⚠ HONEST LIMIT, NOT PAPERED OVER: this composes two arms and each programs DR7 across every core
 * in its own IPI round, so a microsecond-scale window remains in which only site 0 is live. It is
 * not zero and is not claimed to be. Closing it needs a two-slot arm inside ONE IPI round; that is
 * a deeper change to the arm path and is worth doing only if a measurement shows the window being
 * hit. Sequence numbers make such a hit visible rather than silent.
 *
 * ⚠ BOTH SITES ARE EXECUTE BREAKPOINTS (R/W=00, LEN=00) -- a fork point is a CODE address and you
 * trap it by executing it. So this inherits the execute gate: it stays REFUSED until KTRAP_FRAME's
 * EFlags offset is PROVEN, because resuming needs RF. Flags are ignored; there is no data-fork.
 *
 * ReadOffset = va0. ImageBuffer = va1 (reused as a second address, exactly as the dispatch-install
 * path reuses it for the funnel VA). TargetModuleId = pid.
 * BytesRead = slot0, ModuleSize = slot1, ModuleBase = cores armed.
 *
 * ⚠ NO "ALL FIRED" BIT IS RETURNED, DELIBERATELY (D6). v1's handler set one. The kernel reports the
 * hits with their slot numbers and usermode decides what "both fired" means -- which matters because
 * "both, ever" and "both, in the same pass" are different questions and only the records can answer
 * the second.
 */
#define NXCMD_OP_BP_FORK         54u

/*
 * ================================================================================================
 * BRANCH STEPPING (D119) -- IA32_DEBUGCTL[1] + EFLAGS.TF
 * ================================================================================================
 *
 * Trap after every instruction THAT CAUSES A BRANCH instead of after every instruction: control-flow
 * tracing of a target while modifying NOT ONE BYTE of it. No inline hook, no trampoline, no page
 * alias -- the only tracing surface here with no observable footprint in the target, which is what
 * makes it the right instrument against code that checksums itself.
 *
 * ⚠⚠ BTF IS ONE-SHOT. The processor CLEARS it when it raises the #DB (SDM vol 3, 19.4.3), so it is
 * re-armed inside the dispatcher on every trap. Arming once would step ONE branch and then degrade
 * to per-INSTRUCTION stepping, because EFLAGS.TF stays set -- a flood, not a silence.
 *
 * ⚠ TWO HALVES, AND NEITHER DOES ANYTHING ALONE. The kernel sets DEBUGCTL.BTF on every core; the
 * CALLER sets EFLAGS.TF on the target's threads through SetThreadContext (D1). BTF with no TF traps
 * nothing at all, which is deliberate: an arm can never start stepping something by itself.
 *
 *   ARM   ModuleBase = CR3 of the target, ModuleSize = pid (reporting only; CLAIMS go by CR3)
 *   OFF   no parameters
 *   DRAIN OutBuffer/ReadLength; BytesRead = records written, ModuleSize = records still held,
 *         ModuleBase = records DROPPED since arming (a FLOOR on what was missed)
 */
/* Records per drain call. The ring is 8192 and STOPS rather than wrapping, so a window that
 * drains only at the end can never return more than that however long it runs. Half the ring per
 * call leaves headroom for what arrives during the call itself. */
#define NXC_BTF_DRAIN_BATCH      8192u

#define NXCMD_OP_BP_BTF_ARM      73u
#define NXCMD_OP_BP_BTF_OFF      74u
#define NXCMD_OP_BP_BTF_DRAIN    75u

/*
 * NMI OBSERVER (76/77). Added after ELEVEN bugcheck 0x80s produced no evidence about the
 * NMI that caused them. 0x80 means "an NMI arrived and nothing claimed it" -- and the dump says only
 * that, with `GenuineIntel.sys` as the module, which is the placeholder for "attributed to the
 * processor". The driver records what the dump cannot.
 *
 * The callback is registered at driver init and never deregistered, so the observer sees NMIs that
 * arrive WITH NOTHING ARMED -- the state every one of those crashes happened in.
 */
/*
 * CONTINUOUS PT DRAIN (78). TargetModuleId = cpu. Flags bit 0 = refresh the per-core offsets first
 * (IA32_RTIT_* are per-logical-processor, so they need an IPI; do it ONCE per sweep, not per CPU).
 *
 * Returns in BytesRead the bytes COPIED, in ReadOffset the bytes LOST to overrun, and in
 * ImageBuffer the bytes still PENDING. The loss figure is the point: a ToPA region is circular and
 * a lapped buffer looks identical to a fresh one, so without it a trace with a hole in the middle
 * is indistinguishable from a complete one.
 */
#define NXCMD_OP_TRACE_DRAIN     78u

/*
 * ============================================================================================
 * TPM TRAFFIC OBSERVATION (the design notes)
 *
 * The SB spoof stops at rungs C and D, and stopping there is justified by ONE calibration:
 * "it reads no PCRs and issues no Quote". That is an assertion about one target from one
 * investigation, and every decision not to pursue C/D rests on it.
 *
 * A verifier cannot exercise C without TPM2_PCR_Read, nor D without TPM2_Quote. Both are TPM
 * commands with a fixed header, so the question is MEASURABLE. These ops measure it.
 *
 * ⚠ OBSERVATION ONLY. The recorder returns without touching the IRP; the target's command runs
 * exactly as it would have. That is not squeamishness -- an instrument that alters the traffic
 * it measures cannot tell you what the target does, which is the mirror-oracle failure this
 * project has already paid for twice.
 *
 *   `tpmtrace arm`   NXCMD_OP_TPM_INIT  -- ReadOffset = slot count
 *   `tpmtrace dump`  NXCMD_OP_TPM_READ  -- OutBuffer receives NXCMD_TPM_REC records
 * ============================================================================================
 */
#define NXCMD_OP_TPM_INIT        79u
#define NXCMD_OP_TPM_READ        80u

/* How many bytes of a TPM command header must be present before a capture is worth taking:
 * tag(2) + commandSize(4) + commandCode(4). Anything shorter cannot name a command. */
#define NXCMD_TPM_HDR_BYTES      10u

/* NxcTpmTraceInit detail codes. */
#define NXCMD_TPM_INIT_BAD_SLOTS 1u
#define NXCMD_TPM_INIT_ALREADY   2u
#define NXCMD_TPM_INIT_NO_ARENA  3u

/*
 * Why a record carries no command bytes. An empty capture ALWAYS states its cause -- a silent
 * zero would be indistinguishable from "this target never talked to the TPM", which is the exact
 * conclusion the tool exists to support and therefore the exact conclusion it must not fake.
 */
#define NXCMD_TPM_WHY_OK           0u
#define NXCMD_TPM_WHY_NO_STACK     1u  /* no current IRP stack location                       */
#define NXCMD_TPM_WHY_NOT_DEVCTL   2u  /* hook fired on a non-device-control major function   */
#define NXCMD_TPM_WHY_NOT_BUFFERED 3u  /* METHOD_NEITHER/DIRECT -- refused, not dereferenced  */
#define NXCMD_TPM_WHY_NO_BUFFER    4u  /* METHOD_BUFFERED but SystemBuffer was NULL           */
#define NXCMD_TPM_WHY_TOO_SHORT    5u  /* input shorter than a TPM command header             */

/* Why \Driver\TPM's dispatch could not be resolved. 0 = it was. */
#define NXCMD_TPM_RESOLVE_OK          0u
#define NXCMD_TPM_RESOLVE_NO_EXPORT   1u  /* IoDriverObjectType / ObReferenceObjectByName absent */
#define NXCMD_TPM_RESOLVE_NO_DRIVER   2u  /* \Driver\TPM did not resolve                        */
#define NXCMD_TPM_RESOLVE_NO_DISPATCH 3u  /* driver object had no device-control dispatch        */

typedef struct _NXCMD_TPM_REC
{
	NXCMD_U64 Sequence;       /* 0 = never written / being overwritten right now      */
	NXCMD_U64 TimeStamp;      /* KeQueryPerformanceCounter ticks                      */
	NXCMD_U64 Irp;            /* which request, for correlating with anything else    */
	NXCMD_U32 Pid;            /* the ISSUING process -- recorded on its own thread    */
	NXCMD_U32 Tid;
	NXCMD_U32 IoControlCode;
	NXCMD_U32 InputLength;    /* as the IRP DECLARED, which may exceed Captured (D3)  */
	NXCMD_U32 Captured;       /* bytes of Cmd actually valid                          */
	NXCMD_U32 Why;            /* NXCMD_TPM_WHY_*                                      */
	NXCMD_U8  Cmd[64];        /* header + enough body for a PCR selection             */
} NXCMD_TPM_REC;
#define NXCMD_TRACE_DRAIN_REFRESH 0x1u

#define NXCMD_OP_NMI_STATUS      76u   /* counts + the ring, oldest first */
#define NXCMD_OP_NMI_CATCH       77u   /* DIAGNOSTIC: claim unclaimed NMIs so the box survives */

/*
 * One observed NMI. RAW MSR VALUES, never an interpretation -- the whole reason this exists is that
 * every interpretation offered so far has been wrong (D6).
 */
typedef struct _NXCMD_NMI_OBS
{
	NXCMD_U64 Tsc;
	NXCMD_U64 GlobalStatus;   /* IA32_PERF_GLOBAL_STATUS at delivery, before anything cleared it */
	NXCMD_U64 LvtPc;          /* LVT PC as it read; 0 = unreachable, NOT "zero"                  */
	NXCMD_U64 DebugCtl;       /* IA32_DEBUGCTL -- a stray BTF/LBR/BTS enable shows up here       */
	/*
	 * ⚠ CR3 AS THE HANDLER SEES IT. Added because the PEBS CR3 filter judged 277,041
	 * records and kept ZERO while the target was provably spinning -- so the comparison never
	 * matches, and the only way to know why is to see BOTH sides of it. Raw, unmasked: the masking
	 * is itself a suspect.
	 */
	NXCMD_U64 Cr3;
	NXCMD_U32 Cpu;
	NXCMD_U32 Flags;          /* NXCMD_NMIOBS_*                                                  */
} NXCMD_NMI_OBS;

#define NXCMD_NMIOBS_PT_LIVE      0x01u
#define NXCMD_NMIOBS_SAMPLE_LIVE  0x02u
#define NXCMD_NMIOBS_PEBS_LIVE    0x04u
#define NXCMD_NMIOBS_CLAIMED      0x08u   /* the real handler claimed it        */
#define NXCMD_NMIOBS_CAUGHT       0x10u   /* WE claimed it to keep the box alive */

#define NXCMD_NMI_OBS_RING        64u

#pragma pack(push, 1)
typedef struct _NXCMD_BTF_REC
{
	NXCMD_U64 Rip;        /* the branch TARGET -- where control landed          */
	NXCMD_U64 Sequence;   /* monotonic; a gap is a visible loss, never inferred */
	NXCMD_U32 Cpu;
	NXCMD_U32 Reserved0;
} NXCMD_BTF_REC;
#pragma pack(pop)

#define NXCMD_BP_SET_WRITE  0x00000001u  /* DR7 R/W = 01, break on data write   */
#define NXCMD_BP_SET_RW     0x00000002u  /* DR7 R/W = 11, break on read OR write */
#define NXCMD_BP_SET_LEN2   0x00000004u
#define NXCMD_BP_SET_LEN4   0x00000008u
#define NXCMD_BP_SET_LEN8   0x00000010u
/* ⚠ COSTS TWO WRMSRs AND A FENCE PER CLAIMED TRAP -- see NXC_BPD_HIT.PtOffset. Off unless asked. */
#define NXCMD_BP_SET_PTBOUND 0x00000020u

#define NXC_BPD_PRESENT_IRET   0x00000001u  /* Rip, Cs, EFlags, Rsp, Ss -- from the PROVEN tail   */
#define NXC_BPD_PRESENT_TRAP   0x00000002u  /* Dr6, Cr3, slot, address -- from the trap itself    */
#define NXC_BPD_PRESENT_VOLGPR 0x00000004u  /* Rax..R11 -- offsets not derived yet                */
#define NXC_BPD_PRESENT_NVGPR  0x00000008u  /* R12..R15, KEXCEPTION_FRAME -- offsets not derived  */
/*
 * The x86-64 debug-register count. ARCHITECTURAL, not a policy choice -- DR0-DR3 is what the
 * hardware has, and DR7's two-bit L/G and four-bit R/W-LEN fields are laid out for exactly four.
 * Shared with usermode because `bp hits` tallies hits per slot; it used to live in BpDispatch.h,
 * and two definitions that must agree is the failure shape this codebase keeps finding.
 */
#define NXC_BPD_MAX_SLOTS  4u

/*
 * ============================================================================================
 * `bp dispatch status` SHAPE BLOCK -- ONE geometry, shared, because it was TWO and they drifted
 * ============================================================================================
 *
 * ⚠⚠ THIS EXISTS BECAUSE THE DRIFT ALREADY HAPPENED. The kernel sized its local array from
 * NXC_BPD_MAX_CALLERS/NXC_BPD_MAX_CODES and usermode sized its receiving array from its OWN
 * SHAPE_CODE_BASE/SHAPE_MAX_CODES -- two expressions computing one number. On the kernel
 * block grew by NXC_BPD_TR_COUNT and usermode did not, so the copy became short, the kernel refused
 * it (fail-closed, correctly), and EVERY value in the block read 0 while "dispatched exceptions
 * seen: 538" kept printing from a scalar field. The surface looked like the hook had stopped
 * working. It had not; the transport had.
 *
 * Both ends now derive from these. Changing the block means changing ONE expression.
 */
#define NXCMD_BPD_MAX_CALLERS  8u
#define NXCMD_BPD_MAX_CODES    16u

/* Why a frame's IRET tail was rejected -- ordered by position in the matcher's check sequence, so
 * the FURTHEST-progressing rejection is simply the largest value. Shared: usermode names them. */
#define NXC_BPD_TR_CS         0u  /* CS not a plausible selector                                  */
#define NXC_BPD_TR_SS         1u  /* SS not a plausible selector                                  */
#define NXC_BPD_TR_RING       2u  /* CS.RPL != SS.RPL -- pushed together, they always agree        */
#define NXC_BPD_TR_EFL_HIGH   3u  /* EFLAGS upper 32 bits nonzero (32-bit field + padding)         */
#define NXC_BPD_TR_EFL_FIXED  4u  /* EFLAGS architectural fixed bits wrong (1 set; 3,5,15 clear)   */
#define NXC_BPD_TR_RSP_ZERO   5u  /* RSP == 0                                                     */
#define NXC_BPD_TR_RSP_SIDE   6u  /* RSP on the wrong side of the canonical split for CS's ring    */
#define NXC_BPD_TR_COUNT      7u

/* 5 header + 1 caller count + callers + 2 code header + 4 per code + 6 claim + 24 EFlags + tail. */
#define NXCMD_BPD_SHAPE_QWORDS \
	(5u + 1u + NXCMD_BPD_MAX_CALLERS + 2u + 4u * NXCMD_BPD_MAX_CODES + 6u + 24u + NXC_BPD_TR_COUNT + 4u)

#define NXC_BPD_PRESENT_STACK  0x00000010u  /* stack bytes captured AT TRAP TIME                  */

/*
 * ⚠ 256 BYTES, AND THE COPY IS BOUNDED TO RSP'S PAGE. Residency is checked with NxcPteQuery, which
 * walks the SELF-MAP -- page-table pages are always resident, so unlike MmIsAddressValid (documented
 * <= DISPATCH) it is legal on the trap path. One query covers the whole copy precisely BECAUSE the
 * copy cannot leave the page; spanning two pages would need two queries and a second race window.
 */
#define NXC_BPD_STACK_MAX  256u

#define NXC_BPD_PRESENT_LBR    0x00000020u  /* LBR ring snapshotted at the trap (D107)            */
#define NXC_BPD_PRESENT_PT     0x00000040u  /* Intel PT write offset bounded at the trap (D108)   */

/*
 * Why a hit carries no PT bound. PT is COMPLETE and verified independently; this is only about
 * pinning WHERE IN the circular ToPA region a given trap happened, which nothing else records.
 */
#define NXC_BPD_PTWHY_OK          0u
#define NXC_BPD_PTWHY_NOT_ASKED   1u  /* the slot was not armed with --pt; the toggle is not free */
#define NXC_BPD_PTWHY_NOT_ARMED   2u  /* PT is not tracing on this core                           */
#define NXC_BPD_PTWHY_OS_TRACED   3u  /* RTIT_CTL.OS is set, so the trace contains OUR trap path  */

/*
 * ⚠ SIZED TO THE MEASURED DEPTH (32 on all 24 LPs here), NOT to NXCMD_LBR_MAX_ENTRIES (64, the
 * architectural ceiling). That is the opposite of the rule this project usually follows, and the
 * reason is per-record cost: this array is carried by EVERY hit, so 64 would spend 786 KB of static
 * image on slots this silicon can never fill, against 393 KB for 32.
 *
 * ⚠ SO TRUNCATION IS POSSIBLE AND IS REPORTED. LbrDepth carries what the ring was CONFIGURED for and
 * LbrCount what was actually taken; a part with depth 64 yields LbrCount 32 < LbrDepth 64, which
 * reads as "truncated by us", not as "the ring was short" (D3). `lbr read` keeps the full 64.
 */
#define NXC_BPD_LBR_MAX  32u

/* Why a record has no LBR ring. One value per DISTINCT cause -- see NXC_BPD_HIT.LbrWhy. */
#define NXC_BPD_LBRWHY_OK        0u  /* captured                                                  */
#define NXC_BPD_LBRWHY_NO_ARCH   1u  /* CPUID says no architectural LBR -- MSRs never touched      */
#define NXC_BPD_LBRWHY_DISABLED  2u  /* IA32_LBR_CTL.EN clear AT THE TRAP; LbrCtl carries the word */
#define NXC_BPD_LBRWHY_EMPTY     3u  /* armed and enabled, but entry 0 FROM_IP was 0              */

/*
 * ⚠ MEASURED, NOT GUESSED. A write breakpoint on a live thread stack (ping.exe) produced
 * 528 hits in 15 s -- ~35/s. At 64 records that buffer was full 1.8 seconds in, and the other 464
 * hits were gone. 512 covers ~14 s of that rate, which is the length of an actual test dwell.
 *
 * ⚠ THIS IS A CEILING, NOT A GUARANTEE. A breakpoint on a hot global runs orders of magnitude faster
 * and will still wrap; that is what the DROPPED count is for. Sizing it away is not possible, so the
 * contract is that the WINDOW is honest -- see BpdRecordHit for why it keeps the NEWEST hits.
 *
 * 512 * sizeof(NXC_BPD_HIT) ~= 222 KB, static in the driver image. Not the arena (D4) because the
 * write happens in the trap path at arbitrary IRQL, where nothing may be allocated.
 */
#define NXC_BPD_MAX_HITS  512u

#pragma pack(push, 1)
typedef struct _NXC_BPD_HIT
{
	UINT64 Rip;          /* the faulting instruction -- from the derived IRET tail */
	UINT64 Rsp;
	UINT64 EFlags;
	UINT64 Cs;
	UINT64 Ss;

	UINT64 Dr6;          /* the raw condition, so a reader can re-derive the slot  */
	UINT64 Cr3;          /* RAW, PCID bits intact -- masking is the classifier's   */
	UINT64 Address;      /* what was armed in that slot                           */

	/*
	 * ⚠ FILLED ONLY WHEN NXC_BPD_PRESENT_VOLGPR IS SET. The offsets are DERIVED from the trap entry
	 * function (anchored on an IDT gate) and cross-checked against the EFlags offset that live trap
	 * frames proved. Until that derivation succeeds these stay zero AND the flag stays clear -- a
	 * reader must never have to guess whether 0 means "was zero" or "not captured".
	 */
	UINT64 Rax, Rcx, Rdx, R8, R9, R10, R11;

	/*
	 * ⚠ FROM A DIFFERENT STRUCTURE. R12-R15 live in KEXCEPTION_FRAME (arg2), not KTRAP_FRAME, and
	 * are gated by their own PRESENT bit and their own derivation. Two structures, two anchors, two
	 * cross-checks -- never one map assumed to cover both.
	 */
	UINT64 R12, R13, R14, R15;

	UINT64 Sequence;     /* monotonic; gaps mean records were DROPPED, see below   */
	UINT32 Slot;
	UINT32 Why;          /* NXC_BPD_WHY_* -- the classifier's reason, not a guess  */
	UINT32 Present;      /* NXC_BPD_PRESENT_* -- which fields above are REAL       */
	UINT32 Processor;    /* which logical processor took the trap                  */

	/*
	 * ⚠ THE TRAP-TIME STACK, FILLED ONLY WHEN NXC_BPD_PRESENT_STACK IS SET. This is the snapshot the
	 * post-hoc read cannot produce: usermode reads at PASSIVE, long after the frames were popped and
	 * the pages reused, so hits whose RSP sat in a transient frame came back 256 bytes of zeros --
	 * observed twice in the run. "Was zero" and "gone by the time we looked" render alike.
	 *
	 * StackBytes says how many bytes are real and is NOT always StackMax: the copy is bounded to the
	 * page RSP sits in, so a hit near a page edge captures less. Reporting the request instead of the
	 * result is exactly what D3 forbids.
	 */
	UINT32 StackBytes;
	UINT8  Stack[NXC_BPD_STACK_MAX];

	/*
	 * ⚠ THE LBR RING AS IT STOOD AT THE TRAP -- the PATH to the trapping instruction, where the stack
	 * above is the STATE at it. Filled only when NXC_BPD_PRESENT_LBR is set. Decided in D107.
	 *
	 * ⚠ WHY THE BREAKPOINT PATH AND NOT THE INLINE HOOK, which is where LBR sampling lives today.
	 * LBR has no CR3 filter, so it needs a moment that provably belongs to the target. A hook is one,
	 * but it PATCHES the target -- and untouchable images are this framework's whole purpose. A
	 * hardware breakpoint writes nothing into the process. And a usermode hook stub executes at ring
	 * 3, so its own branches are exactly what the USR filter records: D36 measured it destroying 23
	 * of 32 entries before it could freeze. This path runs at ring 0, which the default USR-without-OS
	 * filter excludes entirely (proven here: `lbr selftest` phase 2 = 768 kernel entries with OS on,
	 * phase 1 = 0 with it off), so the ring arrives intact.
	 *
	 * ⚠⚠ CTL IS PART OF THE EVIDENCE, NOT METADATA. `lbr arm` is MACHINE-WIDE while `bp` is
	 * per-target, so the ring may have been armed by someone else, with a filter that makes these
	 * entries mean something different -- OS included (our own kernel path is in there), calls-only
	 * (no conditional branches), call-stack mode (a maintained stack, not a history). A ring read
	 * under an unknown filter is well-formed and misleading, which is worse than an error. LbrCtl is
	 * what the snapshot was taken under; usermode decodes it beside the entries rather than assuming.
	 */
	UINT64 LbrCtl;                        /* IA32_LBR_CTL as found at the trap                    */
	UINT32 LbrDepth;                      /* what the ring was CONFIGURED for (IA32_LBR_DEPTH)    */
	UINT32 LbrCount;                      /* entries actually taken; < LbrDepth means WE truncated */

	/*
	 * ⚠⚠ WHY THE SNAPSHOT DID NOT HAPPEN -- PER RECORD, BECAUSE "ABSENT" ALONE ABSORBS FIXES.
	 *
	 * The first build of this shipped with one ABSENT message covering three different failures:
	 * no architectural LBR, EN clear at the trap, and a ring that recorded nothing. Every record on
	 * the run said ABSENT and the message could not say which -- the exact shape that cost
	 * four boots and three correct-but-irrelevant fixes on 07-31. A reason code is four bytes.
	 *
	 * ⚠ AND LbrCtl IS FILLED EVEN WHEN THE CAPTURE FAILS, so the record carries the raw MSR that the
	 * decision was made from. "EN was clear" plus the word that says so is a diagnosis; "absent" is a
	 * shrug.
	 */
	UINT32 LbrWhy;                        /* NXC_BPD_LBRWHY_*                                     */

	/*
	 * ⚠ WHERE IN THE PT BUFFER THIS TRAP HAPPENED (D108). PT already attributes by CR3 in hardware,
	 * so unlike LBR it needs no moment to be OURS -- what it lacks is a position. The ToPA region is
	 * circular and written continuously (~42 B/ms/core measured, filtered), so by the time usermode
	 * dumps it the bytes covering a trap are long gone. This offset is what lets a dump be decoded up
	 * to the instant of the hit instead of to whenever the dump happened.
	 *
	 * ⚠ OPT-IN PER SLOT (`--pt`), because obtaining it costs two WRMSRs and a fence ON THE TRAP PATH:
	 * the SDM requires TraceEn cleared before the pointer read, or the value is stale. LBR's snapshot
	 * is RDMSR-only and can be unconditional; this cannot, and making it so would put a serializing
	 * instruction on the hot path of every breakpoint on the machine.
	 */
	UINT64 PtOffset;                      /* IA32_RTIT_OUTPUT_MASK_PTRS[63:32] at the trap         */
	UINT32 PtWhy;                         /* NXC_BPD_PTWHY_*                                      */
	/*
	 * ⚠ THE WRAP GENERATION, and it is what makes PtOffset survive a wrap. Two hits either side of
	 * one compare WRONGLY on offset alone -- 5,000 is later than 250,000 once the writer comes round.
	 * (PtGen, PtOffset) is a total order. Software-counted: a single-entry circular ToPA region has
	 * no revolution counter in hardware. Occupies the padding this field was reserved as.
	 */
	UINT32 PtGen;
	NXCMD_LBR_ENTRY Lbr[NXC_BPD_LBR_MAX];
	/*
	 * ⚠ THE PID, SO THE STACK CAN BE READ AFTERWARDS. SMAP is ACTIVE (CR4 bit 21) and every hit so
	 * far is ring 3, so ring 0 cannot read the target's stack at trap time without setting EFLAGS.AC
	 * -- and MmIsAddressValid, the obvious residency check, is documented <= DISPATCH, so a paged-out
	 * user stack would bugcheck rather than fail.
	 *
	 * ⚠ THAT SECOND CLAUSE WAS TRUE OF MmIsAddressValid AND FALSE OF THE PROBLEM. NxcPteQuery walks
	 * the SELF-MAP, and page-table pages are always resident, so it is a legal residency check at any
	 * IRQL -- the constraint was the chosen API, not the trap path. Trap-time capture is Stack[] above.
	 * The pid stays because the two answer different questions: Stack[] is what the frame held AT THE
	 * TRAP, `--stack N` is what it holds NOW, and a disagreement between them is itself evidence.
	 *
	 * ⚠ POST-HOC, AND THAT IS A REAL LIMITATION, NOT A DETAIL. The target has resumed by then, so the
	 * bytes are the stack as it is NOW, not as it was at the trap. Reported as such rather than
	 * presented as a snapshot.
	 */
	UINT32 Pid;
	UINT32 Reserved0;

	/*
	 * ---- THE LAST EVENT RECORD, READ ON THE FAULT PATH ---------------------------------------
	 *
	 * ⚠⚠ THIS IS THE ONLY PLACE LER IS WORTH READING, and that was MEASURED rather than assumed.
	 *
	 * LER holds the branch taken immediately before the last exception, hardware interrupt, or
	 * software interrupt. Read from a general-purpose hook it is almost always the last TIMER
	 * TICK -- verified: a deliberate #PF was forced and the LER sampled just afterwards
	 * still showed the recurring interrupt path, because timer interrupts fire constantly on a live
	 * machine and overwrite an application fault within microseconds.
	 *
	 * Here, in the exception observer, it is read ON the fault path, so it names the branch that
	 * reached the FAULTING instruction -- before any interrupt can replace it. Same three MSRs,
	 * completely different value, purely because of WHERE they are read.
	 *
	 * ⚠ Info shares NXCMD_LBR_ENTRY.Info's layout (BR_TYPE 59:56, CYC_CNT 15:0, MISPRED 63), so it
	 * renders through the same decoder rather than a second one that would have to be kept in step.
	 *
	 * ⚠ ZERO IS "NO EVENT RECORDED", not a branch from address 0.
	 */
	UINT64 LerFrom;
	UINT64 LerTo;
	UINT64 LerInfo;
} NXC_BPD_HIT;
#pragma pack(pop)

/* Size assert lives with the others at the end of this file: NXCMD_ASSERT, not C_ASSERT --
 * this header is consumed by the EDK2 DXE build too, where C_ASSERT does not exist. */

#pragma pack(push, 1)
typedef struct _NXCMD_KPAGE
{
	NXCMD_U64 Va;
	NXCMD_U64 Pfn;
	NXCMD_U32 PteFlags;      /* NXC_PTE_* as NexusCoreBoot.h defines them          */
	NXCMD_U32 Expected;      /* NXCMD_KPAGE_EXP_* from the section characteristics */
	NXCMD_U32 Mismatch;      /* NXCMD_KPAGE_MM_*  -- actual vs expected            */
	NXCMD_U8  Section[8];    /* the covering section's name, NUL-padded            */
} NXCMD_KPAGE;
#pragma pack(pop)

#define NXCMD_KPAGE_EXP_WRITE     0x00000001u  /* IMAGE_SCN_MEM_WRITE   */
#define NXCMD_KPAGE_EXP_EXECUTE   0x00000002u  /* IMAGE_SCN_MEM_EXECUTE */
#define NXCMD_KPAGE_EXP_KNOWN     0x00000004u  /* a section covers this page at all              */
#define NXCMD_KPAGE_EXP_STRADDLE  0x00000008u  /* the page spans a section boundary -- see below */

/*
 * ⚠ A STRADDLING PAGE CANNOT PRODUCE EVIDENCE, and is flagged rather than judged. When sections are
 * not page-aligned in memory one page belongs to two of them, so whichever expectation is chosen is
 * wrong for part of the page. Reporting a mismatch there would manufacture a finding out of a
 * layout detail. The flag says "this page's expectation is not decidable", which is a fact.
 */
#define NXCMD_KPAGE_MM_WRITE      0x00000001u  /* writable where the section says it should not be */
#define NXCMD_KPAGE_MM_EXECUTE    0x00000002u  /* executable where the section says it should not  */
#define NXCMD_KPAGE_MM_NOT_EXEC   0x00000004u  /* NOT executable where the section says it should  */
#define NXCMD_KPAGE_MM_WX_4K      0x00000008u  /* writable AND executable on a 4 KB page           */
/*
 * ⚠ W+X ON A LARGE PAGE IS SEPARATE AND IS **NOT** A MISMATCH. Windows maps ntoskrnl.exe and hal.dll
 * on 2 MB pages by default, and protection applies to the whole 2 MB -- so .text and .data share one
 * mapping and it MUST be writable and executable. Folding that into the W+X count would light up
 * ntoskrnl on the first run and train the reader to ignore the number, which is how `procs --hidden`
 * earned seven false positives before terminating processes were separated out.
 */
#define NXCMD_KPAGE_MM_WX_LARGE   0x00000010u
#define NXCMD_KPAGE_MM_USER       0x00000020u  /* U/S set on KERNEL memory -- always worth a look  */
#define NXCMD_KPAGE_MM_NOT_MAPPED 0x00000040u  /* inside SizeOfImage and the walk found nothing    */

/*
 * ⚠ Caller-written bit in `Flags` for NXCMD_OP_LBR_SNAP_INIT: keep the LAST N snapshots instead of
 * the FIRST N.
 *
 * The default fill-and-stop answers "what does this function do when called" and bounds its own
 * cost -- once the ring is full every later hit is one interlocked increment. WRAP answers the
 * other question: a target that does something interesting ONCE, at an unknown moment, where the
 * branches worth having are the ones AROUND the event and a ring that filled during the first
 * milliseconds after arming holds nothing but startup.
 *
 * ⚠ It pays ~96 RDMSRs on the TARGET'S OWN THREAD for every hit, forever, which is why it is opt-in
 * rather than the default. Snapshots replaced by wrapping are COUNTED and reported separately from
 * drops -- an overwrite was recorded and superseded, a drop was never recorded at all.
 */
#define NXCMD_LBR_SNAP_WRAP     0x00000001u

#define NXCMD_OP_LBR_SNAP_INIT  41u
#define NXCMD_OP_LBR_SNAP_DRAIN 42u
#define NXCMD_OP_LBR_SNAP_FREE  43u

#define NXCMD_LBR_F_ARCH        0x00000001u  /* architectural LBR present (CPUID.1CH)          */
/*
 * ⚠ "EN IS SET" IS NOT "SOMEBODY ELSE OWNS IT" -- and reading it that way made `lbr read` print
 * "LBR IS ARMED BY SOMETHING ELSE" on all 24 cores IMMEDIATELY AFTER WE ARMED THEM (seen).
 * A warning that fires every time cannot warn: the day a real contender appears it reads identically.
 * NXCMD_LBR_F_OURS is what separates them, and it comes from the record `lbr arm` wrote rather than
 * from a second inference that has to agree with it.
 */
#define NXCMD_LBR_F_ENABLED     0x00000002u  /* IA32_LBR_CTL.EN set -- ours or not, see F_OURS  */
#define NXCMD_LBR_F_OURS        0x00000010u  /* WE armed this core (gLbrArmedMask), so not a foe */
#define NXCMD_LBR_F_HAS_INFO    0x00000004u  /* CPUID.1CH:ECX nonzero -- INFO carries something */
#define NXCMD_LBR_F_UNSUPPORTED 0x00000008u  /* no arch LBR here; NOTHING was read (fail-closed) */

/*
 * The two record types `bp list` produces. WHICH ONE comes back is decided by TargetModuleId:
 * 0 -> NXCMD_BP_CPU records (the per-core contention view), a pid -> NXCMD_BP_THREAD records.
 *
 * ⚠ ONE RECORD TYPE PER CALL, deliberately. A single buffer carrying a tagged mix of two layouts is
 * how a length gets applied to the wrong stride, and this buffer is written by the kernel and parsed
 * by usermode -- the exact seam where that mistake is silent. The CLI issues two commands and prints
 * two sections; the kernel never has to describe what it just wrote.
 */
#pragma pack(push, 1)
typedef struct _NXCMD_BP_CPU
{
	NXCMD_U64 Dr[4];
	NXCMD_U64 Dr6;          /* which breakpoint(s) last FIRED, plus BS/BD -- sticky until cleared */
	NXCMD_U64 Dr7;
	NXCMD_U32 CpuNumber;
	NXCMD_U32 Enabled;      /* how many of the four have L or G set on THIS core                  */

	NXCMD_U8  Local[4];     /* Lx -- cleared by the CPU on a task switch; what Windows uses       */
	NXCMD_U8  Global[4];    /* Gx -- survives a task switch                                       */
	NXCMD_U8  Type[4];      /* 00 exec, 01 write, 10 I/O, 11 read-write                           */
	NXCMD_U8  Len[4];       /* 00 1 byte, 01 2, 10 8, 11 4  -- note 10 and 11 are NOT in order    */

	/*
	 * The process each slot was ARMED FOR. The kernel has tracked this all along (gBpSlotPid, used
	 * to stamp hit records) and never reported it, so `bp list` could say a slot was busy and not
	 * say busy WITH WHAT.
	 *
	 * measured, which is why it is here: arming four probes and then KILLING the target
	 * left "96 slot(s) across 24 core(s) enabled" with nothing able to tell that the owner was gone.
	 * Debug registers hold an address, not an owner -- so a dead target frees nothing, and without
	 * this field usermode has nothing to test a live process against.
	 *
	 * 0 = that slot is not armed. Identical on every CPU (the slot table is global, the DR state is
	 * per-core), and carried per-record anyway because a regular layout beats a special case.
	 */
	NXCMD_U32 OwnerPid[4];
} NXCMD_BP_CPU;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct _NXCMD_BP_THREAD
{
	NXCMD_U64 Dr[4];
	NXCMD_U64 Dr7;
	NXCMD_U32 ThreadId;
	NXCMD_U32 Enabled;      /* how many of the four are enabled in THIS thread's context */
} NXCMD_BP_THREAD;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct _NXCMD_THREAD_ENTRY
{
	NXCMD_U64 Teb;          /* PsGetThreadTeb -- v1 claimed this was unexported; it is not  */
	NXCMD_U64 CreateTime;
	NXCMD_U32 ThreadId;
	NXCMD_U32 ProcessId;
	NXCMD_U32 Terminating;  /* reported, never silently dropped -- see above                */
	NXCMD_U32 Reserved0;
} NXCMD_THREAD_ENTRY;
#pragma pack(pop)

#define NXCMD_IDT_MAX_TARGETS 16u

#pragma pack(push, 1)
typedef struct _NXCMD_IDT_TARGET
{
	NXCMD_U64 Va;
	NXCMD_U64 FuncBegin;
	NXCMD_U64 FuncEnd;
	NXCMD_U32 CallSite;
	NXCMD_U32 IsFunctionStart;   /* Va == FuncBegin: the check that makes this checkable */
	NXCMD_U32 IsTailJump;        /* E9 rather than E8 -- how a trap handler reaches the dispatcher */
	/* Inside the probed function's own bounds: an ordinary internal branch, not a transfer. Three
	 * cases need three names -- internal, external-and-a-function-start (dispatcher candidate), and
	 * external-but-not-a-start (the suspicious one). */
	NXCMD_U32 IsInternal;
	/* Found by the unaligned scan rather than the linear decode. Different confidence: the decode
	 * knows the byte began an instruction; the scan relies entirely on the .pdata function-start
	 * filter to reject a coincidental 0xE8/0xE9 inside another instruction. */
	NXCMD_U32 FoundByScan;
	NXCMD_U32 Reserved1;
} NXCMD_IDT_TARGET;

typedef struct _NXCMD_IDT_PROBE
{
	NXCMD_U64 IdtBase;
	NXCMD_U32 IdtLimit;
	NXCMD_U32 Vector;
	NXCMD_U64 HandlerVa;
	NXCMD_U64 HandlerBegin;
	NXCMD_U64 HandlerEnd;
	NXCMD_U32 DecodedBytes;
	NXCMD_U32 TargetCount;
	/*
	 * RSB-stuffing calls the probe DROPPED (Spectre-v2 return-stack fill: a real E8 whose target is
	 * < 0x40 forward). REPORTED rather than silent -- a filter that removes 27 of 37 transfers and
	 * says nothing is indistinguishable from a decode that only ever found 10.
	 *
	 * ⚠ It matters because the dispatcher derivation RANKS candidates by transfer count. Counting
	 * the fill promotes whichever function carries the most Spectre padding and yields a confident
	 * wrong dispatcher address. On the reference build KiExceptionDispatch drops 27, keeps 10.
	 */
	NXCMD_U32 RsbFiltered;
	/*
	 * External transfers to .pdata function STARTS, counted to the end of the function and NOT
	 * capped by the Targets[] table. THIS is what a caller ranks candidates on -- TargetCount
	 * saturates at NXCMD_IDT_MAX_TARGETS and reported 15 for a function whose real figure is 28,
	 * a floor presented as a count.
	 */
	NXCMD_U32 ExternalStarts;
	/* 0 = reached the end, 1 = decoder errored, 2 = table full, 3 = not resident. StopBytes holds
	 * what was actually at StopOffset, because "the decode stopped" is not a finding and the bytes
	 * are the only thing that identifies an encoding this decoder does not know. */
	NXCMD_U32 StopReason;
	NXCMD_U32 StopOffset;
	NXCMD_U8  StopBytes[16];
	NXCMD_IDT_TARGET Targets[NXCMD_IDT_MAX_TARGETS];
} NXCMD_IDT_PROBE;
#pragma pack(pop)

#define NXCMD_HOOK_ST_OK            0u
#define NXCMD_HOOK_ST_BASELINE      1u   /* wrong BEFORE anything was patched            */
#define NXCMD_HOOK_ST_INSTALL       2u
#define NXCMD_HOOK_ST_WRONG_ANSWER  3u   /* hooked, called, and the detour CHANGED it    */
#define NXCMD_HOOK_ST_NOT_LISTED    4u
#define NXCMD_HOOK_ST_REMOVE        5u
#define NXCMD_HOOK_ST_AFTER         6u   /* wrong answer after the restore               */
#define NXCMD_HOOK_ST_NOT_RESTORED  7u   /* the qword did not return to its old value    */
#define NXCMD_HOOK_ST_NO_HIT        8u   /* the LOGGING pass never reached the handler   */

/*
 * Caller-written bit in `Flags` for NXCMD_OP_HOOK_INSTALL: make the detour RECORD the call.
 *
 * ⚠ OPT-IN, AND THE NO-OP DETOUR REMAINS THE DEFAULT. Without this the stub is 14 bytes that
 * touch no register at all -- not even RAX, because `jmp [rip+0]` reads its destination from
 * data -- and that is the variant proven on hardware. With it, the stub carries a context pointer
 * in r10 and runs a shared thunk that saves the volatile set, calls into C at the target's own
 * IRQL, restores and tail-jumps. Strictly more that can go wrong, so it is asked for.
 */
#define NXCMD_HOOK_FLAG_LOG         0x00000001u
/*
 * Snapshot the LBR ring at every hit. Mirrors NXC_HOOK_FLAG_LBR; the kernel side carries the
 * reasoning. Requires NXCMD_HOOK_FLAG_LOG (the no-op detour never reaches C) and a reserved
 * snapshot ring -- both REFUSED rather than ignored, because both would fail silently.
 */
#define NXCMD_HOOK_FLAG_LBR         0x00000002u
/*
 * Run every check and MEASURE THE REAL DISTANCE, then patch nothing. Mirrors NXC_HOOK_FLAG_PROBE.
 *
 * Exists for one question that gates all of phase 3: is the arena within rel32 reach of the
 * exception dispatcher? That was located structurally (D16/D17) and deliberately NOT hooked, and
 * the open item is a ~1.8 GB gap against a +-2 GB limit -- marginal, and KASLR-dependent, so it
 * differs every boot. It cannot be estimated: the reachable thing is the STUB, whose address the
 * arena chooses. And it must not be answered by just trying it, because a successful hook there
 * is a patch on the path of EVERY exception in the system, installed to satisfy curiosity.
 */
#define NXCMD_HOOK_FLAG_PROBE       0x00000004u
/* Mirrors NXC_HOOK_FLAG_EXCEPTION. Monitor-only observer for the exception dispatcher. */
#define NXCMD_HOOK_FLAG_EXCEPTION   0x00000008u

/*
 * ==================================================================================================
 * CALL EVIDENCE -- build-plan items B-01 (file capture) and B-02 (object/registry visibility).
 * ==================================================================================================
 *
 * BOTH ITEMS WERE FILED AS BLOCKED, AND THE BLOCK WAS REAL BUT NARROWER THAN IT LOOKED.
 * FltRegisterFilter, ObRegisterCallbacks and CmRegisterCallbackEx all demand a DriverObject that a
 * manually mapped image does not have and cannot manufacture. That refusal is about REGISTRATION.
 * The functions those callbacks would have told us about are ordinary kernel code at ordinary
 * addresses, and an inline hook on one needs no DriverObject, no registration and no presence in
 * PsLoadedModuleList. The blocked APIs were one route to the evidence, not the evidence.
 *
 * ⚠ WHY THE PLAIN LOGGING HOOK WAS NOT ALREADY ENOUGH -- it forwards args 1 and 2, and for every
 * function these two items care about THE NAME IS NOT IN EITHER:
 *
 *     NtCreateFile (out handle, access, OBJECT_ATTRIBUTES, ...)   name in ARG 3
 *     NtOpenProcess(out handle, access, OBJECT_ATTRIBUTES, CID)   pid  in ARG 4
 *     NtSetValueKey(key handle, UNICODE_STRING*, ...)             name in ARG 2, behind a POINTER
 *
 * A hook that recorded args 1-2 would report "NtCreateFile ran 4000 times" and never once say WHICH
 * FILE -- hooked and blind, which reads like working instrumentation. So the thunk forwards four
 * arguments and the capture DEREFERENCES the one that carries a name.
 *
 * ⚠ THE SHAPE IS TOLD TO THE KERNEL, NEVER GUESSED BY IT (D5/D6). A kernel-side table mapping
 * "NtCreateFile" to "arg 3 is an OBJECT_ATTRIBUTES" would be pinned per-prototype knowledge in ring
 * 0, where being wrong means dereferencing an ACCESS_MASK as a pointer. PlatformCtl knows the
 * prototypes and sends the shape; the kernel reads what it was told to read and REPORTS WHAT IT
 * ACTUALLY GOT (D3) -- including, explicitly, that it got nothing and why.
 */
#define NXCMD_HOOK_FLAG_CALLS       0x00000010u  /* record full call evidence, not a log line */
/* arg3 is a POBJECT_ATTRIBUTES -- follow ->ObjectName. NtCreateFile/NtOpenFile/NtOpenProcess/NtCreateKey */
#define NXCMD_HOOK_FLAG_OBJATTR3    0x00000020u
/* arg2 is a PUNICODE_STRING directly -- NtSetValueKey's value name */
#define NXCMD_HOOK_FLAG_USTR2       0x00000040u
/*
 * arg4 is a PCLIENT_ID -- follow it and record the pid/tid being opened.
 *
 * ⚠ ADDED AFTER THE FIRST SUCCESSFUL B-02a RUN, WHICH ANSWERED THE WRONG HALF OF THE QUESTION.
 * NtOpenProcess fired across eight processes, correctly reported `NULL_OA` (PowerShell opens by
 * CLIENT_ID, not by name) and recorded arg4 as `0xBB10A8E800`. That is a POINTER TO the CLIENT_ID,
 * not the pid. So the output proved a process was opened, by whom, and with what access -- and never
 * once said WHICH PROCESS, which is the entire question B-02 exists to answer. The test's own
 * success criterion ("a record whose arg4 points at a CLIENT_ID for pid 24928") could not be
 * evaluated from the evidence the run produced.
 *
 * It is the SAME defect as recording args 1-2 and never the name, one level down: a pointer captured
 * where the thing behind it is the fact. Solved for strings, left undone for this one.
 *
 * ⚠ INDEPENDENT OF THE NAME SHAPE, NOT AN ALTERNATIVE TO IT. NtOpenProcess can carry BOTH an
 * OBJECT_ATTRIBUTES name and a CLIENT_ID, and which one is populated is the caller's choice -- so
 * this runs alongside _OBJATTR3 rather than instead of it.
 */
#define NXCMD_HOOK_FLAG_CID4        0x00000080u
/* Capture the CONTENT of a file being deleted (B-01, D110). Needs `capture file init` first;
 * without the ring the hook records nothing rather than referencing objects nobody will release. */
#define NXCMD_HOOK_FLAG_FCAP        0x00000100u

/*
 * ==================================================================================================
 * ⚠⚠ THE PROTECTION-CHANGE SHAPE -- arg2 is a PVOID*, arg3 a PSIZE_T. `NtProtectVirtualMemory`.
 * ==================================================================================================
 *
 * EVERY protection this framework reports today is a SAMPLE. `regions` asks the memory manager what
 * a VAD currently records, `NXC_REGION.PteFlags` asks the CPU what a PTE currently enforces, and
 * both answer for the instant they were asked. Nothing observes a protection CHANGE.
 *
 * ⚠ THAT IS A REAL GAP AND THE ARCHIVED CAPTURES MEASURE IT. In the launcher, gsl.dll is mapped
 * THREE times -- one MEM_IMAGE copy plus two 0x2E2C000 MEM_PRIVATE mirrors, all absent from the
 * loader list -- and its cipher phase issues 2787 NtProtectVirtualMemory calls, running each
 * protected region decrypt -> RX -> exec -> re-encrypt -> RW. `GSL.dll+0x2B9C553` held a verdict
 * `imul` at 3s dwell whose signature appears NOWHERE in the 5s image. A dump of that process is
 * therefore honest and useless in the same breath: the page really was RW- when asked, and really
 * did execute microseconds earlier. Sampling harder does not fix sampling.
 *
 * So this flag records the TRANSITION, at the only place both halves exist at once:
 *
 *     ProtBase / ProtSize   *arg2 and *arg3 -- the region, not the pointer to it
 *     Arg[3]                NewProtect -- what it is ABOUT TO BECOME
 *     ProtPte               NXCMD_XLAT_* walked at ProtBase RIGHT NOW -- what the CPU is enforcing
 *                           BEFORE the flip, read on the caller's own thread in its own CR3
 *
 * ⚠ THE `BEFORE` SIDE IS TAKEN FROM THE PTE, NOT FROM `OldProtect`. OldProtect is an OUT parameter
 * -- at entry it points at uninitialised caller memory, so an entry hook that read it would record
 * whatever was on that stack. The PTE is ground truth and is available now. (It is also strictly
 * better evidence: OldProtect reports what the MM last RECORDED, ProtPte what the CPU ENFORCES,
 * and this target is exactly the case where those two can differ.)
 *
 * ⚠ IT DOES NOT PROVE EXECUTION AND MUST NOT BE READ AS PROVING IT (D6). A protection becoming
 * executable says a window OPENED, not that anything ran in it. That still needs a trap in the
 * window -- which is the point: this is what says WHERE and WHEN to put one.
 *
 * ⚠ NEEDS NXCMD_HOOK_FLAG_CALLS. The fields live in NXCMD_CALL_ENTRY, and the log ring's three
 * payload qwords cannot carry them -- asking without it is refused rather than half-recorded.
 */
#define NXCMD_HOOK_FLAG_PROT        0x00000200u
/* arg1/arg2 are (DEVICE_OBJECT, IRP) on a TPM driver dispatch -- record the device-control
 * request into the TPM ring. OBSERVATION ONLY: the recorder never touches the IRP, so the
 * target's command runs exactly as it would have. Mirrors NXC_HOOK_FLAG_TPM. */
#define NXCMD_HOOK_FLAG_TPM         0x00000400u
/*
 * ReadLength carries a SYSCALL SERVICE INDEX, for functions ntoskrnl exports under NEITHER name.
 * measured: NtWriteVirtualMemory and NtReadVirtualMemory have no Nt* and no Zw* export,
 * so the kernel cannot derive an index from a stub it cannot find. Usermode ntdll DOES export them
 * and every stub begins 4C 8B D1 B8 <imm32>, so the caller reads the index and hands it over.
 * The kernel bounds-checks it against the service count and verifies the routine is inside
 * ntoskrnl -- it is usermode input reaching a patch address.
 */
#define NXCMD_HOOK_FLAG_BYINDEX     0x00000400u

/*
 * ⚠ WHY A NAME IS ABSENT IS A FIRST-CLASS FIELD, NOT A BLANK.
 *
 * An earlier finding cost four
 * boots and three correct fixes aimed at a reading that could not tell its own failure modes apart.
 * An empty name here has at least six causes, and they call for opposite responses: NOT_ASKED means
 * the operator did not pass a shape flag; NULL_OA means the caller genuinely passed no attributes
 * (legal -- NtCreateFile with a relative handle); NOT_RESIDENT means the string was paged out and
 * the SAME call would produce it next time; TRUNCATED means we have the name but not all of it.
 * "Blank" would make all six indistinguishable.
 */
#define NXCMD_CALL_NAME_OK          0u
#define NXCMD_CALL_NAME_NOT_ASKED   1u  /* no shape flag on this hook -- nothing was attempted   */
#define NXCMD_CALL_NAME_NULL_OA     2u  /* the attributes pointer itself was NULL                */
#define NXCMD_CALL_NAME_BAD_PTR     3u  /* non-canonical, or outside the ring the caller is in   */
#define NXCMD_CALL_NAME_NOT_RESIDENT 4u /* PTE walk says not present -- paged out, try again     */
#define NXCMD_CALL_NAME_EMPTY       5u  /* UNICODE_STRING present, Length 0                      */
#define NXCMD_CALL_NAME_TRUNCATED   6u  /* copied, but the string is longer than the record      */

#define NXCMD_CALL_NAME_CHARS      128u

/*
 * One observed call. UTF-16 is stored RAW and never NUL-guaranteed -- NameChars says how many were
 * copied and NameCharsAvail says how many the UNICODE_STRING claimed, so a reader can always tell a
 * complete name from a clipped one (D3: report what was ACTUALLY produced, never assume the request
 * was satisfied).
 */
typedef struct _NXCMD_CALL_ENTRY
{
	NXCMD_U64 Sequence;         /* 0 = never written / being overwritten right now */
	NXCMD_U64 TimeStamp;        /* KeQueryPerformanceCounter ticks                 */
	NXCMD_U64 TargetVa;         /* which hook produced this                        */
	NXCMD_U64 ReturnAddress;    /* who called the target                           */
	NXCMD_U64 Arg[4];           /* raw, uninterpreted (D6: evidence, not verdict)   */
	NXCMD_U32 Pid;
	NXCMD_U32 Tid;
	NXCMD_U32 NameWhy;          /* NXCMD_CALL_NAME_*                               */

	/*
	 * The CLIENT_ID behind arg4, when the shape said to follow it. TargetPid is the answer to
	 * "which process is being opened" -- the fact the raw arg4 pointer could not give.
	 * CidWhy reuses NXCMD_CALL_NAME_* so absence has the same seven-way vocabulary as a name.
	 */
	NXCMD_U32 TargetPid;
	NXCMD_U32 TargetTid;
	NXCMD_U32 CidWhy;

	/*
	 * Arguments 5..10, read from the caller's stack at EntryRsp+0x28.
	 *
	 * ⚠ WITHOUT THESE, A WHOLE CLASS OF Nt* FUNCTIONS IS UNREADABLE AT THE POINT THAT MATTERS. The
	 * x64 ABI puts arguments 1-4 in registers and everything after on the stack, and the fact that
	 * decides whether a call is interesting is routinely past the fourth:
	 *
	 *     NtSetInformationFile(Handle, Iosb, Info, Length, FileInformationClass)
	 *                                                      ^ arg 5 -- the ONLY thing that says
	 *                                                        this call is a DELETE
	 *     NtCreateFile(..., CreateDisposition, CreateOptions, ...)
	 *                                          ^ arg 9 -- carries FILE_DELETE_ON_CLOSE
	 *
	 * Six is the count that covers NtSetInformationFile (5) through NtCreateFile's CreateOptions (9)
	 * with one to spare, which is where the family's decisive parameters actually sit.
	 */
	NXCMD_U64 StackArg[6];
	NXCMD_U32 StackWhy;         /* NXCMD_CALL_NAME_* -- absent has causes here too */

	NXCMD_U16 NameChars;        /* chars in Name[]                                 */
	NXCMD_U16 NameCharsAvail;   /* chars the string CLAIMED to have                */
	NXCMD_U16 Name[NXCMD_CALL_NAME_CHARS];

	/*
	 * ---- THE PROTECTION TRANSITION, when NXCMD_HOOK_FLAG_PROT asked for it -------------------
	 *
	 * ⚠ APPENDED, NOT INSERTED, AND THAT IS DELIBERATE. Name[] ends at a multiple of 8, so these
	 * land naturally aligned with no padding AND every field above keeps the offset it had. The
	 * size still travels in Command->Flags and PlatformCtl still checks it, so a mixed-build pair
	 * is caught -- but a layout change that moves existing fields turns that check from a warning
	 * into the only thing standing between a stale reader and silent garbage. Appending means even
	 * an unchecked reader gets the old fields right.
	 *
	 * ProtBase/ProtSize are the DEREFERENCED region -- *arg2 and *arg3 -- because the raw arguments
	 * are pointers into the caller's stack and say nothing about which memory is changing.
	 */
	NXCMD_U64 ProtBase;         /* *arg2 -- VA whose protection is being changed    */
	NXCMD_U64 ProtSize;         /* *arg3 -- bytes, as the CALLER passed them        */
	/*
	 * ⚠⚠ NXC_PTE_* (NexusCoreBoot.h), **NOT** NXCMD_XLAT_* -- AND THE TWO COLLIDE BIT FOR BIT.
	 *
	 *     NXC_PTE_PRESENT  0x02 | NXCMD_XLAT_WRITABLE 0x02
	 *     NXC_PTE_WRITABLE 0x04 | NXCMD_XLAT_USER     0x04
	 *     NXC_PTE_EXECUTE  0x08 | NXCMD_XLAT_NX       0x08   <-- same bit, OPPOSITE SENSE
	 *
	 * Feeding one vocabulary to the other's formatter prints plausible nonsense with the execute
	 * bit exactly inverted, so the two have SEPARATE formatters in PlatformCtl and they are not
	 * interchangeable. NXC_REGION.PteFlags is the XLAT one; this is the PTE one. Check which you
	 * hold before rendering it.
	 *
	 * ⚠ WHY THIS FIELD USES THE CHEAPER WALK, when NXC_REGION.PteFlags uses NxcTranslate:
	 *
	 * NxcTranslate reads the tables through MmCopyMemory(MM_COPY_MEMORY_PHYSICAL), which allocates
	 * from paged pool per call and is PASSIVE_LEVEL only -- four of those per descent. `regions`
	 * can afford it because it walks once per region from a command thread. THIS runs inside the
	 * hook, on the target's own thread, on a path the motivating target hits 2787 times in a
	 * single cipher phase. Paying a pool allocation there is not a measurement, it is a slowdown
	 * we introduced. The self-map walk allocates nothing and is legal at any IRQL.
	 *
	 * ⚠ AND THE COST IS PAID IN PRECISION, WHICH IS STATED RATHER THAN HIDDEN: the self-map walk
	 * reports the LEAF entry's bits, while NxcTranslate accumulates EFFECTIVE permissions across
	 * all four levels (write needs RW at every level, execute is denied if NX is set at ANY). So a
	 * leaf marked writable under a read-only PDE reads writable here and would not in `regions`.
	 * For the question being asked -- did this page's own entry change -- the leaf is the right
	 * granularity; for "what would the CPU do", it is an upper bound.
	 *
	 * ⚠ 0 IS "NOT WALKED", NOT "NO RIGHTS" -- NXC_PTE_VALID is what says the walk completed.
	 */
	NXCMD_U32 ProtPte;
	NXCMD_U32 ProtWhy;          /* NXCMD_CALL_NAME_* -- absent has causes here too  */
} NXCMD_CALL_ENTRY;

#define NXCMD_CALL_STACK_ARGS 6u

#define NXCMD_OP_CALLS_INIT 55u   /* reserve the ring (arena, D4) */
#define NXCMD_OP_CALLS_READ 56u   /* drain it to the caller's OutBuffer (D2) */

/*
 * ==================================================================================================
 * FILE CONTENT CAPTURE -- B-01's second half (D110).
 * ==================================================================================================
 *
 * `hook nt NtSetInformationFile` proves a delete is visible (a5 = FileDispositionInformationEx).
 * This keeps the BYTES. The hook references the FILE_OBJECT and queues it; a system thread resolves
 * the name, opens by path and reads NON-CACHED.
 *
 * ⚠ WHY IS AN OUTCOME, NOT A FLAG. "0 captures" has at least eight causes here and they call for
 * opposite responses: GONE means the window was too short and the design needs tightening, TOO_LARGE
 * means the bound is wrong for this workload, NO_ROOM means the byte budget is exhausted and every
 * later capture will fail the same way, EMPTY means we captured a zero-byte file correctly. A count
 * on its own makes a lost race look exactly like a quiet system.
 */
#define NXC_FCAP_OK           0u
#define NXC_FCAP_GONE         1u  /* the unlink won -- caller closed before the worker opened     */
#define NXC_FCAP_TOO_LARGE    2u  /* over the bound; REFUSED rather than clipped, size reported   */
#define NXC_FCAP_NO_ROOM      3u  /* byte budget exhausted -- every later capture fails too       */
#define NXC_FCAP_OPEN_FAILED  4u  /* a real open/query failure; NtStatus carries which            */
#define NXC_FCAP_READ_FAILED  5u
#define NXC_FCAP_SHORT_READ   6u  /* read succeeded but returned less than the file's size        */
#define NXC_FCAP_EMPTY        7u  /* zero-byte file -- captured correctly, and there is nothing   */
#define NXC_FCAP_NAME_FAILED  8u  /* the object had no resolvable name, so nothing was openable   */

#define NXCMD_FCAP_NAME_CHARS 200u
/* 8 MB. A bound that refuses is worth more than a bound that truncates: a clipped capture is a file
 * nobody can tell is clipped later. FileSize is reported either way, so "how far over" is answerable. */
#define NXCMD_FCAP_MAX_BYTES  (8u * 1024u * 1024u)

typedef struct _NXCMD_FCAP_ENTRY
{
	NXCMD_U64 Sequence;         /* 0 = being written right now */
	NXCMD_U64 TimeStamp;
	NXCMD_U64 FileSize;         /* what the file WAS, even when nothing was captured */
	NXCMD_U64 BytesCaptured;    /* what was ACTUALLY read (D3) -- may be less        */
	NXCMD_U64 ByteOffset;       /* where in the capture arena; use `capture file pull` */
	NXCMD_U64 NtStatus;
	NXCMD_U32 Pid;
	NXCMD_U32 Tid;
	NXCMD_U32 InfoClass;        /* the disposition class that triggered it */
	NXCMD_U32 Why;              /* NXC_FCAP_* */
	NXCMD_U16 NameChars;
	NXCMD_U16 NameCharsAvail;
	NXCMD_U16 Name[NXCMD_FCAP_NAME_CHARS];
} NXCMD_FCAP_ENTRY;

typedef struct _NXCMD_FCAP_STATS
{
	NXCMD_U32 Armed;
	NXCMD_U32 Slots;
	NXCMD_U64 Queued;
	NXCMD_U64 QueueFull;    /* deletes seen with nowhere to put them -- REPORTED, never silent */
	NXCMD_U64 RefFailed;
	NXCMD_U64 Captured;
	NXCMD_U64 Gone;
	NXCMD_U64 Total;
	NXCMD_U64 BytesUsed;
	NXCMD_U64 BytesBudget;
} NXCMD_FCAP_STATS;

#define NXCMD_OP_FCAP_INIT 57u
#define NXCMD_OP_FCAP_READ 58u
#define NXCMD_OP_FCAP_PULL 59u

/*
 * ============================================================================================
 * PTE SCAN (60) -- which pages a target has TOUCHED and WRITTEN, without touching it back.
 * ============================================================================================
 *
 * The CPU maintains two bits per page that nobody has to ask for: ACCESSED (bit 5), set on any
 * translation, and DIRTY (bit 6), set on a write. Reading them costs a page-table walk and
 * perturbs nothing -- no trap, no fault, no interception, no interrupt, and nothing for a target
 * to detect. `NXC_XLAT` already decodes both; this opcode is the RANGE walk that makes them usable.
 *
 * (!) THE DERIVED SIGNAL IS **DIRTY AND EXECUTABLE**. A page that was WRITTEN at runtime and is
 * also EXECUTABLE is code that did not come from the image on disk -- which is what unpacking,
 * decrypting and JIT all look like from outside. Reported as EVIDENCE, never as a verdict (D6):
 * a JIT is indistinguishable from a packer by this measure, and the tool says which pages, not
 * what they mean.
 *
 * (!) READ-ONLY, AND THE WRITE SIDE IS DELIBERATELY ABSENT. Clearing ACCESSED would let a caller
 * measure a WINDOW ("touched since I cleared it") rather than history-since-Windows-last-looked,
 * which is strictly more useful -- and it also needs a TLB shootdown to mean anything, because the
 * CPU only re-sets the bit on a translation that misses the TLB.
 *
 * (!)(!) CLEARING **DIRTY** IS REFUSED OUTRIGHT AND WILL NOT BE ADDED. The Windows Memory Manager
 * uses that bit to decide whether a pageable page must be written back before it is discarded.
 * Clearing it behind MM's back means a MODIFIED page can be treated as clean and dropped without
 * writeback -- silent data loss inside the process under inspection. A framework whose whole claim
 * is safe observation does not get to corrupt the thing it observes. This is a refusal about one
 * specific bit, not about the feature.
 */
#define NXCMD_OP_PTE_SCAN 60u

/*
 * ============================================================================================
 * NMI SAMPLING PROFILER (61-63) -- where a target executes, with NOTHING patched.
 * ============================================================================================
 *
 * A PMU fixed counter overflows every N retired RING-3 instructions, raising a PMI that arrives as
 * an NMI through the same LVT PC entry the ToPA fill counter uses. No breakpoint, no hook, no page
 * permission changed, no byte of the target modified -- there is nothing for it to detect.
 *
 * (!) THE SAMPLED ADDRESS COMES FROM THE **LBR**, NOT A TRAP FRAME. KeRegisterNmiCallback hands its
 * callback no trap frame, so the interrupted RIP is not directly available. The handler instead
 * reads the last RING-3 branch, which is sound for a MEASURED reason: `lbr selftest` proved on
 * that ring-3-only recording yields ZERO kernel entries (phase 1) while the instrument
 * was live (phase 2 = 768). Our own ring-0 NMI path therefore cannot appear in the ring.
 *
 * (!) SAMPLES ARE A DISTRIBUTION, NEVER A TRACE. The gaps between samples are unobserved by
 * construction. This answers "where does it spend time"; PT answers "what path did it take". They
 * compose -- sample to find the hot range, then aim `trace arm --filter` (D112) at it.
 */
/*
 * ============================================================================================
 * PEBS (64-66) -- the CPU writes the register state itself. STAGE 1 IS ALLOCATION ONLY.
 * ============================================================================================
 *
 * The sampling profiler (D114) reports WHERE a target was by reading the last LBR branch, because
 * `KeRegisterNmiCallback` hands its callback no trap frame. PEBS removes that compromise entirely:
 * on a counter overflow the PROCESSOR writes a record containing the PRECISE instruction pointer and,
 * with the GPR group selected, the architectural registers -- no handler involved in capturing it.
 *
 * MEASURED here before a line was written: PEBS on 24/24 cores, record format 6, ARCH_REG set, and
 * BASELINE set, so the layout is CHOSEN via MSR_PEBS_DATA_CFG (Memory Info [0], GPRs [1], XMM [2],
 * LBR [3]) rather than fixed.
 *
 * (!)(!) THIS BLOCK USED TO SAY "PEBS_OUTPUT_PT is also available -- records can go into the PT
 * stream instead of a buffer ... the better END STATE". THAT WAS FALSE, and it was false because
 * `cpuprobe` READ THE WRONG BIT (corrected).
 *
 * IA32_PERF_CAPABILITIES is [14] PEBS_BASELINE, [15] PERF_METRICS, [16] PEBS_OUTPUT_PT_AVAIL,
 * [17] ANYTHREAD_DEPRECATED. The probe reported bit 17 as OUTPUT_PT. Bit 17 is set on every modern
 * part, so it read a confident "24 of 24" for a capability this silicon does not have -- and the
 * off-by-one was camouflaged by PERF_METRICS[15], which genuinely differs between P-cores and
 * E-cores here and makes the neighbourhood look plausible.
 *
 * MEASURED, both raw words, both core types: P 0xAF6FF, E 0x276FF -- bit 16 is ZERO. This processor
 * will not emit BBP/BIP/BEP blocks, so there is nothing for a decoder to read and the feature
 * cannot be built here at all.
 *
 * (!) THE PURPOSE SURVIVES THE MECHANISM. What OUTPUT_PT was wanted for -- precise register state
 * placed inside the control-flow timeline the address filter already scopes -- is reachable by
 * CORRELATION instead of by one stream: a PEBS record carries a TSC at +0x18, and `trace arm --tsc`
 * puts TSC packets in the PT stream. Two streams, one clock. Both halves already exist and are
 * verified in silicon.
 *
 * (!)(!) STAGE 1 WRITES NO MSR, AND THAT IS A SAFETY SPLIT RATHER THAN A STYLE. IA32_DS_AREA is a
 * POINTER THE CPU WRITES THROUGH: a wrong address with PEBS enabled has the processor writing records
 * into memory we do not own. Same hazard as a bad ToPA entry, same answer -- allocate, report the
 * addresses, let them be checked with the hardware still off.
 */
/*
 * ⚠ THE REQUESTED RECORD STRIDE LIVES HERE, IN THE SHARED HEADER, FOR ONE REASON: 160 WAS TYPED AS
 * A LITERAL IN FOUR PLACES AND WAS WRONG IN ALL OF THEM.
 *
 * The kernel sized the buffer with it, and PlatformCtl's drain compared the hardware's own size
 * field against a hardcoded `160` in three separate printf arguments -- including a ratio that
 * DIVIDED BY the difference and printed "skipped 4294967295 of every 0 records" the moment the real
 * record turned out to be LARGER than the guess. Two copies of a number that must agree is the
 * shape this project keeps finding; one define is the cure.
 *
 * 176 = Basic 32 + GPR group 144. Both halves MEASURED, not read: records self-reported 32 bytes
 * with the GPR group off and 176 with it on. The group is 18 qwords -- RFLAGS and RIP as well as the
 * 16 general-purpose registers, which is exactly the pair an "obviously 16 x 8" assumption drops.
 *
 * ⚠ IT IS STILL A REQUEST. Every PEBS record states its own size in its first qword (bits 63:48),
 * and the drain reports the RECORD'S answer and walks at the RECORD'S stride whenever the two
 * disagree. This constant sizes memory; the hardware decides what is in it.
 */
#define NXCMD_PEBS_BASIC_BYTES  32u
#define NXCMD_PEBS_GPR_BYTES    144u
#define NXCMD_PEBS_STRIDE       (NXCMD_PEBS_BASIC_BYTES + NXCMD_PEBS_GPR_BYTES)

/*
 * ---- THE ADAPTIVE BASIC-GROUP HEADER, AS ONE SHARED EXPRESSION -------------------------------
 *
 * Qword 0 of every adaptive PEBS record. Verified against Linux
 * `arch/x86/include/asm/perf_event.h`, `struct pebs_basic`:
 *
 *     u64 format_group:32, retire_latency:16, format_size:16;
 *
 * C bitfields fill from the LSB, so the field order in memory is the REVERSE of how it reads:
 *
 *     bits 31:0   format_group    which groups this record contains (same numbering as DATA_CFG)
 *     bits 47:32  retire_latency  see below -- NOT "time spent retiring"
 *     bits 63:48  format_size     the record's own total size in bytes
 *
 * RETIRE LATENCY, precisely: the number of elapsed CORE CLOCKS between the retirement of the
 * instruction named by this record's IP field and the retirement of the PRIOR instruction. It is
 * an inter-retirement GAP, not a duration spent inside one instruction -- getting that backwards
 * would misread a stall in front of an instruction as the cost of the instruction itself. Source:
 * Intel's TPEBS documentation and Linux `PERF_CAP_PEBS_TIMING_INFO`.
 *
 * ⚠ THESE EXIST BECAUSE THE SIZE FIELD WAS OPEN-CODED AS `(q0 >> 48) & 0xFFFF` IN TWO PLACES.
 * Two copies of a layout are two things that must agree, and this project has already paid for
 * that shape more than once (the 160-vs-176 stride was FOUR copies of one wrong number). One
 * definition, used everywhere.
 *
 * ⚠ RETIRE_LATENCY WAS BEING DISCARDED. The parser read bits 63:48 and bits 15:0 and stepped
 * straight over the 16 bits between them -- so every record captured before already
 * carried this value and nothing looked at it. It needs no enable of its own; it is licensed by
 * IA32_PERF_CAPABILITIES bit 17 (PEBS_TIMING_INFO), which reads 1 on BOTH core types of this part.
 *
 * ⚠ AND IT WAS HIDDEN BY A WRONG NAME ON THAT BIT. The probe called bit 17 "ANYTHREAD_DEPRECATED"
 * and dismissed it as "1 on every modern part" -- so a real capability read as a meaningless
 * always-set bit for a day. That name was itself introduced while FIXING an off-by-one, by
 * reasoning about which neighbour looked plausible. Bit identities come from a source that states
 * them; never from what makes the adjacent bits look sensible.
 *
 * ⚠ AND `format_group` IS 32 BITS WIDE, NOT 16. Only bits 0-3 are currently defined (MEMINFO, GP,
 * XMMS, LBRS), but masking it to 16 would silently drop any future group bit.
 */
#define NXCMD_PEBS_HDR_GROUPS(q0)  ((NXCMD_U32)( (NXCMD_U64)(q0)        & 0xFFFFFFFFull))
#define NXCMD_PEBS_HDR_RETLAT(q0)  ((NXCMD_U32)(((NXCMD_U64)(q0) >> 32) & 0xFFFFull))
#define NXCMD_PEBS_HDR_SIZE(q0)    ((NXCMD_U32)(((NXCMD_U64)(q0) >> 48) & 0xFFFFull))

/*
 * ---- WHICH GROUPS A RECORD CARRIES, AND WHERE THEY SIT --------------------------------------
 *
 * The group bits use the SAME numbering in the record's format_group field as in
 * MSR_PEBS_DATA_CFG, which is what makes a record self-describing: ask for a set of groups, and
 * every record tells you which ones it actually got. Verified against Linux
 * `arch/x86/include/asm/perf_event.h` (PEBS_DATACFG_MEMINFO/GP/XMMS/LBRS).
 */
#define NXCMD_PEBS_GRP_MEM   0x1u   /* data linear address, source, latency, tsx    -- 32 bytes  */
#define NXCMD_PEBS_GRP_GPR   0x2u   /* rflags, rip, 16 GPRs                         -- 144 bytes */
#define NXCMD_PEBS_GRP_XMM   0x4u   /* 16 xmm registers                             -- 256 bytes */
#define NXCMD_PEBS_GRP_LBR   0x8u   /* branch history, count in format_group[31:24] -- 24 each   */

#define NXCMD_PEBS_MEM_BYTES  32u
#define NXCMD_PEBS_XMM_BYTES  256u

/*
 * ---- THE LBR GROUP: BRANCH HISTORY, ATOMIC WITH THE SAMPLE ------------------------------------
 *
 * `lbr read` already exposes the ring, but reading it separately is a second trip the target can
 * execute through. In the record it is the call path AS OF the sampled instruction, by construction.
 *
 * `struct lbr_entry` = { u64 from; u64 to; u64 info; } = 24 bytes -- verified against Linux, not
 * recalled. This machine measures LBR DEPTH 32, so a full group is 768 bytes and a full record is
 * 976: five and a half times the Basic+GPR record. That is why the entry count is REQUESTABLE.
 *
 * ⚠⚠ THE COUNT FIELD ENCODES ENTRIES MINUS ONE. Linux writes it as
 *
 *     pebs_data_cfg |= PEBS_DATACFG_LBRS | ((x86_pmu.lbr_nr - 1) << PEBS_DATACFG_LBR_SHIFT);
 *
 * so asking for 32 entries means writing 31. Writing 32 requests THIRTY-THREE entries' worth of
 * record from a buffer measured for 32 -- the same overrun shape as the 160-vs-176 stride, except
 * the processor does the writing. The `-1` lives in ONE place: NXCMD_PEBS_LBR_CFG below.
 */
#define NXCMD_PEBS_LBR_ENTRY_BYTES  24u    /* from, to, info */
#define NXCMD_PEBS_LBR_MAX_ENTRIES  32u    /* this part's measured LBR depth */
#define NXCMD_PEBS_LBR_BYTES(n)     ((NXCMD_U32)((n) * NXCMD_PEBS_LBR_ENTRY_BYTES))

/* Build the DATA_CFG contribution for `n` entries. The minus-one is HERE and nowhere else. */
#define NXCMD_PEBS_LBR_CFG(n)       (NXCMD_PEBS_GRP_LBR | ((NXCMD_U64)((n) - 1u) << 24))

/*
 * (!) READ THE COUNT BACK OUT OF THE RECORD SIZE, NOT OUT OF THE BITMAP FIELD.
 *
 * The bitmap mirrors DATA_CFG, so it presumably carries the same minus-one encoding -- but
 * "presumably" is how an off-by-one survives. The record states its own TOTAL SIZE, and every other
 * group's size is known, so the LBR count is the remainder divided by 24. That is arithmetic on two
 * facts the hardware reported, with no encoding assumption in it, and it disagrees loudly if the
 * assumption is wrong.
 */
#define NXCMD_PEBS_LBR_COUNT_FROM_SIZE(total, before_lbr) \
	((NXCMD_U32)(((total) > (before_lbr)) ? (((total) - (before_lbr)) / NXCMD_PEBS_LBR_ENTRY_BYTES) : 0u))

/* Field offsets within one LBR entry. */
#define NXCMD_PEBS_LBR_FROM  0u
#define NXCMD_PEBS_LBR_TO    8u
#define NXCMD_PEBS_LBR_INFO  16u

/*
 * ⚠⚠ THE GROUPS APPEAR IN A FIXED ORDER AND AN EARLIER ONE SHIFTS EVERY LATER ONE:
 *
 *     Basic (always, 32) -> MemInfo -> GPR -> XMM -> LBR
 *
 * So enabling MemInfo MOVES THE GPRs from +0x20 to +0x40. Nothing may hardcode a group offset.
 * `NXCMD_PEBS_GROUP_OFF` derives it from the record's own bitmap, which is the same anchoring move
 * the kernel-offset derivations use: count from something the hardware states, not from something
 * we believe. Returns 0 if the group is absent -- callers MUST test presence first.
 */
#define NXCMD_PEBS_GROUP_PRESENT(q0, g) ((NXCMD_PEBS_HDR_GROUPS(q0) & (g)) != 0)

#define NXCMD_PEBS_GROUP_OFF(q0, g)                                                            \
	((NXCMD_U32)(NXCMD_PEBS_BASIC_BYTES +                                                      \
	 (((g) > NXCMD_PEBS_GRP_MEM && NXCMD_PEBS_GROUP_PRESENT(q0, NXCMD_PEBS_GRP_MEM))           \
	      ? NXCMD_PEBS_MEM_BYTES : 0u) +                                                       \
	 (((g) > NXCMD_PEBS_GRP_GPR && NXCMD_PEBS_GROUP_PRESENT(q0, NXCMD_PEBS_GRP_GPR))           \
	      ? NXCMD_PEBS_GPR_BYTES : 0u) +                                                       \
	 (((g) > NXCMD_PEBS_GRP_XMM && NXCMD_PEBS_GROUP_PRESENT(q0, NXCMD_PEBS_GRP_XMM))           \
	      ? NXCMD_PEBS_XMM_BYTES : 0u)))

/* Field offsets WITHIN the MemInfo group, per Linux `struct pebs_meminfo`. */
#define NXCMD_PEBS_MEM_ADDRESS   0u    /* the DATA LINEAR ADDRESS the instruction touched */
#define NXCMD_PEBS_MEM_AUX       8u    /* data source encoding                            */
#define NXCMD_PEBS_MEM_LATENCY   16u   /* access latency -- BITFIELDS, see below          */
#define NXCMD_PEBS_MEM_TSX       24u   /* tsx_tuning                                      */

/*
 * ⚠⚠ THE LATENCY QWORD IS NOT A SCALAR, AND READING IT AS ONE PRODUCES CONFIDENT NONSENSE.
 *
 * First hardware run printed it whole and reported "min 17179869191 / mean 166315755002 cycles".
 * Those are not cycle counts; they are two packed fields being read as one integer. Linux
 * `struct pebs_meminfo` carries this qword as bitfields on parts of this generation:
 *
 *     instr_latency:16, pad:16, cache_latency:16, pad:16
 *
 * So 0x0000400000007 is instr_latency 7 and cache_latency 4 -- and with a threshold of 3, an
 * instr_latency of 7 is exactly what the filter should let through. Read as one number it was
 * 17,179,869,191 "cycles", which is roughly an hour and a half at 3.1 GHz.
 *
 * The lesson is the D3 one again: a field printed under a label it does not match is a stub. It
 * looked like a working feature producing implausible data, when it was a working feature being
 * misread by the reporter.
 */
#define NXCMD_PEBS_MEM_INSTR_LAT(q) ((NXCMD_U32)( (NXCMD_U64)(q)        & 0xFFFFull))
#define NXCMD_PEBS_MEM_CACHE_LAT(q) ((NXCMD_U32)(((NXCMD_U64)(q) >> 32) & 0xFFFFull))

/*
 * What `pebs arm` may ask for. Usermode sends INTENT; the kernel translates to MSR bits and
 * validates. Usermode never hands a raw value to a WRMSR -- IA32_DS_AREA is already a pointer the
 * CPU writes through, and this register decides how much it writes per record.
 *
 * The LBR flag was deliberately absent until the buffer could be sized for it -- a flag accepted
 * and then refused, or accepted and silently ignored, is a stub. It is added HERE, in the same
 * change that raises NXCMD_PEBS_STRIDE_MAX to cover it, which is the condition that was stated.
 *
 * XMM followed on the same condition: it is added here in the change that sizes for its 256 bytes.
 * Why it earns the space on THIS project -- SSE/AVX registers carry CIPHER STATE, and the packers
 * this framework exists to inspect (Themida, VMProtect) use SSE heavily. Seeing xmm0-15 at the
 * sampled instruction is the difference between watching a vectorised routine run and reading the
 * key material it is holding.
 *
 * The LBR ENTRY COUNT rides in bits 15:8 of the same word, not in these flags -- it is a number,
 * not an on/off.
 */
#define NXCMD_PEBS_ARM_FLAG_MEM  0x00000001u
#define NXCMD_PEBS_ARM_FLAG_LBR  0x00000002u
#define NXCMD_PEBS_ARM_FLAG_XMM  0x00000004u
/*
 * Ring selection for PEBS -- same requirement as PT's WantOs and the same self-pollution caveat.
 * (a target's ~70 MB kernel driver is where the interesting behaviour is said to be,
 * so ring-3-only sampling cannot reach the actual target.) Neither bit set keeps the historic
 * default of ring 3 only, so every existing caller is unaffected.
 */
#define NXCMD_PEBS_ARM_FLAG_USR  0x00010000u
#define NXCMD_PEBS_ARM_FLAG_OS   0x00020000u

/*
 * ⚠⚠ THE PMI CR3 FILTER -- REAL SCOPING, AND THE ONLY FLAG HERE THAT CAN BUGCHECK THE MACHINE.
 *
 * PEBS has no hardware CR3 filter. The hardware writes records without asking, so the only moment a
 * record can be judged against an address space is the PMI that follows it -- and obtaining that PMI
 * means programming an APIC LVT to deliver NMI.
 *
 * ⚠⚠ THE FIRST ATTEMPT AT THIS COST FOUR BUGCHECK 0x80s ON, AND THE NMI SOURCE WAS NOT
 * THE CAUSE. That was the standing conclusion for a day -- "PEBS scoping must never introduce an NMI
 * source again" -- and it was wrong. A bisect (A: read the state / B1: test the pointer / B:
 * dereference it) put the fault squarely in the dereference, and reading NxcPebsFree explained why:
 * it freed the DS area and the record buffer and only THEN NULLed the globals pointing at them, so
 * for the window in between it published a pointer to freed memory. A stale pointer passes a null
 * check and kills a dereference -- exactly the B1-survives / B-dies split. The free path now retires
 * before it destroys. The NMI source was an AMPLIFIER of an existing bug, never the bug.
 *
 * Still OPT-IN and OFF by default, because the cost is real even when the correctness is: filtering
 * takes one NMI per record instead of one per buffer-full. Without this flag the driver programs no
 * LVT and generates no NMI at all, and `--pid` scopes nothing (which the arm output states plainly).
 *
 * ⚠ REFUSED WITHOUT A CR3 TO FILTER ON. An LVT armed for a filter with nothing to compare against is
 * all of the cost and none of the capability -- and it is the precise shape that produced an
 * unclaimed NMI: an interrupt source enabled by one condition and claimed under a different one.
 */
#define NXCMD_PEBS_ARM_FLAG_PMIFILTER 0x00040000u

/*
 * ⚠ THE MINIMUM SAMPLE PERIOD WITH FILTERING ON, and the reason it is 100x the unfiltered floor.
 *
 * Filtered mode sets PebsInterruptThreshold one record above the base, which makes every record
 * raise a PMI. At the unfiltered floor of 10000 retired instructions that is ~300k NMIs/sec on each
 * of 24 cores at once. At 1e6 it is ~3k/sec/core -- measurable overhead, bounded, and honest.
 *
 * REFUSED, not clamped: a caller who asked for 10000 and silently got 1000000 would compute rates
 * from the number they asked for rather than the one that ran.
 */
#define NXCMD_PEBS_PMIFILTER_MIN_PERIOD 1000000ull

#define NXCMD_PEBS_ARM_FLAG_ALL  (NXCMD_PEBS_ARM_FLAG_MEM | NXCMD_PEBS_ARM_FLAG_LBR | \
                                  NXCMD_PEBS_ARM_FLAG_XMM | NXCMD_PEBS_ARM_FLAG_USR | \
                                  NXCMD_PEBS_ARM_FLAG_OS  | NXCMD_PEBS_ARM_FLAG_PMIFILTER)

/*
 * `struct pebs_xmm` is `u64 xmm[16*2]` -- 16 registers x 128 bits = 256 bytes, verified against
 * Linux. Two qwords per register, low half first.
 */
#define NXCMD_PEBS_XMM_REGS        16u
#define NXCMD_PEBS_XMM_REG_BYTES   16u

/*
 * The LBR entry count rides in bits 15:8 of the SAME `Flags` word, because the command struct is
 * APPEND-ONLY and every other field on this opcode is taken (TargetModuleId = pid,
 * ReadOffset = period, ReadLength = ldlat threshold, Flags = these bits).
 *
 * ⚠ A `WriteLength` FIELD WAS ALMOST USED HERE AND DOES NOT EXIST. It compiled in my head and
 * nowhere else. Check the struct before reaching for a field name that sounds like it should be
 * there -- this layout is append-only and inventing a field silently targets the wrong bytes.
 *
 * 0 with the LBR flag set means "as many entries as the buffer was sized for".
 */
#define NXCMD_PEBS_ARM_LBR_SHIFT   8u
#define NXCMD_PEBS_ARM_LBR_MASK    0x0000FF00u
#define NXCMD_PEBS_ARM_LBR_GET(f)  ((NXCMD_U32)(((f) & NXCMD_PEBS_ARM_LBR_MASK) >> NXCMD_PEBS_ARM_LBR_SHIFT))
#define NXCMD_PEBS_ARM_LBR_PUT(n)  ((NXCMD_U32)(((n) << NXCMD_PEBS_ARM_LBR_SHIFT) & NXCMD_PEBS_ARM_LBR_MASK))

/*
 * ⚠⚠ THE BUFFER IS SIZED FOR THE LARGEST RECORD THE ARM PATH CAN PRODUCE, NOT THE DEFAULT ONE.
 *
 * The CPU writes records; we only tell it where. `pebs alloc` runs BEFORE `pebs arm`, so at
 * allocation time nobody yet knows whether MemInfo will be requested -- and if the buffer were
 * sized at the 176-byte default and arm then enabled MemInfo, the hardware would write 208-byte
 * records into it.
 *
 * That is EXACTLY the defect already paid for once: a 160-byte assumption against 176-byte
 * hardware records, which landed on a plausible boundary every time and looked correct. The
 * difference is that this one would be the CPU overrunning memory rather than a parser misreading
 * it. So: allocate for the maximum, and set PebsAbsoluteMax at ARM time from the stride actually
 * selected.
 */
/* Everything except LBR -- the sane default for `pebs alloc`, and what a run that never asks for
 * branch history should ever have to reserve. 208 bytes against the 976 the LBR group needs.
 *
 * ⚠ ONE LINE ON PURPOSE. The first version used a backslash line-continuation and was written
 * through a shell heredoc, which ate the backslash and left a literal `\n` in the source -- four
 * compiler errors pointing at the USE SITE in Trace.c rather than at this line. That is the
 * documented heredoc trap; the rule is to use Write/Edit for anything containing escapes, and a
 * macro with no continuation cannot be broken by it at all. */
#define NXCMD_PEBS_STRIDE_NOLBR (NXCMD_PEBS_BASIC_BYTES + NXCMD_PEBS_MEM_BYTES + NXCMD_PEBS_GPR_BYTES)

#define NXCMD_PEBS_STRIDE_MAX  (NXCMD_PEBS_BASIC_BYTES + NXCMD_PEBS_MEM_BYTES + \
                                NXCMD_PEBS_GPR_BYTES + NXCMD_PEBS_XMM_BYTES + \
                                NXCMD_PEBS_LBR_BYTES(NXCMD_PEBS_LBR_MAX_ENTRIES))

/*
 * (!) COMPUTE THE STRIDE FROM THE GROUPS ASKED FOR -- do not reach for STRIDE_MAX.
 *
 * `pebs alloc` sizes each record slot from this, and `pebs arm` refuses anything that needs more.
 * Reserving STRIDE_MAX unconditionally is what made every allocation cost ~23 MB contiguous for a
 * group most runs never request; adding XMM would have taken it past 29 MB. The kernel's
 * NxcPebsStrideFor computes the same number from the DATA_CFG it is about to write -- these two
 * must agree, which is why both are expressed as the same sum in the same order.
 */
#define NXCMD_PEBS_STRIDE_FOR(mem, xmm, lbr_entries)                       \
	((NXCMD_U32)(NXCMD_PEBS_BASIC_BYTES + NXCMD_PEBS_GPR_BYTES +           \
	 ((mem) ? NXCMD_PEBS_MEM_BYTES : 0u) +                                 \
	 ((xmm) ? NXCMD_PEBS_XMM_BYTES : 0u) +                                 \
	 (((lbr_entries) != 0) ? NXCMD_PEBS_LBR_BYTES(lbr_entries) : 0u)))

/*
 * ⚠ THAT IS 976 BYTES, UP FROM 208, AND THE COST IS REAL. At the default 1024 records it is ~1 MB
 * of CONTIGUOUS memory per core, ~24 MB across this machine, allocated whether or not LBR is later
 * requested -- because alloc runs before arm and cannot know.
 *
 * It is sized this way anyway, because the alternative is the CPU writing past a buffer measured
 * for a smaller record. If a core fails to allocate, `pebs alloc` already reports how many
 * succeeded rather than pretending -- and the record count is a parameter, so `pebs alloc 256`
 * cuts it by four.
 */

#define NXCMD_OP_PEBS_ALLOC  64u
#define NXCMD_OP_PEBS_STATUS 65u
#define NXCMD_OP_PEBS_FREE   66u
#define NXCMD_OP_PEBS_ARM    67u
#define NXCMD_OP_PEBS_DISARM 68u
#define NXCMD_OP_PEBS_DRAIN  69u

#pragma pack(push, 1)
typedef struct _NXCMD_PEBS_CPU_STATE
{
	NXCMD_U64 DsAreaVa;        /* the DS management area given to IA32_DS_AREA (stage 2)      */
	NXCMD_U64 DsAreaPa;
	NXCMD_U64 BufferVa;        /* PEBS records land here -- written BY THE CPU                */
	NXCMD_U64 BufferPa;
	NXCMD_U64 BufferBytes;
	NXCMD_U64 ThresholdVa;     /* index reaching this raises the PMI                          */
	NXCMD_U32 CpuNumber;
	NXCMD_U32 Records;         /* how many the buffer holds at the assumed stride             */
	NXCMD_U32 RecordStride;    /* Basic + GPR groups, as REQUESTED. The record's own size      */
	                           /* field is checked against this at drain time, never assumed.  */
	NXCMD_U32 Armed;           /* 0 until stage 2 writes the MSRs on this core                 */

	/*
	 * ---- the TWO enables that between them decide what a record contains ----
	 *
	 * (!) BOTH, BECAUSE ONE COULD NOT NAME A FAILURE. MSR_PEBS_DATA_CFG read back 0x2 on 24/24 cores
	 * -- exactly as requested -- while every record arrived 32 bytes, Basic group only. DATA_CFG says
	 * WHAT a record should hold; IA32_PERFEVTSEL0.Adaptive_Record (bit 34) says to build an adaptive
	 * record at all, and without it DATA_CFG is a correctly-stored value nothing consults. Verifying
	 * one register while a second went unchecked reproduced the original defect one register over.
	 *
	 * (!) EvtSelReadback IS 64-BIT ON PURPOSE. Bit 34 is above 32, and the first attempt to carry it
	 * home used a 32-bit field -- which would have truncated the evidence into the very symptom it
	 * exists to diagnose. The compiler caught that one; the type is the fix.
	 *
	 * Per core, not one global: this is a hybrid part and a feature taking on P cores but not E cores
	 * is a real outcome that a single number would average away.
	 */
	NXCMD_U64 DataCfgReadback; /* MSR_PEBS_DATA_CFG   -- want bit 1  (GPR group)              */
	NXCMD_U64 EvtSelReadback;  /* IA32_PERFEVTSEL0    -- want bit 34 (Adaptive_Record)        */
	/*
	 * MSR_PEBS_LD_LAT_THRESHOLD (0x3F6), read back per core. 0 means the load-latency event is not
	 * in use and INST_RETIRED is counted instead.
	 *
	 * (!) IT IS READ BACK FOR THE SAME REASON DATA_CFG IS. A threshold that did not take shows up
	 * ONLY as an empty buffer -- no error, no status, nothing pointing at the cause. That is exactly
	 * how the missing GPR bit hid, and then how the missing Adaptive_Record bit hid one register
	 * over. Three registers decide what a record contains and how many exist; all three travel home.
	 */
	NXCMD_U64 LdLatReadback;
} NXCMD_PEBS_CPU_STATE;
#pragma pack(pop)

#define NXCMD_OP_SAMPLE_ARM    61u
#define NXCMD_OP_SAMPLE_READ   62u
#define NXCMD_OP_SAMPLE_DISARM 63u

#pragma pack(push, 1)
typedef struct _NXCMD_SAMPLE_ENTRY
{
	NXCMD_U64 LbrFrom;    /* last ring-3 branch SOURCE -- where the target was      */
	NXCMD_U64 LbrTo;      /* and where it went                                     */
	NXCMD_U64 Cr3;        /* masked frame, so a sample attributes to a process      */
	NXCMD_U32 Cpu;
	NXCMD_U32 Reserved0;
} NXCMD_SAMPLE_ENTRY;
#pragma pack(pop)

/*
 * Page-walk decode, DEFINED HERE so both sides read one constant. `Translate.h` ALIASES these
 * rather than restating them -- a restatement is two lists that must agree, and this file has
 * already paid for that shape more than once today.
 */
#define NXCMD_XLAT_PRESENT      0x00000001u
#define NXCMD_XLAT_WRITABLE     0x00000002u
#define NXCMD_XLAT_USER         0x00000004u
#define NXCMD_XLAT_NX           0x00000008u
#define NXCMD_XLAT_ACCESSED     0x00000010u  /* CPU set it on a translation                     */
#define NXCMD_XLAT_DIRTY        0x00000020u  /* CPU set it on a WRITE -- the unpacking signal    */
#define NXCMD_XLAT_LARGE_PAGE   0x00000040u
#define NXCMD_XLAT_GLOBAL       0x00000080u

/* WHY a non-present page is absent. "Not present" alone collapses ordinary paging together with
 * the finding this phase exists to surface (a zero PTE where the loader still lists a mapping). */
#define NXCMD_SW_PRESENT        0u
#define NXCMD_SW_ZERO           1u
#define NXCMD_SW_TRANSITION     2u
#define NXCMD_SW_PROTOTYPE      3u
#define NXCMD_SW_NOT_RESIDENT   4u

#pragma pack(push, 1)
typedef struct _NXCMD_PTE_PAGE
{
	NXCMD_U64 Va;          /* the page this row describes                                    */
	NXCMD_U64 Pfn;         /* physical frame, 0 when not present                             */
	NXCMD_U64 Entry;       /* the raw leaf entry -- kept whole, so a bit we have not decoded  */
	                       /* yet is answerable from a capture already taken                  */
	NXCMD_U32 Flags;       /* NXC_XLAT_* as the walk reported them                           */
	NXCMD_U32 Level;       /* 4 = 4 KB, 3 = 2 MB, 2 = 1 GB                                   */
	NXCMD_U32 SoftState;   /* NXC_SW_* -- WHY a non-present page is absent                    */
	NXCMD_U32 Reserved0;
} NXCMD_PTE_PAGE;
#pragma pack(pop)

/* Why an install or removal refused. Mirrors NXC_HOOK_* in the driver's Hook.h. */
#define NXCMD_HOOK_OK              0u
#define NXCMD_HOOK_BAD_ALIGN       1u   /* (va & 7) > 3: 5 bytes straddle two qwords    */
#define NXCMD_HOOK_OUT_OF_RANGE    2u   /* handler beyond +-2 GB; rel32 cannot reach    */
#define NXCMD_HOOK_NOT_RESIDENT    3u
#define NXCMD_HOOK_DECODE_FAILED   4u
#define NXCMD_HOOK_RELATIVE_INSN   5u   /* a RIP-relative or relative branch was stolen */
#define NXCMD_HOOK_NO_TRAMPOLINE   6u
#define NXCMD_HOOK_VERIFY_FAILED   7u   /* read-back through the ORIGINAL VA disagreed  */
#define NXCMD_HOOK_NO_SLOT         8u
#define NXCMD_HOOK_ALREADY         9u
#define NXCMD_HOOK_FOREIGN_PATCH  10u   /* removal: the qword is no longer what we wrote */
/*
 * ⚠ MIRRORS NXC_HOOK_IS_IDT_HANDLER (Hook.h). The kernel has emitted 11 since the IDT hard block
 * went in; this enum stopped at 10, so the one refusal that is a PERMANENT structural block printed
 * as "REFUSED (11): ?" -- the least informative message in the table for the reason that most needs
 * explaining. The full explanation existed the whole time, in an `if (0)` block twenty lines from
 * the print, unreachable.
 */
#define NXCMD_HOOK_IS_IDT_HANDLER 11u   /* the VA is a live IDT gate -- hard block, never retry */

#pragma pack(push, 1)
typedef struct _NXCMD_HOOK_INFO
{
	NXCMD_U64 TargetVa;
	NXCMD_U64 HandlerVa;
	NXCMD_U64 TrampolineVa;
	NXCMD_U64 AlignedVa;
	NXCMD_U64 OriginalQword;
	NXCMD_U64 PatchedQword;
	NXCMD_U32 StolenBytes;
	NXCMD_U32 Active;
	/*
	 * NXCMD_HOOK_FLAG_* as installed. The kernel has always tracked this per hook -- the hit path
	 * needs it -- but it never crossed the wire, so `hook list` could say WHERE a hook is and not
	 * WHAT IT IS. An exception observer and an LBR sampler on the same VA were indistinguishable
	 * from usermode, which is what made `bp dispatch install` unable to tell "already installed by
	 * me" from "someone else is on that address" and refuse the whole chain over it.
	 */
	NXCMD_U32 InstallFlags;

	/*
	 * ⚠⚠ THE PID FILTER, AND IT IS THE SAME OMISSION AS InstallFlags ABOVE, ONE FIELD LATER.
	 *
	 * The kernel has always tracked this -- the hit path tests it on every call -- but it never
	 * crossed the wire, so `hook list` could say a hook was SCOPED and not say SCOPED TO WHAT. The
	 * scoping was therefore unverifiable from the tool, and `--pid` was taken on trust.
	 *
	 * MEASURED COST,: re-installing an already-installed hook with a different `--pid`
	 * left the OLD filter in place. Every downstream symptom pointed elsewhere -- records arriving
	 * from a process that was not the target read as a broken pid filter in `--follow`, as a
	 * mis-scoped predicate, and as a module-subtraction fault, and several runs were spent on each.
	 * `hook list` was consulted and could not settle it, because the one field that would have was
	 * not printed. A field the kernel knows and does not report is a diagnostic that cannot fire.
	 *
	 * 0 means NOT FILTERED -- every process is recorded -- which is a real state and not "unknown".
	 * Appended, so every field above keeps its offset and an older reader still parses them.
	 */
	NXCMD_U32 FilterPid;
} NXCMD_HOOK_INFO;
#pragma pack(pop)

/*
 * Both qwords are reported so usermode can diff them WITHOUT re-reading the target. A `hook list`
 * whose PatchedQword no longer matches what is live at AlignedVa is the signal that something else
 * patched over us, and it is the same check the driver makes before it will restore anything.
 *
 * The size assert lives with the others at the end of this file, using NXCMD_ASSERT -- C_ASSERT is
 * not available in the DXE's build environment and using it here broke that compile.
 */

#pragma pack(push, 1)
typedef struct _NXCMD_TRACE_CPU_STATE
{
	NXCMD_U64 ToPaPa;
	NXCMD_U64 BufferPa;
	/*
	 * ⚠ THE ONLY FIELD THAT PROVES A TRACE ACTUALLY HAPPENED. Everything else says the hardware was
	 * CONFIGURED; this says it WROTE. Without it, a trace that armed cleanly and recorded nothing is
	 * indistinguishable from one that worked -- and "armed" was all stage 2 could originally report.
	 *
	 * Taken from IA32_RTIT_OUTPUT_MASK_PTRS bits 63:32, read ON the core it belongs to.
	 *
	 * ⚠⚠ IT IS A POSITION, NOT A TOTAL, AND THE DIFFERENCE IS NOT PEDANTRY. This is the hardware's
	 * write pointer WITHIN THE CURRENT OUTPUT REGION. The ToPA here is CIRCULAR by deliberate
	 * choice -- the interesting moment in a capture is almost always the most recent one -- so when
	 * the region fills, the pointer returns to 0 and the trace keeps writing over its own oldest
	 * packets.
	 *
	 * This field was originally documented as "bytes the CPU has written" and a harness check
	 * asserted it only ever increased. Hardware disproved that: a sample of 148,848
	 * was followed by 25,376, because the writer had passed 262,144 and come round. The mechanism
	 * was correct and the description was not. Once Wrapped is set, the TOTAL written is
	 * `BufferSize * WrapPmi + OutputOffset`.
	 *
	 * ⚠ THAT MULTIPLIER USED TO BE DOCUMENTED HERE AS "NOT recoverable from these registers -- Intel
	 * PT has no wrap counter", and it was wrong (corrected). No REGISTER counts wraps,
	 * which is what had been checked. The ToPA entry's INT bit makes the CPU raise an interrupt at
	 * every region fill, so counting them is exact -- see WrapPmi below. Without NXCMD_TRACE_ARM_PMI
	 * the multiplier really is unknown and the total is at-least-BufferSize; with it, the total is
	 * exact. Two different states, and the old text described only one of them as if it were both.
	 */
	NXCMD_U64 OutputOffset;
	NXCMD_U64 RtitStatus;   /* IA32_RTIT_STATUS: Error and Stopped are the silent killers */
	NXCMD_U32 CpuNumber;
	NXCMD_U32 BufferSize;
	NXCMD_U32 Armed;
	/*
	 * Non-zero once the region has been filled at least once, so OutputOffset can no longer be read
	 * as a total.
	 *
	 * ⚠ DETECTED STRUCTURALLY, NOT BY WATCHING FOR THE POINTER TO GO BACKWARDS. A decrease between
	 * two samples proves a wrap, but its absence proves nothing -- two wraps between samples, or one
	 * that lands past where it started, both look like ordinary progress. The reliable signal is the
	 * BUFFER ITSELF: it is zeroed at alloc, so a non-zero byte near the END of the region means the
	 * writer reached that point, which it can only do by filling the region. That answer does not
	 * depend on how often anyone happened to look.
	 */
	NXCMD_U32 Wrapped;

	/*
	 * ⚠ TWO COUNTS OF THE SAME EVENT, BY MECHANISMS THAT SHARE NO CODE, REPORTED SIDE BY SIDE.
	 *
	 * Generation counts pointer reversals noticed at SAMPLE time -- cheap, always on, and a LOWER
	 * BOUND, because two wraps between consecutive samples look like one and a wrap that lands past
	 * where it started looks like none.
	 *
	 * WrapPmi counts ToPA region-fill INTERRUPTS -- exact, every fill, independent of who was
	 * looking, and available only when armed with NXCMD_TRACE_ARM_PMI.
	 *
	 * WrapPmi >= Generation is expected, and the GAP IS THE POINT: it is the sampling undercount
	 * measured rather than argued about. Equality on a slow trace and a large gap on a fast one is
	 * the mechanism working. WrapPmi < Generation would be a genuine contradiction and worth
	 * chasing -- a tool disagreeing with itself is the loudest signal there is
	 * (an earlier finding).
	 */
	NXCMD_U32 Generation;
	NXCMD_U32 WrapPmi;

	/*
	 * What was actually APPLIED to this core, plus why PMI mode is or is not live on it. Both are
	 * needed: without ArmFlags a WrapPmi of 0 cannot be told from a region that never filled, and
	 * without PmiWhy a core that refused PMI mode cannot be told from one never asked.
	 */
	NXCMD_U32 ArmFlags;      /* NXCMD_TRACE_ARM_*     */
	NXCMD_U32 PmiWhy;        /* NXCMD_TRACE_PMIWHY_*  */
	NXCMD_U64 LvtPcSaved;    /* the LVT PC entry displaced on this core, 0 if none was */
	/*
	 * IA32_RTIT_CTL AS IT READ BACK on this core when it armed (D117) -- not what was requested,
	 * what the hardware kept. It is the ground truth for WHICH PACKETS THE TRACE CONTAINS: TSCEn
	 * (10), MTCEn (9) + MTCFreq (17:14), CYCEn (1) + CycThresh (22:19), PSBFreq (27:24), PTWEn (12).
	 *
	 * (!) PER CORE BECAUSE THIS IS A HYBRID PART. Timing support is enumerated per core, so "which
	 * packets is this capture carrying" has no single answer for the machine -- and a decoder run
	 * against the wrong assumption does not report a mismatch, it reports corrupt data.
	 */
	NXCMD_U64 RtitCtl;
} NXCMD_TRACE_CPU_STATE;
#pragma pack(pop)

/*
 * ============================================================================================
 * ARM-TIME OPTIONS -- DEFINED HERE, IN THE SHARED HEADER, ON PURPOSE.
 *
 * The kernel's Trace.h ALIASES these rather than restating them. A restated constant is two lists
 * that must agree, which is the single most productive defect shape in this project's history --
 * most recently a hook flag mask that silently dropped three flags added beside it and made three
 * hardware phases prove nothing. An alias cannot drift.
 * ============================================================================================
 */

/*
 * ============================================================================================
 * PT ADDRESS-RANGE FILTERING -- scope a trace to a ROUTINE instead of a process.
 * ============================================================================================
 *
 * A CR3 filter scopes PT to a process, which on this machine measured ~1.9 GB/s and refilled a
 * 256 KB region every ~135 us. Whatever the buffer size, a whole-process trace of a busy target
 * keeps only the last fraction of a millisecond. Address ranges scope it to code you name.
 *
 * Each range occupies one IA32_RTIT_ADDRn_A/B MSR pair, and its role lives in a 4-bit ADDRn_CFG
 * field of IA32_RTIT_CTL starting at bit 32 (bit = 32 + 4n):
 *
 *   FILTER (CFG 1)  trace ONLY while RIP is inside [Start..End]
 *   STOP   (CFG 2)  stop tracing entirely if control branches INTO [Start..End]
 *
 * (!) HOW MANY RANGES EXIST IS PER-CORE AND MEASURED, NEVER ASSUMED. CPUID.(14H,1):EAX[2:0]
 * reports 2 on this part; the arm path re-checks it ON EACH CORE because this CPU is hybrid and a
 * count that differed between P and E cores would make one filter mean two things.
 *
 * (!) A FILTERED TRACE IS NOT AN EMPTY ONE, and a test that assumes otherwise will misread it. The
 * SDM is explicit that with FilterEn clear the CONTROL-FLOW packets (TNT, TIP) stop, while PIP, MTC
 * and PSB may still be emitted. So 'outside the range' means far fewer bytes, not zero -- and
 * asserting POSITION == 0 would report a working filter as a dead trace.
 */
#define NXCMD_PT_RANGE_FILTER  1u
#define NXCMD_PT_RANGE_STOP    2u
#define NXCMD_PT_RANGE_MAX     4u   /* architectural ceiling; the CORE's own count still governs */

#pragma pack(push, 1)
typedef struct _NXCMD_PT_RANGE
{
	NXCMD_U64 Start;      /* inclusive base  -> IA32_RTIT_ADDRn_A */
	NXCMD_U64 End;        /* inclusive limit -> IA32_RTIT_ADDRn_B */
	NXCMD_U32 Cfg;        /* NXCMD_PT_RANGE_FILTER | _STOP        */
	NXCMD_U32 Reserved0;
} NXCMD_PT_RANGE;
#pragma pack(pop)

/*
 * ============================================================================================
 * PT TIMING PACKETS AND PTWRITE (D117) -- what turns a control-flow trace into a TIMELINE.
 * ============================================================================================
 *
 * Branch tracing answers WHERE execution went. It never answers WHEN, or HOW LONG anything took,
 * or what a VALUE in the program was. These four controls do:
 *
 *   TSC    a timestamp at PSB boundaries -- coarse wall-clock anchors, nearly free
 *   MTC    Mini Time Counter ticks at a divisor of the always-running crystal, so the time
 *          between anchors is BOUNDED instead of unknown
 *   CYC    cycle counts between packets -- the finest resolution PT offers, and the costliest
 *   PTW    the PTWRITE instruction puts its OPERAND into the trace: a value from the program
 *          itself, inline with the control flow that produced it
 *
 * (!)(!) THE THREE 4-BIT FIELDS ARE NOT FREE CHOICES. MTCFreq, CycThresh and PSBFreq each have 16
 * possible encodings and every part implements a SUBSET, enumerated as bitmaps in
 * CPUID.(14H,1) -- EAX[31:16], EBX[15:0] and EBX[31:16] respectively. Writing an unimplemented
 * encoding is a #GP on the WRMSR, and in a manually mapped image with no SEH that is a BUGCHECK
 * rather than an error return. The kernel checks every value against the bitmap OF THE CORE IT IS
 * RUNNING ON and refuses anything absent; nothing here is ever written on the caller's say-so.
 *
 * (!) 0xFF MEANS NOT REQUESTED. 0 is a MEANINGFUL encoding in all three fields, so it cannot double
 * as the unset sentinel -- that exact confusion cost a hardware run on `trace alloc 0` earlier the
 * same day, where a valid value serving as "unset" silently substituted a default.
 */
#define NXCMD_PT_TIMING_UNSET  0xFFu

#pragma pack(push, 1)
typedef struct _NXCMD_PT_TIMING
{
	NXCMD_U32 WantTsc;      /* TSC packets. No CPUID gate -- available wherever PT is.        */
	NXCMD_U32 MtcFreq;      /* MTCEn + MTCFreq encoding, or NXCMD_PT_TIMING_UNSET             */
	NXCMD_U32 CycThresh;    /* CYCEn + CycThresh encoding, or NXCMD_PT_TIMING_UNSET           */
	NXCMD_U32 PsbFreq;      /* PSBFreq encoding, or NXCMD_PT_TIMING_UNSET                     */
	NXCMD_U32 WantPtw;      /* PTWEn -- PTWRITE emits its operand into the trace              */
	NXCMD_U32 WantFupOnPtw; /* FUPonPTW -- pair each PTWRITE payload with the IP that wrote it */
	/*
	 * DisTNT (RTIT_CTL[55]) -- STOP GENERATING TNT PACKETS.
	 *
	 * Not a timing field, but it belongs to this struct because it shares the CPUID.(14H,0) probe
	 * and the same all-or-nothing fail-closed gate as the rest. Gated on EBX[8].
	 *
	 * TNT carries taken/not-taken for conditional branches and is the BULK of trace volume.
	 * Suppressing it keeps every packet that carries an ADDRESS -- TIP, FUP, PSB, PIP, and so calls,
	 * returns and indirect branches -- and drops the conditional detail. The trade is RESOLUTION for
	 * DURATION: the same ToPA buffer covers far more execution of a long-running target.
	 */
	NXCMD_U32 WantDisTnt;

	/*
	 * ---- WHICH RINGS THE TRACE RECORDS (D120) ----------------------------------------------
	 *
	 * A target may load a ~70 MB KERNEL DRIVER and that is reportedly where the
	 * interesting behaviour is. A usermode-only tracer cannot see it, so ring 0 is a requirement,
	 * not a nicety. Before this, PT set RTIT_CTL.USER unconditionally and never .OS.
	 *
	 * WantUser defaults to 1 and WantOs to 0, preserving the historic behaviour for every existing
	 * caller. Both may be set -- ring 0 AND ring 3 in one trace, which is what following a
	 * usermode module into its own driver actually needs.
	 *
	 * ⚠ RING 0 IS SELF-POLLUTING and needs an IP RANGE FILTER to be usable. CR3 filtering cannot
	 * scope kernel code -- the kernel is mapped into every address space -- so `--kernel` without
	 * `--filter <driver_base>-<driver_end>` traces the entire kernel and fills the buffer almost
	 * immediately.
	 */
	NXCMD_U32 WantUser;
	NXCMD_U32 WantOs;
} NXCMD_PT_TIMING;
#pragma pack(pop)

#define NXCMD_TRACE_ARM_STOP   0x00000001u  /* ToPA STOP: halt at the fill, do NOT wrap        */
#define NXCMD_TRACE_ARM_PMI    0x00000002u  /* ToPA INT: interrupt at every fill, and count it */

#define NXCMD_TRACE_PMIWHY_NOT_REQUESTED   0u
#define NXCMD_TRACE_PMIWHY_LIVE            1u
#define NXCMD_TRACE_PMIWHY_NO_X2APIC       2u
#define NXCMD_TRACE_PMIWHY_NO_CALLBACK     3u
#define NXCMD_TRACE_PMIWHY_LVT_READBACK    4u

/*
 * Probe every logical processor's tracing capabilities into OutBuffer as NXCMD_CPU_TRACE_CAPS.
 *
 * READ-ONLY: CPUID and gated RDMSR, no WRMSR anywhere. Reported PER LOGICAL PROCESSOR because this
 * machine is hybrid -- P-cores and E-cores differ in PMU features and LBR DEPTH, so one system-wide
 * answer would just be whichever core the probing thread happened to land on.
 */
#define NXCMD_OP_CPU_PROBE 18u

/* NXCMD_CPU_TRACE_CAPS::Flags */
#define NXCMD_CPU_HAS_PT          0x00000001u  /* CPUID.(07H,0):EBX.INTEL_PT[25]        */
/*
 * ⚠ HAS_LBR MEANS "SOME LBR", NOT "THE LEGACY MSRs ARE THERE" (corrected, D23). It was
 * derived from IA32_PERF_CAPABILITIES.LBR_FMT != 0 and read as licence to touch 0x1C9/0x680/0x6C0 --
 * but an architectural-LBR part reports a format value while the legacy MSRs may not exist, and an
 * RDMSR of an absent MSR is a #GP, which without SEH is a bugcheck rather than a failed probe.
 * NXCMD_CPU_LBR_LEGACY_OK below is the flag that actually licenses those reads.
 */
#define NXCMD_CPU_HAS_LBR         0x00000002u  /* SOME LBR exists -- see the warning above */
#define NXCMD_CPU_HAS_BTS         0x00000004u  /* CPUID.01H:EDX.DS[21] and not disabled  */
#define NXCMD_CPU_HAS_ARCH_LBR    0x00000008u  /* CPUID.(1CH) architectural LBR          */
#define NXCMD_CPU_HAS_PEBS        0x00000010u  /* PEBS present in PERF_CAPABILITIES      */
#define NXCMD_CPU_PT_TOPA         0x00000020u  /* PT supports ToPA output                */
#define NXCMD_CPU_PT_MULTI_TOPA   0x00000040u  /* ToPA with multiple output regions      */
#define NXCMD_CPU_PT_CR3_FILTER   0x00000080u  /* PT can filter by CR3                   */
#define NXCMD_CPU_IS_HYBRID_CORE  0x00000100u  /* CPUID.1AH reported a core type         */
#define NXCMD_CPU_CORE_IS_P       0x00000200u  /* core type 0x40 = Core (P); else Atom (E) */
#define NXCMD_CPU_PT_IN_USE       0x00000400u  /* RTIT_CTL.TraceEn already set -- CONTENDED */
/*
 * CPUID.(14H,0):EBX[2] -- IP filtering and TraceStop. Added.
 *
 * PT is armed with a CR3 filter today, which scopes a trace to a PROCESS. This bit gates scoping it
 * to ADDRESS RANGES instead -- tracing one routine rather than everything a process executes. On
 * this machine an unfiltered trace measured ~1.9 GB/s and refilled a 256 KB region ~7,400 times a
 * second, so the difference is not a refinement; it is whether a capture is readable at all.
 */
#define NXCMD_CPU_PT_IP_FILTER    0x00010000u  /* PT can filter by address range + TraceStop */
/*
 * (!) THIS WAS 0x800 FOR ONE BUILD AND COLLIDED WITH NXCMD_CPU_LBR_LEGACY_OK BELOW.
 *
 * I added it by counting up from PT_IN_USE (0x400) without reading past the comment block that
 * separates the PT flags from the LBR ones -- and 0x800 was already taken on the far side of it.
 * IP filtering is present on all 24 cores here, so the legacy-LBR flag read SET on all 24, and
 * cpuprobe printed `legacy MSRs OK : 24` under its own text saying that number MUST be 0.
 *
 * (!) THE SELF-DECLARED INVARIANT IS WHAT CAUGHT IT. Nothing failed, nothing crashed; a line that
 * states what it must equal disagreed with itself in front of a reader. Only the display consumed
 * the flag, so this boot was never at risk -- but LBR_LEGACY_OK exists to LICENSE reading
 * 0x1C9/0x680/0x6C0, which #GP on an architectural-LBR part with no SEH to catch it. A collision
 * there is a bugcheck waiting for the first caller that trusts it.
 *
 * The assert below now makes the whole class a BUILD failure instead of a reading.
 */
/*
 * ⚠ THE ONLY FLAG THAT LICENSES A LEGACY LBR MSR READ. Set when arch LBR is ABSENT and LBR_FMT is a
 * KNOWN legacy encoding 1-7 (Linux's LBR_FORMAT_MAX_KNOWN is 0x07). Deliberately fail-closed: an
 * unrecognised format reads nothing rather than guessing, because the cost of guessing wrong is a
 * #GP with no SEH to catch it. This also means we never have to settle what LBR_FMT reports on an
 * architectural part -- the answer stops mattering. (D23)
 */
#define NXCMD_CPU_LBR_LEGACY_OK   0x00000800u
#define NXCMD_CPU_LBR_CPL_FILTER  0x00001000u  /* CPUID.1CH:EBX[0] -- IA32_LBR_CTL[2:1] usable   */
#define NXCMD_CPU_LBR_BR_FILTER   0x00002000u  /* CPUID.1CH:EBX[1] -- IA32_LBR_CTL[22:16] usable */
#define NXCMD_CPU_LBR_CALL_STACK  0x00004000u  /* CPUID.1CH:EBX[2] -- IA32_LBR_CTL[3] usable     */
#define NXCMD_CPU_LBR_LIP         0x00008000u  /* CPUID.1CH:EAX[31] -- IPs are LIP, not effective */

#pragma pack(push, 1)
typedef struct _NXCMD_CPU_TRACE_CAPS
{
	NXCMD_U32 CpuNumber;
	NXCMD_U32 Flags;          /* NXCMD_CPU_*                                            */
	NXCMD_U32 CoreType;       /* CPUID.1AH:EAX[31:24]; 0x40 = P-core, 0x20 = E-core     */
	NXCMD_U32 LbrDepth;       /* entries; 0 when unknown or absent                      */
	NXCMD_U64 PerfCaps;       /* IA32_PERF_CAPABILITIES raw, 0 if unreadable            */
	NXCMD_U64 RtitCtl;        /* IA32_RTIT_CTL raw, 0 if PT absent                      */
	/*
	 * ⚠ RAW CPUID.1CH WORDS, KEPT WHOLE. The probe used to record only EAX, so the depth survived
	 * and every capability that decides HOW to arm was thrown away -- CPL filtering, branch-type
	 * filtering, call-stack mode, and whether INFO carries mispredict/cycles/branch-type. Keeping
	 * the raw words means a later question about a bit we have not decoded yet is answerable from
	 * a capture already taken, instead of needing another boot. (D23)
	 */
	NXCMD_U32 LbrCpuidEbx;    /* CPUID.1CH:EBX -- filtering/call-stack support, 0 if no arch LBR */
	NXCMD_U32 LbrCpuidEcx;    /* CPUID.1CH:ECX -- what IA32_LBR_x_INFO carries                   */
	/*
	 * CPUID.(14H,1):EAX[2:0] -- how many IA32_RTIT_ADDRn_A/B range pairs this core has, 0 if none.
	 *
	 * ⚠ A COUNT, NOT A FLAG, and the distinction matters before anything uses it. NXCMD_CPU_PT_IP_FILTER
	 * says the silicon can filter by address; this says how many ranges a capture may actually install.
	 * Code that assumed 4 on a part offering 2 would filter on half of what it was handed and report
	 * success -- the shape this project keeps finding, so the number travels from the start.
	 */
	NXCMD_U32 PtAddrRanges;
	NXCMD_U32 Reserved0;
} NXCMD_CPU_TRACE_CAPS;
#pragma pack(pop)

/*
 * Suspend (14) / resume (15) a target, and list what is frozen (16). TargetModuleId = pid;
 * for THAW, pid 0 means EVERY frozen process.
 *
 * ⚠ REFUSALS ARE THE FEATURE. Suspending Idle, System, a protected process or THE CALLER does not
 * fail -- it succeeds and hangs the machine, reporting nothing. The caller's own PID is the one that
 * actually gets mistyped, and PsSuspendProcess would stop the very thread servicing this command.
 */
#define NXCMD_OP_FREEZE      14u
#define NXCMD_OP_THAW        15u
#define NXCMD_OP_FREEZE_LIST 16u

/*
 * Read a process's memory with the target FROZEN for the duration (17).
 * Same fields as NXCMD_OP_READ_PROC.
 *
 * A dump of a running target is not a consistent snapshot: the first and last pages read are
 * separated by milliseconds of the target's own execution, so a structure spanning them can be
 * captured half-updated -- a pointer already advanced beside the buffer it used to point at.
 *
 * ⚠ FREEZE, READ AND THAW HAPPEN INSIDE THIS ONE COMMAND, on purpose. A caller doing it in three
 * round trips leaves the target suspended forever if it dies in between, and nothing else remembers
 * to undo it. Folding them together means the dangerous case -- a freeze whose thaw depends on a
 * later round trip surviving -- cannot arise. The thaw runs even when the read fails.
 */
#define NXCMD_OP_READ_ATOMIC 17u

/*
 * List the capture watch table into OutBuffer as NXCMD_CAPTURE_ENTRY records (12), and release
 * entries (13). For CLEAR, TargetName selects one entry; an EMPTY TargetName clears ALL.
 *
 * ⚠ CLEAR RELEASES THE ARENA BUFFER, not just the slot. Capture.c calls a permanent tenant in the
 * shared 16 MB arena "a map failing much later for no visible reason" -- so a clear that freed only
 * the slot would be a leak wearing the name of a cleanup.
 *
 * A capture IN FLIGHT is refused rather than waited for, and counted separately in ModuleSize so the
 * caller can simply re-run. Waiting is not available: the notify holds no lock while it copies.
 */
#define NXCMD_OP_CAPTURE_LIST  12u
#define NXCMD_OP_CAPTURE_CLEAR 13u

/* Watch-slot states, mirrored from Capture.c so PlatformCtl can name them. */
#define NXCMD_WATCH_FREE       0u
#define NXCMD_WATCH_ARMED      1u
#define NXCMD_WATCH_CAPTURING  2u
#define NXCMD_WATCH_CAPTURED   3u

#pragma pack(push, 1)
typedef struct _NXCMD_CAPTURE_ENTRY
{
	NXCMD_U64 PristineBase;   /* arena buffer, 0 until captured        */
	NXCMD_U64 LiveBase;       /* where the image was loaded            */
	NXCMD_U32 PristineSize;
	NXCMD_U32 State;          /* NXCMD_WATCH_*                         */
	NXCMD_U8  Name[64];
} NXCMD_CAPTURE_ENTRY;
#pragma pack(pop)

/*
 * Enumerate processes by sweeping the PID space. OutBuffer receives NXCMD_PROCESS_ENTRY records.
 *
 * The kernel half of the hidden-process detector. It asks the CID table (via
 * PsLookupProcessByProcessId), NOT the ActiveProcessLinks list that every usermode enumeration
 * eventually walks -- so a process unlinked from that list is still found here. The difference
 * between this and a usermode snapshot is the detection; PlatformCtl does the subtraction.
 */
#define NXCMD_OP_PROCS 11u

/*
 * One process. Fields chosen so every one comes from an EXPORTED accessor -- no EPROCESS offset is
 * pinned anywhere in this path.
 */
#pragma pack(push, 1)
typedef struct _NXCMD_PROCESS_ENTRY
{
	NXCMD_U32 Pid;
	NXCMD_U32 ParentPid;
	NXCMD_U32 SessionId;
	NXCMD_U32 Flags;
	NXCMD_U64 CreateTime;   /* raw KeQuerySystemTime units; 0 if unavailable */
	NXCMD_U8  Name[16];     /* EPROCESS.ImageFileName: 15 chars + NUL, TRUNCATED BY WINDOWS itself */
} NXCMD_PROCESS_ENTRY;
#pragma pack(pop)

/*
 * One physical RAM range, as returned by NXCMD_OP_PHYS_RANGES.
 *
 * DECLARED HERE, not in the driver's Regions.h, and that is deliberate. NXC_REGION and
 * NXC_MODULE_ENTRY live beside their implementation, which pulls in ntddk, so PlatformCtl has to
 * MIRROR them and pin the layout with a size assert -- two declarations that can drift, held
 * together only by a check someone has to remember to keep correct.
 *
 * This struct needs no kernel type at all, so both sides include the SAME declaration and drift is
 * impossible rather than merely detected. Any future enumeration struct with no kernel dependency
 * belongs here for the same reason.
 */
#pragma pack(push, 1)
typedef struct _NXCMD_PHYS_RANGE
{
	NXCMD_U64 BaseAddress;
	NXCMD_U64 NumberOfBytes;
} NXCMD_PHYS_RANGE;
#pragma pack(pop)

/*
 * NXCMD_OP_READ flag: read the PRISTINE captured copy instead of the live image.
 *
 * The distinction is the entire point of capturing at all. A packed or self-decrypting module is two
 * different things at two different times -- what the loader mapped, and what it turned itself into.
 * Live gives the second; the on-disk file gives NEITHER, because relocations have been applied.
 * Diffing pristine against live is what shows precisely what a module did to itself.
 *
 * Fails with STATUS_NOT_FOUND rather than silently falling back to live: a caller asking for
 * pristine and quietly receiving self-modified bytes would draw exactly the wrong conclusion, and
 * "the capture never happened" is a fact worth surfacing rather than papering over.
 *
 * (v1 had this backwards -- it preferred pristine and used a FORCE_LIVE flag to opt out, so a caller
 * who wanted the live image and whose capture had silently succeeded got the wrong one by default.)
 */
#define NXCMD_READ_FLAG_PRISTINE 0x00000001u

/*
 * Opcodes at or above this are MODULE-OWNED, claimed via NEXUS_HOST_API::RegisterCommand.
 *
 * A split rather than a shared space so a module cannot shadow a Core opcode. That is not tidiness:
 * a module able to claim NXCMD_OP_UNMAP could intercept and refuse its own teardown, turning a
 * recoverable refusal into a module that needs a reboot to remove.
 *
 * The gap below it is deliberate headroom -- Core can add opcodes for years without colliding with
 * anything a module has already shipped against.
 */
#define NXCMD_OP_MODULE_FIRST 0x1000u

/* Result codes, deliberately distinct from NTSTATUS so a bare 0 cannot read as success. */
#define NXCMD_RESULT_PENDING     0u   /* written by the caller; NexusCore overwrites it        */
#define NXCMD_RESULT_OK          1u
#define NXCMD_RESULT_BAD_MAGIC   2u
#define NXCMD_RESULT_BAD_ABI     3u
#define NXCMD_RESULT_BAD_OP      4u
#define NXCMD_RESULT_WRONG_IRQL  5u   /* not PASSIVE: cannot touch the caller's buffer         */
#define NXCMD_RESULT_COPY_FAILED 6u   /* MmCopyVirtualMemory refused the user buffer           */
#define NXCMD_RESULT_REFUSED     7u   /* the mapper rejected the image; see NtStatus           */
#define NXCMD_RESULT_NO_ARENA    8u   /* arena reservation failed at boot                      */
#define NXCMD_RESULT_BUSY        9u   /* another command was in flight; reentry is refused     */
/*
 * The DXE reached the hook but NexusCore never published a handler (boot block absent, or
 * CommandHandler still 0 because DriverEntry did not get that far).
 *
 * ⚠ SPLIT OUT OF NO_ARENA. The DXE reported this case as NO_ARENA, so a driver that
 * never ran and a driver whose 16 MB reservation failed produced the SAME code -- and they need
 * opposite investigations: one points at the driver or the boot block ABI, the other at firmware
 * memory. Diagnosed a live failure by elimination (DiagCallerPid == 0 proved the handler had not
 * run) that the result code should simply have said.
 */
#define NXCMD_RESULT_NO_HANDLER 10u

/*
 * The MODULE refused teardown, or did not drain. It is still mapped, running and intact.
 *
 * ⚠ SPLIT OUT OF NXCMD_RESULT_BUSY, before the overload could mislead anyone. Unmap first
 * reported a refusal as BUSY, whose documented meaning is "another command was in flight" -- a
 * transient worth retrying immediately. A module refusal is a different fact with a different
 * response: a module holding a callback Windows cannot unregister will answer this forever, and
 * retrying just calls Prepare again.
 *
 * Same reasoning that split NO_HANDLER out of NO_ARENA above. Two conditions sharing one code send
 * the reader to the wrong investigation, and the report is the only thing they have.
 */
#define NXCMD_RESULT_MODULE_BUSY 11u

/*
 * The image mapped correctly and its OWN DriverEntry returned failure. IT IS RESIDENT.
 *
 * ⚠ SPLIT OUT OF NXCMD_RESULT_REFUSED, after it cost exactly the confusion it prevents.
 * The two need opposite responses:
 *
 *   REFUSED       the mapper rejected the image. Nothing resident, nothing to clean up, fix the file.
 *   ENTRY_FAILED  the module is MAPPED AND RESIDENT, holding a slot and arena, and must be torn down
 *                 with `unmap`. It is left resident deliberately -- it may have registered callbacks
 *                 before failing, and freeing underneath that is the v1 bug the teardown contract
 *                 exists to prevent.
 *
 * Measured: a stale NexusTestModule refused the host ABI from inside its own entry. The report said
 * REFUSED and withheld the module id, so the slot was consumed and the caller had no handle to
 * release it. ModuleId is now populated on this path precisely so the cleanup is possible.
 *
 * Third instance of this split (NO_HANDLER out of NO_ARENA, MODULE_BUSY out of BUSY). The recurring
 * lesson: when one code covers two states whose correct NEXT ACTION differs, it is the wrong code.
 */
#define NXCMD_RESULT_ENTRY_FAILED 12u

#pragma pack(push, 1)

/**
 * One command. Written by PlatformCtl, read and answered in place by NexusCore.
 *
 * ⚠ ImageBuffer IS A USERMODE POINTER and must be treated as hostile: the caller can free or
 * re-protect it concurrently. NexusCore copies it with MmCopyVirtualMemory, which returns a status
 * rather than raising -- the only safe option without SEH.
 */
typedef struct _NEXUS_COMMAND
{
	NXCMD_U64 Magic;        /* NEXUS_CMD_MAGIC                                          */
	NXCMD_U32 Abi;          /* NEXUS_CMD_ABI                                            */
	NXCMD_U32 StructSize;   /* sizeof(*this) as the CALLER saw it                       */

	NXCMD_U32 Opcode;       /* NXCMD_OP_*                                               */
	/*
	 * CALLER-WRITTEN FLAGS, per-opcode. Was "reserved; must be 0 in ABI 1" and that comment went
	 * stale the moment NXCMD_READ_FLAG_PRISTINE started using it -- corrected rather than
	 * left to mislead.
	 *
	 * ⚠ FLAGS ONLY. This field takes BITS, never a count, an id or an address. Smuggling a value
	 * through it is recorded as a REJECTED alternative on TargetModuleId below, and the reason
	 * generalises: the name would mislead every future reader. When an opcode needs a number, it uses
	 * a field whose name says what the number is, or derives it from something already present.
	 */
	NXCMD_U32 Flags;

	NXCMD_U64 ImageBuffer;  /* usermode VA of the raw .sys bytes -- HOSTILE, copy safely */
	NXCMD_U32 ImageSize;    /* their length                                             */

	/*
	 * ---- ABI 2: written by NEXUSCORE, diagnostic ----
	 *
	 * The process id the handler OBSERVED itself running in. Added after the first live `map`
	 * returned COPY_FAILED / 0xC0000005 with two possible causes that produce an identical symptom:
	 * a bad probe on our side, or the runtime-service call not executing in the caller's process
	 * context (in which case a usermode VA from PlatformCtl means nothing where we read it).
	 *
	 * PlatformCtl compares this against its OWN GetCurrentProcessId(). Equal means context is fine
	 * and the fault was ours; different names the context switch outright. Without it both look the
	 * same from usermode and each guess costs a reboot to test.
	 */
	NXCMD_U32 DiagCallerPid;

	/* ---- written by NexusCore ---- */

	NXCMD_U32 Result;       /* NXCMD_RESULT_*                                           */
	/*
	 * MAP: handle for a later unmap, valid only when Result == OK.
	 *
	 * ⚠ NXCMD_OP_CALLS_READ REUSES IT for the count of hits REJECTED BY THE PID FILTER. Pinned here
	 * beside the field, exactly as BytesRead's bytes-vs-count split is, because the alternative is a
	 * reader inferring it. The field is an OUTPUT, cleared on entry, and CALLS_READ has no map
	 * handle to report -- so nothing is displaced.
	 *
	 * It exists because a scoped hook and a dead hook produce the SAME "0 records" otherwise, and
	 * they call for opposite next actions.
	 */
	NXCMD_U32 ModuleId;
	NXCMD_U64 NtStatus;     /* the mapper's own status, so a refusal says WHICH refusal  */

	/*
	 * ---- ABI 3: written by NEXUSCORE, diagnostic ----
	 *
	 * MapModule.c source line of the refusal, 0 if the mapper did not refuse.
	 *
	 * NtStatus alone is NOT enough and this was measured, not anticipated: NxcMapModule returns
	 * STATUS_INVALID_IMAGE_FORMAT from seventeen separate checks, so a failing map said only
	 * "something about the image was wrong". Reconstructing which one by hand against the file
	 * offline passed every check and still did not explain the failure -- at which point the missing
	 * discriminator was clearly the bug worth fixing, exactly as PteProbeDiag was on the page-table
	 * side.
	 */
	NXCMD_U32 DiagRefusalLine;

	/*
	 * ---- ABI 4: written by NEXUSCORE. A DIAGNOSTIC BIT FIELD, deliberately open-ended. ----
	 *
	 * Every hardening step the mapper performs is invisible from usermode unless it says so, and this
	 * session has already bumped the boot block ABI five times (5->9) because each new measurement
	 * needed its own field and each bump costs a deploy and a reboot. One flags word ends that for
	 * per-map facts: a new NXCMD_SCRUB or NXCMD_MAP bit needs no layout change at all.
	 *
	 * (Written without the glob spelling on purpose -- "NXCMD_SCRUB_*" followed by "/" closes this
	 * comment block. Caught at review; it would have been a confusing parse error.)
	 *
	 * ⚠ ABSENCE OF A BIT IS NOT PROOF OF FAILURE -- it is proof the step did not REPORT. That
	 * distinction is why NO_IMPORTS exists as its own bit rather than being inferred from DONE being
	 * clear: the EFI side learned it when a payload with no import table reported "imports scrubbed:
	 * no", which reads as a fault and is in fact the best possible outcome.
	 */
	NXCMD_U32 DiagFlags;

	/*
	 * ---- ABI 5: written by the CALLER. The module to tear down for NXCMD_OP_UNMAP. ----
	 *
	 * ⚠ AN INPUT, sitting at the end of the output block. That placement is deliberate: the layout
	 * rule is APPEND ONLY, and layout safety outranks semantic grouping. It is documented here rather
	 * than fixed by moving it, because moving it would silently break every deployed pair.
	 *
	 * WHY NOT REUSE ModuleId, which already names exactly this thing: the handler ZEROES ModuleId,
	 * NtStatus, DiagRefusalLine and DiagFlags on entry, before dispatch, so that a stale value from a
	 * previous command can never be read back as though this one had produced it. An input placed in
	 * ModuleId would be destroyed before the handler ever saw it.
	 *
	 * Rejected alternatives: making ModuleId bidirectional (its direction would then depend on the
	 * opcode, in a struct whose whole hygiene story is "outputs are cleared on entry"), and smuggling
	 * the id through Flags (an id is not a flag, and the name would mislead every future reader).
	 * A field whose meaning flips by opcode is the kind of ambiguity that costs a reboot to diagnose.
	 */
	NXCMD_U32 TargetModuleId;

	/*
	 * ============================================================================================
	 * ABI 6 -- NXCMD_OP_READ. Read a LIVE kernel module's memory into a caller-supplied buffer.
	 * ============================================================================================
	 *
	 * Phase 1 of the capture read path. Deliberately TARGET-AGNOSTIC: v1's equivalent was named after one target
	 * end to end with "eaanticheat.sys" hardcoded, which made a general capability look like an
	 * anti-cheat feature. Reading an arbitrary module by name IS the malware-analysis goal.
	 *
	 * ⚠ NO CHUNKING, unlike v1's 256 KB read chunk. v1 chunked because the data rode
	 * back inside the firmware variable payload, which is small. Here the driver copies straight
	 * into OutBuffer -- the caller's own usermode memory -- so one call moves megabytes. Same
	 * primitive Command.c already uses in the opposite direction for MAP.
	 */

	/* ---- in ---- */
	NXCMD_U64 ReadOffset;      /* byte offset within the module (0 = image base)                 */
	NXCMD_U64 OutBuffer;       /* usermode VA to receive the bytes -- HOSTILE, validated + copied */
	NXCMD_U32 ReadLength;      /* bytes requested; capped by NXCMD_READ_MAX                       */

	/* ---- out ---- */

	/*
	 * ⚠⚠ THE NAME IS ONLY TRUE FOR THE FIVE *READ* OPCODES. Everything else puts a COUNT here, and a
	 * caller that treated a count as a byte length would read 27 BYTES out of a buffer holding 27
	 * ENTRIES. Corrected: the field was documented unconditionally as bytes long after
	 * seventeen opcodes had started returning counts.
	 *
	 * The name cannot be fixed -- the layout is APPEND ONLY and renaming would break every deployed
	 * pair -- so the meaning is pinned here instead. This list was generated from the handlers, not
	 * recalled:
	 *
	 *   BYTES   READ, READ_PROC, READ_PHYS, READ_ATOMIC, VA2PA
	 *   COUNT   everything else -- REGIONS, MODULES, PROCS, PHYS_RANGES, POOL_LIST, POOL_BAIT,
	 *           POOL_BAIT_FREE, CAPTURE_LIST, CAPTURE_CLEAR, CPU_PROBE, TRACE_ALLOC, TRACE_STATUS,
	 *           LOG_DRAIN, FREEZE, THAW, FREEZE_LIST, ALIAS_TEST (which returns a failing step)
	 *
	 * FOR THE READ OPCODES: BYTES ACTUALLY COPIED, WHICH MAY BE LESS THAN ReadLength, and that is NOT
	 * a failure. MmCopyMemory reports NumberOfBytesTransferred precisely because a range can be
	 * partly unreadable -- a paged-out or unmapped page inside an otherwise valid image. An
	 * all-or-nothing model would throw away the readable part and report only "failed", which is
	 * exactly the dishonest-report pattern this codebase keeps having to fix. Callers must check
	 * this, not assume ReadLength.
	 */
	NXCMD_U32 BytesRead;
	NXCMD_U64 ModuleBase;      /* where the module was found (0 if not found)                    */
	NXCMD_U32 ModuleSize;      /* its SizeOfImage, so the caller can bound further reads          */

	/*
	 * Module name, ASCII, NUL-padded, matched CASE-INSENSITIVELY against BaseDllName.
	 *
	 * Inline rather than a pointer: a pointer would need its own MmCopyVirtualMemory round trip
	 * before we could even parse the request, doubling the hostile-input surface for 64 bytes of
	 * savings.
	 */
	NXCMD_U8  TargetName[64];
} NEXUS_COMMAND;

/* Per-call read cap. Bounds the kernel staging allocation; raise deliberately, not casually. */
#define NXCMD_READ_MAX  (4u * 1024u * 1024u)

/* DiagFlags bits. Add freely -- that is the point of the field. */
#define NXCMD_SCRUB_DONE       0x00000001u  /* import metadata erased                            */
#define NXCMD_SCRUB_VERIFIED   0x00000002u  /* re-scanned: no residual "ntoskrnl" in the image    */
#define NXCMD_SCRUB_NO_IMPORTS 0x00000004u  /* nothing to scrub -- the STRONGEST result, not a gap */
#define NXCMD_MAP_COOKIE_SEED  0x00000008u  /* /GS SecurityCookie found and seeded               */
#define NXCMD_MAP_NO_COOKIE    0x00000010u  /* no load config / no cookie: nothing to seed        */

/*
 * UNMAP CROSSED THE POINT OF NO RETURN -- set immediately before COMMIT is called.
 *
 * ⚠ WITHOUT THIS, EVERY UNMAP FAILURE LOOKS CATASTROPHIC. An unmap can fail in two utterly different
 * ways, and reporting them alike was measured on hardware: a second `unmap 0` correctly
 * refused with STATUS_NOT_FOUND -- the slot was already gone, nothing was touched -- and PlatformCtl
 * announced "extents are deliberately LEAKED and its slot is now a zombie". A scary, permanent-
 * sounding claim about memory loss that had not happened.
 *
 *   bit CLEAR + failure -> refused BEFORE anything was destroyed. Bad id, no such module, wrong IRQL,
 *                          descriptor validation, or PREPARE saying no. The module (if any) is
 *                          exactly as it was. Nothing leaked.
 *   bit SET   + failure -> COMMIT began and could not finish. Extents deliberately leaked, slot is a
 *                          zombie. This is the real thing.
 *
 * A status code cannot carry this: STATUS_UNSUCCESSFUL is returned for a failed COMMIT, for an
 * already-zombie slot, and for a reclaim that freed nothing. The bit is set at exactly one place, so
 * it says what happened rather than what it might imply.
 */
#define NXCMD_UNMAP_COMMITTED  0x00000020u

/*
 * The unmap was refused because the slot is ALREADY a zombie from an earlier failed teardown.
 *
 * ⚠ WITHOUT THIS, THE HONEST REPORT BECOMES A DISHONEST ONE. A refusal that happens before teardown
 * begins correctly prints "NOTHING WAS DESTROYED and nothing leaked" -- true of a bad id or an empty
 * slot. Against a zombie it is true of the OPERATION and false about the WORLD: that slot's memory is
 * permanently gone, and the module is not "still running exactly as it was", it is in whatever state
 * a failed COMMIT left it in.
 *
 * measured on the first run of the zombie path: 44 KB permanently leaked, and the second
 * unmap cheerfully reported nothing leaked. The inverse of the false-alarm bug fixed hours earlier,
 * and the same lesson -- a report that is locally true can still lead the reader to the wrong
 * conclusion. COMMITTED answers "did THIS call destroy anything"; this answers "is this slot already
 * a casualty".
 */
#define NXCMD_UNMAP_ZOMBIE     0x00000040u

/*
 * ⚠⚠ NXCMD_OP_LBR_SNAP_INIT actually applied WRAP mode. THE POINT IS THE FIELD IT LIVES IN.
 *
 * Confirming a mode by echoing the caller's own `Flags` proves NOTHING: Flags is an INPUT and
 * survives the round trip untouched, so a payload that has never heard of wrap returns the bit the
 * caller sent and the caller reads its own request back as a confirmation. measured --
 * the first version of this check did exactly that and reported "WRAP MODE" against a driver with
 * no wrap support.
 *
 * DiagFlags is CLEARED ON ENTRY by the dispatcher and written only by handlers, so an older payload
 * leaves it ZERO here. That is what makes absence meaningful rather than ambiguous.
 *
 * It matters more than a normal capability check because the failure INVERTS the reading: a
 * fill-and-stop ring keeps the FIRST N snapshots and a wrapping one keeps the LAST N, so an
 * unnoticed downgrade presents the oldest history as the newest.
 */
#define NXCMD_LBR_WRAP_APPLIED 0x00000080u

#pragma pack(pop)

#define NXCMD_OFFSETOF(t, f)      ((NXCMD_U64)(NXCMD_U64*)&(((t*)0)->f))
#define NXCMD_ASSERT(name, expr)  typedef char nxcmd_assert_##name[(expr) ? 1 : -1]

/*
 * Per-field offsets, not just sizeof(). Three independently compiled views of this struct exist
 * (UEFI, kernel, usermode) and two swapped fields keep the total size identical -- so a size check
 * alone would pass while ImageBuffer and ImageSize traded places, which would hand the kernel a
 * length as a pointer.
 */
NXCMD_ASSERT(size,        sizeof(NEXUS_COMMAND) == 168); /* 56@1 64@4 68@5 168@6 */
/* Shared by both sides from THIS header, so this assert guards the packing pragma, not drift. */
NXCMD_ASSERT(physrange,   sizeof(NXCMD_PHYS_RANGE) == 16);
NXCMD_ASSERT(procentry,   sizeof(NXCMD_PROCESS_ENTRY) == 40);
NXCMD_ASSERT(capentry,    sizeof(NXCMD_CAPTURE_ENTRY) == 88);
/* 1248 -> 1272: LerFrom/LerTo/LerInfo. The Last Event Record, read ON the fault path where it names
 * the branch that reached the faulting instruction -- the one reading the LBR ring cannot give,
 * since dispatch keeps recording over it. Appended, so nothing above moves. */
NXCMD_ASSERT(bpdhit,      sizeof(NXC_BPD_HIT) == 1272); /* 1232 + PtOffset/PtWhy/PtPad + LER */
/* 40 -> 48: PtAddrRanges + Reserved0 (CPUID.(14H,1):EAX[2:0], the PT address-range COUNT). */
NXCMD_ASSERT(cpucaps,     sizeof(NXCMD_CPU_TRACE_CAPS) == 48);

/*
 * (!)(!) NO TWO NXCMD_CPU_* FLAGS MAY SHARE A BIT, AND THIS IS THE PROOF -- added after
 * NXCMD_CPU_PT_IP_FILTER was given 0x800, which NXCMD_CPU_LBR_LEGACY_OK already held.
 *
 * A BITWISE OR EQUALS AN ARITHMETIC SUM IF AND ONLY IF NO BIT IS SHARED. One expression therefore
 * proves PAIRWISE distinctness across every flag, and a flag added to one list but not the other
 * fails the BUILD rather than producing a subtly wrong reading.
 *
 * (!) The collision cost nothing because only a display consumed the flag -- cpuprobe printed
 * `legacy MSRs OK : 24` beneath its own text saying that number must be 0, and the invariant caught
 * itself. But LBR_LEGACY_OK exists to LICENSE reading 0x1C9/0x680/0x6C0, which #GP on an
 * architectural-LBR part with no SEH. The next collision there would not be a reading error.
 */
#define NXCMD_CPU_FLAGS_OR  ( \
    NXCMD_CPU_HAS_PT | NXCMD_CPU_HAS_LBR | NXCMD_CPU_HAS_BTS | NXCMD_CPU_HAS_ARCH_LBR | \
    NXCMD_CPU_HAS_PEBS | NXCMD_CPU_PT_TOPA | NXCMD_CPU_PT_MULTI_TOPA | \
    NXCMD_CPU_PT_CR3_FILTER | NXCMD_CPU_IS_HYBRID_CORE | NXCMD_CPU_CORE_IS_P | \
    NXCMD_CPU_PT_IN_USE | NXCMD_CPU_PT_IP_FILTER | NXCMD_CPU_LBR_LEGACY_OK | \
    NXCMD_CPU_LBR_CPL_FILTER | NXCMD_CPU_LBR_BR_FILTER | NXCMD_CPU_LBR_CALL_STACK | \
    NXCMD_CPU_LBR_LIP)
#define NXCMD_CPU_FLAGS_SUM ( \
    NXCMD_CPU_HAS_PT + NXCMD_CPU_HAS_LBR + NXCMD_CPU_HAS_BTS + NXCMD_CPU_HAS_ARCH_LBR + \
    NXCMD_CPU_HAS_PEBS + NXCMD_CPU_PT_TOPA + NXCMD_CPU_PT_MULTI_TOPA + \
    NXCMD_CPU_PT_CR3_FILTER + NXCMD_CPU_IS_HYBRID_CORE + NXCMD_CPU_CORE_IS_P + \
    NXCMD_CPU_PT_IN_USE + NXCMD_CPU_PT_IP_FILTER + NXCMD_CPU_LBR_LEGACY_OK + \
    NXCMD_CPU_LBR_CPL_FILTER + NXCMD_CPU_LBR_BR_FILTER + NXCMD_CPU_LBR_CALL_STACK + \
    NXCMD_CPU_LBR_LIP)
NXCMD_ASSERT(cpuflags_no_overlap, NXCMD_CPU_FLAGS_OR == NXCMD_CPU_FLAGS_SUM);
NXCMD_ASSERT(ptrange,     sizeof(NXCMD_PT_RANGE) == 24);
/* 8 + 8 + 4 + 4 + 64. Crosses the kernel/usermode wire, so its size is pinned like every other. */
NXCMD_ASSERT(kmodule,     sizeof(NXCMD_KMODULE) == 88);
/* 8 + 8 + 4 + 4. Crosses the wire, so pinned like the rest. */
NXCMD_ASSERT(kexec,       sizeof(NXCMD_KEXEC) == 24);
NXCMD_ASSERT(ptepage,     sizeof(NXCMD_PTE_PAGE) == 40);
NXCMD_ASSERT(sampleent,   sizeof(NXCMD_SAMPLE_ENTRY) == 32);
/* 64 -> 80: DataCfgReadback + EvtSelReadback, 8 each. The two enables that between them decide what
 * a PEBS record contains; see the struct. This assert FIRED on the change that added them, which is
 * the point of it -- both sides of this wire are rebuilt together by one build chain, and
 * `pebs status` also refuses at RUNTIME when the kernel's sizeof and the caller's disagree.
 * 80 -> 88: LdLatReadback. THREE registers now decide what a record holds and how many get written,
 * and a threshold that did not take is invisible except as an empty buffer. */
NXCMD_ASSERT(pebscpu,     sizeof(NXCMD_PEBS_CPU_STATE) == 88);



/* 48 -> 72: Generation + WrapPmi + ArmFlags + PmiWhy (4 each) and LvtPcSaved (8). The wrap counters
 * and the reason PMI mode is or is not live on each core. This assert FIRED on the change that added
 * them, which is the entire reason it is here -- a struct that crosses three independently compiled
 * views cannot be allowed to grow silently on one of them. */
/* 72 -> 80: RtitCtl, the read-back that says which timing packets the trace carries (D117). */
NXCMD_ASSERT(tracestate,  sizeof(NXCMD_TRACE_CPU_STATE) == 80);
/* 24 -> 28: WantDisTnt. Shares this struct because it shares the CPUID.(14H,0) probe and the
 * same fail-closed gate, even though it is not a timing control. */
/* 28 -> 36: WantUser + WantOs. Before this, PT set RTIT_CTL.USER unconditionally and could not
 * trace ring 0 at all -- a usermode-only tracer against a target whose kernel driver is the point. */
NXCMD_ASSERT(pttiming,    sizeof(NXCMD_PT_TIMING) == 36);
/* 56 -> 60: InstallFlags, so `hook list` reports WHAT a hook is and not only where. */
/* 60 -> 64: FilterPid appended. Lands naturally aligned with no padding. */
NXCMD_ASSERT(hookinfo,    sizeof(NXCMD_HOOK_INFO)       == 64);
NXCMD_ASSERT(threadent,   sizeof(NXCMD_THREAD_ENTRY)    == 32);
NXCMD_ASSERT(bpthread,    sizeof(NXCMD_BP_THREAD)       == 48);
/* 72 -> 88: OwnerPid[4] appended. */
NXCMD_ASSERT(bpcpu,       sizeof(NXCMD_BP_CPU)          == 88);
NXCMD_ASSERT(lbrentry,    sizeof(NXCMD_LBR_ENTRY)       == 24);
NXCMD_ASSERT(lbrcpu,      sizeof(NXCMD_LBR_CPU)         == 24 + 24 * NXCMD_LBR_MAX_ENTRIES);
/* 32 -> 56 header: LerFrom / LerTo / LerInfo appended after Entry[]. The Last Event Record is the
 * branch before the last exception or interrupt -- the one reading the LBR ring cannot give, since
 * exception dispatch keeps recording over it. Appended, so every existing field keeps its offset,
 * and this assert is what forces the two sides to be rebuilt together. */
NXCMD_ASSERT(lbrsnap,     sizeof(NXCMD_LBR_SNAPSHOT)    == 32 + 24 * NXCMD_LBR_MAX_ENTRIES + 24);
NXCMD_ASSERT(idttarget,   sizeof(NXCMD_IDT_TARGET)      == 48);
/* 72 -> 80: RsbFiltered + Reserved0, added so a probe reports the Spectre-v2 fill it
 * dropped instead of silently shrinking its own transfer count. This assert is what caught the
 * change -- both ends of the wire are rebuilt by the one build chain, so the bump is safe, but it
 * must be DELIBERATE. That is the entire job of this line. */
NXCMD_ASSERT(idtprobe,    sizeof(NXCMD_IDT_PROBE)       == 80 + 16 * 48);
NXCMD_ASSERT(poolentry,   sizeof(NXCMD_POOL_ENTRY) == 24);
/* The DXE rejects any control variable whose DataSize is not exactly this, so the size is part of
 * the contract and both ends must agree on it without anyone checking by eye. */
NXCMD_ASSERT(bootctl,     sizeof(NXCMD_BOOT_CONTROL) == 8);
NXCMD_ASSERT(logentry,    sizeof(NXCMD_LOG_ENTRY) == 56);
NXCMD_ASSERT(off_roff,    NXCMD_OFFSETOF(NEXUS_COMMAND, ReadOffset)  ==  68);
NXCMD_ASSERT(off_obuf,    NXCMD_OFFSETOF(NEXUS_COMMAND, OutBuffer)   ==  76);
NXCMD_ASSERT(off_rlen,    NXCMD_OFFSETOF(NEXUS_COMMAND, ReadLength)  ==  84);
NXCMD_ASSERT(off_bread,   NXCMD_OFFSETOF(NEXUS_COMMAND, BytesRead)   ==  88);
NXCMD_ASSERT(off_mbase,   NXCMD_OFFSETOF(NEXUS_COMMAND, ModuleBase)  ==  92);
NXCMD_ASSERT(off_msize,   NXCMD_OFFSETOF(NEXUS_COMMAND, ModuleSize)  == 100);
NXCMD_ASSERT(off_tname,   NXCMD_OFFSETOF(NEXUS_COMMAND, TargetName)  == 104);
NXCMD_ASSERT(off_target,  NXCMD_OFFSETOF(NEXUS_COMMAND, TargetModuleId) == 64);
NXCMD_ASSERT(off_magic,   NXCMD_OFFSETOF(NEXUS_COMMAND, Magic)       ==  0);
NXCMD_ASSERT(off_abi,     NXCMD_OFFSETOF(NEXUS_COMMAND, Abi)         ==  8);
NXCMD_ASSERT(off_size,    NXCMD_OFFSETOF(NEXUS_COMMAND, StructSize)  == 12);
NXCMD_ASSERT(off_op,      NXCMD_OFFSETOF(NEXUS_COMMAND, Opcode)      == 16);
NXCMD_ASSERT(off_flags,   NXCMD_OFFSETOF(NEXUS_COMMAND, Flags)       == 20);
NXCMD_ASSERT(off_buf,     NXCMD_OFFSETOF(NEXUS_COMMAND, ImageBuffer) == 24);
NXCMD_ASSERT(off_imgsize, NXCMD_OFFSETOF(NEXUS_COMMAND, ImageSize)   == 32);
NXCMD_ASSERT(off_diagpid, NXCMD_OFFSETOF(NEXUS_COMMAND, DiagCallerPid) == 36);
NXCMD_ASSERT(off_result,  NXCMD_OFFSETOF(NEXUS_COMMAND, Result)      == 40);
NXCMD_ASSERT(off_modid,   NXCMD_OFFSETOF(NEXUS_COMMAND, ModuleId)    == 44);
NXCMD_ASSERT(off_ntst,    NXCMD_OFFSETOF(NEXUS_COMMAND, NtStatus)    == 48);
NXCMD_ASSERT(off_refline, NXCMD_OFFSETOF(NEXUS_COMMAND, DiagRefusalLine) == 56);
NXCMD_ASSERT(off_diagflags, NXCMD_OFFSETOF(NEXUS_COMMAND, DiagFlags) == 60);
