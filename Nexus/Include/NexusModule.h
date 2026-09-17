/**
 * @file NexusModule.h
 * @brief THE TEARDOWN CONTRACT. Every driver NexusCore maps at runtime must satisfy this.
 *
 * Shared by NexusCore (the mapper) and every mappable module (hypervisor first). Uses only locally
 * declared fixed-width types so it compiles under the WDK, the UEFI toolchain and a host compiler.
 *
 * ============================================================================================
 * WHY A CONTRACT AT ALL -- this is the lesson v1 paid for
 * ============================================================================================
 *
 * v1 could map, unmap and remap drivers. It was never usable, because the system became unstable
 * after a cycle. TIER-3 RESEARCH FOUND THE CAUSE, and it was not subtle: v1's entire unmap path is
 * v1's `mapper_cmd_driver.c`, 224 lines, whose HandleUnloadDriver simply calls
 * `PeUnloadDriver(MappedEntry)`. Grep that path for Teardown, Devirtualize, Unregister, Reference,
 * Rundown or KeWait and you get NOTHING. It freed the image and moved on.
 *
 * So anything the driver had registered -- PsSetCreateProcessNotifyRoutine, ObRegisterCallbacks,
 * CmRegisterCallback, timers, DPCs, work items, APCs -- kept pointing into freed pages. The kernel
 * then called into them minutes later, in unrelated code. That is exactly what "became unstable"
 * looks like from the outside, and it is why the failure never pointed back at the unmap.
 *
 * ⚠ THE REFERENCE IMPLEMENTATIONS DO NOT SOLVE THIS, AND CANNOT TELL YOU SO.
 *
 * Ophion (a well-built stealth VT-x hypervisor) tears down with DriverUnload ->
 * broadcast_terminate_all() -> KeGenericCallDpc(dpc_terminate_guest). Correct, and it has no drain,
 * no reference count, no grace period anywhere in its sources. nullmap, umap and RedLotus are no
 * different.
 *
 * They are RIGHT to omit it: they are NORMALLY LOADED drivers. The kernel owns their module-list
 * entry and reference count, refuses to unload while a handle or callback is outstanding, and
 * guarantees no new call can enter after unload returns. All of that safety is the KERNEL's, not
 * theirs.
 *
 * A MANUALLY MAPPED IMAGE HAS NONE OF IT. No module-list entry, no reference count, nothing that
 * refuses. Copying their teardown shape without the kernel's machinery underneath is exactly what
 * v1 did. So this contract exists to supply the missing guarantees ourselves.
 *
 * ============================================================================================
 * THE PROTOCOL -- two phases, and the reason it is two
 * ============================================================================================
 *
 *   1. PREPARE   "Can you unload, and stop taking new work."
 *                The module stops accepting new entries, refuses new registrations, and answers
 *                whether teardown is possible AT ALL. It must not destroy anything yet.
 *
 *   2. COMMIT    "Release everything."
 *                Unregister every callback, cancel and flush every timer/DPC/work item, join every
 *                thread, and -- for a hypervisor -- devirtualize on EVERY processor.
 *
 * Two phases because SOME MODULES CANNOT UNLOAD, and that must be discoverable without damage. A
 * hypervisor mid-VM-exit, or a module holding a callback Windows offers no way to unregister, has to
 * be able to say NO. One-phase teardown forces us to either destroy first and ask later, or never
 * ask -- v1 chose never ask.
 *
 * PREPARE returning failure means the module stays mapped and running, untouched. That is a
 * SUCCESSFUL outcome of unmap: a refused unmap is recoverable, a partial one is a bugcheck later.
 *
 * ============================================================================================
 * WHAT THE MAPPER ADDS AFTER COMMIT -- the part no reference does
 * ============================================================================================
 *
 *   3. DRAIN     Wait for ActiveCount to reach zero. The module maintains it around every entry
 *                point, because there is no kernel refcount to consult.
 *
 *                ⚠ DECISION, settled with evidence rather than left open: ActiveCount
 *                stays the MODULE's responsibility, even though a buggy module can lie about it.
 *
 *                Checked across every reference: Ophion, matrix-rs and illusion-rs ALL return ZERO
 *                matches for drain/refcount/rundown/wait. Not one implements it. They are correct
 *                to omit it -- they are normally loaded drivers and the KERNEL refuses to unload
 *                them while a reference is outstanding. We have none of that machinery, so someone
 *                must supply it, and only the module knows when it is inside its own entry points.
 *
 *                WHAT MAKES A LIE SURVIVABLE: the arena. Because memory is never returned to the
 *                kernel, a module that under-reports ActiveCount produces a stale pointer into OUR
 *                arena -- poisoned, and reused only by us -- rather than into an allocation the
 *                kernel has since handed to an unrelated component. Contained damage instead of
 *                system corruption. That containment is why module-owned is acceptable here and
 *                would not be if we freed to pool.
 *   4. BARRIER   KeGenericCallDpc across all processors (Ophion's primitive, used for a different
 *                purpose): when it returns, every processor has been through a known point, so none
 *                is mid-instruction inside the image.
 *   5. POISON    Fill the extent with a deterministically faulting pattern before reusing it.
 *   6. RECLAIM   Mark the arena extent free. The memory NEVER returns to the kernel, so a stale
 *                pointer lands in our arena instead of in another component's allocation.
 *
 * Step 5 is a deliberate tier-4 addition. Without it, a stale call into a reclaimed extent lands on
 * whatever the NEXT module put there and executes it -- silent cross-module corruption, the worst
 * possible failure. Poisoned, the same stale call dies immediately at the call site with a
 * recognisable signature. It converts the undebuggable case into the obvious one.
 */

/*
 * ============================================================================================
 * ⚠ HARD CONSTRAINT: NO SEH. __try/__except DOES NOT WORK IN A MAPPED MODULE.
 * ============================================================================================
 *
 * x64 unwinding is table-driven. On an exception the kernel takes the faulting RIP and resolves it
 * to an image's .pdata VIA THE LOADED-MODULE LIST -- and a manually mapped image is deliberately
 * absent from that list. The unwinder finds no function table, concludes there is no handler, and
 * the exception becomes a BUGCHECK. Every __try/__except in a mapped module is silently inert.
 *
 * measured, after building the "fix" and discovering it cannot exist:
 *
 *     ntoskrnl.exe exports  RtlLookupFunctionEntry, RtlUnwind, RtlUnwindEx, RtlVirtualUnwind,
 *                           RtlVirtualUnwind2, _local_unwind
 *                           -- everything to WALK unwind data, NOTHING to REGISTER a table.
 *     ntdll.dll exports     RtlAddGrowableFunctionTable, RtlDeleteGrowableFunctionTable
 *                           -- USERMODE ONLY. Not available to a driver at all.
 *
 * v1 named RtlAddGrowableFunctionTable as the solution (mapper_cmd_driver.c:81), so v1's mapped
 * drivers almost certainly had non-functional SEH too. Worth weighing when judging why v1 was
 * unstable: exceptions that should have been caught were bugchecks instead.
 *
 * ============================================================================================
 * DO NOT REACH FOR SEH. USE STATUS-RETURNING APIs -- THE REQUIREMENT IS NARROWER THAN IT LOOKS.
 * ============================================================================================
 *
 * READ THIS BEFORE PORTING ANY DRIVER THAT CURRENTLY USES __try. v1's NexusKernel has 33+ __try
 * sites across 8 files (mdl, physical, virtual, scan, registry, events, lbr, shared_memory) and it
 * looks like a hard blocker. It is not. Inspect what they actually guard:
 *
 *     v1 mdl.cpp:52     __try { MmProbeAndLockPages(...) } __except { status = GetExceptionCode(); }
 *
 * That is the dominant pattern in ALL of them -- "touch memory that might be invalid, catch the
 * fault". It is ONE NARROW REQUIREMENT WEARING AN SEH COSTUME, not general exception handling. v1
 * reached for __try because it is the familiar tool, not because nothing else works.
 *
 * ntoskrnl EXPORTS purpose-built, status-returning equivalents -- all verified present on 26200:
 *
 *     MmCopyMemory          reads VIRTUAL or PHYSICAL addresses safely, returns NTSTATUS. This is
 *                           what crash-dump and live-debug code uses. It is the direct replacement
 *                           for probe-and-catch, and it covers most of v1's sites on its own.
 *     MmCopyVirtualMemory   cross-process copy, returns NTSTATUS
 *     MmIsAddressValid      cheap pre-check (racy on its own -- never the sole guard)
 *     ZwQueryVirtualMemory  query a region before touching it
 *     MmGetPhysicalAddress / MmMapIoSpaceEx / MmSecureVirtualMemory
 *
 * A returned status is BETTER than __except(EXCEPTION_EXECUTE_HANDLER), which swallows everything --
 * including the bugs you wanted to see -- and is checkable at every individual call site.
 *
 * SO: do not use __try/__except, __finally, or C++ try/catch. Validate and use status returns.
 *
 * ============================================================================================
 * WHY WE ARE *NOT* PATCHING KiInvertedFunctionTable (decision, do not reopen lightly)
 * ============================================================================================
 *
 * ⚠ AN EARLIER VERSION OF THIS NOTE CLAIMED "real manual mappers patch it directly". THAT WAS
 * UNVERIFIED AND IS WRONG. Checked afterwards, both ways:
 *   - `reference material/` grepped for InvertedFunctionTable / KiInverted -> NOTHING. Not one of
 *     the vendored projects does it.
 *   - the web agrees on the DIAGNOSIS ("SEH is disabled in manually mapped kernel drivers because
 *     the mapper doesn't register exception handling data to InvertedFunctionTable") but offers no
 *     kernel-x64 technique. kdmapper -- the most widely used kernel manual mapper -- simply does not
 *     do it, and the one public project on the subject is x86-32-bit USERMODE.
 *
 * It is a gap the field accepts, not a well-trodden technique. Reasons not to invent it here:
 *   1. no reference implementation to check against, in a codebase where every recent bug came from
 *      building on an unverified assumption;
 *   2. the failure mode is the WORST AVAILABLE -- a bad entry corrupts unwinding for the ENTIRE
 *      SYSTEM, with delayed global symptoms structurally identical to the v1 instability this whole
 *      contract exists to prevent;
 *   3. PatchGuard coverage is unknown and only discoverable by spending boots;
 *   4. the actual requirement is already met by exported APIs, above.
 *
 * REOPEN ONLY IF a component needs GENUINE exception recovery around arbitrary code -- not safe
 * reads. If so it is a deliberate project with its own verifier: locate the table, PROVE the located
 * structure is right by checking ntoskrnl's own entry resolves to ntoskrnl's real .pdata range, and
 * refuse to write on mismatch. Never a signature match taken on faith.
 */

#pragma once

typedef unsigned char      NXM_U8;
typedef unsigned int       NXM_U32;
typedef unsigned long long NXM_U64;

/*
 * ============================================================================================
 * ⚠ DriverEntry MUST RETURN QUICKLY. Long work belongs on a thread you spawn.
 * ============================================================================================
 *
 * Found by the tier-2 web pass  that should have run before any of this was written:
 * a mapped driver's entry must return promptly or risk PatchGuard attention, and persistent work
 * must run on a separate thread rather than looping in the entry point.
 *
 * It is worse for us than for kdmapper-style loaders, because of WHERE our entry is called from.
 * NexusCore is invoked through a hijacked BOOT DRIVER's init path, and modules NexusCore maps are
 * entered synchronously from that same chain. Blocking there is not just a PatchGuard risk -- it
 * stalls boot-driver initialisation.
 *
 * THIS BITES THE HYPERVISOR HARDEST: virtualizing every logical processor is precisely the kind of
 * long, all-CPU operation that must NOT happen inline in DriverEntry. Do the minimum to become
 * live, hand the rest to a thread, and return.
 */

/* 'NXMD' -- validated before any other field in the descriptor is trusted. */
#define NEXUS_MODULE_MAGIC   0x444D584EULL
#define NEXUS_MODULE_ABI     2u   /* 2: Host */

/*
 * The export a mappable module MUST provide. Resolved by NexusCore from the module's own export
 * directory, exactly as the EFI mapper resolves NexusCoreBootSlot -- so no RVA is pinned and the
 * module's layout can change freely without touching the mapper.
 */
#define NEXUS_MODULE_EXPORT_NAME  "NexusModuleDescriptor"

/* Teardown phase results. */
#define NXM_TEARDOWN_OK          0u  /* phase completed                                          */
#define NXM_TEARDOWN_REFUSED     1u  /* cannot unload now; module left RUNNING and intact         */
#define NXM_TEARDOWN_FAILED      2u  /* tried and could not finish -- see the hard rule below     */

/* Module capability / state flags. */
#define NXM_FLAG_HYPERVISOR      0x00000001u  /* COMMIT must devirtualize every processor          */
#define NXM_FLAG_HAS_CALLBACKS   0x00000002u  /* registered kernel callbacks; COMMIT must unregister */
#define NXM_FLAG_HAS_THREADS     0x00000004u  /* owns threads; COMMIT must join them               */
#define NXM_FLAG_TORN_DOWN       0x00000008u  /* set by the module once COMMIT succeeded           */

#pragma pack(push, 1)

/**
 * Prepare: stop taking new work and report whether unload is possible. Must NOT destroy state.
 * Called at PASSIVE_LEVEL.
 */
typedef NXM_U32 (*NXM_PREPARE_FN)(void);

/**
 * Commit: release everything. Called at PASSIVE_LEVEL, only after PREPARE returned NXM_TEARDOWN_OK.
 *
 * ⚠ HARD RULE: returning NXM_TEARDOWN_FAILED here is unrecoverable by design. PREPARE already said
 * unload was possible, so a failure at COMMIT means the module is in an unknown, partly-released
 * state. The mapper will NOT reclaim the extent -- it leaks the arena extent deliberately and
 * forever, because leaking 16 MB of our own arena is strictly better than reusing memory that
 * something may still call into. Do not use FAILED as "I changed my mind"; refuse at PREPARE.
 */
typedef NXM_U32 (*NXM_COMMIT_FN)(void);

/*
 * ============================================================================================
 * FOR HYPERVISOR MODULES: the two devirtualisation shapes, and the hazard between them
 * ============================================================================================
 *
 * TIER-1 sweep of every HV in reference material/ found TWO different approaches, and the choice has
 * consequences COMMIT must handle:
 *
 *   Ophion      broadcast_terminate_all() -> KeGenericCallDpc(dpc_terminate_guest), with
 *               KeSignalCallDpcDone / KeSignalCallDpcSynchronize. All processors at once, at
 *               DISPATCH_LEVEL, barrier-synchronised. Fast, but DISPATCH means no pool and no waits
 *               during teardown.
 *
 *   matrix-rs   devirtualize_system() iterates processors, switches affinity to each
 *               (ProcessorExecutor::switch_to_processor), calls devirtualize_cpu(), moves on. One
 *               CPU at a time, at PASSIVE, so allocation and waiting ARE legal -- but slower.
 *
 * ⚠ THE HAZARD IS IN THE SECOND ONE. Sequential devirtualisation leaves the machine in a MIXED
 * STATE: some processors still in VMX root, others already out. If anything frees or reuses the
 * hypervisor's memory during that window -- its VMCS regions, its EPT hierarchy, its per-CPU state --
 * the result is not a clean bugcheck, it is silent corruption on the CPUs still running under it.
 *
 * Hence the contract: COMMIT must not return NXM_TEARDOWN_OK until EVERY processor is out of VMX
 * root, and the mapper must not touch a single byte of the module's memory until it does. A partial
 * devirtualisation reported as success is the worst outcome available here.
 */

/**
 * The descriptor. The module defines and exports exactly one, statically initialised.
 *
 * Layout locked with per-field asserts for the same reason as the boot block: two independently
 * compiled views that silently disagree is a protocol break, and swapping two fields keeps sizeof()
 * identical so a size check alone would pass.
 */
typedef struct _NEXUS_MODULE_DESCRIPTOR
{
	NXM_U64        Magic;         /* NEXUS_MODULE_MAGIC, checked FIRST                  */
	NXM_U32        Abi;           /* NEXUS_MODULE_ABI                                   */
	NXM_U32        StructSize;    /* sizeof(*this) as the MODULE saw it                  */

	NXM_PREPARE_FN Prepare;       /* phase 1; mandatory                                 */
	NXM_COMMIT_FN  Commit;        /* phase 2; mandatory                                 */

	NXM_U32        Flags;         /* NXM_FLAG_*                                         */

	/*
	 * ACTIVE ENTRY COUNT, maintained by the MODULE: incremented on entry to any of its externally
	 * reachable functions, decremented on exit. This is the reference count the kernel would have
	 * kept for a normally loaded driver and does not keep for us.
	 *
	 * The mapper waits for this to reach 0 after COMMIT and REFUSES to reclaim the extent if it does
	 * not. A module that does not maintain it honestly is a module whose memory we cannot safely
	 * reuse -- and the failure would land on whoever gets that memory next.
	 */
	/*
	 * ⚠⚠ VOLATILE, AND THAT IS A CORRECTNESS REQUIREMENT RATHER THAN A STYLE CHOICE. This is the one
	 * field written by the MODULE (on every entry and exit, potentially on another processor) and
	 * read by the HOST -- and the host reads it in a POLLING LOOP:
	 *
	 *     Drained = (Desc->ActiveCount == 0);
	 *     for (i = 0; !Drained && i < 64; i++) { delay(); Drained = (Desc->ActiveCount == 0); }
	 *
	 * Declared as a plain NXM_U32, nothing OBLIGES the compiler to reload it each iteration. Hoist
	 * that load and the loop becomes a fixed 64-iteration sleep that can never observe the count
	 * drop: every module busy at teardown gets zombied even if it quiesces in 20 ms, and the
	 * behaviour is INDISTINGUISHABLE FROM OUTSIDE from a loop that re-checked and timed out.
	 *
	 * ⚠ IT PROBABLY DOES RELOAD TODAY -- the delay is an indirect call through the NtApi table, so
	 * MSVC must assume the callee can reach this memory. That is the optimizer choosing to be
	 * correct, not being required to. Found by reading while looking for a way to TEST
	 * the re-check; the test needs a module thread, which the host API does not expose, so making the
	 * property STRUCTURAL is both cheaper and stronger than measuring it.
	 * (an earlier finding)
	 *
	 * Layout is unaffected: volatile changes access, not size or offset -- the asserts below still
	 * pin it at +36.
	 */
	volatile NXM_U32 ActiveCount;

	NXM_U8         Name[32];      /* ASCII, NUL-padded; diagnostics only                */

	/*
	 * ---- ABI 2: written by the HOST, read by the MODULE ----
	 *
	 * Pointer to a NEXUS_HOST_API (see NexusHost.h). This is the ONLY way a mapped module can reach
	 * anything: it has no import table it may rely on, must not touch pool, and its arena
	 * allocations have to carry an owner id it cannot make up for itself.
	 *
	 * Every other field here is written by the MODULE and read by the host. This one goes the other
	 * way, and it is in the descriptor because a mapped entry is called as DriverEntry(NULL, NULL) --
	 * there is no argument channel, so the same "write into the image at a known export" mechanism
	 * that carries NexusCoreBootSlot carries this.
	 *
	 * ⚠ THEREFORE THE DESCRIPTOR MUST BE IN WRITABLE DATA. A `const` descriptor lands in .rdata,
	 * which the mapper now protects read-only before the entry runs, and the host's write would
	 * fault. (The host writes this BEFORE applying protections, so the order is safe -- but a const
	 * descriptor is wrong regardless, because ActiveCount is written by the module on every call.)
	 *
	 * NULL means the host did not fill it. A module must CHECK, and refuse rather than proceed: a
	 * module that assumes it is present and finds NULL dereferences zero in kernel mode.
	 */
	NXM_U64        Host;
} NEXUS_MODULE_DESCRIPTOR;

#pragma pack(pop)

#define NXM_OFFSETOF(type, field)     ((NXM_U64)(NXM_U64*)&(((type*)0)->field))
#define NXM_ASSERT_LAYOUT(name, expr) typedef char nxm_assert_##name[(expr) ? 1 : -1]

NXM_ASSERT_LAYOUT(desc_size,   sizeof(NEXUS_MODULE_DESCRIPTOR) == 80);  /* 72@1, 80@2 */
NXM_ASSERT_LAYOUT(off_magic,   NXM_OFFSETOF(NEXUS_MODULE_DESCRIPTOR, Magic)       ==  0);
NXM_ASSERT_LAYOUT(off_abi,     NXM_OFFSETOF(NEXUS_MODULE_DESCRIPTOR, Abi)         ==  8);
NXM_ASSERT_LAYOUT(off_size,    NXM_OFFSETOF(NEXUS_MODULE_DESCRIPTOR, StructSize)  == 12);
NXM_ASSERT_LAYOUT(off_prepare, NXM_OFFSETOF(NEXUS_MODULE_DESCRIPTOR, Prepare)     == 16);
NXM_ASSERT_LAYOUT(off_commit,  NXM_OFFSETOF(NEXUS_MODULE_DESCRIPTOR, Commit)      == 24);
NXM_ASSERT_LAYOUT(off_flags,   NXM_OFFSETOF(NEXUS_MODULE_DESCRIPTOR, Flags)       == 32);
NXM_ASSERT_LAYOUT(off_active,  NXM_OFFSETOF(NEXUS_MODULE_DESCRIPTOR, ActiveCount) == 36);
NXM_ASSERT_LAYOUT(off_name,    NXM_OFFSETOF(NEXUS_MODULE_DESCRIPTOR, Name)        == 40);
NXM_ASSERT_LAYOUT(off_host,    NXM_OFFSETOF(NEXUS_MODULE_DESCRIPTOR, Host)        == 72);

/*
 * Poison pattern written over a reclaimed extent (step 5 above).
 *
 * 0xCC is INT3: a stale CALL into poisoned code raises a breakpoint immediately, at the faulting
 * address, instead of executing whatever the next tenant placed there. Chosen over 0x00 (which
 * decodes as valid `add [rax],al` and can limp on corrupting memory) and over random fill (which
 * gives a different bugcheck every time and hides the pattern). A crash dump full of 0xCC at the
 * instruction pointer says "stale call into an unmapped Nexus module" at a glance.
 */
#define NXM_POISON_BYTE  0xCC
