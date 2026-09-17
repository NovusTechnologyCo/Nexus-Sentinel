/**
 * @file Command.c
 * @brief The kernel end of the command channel. Called by the DXE's SetVariable hook.
 *
 * ============================================================================================
 * WHERE THIS RUNS, and why every constraint below follows from it
 * ============================================================================================
 *
 * PlatformCtl calls SetVariable. Windows takes that through the HAL into gRT->SetVariable, which the
 * DXE has hooked. The hook validates the command and calls straight in here through
 * NEXUS_CORE_BOOT_BLOCK::CommandHandler.
 *
 * So this executes:
 *   - on the CALLING THREAD, in the CALLING PROCESS's context. That is what makes ImageBuffer
 *     readable at all -- it is a usermode VA that only means anything in that address space.
 *   - at PASSIVE_LEVEL, but ONLY because the DXE gates on CR8 == 0 before calling. We re-check
 *     anyway rather than trust it: the gate lives in another binary that ships separately, and
 *     "the other side checks" is how a missing check survives.
 *   - with NO SEH. Not a style choice -- x64 unwinding is table-driven off the loaded-module list
 *     and a manually mapped image is deliberately absent from it (see the block in NexusCore.c).
 *     Every API used here must RETURN failure rather than raise.
 *
 * ============================================================================================
 * ⚠ ImageBuffer IS HOSTILE, and this is the whole reason MmCopyVirtualMemory is used
 * ============================================================================================
 *
 * The caller can free it, re-protect it, or point it at kernel memory, concurrently, from another
 * thread. ProbeForRead is not the answer: its documented contract gives "no guarantees that this
 * address will remain valid after the probe", so correct use REQUIRES try/except -- which we do not
 * have. MmCopyVirtualMemory returns NTSTATUS instead of raising, which makes it the only correct
 * choice here rather than merely the better one.
 *
 * ⚠ PreviousMode is KernelMode, and the usermode range is checked EXPLICITLY before the copy. This
 * header previously claimed UserMode was passed deliberately, so that the kernel would validate the
 * source as a usermode range and refuse a caller pointing ImageBuffer at kernel memory. That was
 * wrong, and it cost a live debugging cycle: PreviousMode governs the probe of BOTH ranges, and the
 * TARGET is our own kernel pool -- so the probe rejected our own staging buffer and every map failed
 * with STATUS_ACCESS_VIOLATION before the source was read. The security property is real and is now
 * enforced by an explicit bound check in the map path, where it can be read.
 */

#pragma runtime_checks("", off)
#pragma check_stack(off)
#pragma strict_gs_check(off)

#include <ntddk.h>

#include "../../Include/NexusCoreBoot.h"
#include "../../Include/NexusCommand.h"
#define NXC_NT_API_TYPED
#include "../../Include/NexusNtApi.h"
#include "Arena.h"
#include "MapModule.h"
#include "Capture.h"
#include "Regions.h"
#include "Pte.h"      /* NxcPteScanUnlistedExec -- `modules --hidden` */
#include "PhysMem.h"
#include "Translate.h"
#include "Processes.h"
#include "Freeze.h"
#include "CpuProbe.h"
#include "Trace.h"
#include "PgScan.h"
#include "Pool.h"
#include "Alias.h"
#include "LogRing.h"
#include "Hook.h"
#include "Idt.h"
#include "Calls.h"
#include "TpmTrace.h"
#include "FileCapture.h"
#include "Ssdt.h"
#include "Threads.h"
#include "Bp.h"
#include "Btf.h"
#include "Lbr.h"
#include "Kpages.h"
#include "BpDispatch.h"

extern volatile NXC_NT_API NexusNtApi;
#include "../../Include/NexusNtApiRedirect.h"

extern void NxcLogExt(_In_z_ PCSTR Format, ...);
#define CmdLog NxcLogExt

/*
 * Upper bound on the RAW FILE we will accept from usermode. ImageSize is caller-supplied, and without
 * a cap a bogus length is an allocation request for as much pool as the caller cares to name.
 *
 * SentinelHV is 102400 bytes on disk and is the largest thing we intend to map, so 8 MB is ~82x
 * headroom on the field this actually bounds.
 *
 * ⚠ BUT THE ARENA IS NOT BOUNDED BY THIS, and measuring SentinelHV made that concrete: its
 * SizeOfImage is 1449984 bytes -- 14.2x its size on disk, because .bss-style sections occupy address
 * space without occupying file. The arena allocation is SizeOfImage plus a guard page, so a 16 MB
 * arena holds ELEVEN SentinelHV-sized modules, not 160. Anyone sizing the arena from disk sizes will
 * be wrong by more than an order of magnitude.
 *
 * A caller CAN still name a SizeOfImage far beyond the arena -- this cap does not constrain it. That
 * fails safely: NxcArenaAllocFor returns NULL and the map is refused with STATUS_INSUFFICIENT_RESOURCES
 * (and its Need + guard-page addition is overflow-checked, Arena.c). Safe, but the refusal says
 * "out of resources" rather than "your image does not fit", which is worth knowing when it happens.
 */
#define NXC_CMD_MAX_IMAGE   (8u * 1024u * 1024u)

/*
 * The x64 Windows user/kernel split, used to validate every usermode pointer a caller hands us.
 *
 * Usermode VAs live below 0x0000_7FFF_FFFF_0000, and the low 64 KB is never a valid user mapping, so
 * a small integer arriving as a "pointer" is rejected rather than probed. Written as constants with
 * the reasoning attached because the alternative -- MmUserProbeAddress -- is a DATA export and our
 * resolution table carries functions only.
 *
 * ⚠ This is the property PreviousMode = UserMode was WRONGLY relied on for; enforced here, in our
 * own code, where it can be read.
 *
 *  HOISTED to file scope from inside the MAP path. NXCMD_OP_READ needs the identical
 * rule for its DESTINATION buffer, and two copies of a security bound is how they drift apart.
 */
#define NXC_USER_VA_FLOOR   0x0000000000010000ULL
#define NXC_USER_VA_CEILING 0x00007FFFFFFF0000ULL

/**
 * Resolve a hook target that arrived as an ntoskrnl EXPORT NAME instead of an address.
 *
 * WHY THIS EXISTS. Build-plan items B-01 (file capture) and B-02 (object/registry
 * visibility) were both filed as BLOCKED because FltRegisterFilter / ObRegisterCallbacks /
 * CmRegisterCallbackEx all refuse a manually mapped image -- they want a DriverObject we do not
 * have and cannot get. The registration APIs are blocked; the FUNCTIONS THEY WOULD HAVE NOTIFIED US
 * ABOUT ARE NOT. An inline hook on NtCreateFile needs no DriverObject, no loaded-module-list entry
 * and no registration, and the hook mechanism is already verified in silicon.
 *
 * WHY A NAME AND NOT AN ADDRESS. An Nt* entry point has no export we can pin: KASLR moves ntoskrnl
 * every boot, so an offline-read offset is a value that was true on the machine that read it. The
 * usermode side cannot resolve it either -- ntoskrnl is not mapped into ring 3 at its kernel VA.
 * Ring 0 has the base and the export directory, so the resolution belongs HERE, re-derived per
 * boot, never carried across one. An earlier finding permits pinning
 * per-boot values in principle; it does not make one CORRECT, and this one would silently arm the
 * middle of some other function.
 *
 * ⚠ ONE EXPRESSION, TWO CONSUMERS -- INSTALL AND REMOVE BOTH CALL THIS. Deriving the target
 * separately in each is precisely
 * An earlier finding, which produced a LIVE
 * PATCH sitting behind a confident "nothing was patched". `unhook NtCreateFile` must compute the
 * identical VA `hook NtCreateFile` computed, and the only way to guarantee that is one function.
 *
 * ⚠ THE TWO FAILURES ARE DISTINGUISHED, and by an INDEPENDENT probe rather than a mirror of the
 * failing call: "no ntoskrnl base" and "that name is not exported" both come back NULL from
 * NxcResolveNtExport, and one status code for two refusals is
 * An earlier finding -- the shape that cost four
 * boots. KeBugCheckEx is the probe: exported by every ntoskrnl that has ever shipped, so if IT
 * resolves the base is good and the caller's name is genuinely absent (STATUS_PROCEDURE_NOT_FOUND);
 * if it does not, the base was never captured (STATUS_NOT_FOUND) and the caller's spelling is
 * irrelevant.
 *
 * Forwarded exports are refused inside FindExport -- a forwarder's "address" points at a
 * "Dll.Function" ASCII string in the export directory, and hooking that patches text.
 */
static NTSTATUS
NxcResolveHookTarget(
	_Inout_ NEXUS_COMMAND* Command,
	_Out_   UINT64*        OutVa
	)
{
	*OutVa = Command->ReadOffset;

	/* An address was supplied: it wins, and nothing here runs. */
	if (Command->ReadOffset != 0 || Command->TargetName[0] == '\0')
		return STATUS_SUCCESS;

	/* NUL-terminate in place -- the caller's 64 bytes may be full with no terminator. */
	Command->TargetName[sizeof(Command->TargetName) - 1] = '\0';

	void* Ep = NxcResolveNtExport((CONST CHAR*)Command->TargetName);

	/*
	 * ⚠ NOT EXPORTED IS NOT UNREACHABLE. measured: the ENTIRE registry syscall family is
	 * Zw-only -- NtSetValueKey, NtCreateKey, NtOpenKey, NtDeleteKey and the rest have no Nt* export,
	 * which is why the first B-02b run refused. The bodies are still there; they are reached through
	 * KiServiceTable, which is what a usermode `syscall` uses.
	 *
	 * ⚠ AND THE Zw EXPORT IS *NOT* AN ACCEPTABLE SUBSTITUTE, which is the trap this branch exists to
	 * avoid. ZwSetValueKey sets PreviousMode = KernelMode and enters the dispatcher; a usermode
	 * registry write never touches it. Hooking it would have installed cleanly, fired for kernel
	 * callers, and reported "registry visibility works" while being blind to every process on the
	 * machine. See Ssdt.c.
	 */
	if (Ep == NULL)
		Ep = NxcResolveSyscallRoutine((CONST CHAR*)Command->TargetName);

	/*
	 * ⚠ LAST ROUTE: A SERVICE INDEX SUPPLIED BY THE CALLER. Both routes above need a NAME the kernel
	 * can find -- an Nt* export, or a Zw* twin to read the index out of. measured:
	 * NtWriteVirtualMemory and NtReadVirtualMemory have NEITHER on this build, so the entire
	 * cross-process read/write family was unreachable from here while being plainly exported by
	 * ntdll. Usermode reads the index from that stub and passes it; this indexes KiServiceTable
	 * directly, with the index bounds-checked and the routine confirmed inside ntoskrnl.
	 */
	if (Ep == NULL && (Command->Flags & NXCMD_HOOK_FLAG_BYINDEX) != 0)
		Ep = NxcResolveSyscallByIndex(Command->ReadLength);

	if (Ep == NULL)
	{
		CONST BOOLEAN BaseOk = (NxcResolveNtExport("KeBugCheckEx") != NULL);
		UINT64 SsdtTable = 0; UINT32 SsdtLimit = 0;
		NxcSsdtStats(&SsdtTable, &SsdtLimit);
		NxcLogExt("hook: '%s' did not resolve -- %s (KiServiceTable %llX, %u services)\n",
		          (CONST CHAR*)Command->TargetName,
		          BaseOk ? "not an ntoskrnl export, and no Zw twin carried a usable service index"
		                 : "NO NTOSKRNL BASE IS RECORDED, so no name could have resolved",
		          SsdtTable, SsdtLimit);
		return BaseOk ? STATUS_PROCEDURE_NOT_FOUND : STATUS_NOT_FOUND;
	}

	*OutVa = (UINT64)(ULONG_PTR)Ep;

	/*
	 * ⚠ REPORT THE VA BACK IN THE FIELD THE ADDRESS FORM USES. Usermode prints what it sent, and for
	 * a name it sent nothing -- so without this, `hook NtCreateFile` would report success against
	 * "0x0" and the operator would have no way to know WHICH address is now patched. Writing it into
	 * ReadOffset also means the value printed is the value hooked, by construction rather than by
	 * two sites agreeing.
	 */
	Command->ReadOffset = (NXCMD_U64)*OutVa;
	return STATUS_SUCCESS;
}

/**
 * Handle one command. Returns STATUS_SUCCESS when the COMMAND was processed -- which is not the same
 * as the operation succeeding. The operation's own outcome goes in Command->Result / NtStatus,
 * because "the channel worked and the map was refused" and "the channel did not work" are different
 * facts and a single status cannot carry both.
 */
static NTSTATUS
NxcCommandDispatch(
	_Inout_ NEXUS_COMMAND* Command
	)
{

	/*
	 * Validate before trusting ANY other field, magic first. The DXE checks these too; doing it
	 * again costs three compares and removes the assumption that it did. Note the struct itself is a
	 * DXE-owned copy in kernel memory, not the caller's buffer -- only ImageBuffer points at
	 * usermode.
	 */
	if (Command->Magic != NEXUS_CMD_MAGIC)
	{
		Command->Result = NXCMD_RESULT_BAD_MAGIC;
		return STATUS_INVALID_PARAMETER;
	}
	if (Command->Abi != NEXUS_CMD_ABI ||
		Command->StructSize != (NXCMD_U32)sizeof(NEXUS_COMMAND))
	{
		CmdLog("cmd: abi=%u size=%u, built for %u/%u -- REFUSED\n",
		       Command->Abi, Command->StructSize,
		       (ULONG)NEXUS_CMD_ABI, (ULONG)sizeof(NEXUS_COMMAND));
		Command->Result = NXCMD_RESULT_BAD_ABI;
		return STATUS_REVISION_MISMATCH;
	}

	/*
	 * Zero EVERY field documented as "written by NexusCore", before doing anything that might return
	 * early.
	 *
	 *: ModuleId and NtStatus were cleared, DiagRefusalLine and DiagFlags were
	 * not -- they were only assigned on the map path, after NxcMapModule. Any path that returned before
	 * that (bad opcode, wrong IRQL, no arena, a rejected pointer) left whatever the CALLER had put
	 * there, and PlatformCtl renders those fields as our report. A caller could therefore hand us
	 * "refused at MapModule.c:449" and a set of scrub flags and have them echoed back as findings.
	 *
	 * Not an attack worth much on its own -- the caller is already elevated -- but it means a diagnostic
	 * channel could report something the driver never observed, which is the one thing a diagnostic must
	 * never do.
	 */
	Command->ModuleId        = 0;
	Command->NtStatus        = 0;
	Command->DiagRefusalLine = 0;
	Command->DiagFlags       = 0;

	/*
	 * Record the context we ACTUALLY run in, on every path including the failures.
	 *
	 * This exists because the first live `map` returned COPY_FAILED / 0xC0000005, which has two
	 * causes that are indistinguishable from usermode: a bad probe on our side, or the runtime
	 * service not executing in the caller's process (making a usermode VA meaningless here).
	 * PlatformCtl compares this to its own pid, so ONE reboot answers the question instead of one
	 * reboot per guess.
	 */
	Command->DiagCallerPid = (NXCMD_U32)(ULONG_PTR)PsGetCurrentProcessId();

	/*
	 * Re-check IRQL even though the DXE gated on CR8. MmCopyVirtualMemory requires PASSIVE_LEVEL,
	 * and the gate is in a separately-shipped binary -- a stale DXE that lost the check would
	 * otherwise turn into a bugcheck here rather than a refusal.
	 */
	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
	{
		Command->Result = NXCMD_RESULT_WRONG_IRQL;
		return STATUS_INVALID_DEVICE_STATE;
	}

	switch (Command->Opcode)
	{
	case NXCMD_OP_NOP:
		/*
		 * Liveness probe. Proves the whole path -- PlatformCtl -> SetVariable -> HAL -> DXE hook ->
		 * this function -> GetVariable -> PlatformCtl -- without mapping anything. Worth having as a
		 * real opcode: when `map` fails, the first question is whether the CHANNEL or the MAPPER
		 * broke, and without this they are indistinguishable from usermode.
		 */
		CmdLog("cmd: NOP -- channel is live\n");
		Command->Result = NXCMD_RESULT_OK;
		return STATUS_SUCCESS;

	case NXCMD_OP_MAP:
		break;

	case NXCMD_OP_UNMAP:
	{
		/*
		 * Handled entirely here rather than falling through to the MAP path below: unmap takes no user
		 * buffer at all, so none of the copy machinery -- the 8 MB staging allocation, the usermode
		 * range check, MmCopyVirtualMemory -- applies to it. Sharing that path would mean guarding
		 * every step with "unless this is an unmap", which is how the map path grows a second, less
		 * tested personality.
		 */
		CONST NTSTATUS UnmapStatus = NxcMapUnmap(Command->TargetModuleId);

		Command->ModuleId        = Command->TargetModuleId;   /* echo: which module this answer is about */
		Command->NtStatus        = (NXCMD_U64)(ULONG_PTR)UnmapStatus;
		Command->DiagRefusalLine = (NXCMD_U32)NxcMapLastRefusalLine();
		/* Carries NXCMD_UNMAP_COMMITTED -- whether anything was actually destroyed. */
		Command->DiagFlags       = NxcMapLastDiagFlags();

		if (NT_SUCCESS(UnmapStatus))
		{
			CmdLog("cmd: unmap %u -- torn down and reclaimed\n", Command->TargetModuleId);
			Command->Result = NXCMD_RESULT_OK;
		}
		else if (UnmapStatus == STATUS_DEVICE_BUSY)
		{
			/*
			 * ⚠ NOT AN ERROR PATH. The module refused teardown, or did not drain, and is left mapped
			 * and running. BUSY rather than REFUSED because REFUSED means "the mapper rejected your
			 * image" -- a permanent property of the input -- whereas this is a property of the
			 * module's CURRENT state and the same request may well succeed later. Collapsing the two
			 * would tell the caller to fix their file when they should simply try again.
			 */
			CmdLog("cmd: unmap %u -- module refused or is busy; left running\n", Command->TargetModuleId);
			/* MODULE_BUSY, not BUSY: that one means "another command was in flight" and is a
			 * transient worth retrying at once. This may be permanent. */
			Command->Result = NXCMD_RESULT_MODULE_BUSY;
		}
		else
		{
			CmdLog("cmd: unmap %u -- FAILED 0x%08X at line %u\n",
			       Command->TargetModuleId, UnmapStatus, Command->DiagRefusalLine);
			Command->Result = NXCMD_RESULT_REFUSED;
		}
		return UnmapStatus;
	}

	case NXCMD_OP_WATCH:
	{
		/*
		 * Arm a pristine capture for the NEXT load of this image. Opt-in, because the notify fires
		 * for every image load on the system and copying them all would exhaust the arena in
		 * seconds and slow every process launch.
		 */
		CHAR WName[sizeof(Command->TargetName)];
		BOOLEAN WTerm = FALSE;
		for (ULONG i = 0; i < sizeof(WName); i++)
		{
			WName[i] = (CHAR)Command->TargetName[i];
			if (WName[i] == '\0') { WTerm = TRUE; break; }
		}
		if (!WTerm || WName[0] == '\0')
		{
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_PARAMETER;
			return STATUS_INVALID_PARAMETER;
		}

		/* Recover from a boot-time registration failure without a reboot -- see Capture.h. */
		(void)NxcCaptureEnsureRegistered();

		CONST NTSTATUS WStatus = NxcCaptureWatch(WName);
		Command->NtStatus = (NXCMD_U64)(ULONG_PTR)WStatus;
		Command->Result   = NT_SUCCESS(WStatus) ? NXCMD_RESULT_OK : NXCMD_RESULT_REFUSED;

		NxcCaptureStats(&Command->ModuleSize, &Command->BytesRead);   /* watched / captured */
		CmdLog("cmd: watch '%s' -> 0x%08X\n", WName, WStatus);
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_REGIONS:
	{
		/*
		 * Enumerate a process's user VA regions into the caller's buffer.
		 *
		 * ENUMERATE ONLY -- no dump, no "interesting" verdict. The kernel reports state/protection/
		 * type/backing-file and usermode applies its own rule (cross-surface decisions D5/D6). That
		 * keeps the heuristic deployable without a kernel rebuild and stops the kernel becoming
		 * policy.
		 */
		Command->BytesRead  = 0;
		Command->ModuleBase = 0;
		Command->ModuleSize = 0;

		CONST ULONG MaxRegions = Command->ReadLength / (ULONG)sizeof(NXC_REGION);
		if (MaxRegions == 0 || Command->ReadLength > NXCMD_READ_MAX)
		{
			CmdLog("cmd: regions buffer %u bytes holds no entries (need >= %u)\n",
			       Command->ReadLength, (ULONG)sizeof(NXC_REGION));
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_BUFFER_TOO_SMALL;
			return STATUS_BUFFER_TOO_SMALL;
		}

		CONST NXCMD_U64 RFirst = Command->OutBuffer;
		CONST NXCMD_U64 RLast  = RFirst + (NXCMD_U64)Command->ReadLength;
		if (RFirst < NXC_USER_VA_FLOOR || RLast > NXC_USER_VA_CEILING || RLast <= RFirst)
		{
			Command->Result = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_ADDRESS;
			return STATUS_INVALID_ADDRESS;
		}

		/* Staging, for the same reason the read path stages: the walk fills kernel memory and one
		 * bounded copy hands it out, rather than writing to usermode from inside the walk. */
		NXC_REGION* CONST Staging =
			(NXC_REGION*)ExAllocatePool2(POOL_FLAG_NON_PAGED, Command->ReadLength, 'gRxN');
		if (Staging == NULL)
		{
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INSUFFICIENT_RESOURCES;
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		ULONG Got = 0, Total = 0;
		CONST NTSTATUS Rst =
			NxcEnumRegions(Command->TargetModuleId, Staging, MaxRegions, &Got, &Total);

		if (!NT_SUCCESS(Rst))
		{
			ExFreePoolWithTag(Staging, 'gRxN');
			CmdLog("cmd: regions pid %u failed 0x%08X\n", Command->TargetModuleId, Rst);
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)Rst;
			return Rst;
		}

		SIZE_T Copied = 0;
		CONST NTSTATUS Out =
			MmCopyVirtualMemory(PsGetCurrentProcess(), Staging, PsGetCurrentProcess(),
			                    (PVOID)(ULONG_PTR)RFirst,
			                    (SIZE_T)Got * sizeof(NXC_REGION), KernelMode, &Copied);
		ExFreePoolWithTag(Staging, 'gRxN');

		if (!NT_SUCCESS(Out))
		{
			Command->Result = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)Out;
			return Out;
		}

		/*
		 * BOTH counts, per D3. Got is what fitted; Total is what EXISTS. A caller seeing only Got
		 * would believe a truncated list was the whole picture -- and missing one region is this
		 * surface's entire failure mode, since the region it misses may be the manual map.
		 */
		Command->BytesRead  = Got;
		Command->ModuleSize = Total;
		Command->Result     = NXCMD_RESULT_OK;
		CmdLog("cmd: regions pid %u -> %u of %u\n", Command->TargetModuleId, Got, Total);
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_READ_PROC:
	{
		/*
		 * Read an absolute VA out of a target process.
		 *
		 * ⚠ NO STAGING BUFFER, unlike NXCMD_OP_READ — and the difference is worth stating because it
		 * looks like an omission. That path stages because its SOURCE is kernel memory and its
		 * destination is usermode, so a single MmCopyVirtualMemory would have to cross privilege in
		 * one call. Here BOTH ends are process address spaces and we are running in the caller's
		 * context, so MmCopyVirtualMemory goes target -> caller directly. One copy, no pool
		 * allocation, nothing to leak on a failure path.
		 */
		Command->BytesRead  = 0;
		Command->ModuleBase = 0;
		Command->ModuleSize = 0;

		if (Command->ReadLength == 0 || Command->ReadLength > NXCMD_READ_MAX)
		{
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_PARAMETER;
			return STATUS_INVALID_PARAMETER;
		}

		CONST NXCMD_U64 PFirst = Command->OutBuffer;
		CONST NXCMD_U64 PLast  = PFirst + (NXCMD_U64)Command->ReadLength;
		if (PFirst < NXC_USER_VA_FLOOR || PLast > NXC_USER_VA_CEILING || PLast <= PFirst)
		{
			Command->Result = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_ADDRESS;
			return STATUS_INVALID_ADDRESS;
		}

		PVOID Target = NULL;
		if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Command->TargetModuleId,
		                                           &Target)) || Target == NULL)
		{
			CmdLog("cmd: read-proc pid %u -- no such process\n", Command->TargetModuleId);
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_NOT_FOUND;
			return STATUS_NOT_FOUND;
		}

		SIZE_T PCopied = 0;
		NTSTATUS PSt =
			MmCopyVirtualMemory(Target, (PVOID)(ULONG_PTR)Command->ReadOffset,
			                    PsGetCurrentProcess(), (PVOID)(ULONG_PTR)PFirst,
			                    (SIZE_T)Command->ReadLength, KernelMode, &PCopied);

		/*
		 * ⚠ MmCopyVirtualMemory IS ALL-OR-NOTHING, so "partial is reported" was a promise this
		 * handler could not keep. measured against a page whose neighbour is reserved
		 * but not committed: it returned STATUS_PARTIAL_COPY with ZERO bytes transferred. The
		 * readable first page was simply lost, and the caller got "unreadable" for a region that
		 * was half readable.
		 *
		 * That matters for exactly the targets this tool exists for. A packed or partly paged-out
		 * image is the normal case, not the exception, and discarding everything because the range
		 * ENDS badly throws away the artifact.
		 *
		 * So on a failed bulk copy, retry PAGE BY PAGE and keep what works. The bulk path stays
		 * first because it is one call for the common case; this runs only when it did not.
		 */
		if (!NT_SUCCESS(PSt) && PCopied == 0 && Command->ReadLength > PAGE_SIZE)
		{
			CONST UINT64 Start = Command->ReadOffset;
			SIZE_T Done = 0;

			while (Done < Command->ReadLength)
			{
				CONST UINT64 At = Start + Done;
				/* Stop at the next page boundary so one bad page cannot cost a good one. */
				SIZE_T Chunk = PAGE_SIZE - (SIZE_T)(At & (PAGE_SIZE - 1));
				if (Chunk > (SIZE_T)Command->ReadLength - Done)
					Chunk = (SIZE_T)Command->ReadLength - Done;

				SIZE_T Got = 0;
				CONST NTSTATUS St =
					MmCopyVirtualMemory(Target, (PVOID)(ULONG_PTR)At,
					                    PsGetCurrentProcess(),
					                    (PVOID)(ULONG_PTR)(PFirst + Done),
					                    Chunk, KernelMode, &Got);
				if (!NT_SUCCESS(St) || Got != Chunk)
					break;               /* first unreadable page ends it; keep everything before */

				Done += Chunk;
			}

			if (Done != 0)
			{
				PCopied = Done;
				/* Still PARTIAL, and still says so. The status is the reason it stopped, not a
				 * complaint about the bytes that did arrive. */
				PSt = STATUS_PARTIAL_COPY;
				CmdLog("cmd: read-proc pid %u @0x%llX -- bulk copy failed, page-wise recovered "
				       "%llu of %u bytes\n",
				       Command->TargetModuleId, Command->ReadOffset,
				       (ULONG64)Done, Command->ReadLength);
			}
		}

		ObfDereferenceObject(Target);

		/*
		 * PARTIAL IS REPORTED, NOT DISCARDED. A region can be partly paged out or partly unmapped,
		 * and the readable part is still the artifact. BytesRead carries what actually landed;
		 * NtStatus carries why it stopped.
		 */
		Command->BytesRead = (NXCMD_U32)PCopied;
		Command->NtStatus  = (NXCMD_U64)(ULONG_PTR)PSt;

		if (PCopied == 0)
		{
			CmdLog("cmd: read-proc pid %u @0x%llX -- unreadable 0x%08X\n",
			       Command->TargetModuleId, Command->ReadOffset, PSt);
			Command->Result = NXCMD_RESULT_REFUSED;
			return PSt;
		}

		Command->Result = NXCMD_RESULT_OK;
		CmdLog("cmd: read-proc pid %u @0x%llX -> %llu of %u bytes\n",
		       Command->TargetModuleId, Command->ReadOffset,
		       (ULONG64)PCopied, Command->ReadLength);
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_PHYS_RANGES:
	{
		/*
		 * The machine's RAM map. Exists so READ_PHYS's refusal is actionable rather than a black box.
		 */
		Command->BytesRead  = 0;
		Command->ModuleBase = 0;
		Command->ModuleSize = 0;

		CONST NXCMD_U64 RFirst = Command->OutBuffer;
		CONST NXCMD_U64 RLast  = RFirst + (NXCMD_U64)Command->ReadLength;
		if (Command->ReadLength < sizeof(NXCMD_PHYS_RANGE) ||
		    Command->ReadLength > NXCMD_READ_MAX ||
		    RFirst < NXC_USER_VA_FLOOR || RLast > NXC_USER_VA_CEILING || RLast <= RFirst)
		{
			Command->Result = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_ADDRESS;
			return STATUS_INVALID_ADDRESS;
		}

		CONST NXCMD_U32 RCap = Command->ReadLength / (NXCMD_U32)sizeof(NXCMD_PHYS_RANGE);
		CONST NXCMD_U32 RBytes = RCap * (NXCMD_U32)sizeof(NXCMD_PHYS_RANGE);

		NXCMD_PHYS_RANGE* CONST RBuf =
			(NXCMD_PHYS_RANGE*)ExAllocatePool2(POOL_FLAG_NON_PAGED, RBytes, 'rPxN');
		if (RBuf == NULL)
		{
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INSUFFICIENT_RESOURCES;
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		NXCMD_U32 RGot = 0, RTotal = 0;
		CONST NTSTATUS RStatus = NxcPhysRanges(RBuf, RCap, &RGot, &RTotal);
		if (!NT_SUCCESS(RStatus))
		{
			ExFreePoolWithTag(RBuf, 'rPxN');
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)RStatus;
			return RStatus;
		}

		SIZE_T RCopied = 0;
		CONST NTSTATUS ROut =
			MmCopyVirtualMemory(PsGetCurrentProcess(), RBuf,
			                    PsGetCurrentProcess(), (PVOID)(ULONG_PTR)RFirst,
			                    RGot * sizeof(NXCMD_PHYS_RANGE), KernelMode, &RCopied);
		ExFreePoolWithTag(RBuf, 'rPxN');

		if (!NT_SUCCESS(ROut))
		{
			Command->Result = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)ROut;
			return ROut;
		}

		/* D3: returned and existing stay separate, so truncation can never read as completeness. */
		Command->BytesRead  = RGot;     /* entries returned */
		Command->ModuleSize = RTotal;   /* entries that exist */
		Command->NtStatus   = (NXCMD_U64)(ULONG_PTR)ROut;
		Command->Result     = NXCMD_RESULT_OK;
		CmdLog("cmd: phys-ranges -> %u of %u ranges\n", RGot, RTotal);
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_LOG_DRAIN:
	{
		Command->BytesRead  = 0;
		Command->ModuleBase = 0;
		Command->ModuleSize = 0;

		CONST NXCMD_U64 GFirst = Command->OutBuffer;
		CONST NXCMD_U64 GLast  = GFirst + (NXCMD_U64)Command->ReadLength;
		if (Command->ReadLength < sizeof(NXCMD_LOG_ENTRY) ||
		    Command->ReadLength > NXCMD_READ_MAX ||
		    GFirst < NXC_USER_VA_FLOOR || GLast > NXC_USER_VA_CEILING || GLast <= GFirst)
		{
			Command->Result = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_ADDRESS;
			return STATUS_INVALID_ADDRESS;
		}

		CONST NXCMD_U32 GCap = Command->ReadLength / (NXCMD_U32)sizeof(NXCMD_LOG_ENTRY);
		NXCMD_LOG_ENTRY* CONST GBuf =
			(NXCMD_LOG_ENTRY*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
			                                  GCap * sizeof(NXCMD_LOG_ENTRY), 'gLxN');
		if (GBuf == NULL)
		{
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INSUFFICIENT_RESOURCES;
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		NXCMD_U32 GGot = 0, GLost = 0;
		NXCMD_U64 GHead = 0;
		CONST NTSTATUS GSt = NxcLogRingDrain(Command->ReadOffset, GBuf, GCap,
		                                     &GGot, &GLost, &GHead);
		if (!NT_SUCCESS(GSt))
		{
			ExFreePoolWithTag(GBuf, 'gLxN');
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)GSt;
			return GSt;
		}

		SIZE_T GCopied = 0;
		CONST NTSTATUS GOut =
			MmCopyVirtualMemory(PsGetCurrentProcess(), GBuf,
			                    PsGetCurrentProcess(), (PVOID)(ULONG_PTR)GFirst,
			                    GGot * sizeof(NXCMD_LOG_ENTRY), KernelMode, &GCopied);
		ExFreePoolWithTag(GBuf, 'gLxN');

		if (!NT_SUCCESS(GOut))
		{
			Command->Result = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)GOut;
			return GOut;
		}

		Command->BytesRead  = GGot;     /* entries returned                       */
		Command->ModuleSize = GLost;    /* entries OVERWRITTEN before we got them */
		Command->ModuleBase = GHead;    /* where to resume                        */
		Command->Result     = NXCMD_RESULT_OK;
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_ALIAS_TEST:
	{
		/*
		 * Stage 1 of the inline hook: prove the writable alias against our OWN page. Installs
		 * nothing. Detail names the step that failed so a red result is actionable rather than
		 * merely negative.
		 */
		NXCMD_U32 Detail = 0;
		CONST NTSTATUS ASt = NxcAliasSelfTest(&Detail);

		Command->BytesRead  = Detail;
		Command->NtStatus   = (NXCMD_U64)(ULONG_PTR)ASt;
		Command->Result     = NT_SUCCESS(ASt) ? NXCMD_RESULT_OK : NXCMD_RESULT_REFUSED;
		return ASt;
	}

	case NXCMD_OP_HOOK_INSTALL:
	{
		/*
		 * ⚠ ModuleBase CARRIES THE MEASURED DISPLACEMENT ON EVERY PATH, INCLUDING FAILURE. It is the
		 * number that turns "out of range" into something actionable: 40 bytes over says find a
		 * nearer stub, 4 GB over says the arena will never reach this target and a code cave in the
		 * module's own padding is the only route. Reporting only "REFUSED" would hide the difference.
		 */
		NXCMD_U32 Detail = 0, Stolen = 0;
		INT64     Delta  = 0;

		/*
		 * Flags come from the caller's Flags word, MASKED to the bits this opcode defines, so an
		 * unknown bit set by a newer PlatformCtl cannot turn into a behaviour.
		 *
		 * ⚠ THE MASK IS A LIST AND MUST BE EXTENDED WITH THE LIST. It read `& NXC_HOOK_FLAG_LOG`
		 * alone, so when LBR and PROBE were added the mask silently stripped them: `hook --lbr`
		 * would have installed a plain logging hook, reported success, and captured nothing --
		 * indistinguishable from a hook that never fired. Found by reading the call site rather than
		 * by the failure, which would have looked like an LBR bug for as long as it took to notice.
		 */
		/* ⚠ ONE NAME, DEFINED BESIDE THE FLAGS IT ACCEPTS -- see NXC_HOOK_FLAG_ALL in Hook.h. This
		 * was a spelled-out list here and silently dropped newly added flags twice, most recently on
		 * when CALLS/OBJATTR3/USTR2 were stripped and three hardware phases proved
		 * nothing. There is no longer a list at this site to forget to extend. */
		CONST NXCMD_U32 HookFlagMask = NXC_HOOK_FLAG_ALL;

		/*
		 * A NAME may stand in for the address (B-01/B-02: the Nt* entry points a minifilter or an
		 * ObRegisterCallbacks registration would have covered). Resolution failure is REFUSED here
		 * and never falls through to NxcHookInstall(0, ...) -- that would refuse for the wrong
		 * reason and print a delta measured against address zero.
		 */
		UINT64 HookVa = 0;
		CONST NTSTATUS RSt = NxcResolveHookTarget(Command, &HookVa);
		if (!NT_SUCCESS(RSt))
		{
			Command->BytesRead  = 0;
			Command->ModuleSize = 0;
			Command->ModuleBase = 0;
			Command->NtStatus   = (NXCMD_U64)(ULONG_PTR)RSt;
			Command->Result     = NXCMD_RESULT_REFUSED;
			return RSt;
		}

		/*
		 * ⚠ TargetModuleId CARRIES THE PID FILTER for this opcode, and 0 means every process.
		 *
		 * It is an INPUT field, unused by hook resolution (which takes ReadOffset or TargetName),
		 * and it already means "pid" for READ_PROC -- so the name stays true rather than flipping
		 * meaning by opcode, which the struct's own contract calls out as the ambiguity that costs
		 * a reboot to diagnose. Not smuggled through Flags: a pid is not a flag.
		 */
		CONST NTSTATUS HSt = NxcHookInstall(HookVa,
		                                    (NXCMD_U32)(Command->Flags & HookFlagMask),
		                                    Command->TargetModuleId,
		                                    &Detail, &Delta, &Stolen);

		/*
		 * ⚠ RUN THE STATIC EFLAGS ORACLE HERE, AGAINST THE VA ACTUALLY BEING HOOKED. Deriving it from
		 * a separately-resolved address would create a second source of truth for "which funnel", and
		 * this project has already been bitten by install and remove computing their target
		 * independently (an earlier finding).
		 *
		 * ⚠ ITS ANSWER IS A CROSS-CHECK, NOT THE VALUE USED -- see NxcBpdSetEflagsOffset. Failure is
		 * deliberately NOT propagated: the live derivation is the authority and works without this,
		 * so a static oracle that finds nothing must not take the dispatcher hook down with it.
		 */
		if (NT_SUCCESS(HSt) && (Command->Flags & NXC_HOOK_FLAG_EXCEPTION) != 0)
		{
			/*
			 * ⚠⚠ THE DERIVATION ANCHORS ON THE **FUNNEL**, AND THIS PASSED IT THE **DISPATCHER**.
			 * Four boots of "(not derived)" and two fixes aimed at the wrong cause came from this one
			 * line. `bp dispatch install` hooks the DISPATCHER (ntoskrnl+0x3D68F0, function
			 * 0x3D6820..0x3D6ADD), so Command->ReadOffset is that. But the EFLAGS.IF test lives at
			 * ntoskrnl+0x6BFCB0, inside the FUNNEL'S function 0x6BFC00..0x6C0101 -- a different region
			 * entirely. The scan was searching a function that never contained the pattern, and said
			 * so as "not derived", which reads as a statement about the kernel.
			 *
			 * ⚠ ONE RESOLUTION, TWO CONSUMERS. The funnel arrives in ImageBuffer (unused by this
			 * opcode) from the SAME DispResolve call that produced the hook target, so the two can
			 * never drift -- deriving it separately here would be the second source of truth that
			 * An earlier finding is about.
			 *
			 * ⚠ AND ZERO IS REFUSED, NOT SUBSTITUTED. An older PlatformCtl sends nothing here; falling
			 * back to ReadOffset would silently reinstate exactly the bug above.
			 */
			CONST UINT64 FunnelVa = Command->ImageBuffer;
			if (FunnelVa >= 0xFFFF800000000000ull)
			{
				/* Kept for the R12-R15 derivation, which runs later, at ARM time. */
				NxcBpdSetFunnelVa(FunnelVa);
				UINT32 EfOffset = 0, EfSites = 0;
				CONST NTSTATUS ESt = NxcIdtDeriveEflagsOffset(FunnelVa, &EfOffset, &EfSites);
				NxcBpdSetEflagsOffset(NT_SUCCESS(ESt) ? EfOffset : 0u);
			}
			else
			{
				NxcBpdSetEflagsOffset(0u);
				NxcLogExt("hook: EFlags cross-check SKIPPED -- no funnel VA supplied (ImageBuffer=%llX). "
				          "The caller is older than the fix; this is not a statement about the kernel.\n",
				          Command->ImageBuffer);
			}
		}

		Command->BytesRead  = Detail;
		Command->ModuleSize = Stolen;
		Command->ModuleBase = (NXCMD_U64)Delta;
		Command->NtStatus   = (NXCMD_U64)(ULONG_PTR)HSt;
		Command->Result     = NT_SUCCESS(HSt) ? NXCMD_RESULT_OK : NXCMD_RESULT_REFUSED;
		return HSt;
	}

	case NXCMD_OP_THREADS:
	{
		Command->BytesRead  = 0;
		Command->ModuleSize = 0;

		CONST NXCMD_U64 TFirst = Command->OutBuffer;
		CONST NXCMD_U64 TLast  = TFirst + (NXCMD_U64)Command->ReadLength;
		if (Command->ReadLength < sizeof(NXCMD_THREAD_ENTRY) ||
		    Command->ReadLength > NXCMD_READ_MAX ||
		    TFirst < NXC_USER_VA_FLOOR || TLast > NXC_USER_VA_CEILING || TLast <= TFirst)
		{
			Command->Result   = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_ADDRESS;
			return STATUS_INVALID_ADDRESS;
		}

		CONST NXCMD_U32 TCap = Command->ReadLength / (NXCMD_U32)sizeof(NXCMD_THREAD_ENTRY);
		NXCMD_THREAD_ENTRY* CONST TBuf =
			(NXCMD_THREAD_ENTRY*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
			                                     (SIZE_T)TCap * sizeof(NXCMD_THREAD_ENTRY), 'rTxN');
		if (TBuf == NULL)
		{
			Command->Result   = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INSUFFICIENT_RESOURCES;
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		NXCMD_U32 TGot = 0, TTotal = 0, TSwept = 0;
		CONST NTSTATUS TSt = NxcEnumThreads(Command->TargetModuleId, TBuf, TCap,
		                                    &TGot, &TTotal, &TSwept);
		if (!NT_SUCCESS(TSt))
		{
			ExFreePoolWithTag(TBuf, 'rTxN');
			Command->Result   = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)TSt;
			return TSt;
		}

		SIZE_T TCopied = 0;
		CONST NTSTATUS TOut =
			MmCopyVirtualMemory(PsGetCurrentProcess(), TBuf,
			                    PsGetCurrentProcess(), (PVOID)(ULONG_PTR)TFirst,
			                    (SIZE_T)TGot * sizeof(NXCMD_THREAD_ENTRY), KernelMode, &TCopied);
		ExFreePoolWithTag(TBuf, 'rTxN');

		if (!NT_SUCCESS(TOut))
		{
			Command->Result   = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)TOut;
			return TOut;
		}

		/* D3: what was produced, and what EXISTS, never one standing in for the other. */
		Command->BytesRead  = TGot;
		Command->ModuleSize = TTotal;
		Command->ModuleBase = TSwept;
		Command->Result     = NXCMD_RESULT_OK;
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_LBR_ARM:
	{
		Command->BytesRead  = 0;
		Command->ModuleSize = 0;
		Command->ModuleBase = 0;

		NXCMD_U32 Armed = 0, Contended = 0, Unsupported = 0;
		CONST NTSTATUS ASt = NxcLbrArm(Command->Flags, &Armed, &Contended, &Unsupported);

		/*
		 * ⚠ THE COUNTS ARE REPORTED ON FAILURE TOO. "Refused" alone would leave the caller unable to
		 * tell a contended facility from an incapable one, and those need opposite responses: find
		 * the owner, versus stop asking for that filter.
		 */
		Command->BytesRead  = Armed;
		Command->ModuleSize = Contended;
		Command->ModuleBase = Unsupported;

		if (!NT_SUCCESS(ASt))
		{
			Command->Result   = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)ASt;
			return ASt;
		}

		Command->Result = NXCMD_RESULT_OK;
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_BP_DISPATCH_STATUS:
	{
		UINT64 Seen = 0, Db = 0, Bp = 0, Rej = 0;
		NxcBpdObserverCounters(&Seen, &Db, &Bp, &Rej);

		UINT64 Zero = 0, Small = 0, User = 0, Looks = 0, NotRec = 0;
		NxcBpdArgShape(&Zero, &Small, &User, &Looks, &NotRec);

		Command->BytesRead  = (NXCMD_U32)(Seen & 0xFFFFFFFFu);
		Command->ModuleSize = (NXCMD_U32)(Db & 0xFFFFFFFFu);
		Command->ModuleBase = Bp;
		Command->ReadOffset = Rej;

		/*
		 * The shape buckets ride in the OutBuffer as five qwords rather than a struct: this opcode
		 * takes no user buffer otherwise, and adding a wire struct for a diagnostic that exists to
		 * answer ONE question would outlive the question.
		 */
		/*
		 * ⚠ LAYOUT GREW (14 qwords -> 16 + 2*16). The histogram of distinct arg1 codes
		 * is appended AFTER the existing fields, so an older reader that asks for the old length
		 * still gets exactly what it expects -- the copy is gated on the caller's ReadLength being
		 * large enough for the WHOLE block, and a short buffer now yields nothing rather than a
		 * half-written one.
		 */
		/*
		 * ⚠⚠ THE RANGE CHECK USED TO COVER 112 BYTES AND THE COPY WRITES 968.
		 *
		 * `112u` was the size of this block before it grew. NXCMD_BPD_SHAPE_QWORDS is now
		 * 5+1+8+2+4*16+6+24+7+4 = 121 qwords = 968 bytes, and the MmCopyVirtualMemory below writes
		 * sizeof(Shape) -- so the VA range was validated for one eighth of what is written. A caller
		 * passing an OutBuffer within 968 bytes of NXC_USER_VA_CEILING, with a ReadLength large
		 * enough to satisfy the inner gate, had the kernel attempt a write crossing the ceiling.
		 *
		 * ⚠ THE CONSEQUENCE IS A SILENT PARTIAL, NOT CORRUPTION, and that is worth stating exactly:
		 * MmCopyVirtualMemory VALIDATES and returns a status rather than raising -- which is why it
		 * is used here -- and the call is `(void)`-cast, so the failure was discarded and the caller
		 * got an unfilled buffer with no error. The bound was wrong; the copy primitive covered for
		 * it.
		 *
		 * ⚠ AND THIS FILE ALREADY RECORDED THE SAME DRIFT ONCE: see the note near the Shape[]
		 * comment about the kernel growing by seven qwords while usermode did not. That one was
		 * fixed by giving both sides ONE macro. This check was left holding a literal.
		 *
		 * Now derived from the same macro as the array, so it cannot drift from what is written.
		 */
		if (Command->OutBuffer >= NXC_USER_VA_FLOOR &&
		    Command->OutBuffer + (NXCMD_BPD_SHAPE_QWORDS * sizeof(NXCMD_U64))
		        <= NXC_USER_VA_CEILING &&
		    Command->ReadLength >= (NXCMD_BPD_SHAPE_QWORDS * sizeof(NXCMD_U64)))
		{
			/* ⚠ ONE SHARED SIZE, NOT A SECOND COPY OF THE ARITHMETIC. Usermode allocates from the
			 * same macro; when this was two expressions they drifted by exactly NXC_BPD_TR_COUNT and
			 * the whole block went to zero. See the note on NXCMD_BPD_SHAPE_QWORDS. */
			UINT64 Shape[NXCMD_BPD_SHAPE_QWORDS];
			RtlZeroMemory(Shape, sizeof(Shape));
			Shape[0] = Zero; Shape[1] = Small; Shape[2] = User;
			Shape[3] = Looks; Shape[4] = NotRec;

			/* ...and WHO called the hooked function, which is what names it offline. */
			UINT64 Callers[NXC_BPD_MAX_CALLERS];
			UINT32 CallerCount = 0;
			NxcBpdCallers(Callers, &CallerCount);
			Shape[5] = CallerCount;
			for (UINT32 i = 0; i < NXC_BPD_MAX_CALLERS; i++)
				Shape[6 + i] = Callers[i];

			/* ...and WHICH codes were actually seen, which is what turns "98 were something
			 * else" from a number into a finding. */
			UINT32 Codes[NXC_BPD_MAX_CODES];
			UINT64 Hits[NXC_BPD_MAX_CODES];
			UINT64 FirstRa[NXC_BPD_MAX_CODES];
			UINT64 ExcAddr[NXC_BPD_MAX_CODES];
			UINT32 CodeCount = 0;
			UINT64 CodeOverflow = 0;
			NxcBpdCodeHistogram(Codes, Hits, FirstRa, ExcAddr, &CodeCount, &CodeOverflow);

			/* The claim path's falsifiable control. Surfaced here rather than left in BpLog --
			 * a counter the operator cannot read is the mistake this session already made once. */
			UINT64 ClCls = 0, ClWould = 0, ClNot = 0;
			UINT32 ClWhy = 0, ClSlot = 0;
			NxcBpdClaimStats(&ClCls, &ClWould, &ClNot, &ClWhy, &ClSlot);

			CONST UINT32 CodeBase = 6u + NXC_BPD_MAX_CALLERS;
			Shape[CodeBase + 0] = CodeCount;
			Shape[CodeBase + 1] = CodeOverflow;

			for (UINT32 i = 0; i < NXC_BPD_MAX_CODES; i++)
			{
				Shape[CodeBase + 2 + 0 * NXC_BPD_MAX_CODES + i] = (UINT64)Codes[i];
				Shape[CodeBase + 2 + 1 * NXC_BPD_MAX_CODES + i] = Hits[i];
				Shape[CodeBase + 2 + 2 * NXC_BPD_MAX_CODES + i] = FirstRa[i];
				Shape[CodeBase + 2 + 3 * NXC_BPD_MAX_CODES + i] = ExcAddr[i];
			}

			/* ...and the claim path's control, AFTER the histogram so an older reader that
			 * asks for the old length still gets exactly what it expects. */
			CONST UINT32 ClaimBase = CodeBase + 2u + 4u * NXC_BPD_MAX_CODES;
			Shape[ClaimBase + 0] = ClCls;
			Shape[ClaimBase + 1] = ClWould;
			Shape[ClaimBase + 2] = ClNot;
			Shape[ClaimBase + 3] = ClWhy;
			Shape[ClaimBase + 4] = ClSlot;
			Shape[ClaimBase + 5] = NxcBpdForeignSuppressed();

			/*
			 * ⚠ THE TRAP-FRAME DERIVATION AND ITS CROSS-CHECK. Both methods' answers are carried,
			 * never just the winner: the static one was measured WRONG (it recovers a
			 * displacement off a BIASED frame pointer, so its raw answer 0xF8 is Dr6, not EFlags at
			 * 0x178) and the only reason that was caught is that somebody could see both numbers.
			 * Reporting one reconciled value would have hidden exactly the thing worth seeing.
			 */
			UINT32 EfOff = 0; UINT64 EfTried = 0, EfAgree = 0, EfDis = 0;
			NxcBpdEflagsCheck(&EfOff, &EfTried, &EfAgree, &EfDis);

			UINT32 EfStatic = 0, EfStaticOk = 0; UINT64 EfNoMatch = 0;
			NxcBpdEflagsCross(&EfStatic, &EfStaticOk, &EfNoMatch);

			UINT32 EfProvenOff = 0;
			CONST BOOLEAN EfProven = NxcBpdEflagsProven(&EfProvenOff);

			CONST UINT32 EfBase = ClaimBase + 6u;
			Shape[EfBase + 0] = EfOff;
			Shape[EfBase + 1] = EfTried;
			Shape[EfBase + 2] = EfAgree;
			Shape[EfBase + 3] = EfDis;
			Shape[EfBase + 4] = EfStatic;
			Shape[EfBase + 5] = EfStaticOk;
			Shape[EfBase + 6] = EfNoMatch;
			Shape[EfBase + 7] = EfProven ? 1ull : 0ull;

			/* What the offset is FOR: resuming execute breakpoints. Carried beside the derivation so
			 * "proven but never used" and "used and failing" are distinguishable states. */
			UINT64 RfWrites = 0, RfRefused = 0;
			NxcBpdRfStats(&RfWrites, &RfRefused);
			Shape[EfBase + 8] = RfWrites;
			Shape[EfBase + 9] = RfRefused;

			/* WHY the derivation yielded nothing, split so geometry and a real frame-shape finding
			 * stop sharing one number. */
			UINT64 EfStrad = 0, EfRipGone = 0, EfTailBad = 0;
			NxcBpdEflagsFailBreakdown(&EfStrad, &EfRipGone, &EfTailBad);
			Shape[EfBase + 10] = EfStrad;
			Shape[EfBase + 11] = EfRipGone;
			Shape[EfBase + 12] = EfTailBad;

			/*
			 * ⚠ THE GPR MAP'S ACTUAL STATE. Its derivation logs through NxcLogExt, which reaches
			 * DbgPrint and NOT the log ring -- so on a machine without a kernel debugger the only
			 * evidence was "ABSENT" in a hit record, which cannot distinguish "never attempted"
			 * from "attempted and refused at gate N". Carrying the state makes it readable.
			 */
			NXC_GPR_MAP Gm;
			CONST BOOLEAN GmValid = NxcBpdGprMap(&Gm);
			Shape[EfBase + 13] = GmValid ? 1ull : 0ull;
			Shape[EfBase + 14] = Gm.Bias;
			Shape[EfBase + 15] = Gm.Offset[NXC_GPR_RAX];
			Shape[EfBase + 16] = Gm.EflagsSeen;

			UINT32 GprTried = 0, GprStatus = 0, GprGate = 0;
			NxcBpdGprStatus(&GprTried, &GprStatus, &GprGate);
			Shape[EfBase + 17] = GprTried;
			Shape[EfBase + 18] = GprStatus;
			Shape[EfBase + 19] = GprGate;
			Shape[EfBase + 20] = Gm.Begin;
			Shape[EfBase + 21] = Gm.First[0];
			Shape[EfBase + 22] = Gm.First[1];
			Shape[EfBase + 23] = NxcBpdEscapes();

			/*
			 * ⚠ WHICH CHECK REJECTED THE TAIL. EfTailBad above is a single number covering EIGHT
			 * distinct rejections, and it is the last unexplained figure in this surface (2-24 per
			 * run). Split so a pile-up names its own cause -- and note that a pile-up on _CS means
			 * SPURIOUS RIP MATCHES during the ~70-offset sweep, not malformed tails.
			 */
			{
				UINT64 Tr[NXC_BPD_TR_COUNT];
				NxcBpdTailRejectBreakdown(Tr);
				for (UINT32 t = 0; t < NXC_BPD_TR_COUNT; t++)
					Shape[EfBase + 24 + t] = Tr[t];

				/* ⚠ AND A WITNESS. The category still needs the VALUES that produced it -- "SS
				 * implausible" is consistent with a legal null SS in a ring-0 frame AND with a
				 * spurious match, and only the selectors tell them apart. */
				UINT64 WCs = 0, WSs = 0, WWhy = 0;
				NxcBpdTailRejectWitness(&WCs, &WSs, &WWhy);
				Shape[EfBase + 24 + NXC_BPD_TR_COUNT + 0] = WCs;
				Shape[EfBase + 24 + NXC_BPD_TR_COUNT + 1] = WSs;
				Shape[EfBase + 24 + NXC_BPD_TR_COUNT + 2] = WWhy;
				Shape[EfBase + 24 + NXC_BPD_TR_COUNT + 3] = NxcBpdTailNullSsAccepted();
			}

			SIZE_T Copied = 0;
			if (Command->ReadLength >= sizeof(Shape))
				(void)MmCopyVirtualMemory(PsGetCurrentProcess(), Shape,
				                          PsGetCurrentProcess(),
				                          (PVOID)(ULONG_PTR)Command->OutBuffer,
				                          sizeof(Shape), KernelMode, &Copied);
		}
		Command->Result     = NXCMD_RESULT_OK;
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_BP_SET:
	{
		Command->BytesRead  = 0;
		Command->ModuleSize = 0;

		/* Type and length are FLAGS (bits), decoded here into the DR7 encodings. The DR7 LEN field
		 * is 00=1, 01=2, 10=8, 11=4 -- NOT in numeric order, which is exactly the kind of table a
		 * caller should never be asked to know. */
		CONST NXCMD_U32 F = Command->Flags;
		CONST NXCMD_U32 Type = (F & NXCMD_BP_SET_RW) ? 3u : (F & NXCMD_BP_SET_WRITE) ? 1u : 0u;
		CONST NXCMD_U32 Len  = (F & NXCMD_BP_SET_LEN8) ? 2u
		                     : (F & NXCMD_BP_SET_LEN4) ? 3u
		                     : (F & NXCMD_BP_SET_LEN2) ? 1u : 0u;

		NXCMD_U32 Slot = 0, Threads = 0;
		UINT64 Diag = 0, Diag2 = 0;
		CONST NTSTATUS SSt = NxcBpSet(Command->TargetModuleId, Command->ReadOffset,
		                              Type, Len, &Slot, &Threads, &Diag, &Diag2);

		Command->BytesRead  = Slot;
		Command->ModuleSize = Threads;
		/* Packed arming breakdown -- see NxcBpSet's OutDiag. Carried so usermode can PRINT the
		 * reason instead of inferring one; a breakdown that only reaches DbgPrint is not reported. */
		Command->ModuleBase = Diag;
		Command->ReadOffset = Diag2;   /* which call refused, and with what -- see NxcBpSet */
		Command->NtStatus   = (NXCMD_U64)(ULONG_PTR)SSt;
		Command->Result     = NT_SUCCESS(SSt) ? NXCMD_RESULT_OK : NXCMD_RESULT_REFUSED;
		return SSt;
	}

	case NXCMD_OP_BP_HITS:
	{
		Command->BytesRead  = 0;
		Command->ModuleSize = 0;
		Command->ModuleBase = 0;

		/*
		 * ⚠ THE TOTAL AND THE DROP COUNT ARE REPORTED EVEN WHEN NO BUFFER IS SUPPLIED, and even when
		 * the copy fails. "How many hits happened" is a different question from "how many did you
		 * manage to hand back", and D3 says report what was ACTUALLY produced -- a caller that gets
		 * 12 records must be able to tell whether that was all of them.
		 */
		/* ⚠ CLEARED BEFORE READING, so `--clear` on its own returns the empty state it just made
		 * rather than one last copy of what it discarded. */
		if ((Command->Flags & NXCMD_BP_HITS_CLEAR) != 0)
			NxcBpdHitsClear();

		UINT32 Held = 0;
		UINT64 Total = 0, Dropped = 0;
		NxcBpdHitStats(&Held, &Total, &Dropped);

		Command->ModuleSize = (NXCMD_U32)(Total & 0xFFFFFFFFu);
		Command->ModuleBase = Dropped;

		CONST NXCMD_U64 HFirst = Command->OutBuffer;
		CONST NXCMD_U64 HLast  = HFirst + (NXCMD_U64)Command->ReadLength;

		if (Command->ReadLength < sizeof(NXC_BPD_HIT) ||
		    Command->ReadLength > NXCMD_READ_MAX ||
		    HFirst < NXC_USER_VA_FLOOR || HLast > NXC_USER_VA_CEILING || HLast <= HFirst)
		{
			Command->Result   = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_ADDRESS;
			return STATUS_INVALID_ADDRESS;
		}

		/*
		 * ⚠ ONE RECORD PER COPY, AND THAT IS DELIBERATE. Staging all 64 in a local array puts 5.6 KB
		 * on the stack, which MSVC answers with a `__chkstk` call -- a real import in a payload that
		 * carries no import table. The build gate rejected exactly that, so the loop is the fix
		 * rather than a larger frame.
		 */
		CONST UINT32 Fits = (UINT32)(Command->ReadLength / sizeof(NXC_BPD_HIT));
		UINT32 Given = 0;
		NTSTATUS HSt2 = STATUS_SUCCESS;

		for (UINT32 i = 0; i < Held && Given < Fits; i++)
		{
			NXC_BPD_HIT One;
			if (!NxcBpdHitAt(i, &One))
				continue;   /* empty or mid-write -- skipped, never half-reported */

			SIZE_T Copied = 0;
			HSt2 = MmCopyVirtualMemory(PsGetCurrentProcess(), &One,
			                           PsGetCurrentProcess(),
			                           (PVOID)(ULONG_PTR)(HFirst + (NXCMD_U64)Given * sizeof(NXC_BPD_HIT)),
			                           sizeof(NXC_BPD_HIT), KernelMode, &Copied);

			if (!NT_SUCCESS(HSt2) || Copied != sizeof(NXC_BPD_HIT))
				break;      /* ⚠ STOP AT THE FIRST FAILURE; BytesRead then states what LANDED */

			Given++;
		}

		/* ⚠ THE COUNT IS WHAT LANDED, not what was asked for and not what was held. */
		Command->BytesRead = Given;
		Command->NtStatus  = (NXCMD_U64)(ULONG_PTR)HSt2;
		Command->Result    = NT_SUCCESS(HSt2) ? NXCMD_RESULT_OK : NXCMD_RESULT_COPY_FAILED;
		return HSt2;
	}

	case NXCMD_OP_BP_CLAIM_ENABLE:
	{
		NxcBpdClaimEnable(Command->TargetModuleId);

		/* ⚠ DIAGNOSTIC: ReadLength carries a countdown of RF writes to SUPPRESS, so the escape
		 * branch can be exercised. Zero on every normal call, which is what `bp claim on` sends. */
		if (Command->ReadLength != 0)
			NxcBpdForceRfFail((UINT32)Command->ReadLength);
		UINT32 En = 0; UINT64 Cl = 0, Rf = 0;
		NxcBpdClaimState(&En, &Cl, &Rf);
		Command->BytesRead  = En;
		Command->ModuleSize = (NXCMD_U32)Cl;
		Command->ModuleBase = Rf;
		Command->Result     = NXCMD_RESULT_OK;
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_BP_GSET:
	{
		/* Same DR7 encodings as BP_SET -- decoded from flags in ONE place so the global and
		 * per-thread paths can never disagree about which bit pattern means what. */
		CONST NXCMD_U32 F = Command->Flags;
		CONST NXCMD_U32 Type = (F & NXCMD_BP_SET_RW) ? 3u : (F & NXCMD_BP_SET_WRITE) ? 1u : 0u;
		CONST NXCMD_U32 Len  = (F & NXCMD_BP_SET_LEN8) ? 2u
		                     : (F & NXCMD_BP_SET_LEN4) ? 3u
		                     : (F & NXCMD_BP_SET_LEN2) ? 1u : 0u;

		NXCMD_U32 Slot = 0, Cpus = 0;
		CONST NTSTATUS GSt = NxcBpSetGlobal(Command->TargetModuleId, Command->ReadOffset,
		                                    Type, Len, &Slot, &Cpus);
		/* ⚠ THE OPT-IN IS RECORDED ONLY ON SUCCESS. Setting it for a slot that failed to arm would
		 * leave the flag on a free slot, and the NEXT arming would silently inherit the toggle. */
		if (NT_SUCCESS(GSt))
			NxcBpSlotSetPtBound(Slot, (F & NXCMD_BP_SET_PTBOUND) != 0);

		Command->BytesRead  = Slot;
		Command->ModuleSize = Cpus;
		Command->NtStatus   = (NXCMD_U64)(ULONG_PTR)GSt;
		Command->Result     = NT_SUCCESS(GSt) ? NXCMD_RESULT_OK : NXCMD_RESULT_REFUSED;
		return GSt;
	}

	case NXCMD_OP_BP_FORK:
	{
		/*
		 * ⚠ ImageBuffer CARRIES THE SECOND ADDRESS, not a buffer. Same reuse the dispatch-install
		 * path already makes for the funnel VA -- the field is a spare U64 on commands that map
		 * nothing, and the alternative is an ABI break for one argument. Flags are IGNORED: both
		 * sites are EXECUTE by construction, so there is nothing for a --write to mean here.
		 */
		NXCMD_U32 Slot0 = 0, Slot1 = 0, Cpus = 0;
		CONST NTSTATUS FSt = NxcBpSetFork(Command->TargetModuleId,
		                                  Command->ReadOffset, Command->ImageBuffer,
		                                  &Slot0, &Slot1, &Cpus);

		Command->BytesRead  = Slot0;
		Command->ModuleSize = Slot1;
		Command->ModuleBase = Cpus;
		Command->NtStatus   = (NXCMD_U64)(ULONG_PTR)FSt;
		Command->Result     = NT_SUCCESS(FSt) ? NXCMD_RESULT_OK : NXCMD_RESULT_REFUSED;
		return FSt;
	}

	/*
	 * ⚠ BRANCH STEPPING (D119). ARM takes the target's CR3 in ModuleBase -- CR3 and not a pid,
	 * because the dispatcher decides on the exception path where CR3 is what the hardware gives it
	 * and a pid cannot safely be resolved. ModuleSize carries the pid for REPORTING only.
	 */
	case NXCMD_OP_BP_BTF_ARM:
	{
		/*
		 * ImageBuffer carries the filter END, the same spare-U64 reuse bp fork makes for its second
		 * address. ModuleBase is the START. Both zero = record every branch.
		 */
		/* Flags bit 0 = trace RING 0 too (D120): clears IA32_FMASK bit 8 so TF survives SYSCALL. */
		CONST NTSTATUS St = NxcBtfArm((UINT32)Command->TargetModuleId,
		                              Command->ModuleBase, Command->ImageBuffer,
		                              (Command->Flags & 1u) ? TRUE : FALSE);
		/* What FMASK ACTUALLY held on cpu 0 before we touched it -- MEASURED, so the caller sees this
		 * machine's value rather than the 0x4700 the documentation quotes. */
		Command->ReadOffset = NxcBtfFmaskSaved(0);
		Command->NtStatus = (NXCMD_U64)(ULONG_PTR)St;
		Command->Result   = NT_SUCCESS(St) ? NXCMD_RESULT_OK : NXCMD_RESULT_REFUSED;
		return St;
	}

	case NXCMD_OP_BP_BTF_OFF:
	{
		CONST NTSTATUS St = NxcBtfDisarm();
		/*
		 * ⚠ ALL FOUR ON 64-BIT FIELDS. BytesRead and ReadLength are U32, and at the ~2.3M
		 * branches/sec measured on a busy target a U32 count wraps in about half an hour. A
		 * counter that silently truncates is worse than one that is absent.
		 */
		Command->ImageBuffer = NxcBtfTaken();
		Command->ModuleBase  = NxcBtfDropped();
		Command->ReadOffset  = NxcBtfTfFailed();
		Command->OutBuffer   = NxcBtfFiltered();
		Command->NtStatus   = (NXCMD_U64)(ULONG_PTR)St;
		Command->Result     = NT_SUCCESS(St) ? NXCMD_RESULT_OK : NXCMD_RESULT_REFUSED;
		return St;
	}

	case NXCMD_OP_BP_BTF_DRAIN:
	{
		NXCMD_BTF_REC* CONST Out = (NXCMD_BTF_REC*)(ULONG_PTR)Command->OutBuffer;
		CONST UINT32 Cap = (UINT32)(Command->ReadLength / sizeof(NXCMD_BTF_REC));

		if (Out == NULL || Cap == 0)
		{
			Command->Result = NXCMD_RESULT_COPY_FAILED;
			return STATUS_INVALID_PARAMETER;
		}

		UINT32 Got = 0, Left = 0;
		UINT64 Dropped = 0;
		CONST NTSTATUS St = NxcBtfDrain((NXC_BTF_REC*)Out, Cap, &Got, &Left, &Dropped);

		/* D3: what was PRODUCED, what is STILL HELD, and what was LOST -- three separate numbers. */
		Command->BytesRead  = Got;
		Command->ModuleSize = Left;
		Command->ModuleBase = Dropped;
		/* ABI gate, same as HOOK_LIST and BP_LIST: the reader refuses on a stride disagreement. */
		Command->Flags      = (NXCMD_U32)sizeof(NXCMD_BTF_REC);
		Command->NtStatus   = (NXCMD_U64)(ULONG_PTR)St;
		Command->Result     = NT_SUCCESS(St) ? NXCMD_RESULT_OK : NXCMD_RESULT_REFUSED;
		return St;
	}

	case NXCMD_OP_BP_GCLEAR:
	{
		CONST NTSTATUS CSt = NxcBpClearGlobal(Command->TargetModuleId);
		Command->NtStatus = (NXCMD_U64)(ULONG_PTR)CSt;
		Command->Result   = NT_SUCCESS(CSt) ? NXCMD_RESULT_OK : NXCMD_RESULT_REFUSED;
		return CSt;
	}

	case NXCMD_OP_BP_CTXPROBE:
	{
		UINT64 Self = 0, Same = 0, Cross = 0, Irql = 0, ApcIns = 0, ApcRan = 0, FlagProbe = 0;
		CONST NTSTATUS PSt = NxcBpCtxProbe(Command->TargetModuleId, &Self, &Same, &Cross, &Irql,
		                                   &ApcIns, &ApcRan, &FlagProbe);

		/* Each is an NTSTATUS, so 32 bits is exact -- cast explicitly rather than widen the field. */
		Command->ModuleBase = Self;                    /* current thread -- direct, no APC     */
		Command->ModuleSize = (NXCMD_U32)Same;         /* same process   -- APC rendezvous     */
		Command->ReadOffset = Cross;                   /* cross process  -- APC + attach       */
		Command->ReadLength = (NXCMD_U32)FlagProbe;    /* which ContextFlags were refused      */
		/* IRQL in the low nibble, then the direct-APC result: bit 8 = insert accepted,
		 * bit 9 = the routine actually ran. See NxcBpCtxProbe. */
		Command->BytesRead  = (NXCMD_U32)((Irql & 0xF) | (ApcIns ? 0x100u : 0u) | (ApcRan ? 0x200u : 0u));
		Command->NtStatus   = (NXCMD_U64)(ULONG_PTR)PSt;
		Command->Result     = NT_SUCCESS(PSt) ? NXCMD_RESULT_OK : NXCMD_RESULT_REFUSED;
		return PSt;
	}

	case NXCMD_OP_BP_CLEAR:
	{
		Command->BytesRead  = 0;
		Command->ModuleSize = 0;

		NXCMD_U32 Threads = 0;
		CONST NTSTATUS CSt2 = NxcBpClear(Command->TargetModuleId, &Threads);

		Command->ModuleSize = Threads;
		Command->NtStatus   = (NXCMD_U64)(ULONG_PTR)CSt2;
		Command->Result     = NT_SUCCESS(CSt2) ? NXCMD_RESULT_OK : NXCMD_RESULT_REFUSED;
		return CSt2;
	}

	case NXCMD_OP_BP_CLASSIFY:
	{
		NXCMD_U32 Ran = 0, Failed = 0, FirstBad = 0;
		CONST NTSTATUS CSt = NxcBpdSelfTest(&Ran, &Failed, &FirstBad);

		Command->BytesRead  = Ran;
		Command->ModuleSize = Failed;
		Command->ModuleBase = FirstBad;

		/*
		 * ⚠ THE IRET-TAIL SUITE RUNS HERE TOO, WITH ITS OWN COUNTS -- not folded into the numbers
		 * above. Two suites summed into one total is how a regression in the smaller one hides: the
		 * caller sees "1 failed of 20" and cannot tell WHICH mechanism broke. Packed as
		 * run<<16 | failed so both survive in one field, and reported separately by PlatformCtl.
		 *
		 * ⚠ AND IT MUST BE ABLE TO FAIL THE WHOLE COMMAND. The trap-frame offset is the precondition
		 * for execute breakpoints; a matcher that accepts a decoy is exactly the defect this suite
		 * exists to catch, so it is not permitted to fail quietly beside a passing classifier.
		 */
		NXCMD_U32 EfRan = 0, EfFailed = 0, EfFirst = 0;
		CONST NTSTATUS ESt = NxcBpdEflagsSelfTest(&EfRan, &EfFailed, &EfFirst);

		/*
		 * ⚠ A THIRD SUITE, WITH ITS OWN COUNTS AGAIN. The GPR derivation is a different mechanism
		 * from both the classifier and the IRET matcher, and summing totals is how a regression in
		 * the smallest one hides. Packed into the HIGH half so the existing low-half layout is
		 * untouched for a reader that only knows about two suites.
		 */
		NXCMD_U32 GpRan = 0, GpFailed = 0, GpFirst = 0;
		CONST NTSTATUS GSt = NxcIdtGprSelfTest(&GpRan, &GpFailed, &GpFirst);

		/* A FOURTH suite, its own counts again. R12-R15 is a different structure, a different
		 * anchor and a different proof from the volatile map; summing them would let a regression
		 * in one hide behind the other. Carried in TargetModuleId, unused on output. */
		NXCMD_U32 NvRan = 0, NvFailed = 0, NvFirst = 0;
		CONST NTSTATUS NSt = NxcIdtNvGprSelfTest(&NvRan, &NvFailed, &NvFirst);
		Command->TargetModuleId = (NvRan << 16) | NvFailed;

		Command->ReadOffset = ((NXCMD_U64)EfRan << 16) | (NXCMD_U64)EfFailed
		                    | ((NXCMD_U64)GpRan << 48) | ((NXCMD_U64)GpFailed << 32);

		NTSTATUS Worst = (!NT_SUCCESS(CSt)) ? CSt : ESt;
		if (NT_SUCCESS(Worst) && !NT_SUCCESS(GSt))
			Worst = GSt;
		if (NT_SUCCESS(Worst) && !NT_SUCCESS(NSt))
			Worst = NSt;

		/* The counts come back either way: "which case" is the whole diagnostic. */
		Command->NtStatus = (NXCMD_U64)(ULONG_PTR)Worst;
		Command->Result   = NT_SUCCESS(Worst) ? NXCMD_RESULT_OK : NXCMD_RESULT_REFUSED;
		return Worst;
	}

	case NXCMD_OP_KPAGES:
	{
		Command->BytesRead  = 0;
		Command->ModuleSize = 0;
		Command->ModuleBase = 0;

		CONST NXCMD_U64 KFirst = Command->OutBuffer;
		CONST NXCMD_U64 KLast  = KFirst + (NXCMD_U64)Command->ReadLength;
		if (Command->ReadLength < sizeof(NXCMD_KPAGE) ||
		    Command->ReadLength > NXCMD_READ_MAX ||
		    KFirst < NXC_USER_VA_FLOOR || KLast > NXC_USER_VA_CEILING || KLast <= KFirst)
		{
			Command->Result   = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_ADDRESS;
			return STATUS_INVALID_ADDRESS;
		}

		/* NUL-terminate from the caller's fixed field rather than trusting it to be terminated. */
		CHAR KName[sizeof(Command->TargetName)];
		for (SIZE_T i = 0; i < sizeof(KName); i++)
			KName[i] = (CHAR)Command->TargetName[i];
		KName[sizeof(KName) - 1] = '\0';

		if (KName[0] == '\0')
		{
			Command->Result   = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_PARAMETER;
			return STATUS_INVALID_PARAMETER;
		}

		CONST NXCMD_U32 KCap = Command->ReadLength / (NXCMD_U32)sizeof(NXCMD_KPAGE);
		NXCMD_KPAGE* CONST KBuf =
			(NXCMD_KPAGE*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
			                              (SIZE_T)KCap * sizeof(NXCMD_KPAGE), 'pKxN');
		if (KBuf == NULL)
		{
			Command->Result   = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INSUFFICIENT_RESOURCES;
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		NXCMD_U32 KGot = 0, KTotal = 0, KSize = 0;
		NXCMD_U64 KBase = 0;
		CONST NTSTATUS KSt = NxcKpages(KName, KBuf, KCap,
		                               (NXCMD_U32)Command->ReadOffset,   /* first page index */
		                               &KGot, &KTotal, &KBase, &KSize);
		if (!NT_SUCCESS(KSt))
		{
			ExFreePoolWithTag(KBuf, 'pKxN');
			Command->Result   = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)KSt;
			return KSt;
		}

		SIZE_T KCopied = 0;
		CONST NTSTATUS KOut =
			MmCopyVirtualMemory(PsGetCurrentProcess(), KBuf,
			                    PsGetCurrentProcess(), (PVOID)(ULONG_PTR)KFirst,
			                    (SIZE_T)KGot * sizeof(NXCMD_KPAGE), KernelMode, &KCopied);
		ExFreePoolWithTag(KBuf, 'pKxN');

		if (!NT_SUCCESS(KOut))
		{
			Command->Result   = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)KOut;
			return KOut;
		}

		Command->BytesRead  = KGot;      /* pages written                */
		Command->ModuleSize = KTotal;    /* pages the image HAS (D3)     */
		Command->ModuleBase = KBase;
		Command->Result     = NXCMD_RESULT_OK;
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_LBR_SNAP_INIT:
	{
		Command->BytesRead  = 0;
		Command->ModuleSize = 0;
		Command->ModuleBase = 0;

		/* Slots ride in TargetModuleId: a count, in a field whose name says what the number is is
		 * the rule -- so ReadLength would be wrong here and Flags (bits only) doubly so. This is a
		 * count of things being addressed, which is the closest honest fit the ABI has. */
		CONST NTSTATUS ISt = NxcLbrSnapInit(Command->TargetModuleId,
		                                    (Command->Flags & NXCMD_LBR_SNAP_WRAP) ? 1u : 0u);

		UINT32 ITaken = 0, IDropped = 0, ISlots = 0;
		NXCMD_U32 IOver = 0;
		NxcLbrSnapCounters(&ITaken, &IDropped, &ISlots, &IOver);
		Command->BytesRead  = ISlots;

		if (!NT_SUCCESS(ISt))
		{
			Command->Result   = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)ISt;
			return ISt;
		}

		/*
		 * ⚠⚠ REPORT THE MODE ACTUALLY APPLIED, so the caller PRINTS what happened rather than what it
		 * asked for (D3). It must be set HERE, in the case that reserves the ring -- an earlier
		 * version of this landed at the end of NXCMD_OP_LBR_SNAP_FREE, one case above, where the
		 * only thing it could confirm was a ring being released.
		 *
		 * A payload one build behind does not know NXCMD_LBR_SNAP_WRAP. It accepts the command,
		 * ignores the bit, reserves a fill-and-stop ring -- and a newer PlatformCtl would print
		 * "keeps the LAST N" over a ring keeping the FIRST N. The operator then reads the oldest
		 * snapshots as the newest: an INVERTED answer, not a degraded one.
		 *
		 * DiagFlags and not Flags, because Flags is an INPUT that survives the round trip untouched
		 * -- echoing it hands the caller its own request back as proof. DiagFlags is cleared on
		 * entry by the dispatcher and written only by handlers, so an older payload leaves it ZERO
		 * and its absence is meaningful. (Both mistakes were made here in turn, and each was caught
		 * by running the command rather than by reading it.)
		 */
		if ((Command->Flags & NXCMD_LBR_SNAP_WRAP) != 0)
			Command->DiagFlags |= NXCMD_LBR_WRAP_APPLIED;

		Command->Result = NXCMD_RESULT_OK;
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_LBR_SNAP_FREE:
	{
		Command->BytesRead  = 0;
		Command->ModuleSize = 0;
		Command->ModuleBase = 0;

		CONST NTSTATUS FSt = NxcLbrSnapFree();
		if (!NT_SUCCESS(FSt))
		{
			Command->Result   = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)FSt;
			return FSt;
		}

		Command->Result = NXCMD_RESULT_OK;
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_LBR_SNAP_DRAIN:
	{
		Command->BytesRead  = 0;
		Command->ModuleSize = 0;
		Command->ModuleBase = 0;

		CONST NXCMD_U64 SFirst = Command->OutBuffer;
		CONST NXCMD_U64 SLast  = SFirst + (NXCMD_U64)Command->ReadLength;
		if (Command->ReadLength < sizeof(NXCMD_LBR_SNAPSHOT) ||
		    Command->ReadLength > NXCMD_READ_MAX ||
		    SFirst < NXC_USER_VA_FLOOR || SLast > NXC_USER_VA_CEILING || SLast <= SFirst)
		{
			Command->Result   = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_ADDRESS;
			return STATUS_INVALID_ADDRESS;
		}

		CONST NXCMD_U32 SCap = Command->ReadLength / (NXCMD_U32)sizeof(NXCMD_LBR_SNAPSHOT);
		NXCMD_LBR_SNAPSHOT* CONST SBuf =
			(NXCMD_LBR_SNAPSHOT*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
			                                     (SIZE_T)SCap * sizeof(NXCMD_LBR_SNAPSHOT), 'sLxN');
		if (SBuf == NULL)
		{
			Command->Result   = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INSUFFICIENT_RESOURCES;
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		NXCMD_U32 SGot = 0, STotal = 0;
		CONST NTSTATUS SSt = NxcLbrSnapDrain(SBuf, SCap, &SGot, &STotal);
		if (!NT_SUCCESS(SSt))
		{
			ExFreePoolWithTag(SBuf, 'sLxN');
			Command->Result   = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)SSt;
			return SSt;
		}

		SIZE_T SCopied = 0;
		CONST NTSTATUS SOut =
			MmCopyVirtualMemory(PsGetCurrentProcess(), SBuf,
			                    PsGetCurrentProcess(), (PVOID)(ULONG_PTR)SFirst,
			                    (SIZE_T)SGot * sizeof(NXCMD_LBR_SNAPSHOT), KernelMode, &SCopied);
		ExFreePoolWithTag(SBuf, 'sLxN');

		if (!NT_SUCCESS(SOut))
		{
			Command->Result   = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)SOut;
			return SOut;
		}

		/* D3, and the DROP count matters as much as the take count: a hook that hit 10,000 times
		 * into 64 slots produced 64 snapshots and 9,936 drops, and only the second number says the
		 * capture was bounded rather than complete. */
		UINT32 DTaken = 0, DDropped = 0, DSlots = 0;
		NXCMD_U32 DOver = 0;
		NxcLbrSnapCounters(&DTaken, &DDropped, &DSlots, &DOver);

		Command->BytesRead  = SGot;
		Command->ModuleSize = STotal;
		Command->ModuleBase = DDropped;
		/* ⚠ OVERWRITTEN RIDES SEPARATELY FROM DROPPED, because they are different facts: a drop was
		 * never recorded, an overwrite was recorded and then superseded by something newer. Folding
		 * them would make "40 slots, 200 taken" unreadable in exactly the mode that produces it. */
		Command->ReadLength = DOver;
		Command->Result     = NXCMD_RESULT_OK;
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_LBR_SELFTEST:
	{
		NXCMD_U32 UserOnly = 0, KernelMode = 0, Cores = 0;
		CONST NTSTATUS TSt = NxcLbrSelfTest(&UserOnly, &KernelMode, &Cores);

		Command->BytesRead  = UserOnly;
		Command->ModuleSize = KernelMode;
		Command->ModuleBase = Cores;

		/*
		 * ⚠ THE VERDICT IS NOT COMPUTED HERE. The kernel reports the two counts and how many cores
		 * produced them; usermode decides whether that is a pass (D5/D6). A driver that returned
		 * "PASS" would be asserting the very property the test exists to question.
		 */
		if (!NT_SUCCESS(TSt))
		{
			Command->Result   = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)TSt;
			return TSt;
		}

		Command->Result = NXCMD_RESULT_OK;
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_LBR_DISARM:
	{
		Command->BytesRead  = 0;
		Command->ModuleSize = 0;
		Command->ModuleBase = 0;

		/* ⚠ Flags bit 0 = FORCED: clear EN regardless of the ownership record. Exists because
		 * `lbr arm --fake-foreign` deliberately arms WITHOUT recording ownership, which the normal
		 * disarm must then refuse to touch -- leaving a diagnostic that could not be undone. */
		NXCMD_U32 Disarmed = 0;
		CONST NTSTATUS DSt = (Command->Flags & 1u) ? NxcLbrDisarmForce(&Disarmed)
		                                           : NxcLbrDisarm(&Disarmed);

		Command->BytesRead = Disarmed;
		if (!NT_SUCCESS(DSt))
		{
			Command->Result   = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)DSt;
			return DSt;
		}

		Command->Result = NXCMD_RESULT_OK;
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_LBR_READ:
	{
		Command->BytesRead  = 0;
		Command->ModuleSize = 0;
		Command->ModuleBase = 0;

		CONST NXCMD_U64 LFirst = Command->OutBuffer;
		CONST NXCMD_U64 LLast  = LFirst + (NXCMD_U64)Command->ReadLength;
		if (Command->ReadLength < sizeof(NXCMD_LBR_CPU) ||
		    Command->ReadLength > NXCMD_READ_MAX ||
		    LFirst < NXC_USER_VA_FLOOR || LLast > NXC_USER_VA_CEILING || LLast <= LFirst)
		{
			Command->Result   = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_ADDRESS;
			return STATUS_INVALID_ADDRESS;
		}

		CONST NXCMD_U32 LCap = Command->ReadLength / (NXCMD_U32)sizeof(NXCMD_LBR_CPU);
		NXCMD_LBR_CPU* CONST LBuf =
			(NXCMD_LBR_CPU*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
			                                (SIZE_T)LCap * sizeof(NXCMD_LBR_CPU), 'rLxN');
		if (LBuf == NULL)
		{
			Command->Result   = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INSUFFICIENT_RESOURCES;
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		NXCMD_U32 LGot = 0, LTotal = 0;
		CONST NTSTATUS LSt = NxcLbrRead(LBuf, LCap, &LGot, &LTotal);
		if (!NT_SUCCESS(LSt))
		{
			ExFreePoolWithTag(LBuf, 'rLxN');
			Command->Result   = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)LSt;
			return LSt;
		}

		SIZE_T LCopied = 0;
		CONST NTSTATUS LOut =
			MmCopyVirtualMemory(PsGetCurrentProcess(), LBuf,
			                    PsGetCurrentProcess(), (PVOID)(ULONG_PTR)LFirst,
			                    (SIZE_T)LGot * sizeof(NXCMD_LBR_CPU), KernelMode, &LCopied);
		ExFreePoolWithTag(LBuf, 'rLxN');

		if (!NT_SUCCESS(LOut))
		{
			Command->Result   = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)LOut;
			return LOut;
		}

		Command->BytesRead  = LGot;
		Command->ModuleSize = LTotal;
		Command->Result     = NXCMD_RESULT_OK;
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_BP_LIST:
	{
		Command->BytesRead  = 0;
		Command->ModuleSize = 0;
		Command->ModuleBase = 0;

		/*
		 * TargetModuleId selects the VIEW, and the two views produce DIFFERENT RECORD TYPES:
		 *   0    -> NXCMD_BP_CPU,    one per logical processor -- the contention check
		 *   pid  -> NXCMD_BP_THREAD, one per thread            -- what a breakpoint actually IS
		 * The stride is therefore chosen here, once, from the same variable that chose the view.
		 */
		CONST BOOLEAN BpPerThread = (Command->TargetModuleId != 0);
		CONST NXCMD_U32 BpStride  = BpPerThread ? (NXCMD_U32)sizeof(NXCMD_BP_THREAD)
		                                        : (NXCMD_U32)sizeof(NXCMD_BP_CPU);

		CONST NXCMD_U64 BFirst = Command->OutBuffer;
		CONST NXCMD_U64 BLast  = BFirst + (NXCMD_U64)Command->ReadLength;
		if (Command->ReadLength < BpStride ||
		    Command->ReadLength > NXCMD_READ_MAX ||
		    BFirst < NXC_USER_VA_FLOOR || BLast > NXC_USER_VA_CEILING || BLast <= BFirst)
		{
			Command->Result   = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_ADDRESS;
			return STATUS_INVALID_ADDRESS;
		}

		CONST NXCMD_U32 BCap = Command->ReadLength / BpStride;
		PVOID CONST BBuf = ExAllocatePool2(POOL_FLAG_NON_PAGED,
		                                   (SIZE_T)BCap * BpStride, 'cBxN');
		if (BBuf == NULL)
		{
			Command->Result   = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INSUFFICIENT_RESOURCES;
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		NXCMD_U32 BGot = 0, BTotal = 0, BFrozen = 0, BReadFail = 0;
		NTSTATUS BSt;

		if (BpPerThread)
			BSt = NxcBpReadThreads(Command->TargetModuleId, (NXCMD_BP_THREAD*)BBuf, BCap,
			                       &BGot, &BTotal, &BFrozen, &BReadFail);
		else
		{
			BSt = NxcBpRead((NXCMD_BP_CPU*)BBuf, BCap, &BGot, &BTotal);

			/*
			 * ⚠ WHICH ENABLED SLOTS ARE OURS. Without this the contention check reports every live
			 * slot as a stranger's -- including the ones we armed a second earlier -- so it cannot
			 * do the one job it exists for. Read from core 0's registers: a global breakpoint is
			 * identical on every core by construction, and if it is NOT identical that is itself
			 * the contention worth seeing rather than something to average away.
			 */
			if (NT_SUCCESS(BSt) && BGot != 0)
				Command->ReadOffset = NxcBpOwnedSlotMask(((CONST NXCMD_BP_CPU*)BBuf)[0].Dr);
		}

		if (!NT_SUCCESS(BSt))
		{
			ExFreePoolWithTag(BBuf, 'cBxN');
			/*
			 * ⚠ THE REFUSAL IS REPORTED AS A REFUSAL, NOT AS AN EMPTY LIST. A frozen target comes back
			 * STATUS_INVALID_DEVICE_STATE from NxcBpReadThreads; passing the status through lets the
			 * CLI say "frozen, thaw it first" instead of "no threads", which is the absent-vs-failed
			 * tri-state this project keeps having to relearn.
			 */
			Command->ModuleBase = BFrozen;
			Command->Result     = NXCMD_RESULT_REFUSED;
			Command->NtStatus   = (NXCMD_U64)(ULONG_PTR)BSt;
			return BSt;
		}

		SIZE_T BCopied = 0;
		CONST NTSTATUS BOut =
			MmCopyVirtualMemory(PsGetCurrentProcess(), BBuf,
			                    PsGetCurrentProcess(), (PVOID)(ULONG_PTR)BFirst,
			                    (SIZE_T)BGot * BpStride, KernelMode, &BCopied);
		ExFreePoolWithTag(BBuf, 'cBxN');

		if (!NT_SUCCESS(BOut))
		{
			Command->Result   = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)BOut;
			return BOut;
		}

		/* D3: written, and existing. Never one standing in for the other. */
		Command->BytesRead  = BGot;
		Command->ModuleSize = BTotal;
		/*
		 * ⚠⚠ REPORT THE RECORD STRIDE. This path had NO ABI gate -- the same exposure HOOK_LIST had
		 * until it was given one, and `calls read` had before that (a payload one build behind wrote
		 * 352-byte records while PlatformCtl read 400-byte ones and produced 45 records of confident
		 * nonsense from a --limit 40).
		 *
		 * NXCMD_BP_CPU just grew 72 -> 88 for OwnerPid[4], so this is precisely the situation: an old
		 * payload with a new PlatformCtl would parse every record after the first from the middle of
		 * its neighbour, and DR values are exactly the kind of output that looks plausible either way.
		 */
		Command->Flags      = BpStride;
		/* How many context reads FAILED. Without it, "0 of 21" reads as "none have breakpoints"
		 * when it actually means "we could not look at any of them" -- absent is not empty. The
		 * per-CPU path uses ReadOffset for its ownership mask; this branch is the per-thread one, so
		 * the two never collide. */
		if (BpPerThread)
			Command->ReadOffset = BReadFail;
		Command->Result     = NXCMD_RESULT_OK;
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_IDT_PROBE:
	{
		Command->BytesRead  = 0;
		Command->ModuleSize = 0;

		CONST NXCMD_U64 IFirst = Command->OutBuffer;
		CONST NXCMD_U64 ILast  = IFirst + (NXCMD_U64)Command->ReadLength;
		if (Command->ReadLength < sizeof(NXCMD_IDT_PROBE) ||
		    Command->ReadLength > NXCMD_READ_MAX ||
		    IFirst < NXC_USER_VA_FLOOR || ILast > NXC_USER_VA_CEILING || ILast <= IFirst)
		{
			Command->Result   = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_ADDRESS;
			return STATUS_INVALID_ADDRESS;
		}

		NXC_IDT_PROBE Probe;
		/* ReadOffset != 0 means FOLLOW A CHAIN: probe that function instead of a gate. */
		CONST NTSTATUS ISt = NxcIdtProbe(Command->TargetModuleId, Command->ReadOffset, &Probe);

		/*
		 * ⚠ THE STRUCT IS COPIED OUT EVEN ON FAILURE, and that is deliberate. A probe that stopped
		 * at "no .pdata entry" has still established the IDT base and the handler address, and those
		 * are exactly what a reader needs to understand WHY it stopped. Returning only a status code
		 * would throw away the evidence and leave the caller with nothing to act on.
		 */
		NXCMD_IDT_PROBE Wire;
		RtlZeroMemory(&Wire, sizeof(Wire));
		Wire.IdtBase      = Probe.IdtBase;
		Wire.IdtLimit     = Probe.IdtLimit;
		Wire.Vector       = Probe.Vector;
		Wire.HandlerVa    = Probe.HandlerVa;
		Wire.HandlerBegin = Probe.HandlerBegin;
		Wire.HandlerEnd   = Probe.HandlerEnd;
		Wire.DecodedBytes = Probe.DecodedBytes;
		Wire.TargetCount  = Probe.TargetCount;
		Wire.RsbFiltered    = Probe.RsbFiltered; /* dropped Spectre-v2 fill -- reported, not silent */
		Wire.ExternalStarts = Probe.ExternalStarts;  /* the UNCAPPED rank value; see Idt.h */
		Wire.StopReason   = Probe.StopReason;
		Wire.StopOffset   = Probe.StopOffset;
		for (NXCMD_U32 b = 0; b < 16; b++)
			Wire.StopBytes[b] = Probe.StopBytes[b];
		for (NXCMD_U32 i = 0; i < Probe.TargetCount && i < NXCMD_IDT_MAX_TARGETS; i++)
		{
			Wire.Targets[i].Va              = Probe.Targets[i].Va;
			Wire.Targets[i].FuncBegin       = Probe.Targets[i].FuncBegin;
			Wire.Targets[i].FuncEnd         = Probe.Targets[i].FuncEnd;
			Wire.Targets[i].CallSite        = Probe.Targets[i].CallSite;
			Wire.Targets[i].IsFunctionStart = Probe.Targets[i].IsFunctionStart;
			Wire.Targets[i].IsTailJump      = Probe.Targets[i].IsTailJump;
			Wire.Targets[i].IsInternal      = Probe.Targets[i].IsInternal;
			Wire.Targets[i].FoundByScan     = Probe.Targets[i].FoundByScan;
		}

		SIZE_T IWrote = 0;
		CONST NTSTATUS IOut =
			MmCopyVirtualMemory(PsGetCurrentProcess(), &Wire,
			                    PsGetCurrentProcess(), (PVOID)(ULONG_PTR)IFirst,
			                    sizeof(Wire), KernelMode, &IWrote);
		if (!NT_SUCCESS(IOut))
		{
			Command->Result   = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)IOut;
			return IOut;
		}

		Command->BytesRead  = Probe.TargetCount;
		Command->ModuleSize = Probe.DecodedBytes;
		Command->NtStatus   = (NXCMD_U64)(ULONG_PTR)ISt;
		Command->Result     = NT_SUCCESS(ISt) ? NXCMD_RESULT_OK : NXCMD_RESULT_REFUSED;
		return ISt;
	}

	case NXCMD_OP_TRACE_DUMP:
	{
		Command->BytesRead  = 0;
		Command->ModuleSize = 0;

		CONST NXCMD_U64 DFirst = Command->OutBuffer;
		CONST NXCMD_U64 DLast  = DFirst + (NXCMD_U64)Command->ReadLength;
		if (Command->ReadLength == 0 || Command->ReadLength > NXCMD_READ_MAX ||
		    DFirst < NXC_USER_VA_FLOOR || DLast > NXC_USER_VA_CEILING || DLast <= DFirst)
		{
			Command->Result   = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_ADDRESS;
			return STATUS_INVALID_ADDRESS;
		}

		/* Staged through non-paged pool because the source is the trace region and the destination
		 * is usermode: MmCopyVirtualMemory wants a kernel source it can read at PASSIVE, and the
		 * region qualifies -- but copying straight out of it would hold no advantage and would tie
		 * the transfer's shape to the buffer's. */
		void* CONST Stage = ExAllocatePool2(POOL_FLAG_NON_PAGED, Command->ReadLength, 'dTxN');
		if (Stage == NULL)
		{
			Command->Result   = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INSUFFICIENT_RESOURCES;
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		NXCMD_U32 Copied = 0;
		CONST NTSTATUS DSt = NxcTraceDump(Command->TargetModuleId, Command->ReadOffset,
		                                  Command->ReadLength, Stage, &Copied);
		if (!NT_SUCCESS(DSt))
		{
			ExFreePoolWithTag(Stage, 'dTxN');
			Command->Result   = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)DSt;
			return DSt;
		}

		SIZE_T Wrote = 0;
		CONST NTSTATUS DOut =
			MmCopyVirtualMemory(PsGetCurrentProcess(), Stage,
			                    PsGetCurrentProcess(), (PVOID)(ULONG_PTR)DFirst,
			                    Copied, KernelMode, &Wrote);
		ExFreePoolWithTag(Stage, 'dTxN');

		if (!NT_SUCCESS(DOut))
		{
			Command->Result   = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)DOut;
			return DOut;
		}

		/* D3: what was ACTUALLY produced, and the region size separately so the caller can tell a
		 * clamped last chunk from a short read. */
		Command->BytesRead  = (NXCMD_U32)Wrote;
		Command->ModuleSize = Copied;
		Command->Result     = NXCMD_RESULT_OK;
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_HOOK_SELFTEST:
	{
		NXCMD_U32 Step = 0, Why = 0;
		NXCMD_U64 Hits = 0;
		CONST NTSTATUS TSt = NxcHookSelfTest(&Step, &Why, &Hits);

		Command->BytesRead  = Step;
		Command->ModuleSize = Why;
		/* Carried on EVERY outcome. A passing selftest that reported no hit count would leave
		 * "did the thunk actually reach C" as something to infer rather than read. */
		Command->ModuleBase = Hits;
		Command->NtStatus   = (NXCMD_U64)(ULONG_PTR)TSt;
		Command->Result     = NT_SUCCESS(TSt) ? NXCMD_RESULT_OK : NXCMD_RESULT_REFUSED;
		return TSt;
	}

	case NXCMD_OP_HOOK_REMOVE:
	{
		NXCMD_U32 Detail = 0;

		/*
		 * ⚠ THE SAME RESOLVER THE INSTALL USED. `unhook NtCreateFile` has to land on the byte
		 * `hook NtCreateFile` patched; a second derivation that merely ought to agree is the defect
		 * An earlier finding records, and
		 * its failure mode is the worst one available here -- a live detour left in ntoskrnl behind
		 * a successful-looking "removed".
		 */
		UINT64 UnhookVa = 0;
		CONST NTSTATUS URSt = NxcResolveHookTarget(Command, &UnhookVa);
		if (!NT_SUCCESS(URSt))
		{
			Command->BytesRead = 0;
			Command->NtStatus  = (NXCMD_U64)(ULONG_PTR)URSt;
			Command->Result    = NXCMD_RESULT_REFUSED;
			return URSt;
		}

		CONST NTSTATUS HSt = NxcHookRemove(UnhookVa, &Detail);

		Command->BytesRead = Detail;
		Command->NtStatus  = (NXCMD_U64)(ULONG_PTR)HSt;
		Command->Result    = NT_SUCCESS(HSt) ? NXCMD_RESULT_OK : NXCMD_RESULT_REFUSED;
		return HSt;
	}

	case NXCMD_OP_TPM_INIT:
	{
		/* Slots in ReadLength; zero means the default rather than an error. */
		CONST NXCMD_U32 Want = (Command->ReadLength != 0) ? Command->ReadLength : 256u;
		UINT32 Detail = 0;
		CONST NTSTATUS TSt = NxcTpmTraceInit(Want, &Detail);

		Command->BytesRead = Detail;
		Command->NtStatus  = (NXCMD_U64)(ULONG_PTR)TSt;
		Command->Result    = NT_SUCCESS(TSt) ? NXCMD_RESULT_OK : NXCMD_RESULT_REFUSED;

		/* sizeof IS the fact, so sizeof is what travels -- see the CALLS_READ note below for the
		 * 45-records-of-garbage this prevents. */
		Command->Flags = (NXCMD_U32)sizeof(NXCMD_TPM_REC);

		/* The VA to hook, handed back so the operator does not have to find it. Resolved even when
		 * the ring init above refused, because knowing WHERE to hook is useful independently of
		 * whether the ring happens to be armed yet. */
		UINT32 RWhy = 0;
		Command->ModuleBase      = NxcTpmResolveDispatch(&RWhy);
		Command->DiagRefusalLine = RWhy;
		/* Bound device count. Zero means the filter is OPEN and the ring will carry every KMDF
		 * driver's device control -- the operator has to know that before reading a dump. */
		Command->ModuleSize      = NxcTpmBoundDeviceCount();
		return TSt;
	}

	case NXCMD_OP_TPM_READ:
	{
		UINT32 TGot = 0, TTotal = 0, TDrop = 0;

		/*
		 * Reported BEFORE any copy and on EVERY path including the refusals below, so that
		 * "0 records" can be told apart from "never armed" and from "nothing touched the TPM".
		 * Three states, one reading otherwise -- and the third is the exact conclusion this whole
		 * feature exists to support, so it must never be reachable by accident.
		 */
		Command->Flags = (NXCMD_U32)sizeof(NXCMD_TPM_REC);

		CONST NXCMD_U64 TFirst = Command->OutBuffer;
		CONST NXCMD_U64 TLast  = TFirst + (NXCMD_U64)Command->ReadLength;
		if (Command->ReadLength < sizeof(NXCMD_TPM_REC) ||
		    Command->ReadLength > NXCMD_READ_MAX ||
		    TFirst < NXC_USER_VA_FLOOR || TLast > NXC_USER_VA_CEILING || TLast <= TFirst)
		{
			Command->Result   = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_ADDRESS;
			return STATUS_INVALID_ADDRESS;
		}

		CONST NXCMD_U32 TCap = Command->ReadLength;
		NXCMD_TPM_REC* CONST TBuf =
			(NXCMD_TPM_REC*)ExAllocatePool2(POOL_FLAG_NON_PAGED, (SIZE_T)TCap, 'tTxN');
		if (TBuf == NULL)
		{
			Command->Result   = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INSUFFICIENT_RESOURCES;
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		CONST NTSTATUS TRd = NxcTpmTraceRead(TBuf, TCap, &TGot, &TTotal, &TDrop);

		/* Counters first, so a refusal still says how much exists and how much was lost. */
		Command->ModuleBase      = TTotal;
		Command->DiagRefusalLine = TDrop;

		if (!NT_SUCCESS(TRd))
		{
			ExFreePoolWithTag(TBuf, 'tTxN');
			Command->BytesRead = 0;
			Command->NtStatus  = (NXCMD_U64)(ULONG_PTR)TRd;
			Command->Result    = NXCMD_RESULT_REFUSED;
			return TRd;
		}

		SIZE_T TCopied = 0;
		CONST NTSTATUS TOut =
			MmCopyVirtualMemory(PsGetCurrentProcess(), TBuf,
			                    PsGetCurrentProcess(), (PVOID)(ULONG_PTR)TFirst,
			                    (SIZE_T)TGot * sizeof(NXCMD_TPM_REC), KernelMode, &TCopied);
		ExFreePoolWithTag(TBuf, 'tTxN');

		if (!NT_SUCCESS(TOut))
		{
			Command->Result   = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)TOut;
			return TOut;
		}

		Command->BytesRead = TGot;          /* D3: what was PRODUCED, not what was asked for */
		Command->NtStatus  = (NXCMD_U64)(ULONG_PTR)STATUS_SUCCESS;
		Command->Result    = NXCMD_RESULT_OK;
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_CALLS_INIT:
	{
		/* Slots arrive in ReadLength. Zero means "the default" rather than an error -- an operator
		 * who did not think about ring depth should still get a working ring. */
		CONST NXCMD_U32 Want = (Command->ReadLength != 0) ? Command->ReadLength : 512u;
		UINT32 Got = 0;
		CONST NTSTATUS CSt = NxcCallsInit(Want, &Got);

		Command->BytesRead = Got;
		Command->NtStatus  = (NXCMD_U64)(ULONG_PTR)CSt;
		Command->Result    = NT_SUCCESS(CSt) ? NXCMD_RESULT_OK : NXCMD_RESULT_REFUSED;

		/* Same ABI fact on init, so a mismatch is caught at setup rather than after a run that
		 * produced records nobody can trust. */
		Command->Flags = (NXCMD_U32)sizeof(NXCMD_CALL_ENTRY);

		UINT32 SSlots = 0; UINT64 STotal = 0, SDrop = 0, SNamed = 0, SExtent = 0;
		NxcCallsStats(&SSlots, &STotal, &SDrop, &SNamed, &SExtent);
		Command->ModuleSize = (NXCMD_U32)SExtent;
		Command->ModuleBase = STotal;
		return CSt;
	}

	case NXCMD_OP_CALLS_READ:
	{
		UINT32 CSlots = 0; UINT64 CTotal = 0, CDrop = 0, CNamed = 0, CExtent = 0;
		NxcCallsStats(&CSlots, &CTotal, &CDrop, &CNamed, &CExtent);

		/*
		 * ⚠⚠ THE RECORD SIZE THIS KERNEL ACTUALLY WRITES, REPORTED BEFORE ANY DATA IS COPIED.
		 *
		 * measured, and it produced the most convincing wrong output of the session.
		 * `calls read --limit 40` came back with FORTY-FIVE records of plausible-looking garbage:
		 * absurd sequence numbers, pids in the millions, names bleeding across record boundaries,
		 * and `a5-10` values that were actually UTF-16 text (0x43005C00080008 is "\C").
		 *
		 * The cause was a payload one build behind: the kernel wrote 352-byte records while
		 * PlatformCtl read 400-byte ones, because StackArg[6]+StackWhy had been added to the shared
		 * struct and only one side had been rebuilt. The ratio IS the tell -- 40 * 400 / 352 = 45.45,
		 * and 45 came back. Every field after the first record was read from the middle of its
		 * neighbour.
		 *
		 * ⚠ AND IT CANNOT BE SOLVED BY REMEMBERING TO REDEPLOY. This is the same shape as the
		 * `Shape[]` break earlier the same day, where the kernel grew by seven qwords and usermode
		 * did not: two sides of one struct with nothing that forces them to agree, failing SILENTLY
		 * and confidently (an earlier finding).
		 * A version counter would be a third thing to keep in sync. sizeof IS the fact, so sizeof is
		 * what travels.
		 */
		Command->Flags = (NXCMD_U32)sizeof(NXCMD_CALL_ENTRY);

		/*
		 * ⚠ THE COUNTERS ARE REPORTED ON EVERY PATH, INCLUDING THE REFUSALS BELOW. "0 records" with
		 * no total is indistinguishable from "the ring was never reserved" and from "nothing has
		 * called that function" -- three states, one reading, which is the shape that absorbs fixes.
		 */
		Command->ModuleBase    = CTotal;
		Command->DiagRefusalLine = (NXCMD_U32)CDrop;
		Command->ModuleSize    = CSlots;

		CONST NXCMD_U64 CFirst = Command->OutBuffer;
		CONST NXCMD_U64 CLast  = CFirst + (NXCMD_U64)Command->ReadLength;
		if (Command->ReadLength < sizeof(NXCMD_CALL_ENTRY) ||
		    Command->ReadLength > NXCMD_READ_MAX ||
		    CFirst < NXC_USER_VA_FLOOR || CLast > NXC_USER_VA_CEILING || CLast <= CFirst)
		{
			Command->Result   = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_ADDRESS;
			return STATUS_INVALID_ADDRESS;
		}

		CONST NXCMD_U32 CCap = Command->ReadLength / (NXCMD_U32)sizeof(NXCMD_CALL_ENTRY);
		NXCMD_CALL_ENTRY* CONST CBuf =
			(NXCMD_CALL_ENTRY*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
			                                   (SIZE_T)CCap * sizeof(NXCMD_CALL_ENTRY), 'cCxN');
		if (CBuf == NULL)
		{
			Command->Result   = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INSUFFICIENT_RESOURCES;
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		UINT32 CGot = 0;
		CONST NTSTATUS RdSt = NxcCallsRead(CBuf, CCap, &CGot, &CTotal, &CDrop, &CNamed);
		if (!NT_SUCCESS(RdSt))
		{
			ExFreePoolWithTag(CBuf, 'cCxN');
			Command->BytesRead = 0;
			Command->NtStatus  = (NXCMD_U64)(ULONG_PTR)RdSt;
			Command->Result    = NXCMD_RESULT_REFUSED;
			return RdSt;
		}

		SIZE_T CCopied = 0;
		CONST NTSTATUS COut =
			MmCopyVirtualMemory(PsGetCurrentProcess(), CBuf,
			                    PsGetCurrentProcess(), (PVOID)(ULONG_PTR)CFirst,
			                    (SIZE_T)CGot * sizeof(NXCMD_CALL_ENTRY), KernelMode, &CCopied);
		ExFreePoolWithTag(CBuf, 'cCxN');

		if (!NT_SUCCESS(COut))
		{
			Command->Result   = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)COut;
			return COut;
		}

		/* D3: what was produced, and out of how many. Named is the one that says whether the SHAPE
		 * flag was right -- 4000 records with 0 names means the wrong argument was dereferenced. */
		Command->BytesRead       = CGot;
		Command->ModuleBase      = CTotal;
		Command->DiagRefusalLine = (NXCMD_U32)CDrop;
		Command->ImageBuffer     = CNamed;

		/*
		 * ⚠ HOOK HITS AND RE-ENTRY DROPS, BECAUSE `seen : N` IS NOT THE NUMBER OF TIMES THE FUNCTION
		 * RAN. The hit path has a per-processor re-entry guard: a hit arriving while the guard is
		 * held is COUNTED and dropped, never recorded. So a call ring reporting 5 records out of 5
		 * hits looks complete while an unknown number of calls were refused one layer above it --
		 * the silent-partial shape, with the counter that would expose it living in a different
		 * file and printed by a different command. Both are carried here so one reading answers it.
		 */
		UINT64 HookHits = 0, HookReentries = 0, HookFiltered = 0;
		NxcHookCounters(&HookHits, &HookReentries, &HookFiltered);
		Command->ReadOffset = HookHits;
		Command->ReadLength = (NXCMD_U32)HookReentries;
		/*
		 * ⚠ FILTERED HITS RIDE IN ModuleId FOR THIS OPCODE, and the meaning is pinned in the header
		 * beside the field -- the same way BytesRead's bytes-vs-count split is pinned, rather than
		 * left to a reader to infer. ModuleId is an OUTPUT, cleared on entry, and unused by
		 * CALLS_READ (it is the map handle).
		 *
		 * Without it a scoped hook is indistinguishable from a dead one: "0 records" is the same
		 * reading whether nothing happened or 75000 hits all belonged to other processes.
		 */
		Command->ModuleId   = (NXCMD_U32)HookFiltered;
		Command->NtStatus        = (NXCMD_U64)(ULONG_PTR)STATUS_SUCCESS;
		Command->Result          = NXCMD_RESULT_OK;
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_FCAP_INIT:
	{
		CONST NXCMD_U32 FSlots = (Command->ReadLength != 0) ? Command->ReadLength : 64u;
		CONST NXCMD_U32 FKb    = (Command->ModuleSize != 0) ? Command->ModuleSize : 1024u;
		UINT32 FGot = 0;
		CONST NTSTATUS FSt = NxcFileCaptureInit(FSlots, FKb, &FGot);

		NXCMD_FCAP_STATS FStats;
		NxcFileCaptureStats(&FStats);

		Command->BytesRead  = FGot;
		Command->ModuleBase = FStats.BytesBudget;
		Command->NtStatus   = (NXCMD_U64)(ULONG_PTR)FSt;
		Command->Result     = NT_SUCCESS(FSt) ? NXCMD_RESULT_OK : NXCMD_RESULT_REFUSED;
		return FSt;
	}

	case NXCMD_OP_FCAP_READ:
	{
		NXCMD_FCAP_STATS FStats;
		NxcFileCaptureStats(&FStats);

		/* ⚠ THE SIZE TRAVELS, exactly as it does for NXCMD_CALL_ENTRY -- a payload one build behind
		 * writing a different-sized record is what produced 45 believable-but-wrong rows out of a
		 * --limit 40 (an earlier finding). */
		Command->Flags = (NXCMD_U32)sizeof(NXCMD_FCAP_ENTRY);

		CONST NXCMD_U64 FFirst = Command->OutBuffer;
		CONST NXCMD_U64 FLast  = FFirst + (NXCMD_U64)Command->ReadLength;
		if (Command->ReadLength < sizeof(NXCMD_FCAP_ENTRY) ||
		    Command->ReadLength > NXCMD_READ_MAX ||
		    FFirst < NXC_USER_VA_FLOOR || FLast > NXC_USER_VA_CEILING || FLast <= FFirst)
		{
			Command->Result   = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_ADDRESS;
			return STATUS_INVALID_ADDRESS;
		}

		CONST NXCMD_U32 FCap = Command->ReadLength / (NXCMD_U32)sizeof(NXCMD_FCAP_ENTRY);
		NXCMD_FCAP_ENTRY* CONST FBuf =
			(NXCMD_FCAP_ENTRY*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
			                                   (SIZE_T)FCap * sizeof(NXCMD_FCAP_ENTRY), 'fCxN');
		if (FBuf == NULL)
		{
			Command->Result   = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INSUFFICIENT_RESOURCES;
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		UINT32 FGot = 0; UINT64 FTotal = 0;
		CONST NTSTATUS FRd = NxcFileCaptureRead(FBuf, FCap, &FGot, &FTotal);
		if (!NT_SUCCESS(FRd))
		{
			ExFreePoolWithTag(FBuf, 'fCxN');
			Command->BytesRead = 0;
			Command->NtStatus  = (NXCMD_U64)(ULONG_PTR)FRd;
			Command->Result    = NXCMD_RESULT_REFUSED;
			return FRd;
		}

		SIZE_T FCopied = 0;
		CONST NTSTATUS FOut =
			MmCopyVirtualMemory(PsGetCurrentProcess(), FBuf,
			                    PsGetCurrentProcess(), (PVOID)(ULONG_PTR)FFirst,
			                    (SIZE_T)FGot * sizeof(NXCMD_FCAP_ENTRY), KernelMode, &FCopied);
		ExFreePoolWithTag(FBuf, 'fCxN');

		if (!NT_SUCCESS(FOut))
		{
			Command->Result   = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)FOut;
			return FOut;
		}

		/* Every counter, on every read. "0 captures" has eight causes and they need separating. */
		Command->BytesRead       = FGot;
		Command->ModuleBase      = FStats.Total;
		Command->ModuleSize      = FStats.Slots;
		Command->ImageBuffer     = FStats.Captured;
		Command->ReadOffset      = FStats.Queued;
		Command->DiagRefusalLine = (NXCMD_U32)FStats.QueueFull;
		Command->DiagFlags       = (NXCMD_U32)FStats.Gone;
		Command->NtStatus        = (NXCMD_U64)(ULONG_PTR)STATUS_SUCCESS;
		Command->Result          = NXCMD_RESULT_OK;
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_FCAP_PULL:
	{
		CONST NXCMD_U64 PFirst = Command->OutBuffer;
		CONST NXCMD_U64 PLast  = PFirst + (NXCMD_U64)Command->ReadLength;
		if (Command->ReadLength == 0 || Command->ReadLength > NXCMD_READ_MAX ||
		    PFirst < NXC_USER_VA_FLOOR || PLast > NXC_USER_VA_CEILING || PLast <= PFirst)
		{
			Command->Result   = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_ADDRESS;
			return STATUS_INVALID_ADDRESS;
		}

		void* CONST PBuf = ExAllocatePool2(POOL_FLAG_NON_PAGED, Command->ReadLength, 'pCxN');
		if (PBuf == NULL)
		{
			Command->Result   = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INSUFFICIENT_RESOURCES;
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		UINT32 PGot = 0;
		CONST NTSTATUS PSt = NxcFileCapturePull(Command->ReadOffset, Command->ReadLength,
		                                        PBuf, &PGot);
		if (!NT_SUCCESS(PSt))
		{
			ExFreePoolWithTag(PBuf, 'pCxN');
			Command->BytesRead = 0;
			Command->NtStatus  = (NXCMD_U64)(ULONG_PTR)PSt;
			Command->Result    = NXCMD_RESULT_REFUSED;
			return PSt;
		}

		SIZE_T PCopied = 0;
		CONST NTSTATUS POut =
			MmCopyVirtualMemory(PsGetCurrentProcess(), PBuf,
			                    PsGetCurrentProcess(), (PVOID)(ULONG_PTR)PFirst,
			                    (SIZE_T)PGot, KernelMode, &PCopied);
		ExFreePoolWithTag(PBuf, 'pCxN');

		if (!NT_SUCCESS(POut))
		{
			Command->Result   = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)POut;
			return POut;
		}

		Command->BytesRead = PGot;      /* what was ACTUALLY copied, never what was asked (D3) */
		Command->NtStatus  = 0;
		Command->Result    = NXCMD_RESULT_OK;
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_HOOK_LIST:
	{
		Command->BytesRead  = 0;
		Command->ModuleSize = 0;

		CONST NXCMD_U64 TFirst = Command->OutBuffer;
		CONST NXCMD_U64 TLast  = TFirst + (NXCMD_U64)Command->ReadLength;
		if (Command->ReadLength < sizeof(NXCMD_HOOK_INFO) ||
		    Command->ReadLength > NXCMD_READ_MAX ||
		    TFirst < NXC_USER_VA_FLOOR || TLast > NXC_USER_VA_CEILING || TLast <= TFirst)
		{
			Command->Result = NXCMD_RESULT_COPY_FAILED;
			return STATUS_INVALID_PARAMETER;
		}

		NXC_HOOK_ENTRY Local[NXC_MAX_HOOKS];
		NXCMD_U32 Got = 0, Total = 0;
		CONST NTSTATUS LSt = NxcHookList(Local, NXC_MAX_HOOKS, &Got, &Total);
		if (!NT_SUCCESS(LSt))
		{
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)LSt;
			Command->Result   = NXCMD_RESULT_REFUSED;
			return LSt;
		}

		/* Narrow the driver's record to the wire record. Kept as separate types on purpose: the
		 * driver's carries an arena extent id that means nothing to usermode and would only invite
		 * someone to pass it back. */
		CONST NXCMD_U32 Fit = Command->ReadLength / (NXCMD_U32)sizeof(NXCMD_HOOK_INFO);
		CONST NXCMD_U32 N   = (Got < Fit) ? Got : Fit;

		NXCMD_HOOK_INFO Wire[NXC_MAX_HOOKS];
		for (NXCMD_U32 i = 0; i < N; i++)
		{
			Wire[i].TargetVa      = Local[i].TargetVa;
			Wire[i].HandlerVa     = Local[i].HandlerVa;
			Wire[i].TrampolineVa  = Local[i].TrampolineVa;
			Wire[i].AlignedVa     = Local[i].AlignedVa;
			Wire[i].OriginalQword = Local[i].OriginalQword;
			Wire[i].PatchedQword  = Local[i].PatchedQword;
			Wire[i].StolenBytes   = Local[i].StolenBytes;
			Wire[i].Active        = Local[i].Active;
			Wire[i].InstallFlags  = Local[i].InstallFlags;   /* WHAT the hook is, not just where */
			Wire[i].FilterPid     = Local[i].FilterPid;      /* and WHO it is scoped to           */
		}

		/* The whole table is at most NXC_MAX_HOOKS records, so it lives on the stack and there is no
		 * pool allocation to leak on any path out of here. */
		SIZE_T Wrote = 0;
		CONST NTSTATUS CSt =
			MmCopyVirtualMemory(PsGetCurrentProcess(), Wire,
			                    PsGetCurrentProcess(), (PVOID)(ULONG_PTR)TFirst,
			                    (SIZE_T)N * sizeof(NXCMD_HOOK_INFO), KernelMode, &Wrote);
		if (!NT_SUCCESS(CSt))
		{
			Command->Result   = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)CSt;
			return CSt;
		}

		/* D3: report what was ACTUALLY produced, and the total separately. */
		Command->BytesRead  = (NXCMD_U32)(Wrote / sizeof(NXCMD_HOOK_INFO));
		Command->ModuleSize = Total;
		/*
		 * ⚠ REPORT OUR OWN RECORD SIZE, so usermode can refuse a mismatched pair instead of parsing
		 * every field from the middle of its neighbour. `calls read` already learned this the
		 * expensive way -- a payload one build behind wrote 352-byte records while PlatformCtl read
		 * 400-byte ones and produced 45 records of confident nonsense from a --limit 40. This record
		 * grew 60 -> 64 when FilterPid was appended, which is exactly that situation again.
		 */
		Command->Flags      = (NXCMD_U32)sizeof(NXCMD_HOOK_INFO);
		Command->NtStatus   = 0;
		Command->Result     = NXCMD_RESULT_OK;
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_POOL_BAIT:
	{
		/* Plant bait. See Pool.h for why this is pool and not arena (the D4 exception). */
		Command->BytesRead  = 0;
		Command->ModuleBase = 0;
		Command->ModuleSize = 0;

		CONST NXCMD_U64 TFirst = Command->OutBuffer;
		CONST NXCMD_U64 TLast  = TFirst + (NXCMD_U64)Command->ReadLength;
		if (Command->ReadLength < sizeof(NXCMD_POOL_ENTRY) ||
		    Command->ReadLength > NXCMD_READ_MAX ||
		    TFirst < NXC_USER_VA_FLOOR || TLast > NXC_USER_VA_CEILING || TLast <= TFirst)
		{
			Command->Result = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_ADDRESS;
			return STATUS_INVALID_ADDRESS;
		}

		/*
		 * ⚠ THE COUNT IS THE CALLER'S BUFFER CAPACITY, not a separate input field.
		 *
		 * It was briefly smuggled through Flags. That is precisely the alternative this struct's own
		 * ABI note records as REJECTED -- "an id is not a flag, and the name would mislead every
		 * future reader" -- and a count is not a flag for the same reason. Rather than add an ABI
		 * field, the capacity IS the count, which is honest: bait we cannot describe back to the
		 * caller is bait they have no address for, and this driver never unloads, so an unreportable
		 * block is a permanent leak with no handle.
		 */
		CONST NXCMD_U32 BCap = Command->ReadLength / (NXCMD_U32)sizeof(NXCMD_POOL_ENTRY);
		NXCMD_POOL_ENTRY Planted[NXC_MAX_BAIT];
		RtlZeroMemory(Planted, sizeof(Planted));

		NXCMD_U32 BGot = 0;
		CONST NTSTATUS BSt = NxcPoolBait(Command->TargetModuleId,
		                                 BCap,
		                                 (NXCMD_U32)Command->ReadOffset,
		                                 Planted, NXC_MAX_BAIT, &BGot);
		if (!NT_SUCCESS(BSt))
		{
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)BSt;
			return BSt;
		}

		CONST NXCMD_U32 BGive = (BGot < BCap) ? BGot : BCap;
		SIZE_T BCopied = 0;
		CONST NTSTATUS BOut =
			MmCopyVirtualMemory(PsGetCurrentProcess(), Planted,
			                    PsGetCurrentProcess(), (PVOID)(ULONG_PTR)TFirst,
			                    BGive * sizeof(NXCMD_POOL_ENTRY), KernelMode, &BCopied);
		if (!NT_SUCCESS(BOut))
		{
			/*
			 * ⚠ THE BAIT IS ALREADY PLANTED. Failing to report it does not un-plant it, and
			 * silently leaving blocks with no way to name them is precisely the permanent leak the
			 * tracking exists to prevent. The count is reported so `pool bait --free` still works.
			 */
			CmdLog("cmd: pool-bait planted %u but the report copy FAILED 0x%08X -- "
			       "run `pool bait --free`\n", BGot, BOut);
			Command->BytesRead = BGot;
			Command->Result = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)BOut;
			return BOut;
		}

		Command->BytesRead  = BGot;
		Command->ModuleSize = NxcPoolBaitCount();
		Command->Result     = NXCMD_RESULT_OK;
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_POOL_BAIT_FREE:
	{
		NXCMD_U32 Freed = 0;
		CONST NTSTATUS FSt = NxcPoolBaitFree(&Freed);
		Command->BytesRead  = Freed;
		Command->ModuleSize = NxcPoolBaitCount();   /* must be 0 afterwards */
		Command->NtStatus   = (NXCMD_U64)(ULONG_PTR)FSt;
		Command->Result     = NT_SUCCESS(FSt) ? NXCMD_RESULT_OK : NXCMD_RESULT_REFUSED;
		return FSt;
	}

	case NXCMD_OP_REGION_FILE:
	{
		/*
		 * WHICH FILE is behind one mapping. TargetModuleId = pid, ReadOffset = a VA in the region.
		 *
		 * ⚠ THE STATUS IS PASSED THROUGH UNCHANGED, and STATUS_FILE_INVALID especially. That is not
		 * a failure -- it means the section is backed by the PAGEFILE rather than a file on disk,
		 * which is itself the interesting answer for an executable MEM_MAPPED region. Collapsing it
		 * into a generic refusal would discard the distinction this opcode exists to draw.
		 */
		Command->BytesRead = 0;

		CONST NXCMD_U64 First = Command->OutBuffer;
		CONST NXCMD_U64 Last  = First + (NXCMD_U64)Command->ReadLength;
		if (Command->ReadLength < sizeof(WCHAR) || Command->ReadLength > NXCMD_READ_MAX ||
		    First < NXC_USER_VA_FLOOR || Last > NXC_USER_VA_CEILING || Last <= First)
		{
			Command->Result   = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_ADDRESS;
			return STATUS_INVALID_ADDRESS;
		}

		VOID* CONST NBuf = ExAllocatePool2(POOL_FLAG_NON_PAGED, Command->ReadLength, 'nRxN');
		if (NBuf == NULL)
		{
			Command->Result   = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INSUFFICIENT_RESOURCES;
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		ULONG NGot = 0;
		CONST NTSTATUS NSt = NxcRegionFile(Command->TargetModuleId, Command->ReadOffset,
		                                   NBuf, Command->ReadLength, &NGot);

		if (NT_SUCCESS(NSt) && NGot != 0)
		{
			SIZE_T NCopied = 0;
			CONST NTSTATUS NOut =
				MmCopyVirtualMemory(PsGetCurrentProcess(), NBuf,
				                    PsGetCurrentProcess(), (PVOID)(ULONG_PTR)First,
				                    NGot, KernelMode, &NCopied);
			if (!NT_SUCCESS(NOut))
			{
				ExFreePoolWithTag(NBuf, 'nRxN');
				Command->Result   = NXCMD_RESULT_COPY_FAILED;
				Command->NtStatus = (NXCMD_U64)(ULONG_PTR)NOut;
				return NOut;
			}
			Command->BytesRead = (NXCMD_U32)NCopied;
		}

		ExFreePoolWithTag(NBuf, 'nRxN');
		Command->NtStatus = (NXCMD_U64)(ULONG_PTR)NSt;
		Command->Result   = NT_SUCCESS(NSt) ? NXCMD_RESULT_OK : NXCMD_RESULT_REFUSED;
		return NSt;
	}

	case NXCMD_OP_KSCAN:
	{
		/*
		 * Executable kernel pages belonging to no loaded module.
		 *
		 * TWO STEPS, and the first is why `modules --kernel` was built first: enumerate the module
		 * list to get the ranges to SUBTRACT, then walk. If the enumeration fails its ntoskrnl
		 * self-check, the scan is ABANDONED rather than run with an incomplete subtrahend -- a
		 * missing module would turn its perfectly ordinary code into a "finding", which is the
		 * false positive this command can least afford.
		 */
		Command->BytesRead  = 0;
		Command->ModuleBase = 0;
		Command->ModuleSize = 0;

		CONST NXCMD_U64 SFirst = Command->OutBuffer;
		CONST NXCMD_U64 SLast  = SFirst + (NXCMD_U64)Command->ReadLength;
		if (Command->ReadLength < sizeof(NXCMD_KEXEC) ||
		    Command->ReadLength > NXCMD_READ_MAX ||
		    SFirst < NXC_USER_VA_FLOOR || SLast > NXC_USER_VA_CEILING || SLast <= SFirst)
		{
			Command->Result = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_ADDRESS;
			return STATUS_INVALID_ADDRESS;
		}

		enum { SCAN_MAX_MODULES = 1024 };
		NXCMD_KMODULE* CONST SMods =
			(NXCMD_KMODULE*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
			                                SCAN_MAX_MODULES * sizeof(NXCMD_KMODULE), 'sKxN');
		UINT64* CONST SBase = (UINT64*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
		                                              SCAN_MAX_MODULES * sizeof(UINT64), 'sBxN');
		UINT64* CONST SEnd  = (UINT64*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
		                                              SCAN_MAX_MODULES * sizeof(UINT64), 'sExN');
		if (SMods == NULL || SBase == NULL || SEnd == NULL)
		{
			if (SMods) ExFreePoolWithTag(SMods, 'sKxN');
			if (SBase) ExFreePoolWithTag(SBase, 'sBxN');
			if (SEnd)  ExFreePoolWithTag(SEnd,  'sExN');
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INSUFFICIENT_RESOURCES;
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		NXCMD_U32 SGotMods = 0, STotalMods = 0;
		CONST NTSTATUS SEnum = NxcEnumKernelModules(0, SMods, SCAN_MAX_MODULES,
		                                            &SGotMods, &STotalMods);
		if (!NT_SUCCESS(SEnum) || SGotMods != STotalMods)
		{
			/* Incomplete subtrahend -> every unlisted module becomes a false finding. Refuse. */
			ExFreePoolWithTag(SMods, 'sKxN');
			ExFreePoolWithTag(SBase, 'sBxN');
			ExFreePoolWithTag(SEnd,  'sExN');
			Command->Result   = NXCMD_RESULT_REFUSED;
			Command->NtStatus = NT_SUCCESS(SEnum)
			                    ? (NXCMD_U64)(ULONG_PTR)STATUS_BUFFER_TOO_SMALL
			                    : (NXCMD_U64)(ULONG_PTR)SEnum;
			return NT_SUCCESS(SEnum) ? STATUS_BUFFER_TOO_SMALL : SEnum;
		}

		for (NXCMD_U32 m = 0; m < SGotMods; m++)
		{
			SBase[m] = SMods[m].Base;
			SEnd[m]  = SMods[m].Base + SMods[m].SizeOfImage;
		}

		CONST NXCMD_U32 SCap = Command->ReadLength / (NXCMD_U32)sizeof(NXCMD_KEXEC);
		NXCMD_KEXEC* CONST SBuf =
			(NXCMD_KEXEC*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
			                              SCap * sizeof(NXCMD_KEXEC), 'sXxN');
		if (SBuf == NULL)
		{
			ExFreePoolWithTag(SMods, 'sKxN');
			ExFreePoolWithTag(SBase, 'sBxN');
			ExFreePoolWithTag(SEnd,  'sExN');
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INSUFFICIENT_RESOURCES;
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		NXCMD_U32 SGot = 0, STotal = 0, STrunc = 0;
		UINT64 SProbes = 0, SReached = 0;
		CONST NTSTATUS SSt = NxcPteScanUnlistedExec(SBase, SEnd, SGotMods,
		                                            (NXCMD_U32)Command->ReadOffset,
		                                            SBuf, SCap, &SGot, &STotal, &STrunc,
		                                            &SProbes, &SReached);
		ExFreePoolWithTag(SMods, 'sKxN');
		ExFreePoolWithTag(SBase, 'sBxN');
		ExFreePoolWithTag(SEnd,  'sExN');

		if (!NT_SUCCESS(SSt))
		{
			ExFreePoolWithTag(SBuf, 'sXxN');
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)SSt;
			return SSt;
		}

		SIZE_T SCopied = 0;
		CONST NTSTATUS SOut =
			MmCopyVirtualMemory(PsGetCurrentProcess(), SBuf,
			                    PsGetCurrentProcess(), (PVOID)(ULONG_PTR)SFirst,
			                    SGot * sizeof(NXCMD_KEXEC), KernelMode, &SCopied);
		ExFreePoolWithTag(SBuf, 'sXxN');

		if (!NT_SUCCESS(SOut))
		{
			Command->Result = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)SOut;
			return SOut;
		}

		Command->BytesRead  = SGot;      /* PRODUCED */
		Command->ModuleSize = STotal;    /* EXISTS   */
		/* Truncation reason in the low bits, VA REACHED above them. The first hardware run
		 * stopped at 22.6 TB and only the flag said so -- without the address there was no way
		 * to tell whether the ceiling was slightly or wildly too low. */
		Command->ModuleBase = ((NXCMD_U64)SReached & ~0xFFull) | (NXCMD_U64)(STrunc & 0xFFu);
		Command->ReadOffset = SProbes;   /* what the walk COST */
		Command->Result     = NXCMD_RESULT_OK;
		Command->NtStatus   = 0;
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_KMODULES:
	{
		/*
		 * Enumerate loaded kernel modules. Mirrors POOL_LIST's shape deliberately: validate the
		 * caller's buffer, stage into non-paged pool, fill, copy out, report PRODUCED and TOTAL.
		 */
		Command->BytesRead  = 0;
		Command->ModuleBase = 0;
		Command->ModuleSize = 0;

		CONST NXCMD_U64 MFirst = Command->OutBuffer;
		CONST NXCMD_U64 MLast  = MFirst + (NXCMD_U64)Command->ReadLength;
		if (Command->ReadLength < sizeof(NXCMD_KMODULE) ||
		    Command->ReadLength > NXCMD_READ_MAX ||
		    MFirst < NXC_USER_VA_FLOOR || MLast > NXC_USER_VA_CEILING || MLast <= MFirst)
		{
			Command->Result = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_ADDRESS;
			return STATUS_INVALID_ADDRESS;
		}

		CONST NXCMD_U32 MCap = Command->ReadLength / (NXCMD_U32)sizeof(NXCMD_KMODULE);
		NXCMD_KMODULE* CONST MBuf =
			(NXCMD_KMODULE*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
			                                MCap * sizeof(NXCMD_KMODULE), 'mKxN');
		if (MBuf == NULL)
		{
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INSUFFICIENT_RESOURCES;
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		NXCMD_U32 MGot = 0, MTotal = 0;
		CONST NTSTATUS MSt = NxcEnumKernelModules((NXCMD_U32)Command->ReadOffset,
		                                          MBuf, MCap, &MGot, &MTotal);
		if (!NT_SUCCESS(MSt))
		{
			ExFreePoolWithTag(MBuf, 'mKxN');
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)MSt;
			return MSt;
		}

		SIZE_T MCopied = 0;
		CONST NTSTATUS MOut =
			MmCopyVirtualMemory(PsGetCurrentProcess(), MBuf,
			                    PsGetCurrentProcess(), (PVOID)(ULONG_PTR)MFirst,
			                    MGot * sizeof(NXCMD_KMODULE), KernelMode, &MCopied);
		ExFreePoolWithTag(MBuf, 'mKxN');

		if (!NT_SUCCESS(MOut))
		{
			Command->Result = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)MOut;
			return MOut;
		}

		/* BytesRead is a COUNT for this opcode, per the field's documented dual meaning.
		 * ModuleSize carries the TOTAL so a truncated page is visible as truncated. */
		Command->BytesRead  = MGot;
		Command->ModuleSize = MTotal;
		Command->Result     = NXCMD_RESULT_OK;
		Command->NtStatus   = 0;
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_POOL_LIST:
	{
		/* A target's RUNTIME allocations. ⚠ BIG POOL ONLY -- see NexusCommand.h. */
		Command->BytesRead  = 0;
		Command->ModuleBase = 0;
		Command->ModuleSize = 0;

		CONST NXCMD_U64 KFirst = Command->OutBuffer;
		CONST NXCMD_U64 KLast  = KFirst + (NXCMD_U64)Command->ReadLength;
		if (Command->ReadLength < sizeof(NXCMD_POOL_ENTRY) ||
		    Command->ReadLength > NXCMD_READ_MAX ||
		    KFirst < NXC_USER_VA_FLOOR || KLast > NXC_USER_VA_CEILING || KLast <= KFirst)
		{
			Command->Result = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_ADDRESS;
			return STATUS_INVALID_ADDRESS;
		}

		CONST NXCMD_U32 KCap = Command->ReadLength / (NXCMD_U32)sizeof(NXCMD_POOL_ENTRY);
		NXCMD_POOL_ENTRY* CONST KBuf =
			(NXCMD_POOL_ENTRY*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
			                                   KCap * sizeof(NXCMD_POOL_ENTRY), 'kPxN');
		if (KBuf == NULL)
		{
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INSUFFICIENT_RESOURCES;
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		NXCMD_U32 KGot = 0, KTotal = 0, KScanned = 0;
		CONST NTSTATUS KSt = NxcPoolList(KBuf, KCap, Command->TargetModuleId,
		                                 Command->ReadOffset, &KGot, &KTotal, &KScanned);
		if (!NT_SUCCESS(KSt))
		{
			ExFreePoolWithTag(KBuf, 'kPxN');
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)KSt;
			return KSt;
		}

		SIZE_T KCopied = 0;
		CONST NTSTATUS KOut =
			MmCopyVirtualMemory(PsGetCurrentProcess(), KBuf,
			                    PsGetCurrentProcess(), (PVOID)(ULONG_PTR)KFirst,
			                    KGot * sizeof(NXCMD_POOL_ENTRY), KernelMode, &KCopied);
		ExFreePoolWithTag(KBuf, 'kPxN');

		if (!NT_SUCCESS(KOut))
		{
			Command->Result = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)KOut;
			return KOut;
		}

		/*
		 * THREE numbers, not two, and the third is what makes a null result readable: Scanned says
		 * how many entries existed BEFORE the filter. Without it, "no matches" and "the enumeration
		 * returned nothing at all" are indistinguishable, and they need opposite investigations.
		 */
		Command->BytesRead  = KGot;       /* returned */
		Command->ModuleSize = KTotal;     /* matched the filter */
		Command->ModuleBase = KScanned;   /* existed before filtering */
		Command->Result     = NXCMD_RESULT_OK;
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_PG_SCAN:
	{
		/*
		 * Is a PatchGuard context resident? READ ONLY -- see Drivers/NexusCore/PgScan.h for the
		 * signatures, the int 20h trap, and why a zero result proves nothing on its own.
		 */
		Command->BytesRead  = 0;
		Command->ModuleBase = 0;
		Command->ModuleSize = 0;

		CONST NXCMD_U64 GFirst = Command->OutBuffer;
		CONST NXCMD_U64 GLast  = GFirst + (NXCMD_U64)Command->ReadLength;
		if (Command->ReadLength < sizeof(NXCMD_PG_CANDIDATE) ||
		    Command->ReadLength > NXCMD_READ_MAX ||
		    GFirst < NXC_USER_VA_FLOOR || GLast > NXC_USER_VA_CEILING || GLast <= GFirst)
		{
			Command->Result = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_ADDRESS;
			return STATUS_INVALID_ADDRESS;
		}

		CONST NXCMD_U32 GCap = Command->ReadLength / (NXCMD_U32)sizeof(NXCMD_PG_CANDIDATE);
		NXC_PG_CANDIDATE* CONST GBuf =
			(NXC_PG_CANDIDATE*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
			                                   GCap * sizeof(NXC_PG_CANDIDATE), 'gPxN');
		if (GBuf == NULL)
		{
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INSUFFICIENT_RESOURCES;
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		NXCMD_U32 GGot = 0, GTotal = 0, GScanned = 0, GSkipped = 0, GAvail = 0;
		NXCMD_U64 GBytes = 0;
		CONST NTSTATUS GSt = NxcPgScan(GBuf, GCap, Command->ReadOffset,
		                               &GGot, &GTotal, &GScanned, &GBytes, &GSkipped, &GAvail);
		if (!NT_SUCCESS(GSt))
		{
			ExFreePoolWithTag(GBuf, 'gPxN');
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)GSt;
			return GSt;
		}

		SIZE_T GCopied = 0;
		CONST NTSTATUS GOut =
			MmCopyVirtualMemory(PsGetCurrentProcess(), GBuf,
			                    PsGetCurrentProcess(), (PVOID)(ULONG_PTR)GFirst,
			                    GGot * sizeof(NXC_PG_CANDIDATE), KernelMode, &GCopied);
		ExFreePoolWithTag(GBuf, 'gPxN');

		if (!NT_SUCCESS(GOut))
		{
			Command->Result = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)GOut;
			return GOut;
		}

		/*
		 * ⚠ SCANNED AND SKIPPED TRAVEL WITH THE RESULT, and they are the difference between a
		 * readable zero and a misleading one. "No candidates" after examining 300 allocations
		 * means something; after examining 0, or after skipping 300 as non-resident, it means
		 * the scan did not happen. Those need opposite investigations, so the caller gets both
		 * numbers rather than a verdict.
		 *
		 * Skipped is packed into the high half of ModuleBase because the transport has no
		 * fourth counter and inventing one for a diagnostic is not worth a protocol change.
		 */
		Command->BytesRead  = GGot;                                     /* returned    */
		Command->ModuleSize = GTotal;                                   /* candidates  */
		Command->ModuleBase = ((NXCMD_U64)GSkipped << 32) | GScanned;   /* skipped|examined */

		/*
		 * ⚠ HOW MANY EXIST, not how many fit. "Examined 4096" read like completeness on a boot
		 * with 5845 qualifying allocations; the snapshot had silently truncated. The caller needs
		 * both numbers to say what FRACTION was covered, and a scan that covered 70% must not be
		 * reported the same way as one that covered all of it.
		 */
		Command->ModuleId   = GAvail;
		Command->Result     = NXCMD_RESULT_OK;
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_TRACE_ALLOC:
	{
		/* STAGE 1: allocates ToPA tables and output regions. Writes NO MSR and starts no trace. */
		Command->BytesRead = 0;

		/*
		 * ⚠⚠ THE SIZE CODE ARRIVES AS +1, AND THE PREVIOUS ENCODING WAS A REAL DEFECT.
		 *
		 * This read `(ReadLength != 0) ? ReadLength : NXC_TOPA_SIZE_CODE_DEFAULT`, so 0 meant BOTH
		 * "size code 0, i.e. 4 KB, the smallest legal ToPA region" AND "the caller said nothing, use
		 * the 256 KB default". `trace alloc 0` silently allocated 256 KB.
		 *
		 * ⚠ AND IT WAS CAUGHT BY THE TOOL CONTRADICTING ITSELF, which is the loudest signal available
		 * (an earlier finding): the alloc printed "4096 bytes
		 * each" and the very next `trace status` printed SIZE 262144 on all 24 rows. Two numbers about
		 * one allocation, in consecutive commands.
		 *
		 * A VALID VALUE MUST NEVER DOUBLE AS THE "UNSET" SENTINEL. With +1 on the wire, 0 is
		 * unambiguously "not specified" -- the same convention `trace arm` already uses for OnlyCpu.
		 */
		NXCMD_U32 SizeCode = NXC_TOPA_SIZE_CODE_DEFAULT;
		if (Command->ReadLength != 0)
		{
			CONST NXCMD_U32 Asked = Command->ReadLength - 1u;
			if (Asked > NXC_TOPA_SIZE_CODE_MAX)
			{
				/* Refuse rather than clamp. A clamp would allocate a size nobody asked for and
				 * report success, which is the defect above wearing a different hat. */
				CmdLog("cmd: trace-alloc size code %u is out of range (0..%u)\n",
				       Asked, NXC_TOPA_SIZE_CODE_MAX);
				Command->Result   = NXCMD_RESULT_REFUSED;
				Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_PARAMETER;
				return STATUS_INVALID_PARAMETER;
			}
			SizeCode = Asked;
		}

		NXCMD_U32 Ok = 0;
		CONST NTSTATUS TSt = NxcTraceAlloc(SizeCode, &Ok);
		Command->BytesRead = Ok;
		Command->NtStatus  = (NXCMD_U64)(ULONG_PTR)TSt;
		if (!NT_SUCCESS(TSt))
		{
			Command->Result = NXCMD_RESULT_REFUSED;
			return TSt;
		}
		/*
		 * ⚠ REPORT THE REGION SIZE THE KERNEL ACTUALLY USED (D3). Usermode used to print a size it
		 * computed from its own argument, which is an ECHO and not a measurement -- it agreed with
		 * itself while disagreeing with the hardware. Now the number comes from this side.
		 */
		Command->ModuleSize = (NXCMD_U32)SizeCode;
		Command->ModuleBase = (NXCMD_U64)1 << (12 + SizeCode);
		Command->Result = NXCMD_RESULT_OK;
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_PEBS_ALLOC:
	{
		NXCMD_U32 POk = 0;
		CONST NXCMD_U32 PRecs = (Command->ReadLength != 0) ? Command->ReadLength : 1024u;
		/* Flags carries the max record size to reserve for -- 0 means the no-LBR default.
		 * Sizing for the worst case unconditionally cost ~23 MB contiguous per alloc. */
		CONST NTSTATUS PSt = NxcPebsAlloc(PRecs, (NXCMD_U32)Command->Flags, &POk);
		Command->BytesRead = POk;
		/*
		 * ⚠ RETURN THE STRIDE ACTUALLY RESERVED, NOT THE ONE ASKED FOR (D3).
		 *
		 * NxcPebsAlloc CLAMPS the request to what this build can honour. Without this the caller
		 * printed "reserving 1232 byte(s) per record" while the kernel had quietly reserved 976 --
		 * a message describing the REQUEST and presenting it as the RESULT, which is the defect
		 * this project names most often. Found by running a new PlatformCtl against an
		 * older kernel on purpose.
		 */
		Command->ModuleBase = (NXCMD_U64)NxcPebsAllocStride();
		Command->NtStatus  = (NXCMD_U64)(ULONG_PTR)PSt;
		Command->Result    = NT_SUCCESS(PSt) ? NXCMD_RESULT_OK : NXCMD_RESULT_REFUSED;
		return PSt;
	}

	case NXCMD_OP_PEBS_ARM:
	{
		UINT64 BCr3 = 0;
		if (Command->TargetModuleId != 0)
		{
			PVOID BProc = NULL;
			if (!NT_SUCCESS(PsLookupProcessByProcessId(
			        (HANDLE)(ULONG_PTR)Command->TargetModuleId, &BProc)) || BProc == NULL)
			{
				Command->Result   = NXCMD_RESULT_REFUSED;
				Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_NOT_FOUND;
				return STATUS_NOT_FOUND;
			}
			NXC_XLAT BProbe;
			(void)NxcTranslate(BProc, 0x10000, &BProbe);
			BCr3 = BProbe.Cr3;
			ObfDereferenceObject(BProc);
		}

		NXCMD_U32 BArmed = 0;
		/* Flags carries WHICH GROUPS the caller wants in a record (NXCMD_PEBS_ARM_FLAG_*). It is
		 * intent, not an MSR value -- NxcPebsArm translates and refuses anything it does not
		 * recognise, because this register sets how many bytes the CPU writes per record. */
		/* ReadLength carries the load-latency threshold in cycles; 0 keeps INST_RETIRED. */
		CONST NTSTATUS BSt = NxcPebsArm(BCr3, Command->ReadOffset,
		                                (NXCMD_U32)Command->Flags,
		                                (NXCMD_U32)Command->ReadLength, &BArmed);
		Command->BytesRead  = BArmed;
		Command->ModuleBase = BCr3;
		/*
		 * ⚠ THE DATA_CFG READ-BACK COMES HOME THROUGH THE COMMAND, NOT THE LOG.
		 *
		 * It was first written with TrcLog, which is NxcLogExt, which is DbgPrint -- invisible to an
		 * operator without a kernel debugger. The `log` ring carries structured command events only,
		 * so the answer to "did the GPR bit take" went somewhere nobody could read it. That is the
		 * fifth occurrence of an earlier finding, and it
		 * happened while fixing a defect whose whole content was "this was never read back".
		 *
		 * ReadOffset carried the period IN; it is free to carry the answer OUT.
		 *
		 * ⚠ AND THEN IT WAS TAKEN BACK OUT AGAIN, WHICH IS THE MORE USEFUL LESSON.
		 *
		 * Returning DATA_CFG here proved nothing: it read back 0x2 exactly as requested while every
		 * record stayed Basic-only, because the missing bit lived in a SECOND register
		 * (IA32_PERFEVTSEL0.Adaptive_Record). Carrying that one home too meant scavenging a second
		 * ad-hoc field -- and the first field tried, ModuleSize, is 32 bits wide against a bit at
		 * position 34. The compiler refused it, which was luck standing in for design.
		 *
		 * Both read-backs now live in NXCMD_PEBS_CPU_STATE and come back through `pebs status`, which
		 * reports them FOR ALL 24 CORES rather than core 0 alone -- and on a hybrid part that
		 * difference is the whole point. `pebs arm` in PlatformCtl issues a status read straight
		 * after arming and summarises from it, so there is ONE expression for these values instead of
		 * two that have to agree.
		 */
		/*
		 * ⚠⚠ WHETHER THE FILTER IS ACTUALLY LIVE, REPORTED BY THE KERNEL THAT ARMED IT.
		 *
		 * PlatformCtl must NOT print its scope line from the flags it sent -- that is reporting the
		 * REQUEST as though it were the RESULT (D3), and this exact surface has already shipped that
		 * bug twice: a CR3 that was resolved and never applied, and a "RING-3" label printed while
		 * --kernel had configured both rings.
		 *
		 * It also fails a real case: an OLD driver paired with a NEW PlatformCtl accepts the flag
		 * (it is inside NXCMD_PEBS_ARM_FLAG_ALL) and ignores it, so the caller would announce a
		 * filter that no code is running. ModuleId comes back 0 there, and the claim collapses to
		 * the honest one on its own.
		 */
		{
			NXCMD_U32 FActive = 0;
			UINT64    FK = 0, FR = 0, FP = 0;
			NxcPebsFilterStats(&FActive, &FK, &FR, &FP);
			Command->ModuleId = NT_SUCCESS(BSt) ? FActive : 0;
		}

		Command->NtStatus   = (NXCMD_U64)(ULONG_PTR)BSt;
		Command->Result     = NT_SUCCESS(BSt) ? NXCMD_RESULT_OK : NXCMD_RESULT_REFUSED;
		return BSt;
	}

	case NXCMD_OP_PEBS_DRAIN:
	{
		Command->BytesRead  = 0;
		Command->ModuleSize = 0;

		CONST NXCMD_U64 DFirst = Command->OutBuffer;
		CONST NXCMD_U64 DLast  = DFirst + (NXCMD_U64)Command->ReadLength;
		if (Command->ReadLength == 0 || Command->ReadLength > NXCMD_READ_MAX ||
		    DFirst < NXC_USER_VA_FLOOR || DLast > NXC_USER_VA_CEILING || DLast <= DFirst)
		{
			Command->Result   = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_ADDRESS;
			return STATUS_INVALID_ADDRESS;
		}

		void* CONST DBuf = ExAllocatePool2(POOL_FLAG_NON_PAGED, Command->ReadLength, 'dPxN');
		if (DBuf == NULL)
		{
			Command->Result   = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INSUFFICIENT_RESOURCES;
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		NXCMD_U32 DGot = 0, DWritten = 0;
		CONST NTSTATUS DSt = NxcPebsDrain(Command->TargetModuleId, DBuf, Command->ReadLength,
		                                  &DGot, &DWritten);
		if (!NT_SUCCESS(DSt))
		{
			ExFreePoolWithTag(DBuf, 'dPxN');
			Command->Result   = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)DSt;
			return DSt;
		}

		SIZE_T DCopied = 0;
		CONST NTSTATUS DOut =
			MmCopyVirtualMemory(PsGetCurrentProcess(), DBuf,
			                    PsGetCurrentProcess(), (PVOID)(ULONG_PTR)DFirst,
			                    DGot, KernelMode, &DCopied);
		ExFreePoolWithTag(DBuf, 'dPxN');
		if (!NT_SUCCESS(DOut))
		{
			Command->Result   = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)DOut;
			return DOut;
		}

		/* bytes RETURNED and bytes the CPU actually WROTE -- D3, because a short buffer and a short
		 * capture are different facts and only one of them is a problem. */
		Command->BytesRead  = DGot;
		Command->ModuleSize = DWritten;
		Command->Result     = NXCMD_RESULT_OK;
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_PEBS_DISARM:
	{
		NXCMD_U32 BOff = 0;
		CONST NTSTATUS BSt = NxcPebsDisarm(&BOff);
		Command->BytesRead = BOff;
		Command->NtStatus  = (NXCMD_U64)(ULONG_PTR)BSt;
		Command->Result    = NT_SUCCESS(BSt) ? NXCMD_RESULT_OK : NXCMD_RESULT_REFUSED;
		return BSt;
	}

	case NXCMD_OP_PEBS_FREE:
	{
		NxcPebsFree();
		Command->BytesRead = 0;
		Command->NtStatus  = 0;
		Command->Result    = NXCMD_RESULT_OK;
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_PEBS_STATUS:
	{
		Command->BytesRead  = 0;
		Command->ModuleSize = 0;

		/*
		 * THE PMI CR3 FILTER TALLY. Restored after the bugchecks were traced to a
		 * use-after-free in NxcPebsFree rather than to the NMI source -- see the block above
		 * NXCMD_PEBS_ARM_FLAG_PMIFILTER.
		 *
		 * ⚠ FOUR NUMBERS SAMPLED IN ONE CALL, and that matters: kept and rejected are read as a
		 * RATIO by the caller, and two separate accessors could straddle an update and produce a
		 * ratio that never existed. `Active` travels with them so usermode can tell "filter off"
		 * from "filter on and nothing matched" -- which are the same 0/0 otherwise.
		 */
		/*
		 * ⚠ ModuleBase IS NOT AVAILABLE HERE -- it carries sizeof(NXCMD_PEBS_CPU_STATE) for the
		 * record-size handshake at the end of this handler, which would overwrite anything put here.
		 * So the PMI COUNT stays kernel-side (it is logged by NxcPebsDisarm) and the wire carries the
		 * three numbers that change a reader's next action: kept, rejected, and whether the filter
		 * was on at all. "Active with nothing judged" already covers the diagnostic the PMI count
		 * would have served -- no interrupts arriving and no records written prompt the same look.
		 */
		{
			NXCMD_U32 FActive = 0;
			UINT64    FKept = 0, FRej = 0, FPmis = 0;
			NxcPebsFilterStats(&FActive, &FKept, &FRej, &FPmis);

			Command->ReadOffset  = FKept;
			Command->ImageBuffer = FRej;
			Command->ModuleId    = FActive;
			(void)FPmis;

			/*
			 * ⚠ THE TARGET CR3 THE FILTER IS COMPARING AGAINST. Carried because the filter judged
			 * 277,041 records and kept ZERO with the target provably spinning -- which means the
			 * COMPARISON is wrong, and a comparison cannot be debugged from one side of it.
			 * ⚠ RIDES IN NtStatus, AND ONLY SURVIVES ON SUCCESS. Every failure path below assigns
			 * NtStatus its real error before returning, so this value is visible only when Result
			 * is OK -- which is exactly when a status code carries no information anyway. Pinned
			 * here beside the assignment because a field whose meaning depends on the opcode is
			 * the ambiguity this header warns about; it is acceptable only stated.
			 */
			Command->NtStatus = NxcPebsTargetCr3();

			/*
			 * Sample loss, carried in two fields this opcode does not otherwise use. Pinned here:
			 * DiagFlags = records DISCARDED as unattributable, DiagRefusalLine = matches LOST to a
			 * full keep buffer. Saturating, because the exact number matters far less than the fact
			 * that it is not zero -- and a filter that hides its losses is the thing being fixed.
			 */
			{
				UINT64 LDrop = 0, LFull = 0;
				NxcPebsFilterLoss(&LDrop, &LFull);
				Command->DiagFlags       = (NXCMD_U32)((LDrop > 0xFFFFFFFFull) ? 0xFFFFFFFFul : LDrop);
				Command->DiagRefusalLine = (NXCMD_U32)((LFull > 0xFFFFFFFFull) ? 0xFFFFFFFFul : LFull);
			}
		}

		CONST NXCMD_U64 QFirst = Command->OutBuffer;
		CONST NXCMD_U64 QLast  = QFirst + (NXCMD_U64)Command->ReadLength;
		if (Command->ReadLength < sizeof(NXCMD_PEBS_CPU_STATE) ||
		    Command->ReadLength > NXCMD_READ_MAX ||
		    QFirst < NXC_USER_VA_FLOOR || QLast > NXC_USER_VA_CEILING || QLast <= QFirst)
		{
			Command->Result   = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_ADDRESS;
			return STATUS_INVALID_ADDRESS;
		}

		CONST NXCMD_U32 QCap = Command->ReadLength / (NXCMD_U32)sizeof(NXCMD_PEBS_CPU_STATE);
		NXCMD_PEBS_CPU_STATE* CONST QBuf =
			(NXCMD_PEBS_CPU_STATE*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
			                                       (SIZE_T)QCap * sizeof(NXCMD_PEBS_CPU_STATE), 'bPxN');
		if (QBuf == NULL)
		{
			Command->Result   = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INSUFFICIENT_RESOURCES;
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		NXCMD_U32 QGot = 0, QTotal = 0;
		CONST NTSTATUS QSt = NxcPebsStatus(QBuf, QCap, &QGot, &QTotal);
		if (!NT_SUCCESS(QSt))
		{
			ExFreePoolWithTag(QBuf, 'bPxN');
			Command->Result   = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)QSt;
			return QSt;
		}

		SIZE_T QCopied = 0;
		CONST NTSTATUS QOut =
			MmCopyVirtualMemory(PsGetCurrentProcess(), QBuf,
			                    PsGetCurrentProcess(), (PVOID)(ULONG_PTR)QFirst,
			                    (SIZE_T)QGot * sizeof(NXCMD_PEBS_CPU_STATE), KernelMode, &QCopied);
		ExFreePoolWithTag(QBuf, 'bPxN');
		if (!NT_SUCCESS(QOut))
		{
			Command->Result   = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)QOut;
			return QOut;
		}

		Command->BytesRead  = QGot;
		Command->ModuleSize = QTotal;
		Command->ModuleBase = (NXCMD_U64)sizeof(NXCMD_PEBS_CPU_STATE);
		Command->Result     = NXCMD_RESULT_OK;
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_SAMPLE_ARM:
	{
		/* pid -> CR3, the same way trace-arm scopes a trace. 0 means every process. */
		UINT64 SCr3 = 0;
		if (Command->TargetModuleId != 0)
		{
			PVOID SProc = NULL;
			if (!NT_SUCCESS(PsLookupProcessByProcessId(
			        (HANDLE)(ULONG_PTR)Command->TargetModuleId, &SProc)) || SProc == NULL)
			{
				Command->Result   = NXCMD_RESULT_REFUSED;
				Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_NOT_FOUND;
				return STATUS_NOT_FOUND;
			}
			NXC_XLAT SProbe;
			(void)NxcTranslate(SProc, 0x10000, &SProbe);
			SCr3 = SProbe.Cr3;
			ObfDereferenceObject(SProc);
		}

		NXCMD_U32 SArmed = 0;
		CONST NTSTATUS SSt = NxcSampleArm(SCr3, Command->ReadOffset, &SArmed);
		Command->BytesRead  = SArmed;
		Command->ModuleBase = SCr3;
		Command->NtStatus   = (NXCMD_U64)(ULONG_PTR)SSt;
		Command->Result     = NT_SUCCESS(SSt) ? NXCMD_RESULT_OK : NXCMD_RESULT_REFUSED;
		return SSt;
	}

	case NXCMD_OP_SAMPLE_DISARM:
	{
		NXCMD_U32 SGot = 0, SLost = 0;
		CONST NTSTATUS SSt = NxcSampleDisarm(&SGot, &SLost);
		Command->BytesRead  = SGot;
		Command->ModuleSize = SLost;
		Command->NtStatus   = (NXCMD_U64)(ULONG_PTR)SSt;
		Command->Result     = NT_SUCCESS(SSt) ? NXCMD_RESULT_OK : NXCMD_RESULT_REFUSED;
		return SSt;
	}

	case NXCMD_OP_SAMPLE_READ:
	{
		Command->BytesRead  = 0;
		Command->ModuleSize = 0;

		CONST NXCMD_U64 SFirst = Command->OutBuffer;
		CONST NXCMD_U64 SLast  = SFirst + (NXCMD_U64)Command->ReadLength;
		if (Command->ReadLength < sizeof(NXCMD_SAMPLE_ENTRY) ||
		    Command->ReadLength > NXCMD_READ_MAX ||
		    SFirst < NXC_USER_VA_FLOOR || SLast > NXC_USER_VA_CEILING || SLast <= SFirst)
		{
			Command->Result   = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_ADDRESS;
			return STATUS_INVALID_ADDRESS;
		}

		CONST NXCMD_U32 SCap = Command->ReadLength / (NXCMD_U32)sizeof(NXCMD_SAMPLE_ENTRY);
		NXCMD_SAMPLE_ENTRY* CONST SBuf =
			(NXCMD_SAMPLE_ENTRY*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
			                                     (SIZE_T)SCap * sizeof(NXCMD_SAMPLE_ENTRY), 'sTxN');
		if (SBuf == NULL)
		{
			Command->Result   = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INSUFFICIENT_RESOURCES;
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		NXCMD_U32 SGot = 0, STotal = 0, SLost = 0;
		CONST NTSTATUS SSt = NxcSampleDrain(SBuf, SCap, &SGot, &STotal, &SLost);
		if (!NT_SUCCESS(SSt))
		{
			ExFreePoolWithTag(SBuf, 'sTxN');
			Command->Result   = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)SSt;
			return SSt;
		}

		SIZE_T SCopied = 0;
		CONST NTSTATUS SOut =
			MmCopyVirtualMemory(PsGetCurrentProcess(), SBuf,
			                    PsGetCurrentProcess(), (PVOID)(ULONG_PTR)SFirst,
			                    (SIZE_T)SGot * sizeof(NXCMD_SAMPLE_ENTRY), KernelMode, &SCopied);
		ExFreePoolWithTag(SBuf, 'sTxN');
		if (!NT_SUCCESS(SOut))
		{
			Command->Result   = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)SOut;
			return SOut;
		}

		/* count, total AND lost -- three different facts (D3). */
		Command->BytesRead  = SGot;
		Command->ModuleSize = STotal;
		Command->ReadLength = SLost;
		Command->ModuleBase = (NXCMD_U64)sizeof(NXCMD_SAMPLE_ENTRY);
		Command->Result     = NXCMD_RESULT_OK;
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_PTE_SCAN:
	{
		/*
		 * Walk a VA RANGE in a target and report the ACCESSED/DIRTY/present state of every page.
		 *
		 * ⚠ NOTHING IS TOUCHED, FAULTED OR CLEARED. NxcTranslate DECODES the tables rather than
		 * probing the address, which is the property D21 established when it reversed D19: v1
		 * faulted pages in and blew up the target's working set, and non-perturbation is a
		 * framework property here rather than a preference. That is exactly what makes A/D worth
		 * reading -- the measurement does not disturb what it measures.
		 *
		 * ⚠ REACHED BY PEPROCESS, NEVER KeStackAttachProcess (D1).
		 */
		Command->BytesRead  = 0;
		Command->ModuleSize = 0;

		CONST NXCMD_U64 PFirst = Command->OutBuffer;
		CONST NXCMD_U64 PLast  = PFirst + (NXCMD_U64)Command->ReadLength;
		if (Command->ReadLength < sizeof(NXCMD_PTE_PAGE) ||
		    Command->ReadLength > NXCMD_READ_MAX ||
		    PFirst < NXC_USER_VA_FLOOR || PLast > NXC_USER_VA_CEILING || PLast <= PFirst)
		{
			Command->Result   = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_ADDRESS;
			return STATUS_INVALID_ADDRESS;
		}

		PVOID PProc = NULL;
		if (!NT_SUCCESS(PsLookupProcessByProcessId(
		        (HANDLE)(ULONG_PTR)Command->TargetModuleId, &PProc)) || PProc == NULL)
		{
			Command->Result   = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_NOT_FOUND;
			return STATUS_NOT_FOUND;
		}

		CONST NXCMD_U32 PCap = Command->ReadLength / (NXCMD_U32)sizeof(NXCMD_PTE_PAGE);
		NXCMD_PTE_PAGE* CONST PBuf =
			(NXCMD_PTE_PAGE*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
			                                 (SIZE_T)PCap * sizeof(NXCMD_PTE_PAGE), 'pTxN');
		if (PBuf == NULL)
		{
			ObfDereferenceObject(PProc);
			Command->Result   = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INSUFFICIENT_RESOURCES;
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		/*
		 * ⚠ BOTH `count` AND `total` (D3). The requested span can exceed what one OutBuffer holds,
		 * and a caller told only how many rows came back cannot tell a short buffer from a short
		 * range. PagesAsked is what the span covers; BytesRead is what was returned.
		 */
		CONST NXCMD_U64 ScanBase  = Command->ReadOffset & ~0xFFFull;
		CONST NXCMD_U64 ScanBytes = (Command->ImageSize != 0) ? Command->ImageSize : 0x1000;
		CONST NXCMD_U64 PagesAsked = (ScanBytes + 0xFFFull) / 0x1000ull;

		NXCMD_U32 Got = 0;
		for (NXCMD_U64 i = 0; i < PagesAsked && Got < PCap; i++)
		{
			CONST NXCMD_U64 Va = ScanBase + i * 0x1000ull;

			NXC_XLAT X;
			(void)NxcTranslate(PProc, Va, &X);

			PBuf[Got].Va        = Va;
			PBuf[Got].Pfn       = X.PhysicalAddress & ~0xFFFull;
			PBuf[Got].Entry     = X.Entries[3];   /* the leaf: PTE, or the PDE for a large page */
			PBuf[Got].Flags     = X.Flags;
			PBuf[Got].Level     = X.Level;
			PBuf[Got].SoftState = X.SoftState;
			PBuf[Got].Reserved0 = 0;
			/* A large page answers for its whole span, so record the level and let usermode say so
			 * rather than silently emitting 512 identical rows for one 2 MB mapping. */
			if (X.Level == 3) PBuf[Got].Entry = X.Entries[2];
			Got++;
		}

		SIZE_T PCopied = 0;
		CONST NTSTATUS POut =
			MmCopyVirtualMemory(PsGetCurrentProcess(), PBuf,
			                    PsGetCurrentProcess(), (PVOID)(ULONG_PTR)PFirst,
			                    (SIZE_T)Got * sizeof(NXCMD_PTE_PAGE), KernelMode, &PCopied);
		ExFreePoolWithTag(PBuf, 'pTxN');
		ObfDereferenceObject(PProc);

		if (!NT_SUCCESS(POut))
		{
			Command->Result   = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)POut;
			return POut;
		}

		Command->BytesRead  = Got;
		Command->ModuleSize = (NXCMD_U32)PagesAsked;
		Command->ModuleBase = (NXCMD_U64)sizeof(NXCMD_PTE_PAGE);
		Command->Result     = NXCMD_RESULT_OK;
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_TRACE_ARM:
	{
		/*
		 * Resolve the pid to a CR3 so the trace can be scoped. Done HERE rather than in Trace.c
		 * because the process lookup belongs with the other process-touching code, and Trace.c
		 * should not need to know what a pid is.
		 */
		Command->BytesRead = 0;

		UINT64 Cr3 = 0;
		if (Command->TargetModuleId != 0)
		{
			PVOID TProc = NULL;
			if (!NT_SUCCESS(PsLookupProcessByProcessId(
			        (HANDLE)(ULONG_PTR)Command->TargetModuleId, &TProc)) || TProc == NULL)
			{
				Command->Result = NXCMD_RESULT_REFUSED;
				Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_NOT_FOUND;
				return STATUS_NOT_FOUND;
			}

			NXC_XLAT Probe;
			/* Any VA will do -- the walk reports the CR3 it used, which is what is wanted. Using
			 * the translate path means the DTB offset it depends on has already been PROVEN. */
			(void)NxcTranslate(TProc, 0x10000, &Probe);
			Cr3 = Probe.Cr3;
			ObfDereferenceObject(TProc);

			if (Cr3 == 0)
			{
				CmdLog("cmd: trace-arm pid %u -- could not resolve a CR3 to filter on\n",
				       Command->TargetModuleId);
				Command->Result = NXCMD_RESULT_REFUSED;
				Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_UNSUCCESSFUL;
				return STATUS_UNSUCCESSFUL;
			}
		}

		CONST NXCMD_U32 OnlyCpu = (Command->Flags != 0)
		                        ? (Command->Flags - 1) : 0xFFFFFFFFu;

		/*
		 * ⚠ ReadLength CARRIES THE ARM FLAGS FOR THIS OPCODE, and Flags cannot: it already carries
		 * OnlyCpu+1 two lines up. Reusing a field per opcode is this channel's established
		 * convention (TRACE_STATUS puts --exact in Flags, TRACE_ALLOC puts the size code in
		 * ReadLength) and the rule that makes it safe is that the reuse is documented at BOTH ends.
		 * There is no read here, so no length is being displaced.
		 */
		/*
		 * ADDRESS-RANGE FILTERS arrive as an ARRAY through OutBuffer (D2 -- one transport for bulk
		 * data, already proven), with ImageSize as the count. Spare scalar fields would have capped
		 * this at however many happened to be free; an array scales to whatever the part offers.
		 *
		 * (!) VALIDATED HERE, AT PASSIVE, BEFORE THE IPI. The arm broadcast runs at IPI_LEVEL where a
		 * bad address cannot be probed and a fault cannot be caught, so every check happens on this
		 * side: bounded count, readable source, CANONICAL addresses, Start <= End, and a Cfg the SDM
		 * defines. Each core then re-derives its OWN range count from CPUID -- this machine is hybrid,
		 * and a WRMSR to an ADDRn pair a core does not implement is a #GP with no SEH to catch it.
		 */
		NXCMD_PT_RANGE Ranges[NXCMD_PT_RANGE_MAX];
		NXCMD_U32 RangeCount = 0;

		if (Command->OutBuffer != 0 && Command->ImageSize != 0)
		{
			if (Command->ImageSize > NXCMD_PT_RANGE_MAX)
			{
				CmdLog("cmd: trace-arm %u ranges requested, max %u\n",
				       Command->ImageSize, NXCMD_PT_RANGE_MAX);
				Command->Result   = NXCMD_RESULT_REFUSED;
				Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_PARAMETER;
				return STATUS_INVALID_PARAMETER;
			}

			CONST SIZE_T RBytes  = (SIZE_T)Command->ImageSize * sizeof(NXCMD_PT_RANGE);
			CONST NXCMD_U64 RFirst = Command->OutBuffer;
			CONST NXCMD_U64 RLast  = RFirst + RBytes;
			if (RFirst < NXC_USER_VA_FLOOR || RLast > NXC_USER_VA_CEILING || RLast <= RFirst)
			{
				Command->Result   = NXCMD_RESULT_COPY_FAILED;
				Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_ADDRESS;
				return STATUS_INVALID_ADDRESS;
			}

			SIZE_T RCopied = 0;
			CONST NTSTATUS RSt =
				MmCopyVirtualMemory(PsGetCurrentProcess(), (PVOID)(ULONG_PTR)RFirst,
				                    PsGetCurrentProcess(), Ranges, RBytes, KernelMode, &RCopied);
			if (!NT_SUCCESS(RSt) || RCopied != RBytes)
			{
				Command->Result   = NXCMD_RESULT_COPY_FAILED;
				Command->NtStatus = (NXCMD_U64)(ULONG_PTR)RSt;
				return RSt;
			}

			for (NXCMD_U32 r = 0; r < Command->ImageSize; r++)
			{
				/* (!) CANONICAL, BOTH ENDS. A non-canonical value in an ADDRn MSR faults on the WRMSR
				 * itself -- refused here rather than discovered at IPI_LEVEL. */
				CONST NXCMD_U64 A = Ranges[r].Start, B = Ranges[r].End;
				CONST BOOLEAN CanonA = (A <= 0x00007FFFFFFFFFFFull) || (A >= 0xFFFF800000000000ull);
				CONST BOOLEAN CanonB = (B <= 0x00007FFFFFFFFFFFull) || (B >= 0xFFFF800000000000ull);
				CONST BOOLEAN CfgOk  = (Ranges[r].Cfg == NXCMD_PT_RANGE_FILTER) ||
				                       (Ranges[r].Cfg == NXCMD_PT_RANGE_STOP);
				if (!CanonA || !CanonB || !CfgOk || A > B)
				{
					CmdLog("cmd: trace-arm range %u rejected (0x%llX..0x%llX cfg %u)\n",
					       r, A, B, Ranges[r].Cfg);
					Command->Result   = NXCMD_RESULT_REFUSED;
					Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_PARAMETER;
					return STATUS_INVALID_PARAMETER;
				}
			}
			RangeCount = Command->ImageSize;
		}

		/*
		 * TIMING REQUEST (D117), carried in ImageBuffer -- unused on this opcode, and a pointer field
		 * rather than a scavenged scalar, so the struct travels intact and can grow.
		 *
		 * (!) THE ENCODINGS ARE RANGE-CHECKED HERE AND CAPABILITY-CHECKED ON EACH CORE, and both are
		 * needed. This check rejects a value that is not a 4-bit encoding at all; only the core
		 * itself knows which of the 16 it IMPLEMENTS, and writing an unimplemented one is a #GP with
		 * no SEH to catch it. Refusing early keeps the obvious mistakes out of an IPI broadcast.
		 */
		NXCMD_PT_TIMING Timing;
		BOOLEAN HaveTiming = FALSE;
		if (Command->ImageBuffer != 0)
		{
			CONST NXCMD_U64 TFirst = Command->ImageBuffer;
			CONST NXCMD_U64 TLast  = TFirst + sizeof(NXCMD_PT_TIMING);
			if (TFirst < NXC_USER_VA_FLOOR || TLast > NXC_USER_VA_CEILING || TLast <= TFirst)
			{
				Command->Result   = NXCMD_RESULT_COPY_FAILED;
				Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_ADDRESS;
				return STATUS_INVALID_ADDRESS;
			}

			SIZE_T TCopied = 0;
			CONST NTSTATUS TSt =
				MmCopyVirtualMemory(PsGetCurrentProcess(), (PVOID)(ULONG_PTR)TFirst,
				                    PsGetCurrentProcess(), &Timing, sizeof(Timing),
				                    KernelMode, &TCopied);
			if (!NT_SUCCESS(TSt) || TCopied != sizeof(Timing))
			{
				Command->Result   = NXCMD_RESULT_COPY_FAILED;
				Command->NtStatus = (NXCMD_U64)(ULONG_PTR)TSt;
				return TSt;
			}

			if ((Timing.MtcFreq   != NXCMD_PT_TIMING_UNSET && Timing.MtcFreq   > 15u) ||
			    (Timing.CycThresh != NXCMD_PT_TIMING_UNSET && Timing.CycThresh > 15u) ||
			    (Timing.PsbFreq   != NXCMD_PT_TIMING_UNSET && Timing.PsbFreq   > 15u))
			{
				CmdLog("cmd: trace-arm timing encoding out of range (mtc %u cyc %u psb %u)\n",
				       Timing.MtcFreq, Timing.CycThresh, Timing.PsbFreq);
				Command->Result   = NXCMD_RESULT_REFUSED;
				Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_PARAMETER;
				return STATUS_INVALID_PARAMETER;
			}

			/* FUPonPTW without PTWEn asks the CPU to pair an IP with a payload that will never be
			 * emitted. Refused rather than silently ignored, so the caller learns which of the two
			 * they forgot. */
			if (Timing.WantFupOnPtw != 0 && Timing.WantPtw == 0)
			{
				CmdLog("cmd: trace-arm FUPonPTW requested without PTWEn\n");
				Command->Result   = NXCMD_RESULT_REFUSED;
				Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_PARAMETER;
				return STATUS_INVALID_PARAMETER;
			}

			HaveTiming = TRUE;
		}

		NXCMD_U32 Armed = 0, RangeRefused = 0, TimingRefused = 0;
		CONST NTSTATUS ASt = NxcTraceArm(Cr3, OnlyCpu, Command->ReadLength,
		                                 (RangeCount != 0) ? Ranges : NULL, RangeCount,
		                                 HaveTiming ? &Timing : NULL,
		                                 &Armed, &RangeRefused, &TimingRefused);

		Command->BytesRead  = Armed;
		/* Cores that took the TRACE but refused the FILTERS -- tracing MORE than asked, not less.
		 * 'armed: N' alone would hide that entirely. */
		Command->ModuleSize = RangeRefused;
		/* Cores that took the TRACE but refused the TIMING. A SEPARATE count from RangeRefused on
		 * purpose: they are different failures with different fixes, and one merged "something was
		 * refused" number is the diagnostic that cannot distinguish its own failure modes. */
		Command->ReadOffset = TimingRefused;
		Command->ModuleBase = Cr3;
		Command->NtStatus   = (NXCMD_U64)(ULONG_PTR)ASt;
		Command->Result     = NT_SUCCESS(ASt) ? NXCMD_RESULT_OK : NXCMD_RESULT_REFUSED;
		return ASt;
	}

	case NXCMD_OP_TRACE_DISARM:
	{
		NXCMD_U32 Off = 0;
		CONST NTSTATUS DSt = NxcTraceDisarm(&Off);
		Command->BytesRead = Off;
		Command->NtStatus  = (NXCMD_U64)(ULONG_PTR)DSt;
		Command->Result    = NT_SUCCESS(DSt) ? NXCMD_RESULT_OK : NXCMD_RESULT_REFUSED;
		return DSt;
	}

	case NXCMD_OP_TRACE_FREE:
	{
		NxcTraceFree();
		Command->BytesRead = 0;
		Command->NtStatus  = 0;
		Command->Result    = NXCMD_RESULT_OK;
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_TRACE_STATUS:
	{
		Command->BytesRead  = 0;
		Command->ModuleSize = 0;

		CONST NXCMD_U64 TFirst = Command->OutBuffer;
		CONST NXCMD_U64 TLast  = TFirst + (NXCMD_U64)Command->ReadLength;
		if (Command->ReadLength < sizeof(NXCMD_TRACE_CPU_STATE) ||
		    Command->ReadLength > NXCMD_READ_MAX ||
		    TFirst < NXC_USER_VA_FLOOR || TLast > NXC_USER_VA_CEILING || TLast <= TFirst)
		{
			Command->Result = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_ADDRESS;
			return STATUS_INVALID_ADDRESS;
		}

		CONST NXCMD_U32 TCap = Command->ReadLength / (NXCMD_U32)sizeof(NXCMD_TRACE_CPU_STATE);
		NXCMD_TRACE_CPU_STATE* CONST TBuf =
			(NXCMD_TRACE_CPU_STATE*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
			                                        TCap * sizeof(NXCMD_TRACE_CPU_STATE), 'tTxN');
		if (TBuf == NULL)
		{
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INSUFFICIENT_RESOURCES;
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		NXCMD_U32 TGot = 0, TTotal = 0;
		/* ⚠ Flags bit 0 = EXACT: stop the trace briefly so the byte count is exact rather than a lower
		 * bound. Opt-in because it perturbs what it measures. */
		CONST NTSTATUS TSt = NxcTraceStatus(TBuf, TCap, &TGot, &TTotal,
		                                    (Command->Flags & 1u) != 0);
		if (!NT_SUCCESS(TSt))
		{
			ExFreePoolWithTag(TBuf, 'tTxN');
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)TSt;
			return TSt;
		}

		SIZE_T TCopied = 0;
		CONST NTSTATUS TOut =
			MmCopyVirtualMemory(PsGetCurrentProcess(), TBuf,
			                    PsGetCurrentProcess(), (PVOID)(ULONG_PTR)TFirst,
			                    TGot * sizeof(NXCMD_TRACE_CPU_STATE), KernelMode, &TCopied);
		ExFreePoolWithTag(TBuf, 'tTxN');

		if (!NT_SUCCESS(TOut))
		{
			Command->Result = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)TOut;
			return TOut;
		}

		Command->BytesRead  = TGot;
		Command->ModuleSize = TTotal;
		/*
		 * ⚠ THE RECORD SIZE TRAVELS WITH THE RECORDS. Twice a payload one build behind
		 * PlatformCtl wrote records of one stride while usermode walked them with another, and the
		 * output was pids in the millions and names bleeding between entries. This struct just grew by
		 * five fields, which is exactly the moment that happens
		 * (an earlier finding). Usermode REFUSES on a
		 * mismatch rather than dividing by a stride the other side does not use.
		 */
		Command->ModuleBase = (NXCMD_U64)sizeof(NXCMD_TRACE_CPU_STATE);
		Command->Result     = NXCMD_RESULT_OK;
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_CPU_PROBE:
	{
		Command->BytesRead  = 0;
		Command->ModuleBase = 0;
		Command->ModuleSize = 0;

		CONST NXCMD_U64 CFirst = Command->OutBuffer;
		CONST NXCMD_U64 CLast  = CFirst + (NXCMD_U64)Command->ReadLength;
		if (Command->ReadLength < sizeof(NXCMD_CPU_TRACE_CAPS) ||
		    Command->ReadLength > NXCMD_READ_MAX ||
		    CFirst < NXC_USER_VA_FLOOR || CLast > NXC_USER_VA_CEILING || CLast <= CFirst)
		{
			Command->Result = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_ADDRESS;
			return STATUS_INVALID_ADDRESS;
		}

		CONST NXCMD_U32 PCap = Command->ReadLength / (NXCMD_U32)sizeof(NXCMD_CPU_TRACE_CAPS);
		NXCMD_CPU_TRACE_CAPS* CONST PBuf =
			(NXCMD_CPU_TRACE_CAPS*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
			                                       PCap * sizeof(NXCMD_CPU_TRACE_CAPS), 'pCxN');
		if (PBuf == NULL)
		{
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INSUFFICIENT_RESOURCES;
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		NXCMD_U32 PGot = 0, PTotal = 0;
		CONST NTSTATUS PSt = NxcCpuProbe(PBuf, PCap, &PGot, &PTotal);
		if (!NT_SUCCESS(PSt))
		{
			ExFreePoolWithTag(PBuf, 'pCxN');
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)PSt;
			return PSt;
		}

		SIZE_T PCopied = 0;
		CONST NTSTATUS POut =
			MmCopyVirtualMemory(PsGetCurrentProcess(), PBuf,
			                    PsGetCurrentProcess(), (PVOID)(ULONG_PTR)CFirst,
			                    PGot * sizeof(NXCMD_CPU_TRACE_CAPS), KernelMode, &PCopied);
		ExFreePoolWithTag(PBuf, 'pCxN');

		if (!NT_SUCCESS(POut))
		{
			Command->Result = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)POut;
			return POut;
		}

		Command->BytesRead  = PGot;
		Command->ModuleSize = PTotal;
		Command->Result     = NXCMD_RESULT_OK;
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_FREEZE:
	{
		Command->BytesRead = 0;
		CONST NTSTATUS FSt = NxcFreezeProcess(Command->TargetModuleId);
		Command->NtStatus = (NXCMD_U64)(ULONG_PTR)FSt;
		if (!NT_SUCCESS(FSt))
		{
			Command->Result = NXCMD_RESULT_REFUSED;
			return FSt;
		}
		Command->BytesRead = 1;
		Command->Result = NXCMD_RESULT_OK;
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_THAW:
	{
		NXCMD_U32 Thawed = 0;
		CONST NTSTATUS TSt = NxcThawProcess(Command->TargetModuleId, &Thawed);
		Command->BytesRead = Thawed;
		Command->NtStatus  = (NXCMD_U64)(ULONG_PTR)TSt;
		if (!NT_SUCCESS(TSt))
		{
			Command->Result = NXCMD_RESULT_REFUSED;
			return TSt;
		}
		Command->Result = NXCMD_RESULT_OK;
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_FREEZE_LIST:
	{
		Command->BytesRead = 0;

		CONST NXCMD_U64 ZFirst = Command->OutBuffer;
		CONST NXCMD_U64 ZLast  = ZFirst + (NXCMD_U64)Command->ReadLength;
		if (Command->ReadLength < sizeof(NXCMD_U32) || Command->ReadLength > NXCMD_READ_MAX ||
		    ZFirst < NXC_USER_VA_FLOOR || ZLast > NXC_USER_VA_CEILING || ZLast <= ZFirst)
		{
			Command->Result = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_ADDRESS;
			return STATUS_INVALID_ADDRESS;
		}

		UINT32 Pids[NXC_MAX_FROZEN];
		UINT32 ZCount = 0;
		CONST NTSTATUS ZSt = NxcFreezeList(Pids, NXC_MAX_FROZEN, &ZCount);
		if (!NT_SUCCESS(ZSt))
		{
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)ZSt;
			return ZSt;
		}

		CONST NXCMD_U32 ZCap = Command->ReadLength / (NXCMD_U32)sizeof(NXCMD_U32);
		CONST NXCMD_U32 ZGive = (ZCount < ZCap) ? ZCount : ZCap;

		SIZE_T ZCopied = 0;
		CONST NTSTATUS ZOut =
			MmCopyVirtualMemory(PsGetCurrentProcess(), Pids,
			                    PsGetCurrentProcess(), (PVOID)(ULONG_PTR)ZFirst,
			                    ZGive * sizeof(UINT32), KernelMode, &ZCopied);
		if (!NT_SUCCESS(ZOut))
		{
			Command->Result = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)ZOut;
			return ZOut;
		}

		Command->BytesRead  = ZGive;
		Command->ModuleSize = ZCount;
		Command->Result     = NXCMD_RESULT_OK;
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_READ_ATOMIC:
	{
		/*
		 * Freeze, read, thaw -- all three inside this one command. See NexusCommand.h for why they
		 * are not three separate round trips.
		 */
		Command->BytesRead  = 0;
		Command->ModuleBase = 0;
		Command->ModuleSize = 0;

		if (Command->ReadLength == 0 || Command->ReadLength > NXCMD_READ_MAX)
		{
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_PARAMETER;
			return STATUS_INVALID_PARAMETER;
		}

		CONST NXCMD_U64 AFirst = Command->OutBuffer;
		CONST NXCMD_U64 ALast  = AFirst + (NXCMD_U64)Command->ReadLength;
		if (AFirst < NXC_USER_VA_FLOOR || ALast > NXC_USER_VA_CEILING || ALast <= AFirst)
		{
			Command->Result = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_ADDRESS;
			return STATUS_INVALID_ADDRESS;
		}

		CONST NTSTATUS AFreeze = NxcFreezeProcess(Command->TargetModuleId);
		if (!NT_SUCCESS(AFreeze))
		{
			/* NOT downgraded to an unfrozen read. A caller who asked for atomic and silently got a
			 * torn one would trust a snapshot that was never consistent -- the same reason
			 * --pristine refuses to fall back to live. */
			CmdLog("cmd: read-atomic pid %u -- freeze REFUSED 0x%08X, NOT reading\n",
			       Command->TargetModuleId, AFreeze);
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)AFreeze;
			return AFreeze;
		}

		PVOID ATarget = NULL;
		NTSTATUS ARead = STATUS_NOT_FOUND;
		SIZE_T ACopied = 0;

		if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Command->TargetModuleId,
		                                          &ATarget)) && ATarget != NULL)
		{
			ARead = MmCopyVirtualMemory(ATarget, (PVOID)(ULONG_PTR)Command->ReadOffset,
			                            PsGetCurrentProcess(), (PVOID)(ULONG_PTR)AFirst,
			                            (SIZE_T)Command->ReadLength, KernelMode, &ACopied);
			ObfDereferenceObject(ATarget);
		}

		/*
		 * ⚠ THE THAW IS UNCONDITIONAL. Every failure path above lands here, because a read that went
		 * wrong must not leave the target suspended -- that is the exact state the registry exists to
		 * prevent, and it would be self-inflicted.
		 */
		NXCMD_U32 AThawed = 0;
		CONST NTSTATUS AThaw = NxcThawProcess(Command->TargetModuleId, &AThawed);

		Command->BytesRead  = (NXCMD_U32)ACopied;
		Command->ModuleSize = AThawed;
		Command->NtStatus   = (NXCMD_U64)(ULONG_PTR)ARead;

		if (!NT_SUCCESS(AThaw) || AThawed == 0)
		{
			/*
			 * Reported LOUDLY and as a failure even if the read succeeded. A target left suspended is
			 * a worse outcome than a missing dump, and a report that led with "OK" would bury it.
			 */
			CmdLog("cmd: read-atomic pid %u -- THAW FAILED 0x%08X, TARGET MAY STILL BE SUSPENDED. "
			       "Run `thaw --all`.\n", Command->TargetModuleId, AThaw);
			Command->Result   = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)AThaw;
			return AThaw;
		}

		if (ACopied == 0)
		{
			Command->Result = NXCMD_RESULT_REFUSED;
			return ARead;
		}

		Command->Result = NXCMD_RESULT_OK;
		CmdLog("cmd: read-atomic pid %u @0x%llX -> %llu of %u bytes (frozen for the read)\n",
		       Command->TargetModuleId, Command->ReadOffset,
		       (ULONG64)ACopied, Command->ReadLength);
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_CAPTURE_LIST:
	{
		/* What is armed and what actually fired -- the one thing the watch could not report, which
		 * made every capture a matter of trusting it had happened. */
		Command->BytesRead  = 0;
		Command->ModuleBase = 0;
		Command->ModuleSize = 0;

		CONST NXCMD_U64 LFirst = Command->OutBuffer;
		CONST NXCMD_U64 LLast  = LFirst + (NXCMD_U64)Command->ReadLength;
		if (Command->ReadLength < sizeof(NXCMD_CAPTURE_ENTRY) ||
		    Command->ReadLength > NXCMD_READ_MAX ||
		    LFirst < NXC_USER_VA_FLOOR || LLast > NXC_USER_VA_CEILING || LLast <= LFirst)
		{
			Command->Result = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_ADDRESS;
			return STATUS_INVALID_ADDRESS;
		}

		CONST NXCMD_U32 LCap = Command->ReadLength / (NXCMD_U32)sizeof(NXCMD_CAPTURE_ENTRY);
		NXCMD_CAPTURE_ENTRY* CONST LBuf =
			(NXCMD_CAPTURE_ENTRY*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
			                                      LCap * sizeof(NXCMD_CAPTURE_ENTRY), 'lCxN');
		if (LBuf == NULL)
		{
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INSUFFICIENT_RESOURCES;
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		ULONG LGot = 0;
		CONST NTSTATUS LSt = NxcCaptureList(LBuf, LCap, &LGot);
		if (!NT_SUCCESS(LSt))
		{
			ExFreePoolWithTag(LBuf, 'lCxN');
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)LSt;
			return LSt;
		}

		SIZE_T LCopied = 0;
		CONST NTSTATUS LOut =
			MmCopyVirtualMemory(PsGetCurrentProcess(), LBuf,
			                    PsGetCurrentProcess(), (PVOID)(ULONG_PTR)LFirst,
			                    LGot * sizeof(NXCMD_CAPTURE_ENTRY), KernelMode, &LCopied);
		ExFreePoolWithTag(LBuf, 'lCxN');

		if (!NT_SUCCESS(LOut))
		{
			Command->Result = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)LOut;
			return LOut;
		}

		Command->BytesRead = LGot;
		Command->NtStatus  = (NXCMD_U64)(ULONG_PTR)LOut;
		Command->Result    = NXCMD_RESULT_OK;
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_CAPTURE_CLEAR:
	{
		/*
		 * An EMPTY TargetName means ALL, and that is the one place this opcode could quietly do the
		 * wrong thing: a caller that forgot to fill the name would wipe every capture. It is
		 * accepted deliberately because "clear everything" needs a spelling, and PlatformCtl makes
		 * the caller type `capture clear --all` rather than letting an omission mean it.
		 */
		Command->BytesRead  = 0;
		Command->ModuleBase = 0;
		Command->ModuleSize = 0;

		CHAR CName[sizeof(Command->TargetName)];
		BOOLEAN CTerm = FALSE;
		for (ULONG i = 0; i < sizeof(CName); i++)
		{
			CName[i] = (CHAR)Command->TargetName[i];
			if (CName[i] == '\0') { CTerm = TRUE; break; }
		}
		if (!CTerm)
		{
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_PARAMETER;
			return STATUS_INVALID_PARAMETER;
		}

		ULONG CCleared = 0, CBusy = 0;
		CONST NTSTATUS CSt =
			NxcCaptureClear((CName[0] == '\0') ? NULL : CName, &CCleared, &CBusy);

		Command->BytesRead  = CCleared;
		Command->ModuleSize = CBusy;
		Command->NtStatus   = (NXCMD_U64)(ULONG_PTR)CSt;

		if (!NT_SUCCESS(CSt))
		{
			Command->Result = NXCMD_RESULT_REFUSED;
			return CSt;
		}

		Command->Result = NXCMD_RESULT_OK;
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_TRACE_DRAIN:
	{
		Command->BytesRead   = 0;
		Command->ReadOffset  = 0;
		Command->ImageBuffer = 0;

		/* One IPI per SWEEP, not per CPU -- 24 broadcasts at a 10 ms interval would be ~2400/sec
		 * and would perturb the very timing the trace is recording. */
		if ((Command->Flags & NXCMD_TRACE_DRAIN_REFRESH) != 0)
			(void)NxcTraceDrainRefresh();

		CONST NXCMD_U64 TFirst = Command->OutBuffer;
		CONST NXCMD_U64 TLast  = TFirst + (NXCMD_U64)Command->ReadLength;
		if (Command->ReadLength == 0 || Command->ReadLength > NXCMD_READ_MAX ||
		    TFirst < NXC_USER_VA_FLOOR || TLast > NXC_USER_VA_CEILING || TLast <= TFirst)
		{
			Command->Result   = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_ADDRESS;
			return STATUS_INVALID_ADDRESS;
		}

		void* CONST TBuf = ExAllocatePool2(POOL_FLAG_NON_PAGED, Command->ReadLength, 'dTxN');
		if (TBuf == NULL)
		{
			Command->Result   = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INSUFFICIENT_RESOURCES;
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		NXCMD_U32 TGot = 0;
		UINT64    TLost = 0, TPend = 0;
		CONST NTSTATUS TSt = NxcTraceDrain((NXCMD_U32)Command->TargetModuleId, TBuf,
		                                   Command->ReadLength, &TGot, &TLost, &TPend);
		if (!NT_SUCCESS(TSt))
		{
			ExFreePoolWithTag(TBuf, 'dTxN');
			Command->Result   = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)TSt;
			return TSt;
		}

		SIZE_T TCopied = 0;
		NTSTATUS TOut = STATUS_SUCCESS;
		if (TGot != 0)
			TOut = MmCopyVirtualMemory(PsGetCurrentProcess(), TBuf,
			                           PsGetCurrentProcess(), (PVOID)(ULONG_PTR)TFirst,
			                           (SIZE_T)TGot, KernelMode, &TCopied);
		ExFreePoolWithTag(TBuf, 'dTxN');
		if (!NT_SUCCESS(TOut))
		{
			Command->Result   = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)TOut;
			return TOut;
		}

		/* PRODUCED, not requested (D3): copied, lost, still pending -- all three, every call. */
		Command->BytesRead   = TGot;
		Command->ReadOffset  = TLost;
		Command->ImageBuffer = TPend;
		Command->Result      = NXCMD_RESULT_OK;
		Command->NtStatus    = 0;
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_NMI_CATCH:
	{
		/* ⚠ DIAGNOSTIC. Flags carries on/off. This SUPPRESSES bugcheck 0x80 -- see Trace.h. */
		NxcNmiSetCatch((NXCMD_U32)Command->Flags);

		UINT64 NTotal = 0, NUnclaimed = 0;
		NXCMD_U32 NCatch = 0, NReg = 0;
		NxcNmiObserveStats(&NTotal, &NUnclaimed, &NCatch, &NReg);
		Command->ReadOffset  = NTotal;
		Command->ImageBuffer = NUnclaimed;
		Command->ModuleId    = NCatch;
		Command->ModuleSize  = NReg;
		Command->Result      = NXCMD_RESULT_OK;
		Command->NtStatus    = 0;
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_NMI_STATUS:
	{
		/*
		 * Counts ALWAYS, ring only if a buffer was supplied. A caller that just wants "has an NMI
		 * happened" must not have to allocate -- and "registered" travels with the counts so a zero
		 * means "none arrived" rather than "nobody was listening", which are opposite facts.
		 */
		UINT64 NTotal = 0, NUnclaimed = 0;
		NXCMD_U32 NCatch = 0, NReg = 0;
		NxcNmiObserveStats(&NTotal, &NUnclaimed, &NCatch, &NReg);
		Command->ReadOffset  = NTotal;
		Command->ImageBuffer = NUnclaimed;
		Command->ModuleId    = NCatch;
		Command->ModuleSize  = NReg;
		Command->ModuleBase  = (NXCMD_U64)sizeof(NXCMD_NMI_OBS);
		Command->BytesRead   = 0;

		CONST NXCMD_U64 NFirst = Command->OutBuffer;
		if (NFirst == 0 || Command->ReadLength < sizeof(NXCMD_NMI_OBS))
		{
			Command->Result   = NXCMD_RESULT_OK;   /* counts only -- not an error */
			Command->NtStatus = 0;
			return STATUS_SUCCESS;
		}

		CONST NXCMD_U64 NLast = NFirst + (NXCMD_U64)Command->ReadLength;
		if (Command->ReadLength > NXCMD_READ_MAX ||
		    NFirst < NXC_USER_VA_FLOOR || NLast > NXC_USER_VA_CEILING || NLast <= NFirst)
		{
			Command->Result   = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_ADDRESS;
			return STATUS_INVALID_ADDRESS;
		}

		CONST NXCMD_U32 NCap = Command->ReadLength / (NXCMD_U32)sizeof(NXCMD_NMI_OBS);
		NXCMD_NMI_OBS* CONST NBuf =
			(NXCMD_NMI_OBS*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
			                                (SIZE_T)NCap * sizeof(NXCMD_NMI_OBS), 'mNxN');
		if (NBuf == NULL)
		{
			Command->Result   = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INSUFFICIENT_RESOURCES;
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		UINT64 NRingTotal = 0;
		CONST NXCMD_U32 NGot = NxcNmiObserveDrain(NBuf, NCap, &NRingTotal);

		SIZE_T NCopied = 0;
		CONST NTSTATUS NOut =
			MmCopyVirtualMemory(PsGetCurrentProcess(), NBuf,
			                    PsGetCurrentProcess(), (PVOID)(ULONG_PTR)NFirst,
			                    (SIZE_T)NGot * sizeof(NXCMD_NMI_OBS), KernelMode, &NCopied);
		ExFreePoolWithTag(NBuf, 'mNxN');
		if (!NT_SUCCESS(NOut))
		{
			Command->Result   = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)NOut;
			return NOut;
		}

		Command->BytesRead = NGot;
		Command->Result    = NXCMD_RESULT_OK;
		Command->NtStatus  = 0;
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_PROCS:
	{
		/*
		 * Sweep the PID space. The kernel half of the hidden-process detector -- see Processes.h for
		 * why this is a kernel command rather than a usermode snapshot.
		 */
		Command->BytesRead  = 0;
		Command->ModuleBase = 0;
		Command->ModuleSize = 0;

		CONST NXCMD_U64 QFirst = Command->OutBuffer;
		CONST NXCMD_U64 QLast  = QFirst + (NXCMD_U64)Command->ReadLength;
		if (Command->ReadLength < sizeof(NXCMD_PROCESS_ENTRY) ||
		    Command->ReadLength > NXCMD_READ_MAX ||
		    QFirst < NXC_USER_VA_FLOOR || QLast > NXC_USER_VA_CEILING || QLast <= QFirst)
		{
			Command->Result = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_ADDRESS;
			return STATUS_INVALID_ADDRESS;
		}

		CONST NXCMD_U32 QCap = Command->ReadLength / (NXCMD_U32)sizeof(NXCMD_PROCESS_ENTRY);
		CONST NXCMD_U32 QBytes = QCap * (NXCMD_U32)sizeof(NXCMD_PROCESS_ENTRY);

		NXCMD_PROCESS_ENTRY* CONST QBuf =
			(NXCMD_PROCESS_ENTRY*)ExAllocatePool2(POOL_FLAG_NON_PAGED, QBytes, 'cPxN');
		if (QBuf == NULL)
		{
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INSUFFICIENT_RESOURCES;
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		NXCMD_U32 QGot = 0, QTotal = 0, QSwept = 0, QUs = 0;
		CONST NTSTATUS QSt = NxcEnumProcesses(QBuf, QCap, &QGot, &QTotal, &QSwept, &QUs);
		if (!NT_SUCCESS(QSt))
		{
			ExFreePoolWithTag(QBuf, 'cPxN');
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)QSt;
			return QSt;
		}

		SIZE_T QCopied = 0;
		CONST NTSTATUS QOut =
			MmCopyVirtualMemory(PsGetCurrentProcess(), QBuf,
			                    PsGetCurrentProcess(), (PVOID)(ULONG_PTR)QFirst,
			                    QGot * sizeof(NXCMD_PROCESS_ENTRY), KernelMode, &QCopied);
		ExFreePoolWithTag(QBuf, 'cPxN');

		if (!NT_SUCCESS(QOut))
		{
			Command->Result = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)QOut;
			return QOut;
		}

		/*
		 * ModuleBase carries the swept ceiling, which is NOT decoration: a PID above it is missed,
		 * and a miss that reads as an absence would invert this command's purpose -- reporting a
		 * process as hidden when it was merely out of range. The caller prints it for that reason.
		 */
		Command->BytesRead  = QGot;      /* entries returned */
		Command->ModuleSize = QTotal;    /* processes found  */
		Command->ModuleBase = QSwept;
		Command->NtStatus   = (NXCMD_U64)(ULONG_PTR)QUs;   /* microseconds, measured */
		Command->Result     = NXCMD_RESULT_OK;
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_VA2PA:
	{
		/*
		 * Translate a VA in a target process by walking its page tables. TargetModuleId = pid,
		 * ReadOffset = the VA. The full NXC_XLAT (per-level entries and effective permissions) goes
		 * to OutBuffer; the answer itself is echoed in ModuleBase so a caller who only wants the PA
		 * does not have to marshal a struct.
		 *
		 * Pairs with readphys: this says WHERE, that reads it. Together they read memory a target has
		 * unmapped or is lying about through its own page tables.
		 */
		Command->BytesRead  = 0;
		Command->ModuleBase = 0;
		Command->ModuleSize = 0;

		CONST NXCMD_U64 XFirst = Command->OutBuffer;
		CONST NXCMD_U64 XLast  = XFirst + sizeof(NXC_XLAT);
		if (XFirst < NXC_USER_VA_FLOOR || XLast > NXC_USER_VA_CEILING || XLast <= XFirst ||
		    Command->ReadLength < sizeof(NXC_XLAT))
		{
			Command->Result = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_ADDRESS;
			return STATUS_INVALID_ADDRESS;
		}

		PVOID XProc = NULL;
		if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Command->TargetModuleId,
		                                           &XProc)) || XProc == NULL)
		{
			CmdLog("cmd: va2pa pid %u -- no such process\n", Command->TargetModuleId);
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_NOT_FOUND;
			return STATUS_NOT_FOUND;
		}

		NXC_XLAT Xlat;
		CONST NTSTATUS XSt = NxcTranslate(XProc, Command->ReadOffset, &Xlat);
		ObfDereferenceObject(XProc);

		/*
		 * A NOT-PRESENT VA IS A RESULT, NOT AN ERROR, and the struct is handed back either way. That
		 * a VA is unmapped -- and at WHICH LEVEL the walk stopped -- is frequently the actual finding:
		 * a region the loader reported as committed whose PDE is absent has been unmapped underneath
		 * the reported state, which is exactly what this command is for.
		 */
		SIZE_T XCopied = 0;
		CONST NTSTATUS XOut = MmCopyVirtualMemory(PsGetCurrentProcess(), &Xlat,
		                                          PsGetCurrentProcess(),
		                                          (PVOID)(ULONG_PTR)XFirst,
		                                          sizeof(Xlat), KernelMode, &XCopied);
		if (!NT_SUCCESS(XOut))
		{
			Command->Result = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)XOut;
			return XOut;
		}

		Command->BytesRead  = (NXCMD_U32)XCopied;
		Command->ModuleBase = Xlat.PhysicalAddress;
		Command->ModuleSize = Xlat.Level;
		Command->NtStatus   = (NXCMD_U64)(ULONG_PTR)XSt;

		if (!NT_SUCCESS(XSt))
		{
			CmdLog("cmd: va2pa pid %u VA 0x%llX -- not mapped (stopped at level %u)\n",
			       Command->TargetModuleId, Command->ReadOffset, Xlat.FailedLevel);
			Command->Result = NXCMD_RESULT_REFUSED;
			return XSt;
		}

		Command->Result = NXCMD_RESULT_OK;
		CmdLog("cmd: va2pa pid %u VA 0x%llX -> PA 0x%llX (level %u, flags 0x%X)\n",
		       Command->TargetModuleId, Command->ReadOffset,
		       Xlat.PhysicalAddress, Xlat.Level, Xlat.Flags);
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_READ_PHYS:
	{
		/*
		 * Read PHYSICAL memory, for when a virtual mapping is absent or lying.
		 *
		 * ⚠ THE RAM-CONTAINMENT CHECK BELOW IS THE POINT OF THIS HANDLER. Everything else here is
		 * the same staging dance as NXCMD_OP_READ. MM_COPY_MEMORY_PHYSICAL reads whatever address it
		 * is given, and a physical address that is a DEVICE REGISTER rather than RAM turns a read
		 * into a side effect -- clearing a status bit, popping a FIFO, or hanging on an unpopulated
		 * bus address. Two host freezes came from exactly that under v1's MmMapIoSpace path.
		 */
		Command->BytesRead  = 0;
		Command->ModuleBase = 0;
		Command->ModuleSize = 0;

		if (Command->ReadLength == 0 || Command->ReadLength > NXCMD_READ_MAX)
		{
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_PARAMETER;
			return STATUS_INVALID_PARAMETER;
		}

		CONST NXCMD_U64 YFirst = Command->OutBuffer;
		CONST NXCMD_U64 YLast  = YFirst + (NXCMD_U64)Command->ReadLength;
		if (YFirst < NXC_USER_VA_FLOOR || YLast > NXC_USER_VA_CEILING || YLast <= YFirst)
		{
			Command->Result = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_ADDRESS;
			return STATUS_INVALID_ADDRESS;
		}

		CONST NXCMD_U64 PaFirst = Command->ReadOffset;
		CONST NXCMD_U64 PaLast  = PaFirst + (NXCMD_U64)Command->ReadLength;
		if (PaLast <= PaFirst)   /* wrap */
		{
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_PARAMETER;
			return STATUS_INVALID_PARAMETER;
		}

		/*
		 * The RAM gate. Checked BEFORE the staging buffer is allocated so a refused address costs
		 * nothing, and reported here rather than left to NxcPhysRead so the enclosing range can be
		 * handed back -- a caller who guessed near a boundary needs the bounds, not just a "no".
		 */
		NXCMD_U64 RangeBase = 0, RangeSize = 0;
		/*
		 * (!) BOTH gates, and this one is the reason the whitelist needs saying twice.
		 *
		 * The software-TPM regions are EfiACPIMemoryNVS and therefore absent from Windows'
		 * system RAM map, so NxcPhysIsRam refuses them. NxcPhysRead knows about the exception --
		 * but this gate runs FIRST, before the staging allocation, and returns before the read
		 * is ever reached. Extending only NxcPhysRead shipped once and did nothing observable:
		 * the refusal still came from here.
		 */
		if (!NxcPhysIsRam(PaFirst, Command->ReadLength, &RangeBase, &RangeSize) &&
		    !NxcPhysIsPublishedTpmRegion(PaFirst, Command->ReadLength, &RangeBase, &RangeSize))
		{
			CmdLog("cmd: read-phys 0x%llX +%u -- NOT SYSTEM RAM, REFUSED "
			       "(use `phys ranges` to see what is)\n", PaFirst, Command->ReadLength);
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_ADDRESS;
			return STATUS_INVALID_ADDRESS;
		}

		Command->ModuleBase = RangeBase;
		Command->ModuleSize = (NXCMD_U32)((RangeSize > 0xFFFFFFFFULL) ? 0xFFFFFFFFULL : RangeSize);

		PVOID CONST YStaging = ExAllocatePool2(POOL_FLAG_NON_PAGED, Command->ReadLength, 'yPxN');
		if (YStaging == NULL)
		{
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INSUFFICIENT_RESOURCES;
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		/*
		 * STAGED, exactly like NXCMD_OP_READ and for the same reason: the physical read writes to its
		 * destination directly with no probe and no SEH here to catch a fault, so it must never be
		 * pointed at the caller's usermode buffer. MmCopyVirtualMemory makes the second hop and
		 * returns a status instead of raising.
		 *
		 * (NxcPhysIsRam runs a second time inside NxcPhysRead. Deliberate: the gate belongs to the
		 * read, not to whoever remembered to call it, and one extra RAM-map query on a diagnostic
		 * path is a trade worth making for a check that cannot be skipped by a future edit.)
		 */
		SIZE_T PTransferred = 0;
		CONST NTSTATUS PhysStatus =
			NxcPhysRead(PaFirst, YStaging, Command->ReadLength, &PTransferred);

		if (PTransferred == 0)
		{
			CmdLog("cmd: read-phys 0x%llX -- unreadable 0x%08X\n", PaFirst, PhysStatus);
			ExFreePoolWithTag(YStaging, 'yPxN');
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)PhysStatus;
			return PhysStatus;
		}

		SIZE_T YCopied = 0;
		CONST NTSTATUS YOut = MmCopyVirtualMemory(PsGetCurrentProcess(), YStaging,
		                                          PsGetCurrentProcess(),
		                                          (PVOID)(ULONG_PTR)YFirst,
		                                          PTransferred, KernelMode, &YCopied);
		ExFreePoolWithTag(YStaging, 'yPxN');

		if (!NT_SUCCESS(YOut))
		{
			Command->Result = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)YOut;
			return YOut;
		}

		Command->BytesRead = (NXCMD_U32)YCopied;
		Command->NtStatus  = (NXCMD_U64)(ULONG_PTR)PhysStatus;  /* may be a PARTIAL-read status */
		Command->Result    = NXCMD_RESULT_OK;
		CmdLog("cmd: read-phys 0x%llX -> %llu of %u bytes (range 0x%llX +0x%llX)\n",
		       PaFirst, (ULONG64)YCopied, Command->ReadLength, RangeBase, RangeSize);
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_MODULES:
	{
		/*
		 * The loader's view of a process. Paired with NXCMD_OP_REGIONS -- the SUBTRACTION is the
		 * manual-map finding, and it is computed in usermode (D5).
		 */
		Command->BytesRead  = 0;
		Command->ModuleBase = 0;
		Command->ModuleSize = 0;

		CONST ULONG MaxMods = Command->ReadLength / (ULONG)sizeof(NXC_MODULE_ENTRY);
		if (MaxMods == 0 || Command->ReadLength > NXCMD_READ_MAX)
		{
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_BUFFER_TOO_SMALL;
			return STATUS_BUFFER_TOO_SMALL;
		}

		CONST NXCMD_U64 MFirst = Command->OutBuffer;
		CONST NXCMD_U64 MLast  = MFirst + (NXCMD_U64)Command->ReadLength;
		if (MFirst < NXC_USER_VA_FLOOR || MLast > NXC_USER_VA_CEILING || MLast <= MFirst)
		{
			Command->Result = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_ADDRESS;
			return STATUS_INVALID_ADDRESS;
		}

		NXC_MODULE_ENTRY* CONST MStage =
			(NXC_MODULE_ENTRY*)ExAllocatePool2(POOL_FLAG_NON_PAGED, Command->ReadLength, 'mRxN');
		if (MStage == NULL)
		{
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INSUFFICIENT_RESOURCES;
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		ULONG MGot = 0, MTotal = 0;
		CONST NTSTATUS Mst =
			NxcEnumModules(Command->TargetModuleId, MStage, MaxMods, &MGot, &MTotal);

		if (!NT_SUCCESS(Mst))
		{
			ExFreePoolWithTag(MStage, 'mRxN');
			CmdLog("cmd: modules pid %u failed 0x%08X\n", Command->TargetModuleId, Mst);
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)Mst;
			return Mst;
		}

		SIZE_T MCopied = 0;
		CONST NTSTATUS MOut =
			MmCopyVirtualMemory(PsGetCurrentProcess(), MStage, PsGetCurrentProcess(),
			                    (PVOID)(ULONG_PTR)MFirst,
			                    (SIZE_T)MGot * sizeof(NXC_MODULE_ENTRY), KernelMode, &MCopied);
		ExFreePoolWithTag(MStage, 'mRxN');

		if (!NT_SUCCESS(MOut))
		{
			Command->Result = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)MOut;
			return MOut;
		}

		Command->BytesRead  = MGot;     /* returned */
		Command->ModuleSize = MTotal;   /* existing */
		Command->Result     = NXCMD_RESULT_OK;
		CmdLog("cmd: modules pid %u -> %u of %u\n", Command->TargetModuleId, MGot, MTotal);
		return STATUS_SUCCESS;
	}

	case NXCMD_OP_READ:
	{
		/*
		 * ============================================================================================
		 * Read a live kernel module into the caller's buffer. Phase 1 of the capture read path.
		 * ============================================================================================
		 *
		 * Handled here rather than sharing the MAP path: the direction is reversed (we WRITE to the
		 * caller's buffer), the staging lifetime is different, and none of MAP's PE validation
		 * applies. Sharing would mean guarding every step with "unless this is a read".
		 */
		Command->BytesRead  = 0;
		Command->ModuleBase = 0;
		Command->ModuleSize = 0;

		if (Command->ReadLength == 0 || Command->ReadLength > NXCMD_READ_MAX)
		{
			CmdLog("cmd: read length %u out of range (cap %u) -- REFUSED\n",
			       Command->ReadLength, NXCMD_READ_MAX);
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_PARAMETER;
			return STATUS_INVALID_PARAMETER;
		}

		/* Same usermode bounds rule as the MAP path, applied to the DESTINATION this time. */
		CONST NXCMD_U64 OutFirst = Command->OutBuffer;
		CONST NXCMD_U64 OutLast  = OutFirst + (NXCMD_U64)Command->ReadLength;
		if (OutFirst < NXC_USER_VA_FLOOR || OutLast > NXC_USER_VA_CEILING || OutLast <= OutFirst)
		{
			CmdLog("cmd: OutBuffer %p +%u is not a usermode range -- REFUSED\n",
			       (PVOID)(ULONG_PTR)OutFirst, Command->ReadLength);
			Command->Result = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_ADDRESS;
			return STATUS_INVALID_ADDRESS;
		}

		/*
		 * The name arrives inline and is HOSTILE. Require a NUL inside the field rather than
		 * forcing one in: a caller that filled all 64 bytes has sent something we cannot interpret,
		 * and silently truncating would resolve a DIFFERENT module than they asked for.
		 */
		CHAR Name[sizeof(Command->TargetName)];
		BOOLEAN Terminated = FALSE;
		for (ULONG i = 0; i < sizeof(Name); i++)
		{
			Name[i] = (CHAR)Command->TargetName[i];
			if (Name[i] == '\0') { Terminated = TRUE; break; }
		}
		if (!Terminated || Name[0] == '\0')
		{
			CmdLog("cmd: read target name is empty or unterminated -- REFUSED\n");
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_PARAMETER;
			return STATUS_INVALID_PARAMETER;
		}

		UINT64 ModBase = 0;
		ULONG  ModSize = 0;
		NTSTATUS FindStatus;

		if (Command->Flags & NXCMD_READ_FLAG_PRISTINE)
		{
			/*
			 * The captured copy, taken before the image ran. NOT a fallback to live on failure --
			 * a caller who asked for pristine and silently received self-modified bytes would draw
			 * precisely the wrong conclusion from them.
			 */
			FindStatus = NxcCaptureFind(Name, &ModBase, &ModSize);
			if (!NT_SUCCESS(FindStatus))
				CmdLog("cmd: read '%s' PRISTINE -- not captured (watched before it loaded?)\n", Name);
		}
		else
		{
			FindStatus = NxcFindKernelModule(Name, &ModBase, &ModSize);
		}

		if (!NT_SUCCESS(FindStatus))
		{
			CmdLog("cmd: read '%s' -- lookup failed 0x%08X\n", Name, FindStatus);
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)FindStatus;
			Command->DiagRefusalLine = (NXCMD_U32)NxcMapLastRefusalLine();
			return FindStatus;
		}

		Command->ModuleBase = ModBase;
		Command->ModuleSize = ModSize;

		/* Clamp to the image. Reported rather than refused: asking for "the rest of the module"
		 * by passing a generous length is a reasonable thing for a caller to do. */
		NXCMD_U32 Want = Command->ReadLength;
		if (Command->ReadOffset >= ModSize)
		{
			CmdLog("cmd: read offset 0x%llX beyond '%s' size 0x%X -- REFUSED\n",
			       Command->ReadOffset, Name, ModSize);
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_PARAMETER;
			return STATUS_INVALID_PARAMETER;
		}
		if (Command->ReadOffset + Want > ModSize)
			Want = (NXCMD_U32)(ModSize - Command->ReadOffset);

		PVOID CONST Staging = ExAllocatePool2(POOL_FLAG_NON_PAGED, Want, 'dRxN');
		if (Staging == NULL)
		{
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INSUFFICIENT_RESOURCES;
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		/*
		 * SOURCE read. MmCopyMemory, not a raw copy: the target is another module's memory and a
		 * page inside it may be unmapped or paged out. This returns a status AND the count actually
		 * transferred, which is the whole reason it is used here -- we have no SEH to catch a fault
		 * and no wish to discard a partial result.
		 */
		SIZE_T Transferred = 0;
		NTSTATUS SrcStatus;

		if (Command->Flags & NXCMD_READ_FLAG_PRISTINE)
		{
			/*
			 * ⚠ THE PRISTINE SOURCE IS OUR OWN ARENA, AND MmCopyMemory CANNOT READ IT. This branch
			 * used to share the MmCopyMemory call below and failed EVERY TIME with
			 * STATUS_INVALID_ADDRESS -- `capture list` said CAPTURED and every read of those bytes
			 * was refused. The arena is EFI runtime memory whose frames are not in Windows' PFN
			 * database, so the validation that makes MmCopyMemory safe for FOREIGN memory has
			 * nothing to consult and it rejects the address.
			 *
			 * NxcCaptureRead does the bounded copy inside the module that OWNS the buffer, which is
			 * how NxcFileCapturePull has always read the byte arena -- and why `fcap pull` worked
			 * while this did not. Same memory, two consumers, one using a primitive that cannot
			 * read it.
			 */
			/*
			 * ⚠ CHUNKED, BECAUSE THE READ RUNS UNDER A DISPATCH-LEVEL SPINLOCK.
			 *
			 * `NxcCaptureRead` holds `gWatchLock` across its copy -- deliberately, so a concurrent
			 * `capture clear` cannot free the buffer mid-read. That is the right invariant and the
			 * wrong duration: a pristine capture is up to 8 MB, which is roughly 800 us of DISPATCH
			 * hold, and `NxcImageLoadNotify` takes the same lock on EVERY image load system-wide.
			 * Every driver load and process start would spin for that window.
			 *
			 * So the copy is bounded per call and this loop resumes. Each iteration re-resolves the
			 * watch entry under the lock, so a `clear` between chunks makes the next call return
			 * NOT_FOUND and we stop with a SHORT read rather than reading freed memory -- which is
			 * exactly what releasing the lock across one big copy would have done instead.
			 *
			 * D3: `Transferred` reports what was ACTUALLY produced, so a short read is visible to
			 * the caller rather than silently padded.
			 */
			ULONG CapDone = 0;
			SrcStatus = STATUS_SUCCESS;
			while (CapDone < Want)
			{
				ULONG CapGot = 0;
				CONST ULONG Chunk = ((Want - CapDone) > NXC_CAPTURE_READ_CHUNK)
				                  ? NXC_CAPTURE_READ_CHUNK : (Want - CapDone);

				SrcStatus = NxcCaptureRead(Name, Command->ReadOffset + CapDone, Chunk,
				                           (UCHAR*)Staging + CapDone, &CapGot);
				if (!NT_SUCCESS(SrcStatus) || CapGot == 0)
					break;

				CapDone += CapGot;
				if (CapGot < Chunk)
					break;      /* end of the captured image */
			}
			if (CapDone != 0)
				SrcStatus = STATUS_SUCCESS;   /* a partial read is data, not failure */
			Transferred = CapDone;
		}
		else
		{
			MM_COPY_ADDRESS Src;
			Src.VirtualAddress = (PVOID)(ULONG_PTR)(ModBase + Command->ReadOffset);
			SrcStatus = MmCopyMemory(Staging, Src, Want, MM_COPY_MEMORY_VIRTUAL, &Transferred);
		}

		if (Transferred == 0)
		{
			CmdLog("cmd: read '%s'+0x%llX -- source unreadable 0x%08X\n",
			       Name, Command->ReadOffset, SrcStatus);
			ExFreePoolWithTag(Staging, 'dRxN');
			Command->Result = NXCMD_RESULT_REFUSED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)SrcStatus;
			return SrcStatus;
		}

		/* Hand it out. KernelMode because BOTH ranges are ours to vouch for -- the destination was
		 * range-checked above, in our own code, rather than left to PreviousMode. */
		SIZE_T Copied = 0;
		CONST NTSTATUS OutStatus = MmCopyVirtualMemory(PsGetCurrentProcess(), Staging,
		                                               PsGetCurrentProcess(),
		                                               (PVOID)(ULONG_PTR)OutFirst,
		                                               Transferred, KernelMode, &Copied);
		ExFreePoolWithTag(Staging, 'dRxN');

		if (!NT_SUCCESS(OutStatus))
		{
			CmdLog("cmd: read '%s' -- copy to caller failed 0x%08X\n", Name, OutStatus);
			Command->Result = NXCMD_RESULT_COPY_FAILED;
			Command->NtStatus = (NXCMD_U64)(ULONG_PTR)OutStatus;
			return OutStatus;
		}

		Command->BytesRead = (NXCMD_U32)Copied;
		Command->NtStatus  = (NXCMD_U64)(ULONG_PTR)SrcStatus;   /* may be a PARTIAL-read status */
		Command->Result    = NXCMD_RESULT_OK;

		CmdLog("cmd: read '%s' base %p +0x%llX -> %llu of %u bytes\n",
		       Name, (PVOID)(ULONG_PTR)ModBase, Command->ReadOffset,
		       (ULONG64)Copied, Command->ReadLength);
		return STATUS_SUCCESS;
	}

	default:
	{
		/*
		 * Not one of Core's. Before refusing, see whether a mapped MODULE claimed this opcode.
		 *
		 * The lookup itself enforces the NXCMD_OP_MODULE_FIRST split, so a Core opcode can never
		 * resolve here even if the table were corrupted into holding one.
		 *
		 * ⚠ SAFE TO CALL WITHOUT RUNDOWN PROTECTION ONLY BECAUSE OF THE GUARD ABOVE US. Every
		 * command, including unmap, is serialised by NxcCommandHandler's interlocked flag, so the
		 * module owning this handler cannot be tearing down while we are inside it -- and unmap
		 * retires its opcodes immediately after PREPARE, before anything is destroyed. If a module
		 * handler ever becomes reachable from a DPC, a kernel callback or a worker thread, that
		 * argument fails and this call needs real rundown protection. See NexusHost.h.
		 */
		CONST NXH_COMMAND_FN Handler = NxcCommandLookup(Command->Opcode);
		if (Handler != NULL)
		{
			CONST NXCMD_U32 ModResult = Handler(Command);

			/*
			 * The module owns Result. Anything else it wrote is its business -- but a module that
			 * left Result at PENDING has told us nothing, and PENDING rendered as an answer reads
			 * as "NexusCore never replied", which would send the reader to entirely the wrong
			 * component. Normalise that one case rather than pass a lie through.
			 */
			Command->Result = (ModResult == NXCMD_RESULT_PENDING)
			                ? NXCMD_RESULT_REFUSED : ModResult;

			CmdLog("cmd: opcode 0x%X handled by a module -> result %u\n",
			       Command->Opcode, Command->Result);
			return STATUS_SUCCESS;
		}

		CmdLog("cmd: unknown opcode %u -- REFUSED\n", Command->Opcode);
		Command->Result = NXCMD_RESULT_BAD_OP;
		return STATUS_NOT_SUPPORTED;
	}
	}

	/* ---- NXCMD_OP_MAP ---- */

	if (Command->ImageBuffer == 0 ||
		Command->ImageSize == 0 ||
		Command->ImageSize > NXC_CMD_MAX_IMAGE)
	{
		CmdLog("cmd: map with buffer %p size %u -- REFUSED (cap %u)\n",
		       (PVOID)(ULONG_PTR)Command->ImageBuffer, Command->ImageSize, NXC_CMD_MAX_IMAGE);
		Command->Result = NXCMD_RESULT_COPY_FAILED;
		Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_PARAMETER;
		return STATUS_INVALID_PARAMETER;
	}

	if (!NxcArenaReady())
	{
		CmdLog("cmd: map requested but there is no arena -- REFUSED\n");
		Command->Result = NXCMD_RESULT_NO_ARENA;
		return STATUS_DEVICE_NOT_READY;
	}

	/*
	 * ============================================================================================
	 * VALIDATE THE CALLER'S RANGE FIRST. This used to run AFTER the staging allocation.
	 * ============================================================================================
	 *
	 *  The pointer check is pure arithmetic on values we already hold, and
	 * it sat below an ExAllocatePool2 of up to 8 MB -- so a caller passing any garbage pointer made us
	 * allocate megabytes of NON-PAGED pool and immediately free it again. Repeat that in a loop and it
	 * is a cheap way to churn the least replaceable memory in the system, from an API a caller can
	 * invoke as fast as it likes.
	 *
	 * Nothing about the check needed the allocation to exist. It is ordered first now, so a bad
	 * pointer costs a compare instead of a pool round-trip.
	 *
	 * The x64 Windows user/kernel split: usermode VAs live below 0x0000_7FFF_FFFF_0000, and the low
	 * 64 KB is never a valid user mapping, so a small integer arriving as a "pointer" is rejected
	 * rather than probed. Written as constants with the reasoning attached because the alternative --
	 * MmUserProbeAddress -- is a DATA export and our resolution table carries functions only.
	 *
	 * ⚠ This is the property PreviousMode = UserMode was WRONGLY relied on for (see the note at the
	 * copy below). Enforced here, in our own code, where it can be read.
	 */
	CONST NXCMD_U64 First = Command->ImageBuffer;
	CONST NXCMD_U64 Last  = First + (NXCMD_U64)Command->ImageSize;   /* size is capped above */

	if (First < NXC_USER_VA_FLOOR || Last > NXC_USER_VA_CEILING || Last <= First)
	{
		CmdLog("cmd: ImageBuffer %p +%u is not a usermode range -- REFUSED\n",
		       (PVOID)(ULONG_PTR)First, Command->ImageSize);
		Command->Result = NXCMD_RESULT_COPY_FAILED;
		Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INVALID_ADDRESS;
		return STATUS_INVALID_ADDRESS;
	}

	/*
	 * STAGING BUFFER. The raw file is copied out of usermode ONCE, here, and the mapper then works
	 * only from kernel memory.
	 *
	 * ⚠ THIS IS NOT AN OPTIMISATION, IT IS THE SECURITY BOUNDARY. If the mapper read the caller's
	 * buffer directly it would be re-reading memory another thread can change between the header
	 * validation and the section copy -- a TOCTOU where the PE we validated is not the PE we map.
	 * Every bounds check MapModule performs would be checking a value that no longer applies.
	 *
	 * Pool, not arena, and deliberately: this is scratch that dies at the end of this call, whereas
	 * the arena is for things that stay resident and must be reclaimable by owner at unmap. Renting
	 * arena space for a transient would fragment the one region a long-lived module has to come out
	 * of -- and measurably so: SentinelHV needs 1.4 MB of staging plus 1.4 MB mapped, which would
	 * take 2.8 MB of a 16 MB arena for the duration of one map. NonPaged because we hold it across a
	 * mapping operation.
	 *
	 * ⚠ ACCEPTED EXPOSURE, named because the review found it and it deserves to be a decision rather
	 * than an oversight. MapModule.c's header says the arena exists because "ExAllocatePool2 is
	 * precisely the enumerable, pool-tagged allocation the arena exists to avoid" -- and this line is
	 * an ExAllocatePool2 with a distinctive tag. For the duration of a map there IS a tagged non-paged
	 * allocation of up to 8 MB attributable to us, and pool-tag enumeration is a standard sweep.
	 *
	 * Judged acceptable because it is transient (freed before this call returns, on every path) and
	 * because the alternatives are worse: the arena costs capacity as above, and a stack buffer cannot
	 * hold a megabyte. The exposure is a brief allocation, not a resident artefact -- which is the
	 * distinction the arena was built around. Same class of accepted cost as the DbgPrint format
	 * strings that carry nt API names.
	 *
	 * If that ever stops being acceptable, the fix is a dedicated staging region reserved by the DXE
	 * alongside the arena -- NOT carving the arena, and NOT a less honest pool tag.
	 */
	PVOID CONST Staging = ExAllocatePool2(POOL_FLAG_NON_PAGED, Command->ImageSize, 'dCxN');
	if (Staging == NULL)
	{
		CmdLog("cmd: no pool for a %u KB staging copy -- REFUSED\n", Command->ImageSize / 1024);
		Command->Result = NXCMD_RESULT_COPY_FAILED;
		Command->NtStatus = (NXCMD_U64)(ULONG_PTR)STATUS_INSUFFICIENT_RESOURCES;
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	SIZE_T Copied = 0;
	PEPROCESS CONST Self = PsGetCurrentProcess();

	/*
	 * PreviousMode = KernelMode, and the usermode range is validated HERE instead.
	 *
	 * ⚠ CORRECTED AFTER THE FIRST LIVE MAP. This passed UserMode, on the reasoning that
	 * it would make the kernel validate the SOURCE as a usermode range and so refuse a caller that
	 * pointed ImageBuffer at kernel memory. That reasoning was wrong: PreviousMode governs the probe
	 * of BOTH ranges, and the TARGET is our own kernel pool -- so the probe rejected our own staging
	 * buffer and the call returned STATUS_ACCESS_VIOLATION before the source was ever touched.
	 * MEASURED: `map` returned COPY_FAILED / 0xC0000005 on a perfectly valid image.
	 *
	 * The security property that argument was reaching for is real and still wanted, so it is
	 * enforced explicitly below rather than delegated to a flag whose semantics I had wrong. An
	 * explicit check is also better evidence: it states the bound in our own code where it can be
	 * read, instead of depending on the internals of an undocumented export.
	 */
	/*
	 * Source and target are the SAME process: we are in the caller's context, so this is "copy from
	 * this process's usermode into kernel pool". MmCopyVirtualMemory is used for its non-raising
	 * failure -- it returns NTSTATUS where ProbeForRead would raise, and we have no SEH.
	 *
	 * If the runtime-service call turns out NOT to run in the caller's process context, this is
	 * where it shows up, and DiagCallerPid below is what will say so.
	 */
	CONST NTSTATUS CopyStatus = MmCopyVirtualMemory(
		Self, (PVOID)(ULONG_PTR)Command->ImageBuffer,
		Self, Staging,
		(SIZE_T)Command->ImageSize,
		KernelMode,
		&Copied);

	if (!NT_SUCCESS(CopyStatus) || Copied != (SIZE_T)Command->ImageSize)
	{
		CmdLog("cmd: copy of %u bytes from %p FAILED 0x%08X (got %llu) -- REFUSED\n",
		       Command->ImageSize, (PVOID)(ULONG_PTR)Command->ImageBuffer,
		       CopyStatus, (ULONG64)Copied);
		ExFreePoolWithTag(Staging, 'dCxN');
		Command->Result = NXCMD_RESULT_COPY_FAILED;
		Command->NtStatus = (NXCMD_U64)(ULONG_PTR)CopyStatus;
		return CopyStatus;
	}

	/*
	 * NXC_MODULE_NONE, not 0, so that "the mapper assigned a slot" is distinguishable from "slot 0".
	 * NxcMapModule writes OutModuleId on the success path AND on the entry-failed path -- and only
	 * those two -- which is what lets the failure below be classified correctly.
	 */
	ULONG ModuleId = NXC_MODULE_NONE;
	CONST NTSTATUS MapStatus = NxcMapModule(Staging, Command->ImageSize, &ModuleId);

	/*
	 * Free the staging copy unconditionally. NxcMapModule copies what it needs into the arena --
	 * headers, then sections to their RVAs -- so nothing it leaves resident points back in here.
	 * Freeing on the SUCCESS path too is the part worth stating: a transient that outlives its use
	 * because only the failure path frees it is a leak that looks like correct code.
	 */
	ExFreePoolWithTag(Staging, 'dCxN');

	Command->NtStatus = (NXCMD_U64)(ULONG_PTR)MapStatus;

	/*
	 * WHICH check refused, not just that one did. Read immediately after NxcMapModule so nothing can
	 * overwrite it in between -- the mapper keeps only the most recent, which is sufficient because
	 * this handler answers one command at a time.
	 */
	Command->DiagRefusalLine = (NXCMD_U32)NxcMapLastRefusalLine();
	Command->DiagFlags       = NxcMapLastDiagFlags();

	if (!NT_SUCCESS(MapStatus))
	{
		/*
		 * ⚠ TWO FAILURES THAT NEED OPPOSITE RESPONSES, and they were reported identically.
		 *
		 *   REFUSED       the mapper rejected the image. NOTHING is resident, nothing to clean up,
		 *                 and the fix is to the file you passed.
		 *   ENTRY_FAILED  the image mapped fine and its own DriverEntry returned failure. It IS
		 *                 RESIDENT -- deliberately, because it may have registered callbacks before
		 *                 failing, and freeing underneath that is the v1 bug -- so it holds a slot
		 *                 and arena until `unmap` runs the full contract on it.
		 *
		 * measured: a stale NexusTestModule refused the host ABI from its own entry, and
		 * the report said "REFUSED" and withheld the module id. The module was resident, the slot
		 * was consumed, and the caller had no handle to tear it down -- a report that was locally
		 * true and left the reader unable to act.
		 */
		if (ModuleId != NXC_MODULE_NONE)
		{
			Command->ModuleId = (NXCMD_U32)ModuleId;
			Command->Result   = NXCMD_RESULT_ENTRY_FAILED;
			CmdLog("cmd: module %u ENTRY returned 0x%08X -- RESIDENT, needs unmap\n",
			       ModuleId, MapStatus);
			return MapStatus;
		}

		CmdLog("cmd: map REFUSED 0x%08X at MapModule.c:%u\n",
		       MapStatus, Command->DiagRefusalLine);
		Command->Result = NXCMD_RESULT_REFUSED;
		return MapStatus;
	}

	Command->ModuleId = (NXCMD_U32)ModuleId;
	Command->Result = NXCMD_RESULT_OK;
	CmdLog("cmd: mapped module id %u\n", ModuleId);
	return STATUS_SUCCESS;
}

/*
 * The boot block, reached through the slot NexusCore.c exports and the EFI mapper patches. This is
 * already the canonical way to find it, so no new plumbing is invented here.
 */
extern volatile NEXUS_CORE_BOOT_BLOCK* NexusCoreBootSlot;

/*
 * Reentrancy guard for the whole command path. See the note in NxcCommandHandler for why an
 * assumption of serialisation was not good enough. LONG rather than BOOLEAN because that is what
 * the Interlocked intrinsics operate on.
 */
static volatile LONG gCommandInProgress = 0;

/**
 * Public entry. Dispatches, then REFRESHES the block's live counters.
 *
 * ============================================================================================
 * WHY THIS WRAPPER EXISTS -- a field that looks live and was frozen
 * ============================================================================================
 *
 * measured, immediately after the first successful runtime map: PlatformCtl still
 * reported `map arena: 0 KB used` with a module resident in it. The map had genuinely allocated --
 * it could not have succeeded otherwise -- but Block->ArenaUsed was written EXACTLY ONCE, in
 * DriverEntry right after NxcArenaInit, at the one moment the arena is guaranteed empty. Nothing
 * ever updated it again, so the status read reported a boot-time snapshot forever.
 *
 * That is the worst kind of signal: not absent, but present, plausible, and permanently wrong. It
 * would have read "0 KB used" through any number of successful maps, and the first person to trust
 * it would conclude the arena was unused.
 *
 * Refreshing HERE rather than inside NxcMapModule, in a wrapper around the dispatch rather than
 * before each return: every command refreshes it, including ones that fail, and no future return
 * path can forget to. A refresh placed at each exit is a maintenance burden that eventually gets
 * missed -- which is precisely how the original single write became stale.
 *
 * The DXE cannot do this itself: it serves the status read but has no kernel APIs, so it cannot ask
 * the allocator anything. The driver has to publish.
 */
NTSTATUS
NxcCommandHandler(
	_Inout_ void* CommandRaw
	)
{
	if (CommandRaw == NULL)
		return STATUS_INVALID_PARAMETER;

	/*
	 * ============================================================================================
	 * SERIALISE. The whole command path assumes one-at-a-time and never enforced it.
	 * ============================================================================================
	 *
	 *  The dispatch below says "the mapper keeps only the most recent, which
	 * is sufficient because this handler answers one command at a time" -- an assumption, stated as a
	 * fact, with nothing backing it. Two concurrent callers would race on the DXE's single mLastCommand
	 * copy, on gLastRefusalLine and gLastDiagFlags, and -- much worse -- inside NxcMapModule, whose
	 * free-slot search and gModules[] assignment are not locked. Two maps could pick the SAME slot and
	 * the second would overwrite the first's record, leaving a resident module with no way to reach it.
	 *
	 * It is PROBABLY true today: UEFI runtime services are not reentrant and the OS is responsible for
	 * serialising them, so Windows holds a lock across gRT->SetVariable. But that is an undocumented
	 * property of another component, and this file already rejects exactly that reasoning one screen
	 * up -- it re-checks IRQL rather than trust the DXE's CR8 gate, because "the gate lives in another
	 * binary that ships separately, and 'the other side checks' is how a missing check survives." The
	 * same argument applies here and was not applied.
	 *
	 * An interlocked flag costs one atomic and converts the assumption into an enforced invariant. It
	 * FAILS CLOSED: a reentrant call is refused rather than allowed to interleave, because a refused
	 * command is a log line and an interleaved one corrupts the module table.
	 */
	if (_InterlockedCompareExchange(&gCommandInProgress, 1, 0) != 0)
	{
		((NEXUS_COMMAND*)CommandRaw)->Result = NXCMD_RESULT_BUSY;
		CmdLog("cmd: REENTERED while a command was in flight -- REFUSED\n");
		return STATUS_DEVICE_BUSY;
	}

	CONST NTSTATUS Status = NxcCommandDispatch((NEXUS_COMMAND*)CommandRaw);

	/*
	 * ⚠ THE LOG RING'S FIRST PRODUCER, and it is a real one on purpose. The ring exists for the
	 * inline hook, which does not exist yet -- and a ring whose only exercise is a synthetic test
	 * written to make it pass is a stub wearing working code. Logging every serviced command gives
	 * it a genuine writer immediately, makes it useful on its own as an audit trail of what the
	 * driver was asked to do, and exercises it under real use before a hook ever depends on it.
	 *
	 * ⚠ NOT LOGGED: the drain command itself. Draining would otherwise append an entry describing
	 * the drain, so a caller polling an idle ring would always find exactly one new event -- its own
	 * question -- and never an empty result. A log that cannot report "nothing happened" is useless
	 * for the thing it is for.
	 */
	{
		CONST NEXUS_COMMAND* CONST Answered = (CONST NEXUS_COMMAND*)CommandRaw;
		if (Answered->Opcode != NXCMD_OP_LOG_DRAIN)
			NxcLogRingWrite(NXCMD_LOG_KIND_COMMAND,
			                (UINT64)Answered->Opcode,
			                (UINT64)Answered->Result,
			                Answered->NtStatus);
	}

	/*
	 * Unconditional, and after the dispatch. NULL-checked because the slot is only non-NULL under a
	 * real map -- a service-started driver refuses long before this, but the check costs nothing and
	 * a wild write here would be in kernel mode.
	 */
	volatile NEXUS_CORE_BOOT_BLOCK* CONST Block = NexusCoreBootSlot;
	if (Block != NULL && Block->Magic == NEXUS_CORE_BOOT_MAGIC)
		Block->ArenaUsed = NxcArenaUsed();

	/*
	 * Released LAST, after the counter refresh, so the next command cannot observe a half-updated
	 * report. Every exit from here runs through this point -- which is the reason the guard lives in
	 * this wrapper rather than in the dispatch, where each of a dozen returns would have to remember.
	 */
	_InterlockedExchange(&gCommandInProgress, 0);

	return Status;
}
