/**
 * @file Hook.h
 * @brief Inline hook on a kernel VA. ONE naturally-aligned 8-byte store, or nothing.
 *
 * ============================================================================================
 * WHY THIS IS NOT A 14-BYTE DETOUR (build-plan item 21, decision D14)
 * ============================================================================================
 *
 * TIER 3 (v1, v1's `hwid_spoof_gpu_inline.c`): v1 built the classic detour --
 *   a 14-byte `FF 25` absolute jump written with RtlCopyMemory, a hand-rolled ~200-line length
 *   decoder, RIP-relative disp32 fixups, trampoline in POOL_FLAG_NON_PAGED_EXECUTE. It is the most
 *   complete thing v1 built in this area, and almost none of it can carry over:
 *
 *     - the write is 2-3 separate stores, so ANOTHER CORE CAN FETCH A HALF-WRITTEN INSTRUCTION
 *     - the MmMapIoSpace fallback is BANNED here: it froze this host twice on system RAM
 *     - the CR0.WP=0 fallback is BANNED here: preemptible, CET is active, already caused a 0xEF
 *     - all three are wrapped in __try/__except, and there is NO SEH in a manually mapped image
 *
 *   Its shape is a three-method ladder that stops at whichever write appears to stick. That turns
 *   "this is not safe here" into "it worked on the third try", and the third try is the one that
 *   bugchecked this machine.
 *
 * TIER 2 (internet, and it is the load-bearing tier): x86 guarantees that a NATURALLY ALIGNED store
 *   of 8 bytes or fewer is atomic -- every other core sees either all the old bytes or all the new
 *   ones. There is no such guarantee for 14. Separately, the SDM's cross-modifying-code protocol
 *   requires a SERIALIZING OPERATION ON THE EXECUTING PROCESSORS, not merely a correct store on the
 *   writing one.
 *
 * TIER 1 (`reference material/`): EfiGuard ships hde64 (Patkov), the same length decoder MinHook
 *   uses -- 346 lines, needing only stdint.h, intrin.h and __stosb. Vendored under hde/. A
 *   trampoline must copy WHOLE instructions; guessing that boundary is how a trampoline ends up
 *   executing the tail of one instruction as the head of another.
 *
 * ============================================================================================
 * WHAT THIS DOES INSTEAD
 * ============================================================================================
 *
 *   1. The patch is `E9 rel32` -- FIVE bytes, which fit inside one aligned qword.
 *   2. The aligned qword containing them is read, the five bytes are SPLICED IN, and the whole
 *      qword is stored back ONCE. Bytes outside the patch keep their original values rather than
 *      being clobbered with padding.
 *   3. The store happens inside KeIpiGenericCall, which holds every other core in an interrupt for
 *      the duration. The atomic store already prevents tearing; the broadcast is what satisfies the
 *      SDM's requirement that the other processors serialize.
 *   4. The write goes through a WRITABLE ALIAS and nowhere else, and the read-back that proves it
 *      goes through the ORIGINAL VA -- an alias pointing at the wrong frames would otherwise read
 *      back its own write and call that success.
 *
 * ⚠ AND IT REFUSES, in five places, rather than reaching for a second method:
 *
 *   - `(Va & 7) > 3`: the five bytes would straddle two qwords and no single store covers them.
 *     A REAL limit on which functions are hookable, reported as one.
 *   - handler further than +-2 GB: `rel32` cannot reach it. Whether our mapped image lands within
 *     2 GB of a given kernel target is not assumed in either direction -- it is measured here and
 *     the actual delta is reported.
 *   - the length decoder erroring anywhere in the first bytes.
 *   - a RIP-relative or relative-branch instruction among the stolen bytes. v1 fixed disp32 up;
 *     that is more capable and it is also more ways to be subtly wrong, and a rel32 CALL cannot be
 *     relocated by adjusting its displacement at all without re-encoding it to a different length.
 *   - the read-back through the original VA not matching what was stored.
 *
 * ⚠ WHAT IT STILL CANNOT PROMISE, stated because the alternative is implying otherwise: if a thread
 * is stopped with its RIP INSIDE the five patched bytes, it resumes into the middle of the new
 * instruction. Atomicity does not help -- the store is indivisible, the resumption is not. The
 * standard answer is a hotpatch prologue the compiler reserved, which we do not control on an
 * arbitrary target. Hooking a FUNCTION ENTRY makes the window small; it does not close it.
 */

#pragma once

#include <ntddk.h>

/** Maximum bytes the trampoline will copy. Five are needed; sixteen is the longest x64 instruction. */
#define NXC_HOOK_MAX_STOLEN   24u

/** How many hooks can be live at once. Small on purpose -- each one is a live code patch. */
#define NXC_MAX_HOOKS         8u

/** Why an install refused. Non-zero values name the step, so a failure explains itself. */
#define NXC_HOOK_OK              0u
#define NXC_HOOK_BAD_ALIGN       1u   /* (Va & 7) > 3 -- five bytes straddle two qwords */
#define NXC_HOOK_OUT_OF_RANGE    2u   /* handler beyond +-2 GB; rel32 cannot reach     */
#define NXC_HOOK_NOT_RESIDENT    3u   /* target bytes not valid/resident               */
#define NXC_HOOK_DECODE_FAILED   4u   /* hde64 could not decode the prologue           */
#define NXC_HOOK_RELATIVE_INSN   5u   /* a RIP-relative or relative branch was stolen  */
#define NXC_HOOK_NO_TRAMPOLINE   6u   /* arena could not give executable memory        */
#define NXC_HOOK_VERIFY_FAILED   7u   /* read-back through the ORIGINAL VA disagreed   */
#define NXC_HOOK_NO_SLOT         8u   /* NXC_MAX_HOOKS already live                    */
#define NXC_HOOK_ALREADY         9u   /* this VA is already hooked                     */
#define NXC_HOOK_FOREIGN_PATCH  10u   /* on removal: the qword is no longer ours       */
/*
 * ⚠⚠ THE TARGET IS AN IDT GATE HANDLER ENTRY. Refused unconditionally -- see the block in
 * NxcHookInstall. An ISR entry runs BEFORE swapgs with interrupts disabled, so the thunk
 * GS-relative PCR read dereferences USER memory inside a trap handler. It bugchecked this
 * machine (CLOCK_WATCHDOG_TIMEOUT). hde64 also cannot decode swapgs, so the
 * stolen-byte count was never trustworthy either.
 */
#define NXC_HOOK_IS_IDT_HANDLER 11u

/** One live hook. */
typedef struct _NXC_HOOK_ENTRY
{
	UINT64 TargetVa;       /* the patched function entry                              */
	UINT64 HandlerVa;      /* where the E9 goes                                       */
	UINT64 TrampolineVa;   /* stolen instructions + an absolute jump back             */
	UINT64 AlignedVa;      /* TargetVa & ~7 -- the qword actually stored to           */
	UINT64 OriginalQword;  /* as it was, for restore                                  */
	UINT64 PatchedQword;   /* as we left it; a later mismatch means someone else wrote */
	UINT32 StolenBytes;
	UINT32 Active;
	UINT32 ExtentId;       /* the arena handle -- NxcArenaFree takes an ID, not a VA   */
	/*
	 * ⚠ THE INSTALL FLAGS, KEPT PER HOOK, because the HIT PATH has to consult them and it runs on
	 * the target's thread with nothing but this pointer in r10. A global "LBR sampling is on" would
	 * be wrong the moment two hooks want different things, and the hit path has no way to ask which
	 * hook it belongs to other than the entry it was handed.
	 */
	UINT32 InstallFlags;   /* NXC_HOOK_FLAG_* as installed                             */
	/*
	 * Record only hits taken by THIS process; 0 records every process.
	 *
	 * APPENDED, so TrampolineVa keeps offset 16 and the thunk's fixed reach is untouched.
	 *
	 * ⚠ IT SUBTRACTS FROM THE RECORD, NEVER FROM BEHAVIOUR. The hit is counted and the target still
	 * runs exactly as it would have; only the ring write and the LBR snapshot are skipped. A filter
	 * that changed what the machine DID would be a patch pretending to be a scope.
	 */
	UINT32 FilterPid;
} NXC_HOOK_ENTRY;

/*
 * The thunk reaches TrampolineVa by fixed offset, so a field reordering must break the BUILD rather
 * than produce a jump to a wild address. Hook.c already C_ASSERTs this; repeated here because the
 * struct is what a reader edits and the assert is what they will not think to look for.
 */
C_ASSERT(FIELD_OFFSET(NXC_HOOK_ENTRY, TrampolineVa) == 16);

/**
 * Install an inline hook.
 *
 * @param TargetVa   kernel VA of the function entry to patch. KERNEL ONLY in this version -- every
 *                   safety property above has to hold once before cross-process translation is
 *                   stacked on top of it (D14.6).
 * @param Flags      NXC_HOOK_FLAG_LOG for a logging detour; 0 for the no-op one.
 * @param OutDetail  NXC_HOOK_* naming the step that refused, 0 on success
 * @param OutDelta   the measured handler-target displacement, ALWAYS written -- it is the number
 *                   that says whether out-of-range is marginal or hopeless
 */
NTSTATUS NxcHookInstall(
	_In_ UINT64 TargetVa,
	_In_ UINT32 Flags,
	_In_ UINT32 FilterPid,
	_Out_ UINT32* OutDetail,
	_Out_ INT64* OutDelta,
	_Out_ UINT32* OutStolen
	);

/**
 * The far end of a --log detour, in HookThunk.asm. Never called from C -- its address is what the
 * generated stub jumps to, and it does not follow the C calling convention on the way out (it tail-
 * jumps into the trampoline rather than returning).
 */
extern void NxcHookThunk(void);

/**
 * Hits recorded, hits REFUSED because the handler was already active on this core, and hits that
 * were real but belonged to a process the filter excluded.
 *
 * ⚠ THE THIRD IS WHAT MAKES A SCOPED HOOK DISTINGUISHABLE FROM A DEAD ONE. "0 records" and "75000
 * hits, none of them yours" call for opposite next actions, and without this they look identical.
 */
void NxcHookCounters(_Out_ UINT64* OutHits, _Out_ UINT64* OutReentries, _Out_ UINT64* OutFiltered);

/**
 * How many installed hooks carry NXC_HOOK_FLAG_LBR.
 *
 * ⚠ EXISTS SO THE SNAPSHOT RING CANNOT BE FREED UNDER A LIVE SAMPLER. Releasing that arena extent
 * while a hook is still storing into it is a use-after-free written by code running at the target's
 * IRQL on the target's thread -- the worst possible place to discover it. `NxcLbrSnapFree` asks this
 * and refuses rather than trusting the caller to unhook first.
 */
UINT32 NxcHookLbrSamplerCount(void);

/**
 * How many installed hooks carry NXC_HOOK_FLAG_EXCEPTION -- i.e. whether anything is actually
 * observing the exception dispatcher RIGHT NOW.
 *
 * ⚠ EXISTS SO `bp set` ASKS A LIVE QUESTION INSTEAD OF READING A CONSTANT. NxcBpHandlerInstalled
 * returned a hardcoded FALSE with a comment calling itself "the single line that changes when item
 * 15 lands". Item 15 landing does NOT make the answer TRUE: it makes it ANSWERABLE. Hardcoding TRUE
 * would be a fake verdict of exactly the kind this project forbids, and a far worse one than the
 * FALSE it replaced -- arming a debug register when nothing is hooked kills the target on its first
 * hit, and the constant would keep claiming a handler existed after `bp dispatch remove`.
 *
 * The count is a FACT about the hook table, so it tracks install and remove for free.
 */
UINT32 NxcHookExceptionObserverCount(void);

/**
 * Remove one hook by target VA.
 *
 * ⚠ REFUSES IF THE QWORD IS NO LONGER WHAT WE LEFT THERE. Something else patched over us, and
 * restoring our saved original would then destroy THEIR patch -- turning one unknown into a second,
 * worse one. Reported as NXC_HOOK_FOREIGN_PATCH and left alone.
 */
NTSTATUS NxcHookRemove(_In_ UINT64 TargetVa, _Out_ UINT32* OutDetail);

/**
 * Remove every live hook.
 *
 * ⚠ NOTHING CALLS THIS YET, AND THAT IS A PROPERTY OF THE IMAGE, NOT AN OVERSIGHT. A manually
 * mapped image has no driver object, so there is no DriverUnload and no teardown path to hang it
 * on -- the same absence that rules out FltRegisterFilter and ObRegisterCallbacks here. The image
 * lives until the machine reboots, and so does any patch it installed.
 *
 * The practical consequence is that `unhook` (or a reboot) is the ONLY way a patch comes out, and
 * `hook list` is the only way to find one you forgot. It is kept and exported so that the moment a
 * teardown path does exist, the correct call is already written rather than remembered.
 */
void NxcHookRemoveAll(void);

/** Copy the live hook table out for `PlatformCtl hook list`. */
NTSTATUS NxcHookList(
	_Out_writes_(Cap) NXC_HOOK_ENTRY* Out,
	_In_ UINT32 Cap,
	_Out_ UINT32* Got,
	_Out_ UINT32* Total
	);

/**
 * ============================================================================================
 * ⚠ STAGE 1: THE DETOUR IS A NO-OP. It changes control flow and nothing else.
 * ============================================================================================
 *
 * The handler installed by `hook <va>` is not a logger yet. It is fourteen bytes:
 *
 *     FF 25 00 00 00 00        jmp qword ptr [rip+0]
 *     <qword: trampoline>
 *
 * which jumps straight into the trampoline, which runs the stolen instructions and jumps back to
 * target+N. The hooked function therefore behaves EXACTLY as it did, having taken a detour through
 * two jumps to get there.
 *
 * That is the entire point of stage 1, and it is the same split that made Intel PT cheap to get
 * wrong safely. Everything hard about an inline hook -- the length decode, the trampoline, the
 * relative-branch rejection, the aligned splice, the alias write, the read-back, the restore -- is
 * exercised end to end, while the thing running at the patched address touches NO REGISTER. This
 * encoding was chosen over `mov rax, imm64 / jmp rax` for exactly that reason: `jmp [rip+0]` reads
 * its destination from data, so there is no immediate to mis-encode and not even RAX is disturbed.
 *
 * A logging thunk has to save rcx/rdx/r8/r9 and xmm0-3, call into C, restore, and tail-jump -- some
 * sixty hand-encoded bytes executing at an arbitrary kernel function entry with no SEH. Building
 * that on top of an UNPROVEN patch mechanism would mean a bugcheck could not say which half was
 * wrong. Stage 2 is a small delta on a proven base; stage 1 is the base.
 */

/*
 * Space reserved for the stub. The stage-1 no-op form is 14 bytes; the stage-2 --log form is 24
 * (10 to load the context into r10, then the same 14-byte absolute jump). The larger is reserved
 * unconditionally so the two variants share one extent layout and one trampoline offset -- ten
 * bytes of slack is cheaper than two layouts to keep in agreement.
 */
#define NXC_HOOK_STUB_BYTES   24u

/**
 * Install a LOGGING detour instead of a no-op one.
 *
 * ⚠ OPT-IN, AND THE NO-OP REMAINS THE DEFAULT. The stage-1 stub touches no register at all -- not
 * even RAX, since `jmp [rip+0]` reads its destination from data -- and it is the variant proven on
 * hardware. The logging stub carries a context pointer in r10 and runs the shared thunk, which
 * saves the volatile set, calls into C at the target's own IRQL, restores and tail-jumps. That is
 * strictly more that can go wrong, so it is asked for rather than assumed.
 */
#define NXC_HOOK_FLAG_LOG     0x00000001u

/*
 * ⚠ SNAPSHOT THE LBR RING AT EVERY HIT. This is what makes LBR ATTRIBUTABLE, and it is the whole
 * reason LBR did not need the system-wide `#DB` interception (D23).
 *
 * LBR has no CR3 filter, so a ring read from a command thread holds whichever process last ran on
 * that core -- true but useless. A hook stub runs on THE TARGET'S OWN THREAD, immediately after the
 * target's own branches, so the ring at that instant is the path INTO the hook and nothing else.
 * With LBR armed ring-3-only, that path is the target's USER-MODE call chain leading to whatever
 * syscall reached this function -- which is precisely what Intel PT cannot reconstruct without the
 * target's image.
 *
 * ⚠ IT IS EXPENSIVE AND THEREFORE BOUNDED. A snapshot is up to 3 RDMSRs per entry (~96 for a
 * depth-32 ring), several microseconds, on the target's own thread at its own IRQL. A hook on a hot
 * function would pay that on every call forever, so capture STOPS at a fixed snapshot count while
 * hit counting continues. The cost is bounded by construction rather than by remembering to unhook.
 *
 * ⚠ REQUIRES NXC_HOOK_FLAG_LOG. The no-op detour never reaches C, so there is nowhere to sample
 * from -- asking for LBR without logging is refused rather than silently doing nothing.
 */
#define NXC_HOOK_FLAG_LBR     0x00000002u

/*
 * ⚠ RUN EVERY CHECK, ALLOCATE THE REAL STUB, MEASURE THE REAL DISTANCE -- AND PATCH NOTHING.
 *
 * This exists because of ONE specific question that gates all of phase 3: is the arena within
 * `rel32` reach of the exception dispatcher? The dispatcher was located structurally (D16/D17) and
 * deliberately NOT hooked, and the recorded open item is a ~1.8 GB gap against a +-2 GB limit --
 * marginal, and KASLR-dependent, so it is different every boot.
 *
 * ⚠ THE ANSWER CANNOT BE ESTIMATED, IT HAS TO BE MEASURED, because the reachable thing is the STUB
 * and the stub's address is not known until the arena has chosen one. So the probe really does
 * allocate, really does compute the delta from the address it got, and then releases it. Anything
 * short of that would report the distance to a stub the real install would not have used.
 *
 * ⚠ AND IT MUST NOT BE ANSWERED BY JUST TRYING IT. `hook <dispatcher>` succeeding is a patch on the
 * path of EVERY exception in the system, installed to answer a question. The probe makes the
 * measurement free of that decision, which is what lets the decision be made on evidence.
 */
#define NXC_HOOK_FLAG_PROBE   0x00000004u

/*
 * ⚠⚠ THE EXCEPTION-PATH VARIANT. The hit handler treats arg1 as a PEXCEPTION_RECORD, counts by
 * exception code, and does NOTHING else -- no ring write, no LBR snapshot, no claim.
 *
 * It exists because KiDispatchException runs for EVERY dispatched exception on the machine. The
 * normal --log path writes a ring entry per hit, which here would flood a 4096-entry ring in well
 * under a second and destroy every other record in it; --lbr would add ~96 RDMSRs to the system
 * exception path, which is not a diagnostic but a slowdown we introduced. Both are skipped.
 *
 * ⚠ NEEDS NO ASSEMBLY CHANGE, and that is why this stage is reachable at all: the thunk already
 * forwards the target first two integer arguments, and KiDispatchException first is the exception
 * record -- a PUBLIC structure whose ExceptionCode has been at offset 0 since NT. Nothing is
 * pinned and nothing can drift.
 */
#define NXC_HOOK_FLAG_EXCEPTION 0x00000008u

/*
 * Call evidence -- B-01/B-02. Mirrors NXCMD_HOOK_FLAG_CALLS / _OBJATTR3 / _USTR2, whose reasoning is
 * carried in NexusCommand.h next to the record they fill.
 *
 * ⚠ _CALLS IMPLIES REACHING C, so it depends on the LOGGING detour exactly as --lbr does, and is
 * refused without it for the same reason: the no-op stub never reaches C, so the hook would install
 * cleanly, take every hit, and record nothing -- a command that lies about what it did.
 */
#define NXC_HOOK_FLAG_CALLS     0x00000010u
#define NXC_HOOK_FLAG_OBJATTR3  0x00000020u
#define NXC_HOOK_FLAG_USTR2     0x00000040u
/* arg4 is a PCLIENT_ID -- follow it for the pid/tid being opened. Independent of the name shape;
 * NtOpenProcess may carry both, and which is populated is the caller's choice. */
#define NXC_HOOK_FLAG_CID4      0x00000080u
/* Arg1 is a file HANDLE and arg5 may be a delete disposition -- capture the CONTENT (B-01, D110).
 * The hook only references and queues; the worker does the reading. */
#define NXC_HOOK_FLAG_FCAP      0x00000100u
/* arg2 is a PVOID* and arg3 a PSIZE_T -- follow both, then walk the PTE at the resulting VA to
 * record what the CPU enforces BEFORE the flip. Mirrors NXCMD_HOOK_FLAG_PROT, whose reasoning is
 * carried in NexusCommand.h next to the fields it fills. Depends on _CALLS: the fields live in
 * NXCMD_CALL_ENTRY and the log ring's three qwords cannot hold them. */
#define NXC_HOOK_FLAG_PROT      0x00000200u
/*
 * arg1/arg2 are (DEVICE_OBJECT, IRP) on a TPM driver dispatch -- decode the device-control request
 * and record it. OBSERVATION ONLY: the recorder returns without touching the IRP, so the target's
 * TPM command runs exactly as it would have. See TpmTrace.h for why the instrument must not also
 * be a mechanism, and scope doc §3c for the question it answers.
 *
 * Independent of _LOG and _CALLS on purpose: this hook's payload is neither the log ring's three
 * qwords nor an NXCMD_CALL_ENTRY, and pretending otherwise would put TPM records somewhere a
 * `tpmtrace dump` would never look -- the exact failure described below.
 */
#define NXC_HOOK_FLAG_TPM       0x00000400u

/**
 * ⚠⚠ THE ACCEPT-MASK LIVES HERE, WITH THE FLAGS, BECAUSE A MASK KEPT ANYWHERE ELSE IS A SECOND LIST.
 *
 * The command path masks the caller's Flags word so an unknown bit from a newer PlatformCtl cannot
 * turn into a behaviour. That mask used to be spelled out at the call site, and it has now silently
 * dropped newly added flags TWICE:
 *
 *   it read `& NXC_HOOK_FLAG_LOG` alone, so LBR and PROBE were stripped -- `hook --lbr`
 *               installed a plain logging hook, reported success, and captured nothing.
 *   CALLS / OBJATTR3 / USTR2 were added HERE and the mask was not extended, so
 *               `hook nt NtCreateFile` installed as a LOG hook. It patched correctly, fired
 *               correctly, restored correctly, and `calls read` said `seen : 0 call(s)` -- the hits
 *               had gone to the log ring. Three hardware phases proved nothing.
 *
 * The second time happened while reading the comment describing the first, which is the argument
 * for structure over warning: a comment asserting an invariant camouflages its violation
 * (an earlier finding). Adding a flag
 * above and forgetting this line is still possible -- but now the flag and the mask are adjacent
 * and reviewed together, instead of being a header and a switch case 700 lines apart.
 */
#define NXC_HOOK_FLAG_ALL       (NXC_HOOK_FLAG_LOG       | \
                                 NXC_HOOK_FLAG_LBR       | \
                                 NXC_HOOK_FLAG_PROBE     | \
                                 NXC_HOOK_FLAG_EXCEPTION | \
                                 NXC_HOOK_FLAG_CALLS     | \
                                 NXC_HOOK_FLAG_OBJATTR3  | \
                                 NXC_HOOK_FLAG_USTR2     | \
                                 NXC_HOOK_FLAG_CID4      | \
                                 NXC_HOOK_FLAG_FCAP      | \
                                 NXC_HOOK_FLAG_PROT      | \
                                 NXC_HOOK_FLAG_TPM)

/*
 * ⚠⚠ AND NOW THE BUILD ENFORCES IT, BECAUSE ADJACENCY IS A REVIEW CONVENTION AND THIS DEFECT HAS
 * ALREADY LANDED TWICE.
 *
 * The paragraph above ends "Adding a flag above and forgetting this line is still possible". That
 * is an accurate description of a hazard and no defence against it -- and the second occurrence
 * happened WHILE READING THE COMMENT DESCRIBING THE FIRST. A comment asserting an invariant
 * camouflages its violation.
 *
 * NXC_HOOK_FLAG_NEXT is the next FREE bit. The flags are consecutive from bit 0, so a complete
 * NXC_HOOK_FLAG_ALL is exactly every bit below it -- one expression, checked by the compiler:
 *
 *   add a flag and forget ALL   -> ALL != NEXT-1   -> BUILD FAILS
 *   add to ALL and forget NEXT  -> ALL != NEXT-1   -> BUILD FAILS
 *
 * Both directions fail loudly, which is the property "reviewed together" never had. Adding a flag
 * is now two edits that the compiler insists agree, instead of two that a reader must notice.
 *
 * ⚠ IT ALSO PROVES THE BITS ARE CONSECUTIVE AND DISTINCT. A duplicated or skipped bit makes the OR
 * of the flags stop equalling NEXT-1, so this catches the same class NXCMD_CPU_FLAGS_OR/SUM catches
 * for the CPU flags -- which was itself added after a real collision (NXCMD_CPU_PT_IP_FILTER over
 * NXCMD_CPU_LBR_LEGACY_OK).
 */
#define NXC_HOOK_FLAG_NEXT      0x00000800u

C_ASSERT(NXC_HOOK_FLAG_ALL == (NXC_HOOK_FLAG_NEXT - 1u));

/**
 * ============================================================================================
 * PROVE THE PATCH END TO END, AGAINST A FUNCTION WE OWN, TOUCHING NOTHING ELSE.
 * ============================================================================================
 *
 * ⚠ EVERY HOOK CHECK THAT CAN RUN IN THE HARNESS IS A REFUSAL. That is deliberate -- an automated
 * suite that patches live kernel code and then relies on its own assertions to take the patch back
 * out is one failed assertion from leaving a jump into freed memory, on an image with no unload
 * path. But it means the whole INSTALL side had never executed, and a mechanism that has only ever
 * been observed saying no is not a mechanism anyone has evidence works.
 *
 * This closes that without going near foreign code. It hooks a function inside NexusCore whose
 * return value is known, and the sequence is the proof:
 *
 *   1. call it, record the answer                    -- the baseline, measured not assumed
 *   2. install the hook
 *   3. CALL IT AGAIN AND REQUIRE THE SAME ANSWER     <-- the actual test
 *   4. remove the hook
 *   5. call once more, and check the qword is byte-for-byte what it was before step 2
 *
 * Step 3 is the one that cannot be faked. The detour is a no-op, so the ONLY way the original
 * answer comes back is if the patched jump reached the stub, the stub reached the trampoline, the
 * stolen instructions executed correctly at their new address, and the jump back landed exactly at
 * target+N. Any of those wrong and the result is a wrong value or a bugcheck -- not a silent pass.
 *
 * If it fails, the damage is confined to a function whose only caller is this test.
 */
#define NXC_HOOK_ST_OK             0u
#define NXC_HOOK_ST_BASELINE       1u   /* the victim was wrong BEFORE anything was patched  */
#define NXC_HOOK_ST_INSTALL        2u   /* install refused; OutDetail2 carries its reason    */
#define NXC_HOOK_ST_WRONG_ANSWER   3u   /* ⚠ hooked, called, and the detour CHANGED the result */
#define NXC_HOOK_ST_NOT_LISTED     4u   /* installed but absent from the table               */
#define NXC_HOOK_ST_REMOVE         5u   /* removal refused                                   */
#define NXC_HOOK_ST_AFTER          6u   /* wrong answer after restore                        */
#define NXC_HOOK_ST_NOT_RESTORED   7u   /* the qword did not return to its original value    */
#define NXC_HOOK_ST_NO_HIT         8u   /* the LOGGING pass never reached the C handler      */
/* Pass 2 -- the LBR-sampling join, which had never executed before. */
#define NXC_HOOK_ST_NO_SNAP_RING   9u   /* could not reserve the snapshot ring               */
#define NXC_HOOK_ST_NO_LBR        10u   /* could not arm LBR; Detail2 = contended core count */
#define NXC_HOOK_ST_NO_SNAPSHOT   11u   /* hook fired, no snapshot -- --lbr missed the hit   */
#define NXC_HOOK_ST_EMPTY_SNAPSHOT 12u  /* snapshot taken but empty: LBR was not recording   */
#define NXC_HOOK_ST_WRONG_THREAD  13u   /* not attributed to the hitting thread              */

/**
 * @param OutDetail   NXC_HOOK_ST_* -- which step failed
 * @param OutDetail2  the NXC_HOOK_* reason, when the failing step was an install or a removal
 * @param OutHits     ring entries THIS RUN's logging pass produced -- a DELTA, never the lifetime
 *                    total. Reported on success as well as failure, because "it passed" does not
 *                    show that the thunk reached C: a detour that restores everything perfectly
 *                    without calling the handler passes every other check in the sequence.
 *
 *                    ⚠ The delta matters. Asserting a non-zero TOTAL is sound exactly once per
 *                    boot; every later run would pass on the leftover count from an earlier one
 *                    even with the thunk completely broken.
 */
NTSTATUS NxcHookSelfTest(_Out_ UINT32* OutDetail, _Out_ UINT32* OutDetail2, _Out_ UINT64* OutHits);
