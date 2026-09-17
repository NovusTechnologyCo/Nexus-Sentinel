/**
 * @file PgScan.h
 * @brief Is a PatchGuard context resident? -- a DIRECT answer instead of waiting for a bugcheck.
 *
 * ============================================================================================
 * WHY THIS EXISTS
 * ============================================================================================
 *
 * After defusing PatchGuard at boot, the only evidence that it worked was "the machine has not
 * bugchecked yet". That is not a measurement. PG's verification routes are randomised per boot
 * and some are slow, so a clean hour proves less than it feels like, and a clean day still is
 * not proof.
 *
 * The published alternative is direct: a PG context is a large allocation, and per Satoshi
 * Tanda's PgResarch "there is no other mechanism to allocate a PatchGuard context" -- every one
 * of them is big enough to be tracked as big pool. So enumerate big pool and look. No waiting,
 * no deliberate crash, read-only.
 *
 * ============================================================================================
 * ⚠⚠ THE INT 20h TRAP -- DO NOT "TEST" PATCHGUARD THAT WAY
 * ============================================================================================
 *
 * Issuing `int 20h` from kernel mode does invoke PG's verification path (KiSwInterrupt ->
 * KiSwInterruptDispatch), and it is widely suggested as an on-demand trigger. It is a TERRIBLE
 * test for a machine we have already patched.
 *
 * KiSwInterruptDispatch dereferences g_PgContext almost immediately -- EfiGuard issue #23
 * reports the crash at `KiSwInterruptDispatch+0x27`, `test dword ptr [rdi+994h]`, with rdi 0.
 * Our defusal RELOCATES g_PgContext into the INIT section, which is DISCARDED after boot. So on
 * a successfully patched machine, int 20h dereferences a pointer into freed memory and crashes
 * for a reason that has nothing to do with whether PG is alive.
 *
 * A bad-pointer crash and a genuine 0x109 are indistinguishable from the outside. The test
 * would cost a reboot and answer nothing.
 *
 * ============================================================================================
 * ⚠⚠ ABSENCE OF EVIDENCE. READ Pool.h's WARNING, IT APPLIES HERE WITH FORCE
 * ============================================================================================
 *
 * Pool.h already says it: an empty big-pool result means "no BIG allocation matched", never
 * "the thing is not there". That trap is far more tempting here, because a zero result is
 * exactly the answer we are hoping for.
 *
 * So this module is built to be WRONG LOUDLY rather than quietly reassuring:
 *
 *   - every result reports what was examined -- allocations, bytes, and what was skipped
 *   - a zero result is reported as "no candidate matched these signatures", never as "PG absent"
 *   - the signatures are listed per candidate, so a hit can be judged rather than trusted
 *
 * (!) AND IT IS NOT A MEASUREMENT UNTIL IT HAS SEEN A POSITIVE. A detector that has only ever
 * returned zero is indistinguishable from a detector that is broken. Validate it against a boot
 * with PG patching DISABLED, where a context MUST exist -- one reboot turns this from an
 * assumption into evidence, which is the whole point of building it.
 *
 * ============================================================================================
 * ⚠⚠ ALL OF THIS WAS REWRITTEN AFTER THE CONTROL BOOT. READ THIS FIRST.
 * ============================================================================================
 *
 * The control boot described above was run. PatchGuard was left alive, pgscan was run, and it
 * reported 13 candidates, NONE of which was PatchGuard. The real context was found instead by
 * reading g_PgContext out of the live kernel:
 *
 *     g_PgContext            -> 0xFFFFAB087431341C
 *     containing allocation  -> 0xFFFFAB0874313000  size 0x42000  tag `FOCX`  NonPaged
 *     at the context address -> 2E 48 31 11  48 31 51 08  48 31 51 10  48 31 51 18 ...
 *                               i.e. `cs: xor [rcx],rdx` then an unrolled run of
 *                               `xor [rcx+N],rdx` stepping 8, then `add rcx,0x78`, repeating
 *     PTE for that page      -> RW NX kernel-only, 2 MB large page
 *     allocation base        -> 0x41C bytes of high-entropy padding, then the stub
 *
 * THE ENUMERATION WAS NEVER THE PROBLEM. That allocation is in big pool and pgscan examined it.
 * Tanda's premise holds. All four signatures were simply wrong, and every one of them wrong in
 * the direction that produces a confident zero:
 *
 *   SIZE       assumed 0x100000 + 0xAE8. MEASURED 0x42000 -- 264 KB, four times smaller. The
 *              floor was 0x40000, which is ONE ROUNDING away from having hidden it entirely.
 *   UNALIGNED  assumed the allocation base is not 16-byte aligned. MEASURED page-aligned. The
 *              padding offsets the CONTEXT INSIDE the allocation; the test looked at the wrong
 *              object and could never have fired on anything.
 *   CONST_A/B  assumed plaintext in the context. MEASURED absent. The context is encrypted --
 *              that is what the stub above exists to undo. Only the stub is readable.
 *   RWX        assumed "essentially nothing else should be" RWX. MEASURED RW + NX. Inverted: it
 *              cannot match PatchGuard and matches DMA buffers, which is precisely what the 13
 *              false positives were.
 *
 * (!) THE LESSON, WHICH IS WORTH MORE THAN THE SIGNATURES: all four came from reading about
 * PatchGuard rather than from looking at one. They were self-consistent, they were plausible,
 * and they agreed with each other -- and the tool built on them returned the answer we wanted
 * for two boots running. One control boot cost one reboot and refuted all four.
 *
 * ============================================================================================
 * SECOND CONTROL BOOT, SAME DAY -- WHAT VARIES AND WHAT DOES NOT
 * ============================================================================================
 *
 * The rewritten scanner was then run on a second control boot. It returned ONE candidate, and
 * the g_PgContext cross-check confirmed that candidate contains the pointer. End to end, in the
 * kernel, on live memory -- not a replay of captured bytes.
 *
 *                     control boot 1            control boot 2
 *     allocation      0xFFFFAB0874313000        0xFFFF948AA3313000      moves (KASLR)
 *     size            0x42000                   0x42000                 STABLE on this build
 *     tag             `FOCX`                    `IxLd`                  RANDOM per boot
 *     padding         context at +0x41C         context at +0x2E6       RANDOM, both < 0x800
 *     stub run        +0x420                    +0x2EA                  always padding + 4
 *     RWX             not set                   not set                 NX, confirmed twice
 *
 * ⚠ THE TAG AND THE PADDING ARE RANDOM PER BOOT. Nothing may key on either. `FOCX` is in this
 * file only as evidence, never as a constant -- a tag allowlist would have looked like it worked
 * for exactly as long as it took to reboot.
 *
 * The 4-byte gap between the context and the matched run is the stub's first instruction, the
 * mod=00 `xor [rcx],rdx` the run test deliberately does not require. It reproduced exactly, so
 * that omission is understood rather than lucky.
 *
 * FALSE POSITIVES WENT 13 -> 0 WHILE TRUE POSITIVES WENT 0 -> 1, over ~2500 allocations. The
 * DMA buffers vanished because RWX stopped being strong, and the context appeared because the
 * stub search replaced signatures that could not match it. Those are the same change.
 *
 * (!) HONEST BOUNDARY, NOT A CLOSED QUESTION: exactly ONE context was found. PatchGuard is
 * documented to maintain more than one in some configurations, and a single sample cannot
 * distinguish "there was one" from "we found one of several". Allocations below the floor, and
 * the ~65 skipped as non-resident, were never searched. This does not touch the defusal verdict
 * -- that rests on g_PgContext and on the stubbed init routines, which prevent contexts being
 * created at all -- but it is the next thing a second pair of eyes should pull on.
 *
 * ============================================================================================
 * SIGNATURES, AND WHERE THEY COME FROM
 * ============================================================================================
 *
 * Tanda's original identification XORs candidate memory against CmpAppendDllSection's bytes and
 * tests the recovered key against following bytes. It needs CmpAppendDllSection located in the
 * running kernel and predates 24H2's dual-encryption layer, so it is not what this implements.
 *
 * What this implements comes from the control boot, not from a write-up:
 *
 *   STUB       the decryption loop, found at a 0..0x7FF offset into the allocation. Structural
 *              rather than literal: a run of >= PG_STUB_MIN_RUN instructions of the form
 *              `48 31 <modrm> <disp8>` -- REX.W xor r/m64, r64 -- sharing one modrm byte, with
 *              disp8 advancing by 8 each time. That is a loop walking a buffer in qword steps,
 *              which is what an in-place decryptor IS, and it survives PatchGuard picking
 *              different registers. 8 instructions is 32 bytes of exact structure; the odds of
 *              it in arbitrary data are nil.
 *   CONST_A/B  kept, and expected to stay silent. They cost one pass over memory already being
 *              read, they are the one signature that would identify a context OUTRIGHT, and a
 *              build that stops encrypting is worth catching for free. Not strong on evidence --
 *              strong if it ever fires.
 *   RWX        kept, REPORTED, and NEVER strong. Measured NX on the real context, so it is now a
 *              negative indicator: an RWX candidate is more likely a DMA buffer than PatchGuard.
 *              It stays because removing a measurement because it disagreed with expectations is
 *              how this file got into trouble in the first place.
 *
 * (!) AND A DETERMINISTIC ROUTE EXISTS -- PREFER IT WHEN YOU HAVE THE RVA. g_PgContext is a
 * pointer the kernel maintains; reading it needs no signature at all. After defusal it points
 * into the DISCARDED INIT section, and while PatchGuard is alive it points at the stub above:
 *
 *     PlatformCtl read ntoskrnl.exe <g_PgContext RVA> 8
 *
 * The DXE prints that RVA at boot. This scanner exists for the case where you do not have it,
 * and as an INDEPENDENT check on the DXE's own claim to have relocated the pointer -- asking the
 * component under test whether it worked is not a measurement.
 */

#pragma once

#include <ntddk.h>
#include "../../Include/NexusCoreBoot.h"
#include "../../Include/NexusCommand.h"

/**
 * A big-pool allocation matched at least one PatchGuard signature.
 *
 * (!) 0x01 (SIZE) and 0x02 (UNALIGNED) ARE RETIRED AND MUST NOT BE REUSED. Both were measured
 * wrong -- see the block at the top of this file. The values are burned rather
 * than recycled so that a PlatformCtl built before that day cannot render a new signature under
 * an old name; the two ends of this wire are rebuilt together, but a stale binary on disk is not
 * a hypothetical in a project that ships an .exe the user copies by hand.
 */
#define NXC_PGSIG_CONST_A     0x04u   /* 0x5C5FC0A76E374B18 in plaintext -- not seen in practice */
#define NXC_PGSIG_CONST_B     0x08u   /* 0x4C48B4211BBACBEB in plaintext -- not seen in practice */
#define NXC_PGSIG_RWX         0x10u   /* MEASURED NX on the real context: a NEGATIVE indicator   */
#define NXC_PGSIG_STUB        0x20u   /* the unrolled XOR decryption loop -- the real signature  */

/**
 * Signatures strong enough to report on their own.
 *
 * (!) RWX IS DELIBERATELY ABSENT, and its absence is the whole correction of. It was
 * in this set, it is the reason 13 DMA buffers were reported as candidates, and it cannot match
 * PatchGuard because PatchGuard's pages are NX. It is still COMPUTED and still REPORTED -- the
 * fix for a misleading signal is to describe it correctly, not to stop measuring it.
 */
#define NXC_PGSIG_STRONG      (NXC_PGSIG_CONST_A | NXC_PGSIG_CONST_B | NXC_PGSIG_STUB)

/**
 * The stub search.
 *
 * WINDOW: PatchGuard prepends 0..0x7FF random bytes, and g_PgContext points at the stub, so the
 * stub begins within the first 0x800 bytes of the allocation. Measured at +0x41C.
 *
 * RUN: eight `48 31 <modrm> <disp8>` instructions with a shared modrm and disp8 stepping by 8 is
 * 32 bytes of exact structure. The observed stub runs 16 before its `add rcx,0x78`, so eight is
 * half the real thing -- deliberately, because the number of unrolled steps is exactly the kind
 * of detail that changes between builds and the last set of signatures died of assuming it would
 * not.
 */
#define PG_STUB_WINDOW        0x800u
#define PG_STUB_MIN_RUN       8u

typedef struct _NXC_PG_CANDIDATE
{
	UINT64 Address;      /* big-pool allocation base, flag bit already masked off */
	UINT64 SizeInBytes;
	UINT32 TagUlong;
	UINT32 Signatures;   /* NXC_PGSIG_* */
	/*
	 * Where the match was, or 0. For a constant, the constant. For STUB, the start of the
	 * matched RUN -- which is NOT quite the context.
	 *
	 * (!) MEASURED: g_PgContext was +0x41C and the run matches at +0x420. The four bytes in
	 * between are the stub's first instruction, `2E 48 31 11` -- a CS-prefixed `xor [rcx],rdx`
	 * with mod=00, so it carries no displacement to advance and is deliberately NOT required by
	 * the run test. Reporting where the RUN starts rather than guessing backwards over an
	 * optional prefix keeps this field a measurement instead of an inference; treat it as "the
	 * context begins at or just before here".
	 */
	UINT64 HitOffset;
} NXC_PG_CANDIDATE;

/*
 * (!) THE DRIVER STRUCT AND THE WIRE STRUCT MUST STAY THE SAME SIZE.
 *
 * The command handler validates the caller's buffer and computes its capacity using
 * sizeof(NXCMD_PG_CANDIDATE) -- the packed wire form -- but allocates and copies using
 * sizeof(NXC_PG_CANDIDATE), this one, which is not packed. They are both 32 bytes today and
 * neither has padding, so the two agree by luck of layout rather than by construction.
 *
 * A field added to either one makes the copy length exceed the length that was validated,
 * silently, on a path that writes to a caller-supplied address. This is the "two lists that
 * must agree" shape, so a machine checks it instead of a reviewer.
 */
typedef char nxc_pgcand_size_assert[(sizeof(NXC_PG_CANDIDATE) == sizeof(NXCMD_PG_CANDIDATE)) ? 1 : -1];

/**
 * Examine resident big-pool allocations for PatchGuard contexts.
 *
 * READ ONLY. Nothing is written, nothing is allocated in the target, and no kernel structure is
 * modified. Safe to run repeatedly on a live system.
 *
 * @param Out            candidates, most-signatures-first is NOT guaranteed -- caller sorts
 * @param Cap            capacity of @p Out
 * @param MinSize        smallest allocation to consider; 0 uses the built-in floor
 * @param OutGot         candidates written
 * @param OutTotal       candidates found (may exceed OutGot -- report both, never just one)
 * @param OutScanned     big-pool allocations EXAMINED
 * @param OutBytes       bytes actually byte-scanned, so a small number exposes a scan that
 *                       skipped almost everything and still returned "nothing found"
 * @param OutSkipped     allocations skipped because a page was not resident
 * @param OutAvailable   allocations that EXIST at or above the floor, which may exceed what was
 *                       examined. See the note on truncation in PgScan.c -- this is the number
 *                       that turns "examined 4096" from a fact into a coverage figure.
 */
NTSTATUS
NxcPgScan(
	_Out_writes_(Cap) NXC_PG_CANDIDATE* Out,
	_In_ UINT32 Cap,
	_In_ UINT64 MinSize,
	_Out_ UINT32* OutGot,
	_Out_ UINT32* OutTotal,
	_Out_ UINT32* OutScanned,
	_Out_ UINT64* OutBytes,
	_Out_ UINT32* OutSkipped,
	_Out_ UINT32* OutAvailable
	);
