/**
 * @file NexusCoreBoot.h
 * @brief The ONE contract shared by the EFI mapper and the NexusCore kernel driver.
 *
 * This header is included from BOTH sides of a handoff that crosses an execution-environment
 * boundary no debugger spans in one session:
 *
 *     PlatformRuntimeDxe.efi  (UEFI, EDK2 types, no CRT)
 *              |  embeds NexusCore.sys bytes, maps them, writes this block
 *              v
 *     NexusCore.sys           (kernel, ntddk types, no CRT either)
 *
 * So it must compile under both toolchains, which is why it uses only fixed-width integers
 * declared locally and NOTHING from <Uefi.h> or <ntddk.h>. Add nothing here that pulls in either.
 *
 * WHY A SHARED BLOCK AT ALL, rather than passing arguments: a manually-mapped driver's entry is
 * called as DriverEntry(NULL, NULL). It has no DriverObject and no RegistryPath -- umap notes
 * mapped drivers "must be designed to function without a real driver object". There is therefore
 * no argument channel, so the mapper writes what the driver needs INTO THE DRIVER'S OWN IMAGE at
 * a known symbol before calling the entry point. That is the RedLotus `mapper_data` pattern
 * (reference material/BlackAlien/redlotus/src/RedLotus.cpp), and it is proven in the field.
 *
 * ⚠ LAYOUT IS LOAD-BEARING. Both sides compile this independently, so a silent layout change is
 * a silent protocol break -- the exact failure class that shipped in the TCG transform when the
 * digest preimage was computed from the wrong offset. Every field is explicitly sized, the struct
 * is packed to a fixed layout, and both sides assert sizeof() and key offsets at compile time.
 * Never insert a field; only append, and bump NEXUS_CORE_BOOT_ABI.
 */

#pragma once

/*
 * Local fixed-width types. Deliberately not <stdint.h>: the UEFI side builds without a CRT and
 * the kernel side has its own ULONG-family spelling, and importing either one's headers here
 * would make this file un-includable from the other.
 */
typedef unsigned char      NXC_U8;
typedef unsigned short     NXC_U16;
typedef unsigned int       NXC_U32;
typedef unsigned long long NXC_U64;

/*
 * For sizeof(NEXUS_COMMAND) in NXC_STATUS_REPORT_SIZE below -- the status report carries the last
 * answered command. Safe to include: NexusCommand.h declares its own fixed-width types for exactly
 * the same reason this file does and pulls in neither <Uefi.h> nor <ntddk.h>, so it stays includable
 * from the UEFI side, the kernel side and a host compiler alike.
 */
#include "NexusCommand.h"

/* 'NXCB' little-endian. Checked by the driver before it trusts a single other field. */
#define NEXUS_CORE_BOOT_MAGIC   0x42435848ULL

/*
 * ABI version. BUMP THIS whenever a field is appended. The driver refuses a block whose ABI it
 * does not know, which is the only thing standing between a stale DXE and a mapped driver reading
 * garbage as pointers. Fail closed: refusing to run is recoverable, a wild write is not.
 */
#define NEXUS_CORE_BOOT_ABI    20u   /* 20: PgContextRva -- Reserved1 given a meaning; the
                                     *     deterministic 'is PatchGuard defused' answer.
                                     * 18: TpmFirmwareTcg -- what the FIRMWARE publishes,
                                      *     because the probe printed only to the boot screen
                                      * 17: Tpm* -- the software-TPM regions, so ring 0 can
                                      *     FIND them and readphys can be let into them
                                      * 16: Inherited*Pte -- the PTEs as WINDOWS handed them
                                      *     over, before we protected anything (I-04).
                                      * 15: DxeIdent -- WHICH DXE is running. PayloadIdent
                                      *     only identifies the embedded DRIVER, so a DXE-only
                                      *     change (proven 07-28 by the DSE removal) left the
                                      *     ident unchanged and the deploy unverifiable.
                                      * 14: KernelRevision -- the UBR. ABI 13 recorded only
                                      *     the BUILD, which does NOT move on the monthly updates
                                      *     that actually rewrite ntoskrnl and rot our signatures.
                                      * 13: MEASURED protection state (KernelBuild, CR4,
                                      *     hypervisor vendor) -- VBS/HVCI being OFF is the
                                      *     assumption everything rests on, so it is now read
                                      *     from HARDWARE every boot instead of by hand, once.
                                      * 12: KernelPatchLine -- WHY the kernel patch failed,
                                      *     in its OWN slot so a non-fatal advisory failure
                                      *     cannot occupy the first-writer-wins DxeRefusalLine
                                      *     and mask the bind failure that actually stopped us.
                                      * 11: PayloadIdent -- WHICH build is running.
                                      * 10: DxeRefusalLine -- WHY a boot phase gave up.
                                      * 9: per-phase entry cost (localise the variance).
                                      * 8: real entry timing (QPC + APERF/MPERF + NX cost).
                                      * 7: CommandHandler + the answered command in the report.
                                      * 2: arena.  3: nt base/size.  4: EntryDurationUs.
                                      * 5: measured page protections, firmware MAT, and
                                      *    the result of applying per-section protections.
                                      *    All three landed together deliberately -- ABI is
                                      *    about what has DEPLOYED, and no ABI 5 build has
                                      *    ever run, so folding them into one bump keeps the
                                      *    version history matched to real boots.
                                      * 6: PteProbeDiag -- ABI 5 DID reach hardware, so this one
                                      *    is a real bump rather than a fold.                   */

/*
 * BootFlags bits, set by the MAPPER. These exist so a mapper-side omission is distinguishable from
 * a driver-side failure -- added after exactly that ambiguity cost a boot.
 *
 * The mapper had never written the driver's exported slot, so DriverEntry found NULL and returned
 * without touching the block. The symptoms (Status UNSET, TSC 0, Caps 0, launch fired) were
 * IDENTICAL to "the driver faulted on its first write", and the diagnosis went to the wrong
 * suspect. This bit makes the two cases separable from the data alone.
 */
#define NXC_BOOTFLAG_SLOT_BOUND       0x00000001u  /* mapper resolved + wrote NexusCoreBootSlot   */
#define NXC_BOOTFLAG_IMPORTS_SCRUBBED 0x00000002u  /* import names/descriptors zeroed post-bind   */
#define NXC_BOOTFLAG_SCRUB_VERIFIED   0x00000004u  /* re-scanned the image: no residual "ntoskrnl" */
#define NXC_BOOTFLAG_ENTRY_HIJACK     0x00000008u  /* a boot driver's EntryPoint was redirected    */
#define NXC_BOOTFLAG_PROXIED          0x00000010u  /* driver called the original entry and it ran  */
/*
 * Payload had NO import directory at all -- the BEST outcome, not a failure.
 *
 * Added after the first boot with the import table removed reported "imports scrubbed:
 * no / scrub did not run", which reads as a fault when it actually means there was nothing left to
 * scrub. IMPORTS_SCRUBBED and this flag are mutually exclusive and both are success; only the
 * absence of BOTH is a problem.
 */
#define NXC_BOOTFLAG_NO_IMPORTS       0x00000020u  /* nothing to scrub: payload had no import table */

/*
 * ============================================================================================
 * DXE PHASE PROGRESS. Added after a failure nobody could locate.
 * ============================================================================================
 *
 * A status read showed the arena reserved and the image mapped -- so the DXE had run -- but the
 * driver never launched and everything BIND produces was absent. That narrows it to "the winload hook
 * never fired", and then stops, because the DXE records NOTHING about its own progress. Four very
 * different causes produce byte-identical output:
 *
 *   the bootmgfw hook never fired          -> winload was never patched
 *   the winload patch was refused          -> version gate, or the .text signature scan missed
 *   the patch applied, the hook never ran  -> OslFwpKernelSetupPhase1 not reached
 *   the boot resumed via winresume.efi     -> not patched at all (Fast Startup)
 *
 * I guessed the last one from HiberbootEnabled=1 and was wrong -- it had been a full restart. That is
 * the whole argument for these bits: with them the answer is read, not inferred.
 *
 * Bits, not a counter, because phases can be skipped rather than merely stopped, and because the
 * absence of a LATER bit alongside the presence of an EARLIER one is exactly the pair that localises
 * the break.
 *
 * ⚠ No ABI bump: BootFlags already exists and bits 0x40 up were free. Adding bit definitions is not a
 * layout change, which is the point of having a flags word at all.
 */
#define NXC_BOOTFLAG_DXE_ENTERED      0x00000040u  /* DXE entry point ran                          */
#define NXC_BOOTFLAG_RESERVED         0x00000080u  /* NexusCoreReserve got its pages               */
#define NXC_BOOTFLAG_BOOTMGFW_HOOKED  0x00000100u  /* bootmgfw image-load hook installed           */
#define NXC_BOOTFLAG_WINLOAD_PATCHED  0x00000200u  /* winload patched: the hook is in place        */
#define NXC_BOOTFLAG_SVAM_FIRED       0x00000400u  /* SetVirtualAddressMap ran (phase 3)           */
#define NXC_BOOTFLAG_BIND_RAN         0x00000800u  /* NexusCoreBind reached -- ntoskrnl was known  */

/*
 * The driver REFUSED to proxy: OriginalEntry did not look like a mapped kernel address.
 *
 * Set by the DRIVER, unlike the phase bits above. Exists because the alternative to refusing is an
 * indirect call to a bad pointer in kernel mode, which is a bugcheck with no diagnostic -- and the
 * block would have already been stamped STATUS_OK, so the surviving evidence would actively mislead.
 */
#define NXC_BOOTFLAG_PROXY_REFUSED    0x00001000u

/*
 * A gRT->ConvertPointer call failed during SetVirtualAddressMap, so something we hold is still a
 * PHYSICAL address that stopped meaning anything when the switch completed.
 *
 * Recorded because the alternative is silence followed by a wild call or a fault inside a firmware
 * runtime service. The DXE now disarms whatever could not be converted -- a launch that never fires is
 * diagnosable; a launch into a stale physical pointer is a bugcheck with no evidence.
 */
#define NXC_BOOTFLAG_SVAM_CONVERT_FAILED 0x00002000u

/*
 * PatchNtoskrnl returned EFI_SUCCESS.
 *
 * ⚠ ITS RESULT WAS OTHERWISE INVISIBLE AFTER BOOT. gKernelPatchInfo.Status is consumed in exactly one
 * place -- a coloured console banner during boot -- and nothing records it. Bind proceeds regardless
 * (correctly: our manual map does not depend on the kernel patch), so a FAILED kernel patch leaves a
 * system where every status read says OK while the patch silently did not apply.
 *
 * That is tolerable today because nothing we currently do needs it, and dangerous the moment
 * something does: the failure has no symptom to notice.
 */
#define NXC_BOOTFLAG_KERNEL_PATCHED   0x00004000u

/*
 * Set UNCONDITIONALLY at the PatchNtoskrnl call site, both outcomes. Pure "this DXE asks the
 * question", carrying no verdict of its own.
 *
 * WHY a second bit for one fact: flag additions deliberately do NOT bump the ABI (see the note at
 * the top of the flag block -- free bits in an existing word are not a layout change). So a clear
 * NXC_BOOTFLAG_KERNEL_PATCHED is ambiguous on its own: it means "the patch failed" OR "this DXE
 * predates the flag entirely", and those want opposite reactions from the reader. One bit cannot
 * encode a tri-state. Two can:
 *
 *     neither      -> DXE predates this check; the question is UNANSWERED, say so
 *     EVALUATED    -> the patch ran and FAILED  <-- the state that had no symptom
 *     both         -> applied
 *
 * Tried and rejected: bumping the ABI so absence implies failure. It would work, but it breaks the
 * established rule that ABI tracks LAYOUT, and it makes every future flag a lockstep redeploy.
 * Rejected harder: printing "failed" on the bare absence -- that fires a false alarm on exactly the
 * stale build that PayloadIdent exists to reveal, and a report that cries wolf stops being read.
 */
#define NXC_BOOTFLAG_KERNEL_PATCH_EVALUATED 0x00008000u

/*
 * ============================================================================================
 * TCG / SECURE BOOT SPOOF OUTCOME. Added (review), same defect as the kernel patch.
 * ============================================================================================
 *
 * The TCG results were reported by two Print() calls at ExitBootServices and NOWHERE ELSE, so
 * whether the Secure Boot measurement spoof actually worked was unknowable minutes after boot.
 *
 * Worse than the kernel patch case, because those prints sat INSIDE the `Status == EFI_SUCCESS`
 * branch of the kernel-patch reporting block: a failed kernel patch SUPPRESSED THE TCG REPORT
 * ENTIRELY, even though the two are unrelated and the TCG work had already run. Exactly the
 * gated-report bug found in the driver's hardening output earlier the same day -- a report
 * conditioned on an unrelated success hides precisely the boots worth reading.
 *
 * These are recorded at ExitBootServices, which is the FINAL state rather than a sample: the log
 * is measured no further after that point, so the hook's call count cannot change afterwards.
 *
 * EVALUATED is set unconditionally and carries no verdict -- the same tri-state encoding as the
 * kernel-patch flags, and for the same reason: without it, a clear HOOK_FIRED bit cannot be told
 * apart from a DXE that predates these flags, and the reader would report a spoof failure on a
 * merely-stale build.
 *
 * ⚠ No ABI bump: flag bits in an existing word are not a layout change.
 */
#define NXC_BOOTFLAG_TCG_EVALUATED    0x00010000u  /* this DXE reports TCG outcomes at all      */
#define NXC_BOOTFLAG_TCG_HOOK_FIRED   0x00020000u  /* GetEventLog hook served >= 1 call         */
#define NXC_BOOTFLAG_TCG_ACPI_OK      0x00040000u  /* the in-place ACPI log patch succeeded     */

/*
 * ⚠⚠ THE RUNG THAT WAS MISSING, AND IT COST A BOOT TO NOTICE.
 *
 * NXC_BOOTFLAG_BOOTMGFW_HOOKED has existed since ABI 12 and was NEVER SET BY ANYTHING -- declared,
 * printed nowhere, tested nowhere. Meanwhile the printed trail jumped straight from "DXE entry +
 * reserve" to "winload patched", so TWO completely different failures rendered identically:
 *
 *   the LoadImage hook was never installed        -> nothing could ever be caught
 *   the hook was installed but bootmgfw never came through it -> the boot path bypassed it
 *   bootmgfw came through and PatchBootManager failed          -> a real patch refusal
 *
 * measured: a boot showed `[ ] winload patched` with DxeRefusalLine == 0, and separating
 * those three took reading the DXE source. SEEN is set the moment HookedLoadImage identifies
 * bootmgfw, so the trail now distinguishes "never reached us" from "reached us and failed".
 */
#define NXC_BOOTFLAG_BOOTMGFW_SEEN    0x00080000u  /* HookedLoadImage identified bootmgfw.efi   */

/*
 * ⚠ THE TWO RUNGS BETWEEN "bootmgfw seen" AND "winload patched".
 *
 * PatchBootManager writes a hook over bootmgfw!ImgArchStartBootApplication, and THAT hook is what
 * calls PatchWinload when the boot application starts. Between "we saw bootmgfw" and "winload was
 * patched" there are therefore two more places to fail, and until both were invisible:
 *
 *   IMGARCH_HOOKED -- PatchBootManager reached the end and wrote the hook. Its refusal sites already
 *                     record DxeRefusalLine, so a ZERO refusal with this flag CLEAR would mean the
 *                     function returned early down a path that records nothing.
 *   IMGARCH_FIRED  -- the hook actually RAN. Clear-with-HOOKED-set is the interesting state: the
 *                     patch is in place and bootmgfw never called the function we hooked.
 *
 * Measured that day: bootmgfw WAS seen, DxeRefusalLine was 0, and winload was never patched -- a
 * combination these two flags reduce to a single unambiguous rung.
 */
#define NXC_BOOTFLAG_IMGARCH_HOOKED   0x00100000u  /* ImgArchStartBootApplication hook written  */
#define NXC_BOOTFLAG_IMGARCH_FIRED    0x00200000u  /* ...and it actually ran                    */

/*
 * ============================================================================================
 * WHY THE HOOK FIRED AND winload WAS STILL NOT PATCHED. Added after a boot that could
 * not be diagnosed, only guessed at.
 * ============================================================================================
 *
 * IMGARCH_FIRED and WINLOAD_PATCHED were adjacent rungs with nothing between them, so a boot showing
 * `[x] fired  [ ] patched` had TWO indistinguishable explanations -- and the hook body contains
 * exactly two early exits that reach neither rung:
 *
 *   RtlpImageNtHeaderEx returned NULL   -> the image is not a valid PE
 *   GetInputFileType != WinloadEfi      -> it was some other image entirely
 *
 * ⚠ NEITHER RECORDED ANYTHING. The first prints to the console and waits for a key; the second calls
 * DEBUG(), which is COMPILED OUT of a release build. Both then `goto CallOriginal` and the boot
 * continues normally, so by the time Windows is up there is no trace of which one ran -- the precise
 * shape an earlier finding exists to prevent, and the
 * fourth time it has cost a diagnosis here.
 *
 * ⚠ AND THE VACUUM GOT FILLED WITH A GUESS. With nothing recorded, the status tool offered a
 * registry-derived hypothesis about the boot path, which was wrong and had ALREADY been wrong once
 * (see the comment above the phase bits). An unrecorded branch does not read as "unknown" -- it reads
 * as an invitation to speculate. That is the real cost of a missing flag.
 *
 * IMGARCH_NOT_WINLOAD carries the observed type in the two bits below it, so the answer is "it was
 * bootmgfw" or "it was Unknown" rather than merely "it was not winload". WHICH image the boot handed
 * us is the whole question.
 */
#define NXC_BOOTFLAG_IMGARCH_BAD_PE      0x00400000u  /* hook fired, image was not a valid PE      */
#define NXC_BOOTFLAG_IMGARCH_NOT_WINLOAD 0x00800000u  /* hook fired, image was not winload.efi     */

/* Observed INPUT_FILETYPE, valid only when IMGARCH_NOT_WINLOAD is set. 0=Unknown 1=BootmgfwEfi
 * 2=WinloadEfi 3=Ntoskrnl -- the enum's own order, not a re-encoding that could drift from it. */
#define NXC_BOOTFLAG_IMGARCH_TYPE_SHIFT  24
#define NXC_BOOTFLAG_IMGARCH_TYPE_MASK   0x03000000u
#define NXC_BOOTFLAG_IMGARCH_TYPE(f)     (((f) & NXC_BOOTFLAG_IMGARCH_TYPE_MASK) >> NXC_BOOTFLAG_IMGARCH_TYPE_SHIFT)

/*
 * ⚠⚠ WHAT THE HOOK ACTUALLY SAW, RECORDED RATHER THAN INFERRED (ABI 17).
 *
 * The driver loads on some boots and not others, and every explanation offered for that so far has
 * been an inference from an absence. These two fields end the guessing: they are written BY THE DXE
 * AT THE MOMENT the hook runs, and they say what came through it.
 *
 * SUBSYS -- the PE Subsystem field of the last image the hook was handed that was NOT our patch
 * target. Five bits, because the value we most expect to see (0x10, Windows boot application) does
 * not fit in four. 0 means nothing was recorded.
 *
 * MULTI  -- set when the hook fired MORE THAN ONCE in a boot. That single bit distinguishes "we got
 * one look and it was the wrong image" from "several applications were started and we saw them" --
 * which are different problems with different fixes, and are indistinguishable without it.
 */
#define NXC_BOOTFLAG_IMGARCH_SUBSYS_SHIFT 26
#define NXC_BOOTFLAG_IMGARCH_SUBSYS_MASK  0x7C000000u
#define NXC_BOOTFLAG_IMGARCH_SUBSYS(f)    (((f) & NXC_BOOTFLAG_IMGARCH_SUBSYS_MASK) >> NXC_BOOTFLAG_IMGARCH_SUBSYS_SHIFT)
#define NXC_BOOTFLAG_IMGARCH_MULTI        0x80000000u

/*
 * ABI 18 -- TpmFirmwareTcg. What the FIRMWARE published, measured by the DXE at entry.
 *
 * (!) These describe the firmware, NOT us. NXC_FWTCG_TCG2 being clear does not mean our software
 * TPM failed; it means the platform offered the boot loader no TPM at all.
 */
#define NXC_FWTCG_PROBED          0x00000001u  /* the DXE ran the probe (else the rest are moot) */
#define NXC_FWTCG_TCG2            0x00000002u  /* EFI_TCG2_PROTOCOL located                      */
#define NXC_FWTCG_TCG12           0x00000004u  /* EFI_TCG_PROTOCOL (1.2) located                 */
#define NXC_FWTCG_FINAL_EVENTS    0x00000008u  /* TCG2 final-events table in the config table    */

/* Status codes the driver reports back through the block. */
#define NXC_STATUS_UNSET        0u   /* mapper zeroed the block and nothing has run yet   */
#define NXC_STATUS_ENTERED      1u   /* DriverEntry reached -- the mapping itself worked   */
#define NXC_STATUS_ABI_MISMATCH 2u   /* driver refused: unknown NEXUS_CORE_BOOT_ABI        */
#define NXC_STATUS_BAD_MAGIC    3u   /* driver refused: block did not carry the magic      */
#define NXC_STATUS_OK           4u   /* all self-checks passed, driver is live             */

/*
 * Per-capability results, so a partial failure is DIAGNOSABLE rather than just "it did not work".
 * Stage 1's whole purpose is proving which parts of the kernel environment the foothold actually
 * gives us -- a single pass/fail bit would tell us nothing about WHERE it broke, and this handoff
 * has no debugger. Mirrors the progressive probing in BlackAlien's testdriver.
 */
#define NXC_CAP_DBGPRINT        0x00000001u  /* DbgPrint / vDbgPrintEx reached             */
#define NXC_CAP_RTL_STRING      0x00000002u  /* RtlInitUnicodeString: Rtl* imports bound   */
#define NXC_CAP_POOL            0x00000004u  /* ExAllocatePool2 + ExFreePoolWithTag        */
#define NXC_CAP_DELAY           0x00000008u  /* KeDelayExecutionThread: we are at PASSIVE  */
#define NXC_CAP_IRQL_PASSIVE    0x00000010u  /* KeGetCurrentIrql() == PASSIVE_LEVEL        */

/*
 * ============================================================================================
 * ABI 5 -- MEASURED PAGE PROTECTIONS. What the hardware actually says, not what we assumed.
 * ============================================================================================
 *
 * Task 7 is "a mapped image is one flat protection, so .text and .data share permissions". Before
 * changing that, we have to know what the permissions ARE, and there was no way to see them: the
 * arena is EfiRuntimeServicesCode, and how Windows maps EFI runtime regions is the firmware's
 * EFI_MEMORY_ATTRIBUTES_TABLE decision, not ours.
 *
 * Two outcomes are possible and they need OPPOSITE work:
 *   - arena is RWX  -> task 7 is real: tighten .text to RX and everything else to NX.
 *   - arena is R-X  -> a LATENT BUG that has never fired, because nothing has written to the arena
 *                      on hardware yet. The arena allocator's first real write would bugcheck, and
 *                      it would present as an unexplained early-boot crash.
 *
 * The second is worse than the problem we set out to fix and is invisible to every check we run
 * today. Hence: measure first, in the same boot, and report both the PTE bits and what the firmware
 * published -- so that if the bits are surprising, the reason is right next to them.
 */
#define NXC_PTE_VALID     0x00000001u  /* the walk completed; without this the rest is meaningless */
#define NXC_PTE_PRESENT   0x00000002u
#define NXC_PTE_WRITABLE  0x00000004u
#define NXC_PTE_EXECUTE   0x00000008u  /* NX bit CLEAR -- stated positively, as it will be read    */
#define NXC_PTE_USER      0x00000010u  /* must be 0 for kernel memory; set would be a real finding */
#define NXC_PTE_LARGE_2M  0x00000020u  /* mapped by a PDE -- 4 KB protection is IMPOSSIBLE here    */
#define NXC_PTE_LARGE_1G  0x00000040u  /* mapped by a PPE -- ditto, worse                          */
#define NXC_PTE_DIRTY     0x00000080u
#define NXC_PTE_GLOBAL    0x00000100u

/*
 * What the FIRMWARE published, read by the DXE from the configuration table.
 *
 * EFI_MEMORY_ATTRIBUTES_TABLE is how modern firmware tells the OS to apply W^X to runtime regions.
 * If it is absent, Windows has nothing to act on and runtime memory tends to stay RWX. If it is
 * present and covers our arena, the attributes in it are the reason for whatever the PTEs show --
 * which turns a surprising measurement into an explained one instead of a new investigation.
 */
#define NXC_MAT_PRESENT        0x00000001u  /* firmware published the table at all       */
#define NXC_MAT_ARENA_COVERED  0x00000002u  /* a descriptor covers our arena             */
#define NXC_MAT_ARENA_RO       0x00000004u  /* ...carrying EFI_MEMORY_RO                 */
#define NXC_MAT_ARENA_XP       0x00000008u  /* ...carrying EFI_MEMORY_XP (no execute)    */
#define NXC_MAT_IMAGE_COVERED  0x00000010u  /* a descriptor covers the image BASE (header page) */
#define NXC_MAT_IMAGE_RO       0x00000020u
#define NXC_MAT_IMAGE_XP       0x00000040u

/*
 * ============================================================================================
 * THE IMAGE'S **CODE** PAGES, classified separately. Added -- and it closes a
 * "fragile assumption" that turned out to be a MISREADING of our own probe.
 * ============================================================================================
 *
 * The flags above classify mImageBase -- the FIRST BYTE of the image, which is the PE HEADER page.
 * They were being reported as if they described the whole image, and the header page comes back
 * EFI_MEMORY_XP. I read that as "firmware marks our image no-execute yet our code runs, so Windows
 * must not enforce the MAT here" and logged it as an assumption we depended on without choosing.
 *
 * I then "corrected" that to: the MAT splits a runtime image so CODE carries EFI_MEMORY_RO and
 * headers/data carry XP, therefore sampling the base page was simply the wrong sample and there was
 * no conflict.
 *
 * ⚠ THAT CORRECTION WAS ALSO WRONG, and these bits are what proved it. measured: the
 * ENTRY POINT's page reports EFI_MEMORY_XP as well. Both samples are XP.
 *
 * The reason the split argument does not apply: it holds for images the FIRMWARE loaded and knows the
 * section layout of. Our image is not one. It is a gBS->AllocatePages(EfiRuntimeServicesCode) block
 * that we wrote a PE into afterwards -- the firmware has no idea there are sections in there, so it
 * covers the whole allocation with one descriptor and marks it XP, which is the conservative and
 * correct thing for it to do.
 *
 * ⚠ SO THE ORIGINAL OBSERVATION STANDS, now with better evidence: the firmware says this memory is
 * no-execute, and our code executes from it. Windows is not applying the MAT attribute to this
 * region. That is a REAL DEPENDENCY, not an artefact -- see the note on EfiMatFlags below.
 *
 * Two lessons, both paid for here: a probe that samples ONE address but is reported under a REGION's
 * name will be read as describing the region; and a tidy explanation that dissolves an anomaly
 * deserves the same suspicion as the anomaly did. I closed this item on the strength of an argument
 * and the measurement reopened it.
 */
#define NXC_MAT_CODE_COVERED   0x00000080u  /* a descriptor covers the image's ENTRY POINT      */
#define NXC_MAT_CODE_RO        0x00000100u
#define NXC_MAT_CODE_XP        0x00000200u

#pragma pack(push, 1)

/**
 * The handoff block. The mapper fills the INPUT half, zeroes the OUTPUT half, then calls
 * DriverEntry. The driver validates, fills the OUTPUT half, and returns.
 *
 * Both halves live in one structure on purpose: it is a single allocation whose address the DXE
 * already knows, so no second pointer has to survive the boundary.
 */
typedef struct _NEXUS_CORE_BOOT_BLOCK
{
	/* ---- INPUT: written by the EFI mapper before DriverEntry is called ---- */

	NXC_U64 Magic;              /* NEXUS_CORE_BOOT_MAGIC; validated FIRST         */
	NXC_U32 Abi;                /* NEXUS_CORE_BOOT_ABI                            */
	NXC_U32 InputSize;          /* sizeof(this struct) as the MAPPER saw it, so a
	                             * size mismatch is caught even when ABI matches   */

	NXC_U64 OriginalEntry;      /* hijacked driver's real entry, for the proxy call.
	                             * RedLotus keeps this at mapper_data[0]; naming it
	                             * is clearer and survives a layout change.        */
	NXC_U64 MappedImageBase;    /* where the mapper put us -- lets the driver log
	                             * its own base without walking anything           */
	NXC_U32 MappedImageSize;
	NXC_U32 BootFlags;          /* reserved; must be 0 in ABI 1                    */

	/* ---- OUTPUT: zeroed by the mapper, written by the driver ---- */

	NXC_U32 Status;             /* one of NXC_STATUS_*                             */
	NXC_U32 Capabilities;       /* bitmask of NXC_CAP_* that actually worked       */
	NXC_U64 EntryTsc;           /* __rdtsc() at entry. Proves THIS boot ran, not a
	                             * stale block from a previous one -- an unchanged
	                             * value across boots is the tell.                 */
	NXC_U32 EntryIrql;          /* IRQL we were called at; drives what is legal    */

	/*
	 * ABI 4. How long DriverEntry took, in microseconds -- measured by the driver itself.
	 *
	 * NOT decoration. Our entry runs on the HIJACKED BOOT DRIVER'S INIT PATH, and a mapped driver's
	 * entry must return promptly (tier-2 research): persistent work belongs on a spawned thread, not
	 * inline. Blocking here stalls boot-driver initialisation and risks PatchGuard attention.
	 *
	 * "Should be fast" is an assumption. This measures it, so a regression that adds work to the boot
	 * path is VISIBLE in `PlatformCtl status` instead of being discovered as a slow or failed boot.
	 * Same principle as every other counter in this block.
	 */
	NXC_U32 EntryDurationUs;

	/* ---- ABI 2: the RUNTIME MAP ARENA. Appended, never inserted. ---- */

	/*
	 * NexusCore's job is mapping FURTHER drivers at runtime, and it cannot use the allocation source
	 * the EFI mapper used for NexusCore itself: EfiRuntimeServicesCode has to be reserved during DXE
	 * entry, and gBS is long gone by the time a runtime map is requested.
	 *
	 * The obvious fallback is ExAllocatePool2 -- which is exactly what we criticised nullmap for
	 * ("can be dumped so easily", plus a pool tag and presence in pool enumeration). So instead the
	 * DXE reserves ONE arena at boot and NexusCore sub-allocates from it.
	 *
	 * THIS IS THE KEY TO STABLE UNMAP/REMAP, which is the requirement v1 failed. Because the arena
	 * never leaves our control:
	 *   - unmap is "mark the extent free", NOT "return pages to the kernel";
	 *   - a stale pointer therefore lands in OUR arena, not in some unrelated allocation the kernel
	 *     has since handed out to someone else -- the difference between reading wrong data and
	 *     corrupting another component;
	 *   - remap reuses the same memory with no allocator churn and nothing new appearing anywhere.
	 *
	 * ⚠ The arena alone does NOT make unmap safe. v1's unmap freed the image with no teardown
	 * contract, no callback unregistration and no grace period (its whole unmap path is 224 lines
	 * calling PeUnloadDriver, with no mention of unregister/rundown/wait anywhere) -- which is why
	 * the system became unstable. The arena removes one failure class; the mandatory teardown
	 * contract removes the bigger one.
	 */
	NXC_U64 ArenaBase;          /* runtime map arena, 0 if the reservation failed  */
	NXC_U32 ArenaSize;          /* bytes reserved                                  */
	NXC_U32 ArenaUsed;          /* bytes currently allocated, maintained by NexusCore */

	/* ---- ABI 3: ntoskrnl location, so the runtime mapper can bind imports ---- */

	/*
	 * NexusCore maps FURTHER drivers at runtime and must resolve their imports against ntoskrnl --
	 * which means knowing where ntoskrnl is. The DXE already has both values in its winload hook
	 * (KernelEntry->DllBase / SizeOfImage), so handing them over costs nothing.
	 *
	 * The alternative was deriving the base from one of our own resolved IAT entries by masking to a
	 * page and scanning backwards for "MZ". That works, but it is a guess dressed as a computation:
	 * unbounded backwards scanning through kernel memory, and no way to tell a real header from a
	 * coincidental byte pair without more validation than the honest approach needs. Passing the
	 * value we already possess is strictly better.
	 */
	NXC_U64 KernelBase;         /* ntoskrnl.exe image base, 0 if unknown           */
	NXC_U32 KernelSize;         /* its SizeOfImage, for bounds-checking resolutions */

	/*
	 * RVA of g_PgContext within ntoskrnl, as the DXE's semantic locator found it. 0 = not
	 * located (or the DXE predates ABI 20).
	 *
	 * WHY THIS IS HERE: this is the deterministic answer to "is PatchGuard
	 * defused", and it costs nothing -- the DXE already computes it. The defusal repoints
	 * g_PgContext at the DISCARDED INIT section, so reading that pointer and asking which
	 * section it lands in settles the question outright, where the big-pool scanner only ever
	 * offers an absence. MEASURED both ways: PatchGuard alive -> pool, at its
	 * decryption stub; defused -> exactly ntoskrnl + INIT's VirtualAddress.
	 *
	 * (!) IT MUST BE PUBLISHED ON A CONTROL BOOT TOO. The locator runs even when the defusal is
	 * skipped, precisely so `pgdefuse verify` works on the boot you most want to verify. A field
	 * only populated on the boots that need no checking would be useless.
	 *
	 * The RVA changes with every kernel build, which is exactly why it is published rather than
	 * written down -- see what happened to the pgscan signatures.
	 *
	 * Takes Reserved1's slot: same type, same offset 92, so the LAYOUT is unchanged and the
	 * assert below is untouched. Only the meaning is new, which is what the ABI bump records.
	 */
	NXC_U32 PgContextRva;

	/* ---- ABI 5: measured protections. See the NXC_PTE_/NXC_MAT_ block above for why. ---- */

	/*
	 * The page-table self-map base the driver PROVED this boot (0 = it refused to guess).
	 *
	 * Reported rather than kept private because it is the one value everything else here depends
	 * on: if it is 0, the two flag words below are meaningless, and that distinction has to be
	 * visible in the output. "Flags are zero" and "we could not look" are different facts and this
	 * project has already lost time to a report that conflated them.
	 */
	NXC_U64 PteSelfMapBase;

	NXC_U32 ImagePteFlags;      /* NXC_PTE_* for MappedImageBase                    */
	NXC_U32 ArenaPteFlags;      /* NXC_PTE_* for ArenaBase                          */

	/*
	 * NXC_MAT_* -- written by the MAPPER, at boot, from the firmware configuration table. Kept
	 * beside the measured bits on purpose: the PTE flags are the symptom, this is the cause.
	 */
	NXC_U32 EfiMatFlags;

	/*
	 * Result of applying each section's own characteristics to the pages backing it.
	 *
	 * BOTH counts are carried, not just a success flag, because "3 applied, 3 refused" is a real and
	 * likely outcome -- a section on a large page is skipped rather than aborting the image -- and it
	 * means half the image is still RWX. A boolean would render that as success.
	 */
	NXC_U32 ProtectApplied;
	NXC_U32 ProtectRefused;

	/*
	 * ABI 6. Why the self-map probe ended the way it did. Low 16 bits: candidate indices whose
	 * computed self-entry address was READABLE. High 16 bits: of those, how many held a PRESENT
	 * entry.
	 *
	 * Added after the first boot reported "NOT DERIVED" and nothing else. The cause was a one-bit
	 * error in the page-index mask, and this single number would have named it immediately:
	 *
	 *   readable = 0    -> the ADDRESS MATH is wrong (or nothing is mapped there). What actually
	 *                      happened: a 35-bit mask instead of 36 sent every probe somewhere useless.
	 *   readable > 0,
	 *   present  > 0,
	 *   no match       -> the addresses are sane but the CR3 IDENTITY does not hold, which would
	 *                      mean the self-map assumption itself is wrong on this machine.
	 *
	 * Those two need completely different investigations, and without this they are the same output.
	 * The driver has no debugger and DbgPrint goes nowhere anyone can see -- this block is the ONLY
	 * channel, so a failure that costs a reboot to observe must carry its own discriminator.
	 */
	NXC_U32 PteProbeDiag;

	/*
	 * ABI 7 -- THE COMMAND ENTRY POINT. Written by the DRIVER during DriverEntry, called by the DXE's
	 * SetVariable hook. Kernel VA of `NTSTATUS NxcCommandHandler(void* Command)`; 0 until NexusCore
	 * has run.
	 *
	 * WHY THROUGH THE BLOCK rather than a second exported symbol like NexusCoreBootSlot: the DXE
	 * already holds this pointer and already writes into it, so routing costs no new export
	 * resolution and no second RVA to keep straight. It also FAILS CLOSED for free -- the DXE
	 * allocates the block zeroed, so before NexusCore runs this is 0 and the hook has nothing to
	 * call. A separate export would have to be resolved and then separately proven non-stale.
	 *
	 * ⚠ THE DXE MUST CHECK IT IS NON-ZERO AND MUST GATE ON CR8 == 0 BEFORE CALLING. The handler
	 * copies a usermode buffer with MmCopyVirtualMemory, which requires PASSIVE_LEVEL, and it runs in
	 * the calling thread's process context -- which is exactly what makes the caller's pointer
	 * readable at all. Calling it from an arbitrary IRQL is a bugcheck, not a degraded result.
	 */
	NXC_U64 CommandHandler;

	/*
	 * ============================================================================================
	 * ABI 8 -- MEASURE THE ENTRY COST PROPERLY. EntryDurationUs was not a measurement.
	 * ============================================================================================
	 *
	 * EntryDurationUs is a raw TSC delta divided by a hardcoded 3000, i.e. "assume 3 GHz". Across five
	 * boots doing near-identical work it read 1817, 2427, 10964, 2084 and 13080 -- two clusters about
	 * 6x apart. That is not scatter, and a field added to catch regressions that swings 6x on its own
	 * cannot catch anything.
	 *
	 * ⚠ THE TSC CANNOT ANSWER THIS BY ITSELF, which is the whole reason these fields exist. An
	 * invariant TSC ticks at a FIXED rate regardless of core frequency, so it measures TIME, not
	 * cycles. Identical work on a slower core therefore spans MORE TSC ticks. "The work grew" and
	 * "the clock dropped" produce the identical symptom, and no amount of TSC sampling separates them.
	 *
	 * So:
	 *   QpcFrequency + EntryQpcTicks -- KeQueryPerformanceCounter has a KNOWN frequency, so this is
	 *     the real elapsed time with no assumed constant anywhere. It replaces the 3 GHz fiction.
	 *   AperfMperfPct -- IA32_APERF / IA32_MPERF over the entry, as a percentage. MPERF advances at
	 *     the fixed TSC rate; APERF advances proportional to ACTUAL core frequency. Their ratio IS the
	 *     average core-frequency ratio for the interval, which is exactly the missing variable. ~100
	 *     means the core ran at base; ~20 means it ran at a fifth of base and identical work would
	 *     take 5x the wall time. 0 means the CPU does not advertise the capability and we did not read
	 *     the MSRs (see the CPUID gate in NexusCore.c -- a #GP here would be a bugcheck, no SEH).
	 *   ArenaNxTsc -- raw TSC delta for the whole-arena NX pass alone, the largest single cost and the
	 *     prime suspect. Reported raw, not converted, so it can be compared against EntryTsc-derived
	 *     totals without a second conversion introducing a second assumption.
	 */
	NXC_U64 QpcFrequency;
	NXC_U64 EntryQpcTicks;
	NXC_U32 AperfMperfPct;
	NXC_U32 ArenaNxTsc;

	/*
	 * ============================================================================================
	 * ABI 9 -- PER-PHASE COST, so ONE slow boot localises the swing instead of merely showing it.
	 * ============================================================================================
	 *
	 * ABI 8 timed the arena NX pass alone, on the theory that the largest CPU cost was the likely
	 * source of the 6x variance. TWO BOOTS DISPROVED THAT: the NX pass measured 1414840 and 1404342
	 * TSC ticks -- 0.75% apart -- while total entry moved 2797 -> 2083 us. Real CPU work is stable.
	 *
	 * That also kills the core-frequency explanation I offered earlier. If the clock had dropped ~6x,
	 * the NX pass would have grown ~6x with it; it does not move at all, and APERF/MPERF reads 137-144%
	 * (turbo) on the fast boots. Whatever varies is NOT CPU work.
	 *
	 * ⚠ THE LIKELY CULPRIT IS A BLOCKING WAIT, and there is exactly one: NxcProbeCapabilities calls
	 * KeDelayExecutionThread with a relative 1 ms delay to prove the thread can block. A RELATIVE delay
	 * expires on the next system clock tick, and Windows' default interval is ~15.6 ms -- so that call
	 * can take anywhere from ~1 ms to ~15.6 ms depending purely on where in the tick period it lands.
	 * That is precisely the magnitude and the unpredictability observed (fast ~2 ms, slow ~11-13 ms).
	 *
	 * These four fields test it directly rather than arguing it. If CapsProbeTsc carries the difference
	 * on a slow boot, the entry cost is a timer artefact and the probe's 1 ms sleep is the whole story
	 * -- at which point the real question becomes whether a diagnostic that can cost 15 ms belongs on
	 * the boot-driver init path at all.
	 *
	 * Raw TSC ticks, deliberately. PlatformCtl already derives the true TSC rate from QPC, so storing
	 * converted microseconds here would bake in a second conversion and a second chance to be wrong --
	 * which is exactly how the NX pass came to be reported as 141 ms.
	 */
	/*
	 * ============================================================================================
	 * ABI 10 -- WHY THE DXE GAVE UP. Source line of the first boot-phase refusal, 0 if none.
	 * ============================================================================================
	 *
	 * The phase trail says WHICH phase did not happen. It cannot say why, and for the winload patch
	 * there are four distinct refusals that all present identically as "[ ] winload patched":
	 * the version could not be read, the build is below the supported floor, .text was not found, or
	 * the OslFwpKernelSetupPhase1 signature did not match. Those have completely different responses
	 * -- one is a Windows update, one is a corrupt image, one is a signature that needs re-deriving.
	 *
	 * Every one of them currently reports by Print() during boot, which scrolls away. After the fact
	 * there is nothing. That is precisely the hole that left the arming failure
	 * undiagnosed: the trail would have shown the gap and stopped there.
	 *
	 * __LINE__ rather than an enum, for the same reasons it works in MapModule: nothing to keep in
	 * sync, it cannot drift from the check it describes, and it names the exact test. Read against the
	 * build that produced it; never stored.
	 */
	NXC_U32 DxeRefusalLine;

	/*
	 * ============================================================================================
	 * ABI 11 -- WHICH BUILD IS ACTUALLY RUNNING. First 8 bytes of the payload's SHA-256.
	 * ============================================================================================
	 *
	 * "Did my deploy take?" has been answered by INFERENCE all session -- watch for a behaviour
	 * change, conclude the new DXE must be live. That is a guess every time, and it is wrong in
	 * exactly the case that matters: when the deploy did NOT take.
	 *
	 * The Loader searches six paths and falls back SILENTLY. If the primary
	 * (EFI/OEM/PlatformRuntimeDxe.efi) is missing -- copied to the wrong place, ESP not mounted, a
	 * typo -- it quietly loads the legacy EFI/OEM/NexusBootDxe.efi instead, which may be months old.
	 * Those fallbacks are deliberate and correct, because a half-migrated ESP must still boot. But
	 * they mean "it booted" proves nothing about WHICH DXE booted.
	 *
	 * A stale DXE with an older boot-block ABI is caught loudly by the driver's ABI check. A stale
	 * DXE with the SAME ABI is not caught at all: it simply behaves like an older build, and every
	 * conclusion drawn from that boot is quietly about the wrong binary.
	 *
	 * The SHA is already computed in NexusCoreReserve to verify the payload, so this costs a copy. It
	 * identifies the embedded NexusCore exactly, and therefore the DXE that embeds it -- compare it
	 * against the sha256 that tools/embed_driver.py prints at build time.
	 */
	NXC_U64 PayloadIdent;

/*
 * ⚠ PACKED (FileId << 16) | Line, NOT a bare line number.
 *
 * The first cut stored __LINE__ alone and PlatformCtl printed it as "PatchWinload.c:NNN" -- correct
 * only because winload was the one instrumented file. The moment PatchBootmgr or PatchNtoskrnl gains
 * a refusal site, a bare line is ambiguous across three files with overlapping line ranges, and the
 * label becomes a confident lie about which check fired.
 *
 * Caught on deploying ABI 10, before instrumenting the second file. Line numbers fit in 16 bits with
 * room to spare (no file here is close to 65535 lines), so the id costs nothing and makes the value
 * self-describing rather than dependent on there being exactly one source.
 */
#define NXC_DXE_FILE_WINLOAD    1u
#define NXC_DXE_FILE_BOOTMGR    2u
#define NXC_DXE_FILE_NTOSKRNL   3u
#define NXC_DXE_FILE_MAPCORE    4u
#define NXC_DXE_FILE_LOADER     5u

#define NXC_DXE_REFUSAL(FileId, Line)  (((NXC_U32)(FileId) << 16) | ((NXC_U32)(Line) & 0xFFFFu))
#define NXC_DXE_REFUSAL_FILE(Packed)   ((Packed) >> 16)
#define NXC_DXE_REFUSAL_LINE(Packed)   ((Packed) & 0xFFFFu)

	NXC_U32 CapsProbeTsc;      /* NxcProbeCapabilities, INCLUDING the 1 ms KeDelayExecutionThread */
	NXC_U32 ArenaInitTsc;      /* NxcArenaInit + NxcMapInit                                       */
	NXC_U32 PteInitTsc;        /* self-map derivation: up to 256 candidate probes                 */
	NXC_U32 ImageProtectTsc;   /* per-section + header protections on our own image               */

	/*
	 * ABI 12 -- WHY the kernel patch failed. Same packed encoding as DxeRefusalLine, and a SEPARATE
	 * SLOT ON PURPOSE.
	 *
	 * ⚠ DO NOT MERGE THIS INTO DxeRefusalLine. That field is first-writer-wins (see
	 * NexusCoreSetRefusalLine), and PatchNtoskrnl runs BEFORE phase-2 bind. Its failures are
	 * non-fatal by design -- bind proceeds regardless, because our manual map does not depend on the
	 * kernel patch. So routing them into the shared slot would let an ADVISORY failure permanently
	 * occupy it and hide the BIND failure that actually stopped NexusCore from loading. The scarce
	 * single slot belongs to failures that STOP things.
	 *
	 * That is not hypothetical tidiness: instrumenting PatchNtoskrnl into the shared field was the
	 * obvious way to finish the refusal-line work, and it would have quietly broken the diagnostic
	 * that took two commits to build.
	 *
	 * Worth the ABI bump because signature rot is the realistic failure here: PatchGuard/DSE patterns
	 * are matched against a kernel Microsoft updates monthly, and "which pattern stopped matching"
	 * is the whole question after an update. The flag says it broke; this says where.
	 */
	NXC_U32 KernelPatchLine;

	/*
	 * ============================================================================================
	 * ABI 13 -- MEASURED PLATFORM PROTECTION STATE. The load-bearing assumption, made visible.
	 * ============================================================================================
	 *
	 * Everything this framework does rests on VBS/HVCI being OFF. With them on: HVCI enforces W^X
	 * through SLAT so manual-mapping executable code is blocked, kernel code pages become
	 * RO-and-validated so the PatchGuard patches die, HyperGuard checks integrity from VTL1 where
	 * VTL0 cannot reach it, and Hyper-V owns VMX root so SentinelHV cannot launch at all.
	 *
	 * That assumption was verified ONCE, by hand, from usermode. Microsoft is actively pushing
	 * VBS-on-by-default, so a Windows update or a Core Isolation toggle could flip it silently --
	 * and the failure would present as an inexplicable bugcheck or a mapper that stopped working,
	 * with nothing pointing at the cause. Recorded per boot so the answer is READ, not rediscovered.
	 *
	 * ⚠ MEASURED FROM HARDWARE, NOT ASKED OF WINDOWS. CR4 and CPUID are architectural state the OS
	 * cannot misreport to us; WMI/registry answers are just data structures a compromised or
	 * instrumented system can edit. For a framework built to inspect hostile code, asking the
	 * potentially-compromised system whether it is protected is the wrong oracle -- the same
	 * disagreeing-oracle lesson.
	 */

	/* Windows kernel build, captured by the DXE from ntoskrnl's version resource (0 if unread).
	 * PatchGuard/DSE signatures are matched against THIS build; when it moves, expect rot. */
	NXC_U32 KernelBuild;

	/*
	 * CR4 as the driver observed it at DriverEntry. One register answers several questions:
	 *   bit 13 VMXE  -- VMX is enabled: SOMETHING owns VMX root (Hyper-V, or our own SentinelHV)
	 *   bit 20 SMEP  -- kernel cannot execute user pages
	 *   bit 21 SMAP  -- kernel cannot read user pages without STAC
	 *   bit 23 CET   -- shadow stacks active; this is what makes a WP-disable window unsafe and
	 *                   already cost one cold-boot 0xEF
	 */
	NXC_U64 EntryCr4;

	/*
	 * CPUID leaf 0x40000000 vendor string, or all-zero when CPUID.01H:ECX[31] says no hypervisor.
	 *
	 * NOT NUL-terminated and deliberately not treated as a C string -- it is 12 raw bytes from
	 * EBX/ECX/EDX. "Microsoft Hv" means Hyper-V is running, which on this machine would mean VBS
	 * came back on. A DIFFERENT non-empty vendor means our own hypervisor is live, so this field
	 * usefully answers "is SentinelHV up" with the same bytes.
	 */
	NXC_U8  HvVendor[12];

	/*
	 * ABI 14 -- the kernel's UBR / revision (the ".8894" in 10.0.26100.8894).
	 *
	 * ⚠ THIS IS THE NUMBER THAT ACTUALLY TRACKS SIGNATURE ROT, and ABI 13 shipped without it.
	 * KernelBuild alone said "when it moves, expect rot" -- a promise it cannot keep, because the
	 * BUILD is stable for years while the REVISION changes every Patch Tuesday and rewrites the very
	 * bytes DisablePatchGuard scans for.
	 *
	 * Measured here: ntoskrnl.exe is 10.0.26100.8894 while Windows reports itself as build
	 * 26200 / "25H2". 25H2 is an enablement package over 24H2's branch, so the OS LABEL and the KERNEL
	 * BINARY version genuinely differ -- watching "25H2" tells you nothing about the bytes we patch.
	 * The pair (KernelBuild, KernelRevision) is the real identity of what the signatures were aimed at.
	 *
	 * Kept as its own field rather than packed into KernelBuild's spare 16 bits: ABI 13 is already
	 * deployed with a defined meaning, and silently re-interpreting a live field is the overloading
	 * mistake that made a module refusal read as a command collision earlier the same day.
	 */
	NXC_U32 KernelRevision;

	/*
	 * ABI 15 -- the DXE's OWN PE TimeDateStamp. WHICH PlatformRuntimeDxe.efi is running.
	 *
	 * ⚠ PayloadIdent DOES NOT ANSWER THIS, and I claimed it did. It is the SHA-256 prefix of the
	 * embedded NexusCore.sys, so it identifies the DRIVER. I described it as identifying "the DXE
	 * that embeds it" -- true only when the payload also changed. Proven wrong by the DSE
	 * removal: a DXE-only change left NexusCore.sys byte-identical, the ident read the same before and
	 * after, and "did my deploy take" became unanswerable again for exactly the class of change where
	 * nothing else is visible either.
	 *
	 * TimeDateStamp rather than a hash of the file: an image cannot contain its own hash, and the DXE
	 * can read this from its own headers at runtime with no build-step cooperation. Under /Brepro the
	 * linker writes a content hash here instead of a clock value, which is strictly better for this
	 * purpose -- either way it changes when the binary changes.
	 *
	 * Compare against the deployed file with:
	 *     tools/pe_timestamp.py <path-to-PlatformRuntimeDxe.efi>
	 */
	NXC_U32 DxeIdent;

	/*
	 * ============================================================================================
	 * ABI 16 -- THE PTEs AS WINDOWS HANDED THEM OVER, BEFORE WE TOUCHED ANYTHING (I-04)
	 * ============================================================================================
	 *
	 * These answer ONE question that nothing else in this block can: DOES WINDOWS ENFORCE THE
	 * FIRMWARE'S MEMORY ATTRIBUTES TABLE?
	 *
	 * The MAT marks our image pages EFI_MEMORY_XP -- measured, both the header page and the ENTRY
	 * page, every boot. We execute from the entry page anyway, so Windows is not applying it. That
	 * is a DEPENDENCY, not a choice: our first instruction runs from the EFI runtime mapping Windows
	 * builds at SetVirtualAddressMap, and if a future Windows honoured the XP attribute the call
	 * would fault before DriverEntry could fix a single PTE.
	 *
	 * ⚠⚠ AND THE MEASUREMENT ALREADY EXISTED AND WAS BEING THROWN AWAY. NexusCore.c queried the
	 * image PTE into ImagePteFlags before any protection ran -- exactly this value -- and then
	 * OVERWROTE the same field after NxcPteProtectImage, so what survived described OUR OWN
	 * protection work. The field's own comment had been rewritten to say so. One name, two meanings,
	 * and the meaning that mattered was the one that got lost.
	 *
	 * ⚠ WHY THE ENTRY PAGE SEPARATELY: the header page and the code page are different sections in
	 * different MAT descriptors, and we later protect them differently (header R--, code R-X). Only
	 * the ENTRY page has to be executable for the boot to survive, so only it is the real dependency.
	 * Taken from the address of DriverEntry itself rather than a computed RVA -- the function that
	 * must be callable is the least ambiguous way to name the page that must be executable.
	 *
	 * TRIPWIRE: today every one of these reads EXECUTE with the MAT asking XP -- Windows ignoring the
	 * table. If any of them is ever seen WITHOUT NXC_PTE_EXECUTE while the MAT asks XP, Windows has
	 * begun enforcing, and the next Windows that enforces it on the ENTRY page stops this machine
	 * booting with our DXE installed. That is a warning we can only receive while still alive, which
	 * is why it is measured on the inherited state rather than inferred from the fact we are running.
	 */
	NXC_U32 InheritedImagePte;   /* NXC_PTE_* at MappedImageBase, BEFORE NxcPteProtectImage */
	NXC_U32 InheritedArenaPte;   /* NXC_PTE_* at ArenaBase,       BEFORE the arena NX pass  */
	NXC_U32 InheritedEntryPte;   /* NXC_PTE_* at &DriverEntry -- the page that MUST execute */
	NXC_U32 InheritedPteValid;   /* bit 0/1/2 set if the matching query above SUCCEEDED     */

	/*
	 * ============================================================================================
	 * ABI 17 -- THE SOFTWARE-TPM REGIONS. Where they are, and which boot they belong to.
	 * ============================================================================================
	 *
	 * The DXE allocates two EfiACPIMemoryNVS regions at boot (the design notes 3.3):
	 * region A is the RAM CRB transport that the ACPI TPM2 table advertises, region B is the
	 * canonical TPM state that is deliberately NOT ACPI-described. Ring 0 has to be able to find
	 * both, and until now it could not: nothing carried the addresses across ExitBootServices.
	 *
	 * (!) THIS IS NOT ONLY FOR DIAGNOSTICS. It is what unblocked Phase 1.6.
	 *
	 * `readphys` refuses region A -- correctly, by its own rule -- because Windows does not report
	 * EfiACPIMemoryNVS as system RAM, so the region falls in a hole of MmGetPhysicalMemoryRanges.
	 * The guard exists so a stray read cannot touch device MMIO and change device state or hang the
	 * bus. NVS is ordinary DRAM the DXE allocated itself and carries neither risk, but the guard
	 * cannot tell the difference from the RAM map alone.
	 *
	 * Publishing the extents here lets the guard admit EXACTLY these two regions and nothing else.
	 * That is a whitelist of memory we allocated, not a relaxation of the rule -- see PhysMem.c.
	 *
	 * (!) THE EPOCH IS THE POINT, NOT DECORATION. The physical addresses are valid ONLY for the
	 * boot epoch that allocated them. After S4, Fast Startup, or any firmware reinitialisation the
	 * DXE runs again and allocates FRESH regions -- while a resumed kernel may still hold an
	 * address from the previous epoch. The hazard is a stale pointer that still looks valid: it may
	 * point at perfectly readable memory that is now something else entirely.
	 *
	 * So anything that caches one of these addresses MUST re-read TpmBootEpoch and rediscover on a
	 * mismatch. Never trust an address recovered from saved driver state.
	 *
	 * Zero means the DXE did not allocate that region this boot -- transport init is non-fatal by
	 * design, so zero is a legitimate state and not an error to be papered over. TpmBootEpoch is
	 * likewise 0 when nothing was allocated; 0 is reserved as never-valid.
	 */
	NXC_U64 TpmTransportBase;    /* region A: CRB LOCALITY base. The ACPI table publishes
	                              * this + 0x40 (the control area), NOT this address.        */
	NXC_U64 TpmStateBase;        /* region B: canonical state, not ACPI-described             */
	NXC_U64 TpmBootEpoch;        /* fresh per boot; 0 is never valid. See above.              */
	NXC_U32 TpmTransportSize;    /* bytes; 0 if region A was not allocated                    */
	NXC_U32 TpmStateSize;        /* bytes; 0 if region B was not allocated                    */

	/*
	 * ============================================================================================
	 * ABI 18 -- WHAT THE FIRMWARE ITSELF PUBLISHES ABOUT TPM.
	 * ============================================================================================
	 *
	 * The DXE already probed for EFI_TCG2_PROTOCOL, the 1.2 EFI_TCG_PROTOCOL and the TCG2
	 * final-events table -- and printed the answer to the BOOT SCREEN, where nothing on the OS
	 * side can read it. That made a result the whole phase ordering depends on reachable only by
	 * photographing a monitor.
	 *
	 * (!) IT MATTERS BECAUSE IT IS UPSTREAM OF EVERYTHING WE HAVE BEEN ADJUSTING. The ACPI TPM2
	 * table and the CRB describe a device to the OS; TCG2 is how FIRMWARE offers a TPM to the BOOT
	 * LOADER. Windows has produced no MeasuredBoot log since Intel PTT was disabled, and those logs
	 * are written by the loader -- so if TCG2 is absent, the loader had nothing to measure into and
	 * no amount of CRB correctness would change that.
	 *
	 * (!) PROBED is a SEPARATE BIT from the three results, deliberately. Without it, a zeroed field
	 * from a DXE that predates ABI 18 is indistinguishable from "probed, found nothing" -- which is
	 * exactly the false-negative shape that made an unvalidated instrument look like a passing test
	 * earlier in this phase.
	 */
	NXC_U32 TpmFirmwareTcg;      /* NXC_FWTCG_* bits; 0 means the DXE never probed             */

	/*
	 * ============================================================================================
	 * ABI 19 -- THE TCG2 EVENT LOG EXTENT, so the log can be read AFTER Windows has booted.
	 * ============================================================================================
	 *
	 * (!) THIS EXISTS BECAUSE THE TWO OBVIOUS INDICATORS CANNOT ANSWER THE QUESTION. Whether the
	 * boot loader actually measured through our EFI_TCG2_PROTOCOL was to be judged by TpmPresent
	 * and the MeasuredBoot log -- and BOTH of those sit downstream of G1. tpm.sys reports no TPM
	 * because nothing services the CRB after ExitBootServices, which is true whether the loader
	 * measured perfectly or never called us at all. Neither indicator can separate the two.
	 *
	 * The log itself CAN. At DXE exit it holds exactly one entry -- the Spec ID header event we
	 * write ourselves. Every entry beyond that was added by a HashLogExtendEvent call from
	 * someone else, and the only someone else before ExitBootServices is the boot loader. So:
	 *
	 *     Count == 1   the loader never called us -- TCG2 alone is NOT sufficient
	 *     Count >  1   the loader measured through us, and the entries name what it measured
	 *
	 * That is a direct observation of the thing in question rather than an inference from two
	 * confounded downstream signals, and it costs one whitelisted physical read.
	 *
	 * (!) The log is EfiACPIMemoryNVS, so it survives ExitBootServices and is still there to be
	 * read from the OS. Zero means TCG2 was not installed this boot -- either the firmware already
	 * published it and we stood down, or allocation failed. Both are legitimate states.
	 *
	 * (!) SUBJECT TO THE SAME EPOCH RULE as the transport regions above: re-read TpmBootEpoch and
	 * rediscover on a mismatch. An address cached across S4 or Fast Startup may point at memory
	 * that is now something else.
	 */
	NXC_U32 TpmEventLogSize;     /* bytes; 0 if TCG2 was not installed this boot               */
	NXC_U64 TpmEventLogBase;     /* TCG2 crypto-agile event log, EfiACPIMemoryNVS              */
} NEXUS_CORE_BOOT_BLOCK;

#pragma pack(pop)

/*
 * Compile-time layout lock, enforced on BOTH sides from this one header.
 *
 * The C_ASSERT-on-every-offset habit exists because a trap-structure offset bug has bitten this
 * project before and cost real debugging; the standing rule is to assert them rather than trust
 * that two independently-compiled views agree. A negative-array-size assert is used instead of
 * static_assert / C_ASSERT so this works under the UEFI toolchain, the WDK, and a host compiler
 * without depending on any of their headers.
 */
/*
 * Size of the status report served by the hooked GetVariable: the boot block, then two UINT32
 * launch counters (calls-while-armed, CR8-gate rejections). Read by tools/nexuscore_status.py.
 *
 * The counters are appended rather than folded into the block because the block is written by the
 * DRIVER and the counters are owned by the MAPPER -- keeping them separate means neither can
 * clobber the other, and a driver that never ran still yields truthful counters.
 *
 * ABI 7 APPENDS THE LAST ANSWERED COMMAND after the counters, so one read returns both the boot
 * status and the outcome of the last `map`. That is not a convenience -- it is the ONLY way a result
 * gets back to usermode. SetVariable is write-only by contract: Windows captures the caller's buffer
 * into kernel memory before the firmware call, and nothing copies it back, so a handler that answers
 * "in place" answers into a kernel copy the caller never sees again. The existing backdoor appears to
 * read values back through that buffer and this deliberately does NOT depend on the same behaviour.
 * Commands go out over SetVariable; results come back over GetVariable.
 */
#define NXC_STATUS_REPORT_SIZE  (sizeof(NEXUS_CORE_BOOT_BLOCK) + 8u + sizeof(NEXUS_COMMAND))

#define NXC_OFFSETOF(type, field)     ((NXC_U64)(NXC_U64*)&(((type*)0)->field))
#define NXC_ASSERT_LAYOUT(name, expr) typedef char nxc_assert_##name[(expr) ? 1 : -1]

NXC_ASSERT_LAYOUT(block_size, sizeof(NEXUS_CORE_BOOT_BLOCK) == 288); /* ... 240@16 272@17 276@18 288@19 */
NXC_ASSERT_LAYOUT(off_cmdhandler, NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, CommandHandler) == 128);
NXC_ASSERT_LAYOUT(off_qpcfreq,    NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, QpcFrequency)   == 136);
NXC_ASSERT_LAYOUT(off_qpcticks,   NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, EntryQpcTicks)  == 144);
NXC_ASSERT_LAYOUT(off_aperf,      NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, AperfMperfPct)  == 152);
NXC_ASSERT_LAYOUT(off_arenanx,    NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, ArenaNxTsc)     == 156);
NXC_ASSERT_LAYOUT(off_dxerefuse,  NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, DxeRefusalLine)  == 160);
NXC_ASSERT_LAYOUT(off_ident,      NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, PayloadIdent)    == 164);
NXC_ASSERT_LAYOUT(off_kpline,     NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, KernelPatchLine) == 188);
/* ABI 13 -- measured protection state. */
NXC_ASSERT_LAYOUT(off_kbuild,     NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, KernelBuild)     == 192);
NXC_ASSERT_LAYOUT(off_cr4,        NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, EntryCr4)        == 196);
NXC_ASSERT_LAYOUT(off_hvvendor,   NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, HvVendor)        == 204);
NXC_ASSERT_LAYOUT(off_krev,       NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, KernelRevision)  == 216);
NXC_ASSERT_LAYOUT(off_dxeident,   NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, DxeIdent)        == 220);
/* ABI 17 -- the software-TPM regions. Ordered for natural alignment: the three UINT64s first,
 * then the two UINT32s, so no padding is introduced and the offsets below are exact. */
NXC_ASSERT_LAYOUT(off_tpmxport,   NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, TpmTransportBase) == 240);
NXC_ASSERT_LAYOUT(off_tpmstate,   NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, TpmStateBase)     == 248);
NXC_ASSERT_LAYOUT(off_tpmepoch,   NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, TpmBootEpoch)     == 256);
NXC_ASSERT_LAYOUT(off_tpmxsize,   NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, TpmTransportSize) == 264);
NXC_ASSERT_LAYOUT(off_tpmssize,   NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, TpmStateSize)     == 268);
NXC_ASSERT_LAYOUT(off_fwtcg,      NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, TpmFirmwareTcg)  == 272);
/* ABI 19 -- the TCG2 event log extent. Ordered size-then-base so both land naturally aligned
 * inside a pack(1) struct: 276 % 4 == 0 for the UINT32, 280 % 8 == 0 for the UINT64. */
NXC_ASSERT_LAYOUT(off_evlogsz,    NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, TpmEventLogSize) == 276);
NXC_ASSERT_LAYOUT(off_evlogbase,  NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, TpmEventLogBase) == 280);
NXC_ASSERT_LAYOUT(off_caps_t,     NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, CapsProbeTsc)    == 172);
NXC_ASSERT_LAYOUT(off_arenainit_t,NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, ArenaInitTsc)    == 176);
NXC_ASSERT_LAYOUT(off_pteinit_t,  NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, PteInitTsc)      == 180);
NXC_ASSERT_LAYOUT(off_imgprot_t,  NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, ImageProtectTsc) == 184);
/* Moves whenever the block OR NEXUS_COMMAND grows -- which is the point: the assert forces the
 * number to be re-derived rather than silently drifting from the sum above. 400 -> 416 at ABI 16,
 * the block gaining four UINT32s for the inherited PTEs (I-04); 416 -> 448 at ABI 17, the block
 * gaining three UINT64s and two UINT32s for the software-TPM regions; 452 -> 464 at ABI 19,
 * the block gaining the TCG2 event log base and size. */
NXC_ASSERT_LAYOUT(report_size,    NXC_STATUS_REPORT_SIZE == 464);

/*
 * Offsets asserted individually rather than only sizeof(): a pair of fields swapped, or one
 * widened while another narrows, keeps the total size identical and breaks the protocol silently.
 * sizeof() alone would pass. That is the same shape as the digest-preimage bug -- an aggregate
 * check that cannot see a compensating error inside it.
 */
NXC_ASSERT_LAYOUT(off_magic,      NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, Magic)            ==  0);
NXC_ASSERT_LAYOUT(off_abi,        NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, Abi)              ==  8);
NXC_ASSERT_LAYOUT(off_inputsize,  NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, InputSize)        == 12);
NXC_ASSERT_LAYOUT(off_origentry,  NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, OriginalEntry)    == 16);
NXC_ASSERT_LAYOUT(off_imagebase,  NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, MappedImageBase)  == 24);
NXC_ASSERT_LAYOUT(off_imagesize,  NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, MappedImageSize)  == 32);
NXC_ASSERT_LAYOUT(off_bootflags,  NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, BootFlags)        == 36);
NXC_ASSERT_LAYOUT(off_status,     NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, Status)           == 40);
NXC_ASSERT_LAYOUT(off_caps,       NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, Capabilities)     == 44);
NXC_ASSERT_LAYOUT(off_tsc,        NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, EntryTsc)         == 48);
NXC_ASSERT_LAYOUT(off_irql,       NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, EntryIrql)        == 56);
/*
 * (review) These two were the only fields in the block with no offset assert -- found by
 * recomputing every offset from the declared field widths and diffing against the assert list.
 *
 * Not a live hole: with 35 of 37 fields pinned AND sizeof asserted, an insertion anywhere already
 * broke SOME assert, and the recomputation agreed with all 35. Added so the invariant is uniform and
 * checkable by inspection -- "every field is pinned" is a property you can verify at a glance,
 * whereas "every field except two, which are covered transitively by their neighbours" is a fact
 * that has to be re-derived by whoever next appends a field.
 */
NXC_ASSERT_LAYOUT(off_entryus,    NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, EntryDurationUs)  == 60);
/* ABI 2 additions -- asserted individually for the same reason as everything above. */
NXC_ASSERT_LAYOUT(off_arenabase,  NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, ArenaBase)        == 64);
NXC_ASSERT_LAYOUT(off_arenasize,  NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, ArenaSize)        == 72);
NXC_ASSERT_LAYOUT(off_arenaused,  NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, ArenaUsed)        == 76);
/* ABI 3 additions. */
NXC_ASSERT_LAYOUT(off_kbase,      NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, KernelBase)       == 80);
NXC_ASSERT_LAYOUT(off_ksize,      NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, KernelSize)       == 88);
/* Explicit padding, but pinned like everything else: it is the natural place a future field gets
 * "reused" into, and that reuse must be a deliberate ABI decision rather than a silent one. */
/* Unchanged offset on purpose: ABI 20 renamed this field, it did not move it. */
NXC_ASSERT_LAYOUT(off_pgrva,      NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, PgContextRva)     == 92);
/* ABI 5 additions. */
NXC_ASSERT_LAYOUT(off_selfmap,    NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, PteSelfMapBase)   == 96);
NXC_ASSERT_LAYOUT(off_imgpte,     NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, ImagePteFlags)    == 104);
NXC_ASSERT_LAYOUT(off_arenapte,   NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, ArenaPteFlags)    == 108);
NXC_ASSERT_LAYOUT(off_matflags,   NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, EfiMatFlags)      == 112);
NXC_ASSERT_LAYOUT(off_protok,     NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, ProtectApplied)   == 116);
NXC_ASSERT_LAYOUT(off_protno,     NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, ProtectRefused)   == 120);
NXC_ASSERT_LAYOUT(off_ptediag,    NXC_OFFSETOF(NEXUS_CORE_BOOT_BLOCK, PteProbeDiag)     == 124);
