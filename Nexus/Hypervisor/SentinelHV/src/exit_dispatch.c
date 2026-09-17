/**
 * @file exit_dispatch.c
 * @brief Main VM-exit dispatcher and guest RIP advancement utility.
 *
 * Contains ShvHandleVmExit, the central routing function called from the
 * assembly exit stub (ShvVmExitStub) on every VM-exit. Reads the exit reason
 * from VMCS, logs it to CMOS diagnostics for post-mortem analysis, and
 * dispatches to the appropriate handler based on the basic reason code.
 *
 * Handled exit reasons: CPUID, MSR read/write, CR access, XSETBV, INVD,
 * VMCALL, EPT violation, EPT misconfiguration, and triple fault. Unhandled
 * reasons trigger a bugcheck with diagnostic information.
 *
 * Also provides ShvAdvanceGuestRip, which reads the VM-exit instruction
 * length from VMCS and advances the guest instruction pointer. This is
 * called by most handlers to prevent the guest from re-executing the
 * intercepted instruction after VMRESUME.
 */

#include "shv.h"

/* MTF bit in primary processor-based VM-execution controls */
#ifndef CPU_BASED_MONITOR_TRAP_FLAG
#define CPU_BASED_MONITOR_TRAP_FLAG  (1UL << 27)
#endif

/* ── Safe Guest Memory Reader (kernel VAs only) ───────────────────
 *
 * MmGetPhysicalAddress is documented safe from VMX root — it walks the
 * kernel self-referencing PTE map without locks or IRQL changes. If it
 * returns 0, the VA is not mapped and a direct read would page-fault.
 * If it returns non-zero, the physical page is mapped and dereferencing
 * the VA is safe.
 *
 * Only use for KERNEL virtual addresses (upper half, 0xFFFF800000000000+).
 * User-mode VAs depend on the current CR3 which is the host's in VMX root.
 */
static BOOLEAN
ShvSafeReadKernelVa(
    ULONG64 va,
    PVOID   out,
    SIZE_T  size
)
{
    if (out == NULL || size == 0)
        return FALSE;
    /* Kernel VA check: high bits must be all 1s (canonical kernel half) */
    if ((va & 0xFFFF800000000000ULL) != 0xFFFF800000000000ULL)
        return FALSE;

    /* Walk page-by-page: each page must be present.
     *
     * HV-3 hit-rate fix: MmIsAddressValid gives false negatives
     * at VMX-root HIGH_LEVEL IRQL (docs say "any IRQL" but empirically ~80%
     * of valid kernel stack reads returned FALSE). MmGetPhysicalAddress is
     * the authoritative, lock-free check — if it returns non-zero, the page
     * IS mapped and the read is safe. Drop MmIsAddressValid. Validate the
     * FIRST and LAST byte of each page independently via MmGetPhysicalAddress
     * so partial-page scenarios (RSP near guard page) still fail closed. */
    UCHAR* dst = (UCHAR*)out;
    ULONG64 remaining = size;
    ULONG64 cur = va;

    while (remaining > 0) {
        /* First-byte check: page present? */
        PHYSICAL_ADDRESS pa = MmGetPhysicalAddress((PVOID)cur);
        if (pa.QuadPart == 0)
            return FALSE;

        ULONG64 pageOff = cur & 0xFFF;
        ULONG64 chunk = 0x1000 - pageOff;
        if (chunk > remaining) chunk = remaining;

        /* Last-byte check: in case the chunk straddles near the next page's
         * boundary or the next page is a guard. For chunks entirely inside
         * one page this is the same page PA as above — cheap check. */
        if (chunk > 1) {
            PHYSICAL_ADDRESS paLast = MmGetPhysicalAddress((PVOID)(cur + chunk - 1));
            if (paLast.QuadPart == 0)
                return FALSE;
        }

        RtlCopyMemory(dst, (PVOID)cur, (SIZE_T)chunk);

        dst += chunk;
        cur += chunk;
        remaining -= chunk;
    }
    return TRUE;
}

/* ── DllMain Fork-Capture: in-VMX-root guest VA→PA + stack reader ──────
 *
 * All physical reads use ShvEptReadPhysicalPage (MmMapIoSpaceEx), the same
 * path already exercised by VMCALL_EPT_READ_PAGE.  DirectMapBase is unsound
 * on this system (two D1 BSODs confirmed); g_PteBase=0 blocks the PTE_BASE
 * self-ref path.  These helpers fall back to 0/FALSE gracefully; a failed
 * stack read sets StackLen=0 so the Python tool knows to retry via RPM.
 *
 * ForkCapPageScratch is a 4 KB buffer in g_Shv used for PT page reads and
 * as source for slice copies into the record's Stack[] field.  Single-thread
 * DllMain serialises the two trap fires so there is no scratch-buffer race.
 *
 * Each ForkCapReadPte call = 1× MmMapIoSpaceEx + copy + MmUnmapIoSpace.
 * 4 calls for the 4-level walk + 1-2 for the stack pages = ~5-6 calls
 * total; acceptable cost in VMX root while the guest is paused. */

/* Read a single 8-byte PTE from a physical byte address.
 * Reads the containing 4 KB page into g_Shv.ForkCapPageScratch. */
static BOOLEAN ForkCapReadPte(_In_ ULONG64 PtePhysAddr, _Out_ PULONG64 Out)
{
    if (PtePhysAddr == 0 || (PtePhysAddr >> 48) != 0) return FALSE;
    ULONG64 pageBase = PtePhysAddr & ~0xFFFULL;
    ULONG   off      = (ULONG)(PtePhysAddr & 0xFFF);
    if (!ShvEptReadPhysicalPage(pageBase, g_Shv.ForkCapPageScratch)) return FALSE;
    *Out = *(PULONG64)(g_Shv.ForkCapPageScratch + off);
    return TRUE;
}

/* Walk the 4-level guest page tables to translate a user-mode VA to PA.
 * Handles 2 MB and 1 GB large pages.  Does NOT handle non-canonical VAs. */
static BOOLEAN ForkCapTranslateVa(
    _In_  ULONG64  GuestCr3,
    _In_  ULONG64  Va,
    _Out_ PULONG64 OutPa)
{
    /* PML4 — bits 47:39 */
    ULONG64 pml4e;
    if (!ForkCapReadPte((GuestCr3 & ~0xFFFULL) + (((Va >> 39) & 0x1FF) * 8), &pml4e))
        return FALSE;
    if (!(pml4e & 1)) return FALSE;

    /* PDPT — bits 38:30 */
    ULONG64 pdpte;
    if (!ForkCapReadPte((pml4e & 0x000FFFFFFFFFF000ULL) + (((Va >> 30) & 0x1FF) * 8), &pdpte))
        return FALSE;
    if (!(pdpte & 1)) return FALSE;
    if (pdpte & (1ULL << 7)) { /* 1 GB page */
        *OutPa = (pdpte & 0x000FFFFFC0000000ULL) | (Va & 0x3FFFFFFFULL);
        return TRUE;
    }

    /* PD — bits 29:21 */
    ULONG64 pde;
    if (!ForkCapReadPte((pdpte & 0x000FFFFFFFFFF000ULL) + (((Va >> 21) & 0x1FF) * 8), &pde))
        return FALSE;
    if (!(pde & 1)) return FALSE;
    if (pde & (1ULL << 7)) { /* 2 MB page */
        *OutPa = (pde & 0x000FFFFFFFE00000ULL) | (Va & 0x1FFFFFULL);
        return TRUE;
    }

    /* PT — bits 20:12 */
    ULONG64 pte;
    if (!ForkCapReadPte((pde & 0x000FFFFFFFFFF000ULL) + (((Va >> 12) & 0x1FF) * 8), &pte))
        return FALSE;
    if (!(pte & 1)) return FALSE;

    *OutPa = (pte & 0x000FFFFFFFFFF000ULL) | (Va & 0xFFFULL);
    return TRUE;
}

/* Read up to MaxBytes from a guest user-mode virtual address into DstBuf.
 * Walks page by page; stops on first untranslatable page.  Returns the
 * number of bytes successfully copied. */
static ULONG ForkCapReadGuestStack(
    _In_  ULONG64 GuestCr3,
    _In_  ULONG64 VaStart,
    _Out_ PUCHAR  DstBuf,
    _In_  ULONG   MaxBytes)
{
    ULONG  copied = 0;
    ULONG64 va    = VaStart;

    while (copied < MaxBytes) {
        /* Translate the start VA of this slice */
        ULONG64 pa = 0;
        if (!ForkCapTranslateVa(GuestCr3, va, &pa)) break;

        /* Read the containing 4 KB page into the scratch buffer */
        ULONG64 pageBase = pa & ~0xFFFULL;
        if (!ShvEptReadPhysicalPage(pageBase, g_Shv.ForkCapPageScratch)) break;

        /* Copy the relevant slice from scratch into DstBuf */
        ULONG pageOff = (ULONG)(pa & 0xFFF);
        ULONG chunk   = 0x1000 - pageOff;
        if (copied + chunk > MaxBytes) chunk = MaxBytes - copied;
        RtlCopyMemory(DstBuf + copied, g_Shv.ForkCapPageScratch + pageOff, chunk);

        copied += chunk;
        va     += chunk;
    }
    return copied;
}

/* ── Advance Guest RIP ────────────────────────────────────────────── */

/**
 * @brief Advance guest RIP past the instruction that caused the VM-exit.
 *
 * Reads VMCS_RO_VMEXIT_INSTRUCTION_LEN (set by the CPU on exit) and adds
 * it to VMCS_GUEST_RIP. Without this, VMRESUME would re-execute the same
 * instruction, causing an infinite exit loop.
 */
void
ShvAdvanceGuestRip(void)
{
    SIZE_T instrLen = 0;
    SIZE_T guestRip = 0;

    __vmx_vmread(VMCS_RO_VMEXIT_INSTRUCTION_LEN, &instrLen);
    __vmx_vmread(VMCS_GUEST_RIP, &guestRip);
    __vmx_vmwrite(VMCS_GUEST_RIP, guestRip + instrLen);
}

/* ── Main VM-Exit Handler ─────────────────────────────────────────── */

/**
 * @brief Main VM-exit handler dispatcher.
 *
 * Called from the ASM exit stub with the saved guest register context and
 * the per-CPU VCPU data pointer. Reads the basic exit reason from VMCS,
 * logs it to CMOS, and routes to the appropriate handler.
 *
 * Most handlers modify the guest context (e.g., CPUID results in RAX-RDX)
 * and return FALSE to proceed with VMRESUME. The VMCALL devirtualize
 * handler returns TRUE to signal that VMX has been disabled and the stub
 * should not attempt VMRESUME.
 *
 * Unhandled exit reasons are fatal: diagnostic data is written to CMOS
 * and a bugcheck is triggered with the exit reason and qualification.
 *
 * @param GuestContext  Saved guest GPR state (modifiable by handlers).
 * @param Vcpu          Per-CPU VCPU data (used by VMCALL handler).
 * @return TRUE if devirtualized (skip VMRESUME), FALSE for normal resume.
 */
BOOLEAN
ShvHandleVmExit(
    _Inout_ PGUEST_CONTEXT GuestContext,
    _In_    PVCPU_DATA Vcpu
    )
{
    SIZE_T exitReason = 0;
    __vmx_vmread(VMCS_RO_EXIT_REASON, &exitReason);

    /* Basic exit reason is bits [15:0]; bit 31 = VM-entry failure */
    ULONG32 basicReason = (ULONG32)(exitReason & 0xFFFF);

    /* Update exit counters in VCPU (readable from guest mode) */
    InterlockedIncrement(&Vcpu->ExitTotal);
    InterlockedExchange(&Vcpu->ExitLastReason, (LONG)basicReason);

    /* CMOS exit logging DISABLED — writing to ports 0x70/0x71 on every
     * VM exit (65K+/sec during tracing) corrupts the RTC clock on crash.
     * The CMOS address register gets left pointing at a diagnostic byte
     * instead of the RTC, causing system clock to shift by hours.
     * VCPU exit counters above are sufficient for diagnostics. */

    /* ── Pending hook check (shared memory polling) ───────────────────
     * NexusDSEFix writes hook parameters to g_Shv via the backdoor,
     * then we pick them up here on the next VM exit — ANY VM exit.
     * No CPUID/MSR/VMCALL handler modification needed.
     * Fields: PendingHookVa (target VA), PendingHookPa (resolved PA, or 0)
     * When PendingHookVa != 0, install the hook and clear the field. */
    if (g_Shv.PendingHookVa != 0 && g_Shv.SecondaryEptp != 0) {
        ULONG64 hookVa = g_Shv.PendingHookVa;
        ULONG64 hookPa = g_Shv.PendingHookPa;

        /* Bit 0 of PendingHookCopyFromVa is the capture-R8 flag.
         * (Real page-aligned VAs never have bit 0 set, so this is safe.) */
        BOOLEAN captureR8 = (g_Shv.PendingHookCopyFromVa & 1ULL) != 0;
        /* Mask off the flag bit so ShvEptInstallHook sees a clean VA. */
        g_Shv.PendingHookCopyFromVa &= ~1ULL;

        /* Resolve PA from VA if not provided.
         * MmGetPhysicalAddress is safe from VMX root — it only reads PTEs
         * via the kernel's self-referencing PTE map (no locks, no IRQL). */
        if (hookPa == 0) {
            PHYSICAL_ADDRESS phys = MmGetPhysicalAddress((PVOID)hookVa);
            hookPa = (ULONG64)phys.QuadPart;
        }

        /* Clear the pending request BEFORE installing (prevent re-entry) */
        InterlockedExchange64((volatile LONG64*)&g_Shv.PendingHookVa, 0);
        InterlockedExchange64((volatile LONG64*)&g_Shv.PendingHookPa, 0);
        /* PendingHookCopyFromVa is read inside ShvEptInstallHook, clear AFTER */

        if (hookPa != 0) {
            NTSTATUS hookSt = ShvEptInstallHook(hookVa, hookPa);
            if (NT_SUCCESS(hookSt)) {
                /* Stamp captureR8 onto the newly-installed hook slot.
                 * ShvEptInstallHook increments EptHookCount, so the new
                 * entry is EptHooks[EptHookCount-1]. */
                if (g_Shv.EptHookCount > 0 && captureR8) {
                    ULONG idx = g_Shv.EptHookCount - 1;
                    g_Shv.EptHooks[idx].CaptureR8Buffer = TRUE;
                }

                /* INVEPT both contexts */
                ULONG64 eptp = ShvEptGetEptp();
                if (eptp) {
                    INVEPT_DESCRIPTOR desc = {0};
                    desc.EptPointer = eptp;
                    ShvInvept(INVEPT_SINGLE_CONTEXT, &desc);
                }
                ULONG64 septp = ShvEptGetSecondaryEptp();
                if (septp) {
                    INVEPT_DESCRIPTOR desc = {0};
                    desc.EptPointer = septp;
                    ShvInvept(INVEPT_SINGLE_CONTEXT, &desc);
                }
                g_Shv.PendingHookResult = 1;  /* Success */
                /* Bump generation so ALL CPUs sync INVEPT + exception bitmap */
                InterlockedIncrement(&g_Shv.InveptGeneration);
            } else {
                g_Shv.PendingHookResult = 0xE5;  /* Failed */
            }
        } else {
            g_Shv.PendingHookResult = 0xE7;  /* PA resolution failed */
        }
        /* Clear copy-from VA after install attempt */
        InterlockedExchange64((volatile LONG64*)&g_Shv.PendingHookCopyFromVa, 0);
    }

    /* ── DR0 read-trap arming (added, per-CPU) ──
     * DR0 is per-physical-CPU. We must arm it on EVERY VCPU separately.
     * Each VM-exit checks: if PendingDrTrapVa != 0 AND this CPU's local
     * DR0 != PendingDrTrapVa, install. The check on DR0 itself acts as
     * "have we installed locally?" — survives reboot of this code path.
     *
     * DR7 bits for read-or-write trap:
     *   bit  1 (G0)        = 1   global enable for DR0
     *   bit 16-17 (R/W0)   = 11b read-or-write
     *   bit 18-19 (LEN0)   = 11b length 8 bytes
     *   bit 10 reserved    = 1
     *   total = 0xF0402
     */
    if (g_Shv.PendingDrTrapVa != 0 && g_Shv.DrTrapDisarmed == 0) {
        ULONG64 currentDr0 = __readdr(0);
        if (currentDr0 != g_Shv.PendingDrTrapVa) {
            /* This CPU hasn't been armed yet (or DR0 was clobbered).
             * Set both DR0 and DR7. Also enable #DB in exception bitmap
             * for this VCPU. */
            SIZE_T excBitmap = 0;
            __vmx_vmread(VMCS_CTRL_EXCEPTION_BITMAP, &excBitmap);
            if (!(excBitmap & (1ULL << 1))) {
                excBitmap |= (1ULL << 1);
                __vmx_vmwrite(VMCS_CTRL_EXCEPTION_BITMAP, excBitmap);
            }
            __writedr(0, g_Shv.PendingDrTrapVa);
            /* DR7 layout per mode:
             *   R/W mode (0): G0=1, RW0=11 (R/W), LEN0=11 (8 bytes), bit10 = 0xF0402
             *   EXECUTE  (1): G0=1, RW0=00 (X),  LEN0=00 (1 byte),  bit10 = 0x00402
             */
            ULONG64 dr7 = (g_Shv.PendingDrTrapMode == 1) ? 0x00402ULL : 0xF0402ULL;
            __writedr(7, dr7);
            __vmx_vmwrite(VMCS_GUEST_DR7, dr7);
            /* DrTrapInstalled becomes a counter: bumps every CPU that arms */
            InterlockedIncrement(&g_Shv.DrTrapInstalled);
        }
    }

    /* Disarm: UM sets DrTrapDisarmed != 0 — every CPU clears its DR0/DR7. */
    if (g_Shv.DrTrapDisarmed != 0) {
        ULONG64 currentDr0 = __readdr(0);
        if (currentDr0 != 0) {
            __writedr(0, 0);
            __writedr(7, 0x400ULL);
            __vmx_vmwrite(VMCS_GUEST_DR7, 0x400ULL);
            SIZE_T excBitmap = 0;
            __vmx_vmread(VMCS_CTRL_EXCEPTION_BITMAP, &excBitmap);
            excBitmap &= ~(1ULL << 1);
            __vmx_vmwrite(VMCS_CTRL_EXCEPTION_BITMAP, excBitmap);
        }
        /* Once all CPUs have cleared, the next exit will see PendingDrTrapVa
         * already 0 and skip — but for clarity, only the LAST disarmed CPU
         * resets the request. We approximate by having every CPU clear
         * the request (idempotent). */
        InterlockedExchange64((volatile LONG64*)&g_Shv.PendingDrTrapVa, 0);
    }

    /* ── DllMain fork-capture pending-op  ─────────────────
     * UM tool (NexusDSEFix --fork-cap arm <va0> <va1>) writes the site VAs
     * to PendingForkCap* then flips PendingForkCapOp last.  We pick it up
     * on the next VM exit on any CPU.  Conflict check: if the existing
     * single-DR DrTrap is armed, refuse arm (0xE2) to avoid DR0 clobbering.
     * The per-CPU DR arming block below runs every VM exit while armed. */
    {
        ULONG64 op = InterlockedExchange64((volatile LONG64*)&g_Shv.PendingForkCapOp, 0);
        if (op != 0) {
            if (op == DLLMAIN_FORK_OP_ARM) {
                /* Refuse if the single-DR DrTrap is also active (DR0 conflict) */
                if (g_Shv.DrTrapInstalled && !g_Shv.DrTrapDisarmed) {
                    InterlockedExchange64((volatile LONG64*)&g_Shv.PendingForkCapResult, 0xE2);
                } else {
                    g_Shv.ForkCapSiteVa[0]    = g_Shv.PendingForkCapSiteVa[0];
                    g_Shv.ForkCapSiteVa[1]    = g_Shv.PendingForkCapSiteVa[1];
                    g_Shv.ForkCapTargetCr3    = g_Shv.PendingForkCapTargetCr3;
                    RtlZeroMemory(g_Shv.ForkCapRecords, sizeof(g_Shv.ForkCapRecords));
                    InterlockedExchange(&g_Shv.ForkCapHits, 0);
                    InterlockedExchange(&g_Shv.ForkCapAllFired, 0);
                    InterlockedExchange(&g_Shv.ForkCapArmed, 1);
                    InterlockedExchange64((volatile LONG64*)&g_Shv.PendingForkCapResult, 1);
                }
            } else if (op == DLLMAIN_FORK_OP_DISARM) {
                InterlockedExchange(&g_Shv.ForkCapArmed, 0);
                /* Set AllFired=1 so the per-vCPU else-if branch below clears
                 * DR0/DR1/VMCS_GUEST_DR7/exception-bitmap on every CPU's next
                 * VM exit.  Without this, VMCS_GUEST_DR7 stays at 0x40A after
                 * a forced disarm (before any sites fire), and the target's KM driver
                 * detects the armed DR7 on the next game launch. */
                InterlockedExchange(&g_Shv.ForkCapAllFired, 1);
                InterlockedExchange64((volatile LONG64*)&g_Shv.PendingForkCapResult, 1);
            } else {
                /* STATUS or unknown — just acknowledge */
                InterlockedExchange64((volatile LONG64*)&g_Shv.PendingForkCapResult,
                                      (op == DLLMAIN_FORK_OP_STATUS) ? 1ULL : 0xE5ULL);
            }
        }
    }

    /* ── DllMain fork-capture per-CPU DR arming  ───────────
     * Each physical CPU maintains its own DR0 and DR1.  When ForkCapArmed
     * is set, arm both DRs in EXECUTE mode (RW=00, LEN=00) on THIS CPU.
     * DR7 layout: G0=bit1 (DR0 global enable), G1=bit3 (DR1 global enable),
     * bit10=reserved-always-1; RW0/LEN0 = 00 = execute-1-byte.
     *   Both armed:    DR7 = 0x40A
     *   Only DR0:      DR7 = 0x402
     *   Only DR1:      DR7 = 0x408
     * Also enable #DB interception (exception bitmap bit 1) for this vCPU. */
    if (g_Shv.ForkCapArmed && !g_Shv.ForkCapAllFired) {
        SIZE_T excBitmap = 0;
        __vmx_vmread(VMCS_CTRL_EXCEPTION_BITMAP, &excBitmap);
        if (!(excBitmap & (1ULL << 1))) {
            excBitmap |= (1ULL << 1);
            __vmx_vmwrite(VMCS_CTRL_EXCEPTION_BITMAP, excBitmap);
        }
        ULONG64 dr7 = (1ULL << 10);  /* bit10 reserved, always 1 */
        if (g_Shv.ForkCapSiteVa[0] != 0 && !g_Shv.ForkCapRecords[0].Fired) {
            if (__readdr(0) != g_Shv.ForkCapSiteVa[0]) __writedr(0, g_Shv.ForkCapSiteVa[0]);
            dr7 |= (1ULL << 1);  /* G0: global enable DR0 */
        }
        if (g_Shv.ForkCapSiteVa[1] != 0 && !g_Shv.ForkCapRecords[1].Fired) {
            if (__readdr(1) != g_Shv.ForkCapSiteVa[1]) __writedr(1, g_Shv.ForkCapSiteVa[1]);
            dr7 |= (1ULL << 3);  /* G1: global enable DR1 */
        }
        __writedr(7, dr7);
        __vmx_vmwrite(VMCS_GUEST_DR7, dr7);
    } else if (g_Shv.ForkCapAllFired) {
        /* Both sites captured; clear our DRs so they don't keep firing */
        __writedr(0, 0); __writedr(1, 0);
        __writedr(7, 0x400ULL);
        __vmx_vmwrite(VMCS_GUEST_DR7, 0x400ULL);
        SIZE_T excBitmap2 = 0;
        __vmx_vmread(VMCS_CTRL_EXCEPTION_BITMAP, &excBitmap2);
        if (excBitmap2 & (1ULL << 1)) {
            excBitmap2 &= ~(1ULL << 1);
            __vmx_vmwrite(VMCS_CTRL_EXCEPTION_BITMAP, excBitmap2);
        }
    }

    /* ── Pending xcap setup check (shared memory polling) ─────────────
     * Same pattern as PendingHookVa above. NexusDSEFix issues
     * VMCALL_XCAP_SETUP which writes the request into the PendingXcap*
     * fields; we pick it up here on the next VM exit and call
     * ShvEptXcapWalkAndTrap from VMX root.
     *
     * VaBase is the trigger field — exit_vmcall.c writes Cr3/VaEnd
     * before VaBase, so a non-zero VaBase means the request is fully
     * populated. */
    if (g_Shv.PendingXcapVaBase != 0) {
        ULONG64 cr3    = g_Shv.PendingXcapCr3;
        ULONG64 vaBase = g_Shv.PendingXcapVaBase;
        ULONG64 vaEnd  = g_Shv.PendingXcapVaEnd;

        /* Clear the trigger BEFORE running so we don't re-enter on the
         * next VM exit if the walk takes a while. */
        InterlockedExchange64((volatile LONG64*)&g_Shv.PendingXcapVaBase, 0);
        InterlockedExchange64((volatile LONG64*)&g_Shv.PendingXcapVaEnd,  0);
        InterlockedExchange64((volatile LONG64*)&g_Shv.PendingXcapCr3,    0);

        if (vaEnd > vaBase) {
            ShvEptXcapWalkAndTrap(cr3, vaBase, vaEnd, FALSE);
            InterlockedExchange64((volatile LONG64*)&g_Shv.PendingXcapResult, 1);

            /* Bump generation so all CPUs sync INVEPT and pick up the
             * fresh xcap PTE state on their next VM exit. */
            InterlockedIncrement(&g_Shv.InveptGeneration);
        } else {
            InterlockedExchange64((volatile LONG64*)&g_Shv.PendingXcapResult, 0xE5);
        }
    }

    /* ── Pending UM write-trap op (Phase C v1, Apr 2026) ─────────────
     * NexusCore kernel writes PendingWriteTrap{Cr3,VaBase,Size,
     * RipFilter,TargetPid} first, then flips PendingWriteTrapOp last
     * (1=install, 2=uninstall, 3=status-only). We consume the request
     * here on the next VM exit on any CPU.
     *
     * TargetPa resolution: for install requests, the kernel caller
     * has ALREADY computed pageAlignedPa via KeStackAttachProcess +
     * MmGetPhysicalAddress and stashed it in PendingWriteTrapSize's
     * upper bits. Convention:
     *   PendingWriteTrapSize   lo32 = range size in bytes (0-4096)
     *   PendingWriteTrapSize   hi32 = unused
     *   PendingWriteTrapVaBase is the UM VA (full 64 bits)
     *   A separate field 'PendingWriteTrapTargetPid' carries PA
     *     when lo32 of VaBase == 0 and hi32 is used as the PA? NO —
     *     simpler: the kernel passes the PA separately via
     *     PendingWriteTrapTargetPid repurposed as PA-low.
     *
     * Revised simpler convention: the kernel resolves PID→CR3+PA
     * and fills Cr3 + VaBase + TargetPa (stashed into TargetPid field
     * as the "target PA" qword — it's the same size). VaBase still
     * carries the UM VA. Size is the range length. */
    {
        /* Atomic take-and-own: exactly one VP handles each op submission.
         * Exchange Op→0 first so racing VPs on other cores see 0 and skip.
         * All sub-fields are read after owning, before they can be cleared
         * by a second VP (which no longer happens). */
        ULONG64 op = InterlockedExchange64((volatile LONG64*)&g_Shv.PendingWriteTrapOp, 0);
        if (op != 0) {
        ULONG64 cr3   = g_Shv.PendingWriteTrapCr3;
        ULONG64 vaBa  = g_Shv.PendingWriteTrapVaBase;
        ULONG64 sz    = g_Shv.PendingWriteTrapSize;
        ULONG64 rip   = g_Shv.PendingWriteTrapRipFilter;
        /* PendingWriteTrapTargetPid is repurposed as TargetPa (kernel
         * resolved PA via KeStackAttachProcess + MmGetPhysicalAddress).
         * When PID convention is added later, the kernel shim does the
         * PID→PA resolve before flipping PendingWriteTrapOp. */
        ULONG64 tpa   = g_Shv.PendingWriteTrapTargetPid;

        /* Clear sub-fields after reading. Op is already 0. */
        InterlockedExchange64((volatile LONG64*)&g_Shv.PendingWriteTrapCr3,       0);
        InterlockedExchange64((volatile LONG64*)&g_Shv.PendingWriteTrapVaBase,    0);
        InterlockedExchange64((volatile LONG64*)&g_Shv.PendingWriteTrapSize,      0);
        InterlockedExchange64((volatile LONG64*)&g_Shv.PendingWriteTrapRipFilter, 0);
        InterlockedExchange64((volatile LONG64*)&g_Shv.PendingWriteTrapTargetPid, 0);

        NTSTATUS stWt = STATUS_UNSUCCESSFUL;
        if (op == 1 /* INSTALL */) {
            if (sz == 0 || sz > PAGE_SIZE) {
                sz = PAGE_SIZE;
            }
            stWt = ShvEptInstallWriteTrap(cr3, tpa, vaBa, vaBa + sz, rip);
        } else if (op == 2 /* UNINSTALL */) {
            stWt = ShvEptUninstallWriteTrap();
        } else if (op == 3 /* STATUS */) {
            /* Status-only — no state change. Just report success.
             * Caller reads the g_Shv.WriteTrap* counters directly. */
            stWt = STATUS_SUCCESS;
        } else {
            SHV_ERR("WriteTrap: unknown pending op %llu", op);
            stWt = STATUS_INVALID_PARAMETER;
        }

        InterlockedExchange64((volatile LONG64*)&g_Shv.PendingWriteTrapResult,
                              NT_SUCCESS(stWt) ? 1 : 0xE5);
        } /* if (op != 0) */
    } /* WriteTrap block */

    /* ── UM EPT Read-Trap pending-op (Phase C-R, Apr 2026) ────────────
     * Same shape as write-trap pending-op block above. */
    {
        ULONG64 op = InterlockedExchange64((volatile LONG64*)&g_Shv.PendingReadTrapOp, 0);
        if (op != 0) {
        ULONG64 cr3   = g_Shv.PendingReadTrapCr3;
        ULONG64 vaBa  = g_Shv.PendingReadTrapVaBase;
        ULONG64 sz    = g_Shv.PendingReadTrapSize;
        ULONG64 rip   = g_Shv.PendingReadTrapRipFilter;
        ULONG64 tpa   = g_Shv.PendingReadTrapTargetPid;

        InterlockedExchange64((volatile LONG64*)&g_Shv.PendingReadTrapCr3,       0);
        InterlockedExchange64((volatile LONG64*)&g_Shv.PendingReadTrapVaBase,    0);
        InterlockedExchange64((volatile LONG64*)&g_Shv.PendingReadTrapSize,      0);
        InterlockedExchange64((volatile LONG64*)&g_Shv.PendingReadTrapRipFilter, 0);
        InterlockedExchange64((volatile LONG64*)&g_Shv.PendingReadTrapTargetPid, 0);

        NTSTATUS stRt = STATUS_UNSUCCESSFUL;
        if (op == READ_TRAP_OP_INSTALL) {
            if (sz == 0 || sz > PAGE_SIZE) sz = PAGE_SIZE;
            stRt = ShvEptInstallReadTrap(cr3, tpa, vaBa, vaBa + sz, rip);
        } else if (op == READ_TRAP_OP_UNINSTALL) {
            stRt = ShvEptUninstallReadTrap();
        } else if (op == READ_TRAP_OP_STATUS) {
            stRt = STATUS_SUCCESS;
        } else {
            SHV_ERR("ReadTrap: unknown pending op %llu", op);
            stRt = STATUS_INVALID_PARAMETER;
        }

        InterlockedExchange64((volatile LONG64*)&g_Shv.PendingReadTrapResult,
                              NT_SUCCESS(stRt) ? 1 : 0xE5);
        } /* if (op != 0) */
    } /* ReadTrap block */

    /* ── Auto-arm deferred UM install  ────────────────────
     * UM image loads via NtMapViewOfSection can fire LoadImage notify
     * BEFORE the specific section pages have been faulted in. In that
     * case the callback can't resolve VA->PA via MmGetPhysicalAddress
     * and stashes the request here. We retry on every VMexit; once
     * the guest CR3 matches and the page is finally backed (or even
     * resolvable via PT walk in the target CR3), we install the trap
     * via the same PendingExec/ReadTrap mechanism the callback would
     * have used. */
    if (g_Shv.AutoArmDeferredActive == 1) {
        /* KPTI (Kernel VA Shadowing) fix: on Windows 10/11 with KPTI the
         * CR3 stored at LoadImageNotify time (kernel mode) is the process's
         * DirectoryTableBase.  VM exits from user-mode code carry the
         * UserDirectoryTableBase — a different physical address.  The old
         * `curCr3 == wantCr3` check therefore NEVER fires for UM images.
         *
         * The correct approach: for user-mode images (AutoArmDeferredFilterCr3
         * != 0), skip the CR3 match entirely.  User-space VAs resolve
         * identically via both DTB and UDTB (they share the same lower-half
         * PML4 entries), so ShvTranslateGuestVa(DTB, userVA) succeeds as soon
         * as the page is resident, regardless of which CR3 the current VM exit
         * used.  For KM images (FilterCr3==0) keep the old exact-match guard
         * to avoid unnecessary walks on unrelated exits. */
        BOOLEAN inScope;
        if (g_Shv.AutoArmDeferredFilterCr3 == 0) {
            /* KM image: fire on any exit (trap is global) */
            inScope = TRUE;
        } else {
            /* UM image: attempt on any exit — KPTI means CR3 won't match
             * when user-mode code is running; user VA resolves via stored
             * kernel DTB regardless of current guest CR3. */
            inScope = TRUE;
        }
        if (inScope) {
            InterlockedIncrement64((volatile LONG64*)&g_Shv.AutoArmDeferredAttempts);
            ULONG64 va = g_Shv.AutoArmDeferredVa;
            ULONG64 paOut = 0;
            if (ShvTranslateGuestVa(g_Shv.AutoArmDeferredCr3, va, &paOut) && paOut != 0) {
                ULONG64 paPage = paOut & ~0xFFFULL;
                ULONG64 sz     = g_Shv.AutoArmDeferredSize ? g_Shv.AutoArmDeferredSize : 0x1000ULL;
                ULONG64 filter = g_Shv.AutoArmDeferredFilterCr3;
                ULONG64 ttype  = g_Shv.AutoArmDeferredTrapType;
                if (ttype == 1) {
                    g_Shv.PendingReadTrapCr3        = filter;
                    g_Shv.PendingReadTrapVaBase     = va;
                    g_Shv.PendingReadTrapSize       = sz;
                    g_Shv.PendingReadTrapRipFilter  = 0;
                    g_Shv.PendingReadTrapTargetPid  = paPage;
                    g_Shv.PendingReadTrapResult     = 0;
                    g_Shv.PendingReadTrapOp         = 1;
                    if (g_Shv.AutoArmAutoStop != 0)
                        g_Shv.ReadTrapAutoStop = (LONG)g_Shv.AutoArmAutoStop;
                } else if (ttype == 2) {
                    g_Shv.PendingExecTrapCr3        = filter;
                    g_Shv.PendingExecTrapVaBase     = va;
                    g_Shv.PendingExecTrapSize       = sz;
                    g_Shv.PendingExecTrapRipFilter  = 0;
                    g_Shv.PendingExecTrapTargetPid  = paPage;
                    g_Shv.PendingExecTrapResult     = 0;
                    g_Shv.PendingExecTrapOp         = 1;
                    if (g_Shv.AutoArmAutoStop != 0)
                        g_Shv.ExecTrapAutoStop = (LONG)g_Shv.AutoArmAutoStop;
                }
                g_Shv.AutoArmInstallStatus = (LONG)STATUS_SUCCESS;
                /* Clear the deferred trigger so we don't re-fire. The
                 * PendingExec/ReadTrap op flag is consumed by the next
                 * block in this same dispatch pass. */
                InterlockedExchange(&g_Shv.AutoArmDeferredActive, 0);
            }
        }
    }

    /* ── UM EPT Exec-Trap pending-op (Phase C-X, Apr 2026) ────────────
     * Same shape as read-trap pending-op block above. */
    /* Atomic take-and-own: exchange Op→0 first so only one VP handles each
     * submission.  Racing VPs on other cores see 0 and skip. */
    {
        ULONG64 op = InterlockedExchange64((volatile LONG64*)&g_Shv.PendingExecTrapOp, 0);
        if (op != 0) {
        InterlockedIncrement(&g_Shv.ExecTrapLogTotal);  /* "reached+op!=0" counter */
        SHV_LOG("ExecTrap: processing pending op=%llu va=0x%llX pa=0x%llX",
                op, g_Shv.PendingExecTrapVaBase,
                g_Shv.PendingExecTrapTargetPid);
        ULONG64 cr3   = g_Shv.PendingExecTrapCr3;
        ULONG64 vaBa  = g_Shv.PendingExecTrapVaBase;
        ULONG64 sz    = g_Shv.PendingExecTrapSize;
        ULONG64 rip   = g_Shv.PendingExecTrapRipFilter;
        ULONG64 tpa   = g_Shv.PendingExecTrapTargetPid;

        InterlockedExchange64((volatile LONG64*)&g_Shv.PendingExecTrapCr3,       0);
        InterlockedExchange64((volatile LONG64*)&g_Shv.PendingExecTrapVaBase,    0);
        InterlockedExchange64((volatile LONG64*)&g_Shv.PendingExecTrapSize,      0);
        InterlockedExchange64((volatile LONG64*)&g_Shv.PendingExecTrapRipFilter, 0);
        InterlockedExchange64((volatile LONG64*)&g_Shv.PendingExecTrapTargetPid, 0);

        NTSTATUS stXt = STATUS_UNSUCCESSFUL;
        if (op == EXEC_TRAP_OP_INSTALL) {
            if (sz == 0 || sz > PAGE_SIZE) sz = PAGE_SIZE;
            /* Lazy resource init: PrepareHookResources and PrepareExecTrapResources
             * are idempotent (no-op if already done). Calling them here ensures
             * g_HookRes.Ready=TRUE and g_Shv.ExecTrapLog!=NULL even if the init-
             * time allocs failed (e.g. memory pressure at early boot). This fixes
             * ShvEptInstallExecTrap returning STATUS_UNSUCCESSFUL (0xC0000001). */
            ShvEptPrepareHookResources();
            ShvEptPrepareExecTrapResources();
            /* KPTI (Windows 10/11): UM-side stores the kernel DirectoryTableBase
             * as cr3, but VM exits from user-mode code carry UserDirectoryTableBase.
             * DTB != UDTB → first hit is filtered → ExecTrapFilteredCr3==0 path
             * fires PendingExecTrapOp=2 (auto-uninstall) → 0 captured hits.
             * Fix: always install with cr3=0 (no per-process filter).  The VA
             * range (VaBase/VaEnd = one 4KB page) provides sufficient restriction
             * for single-process targets like gsl.exe/EAAntiCheat DLLs. */
            stXt = ShvEptInstallExecTrap(0 /* cr3: KPTI-safe global */, tpa, vaBa, vaBa + sz, rip);
        } else if (op == EXEC_TRAP_OP_UNINSTALL) {
            stXt = ShvEptUninstallExecTrap();
        } else if (op == EXEC_TRAP_OP_STATUS) {
            stXt = STATUS_SUCCESS;
        } else {
            SHV_ERR("ExecTrap: unknown pending op %llu", op);
            stXt = STATUS_INVALID_PARAMETER;
        }

        /* Pass raw NTSTATUS on failure so caller can distinguish:
         * STATUS_UNSUCCESSFUL(0xC0000001)=log/hook/ept null,
         * STATUS_INVALID_PARAMETER(0xC000000D)=bad PA/range,
         * STATUS_ALREADY_INITIALIZED(0xC0000510)=trap active (WDK 26100 value),
         * STATUS_INSUFFICIENT_RESOURCES(0xC000009A)=split failed */
        InterlockedExchange64((volatile LONG64*)&g_Shv.PendingExecTrapResult,
                              NT_SUCCESS(stXt) ? 1 : ((ULONG64)stXt & 0xFFFFFFFF));
        } /* if (op != 0) */
    } /* ExecTrap block */

    /* ── Chained exec-trap pending-op (iter#179) ──────────
     * Op 1 = ENABLE:  copy Pending* chain config into live fields and
     *                 set ExecTrapChainEnabled=1, ExecTrapChainFired=0.
     *                 Target PA must already be pre-split (guest called
     *                 ShvEptInstallExecTrap+Uninstall to allocate the PT).
     * Op 2 = DISABLE: clear ExecTrapChainEnabled. */
    {
        ULONG64 op = InterlockedExchange64((volatile LONG64*)&g_Shv.PendingExecTrapChainOp, 0);
        if (op != 0) {

        if (op == 1) {
            g_Shv.ExecTrapChainAnchorVa      = g_Shv.PendingExecTrapChainAnchorVa;
            g_Shv.ExecTrapChainTargetPa      = g_Shv.PendingExecTrapChainTargetPa;
            g_Shv.ExecTrapChainTargetVaBase  = g_Shv.PendingExecTrapChainTargetVaBase;
            g_Shv.ExecTrapChainTargetCr3     = g_Shv.PendingExecTrapChainTargetCr3;
            g_Shv.ExecTrapChainAutoStop      = g_Shv.PendingExecTrapChainAutoStop;
            g_Shv.ExecTrapChainRcxLow12     = g_Shv.PendingExecTrapChainRcxLow12;
            g_Shv.ExecTrapChainRdxRva       = g_Shv.PendingExecTrapChainRdxRva;
            g_Shv.ExecTrapChainRcxRva       = g_Shv.PendingExecTrapChainRcxRva;
            g_Shv.ExecTrapChainStage3Pa     = g_Shv.PendingExecTrapChainStage3Pa;
            InterlockedExchange64((volatile LONG64*)&g_Shv.ExecTrapChainFired,   0);
            /* Drop any "stage-2 page not resident, retry" state from a previous
             * run before arming; a stale VA would bypass the EP filter. */
            ShvEptChainResetPending();
            InterlockedExchange64((volatile LONG64*)&g_Shv.ExecTrapChainEnabled, 1);

            /* If anchor trap is already armed, tighten it to fire only at the
             * exact anchor VA.  This filters the many non-anchor hits on the
             * anchor page (which use MTF but don't need to be logged) so the
             * chain fires precisely at the right instruction. */
            if (g_Shv.ExecTrapActive) {
                g_Shv.ExecTrapRipFilter = g_Shv.ExecTrapChainAnchorVa;
            }

            SHV_LOG("ExecTrapChain: enabled anchor=0x%llX targetPa=0x%llX targetVa=0x%llX rcxRva=0x%llX",
                    g_Shv.ExecTrapChainAnchorVa, g_Shv.ExecTrapChainTargetPa,
                    g_Shv.ExecTrapChainTargetVaBase, g_Shv.ExecTrapChainRcxRva);
            InterlockedExchange64((volatile LONG64*)&g_Shv.PendingExecTrapChainResult, 1);
        } else if (op == 2) {
            InterlockedExchange64((volatile LONG64*)&g_Shv.ExecTrapChainEnabled, 0);
            SHV_LOG("ExecTrapChain: disabled");
            InterlockedExchange64((volatile LONG64*)&g_Shv.PendingExecTrapChainResult, 1);
        } else {
            InterlockedExchange64((volatile LONG64*)&g_Shv.PendingExecTrapChainResult, 0xE5);
        }
        } /* if (op != 0) */
    } /* ChainOp block */

    /* ── Exec-trap hash-capture pending-op  ───────────────
     * Op 1 = SET:    copy PendingExecTrapCapSrc/Len into the live fields.
     *                Validates Src in [1..6] and Len in [1..EXEC_TRAP_PAYLOAD_BYTES]
     *                (=512; a full [RSP..RSP+0x200] stack window).
     * Op 2 = DISABLE: clears Src + Len + stats (hits, read-fails).
     * Result: 1 = ok, 0xE5 = fail. Fields are read back by UM after. */
    {
        ULONG64 op = InterlockedExchange64((volatile LONG64*)&g_Shv.PendingExecTrapCapOp, 0);
        if (op != 0) {
        ULONG64 src = g_Shv.PendingExecTrapCapSrc;
        ULONG64 len = g_Shv.PendingExecTrapCapLen;

        InterlockedExchange64((volatile LONG64*)&g_Shv.PendingExecTrapCapSrc, 0);
        InterlockedExchange64((volatile LONG64*)&g_Shv.PendingExecTrapCapLen, 0);

        NTSTATUS stCap = STATUS_UNSUCCESSFUL;
        if (op == EXEC_TRAP_CAP_OP_SET) {
            if (src < 1 || src > (ULONG64)EXEC_TRAP_CAP_SRC_MAX ||
                len == 0 || len > (ULONG64)EXEC_TRAP_PAYLOAD_BYTES) {
                SHV_ERR("ExecTrapCap: invalid set — src=%llu len=%llu", src, len);
                stCap = STATUS_INVALID_PARAMETER;
            } else {
                InterlockedExchange((volatile LONG*)&g_Shv.ExecTrapCapHits,      0);
                InterlockedExchange((volatile LONG*)&g_Shv.ExecTrapCapReadFails, 0);
                /* Write Len BEFORE Src — hit handler reads Src first as the
                 * arming gate, so a non-zero Src must see a non-zero Len. */
                InterlockedExchange((volatile LONG*)&g_Shv.ExecTrapCapLen,
                                    (LONG)(ULONG32)len);
                InterlockedExchange((volatile LONG*)&g_Shv.ExecTrapCapSrc,
                                    (LONG)(ULONG32)src);
                SHV_LOG("ExecTrapCap: armed src=%llu len=%llu", src, len);
                stCap = STATUS_SUCCESS;
            }
        } else if (op == EXEC_TRAP_CAP_OP_DISABLE) {
            InterlockedExchange((volatile LONG*)&g_Shv.ExecTrapCapSrc, 0);
            InterlockedExchange((volatile LONG*)&g_Shv.ExecTrapCapLen, 0);
            InterlockedExchange((volatile LONG*)&g_Shv.ExecTrapCapHits,      0);
            InterlockedExchange((volatile LONG*)&g_Shv.ExecTrapCapReadFails, 0);
            SHV_LOG("ExecTrapCap: disabled");
            stCap = STATUS_SUCCESS;
        } else {
            SHV_ERR("ExecTrapCap: unknown pending op %llu", op);
            stCap = STATUS_INVALID_PARAMETER;
        }

        InterlockedExchange64((volatile LONG64*)&g_Shv.PendingExecTrapCapResult,
                              NT_SUCCESS(stCap) ? 1 : 0xE5);
        } /* if (op != 0) */
    } /* ExecTrapCap block */

    /* ── Syscall SSN trap pending-ops  ────────────────────────
     * Three independent one-shot ops; each clears its own Op when done.
     *
     * 1. PendingQueryLstarOp: read IA32_LSTAR (0xC0000082) in VMX-root and write
     *    back to PendingQueryLstarResult. On a type-2 HV that does not swap LSTAR
     *    on VM-entry/exit, the host MSR equals the guest's KiSystemCall64Shadow VA.
     *
     * 2. PendingTranslateKvaOp: translate a kernel VA → PA using the host CR3
     *    (__readcr3() in VMX-root = the kernel's own page tables) via the existing
     *    ShvTranslateGuestVa walker. Lets UM compute the LSTAR page's PA without
     *    going through the UWTR mapper (which only handles user-mode VAs).
     *
     * 3. PendingExecTrapRaxFilterOp: set or clear ExecTrapRaxFilter.
     *    Op 1 = latch PendingExecTrapRaxFilter into ExecTrapRaxFilter.
     *    Op 2 = clear ExecTrapRaxFilter (disable RAX filtering). */
    if (g_Shv.PendingQueryLstarOp == 1) {
        g_Shv.PendingQueryLstarResult = __readmsr(0xC0000082);  /* IA32_LSTAR */
        InterlockedExchange64((volatile LONG64*)&g_Shv.PendingQueryLstarOp, 0);
    }

    if (g_Shv.PendingTranslateKvaOp == 1) {
        ULONG64 pa = 0;
        /* ShvTranslateGuestVa uses ShvReadGuestPhysQword which is disabled on
         * VBS/HVCI (PT pages outside DirectMapBase → BSOD at VMX root). Use
         * ShvTranslateVaDirect instead: reads PTE via the PTE_BASE self-ref
         * with a 48-bit mask that fixes the kernel-VA uint64 overflow. */
        if (ShvTranslateVaDirect(g_Shv.PendingTranslateKvaVa, &pa) && pa != 0) {
            g_Shv.PendingTranslateKvaResult = pa;
        } else {
            g_Shv.PendingTranslateKvaResult = ~0ULL;
            SHV_WARN("TranslateKva: ShvTranslateVaDirect failed for VA 0x%llX",
                     g_Shv.PendingTranslateKvaVa);
        }
        InterlockedExchange64((volatile LONG64*)&g_Shv.PendingTranslateKvaOp, 0);
    }

    if (g_Shv.PendingExecTrapRaxFilterOp != 0) {
        ULONG64 op = g_Shv.PendingExecTrapRaxFilterOp;
        InterlockedExchange64((volatile LONG64*)&g_Shv.PendingExecTrapRaxFilterOp, 0);
        if (op == 1) {
            InterlockedExchange64((volatile LONG64*)&g_Shv.ExecTrapRaxFilter,
                                  (LONG64)g_Shv.PendingExecTrapRaxFilter);
            SHV_LOG("ExecTrapRaxFilter: set to 0x%llX", g_Shv.ExecTrapRaxFilter);
            InterlockedExchange64((volatile LONG64*)&g_Shv.PendingExecTrapRaxFilterResult, 1);
        } else if (op == 2) {
            InterlockedExchange64((volatile LONG64*)&g_Shv.ExecTrapRaxFilter, 0);
            SHV_LOG("ExecTrapRaxFilter: cleared");
            InterlockedExchange64((volatile LONG64*)&g_Shv.PendingExecTrapRaxFilterResult, 1);
        } else {
            SHV_ERR("ExecTrapRaxFilter: unknown op %llu", op);
            InterlockedExchange64((volatile LONG64*)&g_Shv.PendingExecTrapRaxFilterResult, 0xE5);
        }
    }

    /* ── RIP-trace pending-op  ───────────────────────────
     * Op codes:
     *   1 = arm:    copy StepsMax/StopLow/StopHigh/Cr3/StopOnRange into
     *               the live fields, zero the log, flip RipTraceActive=1
     *               and RipTraceArmOnHit=1. Next read-trap hit starts
     *               logging.
     *   2 = disarm: clear Active + ArmOnHit so the next MTF stops.
     *   3 = status: no-op, just result=1 (UM reads log fields directly).
     * No install/uninstall of the read-trap itself — UM does that via
     * the normal --um-read-trap commands. */
    if (g_Shv.PendingRipTraceOp != 0 && g_Shv.RipTraceLog != NULL) {
        ULONG64 op    = g_Shv.PendingRipTraceOp;
        NTSTATUS stRt = STATUS_UNSUCCESSFUL;
        if (op == 1) {
            /* Latch parameters. StepsMax 0 → default in MTF handler. */
            g_Shv.RipTraceStepsMax    = (ULONG)g_Shv.PendingRipTraceStepsMax;
            g_Shv.RipTraceStopLow     = g_Shv.PendingRipTraceStopLow;
            g_Shv.RipTraceStopHigh    = g_Shv.PendingRipTraceStopHigh;
            g_Shv.RipTraceCr3Filter   = g_Shv.PendingRipTraceCr3;
            g_Shv.RipTraceStopOnRange = (ULONG)g_Shv.PendingRipTraceStopOnRange;

            /* Zero the ring. 256 KB — cheap. */
            RtlZeroMemory(g_Shv.RipTraceLog,
                          (SIZE_T)RIP_TRACE_LOG_MAX * sizeof(RIP_TRACE_ENTRY));
            InterlockedExchange(&g_Shv.RipTraceLogIndex, 0);
            InterlockedExchange(&g_Shv.RipTraceLogTotal, 0);
            InterlockedExchange(&g_Shv.RipTraceStepsTaken, 0);

            /* Flip Active and ArmOnHit LAST. Both need to be 1 for
             * the read-trap hit handler to pick this up. */
            InterlockedExchange((volatile LONG*)&g_Shv.RipTraceArmOnHit, 1);
            InterlockedExchange((volatile LONG*)&g_Shv.RipTraceActive, 1);
            stRt = STATUS_SUCCESS;
        } else if (op == 2) {
            InterlockedExchange((volatile LONG*)&g_Shv.RipTraceArmOnHit, 0);
            InterlockedExchange((volatile LONG*)&g_Shv.RipTraceActive, 0);
            stRt = STATUS_SUCCESS;
        } else if (op == 3) {
            stRt = STATUS_SUCCESS;   /* UM will read log directly */
        } else {
            SHV_ERR("RipTrace: unknown pending op %llu", op);
            stRt = STATUS_INVALID_PARAMETER;
        }

        InterlockedExchange64((volatile LONG64*)&g_Shv.PendingRipTraceResult,
                              NT_SUCCESS(stRt) ? 1 : 0xE5);
        InterlockedExchange64((volatile LONG64*)&g_Shv.PendingRipTraceOp, 0);
    }

    /* ── KM Cipher Trap pending-op  ─────────────────
     * Op 1 = INSTALL:   arm 80 exec-traps (KmBase + KmSize from pending fields)
     * Op 2 = UNINSTALL: remove all cipher exec-traps
     * Op 3 = STATUS:    no-op (UM reads counters directly from g_Shv)
     * Result: 1 = ok, 0xE5 = fail. */
    if (g_Shv.PendingCipherTrapOp != 0) {
        ULONG64 op   = g_Shv.PendingCipherTrapOp;
        ULONG64 base = g_Shv.PendingCipherTrapKmBase;
        ULONG64 size = g_Shv.PendingCipherTrapKmSize;

        InterlockedExchange64((volatile LONG64*)&g_Shv.PendingCipherTrapKmBase, 0);
        InterlockedExchange64((volatile LONG64*)&g_Shv.PendingCipherTrapKmSize, 0);

        NTSTATUS stCt = STATUS_UNSUCCESSFUL;
        if (op == CIPHER_TRAP_OP_INSTALL) {
            if (base == 0 || size == 0) {
                SHV_ERR("CipherTrap: install without KmBase/KmSize");
                stCt = STATUS_INVALID_PARAMETER;
            } else {
                stCt = ShvCipherTrapInstall(base, size);
            }
        } else if (op == CIPHER_TRAP_OP_UNINSTALL) {
            ShvCipherTrapUninstall();
            stCt = STATUS_SUCCESS;
        } else if (op == CIPHER_TRAP_OP_STATUS) {
            stCt = STATUS_SUCCESS;
        } else if (op == CIPHER_TRAP_OP_SETMASK) {
            /* maskLo stored in PendingCipherTrapKmBase, maskHi in KmSize */
            ShvCipherTrapSetSkipMask(base, size);
            stCt = STATUS_SUCCESS;
        } else {
            SHV_ERR("CipherTrap: unknown pending op %llu", op);
            stCt = STATUS_INVALID_PARAMETER;
        }

        InterlockedExchange64((volatile LONG64*)&g_Shv.PendingCipherTrapResult,
                              NT_SUCCESS(stCt) ? 1 : 0xE5);
        InterlockedExchange64((volatile LONG64*)&g_Shv.PendingCipherTrapOp, 0);
    }

    /* ── HV-3: Pending spoof-config op (Apr 2026) ────────────────────
     * User-mode configures per-hook spoof behavior by filling
     * PendingSpoof{HookIdx, Kind, RetValue} and flipping PendingSpoofOp
     * last. We pick it up here on the next VM exit and write the
     * corresponding EptHookExtra[] slot.
     *
     * HookIdx is bounds-checked against EPT_HOOK_MAX. The target slot
     * does NOT have to be Active — spoof metadata can be pre-loaded
     * before the hook is installed and it takes effect on the next
     * InstallHook call into that slot. */
    if (g_Shv.PendingSpoofOp != 0) {
        ULONG64 op   = g_Shv.PendingSpoofOp;
        ULONG64 idx  = g_Shv.PendingSpoofHookIdx;
        ULONG64 kind = g_Shv.PendingSpoofKind;
        ULONG64 ret  = g_Shv.PendingSpoofRetValue;

        /* Clear pending fields BEFORE applying so a concurrent re-entry
         * on another CPU doesn't process the same op twice. Clear Op
         * LAST so UM sees result-before-op-cleared. */
        InterlockedExchange64((volatile LONG64*)&g_Shv.PendingSpoofHookIdx,   0);
        InterlockedExchange64((volatile LONG64*)&g_Shv.PendingSpoofKind,     0);
        InterlockedExchange64((volatile LONG64*)&g_Shv.PendingSpoofRetValue, 0);

        ULONG64 result = 0xE5;
        if (op == SPOOF_OP_SET && idx < EPT_HOOK_MAX) {
            g_Shv.EptHookExtra[idx].HookKind      = (ULONG32)kind;
            g_Shv.EptHookExtra[idx].SpoofRetValue = ret;
            result = 1;
        }

        InterlockedExchange64((volatile LONG64*)&g_Shv.PendingSpoofResult, (LONG64)result);
        InterlockedExchange64((volatile LONG64*)&g_Shv.PendingSpoofOp, 0);
    }

    /* ── Xcap EPTP sanity sample ──────────────────────────────────────
     * On every VM exit during the xcap session, read the current
     * VMCS_CTRL_EPTP and compare to PrimaryEptp. If they differ, this
     * CPU is on the secondary EPT (dual-EPT switch from a hook execution),
     * which means our xcap traps (only modifying primary) are invisible
     * to it. Surfacing this is the smoking-gun diagnostic for "the trap
     * is in memory but the CPU isn't using that EPT". */
    if (g_Shv.XcapActive && g_Shv.PrimaryEptp != 0) {
        SIZE_T sampleEptp = 0;
        __vmx_vmread(VMCS_CTRL_EPTP, &sampleEptp);
        if ((ULONG64)sampleEptp != g_Shv.PrimaryEptp) {
            InterlockedIncrement(&g_Shv.XcapNonPrimaryEptpCount);
            g_Shv.XcapLastNonPrimaryEptp = (ULONG64)sampleEptp;
        }
    }

    /* ── Xcap RIP sampling ────────────────────────────────────────────
     * On every VM exit, if xcap is active and the guest CR3 matches the
     * armed target CR3, sample the guest RIP. This is the definitive
     * answer to "does the launcher actually execute image pages?".
     *
     * Cheap (one VMREAD + one compare + a few atomic ops) and runs on
     * every exit, so the sample density is high (thousands per second
     * across timer ticks alone). */
    if (g_Shv.XcapActive) {
        SIZE_T sampleCr3 = 0, sampleRip = 0;
        __vmx_vmread(VMCS_GUEST_CR3, &sampleCr3);
        if (((ULONG64)sampleCr3 & ~0xFFFULL) == g_Shv.XcapTargetCr3 &&
            g_Shv.XcapTargetCr3 != 0) {
            __vmx_vmread(VMCS_GUEST_RIP, &sampleRip);
            InterlockedIncrement(&g_Shv.XcapRipSampleCount);
            g_Shv.XcapLastRip = (ULONG64)sampleRip;
            if ((ULONG64)sampleRip >= g_Shv.XcapVaBase &&
                (ULONG64)sampleRip <  g_Shv.XcapVaEnd) {
                InterlockedIncrement(&g_Shv.XcapRipInImageCount);
                if (g_Shv.XcapFirstRipIn == 0) {
                    g_Shv.XcapFirstRipIn = (ULONG64)sampleRip;
                }
            } else {
                if (g_Shv.XcapFirstRipOut == 0) {
                    g_Shv.XcapFirstRipOut = (ULONG64)sampleRip;
                }
            }
        }
    }

    /* ── Per-CPU INVEPT + exception bitmap sync ─────────────────────
     * After hook installation, only the installing CPU has fresh TLBs
     * and the exception bitmap updated. All other CPUs must catch up.
     * Check the generation counter on every VM exit (cheap compare). */
    {
        LONG curGen = g_Shv.InveptGeneration;
        if (Vcpu->LastInveptGeneration != curGen) {
            Vcpu->LastInveptGeneration = curGen;

            /* Flush stale EPT TLB entries on THIS CPU */
            ULONG64 eptp = ShvEptGetEptp();
            if (eptp) {
                INVEPT_DESCRIPTOR desc = {0};
                desc.EptPointer = eptp;
                ShvInvept(INVEPT_SINGLE_CONTEXT, &desc);
            }
            ULONG64 septp = ShvEptGetSecondaryEptp();
            if (septp) {
                INVEPT_DESCRIPTOR desc = {0};
                desc.EptPointer = septp;
                ShvInvept(INVEPT_SINGLE_CONTEXT, &desc);
            }

            /* Set exception bitmap bit 3 (#BP) on THIS CPU's VMCS */
            InterlockedIncrement(&g_Shv.ExcBitmapSyncs);
            if (g_Shv.EptHookCount > 0) {
                SIZE_T excBitmap = 0;
                __vmx_vmread(VMCS_CTRL_EXCEPTION_BITMAP, &excBitmap);
                excBitmap |= (1UL << 3);
                __vmx_vmwrite(VMCS_CTRL_EXCEPTION_BITMAP, excBitmap);
            }
        }
    }

    switch (basicReason) {

    case EXIT_REASON_CPUID:
        InterlockedIncrement(&Vcpu->ExitCpuid);

        /* ── Check if this CPUID is a hook trigger ─────────────────────
         * Hooks write CPUID (0F A2) at the function entry point in the
         * shadow page. CPUID is an UNCONDITIONAL VM exit — no exception
         * bitmap needed. Check guest RIP against hook table BEFORE
         * executing the real CPUID handler.
         *
         * MUST check even after auto-stop. Other hooks may still have
         * CPUID in their shadow pages. If we skip recovery, the CPUID
         * falls through to ShvHandleCpuid which corrupts EAX-EDX and
         * ShvAdvanceGuestRip which skips 2 bytes of the function → BSOD.
         * The MTF handler handles auto-stop by not re-arming CPUID. */
        if (g_Shv.EptHookCount > 0) {
            SIZE_T hookRip = 0;
            __vmx_vmread(VMCS_GUEST_RIP, &hookRip);

            int cpuidHookIdx = -1;
            for (ULONG i = 0; i < g_Shv.EptHookCount; i++) {
                if (g_Shv.EptHooks[i].Active &&
                    g_Shv.EptHooks[i].TargetVa == (ULONG64)hookRip) {
                    cpuidHookIdx = (int)i;
                    break;
                }
            }

            if (cpuidHookIdx >= 0) {
                /* This is a hook-triggered CPUID, not a real CPUID call.
                 * Do NOT execute CPUID or advance RIP. Instead: log the
                 * call, restore original bytes, single-step, re-arm. */
                InterlockedIncrement(&g_Shv.EptHookHits);
                InterlockedIncrement(&g_Shv.BpExitsMatched);
                InterlockedIncrement(&g_Shv.SyscallLogAllCalls);

                /* ── HV-3: Spoof-mode dispatch (Apr 2026) ─────────────
                 * If EptHookExtra[cpuidHookIdx].HookKind != LOG, skip
                 * the function body entirely: pop retaddr off [RSP],
                 * set GuestRip = retaddr, RSP += 8, set RAX per kind,
                 * switch to primary EPT, INVEPT. No MTF, no re-arm —
                 * the shadow page keeps its CPUID bytes, so the next
                 * call to this function re-triggers our spoof path.
                 *
                 * Safety: [RSP] read uses ShvSafeReadKernelVa which
                 * verifies the page is mapped via MmGetPhysicalAddress
                 * + MmIsAddressValid. If the read fails (paged-out or
                 * not canonical-kernel), we fall through to the LOG
                 * path so the original function runs normally. */
                {
                    ULONG32 hookKind = g_Shv.EptHookExtra[cpuidHookIdx].HookKind;
                    if (hookKind == HOOK_KIND_SPOOF_RAX) {
                        SIZE_T guestRsp = 0;
                        __vmx_vmread(VMCS_GUEST_RSP, &guestRsp);

                        ULONG64 retaddr = 0;
                        if (ShvSafeReadKernelVa((ULONG64)guestRsp,
                                                &retaddr, sizeof(retaddr))) {
                            /* Set spoofed return value */
                            GuestContext->Rax =
                                g_Shv.EptHookExtra[cpuidHookIdx].SpoofRetValue;

                            /* Jump directly back to caller (skip function body) */
                            __vmx_vmwrite(VMCS_GUEST_RIP, (SIZE_T)retaddr);
                            __vmx_vmwrite(VMCS_GUEST_RSP, (SIZE_T)(guestRsp + 8));

                            /* Switch back to primary EPT so the caller
                             * runs under normal (non-hook-shadow) view. */
                            if (g_Shv.PrimaryEptp != 0) {
                                __vmx_vmwrite(VMCS_CTRL_EPTP, g_Shv.PrimaryEptp);
                                INVEPT_DESCRIPTOR desc = {0};
                                desc.EptPointer = g_Shv.PrimaryEptp;
                                ShvInvept(INVEPT_SINGLE_CONTEXT, &desc);
                            }

                            InterlockedIncrement(
                                (volatile LONG*)&g_Shv.EptHookExtra[cpuidHookIdx].SpoofHits);

                            break;  /* Done — no MTF, no re-arm */
                        }
                        /* Safe-read failed → fall through to LOG path
                         * so the function runs normally and we don't
                         * crash the guest with a bad RIP jump. */
                    }
                    /* HOOK_KIND_LOG (and future kinds not handled yet):
                     * fall through to existing logging path below. */
                }

                /* Caller-filtered logging (same as the old #BP path) */
                {
                    SIZE_T guestRsp = 0;
                    SIZE_T cr3 = 0;
                    __vmx_vmread(VMCS_GUEST_RSP, &guestRsp);
                    __vmx_vmread(VMCS_GUEST_CR3, &cr3);

                    /* DISABLED: [RSP] safe read — TOCTOU races at HIGH_IRQL
                     * can BSOD even with MmIsAddressValid belt-and-suspenders.
                     * User-mode can read via backdoor post-capture (accepting
                     * stale/freed stack risk). */
                    ULONG64 callerRip = 0;
                    ULONG32 captureFlags = 0;

                    BOOLEAN skipCaller = FALSE;
                    if (g_Shv.TraceSkipCount > 0 && callerRip != 0) {
                        for (ULONG sk = 0; sk < g_Shv.TraceSkipCount && sk < TRACE_SKIP_MAX; sk++) {
                            if (callerRip == g_Shv.TraceSkipCallers[sk]) {
                                skipCaller = TRUE;
                                InterlockedIncrement(&g_Shv.TraceSkipHits);
                                break;
                            }
                        }
                    }

                    BOOLEAN shouldLog = !skipCaller;
                    ULONG64 filterBase = g_Shv.TraceFilterBase;
                    ULONG64 filterEnd  = g_Shv.TraceFilterEnd;

                    /* Dual-mode filter:
                     *   - If filterBase >= 0xFFFF800000000000 (canonical
                     *     kernel VA): treat as CallerRip range filter.
                     *   - If filterBase < 0xFFFF800000000000 but non-zero:
                     *     treat as CR3 match filter (for user-mode process
                     *     hooking like GameService.exe). */
                    if (shouldLog && filterBase != 0) {
                        if (filterBase >= 0xFFFF800000000000ULL) {
                            /* RIP range mode (original behavior) */
                            if (filterEnd != 0 && callerRip != 0 &&
                                (callerRip < filterBase || callerRip >= filterEnd)) {
                                shouldLog = FALSE;
                                InterlockedIncrement(&g_Shv.SyscallLogFiltered);
                            }
                        } else {
                            /* CR3 match mode — filterBase holds target process CR3.
                             * Guest CR3 must match exactly to log. */
                            if ((ULONG64)cr3 != filterBase) {
                                shouldLog = FALSE;
                                InterlockedIncrement(&g_Shv.SyscallLogFiltered);
                            }
                        }
                    }

                    if (shouldLog && g_Shv.SyscallLog != NULL) {
                        LONG total = InterlockedIncrement(&g_Shv.SyscallLogTotal);
                        LONG slot = InterlockedIncrement(&g_Shv.SyscallLogIndex) - 1;
                        slot = slot % SYSCALL_LOG_MAX;
                        if (slot < 0) slot += SYSCALL_LOG_MAX;

                        PSYSCALL_LOG_ENTRY entry = &g_Shv.SyscallLog[slot];
                        entry->CallerRip  = callerRip;
                        entry->TargetVa   = g_Shv.EptHooks[cpuidHookIdx].TargetVa;
                        entry->GuestCr3   = (ULONG64)cr3;
                        entry->Arg1       = GuestContext->Rcx;
                        entry->Arg2       = GuestContext->Rdx;
                        entry->Arg3       = GuestContext->R8;
                        entry->Arg4       = GuestContext->R9;
                        entry->Rax        = GuestContext->Rax;
                        entry->Rbx        = GuestContext->Rbx;
                        entry->HookIndex  = (ULONG32)cpuidHookIdx;
                        entry->CpuIndex   = Vcpu->ProcessorIndex;
                        entry->Counter    = (ULONG32)total;

                        /* DISABLED: all guest-memory reads from VMX root.
                         * IRP snapshot, buffer snapshot, CallerRip — any of
                         * these can TOCTOU-race and BSOD at HIGH_IRQL.
                         * Zero the fields; user-mode reads via backdoor
                         * post-capture (stale-data risk acceptable). */
                        entry->IrpMajorFunction = 0;
                        entry->IrpMinorFunction = 0;
                        entry->IrpFlags         = 0;
                        entry->IrpControl       = 0;
                        entry->IrpIoControlCode = 0;
                        entry->IrpInputLength   = 0;
                        entry->IrpOutputLength  = 0;
                        RtlZeroMemory(entry->BufferSnapshot, sizeof(entry->BufferSnapshot));
                        entry->CaptureFlags = captureFlags;
                    }
                }

                /* Recovery: restore original 2 bytes, single-step, re-arm.
                 * RIP already points to the hook (CPUID is at-instruction,
                 * not past-instruction like INT3). No need to adjust RIP.
                 *
                 * RESOLVER DECODE MODE (hook index 0):
                 * Instead of re-arming after 1 MTF step, chain multiple MTF
                 * single-steps to let the resolver execute fully. After the
                 * resolver RETs and the caller does MOV+XOR, one of the GP
                 * registers will contain the decoded function pointer.
                 * We save ECX at entry and scan registers after ~15 steps. */
                {
                    ULONG32 off = g_Shv.EptHooks[cpuidHookIdx].PageOffset;
                    PUCHAR shadow = (PUCHAR)g_Shv.EptHooks[cpuidHookIdx].ShadowVa;
                    shadow[off]     = g_Shv.EptHooks[cpuidHookIdx].OrigBytes[0];
                    shadow[off + 1] = g_Shv.EptHooks[cpuidHookIdx].OrigBytes[1];

                    SIZE_T procBased = 0;
                    __vmx_vmread(VMCS_CTRL_PROC_BASED_EXEC, &procBased);
                    procBased |= (SIZE_T)CPU_BASED_MONITOR_TRAP_FLAG;
                    __vmx_vmwrite(VMCS_CTRL_PROC_BASED_EXEC, procBased);

                    Vcpu->MtfHookRearmPending = TRUE;
                    Vcpu->MtfHookIndex = (ULONG)cpuidHookIdx;

                    /* Resolver decode: hook 0 = the target's IAT resolver. Save ECX and
                     * start multi-step chain (up to 30 MTF single-steps to find
                     * a call/jmp rXX in the resolver body).
                     *
                     * HV-3 gate (Apr 2026): resolver-decode ONLY fires when a
                     * trace filter is configured (TraceFilterBase != 0).
                     * Without a filter, the 30-MTF single-step chain was running
                     * for every hook fire on slot 0, regardless of whether the
                     * hook was the target's IAT resolver. On a plain --ept-hook test
                     * target (e.g. MmIsDriverVerifyingByAddress during HV-3
                     * validation 2026-04-19) this produced hundreds of thousands
                     * of spurious MTF vmexits, eventually racing into
                     * SYSTEM_THREAD_EXCEPTION_NOT_HANDLED on netadaptercx code
                     * paths. Gating on TraceFilterBase preserves the the target-IAT
                     * flow (always sets a filter) while making non-the target hooks
                     * take the simple 1-step re-arm path. */
                    if (cpuidHookIdx == 0 && g_Shv.TraceFilterBase != 0) {
                        Vcpu->MtfResolverStep = 1;
                        Vcpu->MtfResolverEcx = GuestContext->Rcx;
                        Vcpu->MtfResolverTableVal = 0; /* filled after resolver runs */
                    } else {
                        Vcpu->MtfResolverStep = 0;
                    }
                }

                break;  /* Don't execute real CPUID, don't advance RIP */
            }
        }

        /* ── Magic CPUID leaf: bulk log dump ────────────────────────────
         * RAX = CPUID_LEAF_DUMP_LOG (0x4E585443 "NXTC")
         * RBX = user buffer VA (pre-touched, pages present)
         * RCX = max entry count
         * Returns: RAX = entries copied, RBX = total logged
         *
         * Also freezes hooks (sets TraceAutoStop=1) as a side effect. */
        if ((ULONG32)GuestContext->Rax == CPUID_LEAF_DUMP_LOG) {
            /* Freeze hooks immediately */
            g_Shv.TraceAutoStop = 1;

            /* Buffer VA and max count passed via g_Shv fields (since
             * __cpuidex can only set EAX/ECX, not RBX from user mode).
             * TraceFilterBase = buffer VA, TraceFilterEnd = max count. */
            ULONG64 bufVa   = g_Shv.TraceFilterBase;
            ULONG64 maxCnt  = g_Shv.TraceFilterEnd;
            ULONG64 copied  = 0;

            if (g_Shv.SyscallLog != NULL && bufVa != 0 && maxCnt > 0) {
                ULONG count = (ULONG)g_Shv.SyscallLogTotal;
                if (count > SYSCALL_LOG_MAX) count = SYSCALL_LOG_MAX;
                if (count > (ULONG)maxCnt) count = (ULONG)maxCnt;

                /* STAC: allow supervisor access to user-mode pages (SMAP) */
                _stac();
                RtlCopyMemory(
                    (PVOID)bufVa,
                    g_Shv.SyscallLog,
                    count * sizeof(SYSCALL_LOG_ENTRY)
                );
                _clac();

                copied = count;
            }

            GuestContext->Rax = copied;
            GuestContext->Rbx = (ULONG64)g_Shv.SyscallLogTotal;
            GuestContext->Rcx = 0;
            GuestContext->Rdx = 0;
            ShvAdvanceGuestRip();
            break;
        }

        /* Normal CPUID — not a hook */
        ShvHandleCpuid(GuestContext);
        ShvAdvanceGuestRip();
        break;

    case EXIT_REASON_MSR_READ:
        ShvHandleMsrRead(GuestContext);
        ShvAdvanceGuestRip();
        break;

    case EXIT_REASON_MSR_WRITE:
        {
            ShvHandleMsrWrite(GuestContext);
            /* If WRMSR rejected the value with #GP injection, do NOT
             * advance RIP. Same pattern as XSETBV. */
            SIZE_T entryInfo = 0;
            __vmx_vmread(VMCS_CTRL_VMENTRY_INTERRUPTION_INFO, &entryInfo);
            if (((ULONG32)entryInfo & INT_INFO_VALID) == 0) {
                ShvAdvanceGuestRip();
            }
        }
        break;

    case EXIT_REASON_CR_ACCESS:
        InterlockedIncrement(&Vcpu->ExitCrAccess);
        ShvHandleCrAccess(GuestContext);
        ShvAdvanceGuestRip();
        break;

    case 29:  /* EXIT_REASON_DR_ACCESS — spoof DR0-3 reads when DR-trap installed.
               *
               * Themida's anti-debug reads DR0-3 to detect our HW breakpoint.
               * When MOV-DR exiting is enabled, every guest `mov r, drN` VM-exits
               * here. We return 0 for DR0-3 reads if DrTrapInstalled, masking our
               * trap from Themida. TSC compensation hides the VM-exit overhead
               * so RDTSC-around-DR timing probes don't detect the HV.
               *
               * Exit qualification layout:
               *   bits 0-2:  DR number (0-7)
               *   bit 4:     direction (0=write to DR, 1=read from DR)
               *   bits 8-11: GP register index (0=RAX, 1=RCX, 2=RDX, 3=RBX,
               *              4=RSP, 5=RBP, 6=RSI, 7=RDI, 8-15=R8-R15)
               */
        {
            SIZE_T qual = 0;
            __vmx_vmread(VMCS_RO_EXIT_QUALIFICATION, &qual);
            ULONG32 drNum    = (ULONG32)(qual & 0x7);
            ULONG32 dir      = (ULONG32)((qual >> 4) & 0x1);   /* 1 = read */
            ULONG32 gpRegIdx = (ULONG32)((qual >> 8) & 0xF);

            /* CRITICAL: MOV-DR is privileged (CPL=0 only). If guest is in
             * user mode (CPL=3), bare metal would #GP. Themida exploits this
             * by trying `mov rax, dr0` from CPL=3 and catching #GP via SEH —
             * if no #GP fires, HV present. We MUST inject #GP for non-CPL0
             * to mimic bare metal exactly. */
            SIZE_T csSel = 0;
            __vmx_vmread(VMCS_GUEST_CS_SELECTOR, &csSel);
            ULONG cpl = (ULONG)(csSel & 0x3);
            if (cpl != 0) {
                ShvInjectException(VECTOR_GP, 0);
                /* Do NOT advance RIP - exception delivery handles that */
                /* TSC compensation: even the failure path costs cycles */
                {
                    SIZE_T tsc_off = 0;
                    __vmx_vmread(VMCS_CTRL_TSC_OFFSET, &tsc_off);
                    tsc_off -= 2500;
                    __vmx_vmwrite(VMCS_CTRL_TSC_OFFSET, tsc_off);
                }
                break;
            }

            BOOLEAN drSpoofActive = (g_Shv.DrTrapInstalled != 0) ||
                                    (g_Shv.ForkCapArmed && !g_Shv.ForkCapAllFired);
            if (dir == 1 && drSpoofActive &&
                (drNum <= 3 || drNum == 6 || drNum == 7)) {
                /* Read of DR0-3, DR6, or DR7 while DR-trap or ForkCap armed → return
                 * a "clean" value matching what the guest THINKS is in DR.
                 * For DR0-3 we return the per-VCPU GuestIntendedDr[] value
                 * (what the guest most recently wrote, OR 0 if never written).
                 * This defeats Themida's write-then-read-DR0 verification AND
                 * a KM ring-0 DR7 read (which would see G0=1 and block DllMain).
                 *
                 * Spoofed values:
                 *   DR0-3: GuestIntendedDr[drNum] (what guest wrote, or 0 default)
                 *   DR6:   0xFFFF0FF0 (default reset value, no debug events)
                 *   DR7:   0x400 (default reset value, no breakpoints enabled)
                 */
                ULONG64 spoofedValue;
                if (drNum <= 3) spoofedValue = Vcpu->GuestIntendedDr[drNum];
                else if (drNum == 6) spoofedValue = 0xFFFF0FF0;
                else spoofedValue = 0x400;  /* DR7 */

                /* Map gpRegIdx to GuestContext field. RSP is special. */
                ULONG64* gpRegs[16] = {
                    &GuestContext->Rax, &GuestContext->Rcx,
                    &GuestContext->Rdx, &GuestContext->Rbx,
                    NULL,  /* RSP — handled below */
                    &GuestContext->Rbp, &GuestContext->Rsi,
                    &GuestContext->Rdi, &GuestContext->R8,
                    &GuestContext->R9,  &GuestContext->R10,
                    &GuestContext->R11, &GuestContext->R12,
                    &GuestContext->R13, &GuestContext->R14,
                    &GuestContext->R15
                };

                if (gpRegIdx == 4) {
                    /* RSP target — write to VMCS guest RSP */
                    __vmx_vmwrite(VMCS_GUEST_RSP, spoofedValue);
                } else if (gpRegs[gpRegIdx] != NULL) {
                    *gpRegs[gpRegIdx] = spoofedValue;
                }
                InterlockedIncrement(&g_Shv.DrTrapMisses);  /* repurpose as spoof count */
            } else {
                /* Pass through: actually execute the DR access. For reads,
                 * we already left the value in the DR; for writes, we'd need
                 * to actually write the DR. Simplest: just don't intercept
                 * what we don't care about. Cleanest is to emulate. */
                if (dir == 0) {
                    /* MOV to DR: read source register, write to actual DR */
                    ULONG64 srcVal = 0;
                    if (gpRegIdx == 4) {
                        __vmx_vmread(VMCS_GUEST_RSP, &srcVal);
                    } else {
                        ULONG64* srcs[16] = {
                            &GuestContext->Rax, &GuestContext->Rcx,
                            &GuestContext->Rdx, &GuestContext->Rbx,
                            NULL,
                            &GuestContext->Rbp, &GuestContext->Rsi,
                            &GuestContext->Rdi, &GuestContext->R8,
                            &GuestContext->R9,  &GuestContext->R10,
                            &GuestContext->R11, &GuestContext->R12,
                            &GuestContext->R13, &GuestContext->R14,
                            &GuestContext->R15
                        };
                        if (srcs[gpRegIdx]) srcVal = *srcs[gpRegIdx];
                    }
                    /* Actually write the DR. Note: if we have a DR-trap or ForkCap,
                     * we SKIP writes to DR0-3 and DR7 — preserves our trap config.
                     * Save guest's intended DR0-3 value so subsequent reads
                     * return what the guest expects (write-then-read pattern).
                     * DR7 writes silently dropped (we keep our G0=1 setup). */
                    if (drSpoofActive && (drNum <= 3 || drNum == 7)) {
                        if (drNum <= 3) {
                            Vcpu->GuestIntendedDr[drNum] = srcVal;
                        }
                        /* SKIP the actual __writedr — preserve our trap. */
                    } else {
                        switch (drNum) {
                            case 0: __writedr(0, srcVal); break;
                            case 1: __writedr(1, srcVal); break;
                            case 2: __writedr(2, srcVal); break;
                            case 3: __writedr(3, srcVal); break;
                            case 6: __writedr(6, srcVal); break;
                            case 7: __writedr(7, srcVal); break;
                        }
                    }
                } else {
                    /* MOV from DR with no trap (or DR4-7) — return real value */
                    ULONG64 actualValue = 0;
                    switch (drNum) {
                        case 0: actualValue = __readdr(0); break;
                        case 1: actualValue = __readdr(1); break;
                        case 2: actualValue = __readdr(2); break;
                        case 3: actualValue = __readdr(3); break;
                        case 6: actualValue = __readdr(6); break;
                        case 7: actualValue = __readdr(7); break;
                    }
                    ULONG64* gpRegs2[16] = {
                        &GuestContext->Rax, &GuestContext->Rcx,
                        &GuestContext->Rdx, &GuestContext->Rbx,
                        NULL,
                        &GuestContext->Rbp, &GuestContext->Rsi,
                        &GuestContext->Rdi, &GuestContext->R8,
                        &GuestContext->R9,  &GuestContext->R10,
                        &GuestContext->R11, &GuestContext->R12,
                        &GuestContext->R13, &GuestContext->R14,
                        &GuestContext->R15
                    };
                    if (gpRegIdx == 4) {
                        __vmx_vmwrite(VMCS_GUEST_RSP, actualValue);
                    } else if (gpRegs2[gpRegIdx]) {
                        *gpRegs2[gpRegIdx] = actualValue;
                    }
                }
            }
            /* TSC compensation: subtract VM-exit roundtrip cost so the
             * guest's RDTSC delta around this MOV-DR looks bare-metal (~5
             * cycles) instead of inflated by the VM-exit (~2500 cycles).
             * Themida's RDTSC-around-DR probes won't detect the HV. */
            {
                SIZE_T tsc_off = 0;
                __vmx_vmread(VMCS_CTRL_TSC_OFFSET, &tsc_off);
                tsc_off -= 2500;
                __vmx_vmwrite(VMCS_CTRL_TSC_OFFSET, tsc_off);
            }
            ShvAdvanceGuestRip();
        }
        break;

    case EXIT_REASON_XSETBV:
        {
            /* Snapshot the entry-interruption-info VALID bit to detect whether
             * the handler injected an exception. If injected, do NOT advance
             * RIP — the exception delivery semantics push the original RIP
             * onto the guest stack and the handler resumes at the right
             * place (after IRET, NOT after XSETBV). */
            ShvHandleXsetbv(GuestContext);
            SIZE_T entryInfo = 0;
            __vmx_vmread(VMCS_CTRL_VMENTRY_INTERRUPTION_INFO, &entryInfo);
            if (((ULONG32)entryInfo & INT_INFO_VALID) == 0) {
                ShvAdvanceGuestRip();
            }
        }
        break;

    case EXIT_REASON_HLT:
        /* HLT exiting: execute real HLT in VMX root (enters C1, safe).
         * This prevents deep C-states (C6/C7) that destroy VMX state. */
        __halt();
        ShvAdvanceGuestRip();
        break;

    case EXIT_REASON_MWAIT:
        /* MWAIT exiting: skip the MWAIT (advance past it).
         * MWAIT with deep C-state hints can power down the core and
         * destroy VMX state on Arrow Lake. Skipping it makes the idle
         * loop spin back and try again (eventually hitting HLT). */
        ShvAdvanceGuestRip();
        break;

    case EXIT_REASON_INVD:
        ShvHandleInvd();
        ShvAdvanceGuestRip();
        break;

    case EXIT_REASON_VMCALL:
        if (ShvHandleVmcall(GuestContext, Vcpu)) {
            /* Devirtualize: do NOT vmresume */
            return TRUE;
        }
        {
            /* Item #6 — VMCALL handlers may inject #UD on bad-cookie or
             * unknown command. If injected, the exception delivery path
             * advances RIP for us; do NOT call ShvAdvanceGuestRip. */
            SIZE_T entryInfo = 0;
            __vmx_vmread(VMCS_CTRL_VMENTRY_INTERRUPTION_INFO, &entryInfo);
            if (((ULONG32)entryInfo & INT_INFO_VALID) == 0) {
                ShvAdvanceGuestRip();
            }
        }
        break;

    case EXIT_REASON_MONITOR_TRAP_FLAG:
        ShvHandleMtfExit(GuestContext, Vcpu);
        /* Do NOT advance RIP — MTF fires after the instruction completes */
        break;

    case EXIT_REASON_EPT_VIOLATION:
        ShvHandleEptViolation(GuestContext, Vcpu);
        /* Do NOT advance RIP — handler injects #GP or handles the fault */
        break;

    case EXIT_REASON_EPT_MISCONFIG:
        ShvHandleEptMisconfig(GuestContext);
        /* Fatal — does not return */
        break;

    case EXIT_REASON_TRIPLE_FAULT:
        ShvHandleTripleFault();
        /* Does not return */
        break;

    case EXIT_REASON_EXTERNAL_INTERRUPT:
        /* Without ACK_INTERRUPT_ON_EXIT, the interrupt is NOT acknowledged
         * during VM-exit. On VMRESUME with guest IF=1, the pending interrupt
         * is delivered to the guest IDT naturally. Nothing to do here. */
        break;

    case EXIT_REASON_EXCEPTION_NMI:
        InterlockedIncrement(&Vcpu->ExitNmi);
        {
        /* Exception or NMI exit. With NMI_EXITING enabled, NMIs come here.
         * Also handles #BP (vector 3) from dual-EPT INT3 hooks. */
        SIZE_T intInfo = 0;
        __vmx_vmread(VMCS_RO_VMEXIT_INTERRUPTION_INFO, &intInfo);

        ULONG32 vector = (ULONG32)(intInfo & 0xFF);
        BOOLEAN valid = (intInfo >> 31) & 1;

        /* ── #DB from DllMain fork-capture DR execute-trap  ─
         * Fires from DR0 (site 0, gsl+0x36A3A7) or DR1 (site 1, gsl+0x28A7314).
         * Captures all 16 GPRs + RSP/RIP/CR3 from GuestContext/VMCS, then reads
         * 2 KB of guest stack in-VMX-root via ForkCapTranslateVa +
         * ShvEptReadPhysicalPage (MmMapIoSpaceEx; same path as EPT_READ_PAGE).
         * Sets RFLAGS.RF so the trapped instruction can complete without re-firing.
         * When both sites are captured, clears ForkCapArmed + DR0/DR1 + exception
         * bitmap so no further #DB overhead is incurred.
         *
         * CR3 filter: if ForkCapTargetCr3 != 0, only capture from that CR3
         * (avoids false fires from other processes sharing a module VA). */
        if (valid && vector == 1 && g_Shv.ForkCapArmed && !g_Shv.ForkCapAllFired) {
            ULONG64 dr6 = __readdr(6);
            /* B0 = bit0 (DR0), B1 = bit1 (DR1) */
            BOOLEAN b0 = (dr6 & 0x1) != 0;
            BOOLEAN b1 = (dr6 & 0x2) != 0;

            if (b0 || b1) {
                ULONG64 guestRip = 0, guestRsp = 0, guestCr3 = 0;
                __vmx_vmread(VMCS_GUEST_RIP, &guestRip);
                __vmx_vmread(VMCS_GUEST_RSP, &guestRsp);
                __vmx_vmread(VMCS_GUEST_CR3, &guestCr3);

                BOOLEAN cr3Match = (g_Shv.ForkCapTargetCr3 == 0 ||
                                    guestCr3 == g_Shv.ForkCapTargetCr3);

                /* Helper macro: populate a record and try stack read */
#define FORK_CAP_FILL(recIdx, drIdx, drBit) \
                if ((dr6 & (drBit)) && g_Shv.ForkCapSiteVa[(recIdx)] != 0 && \
                    !g_Shv.ForkCapRecords[(recIdx)].Fired && cr3Match) { \
                    PDLLMAIN_FORK_RECORD rec = &g_Shv.ForkCapRecords[(recIdx)]; \
                    rec->SiteIndex = (recIdx); \
                    rec->DrNum     = (drIdx); \
                    rec->CpuIndex  = Vcpu->ProcessorIndex; \
                    rec->GuestRip  = guestRip; \
                    rec->GuestCr3  = guestCr3; \
                    rec->Rax = GuestContext->Rax; rec->Rcx = GuestContext->Rcx; \
                    rec->Rdx = GuestContext->Rdx; rec->Rbx = GuestContext->Rbx; \
                    rec->Rsp = guestRsp; \
                    rec->Rbp = GuestContext->Rbp; rec->Rsi = GuestContext->Rsi; \
                    rec->Rdi = GuestContext->Rdi; \
                    rec->R8  = GuestContext->R8;  rec->R9  = GuestContext->R9; \
                    rec->R10 = GuestContext->R10; rec->R11 = GuestContext->R11; \
                    rec->R12 = GuestContext->R12; rec->R13 = GuestContext->R13; \
                    rec->R14 = GuestContext->R14; rec->R15 = GuestContext->R15; \
                    /* Stack: capture DLLMAIN_FORK_STACK_BYTES starting BELOW RSP */ \
                    ULONG64 stackBase = guestRsp - DLLMAIN_FORK_STACK_BELOW; \
                    rec->StackVaBase = stackBase; \
                    rec->StackLen = ForkCapReadGuestStack( \
                        guestCr3, stackBase, rec->Stack, DLLMAIN_FORK_STACK_BYTES); \
                    rec->StackPad = 0; \
                    /* Write Fired LAST — serves as the publication fence */ \
                    InterlockedExchange((volatile LONG*)&rec->Fired, 1); \
                    InterlockedIncrement(&g_Shv.ForkCapHits); \
                    __writedr(6, dr6 & ~(ULONG64)(drBit)); \
                }

                FORK_CAP_FILL(0, 0, 0x1)  /* DR0 → site 0 */
                FORK_CAP_FILL(1, 1, 0x2)  /* DR1 → site 1 */
#undef FORK_CAP_FILL

                /* When all ARMED sites have fired: disarm everything.
                 * A site with SiteVa==0 was never armed (single-site mode)
                 * and counts as "already done". */
                BOOLEAN site0done = (g_Shv.ForkCapSiteVa[0] == 0 || g_Shv.ForkCapRecords[0].Fired);
                BOOLEAN site1done = (g_Shv.ForkCapSiteVa[1] == 0 || g_Shv.ForkCapRecords[1].Fired);
                if (site0done && site1done) {
                    InterlockedExchange(&g_Shv.ForkCapAllFired, 1);
                    InterlockedExchange(&g_Shv.ForkCapArmed, 0);
                    __writedr(0, 0); __writedr(1, 0);
                    __writedr(7, 0x400ULL);
                    __vmx_vmwrite(VMCS_GUEST_DR7, 0x400ULL);
                    SIZE_T excBitmapOff = 0;
                    __vmx_vmread(VMCS_CTRL_EXCEPTION_BITMAP, &excBitmapOff);
                    excBitmapOff &= ~(1ULL << 1);
                    __vmx_vmwrite(VMCS_CTRL_EXCEPTION_BITMAP, excBitmapOff);
                }

                /* Set RFLAGS.RF so the trapped instruction executes once
                 * without re-triggering the #DB. */
                SIZE_T rflagsVal = 0;
                __vmx_vmread(VMCS_GUEST_RFLAGS, &rflagsVal);
                rflagsVal |= 0x10000ULL;  /* RF bit */
                __vmx_vmwrite(VMCS_GUEST_RFLAGS, rflagsVal);
                break;
            }
        }

        /* ── #DB from DR0 read-trap (added) ──────────────
         * If our DR-trap is armed AND the guest #DB came from DR0 (BS bit
         * in DR6 status), log RIP+regs to SyscallLog and resume. RFLAGS.RF
         * must be set so the same instruction doesn't re-trigger.
         *
         * DR6 layout (read on guest #DB):
         *   bits 0-3 = B0-B3 (which DR fired). We use DR0 only -> bit 0.
         *   bit 14 = BS (single-step from RFLAGS.TF; not us)
         *   bit 13 = BD (debug register access; not us)
         */
        if (valid && vector == 1 && g_Shv.DrTrapInstalled) {
            /* Read DR6 to confirm DR0 fired. Reading DR6 from VMX root
             * gets the GUEST's DR6 because debug registers are not
             * automatically save/restored. */
            ULONG64 dr6 = __readdr(6);
            if (dr6 & 0x1) {
                /* Our trap fired. */
                InterlockedIncrement(&g_Shv.DrTrapHits);

                SIZE_T guestRip = 0, guestRsp = 0, cr3 = 0;
                __vmx_vmread(VMCS_GUEST_RIP, &guestRip);
                __vmx_vmread(VMCS_GUEST_RSP, &guestRsp);
                __vmx_vmread(VMCS_GUEST_CR3, &cr3);

                /* Apply CR3 filter if set */
                if (g_Shv.PendingDrTrapCr3 == 0 || (ULONG64)cr3 == g_Shv.PendingDrTrapCr3) {
                    if (g_Shv.SyscallLog != NULL) {
                        LONG total = InterlockedIncrement(&g_Shv.SyscallLogTotal);
                        LONG slot = InterlockedIncrement(&g_Shv.SyscallLogIndex) - 1;
                        slot = slot % SYSCALL_LOG_MAX;
                        if (slot < 0) slot += SYSCALL_LOG_MAX;

                        PSYSCALL_LOG_ENTRY entry = &g_Shv.SyscallLog[slot];
                        entry->CallerRip  = (ULONG64)guestRip;
                        entry->TargetVa   = g_Shv.PendingDrTrapVa;
                        entry->GuestCr3   = (ULONG64)cr3;
                        entry->Arg1       = GuestContext->Rcx;
                        entry->Arg2       = GuestContext->Rdx;
                        entry->Arg3       = GuestContext->R8;
                        entry->Arg4       = GuestContext->R9;
                        entry->Rax        = GuestContext->Rax;
                        entry->Rbx        = GuestContext->Rbx;
                        entry->HookIndex  = 0xDB;          /* magic: DR-trap origin */
                        entry->CpuIndex   = Vcpu->ProcessorIndex;
                        entry->Counter    = (ULONG32)total;
                    }
                }

                /* Clear B0 in DR6 so a future trap can fire */
                __writedr(6, dr6 & ~0x1ULL);

                /* Set RFLAGS.RF so the faulting instruction completes
                 * without re-triggering the breakpoint. */
                SIZE_T rflags = 0;
                __vmx_vmread(VMCS_GUEST_RFLAGS, &rflags);
                rflags |= 0x10000;  /* RF bit */
                __vmx_vmwrite(VMCS_GUEST_RFLAGS, rflags);

                /* Do NOT advance RIP — the hardware re-executes the
                 * trapped instruction with RF=1, which suppresses #DB. */
                break;
            } else {
                /* #DB happened but not from our DR0 — re-inject to guest */
                InterlockedIncrement(&g_Shv.DrTrapMisses);
            }
        }

        /* ── #BP from dual-EPT hook ────────────────────────────────── */
        if (valid && vector == 3) {
            InterlockedIncrement(&g_Shv.BpExitsTotal);
        }
        if (valid && vector == 3 && g_Shv.EptHookCount > 0) {
            SIZE_T guestRip = 0;
            __vmx_vmread(VMCS_GUEST_RIP, &guestRip);

            /* INT3 pushes RIP past the 0xCC byte, so the faulting address
             * is guestRip - 1. Match against our hook table. */
            ULONG64 faultAddr = (ULONG64)guestRip - 1;
            int hookIdx = -1;

            for (ULONG i = 0; i < g_Shv.EptHookCount; i++) {
                if (g_Shv.EptHooks[i].Active &&
                    g_Shv.EptHooks[i].TargetVa == faultAddr) {
                    hookIdx = (int)i;
                    break;
                }
            }

            if (hookIdx >= 0) {
                /* This is our hook. Log the hit. */
                InterlockedIncrement(&g_Shv.EptHookHits);
                InterlockedIncrement(&g_Shv.BpExitsMatched);
                InterlockedIncrement(&g_Shv.SyscallLogAllCalls);

                /* ── Caller-filtered syscall logging ──────────────────────
                 * Read return address from guest [RSP] to identify caller.
                 * If a filter range is set, only log when caller is within
                 * that range (e.g. the target module). If no filter, log all.
                 *
                 * At INT3 entry: RSP → return address (pushed by CALL).
                 * RCX/RDX/R8/R9 = function args (x64 fastcall, pre-prologue).
                 * Kernel stacks are in NonPagedPool — always resident. */
                {
                    SIZE_T guestRsp = 0;
                    SIZE_T cr3 = 0;
                    __vmx_vmread(VMCS_GUEST_RSP, &guestRsp);
                    __vmx_vmread(VMCS_GUEST_CR3, &cr3);

                    /* DISABLED: [RSP] safe read (see primary handler) */
                    ULONG64 callerRip = 0;
                    ULONG32 captureFlags = 0;

                    /* Apply caller filter: skip logging if filter is set
                     * and caller is outside the filter range. */
                    BOOLEAN shouldLog = TRUE;
                    ULONG64 filterBase = g_Shv.TraceFilterBase;
                    ULONG64 filterEnd  = g_Shv.TraceFilterEnd;
                    if (filterBase != 0 && filterEnd != 0) {
                        if (callerRip != 0 && (callerRip < filterBase || callerRip >= filterEnd)) {
                            shouldLog = FALSE;
                            InterlockedIncrement(&g_Shv.SyscallLogFiltered);
                        }
                    }

                    /* Log to syscall trace ring buffer */
                    if (shouldLog && g_Shv.SyscallLog != NULL) {
                        LONG total = InterlockedIncrement(&g_Shv.SyscallLogTotal);
                        LONG slot = InterlockedIncrement(&g_Shv.SyscallLogIndex) - 1;
                        slot = slot % SYSCALL_LOG_MAX;
                        if (slot < 0) slot += SYSCALL_LOG_MAX;

                        PSYSCALL_LOG_ENTRY entry = &g_Shv.SyscallLog[slot];
                        entry->CallerRip  = callerRip;
                        entry->TargetVa   = g_Shv.EptHooks[hookIdx].TargetVa;
                        entry->GuestCr3   = (ULONG64)cr3;
                        entry->Arg1       = GuestContext->Rcx;
                        entry->Arg2       = GuestContext->Rdx;
                        entry->Arg3       = GuestContext->R8;
                        entry->Arg4       = GuestContext->R9;
                        entry->Rax        = GuestContext->Rax;
                        entry->Rbx        = GuestContext->Rbx;
                        entry->HookIndex  = (ULONG32)hookIdx;
                        entry->CpuIndex   = Vcpu->ProcessorIndex;
                        entry->Counter    = (ULONG32)total;

                        /* DISABLED: IRP/buffer snapshots (see primary handler) */
                        entry->IrpMajorFunction = 0;
                        entry->IrpMinorFunction = 0;
                        entry->IrpFlags         = 0;
                        entry->IrpControl       = 0;
                        entry->IrpIoControlCode = 0;
                        entry->IrpInputLength   = 0;
                        entry->IrpOutputLength  = 0;
                        RtlZeroMemory(entry->BufferSnapshot, sizeof(entry->BufferSnapshot));
                        entry->CaptureFlags = captureFlags;
                    }

                    /* Also log to FIFO ring buffer for legacy readback */
                    {
                        LONG idx = InterlockedIncrement(&g_Shv.FifoLogTotal) - 1;
                        ULONG fslot = (ULONG)(idx % FIFO_ACCESS_LOG_MAX);
                        g_Shv.FifoLog[fslot].GuestRip = faultAddr;
                        g_Shv.FifoLog[fslot].GuestCr3 = (ULONG64)cr3;
                        g_Shv.FifoLog[fslot].GuestLinearAddr = callerRip;
                        g_Shv.FifoLog[fslot].GpaOffset = g_Shv.EptHooks[hookIdx].PageOffset;
                        g_Shv.FifoLog[fslot].CpuIndex = Vcpu->ProcessorIndex;
                        g_Shv.FifoLog[fslot].AccessType = 0x20;  /* Hook hit */
                        g_Shv.FifoLog[fslot].Counter = (ULONG32)(idx + 1);
                    }
                }

                /* Recovery: restore original byte in shadow, single-step,
                 * then re-arm INT3.
                 *
                 * 1. Restore original 2 bytes in the shadow page
                 * 2. Set RIP back to faultAddr (re-execute the original instruction)
                 * 3. Stay in secondary EPT (shadow now has real bytes)
                 * 4. Enable MTF for single-step
                 * 5. After MTF: re-write CPUID, switch to primary EPT */
                {
                    ULONG32 off = g_Shv.EptHooks[hookIdx].PageOffset;
                    PUCHAR shadow = (PUCHAR)g_Shv.EptHooks[hookIdx].ShadowVa;
                    shadow[off]     = g_Shv.EptHooks[hookIdx].OrigBytes[0];
                    shadow[off + 1] = g_Shv.EptHooks[hookIdx].OrigBytes[1];

                    __vmx_vmwrite(VMCS_GUEST_RIP, (SIZE_T)faultAddr);

                    SIZE_T procBased = 0;
                    __vmx_vmread(VMCS_CTRL_PROC_BASED_EXEC, &procBased);
                    procBased |= (SIZE_T)CPU_BASED_MONITOR_TRAP_FLAG;
                    __vmx_vmwrite(VMCS_CTRL_PROC_BASED_EXEC, procBased);

                    Vcpu->MtfHookRearmPending = TRUE;
                    Vcpu->MtfHookIndex = (ULONG)hookIdx;
                }

                break;  /* Don't re-inject #BP */
            }
        }

        /* ── Not our hook — track unmatched #BP ────────────────────── */
        if (valid && vector == 3 && g_Shv.EptHookCount > 0) {
            InterlockedIncrement(&g_Shv.BpExitsUnmatched);
            /* Log unmatched #BP RIP to first available FIFO slot */
            SIZE_T unmRip = 0;
            __vmx_vmread(VMCS_GUEST_RIP, &unmRip);
            SIZE_T unmCr3 = 0;
            __vmx_vmread(VMCS_GUEST_CR3, &unmCr3);
            LONG idx = InterlockedIncrement(&g_Shv.FifoLogTotal) - 1;
            ULONG slot = (ULONG)(idx % FIFO_ACCESS_LOG_MAX);
            g_Shv.FifoLog[slot].GuestRip = (ULONG64)unmRip;
            g_Shv.FifoLog[slot].GuestCr3 = (ULONG64)unmCr3;
            g_Shv.FifoLog[slot].GuestLinearAddr = (ULONG64)unmRip - 1;
            g_Shv.FifoLog[slot].GpaOffset = 0;
            g_Shv.FifoLog[slot].CpuIndex = Vcpu->ProcessorIndex;
            g_Shv.FifoLog[slot].AccessType = 0x30;  /* Unmatched #BP */
            g_Shv.FifoLog[slot].Counter = (ULONG32)(idx + 1);
        }

        /* ── Re-inject exception/NMI to guest ──────────────────────── */
        if (valid) {
            __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFO, (ULONG32)intInfo);
            if (intInfo & (1ULL << 11)) {
                SIZE_T errCode = 0;
                __vmx_vmread(VMCS_RO_VMEXIT_INTERRUPTION_ERROR, &errCode);
                __vmx_vmwrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR, (ULONG32)errCode);
            }
        }
        break;
    }

    case 67:  /* EXIT_REASON_UMWAIT — Arrow Lake+ power-efficient wait */
    case 68:  /* EXIT_REASON_TPAUSE — Arrow Lake+ timed pause */
        ShvHandleUmwaitTpause();
        ShvAdvanceGuestRip();
        break;

    /* ── VMX-instruction guest probes (item #6) ─────────────────────────
     * Javelin's KM scan found 3× VMXOFF + 10× VMCALL + 2× VMLAUNCH +
     * 1× VMRESUME presence-detect sites. On bare metal (no VMX-on),
     * every one of these instructions raises #UD. Our HV traps them
     * because we're in VMX root. The CORRECT handling is to inject #UD
     * back into the guest — making the system look exactly like a
     * non-virtualized box. NEVER actually execute the VMX op (would
     * tear down our own HV) and NEVER fall through to the default
     * emergency-devirtualize path.
     *
     * VMCALL is special: it has its own exit reason and is gated by
     * the R10/R11/R12 signature in exit_vmcall.c — that's already
     * handled. VMCALL exits with non-matching signature should also
     * inject #UD; verify exit_vmcall.c does that.
     *
     * Note: with the VMCS exec-controls correctly configured, VMXON
     * (27) outside VMX-non-root would actually #UD natively without
     * exiting. But we still list it for safety. */
    case EXIT_REASON_VMCLEAR:    /* 19 */
    case EXIT_REASON_VMLAUNCH:   /* 20 */
    case EXIT_REASON_VMPTRLD:    /* 21 */
    case EXIT_REASON_VMPTRST:    /* 22 */
    case EXIT_REASON_VMREAD:     /* 23 */
    case EXIT_REASON_VMRESUME:   /* 24 */
    case EXIT_REASON_VMWRITE:    /* 25 */
    case EXIT_REASON_VMXOFF:     /* 26 */
    case EXIT_REASON_VMXON:      /* 27 */
    case EXIT_REASON_INVEPT:     /* 50 */
    case EXIT_REASON_INVVPID:    /* 53 */
        InterlockedIncrement(&Vcpu->ExitOther);
        /* Do NOT execute the operation. Inject #UD; the exception
         * delivery semantics push the original RIP onto the guest
         * stack, so we MUST NOT advance RIP here. */
        ShvInjectException(VECTOR_UD, 0);
        break;

    default: {
        InterlockedIncrement(&Vcpu->ExitOther);
        /*
         * Unhandled exit reason — emergency devirtualize instead of bugcheck.
         * Save diagnostic data in VCPU, then VMXOFF + return to guest.
         * The guest continues without VMX, and DriverEntry can read the data.
         */
        InterlockedExchange(&Vcpu->ExitLastReason, (LONG)basicReason);

        SIZE_T guestRip = 0, guestRsp = 0, guestRflags = 0;
        __vmx_vmread(VMCS_GUEST_RIP, &guestRip);
        __vmx_vmread(VMCS_GUEST_RSP, &guestRsp);
        __vmx_vmread(VMCS_GUEST_RFLAGS, &guestRflags);

        Vcpu->VmxActive = FALSE;
        Vcpu->Launched = FALSE;

        /* Emergency devirtualize: VMXOFF and return to guest code */
        ShvVmxOffAndRestore(
            (ULONG64)guestRip,
            (ULONG64)guestRsp,
            (ULONG64)guestRflags,
            0  /* RAX = 0 */
        );
        /* Does not return */
        break;
    }
    }

    return FALSE;
}
