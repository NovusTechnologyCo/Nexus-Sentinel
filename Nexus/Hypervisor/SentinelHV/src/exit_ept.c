/**
 * @file exit_ept.c
 * @brief EPT violation and misconfiguration VM-exit handlers.
 *
 * Handles two EPT-related exit reasons:
 *
 *   - **EPT Violation (48)**: A guest memory access violated EPT permissions.
 *     Two cases:
 *       1. FIFO page (0xFED10000): The TPM FIFO read-trap intentionally
 *          removes the Read bit from this 4KB PTE. On violation, the handler
 *          logs the access (RIP, CR3, GPA offset, CPU#), temporarily restores
 *          the Read bit, and enables Monitor Trap Flag (MTF) for single-step.
 *          The guest re-executes the faulting read (reading spoofed shadow data),
 *          then the MTF exit re-arms the trap. Does NOT advance RIP.
 *       2. All other addresses: unexpected in identity-map mode. Logs
 *          diagnostics and injects #GP(0) into the guest.
 *
 *   - **EPT Misconfiguration (49)**: An EPT entry has an illegal bit
 *     combination (e.g., write-only without read, reserved bits set, invalid
 *     memory type). This always indicates a bug in EPT construction and is
 *     fatal -- the handler logs the faulting GPA and triggers a bugcheck.
 *
 *   - **MTF Exit (37)**: Fires after a single guest instruction completes
 *     when Monitor Trap Flag was enabled by the FIFO violation handler.
 *     Disables MTF and re-removes the Read bit from the FIFO PTE.
 */

#include "shv.h"

/* Physical address range of the TPM FIFO page */
#define TPM_FIFO_PAGE_BASE  0xFED10000ULL
#define TPM_FIFO_PAGE_MASK  (~0xFFFULL)

/* MTF bit in primary processor-based VM-execution controls */
#define CPU_BASED_MONITOR_TRAP_FLAG  (1UL << 27)

/* ── FIFO Access Logger ─────────────────────────────────────────── */

/**
 * @brief Log a FIFO page access to the global ring buffer.
 *
 * Records the guest RIP, CR3, GLA, GPA offset, CPU index, and access type
 * into the next slot of the FIFO_ACCESS_LOG ring buffer in g_Shv.
 * Thread-safe via InterlockedIncrement on the index.
 *
 * @param guestRip         Guest instruction pointer.
 * @param guestCr3         Guest CR3 (page table base).
 * @param guestLinearAddr  Guest linear address used for the access.
 * @param gpaOffset        Offset within the FIFO page (0x000-0xFFF).
 * @param cpuIndex         Logical processor number.
 * @param accessType       Access type flags (Read=1, Write=2, Execute=4).
 */
static void
ShvLogFifoAccess(
    _In_ ULONG64 guestRip,
    _In_ ULONG64 guestCr3,
    _In_ ULONG64 guestLinearAddr,
    _In_ ULONG32 gpaOffset,
    _In_ ULONG32 cpuIndex,
    _In_ ULONG32 accessType
    )
{
    LONG total = InterlockedIncrement(&g_Shv.FifoLogTotal);
    LONG slot = InterlockedIncrement(&g_Shv.FifoLogIndex) - 1;
    slot = slot % FIFO_ACCESS_LOG_MAX;
    if (slot < 0) slot += FIFO_ACCESS_LOG_MAX;

    PFIFO_ACCESS_LOG_ENTRY entry = &g_Shv.FifoLog[slot];
    entry->GuestRip = guestRip;
    entry->GuestCr3 = guestCr3;
    entry->GuestLinearAddr = guestLinearAddr;
    entry->GpaOffset = gpaOffset;
    entry->CpuIndex = cpuIndex;
    entry->AccessType = accessType;
    entry->Counter = (ULONG32)total;
}

/* ── EPT Violation Handler ───────────────────────────────────────── */

/**
 * @brief Handle an EPT violation VM-exit.
 *
 * If the faulting GPA is in the TPM FIFO page (0xFED10000-0xFED10FFF) and
 * the FIFO trap is active, this is an intentional read-trap:
 *   1. Log the access (RIP, CR3, GLA, GPA offset, CPU#, access type).
 *   2. Temporarily restore Read on the FIFO EPT PTE.
 *   3. Enable Monitor Trap Flag (MTF) in VMCS proc-based controls.
 *   4. Set MtfFifoRearmPending on the VCPU.
 *   5. Return without advancing RIP — the guest re-executes the faulting
 *      instruction, which now succeeds (reading from the shadow buffer).
 *   6. The CPU fires an MTF exit after that one instruction.
 *
 * For all other EPT violations, logs diagnostics and injects #GP(0).
 *
 * @param GuestContext  Guest registers (unused for FIFO path).
 * @param Vcpu          Per-CPU data (MtfFifoRearmPending set for FIFO path).
 */
void
ShvHandleEptViolation(
    _Inout_ PGUEST_CONTEXT GuestContext,
    _In_    PVCPU_DATA Vcpu
    )
{
    UNREFERENCED_PARAMETER(GuestContext);

    SIZE_T exitQualification = 0;
    SIZE_T guestPhysicalAddr = 0;
    SIZE_T guestRip = 0;
    SIZE_T guestLinearAddr = 0;
    SIZE_T guestCr3 = 0;

    __vmx_vmread(VMCS_RO_EXIT_QUALIFICATION, &exitQualification);
    __vmx_vmread(VMCS_RO_GUEST_PHYSICAL_ADDR, &guestPhysicalAddr);
    __vmx_vmread(VMCS_GUEST_RIP, &guestRip);
    __vmx_vmread(VMCS_GUEST_CR3, &guestCr3);

    /* Guest linear address is valid if bit 7 of exit qualification is set */
    if (exitQualification & EPT_VIOLATION_GLA_VALID) {
        __vmx_vmread(VMCS_RO_GUEST_LINEAR_ADDR, &guestLinearAddr);
    }

    /* Count EVERY EPT violation while xcap is active, regardless of type
     * (read / write / execute / FIFO / hook / xcap / unknown). This is
     * the "is the EPT walker producing any faults at all" diagnostic. */
    if (g_Shv.XcapActive) {
        InterlockedIncrement(&g_Shv.XcapTotalEptViolations);
    }

    /* ── Dual-EPT hook switching (GPA-matched, not generic) ──────────── */
    /* Only fires for pages registered in the hook table. When no hooks are
     * installed (EptHookCount == 0), this entire block is skipped.
     *
     * PRIMARY EPT: hooked page is RW (no X) → execute violation → switch to SECONDARY
     * SECONDARY EPT: hooked page is X-only → read/write violation → switch to PRIMARY
     */
    if (g_Shv.EptHookCount > 0) {
        ULONG64 gpaPage = (ULONG64)guestPhysicalAddr & ~0xFFFULL;
        BOOLEAN isHookedPage = FALSE;

        /* Check if this GPA matches any registered hook (active OR dead).
         * Dead hooks (Active=FALSE after auto-stop) still have modified EPT
         * PTEs (no-X in primary). We must still switch to secondary EPT
         * where the shadow has original bytes — otherwise execution on the
         * page causes #GP injection → BSOD. */
        for (ULONG i = 0; i < g_Shv.EptHookCount; i++) {
            if ((g_Shv.EptHooks[i].TargetPa & ~0xFFFULL) == gpaPage) {
                isHookedPage = TRUE;
                break;
            }
        }

        if (isHookedPage) {
            BOOLEAN isExecuteViolation = (exitQualification & EPT_VIOLATION_INSTRUCTION_FETCH) != 0;

            InterlockedIncrement(&g_Shv.EptHookViolations);

            if (isExecuteViolation) {
                /* Execute on hooked page (PRIMARY) → switch to SECONDARY (shadow with INT3).
                 * CRITICAL: Verify exception bitmap bit 3 is set BEFORE switching.
                 * The shadow page has INT3 at hook points — if bit 3 is NOT set,
                 * INT3 goes to guest IDT → BSOD (SYSTEM_SERVICE_EXCEPTION).
                 * This is the last line of defense against bitmap sync races. */
                {
                    SIZE_T excBitmap = 0;
                    __vmx_vmread(VMCS_CTRL_EXCEPTION_BITMAP, &excBitmap);
                    if (!(excBitmap & (1UL << 3))) {
                        excBitmap |= (1UL << 3);
                        __vmx_vmwrite(VMCS_CTRL_EXCEPTION_BITMAP, excBitmap);
                    }
                }
                InterlockedIncrement(&g_Shv.EptHookSwitchToSec);
                __vmx_vmwrite(VMCS_CTRL_EPTP, g_Shv.SecondaryEptp);
                return;  /* Re-execute instruction under SECONDARY EPT */
            } else {
                /* Read/Write on hooked page (SECONDARY) → switch to PRIMARY (original code) */
                InterlockedIncrement(&g_Shv.EptHookSwitchToPri);
                __vmx_vmwrite(VMCS_CTRL_EPTP, g_Shv.PrimaryEptp);
                return;  /* Re-execute access under PRIMARY EPT */
            }
        }
    }

    /* ── KM Cipher Trap  ────────────────────────────
     * Multi-site exec-trap for the 80 cipher-function exit pages.
     * Runs BEFORE the single-site exec-trap — cipher site PAs are distinct
     * from the single exec-trap target and both checks are O(1)/O(80). */
    if (g_Shv.CipherTrapActive) {
        ULONG consumedC = ShvCipherTrapTryHandle(
            (ULONG64)guestPhysicalAddr,
            (ULONG64)guestRip,
            (ULONG64)guestCr3,
            (ULONG64)exitQualification,
            Vcpu->ProcessorIndex,
            Vcpu,
            GuestContext);
        if (consumedC) {
            return;
        }
    }

    /* ── UM EPT Exec-Trap (Phase C-X v1) ─────────────────────────────
     * Fires on instruction fetches to the armed GPA. Runs BEFORE
     * read/write-trap so that if multiple traps share a page, exec-trap
     * can defer R/W violations (returns 0) and handle pure execs (1). */
    if (g_Shv.ExecTrapActive) {
        ULONG consumedX = ShvEptExecTrapTryHandle(
            (ULONG64)guestPhysicalAddr,
            (ULONG64)guestLinearAddr,
            (ULONG64)guestRip,
            (ULONG64)guestCr3,
            (ULONG64)exitQualification,
            Vcpu->ProcessorIndex,
            Vcpu,
            GuestContext);
        if (consumedX) {
            return;
        }
    }

    /* ── UM EPT Read-Trap (Phase C-R v1) ─────────────────────────────
     * Fires on pure reads to the armed GPA. Runs BEFORE write-trap so
     * that if both are armed on the same page, read-trap can defer to
     * write-trap on write violations (returns 0) and handle pure reads
     * itself (returns 1). See plan §D4/E3. */
    if (g_Shv.ReadTrapActive) {
        ULONG consumed = ShvEptReadTrapTryHandle(
            (ULONG64)guestPhysicalAddr,
            (ULONG64)guestLinearAddr,
            (ULONG64)guestRip,
            (ULONG64)guestCr3,
            (ULONG64)exitQualification,
            Vcpu->ProcessorIndex,
            Vcpu);
        if (consumed) {
            return;
        }
    }

    /* ── UM EPT Write-Trap (Phase C v1) ──────────────────────────────
     * Fires on writes to the armed GPA. CR3 + VA-range + RIP filters
     * in the handler decide whether to log. Always re-arms via MTF.
     * Must run BEFORE the Xcap and FIFO blocks because a write-trap
     * violation on a page that also happens to be xcap-tracked (rare)
     * should be handled by write-trap first. */
    if (g_Shv.WriteTrapActive) {
        ULONG consumed = ShvEptWriteTrapTryHandle(
            (ULONG64)guestPhysicalAddr,
            (ULONG64)guestLinearAddr,
            (ULONG64)guestRip,
            (ULONG64)guestCr3,
            (ULONG64)exitQualification,
            Vcpu->ProcessorIndex,
            Vcpu);
        if (consumed) {
            /* W=1 restored, MTF armed, MtfWriteTrapRearmPending set.
             * Guest re-executes the write, it succeeds, MTF fires,
             * ShvHandleMtfExit re-removes W and disables MTF. */
            return;
        }
    }

    /* ── Xcap (execute-trap page capture) ────────────────────────────── */
    /* When an xcap session is armed, the EPT violation handler is the only
     * place where we get to see "guest is about to execute a freshly
     * decrypted page". The handler copies the now-plaintext 4 KB out, then
     * restores Execute on the PTE so the guest never sees a fault. */
    if (g_Shv.XcapActive &&
        (exitQualification & EPT_VIOLATION_INSTRUCTION_FETCH) != 0) {
        /* Count EVERY execute violation, even ones that don't match an
         * xcap PA. This is the smoking gun for "is the trap mechanism
         * actually being exercised". If XcapAnyExecViolation > 0 but
         * XcapViolationCount == 0, our trap is firing but on PAs we
         * don't have in PaTable (something is splitting the EPT for
         * a different reason and the launcher hits it). If both are 0,
         * Execute=0 PTE writes aren't actually causing faults — bigger
         * problem. */
        InterlockedIncrement(&g_Shv.XcapAnyExecViolation);

        ULONG handled = ShvEptXcapTryCapture(
            (ULONG64)guestPhysicalAddr,
            (ULONG64)guestLinearAddr,
            (ULONG64)guestRip,
            (ULONG64)guestCr3,
            Vcpu->ProcessorIndex);
        if (handled) {
            /* Page captured (or wrong-CR3 skip). Execute is now allowed
             * on this PTE; the guest re-executes the faulting instruction
             * and succeeds. Do NOT advance RIP. */
            return;
        }
    }

    /* ── Check if this is a FIFO page access we intentionally trapped ── */
    if (((ULONG64)guestPhysicalAddr & TPM_FIFO_PAGE_MASK) == TPM_FIFO_PAGE_BASE &&
        g_Shv.FifoTrapActive)
    {
        /* Determine access type from exit qualification */
        ULONG32 accessType = 0;
        if (exitQualification & EPT_VIOLATION_DATA_READ)         accessType |= 1;
        if (exitQualification & EPT_VIOLATION_DATA_WRITE)        accessType |= 2;
        if (exitQualification & EPT_VIOLATION_INSTRUCTION_FETCH) accessType |= 4;

        /* Log the access */
        ULONG32 gpaOffset = (ULONG32)((ULONG64)guestPhysicalAddr & 0xFFF);
        ShvLogFifoAccess(
            (ULONG64)guestRip,
            (ULONG64)guestCr3,
            (ULONG64)guestLinearAddr,
            gpaOffset,
            Vcpu->ProcessorIndex,
            accessType
        );

        /* Temporarily restore Read bit on the FIFO PTE so the guest can
         * re-execute the faulting instruction and read from the shadow buffer. */
        ShvEptFifoRestoreRead();

        /* Enable Monitor Trap Flag (MTF) for single-step.
         * After the guest executes one instruction, we get EXIT_REASON_MONITOR_TRAP_FLAG
         * and can re-arm the trap. */
        SIZE_T procBased = 0;
        __vmx_vmread(VMCS_CTRL_PROC_BASED_EXEC, &procBased);
        procBased |= CPU_BASED_MONITOR_TRAP_FLAG;
        __vmx_vmwrite(VMCS_CTRL_PROC_BASED_EXEC, procBased);

        /* Mark that the MTF exit should re-arm the FIFO trap */
        Vcpu->MtfFifoRearmPending = TRUE;

        /* Do NOT advance RIP — the guest must re-execute the faulting instruction */
        return;
    }

    /* ── All other EPT violations: unexpected, inject #GP(0) ────────── */

    /* Log EPT violation GPA to CMOS for post-mortem analysis */
    ShvCmosWrite(SHV_CMOS_FATAL, 0xEE);  /* 0xEE = EPT violation */
    ShvCmosWrite(SHV_CMOS_RIP0, (UCHAR)guestPhysicalAddr);
    ShvCmosWrite(SHV_CMOS_RIP1, (UCHAR)(guestPhysicalAddr >> 8));
    ShvCmosWrite(SHV_CMOS_RIP2, (UCHAR)(guestPhysicalAddr >> 16));
    ShvCmosWrite(SHV_CMOS_RIP3, (UCHAR)(guestPhysicalAddr >> 24));
    /* Store GPA high bytes in qualification slots */
    ShvCmosWrite(SHV_CMOS_QUAL0, (UCHAR)(guestPhysicalAddr >> 32));
    ShvCmosWrite(SHV_CMOS_QUAL1, (UCHAR)(guestPhysicalAddr >> 40));
    /* Store exit qualification low 2 bytes */
    ShvCmosWrite(SHV_CMOS_RSN16_LO, (UCHAR)exitQualification);
    ShvCmosWrite(SHV_CMOS_RSN16_HI, (UCHAR)(exitQualification >> 8));

    SHV_ERR("EPT VIOLATION: GPA=0x%llX RIP=0x%llX Access: %s%s%s | Entry: %s%s%s",
            (ULONG64)guestPhysicalAddr, (ULONG64)guestRip,
            (exitQualification & EPT_VIOLATION_DATA_READ) ? "R" : "-",
            (exitQualification & EPT_VIOLATION_DATA_WRITE) ? "W" : "-",
            (exitQualification & EPT_VIOLATION_INSTRUCTION_FETCH) ? "X" : "-",
            (exitQualification & EPT_VIOLATION_ENTRY_READABLE) ? "R" : "-",
            (exitQualification & EPT_VIOLATION_ENTRY_WRITABLE) ? "W" : "-",
            (exitQualification & EPT_VIOLATION_ENTRY_EXECUTABLE) ? "X" : "-");

    /*
     * Inject #GP(0) into the guest.
     *
     * VMCS_CTRL_VMENTRY_INTERRUPTION_INFO format:
     *   [7:0]   = Vector (13 = #GP)
     *   [10:8]  = Type (3 = Hardware exception)
     *   [11]    = Error code valid (1 for #GP)
     *   [31]    = Valid (1)
     */
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFO,
                  (1UL << 31) |    /* Valid */
                  (3UL << 8)  |    /* Hardware exception */
                  (1UL << 11) |    /* Error code valid */
                  13);             /* #GP vector */
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR, 0);
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_INSTRUCTION_LEN, 0);

    /* Do NOT advance RIP — the guest will handle #GP at the faulting instruction */
}

/* ── MTF Exit Handler ────────────────────────────────────────────── */

/**
 * @brief Handle Monitor Trap Flag VM-exit (exit reason 37).
 *
 * This fires after the guest has executed exactly one instruction following
 * the FIFO EPT violation handler enabling MTF. The faulting FIFO read has
 * now completed (reading from the shadow buffer). We:
 *   1. Disable MTF in VMCS proc-based controls.
 *   2. Re-remove the Read bit from the FIFO EPT PTE (re-arm the trap).
 *   3. Clear MtfFifoRearmPending on the VCPU.
 *
 * Does NOT advance RIP — MTF fires after instruction completion, and the
 * guest RIP already points to the next instruction.
 *
 * @param GuestContext  Guest registers (unused).
 * @param Vcpu          Per-CPU data with MtfFifoRearmPending flag.
 */
void
ShvHandleMtfExit(
    _Inout_ PGUEST_CONTEXT GuestContext,
    _In_    PVCPU_DATA Vcpu
    )
{
    UNREFERENCED_PARAMETER(GuestContext);

    /* Always disable MTF — it should only be on for one instruction */
    SIZE_T procBased = 0;
    __vmx_vmread(VMCS_CTRL_PROC_BASED_EXEC, &procBased);
    procBased &= ~(SIZE_T)CPU_BASED_MONITOR_TRAP_FLAG;
    __vmx_vmwrite(VMCS_CTRL_PROC_BASED_EXEC, procBased);

    /* Re-arm the FIFO read-trap if this MTF was from a FIFO violation */
    if (Vcpu->MtfFifoRearmPending) {
        Vcpu->MtfFifoRearmPending = FALSE;
        ShvEptFifoRemoveRead();
    }

    /* Re-arm the UM write-trap if this MTF was from a write-trap violation.
     * Paired with the temporary W=1 restore in ShvEptWriteTrapTryHandle.
     * Flip W back to 0 and INVEPT so the next guest write faults. */
    if (Vcpu->MtfWriteTrapRearmPending) {
        Vcpu->MtfWriteTrapRearmPending = FALSE;
        Vcpu->MtfWriteTrapHookIndex = 0;  /* reset for next cycle */
        ShvEptWriteTrapRearm();
    }

    /* Re-arm the UM read-trap if this MTF was from a read-trap violation.
     * Paired with the temporary saved-PTE restore in ShvEptReadTrapTryHandle.
     * Re-clear R/W/X (single qword store) and INVEPT. */
    if (Vcpu->MtfReadTrapRearmPending) {
        Vcpu->MtfReadTrapRearmPending = FALSE;
        Vcpu->MtfReadTrapHookIndex = 0;
        ShvEptReadTrapRearm();
    }

    /* Re-arm the UM exec-trap if this MTF was from an exec-trap violation.
     * Paired with the temporary saved-PTE restore in ShvEptExecTrapTryHandle.
     * Re-clear X only (R/W preserved) via single-qword store + INVEPT. */
    if (Vcpu->MtfExecTrapRearmPending) {
        Vcpu->MtfExecTrapRearmPending = FALSE;
        Vcpu->MtfExecTrapHookIndex = 0;
        ShvEptExecTrapRearm();
    }

    /* Re-arm the KM cipher exec-trap after single-step completes.
     * Paired with the X=1 restore in ShvCipherTrapTryHandle. */
    if (Vcpu->MtfCipherTrapRearmPending) {
        Vcpu->MtfCipherTrapRearmPending = FALSE;
        ShvCipherTrapRearm(Vcpu);
    }

    /* ── RIP-trace step  ─────────────────────────────────
     * If this vcpu is tracing, log GuestRip and keep MTF enabled for
     * the next instruction. Stops when:
     *   - StepsTaken reaches StepsMax (default 5000, cap in shv.h)
     *   - StopOnRange=1 and GuestRip is outside [StopLow, StopHigh]
     *   - CR3 filter is set and current CR3 doesn't match (we still
     *     re-enable MTF so we keep polling, but we don't log — the
     *     guest OS scheduled another thread on this CPU briefly)
     * Also terminates implicitly when the guest context-switches away
     * from this vcpu (TLB flush changes CR3; we skip logging that step
     * but stay armed so we catch the thread when it comes back). */
    if (Vcpu->RipTracePending && g_Shv.RipTraceActive == 1 && g_Shv.RipTraceLog) {
        SIZE_T guestRip = 0, guestCr3 = 0;
        __vmx_vmread(VMCS_GUEST_RIP, &guestRip);
        __vmx_vmread(VMCS_GUEST_CR3, &guestCr3);

        BOOLEAN cr3Match = (g_Shv.RipTraceCr3Filter == 0) ||
                           ((ULONG64)guestCr3 == g_Shv.RipTraceCr3Filter);
        BOOLEAN inRange = TRUE;
        if (g_Shv.RipTraceStopOnRange) {
            inRange = ((ULONG64)guestRip >= g_Shv.RipTraceStopLow &&
                       (ULONG64)guestRip <  g_Shv.RipTraceStopHigh);
        }

        BOOLEAN stop = FALSE;

        if (cr3Match) {
            /* Log this RIP. */
            LONG idx = InterlockedIncrement(&g_Shv.RipTraceLogTotal) - 1;
            LONG slot = idx % RIP_TRACE_LOG_MAX;
            g_Shv.RipTraceLog[slot].GuestRip = (ULONG64)guestRip;
            g_Shv.RipTraceLog[slot].GuestCr3 = (ULONG64)guestCr3;
            InterlockedExchange(&g_Shv.RipTraceLogIndex, slot + 1);

            LONG taken = InterlockedIncrement(&g_Shv.RipTraceStepsTaken);
            ULONG cap = g_Shv.RipTraceStepsMax ? g_Shv.RipTraceStepsMax : 5000;
            if (taken >= (LONG)cap) stop = TRUE;
            if (g_Shv.RipTraceStopOnRange && !inRange) stop = TRUE;
        }
        /* If CR3 didn't match, we're currently on some other thread/
         * process scheduled on this vcpu. Skip logging but keep MTF on
         * so we catch the scanner thread when the scheduler puts it
         * back on this CPU. */

        if (stop) {
            Vcpu->RipTracePending = FALSE;
            InterlockedExchange((volatile LONG*)&g_Shv.RipTraceActive, 0);
            SHV_LOG("RipTrace: stopped on CPU %u, %ld steps total",
                    (ULONG)Vcpu->ProcessorIndex,
                    g_Shv.RipTraceStepsTaken);
        } else {
            /* Keep MTF enabled for next instruction. */
            procBased |= (SIZE_T)CPU_BASED_MONITOR_TRAP_FLAG;
            __vmx_vmwrite(VMCS_CTRL_PROC_BASED_EXEC, procBased);
        }
    }

    /* Re-arm CPUID hook in shadow page after hook single-step completes.
     * The CPUID handler restored the original 2 bytes and enabled MTF.
     * Now that the original instruction has executed, write CPUID back
     * and switch to primary EPT (normal RW, no execute on hook page).
     *
     * AUTO-STOP: If TraceAutoStop > 0 and we've captured enough entries,
     * DON'T re-arm the hook. Leave original bytes in the shadow page.
     * The hook is now permanently dead — no more CPUID triggers on this
     * function. System returns to near-normal performance. */
    if (Vcpu->MtfHookRearmPending) {
        /* ── Resolver decode: multi-step single-stepping ───────────────
         * When MtfResolverStep > 0, we're walking through the resolver
         * body + call site. Keep MTF enabled until we've taken enough
         * steps for the resolver to RET and the caller to XOR.
         *
         * Resolver = ~10 instructions. Call site = ~5 (add rsp, mov, xor,
         * call, etc.). Total ~15. We step 18 times to be safe.
         * On step 18: read all GP registers, find kernel VA, log it.
         * Then fall through to normal re-arm/switch logic. */
        /* ── RESOLVER DECODE MODE — single-step until we see the actual call ──
         *
         * The OLD logic ("step 18 times then scan GP registers for any kernel
         * pointer") was unreliable: ~30% of decoded entries were stale kernel
         * pointers from unrelated registers. Verified by static decoder
         * comparison — see the decoded IAT reference.
         *
         * NEW logic: at every MTF step, peek at the bytes at guest_rip. If the
         * CPU is about to execute `call rXX` or `jmp rXX` (FF /2 or FF /4 with
         * register-direct ModRM), the target register holds the actual decoded
         * function pointer the target is about to call — that's our ground truth.
         * Capture it precisely, with no guessing.
         *
         * Memory access safety: we only read at guest_rip when it's inside the
         * the target range (TraceFilterBase..TraceFilterEnd). That module is loaded
         * as a kernel driver in non-paged memory; its code pages are always
         * present in the host CR3 mapping (which is the kernel CR3 at SentinelHV
         * install time). Reading 3 bytes at a kernel non-paged address from
         * VMX root is safe because no page fault can occur.
         *
         * Step budget: 30 instructions max. The resolver is ~10 instructions,
         * the post-call sequence (add rsp, mov reg rax, xor reg key, ... call
         * reg) is up to ~10 more. 30 leaves headroom for compiler-interleaved
         * code without unbounded stepping.
         */
        if (Vcpu->MtfResolverStep > 0) {
            ULONG64 guestRip = 0;
            __vmx_vmread(VMCS_GUEST_RIP, &guestRip);

            ULONG64 decodedVa = 0;
            BOOLEAN captured = FALSE;

            /* Only read instruction bytes if we're inside the target range */
            if (g_Shv.TraceFilterBase != 0 && g_Shv.TraceFilterEnd != 0 &&
                guestRip >= g_Shv.TraceFilterBase &&
                guestRip + 3 < g_Shv.TraceFilterEnd) {
                volatile PUCHAR ip = (volatile PUCHAR)(ULONG_PTR)guestRip;
                UCHAR b0 = ip[0];
                UCHAR b1 = ip[1];
                UCHAR b2 = ip[2];

                /* Detect call/jmp r/m64 with register-direct ModRM (mod=11).
                 * Encodings:
                 *   FF /2 (call) or FF /4 (jmp), low 8 regs   → 2 bytes
                 *   41 FF /2 or /4, r8..r15                   → 3 bytes (REX.B)
                 *   48 FF /2 or /4, low 8 regs                → 3 bytes (REX.W, harmless)
                 *   49 FF /2 or /4, r8..r15                   → 3 bytes (REX.W+B)
                 */
                UCHAR modrm = 0;
                BOOLEAN highReg = FALSE;
                BOOLEAN isCallOrJmp = FALSE;

                if (b0 == 0xFF) {
                    modrm = b1;
                    isCallOrJmp = TRUE;
                } else if ((b0 == 0x41 || b0 == 0x49) && b1 == 0xFF) {
                    modrm = b2;
                    highReg = TRUE;
                    isCallOrJmp = TRUE;
                } else if (b0 == 0x48 && b1 == 0xFF) {
                    modrm = b2;
                    isCallOrJmp = TRUE;
                }

                if (isCallOrJmp && (modrm & 0xC0) == 0xC0) {
                    UCHAR op = (UCHAR)((modrm >> 3) & 0x7);
                    UCHAR rm = (UCHAR)(modrm & 0x7);
                    if (op == 2 || op == 4) {  /* /2 = call, /4 = jmp */
                        ULONG64 lowRegs[] = {
                            GuestContext->Rax, GuestContext->Rcx, GuestContext->Rdx,
                            GuestContext->Rbx, GuestContext->Rsp, GuestContext->Rbp,
                            GuestContext->Rsi, GuestContext->Rdi
                        };
                        ULONG64 highRegs[] = {
                            GuestContext->R8,  GuestContext->R9,  GuestContext->R10,
                            GuestContext->R11, GuestContext->R12, GuestContext->R13,
                            GuestContext->R14, GuestContext->R15
                        };
                        decodedVa = highReg ? highRegs[rm] : lowRegs[rm];
                        /* Sanity-check: must be a canonical kernel address */
                        if ((decodedVa >> 47) == 0x1FFFF) {
                            captured = TRUE;
                        }
                    }
                }
            }

            if (captured) {
                /* Got the actual function being called — log and end chain */
                if (g_Shv.SyscallLog != NULL) {
                    LONG total = InterlockedIncrement(&g_Shv.SyscallLogTotal);
                    LONG slot = InterlockedIncrement(&g_Shv.SyscallLogIndex) - 1;
                    slot = slot % SYSCALL_LOG_MAX;
                    if (slot < 0) slot += SYSCALL_LOG_MAX;

                    PSYSCALL_LOG_ENTRY entry = &g_Shv.SyscallLog[slot];
                    entry->CallerRip  = decodedVa;          /* decoded function VA */
                    entry->TargetVa   = g_Shv.EptHooks[Vcpu->MtfHookIndex].TargetVa;
                    entry->GuestCr3   = Vcpu->MtfResolverEcx;   /* ECX hash */
                    entry->Arg1       = (ULONG64)guestRip;       /* call site RIP */
                    entry->Arg2       = Vcpu->MtfResolverTableVal; /* enc table val */
                    entry->Arg3       = (ULONG64)Vcpu->MtfResolverStep;
                    entry->Arg4       = 0;
                    entry->HookIndex  = 0xFE;  /* marker: precise resolver decode */
                    entry->CpuIndex   = Vcpu->ProcessorIndex;
                    entry->Counter    = (ULONG32)total;
                    entry->CaptureFlags = 0;
                    entry->IrpMajorFunction = 0;
                    entry->IrpMinorFunction = 0;
                    entry->IrpFlags = 0;
                    entry->IrpControl = 0;
                    entry->IrpIoControlCode = 0;
                    entry->IrpInputLength = 0;
                    entry->IrpOutputLength = 0;
                    RtlZeroMemory(entry->BufferSnapshot, sizeof(entry->BufferSnapshot));
                }
                Vcpu->MtfResolverStep = 0;
                /* Fall through to normal re-arm/switch logic */
            } else if (Vcpu->MtfResolverStep < 30) {
                /* Step 1: capture resolver return value (RAX after the resolver
                 * RETs has the encrypted table[index]). Stash for logging. */
                if (Vcpu->MtfResolverStep == 1) {
                    Vcpu->MtfResolverTableVal = GuestContext->Rax;
                }
                /* Keep stepping */
                Vcpu->MtfResolverStep++;
                SIZE_T procBased2 = 0;
                __vmx_vmread(VMCS_CTRL_PROC_BASED_EXEC, &procBased2);
                procBased2 |= (SIZE_T)CPU_BASED_MONITOR_TRAP_FLAG;
                __vmx_vmwrite(VMCS_CTRL_PROC_BASED_EXEC, procBased2);
                return;  /* stay on secondary EPT, continue single-stepping */
            } else {
                /* Step budget exhausted without finding a call/jmp rXX.
                 * Do NOT log a guess — leave the entry undecoded. The static
                 * decoder will catch it via the static IAT decoder. */
                Vcpu->MtfResolverStep = 0;
                InterlockedIncrement(&g_Shv.SyscallLogFiltered);  /* count exhaustions */
                /* Fall through to re-arm */
            }
        }

        Vcpu->MtfHookRearmPending = FALSE;
        ULONG idx = Vcpu->MtfHookIndex;

        if (idx < g_Shv.EptHookCount && g_Shv.EptHooks[idx].Active) {
            LONG autoStop = (LONG)g_Shv.TraceAutoStop;
            BOOLEAN shouldRearm = TRUE;

            if (autoStop > 0 && g_Shv.SyscallLogAllCalls >= autoStop) {
                /* Auto-stop threshold reached. Don't re-arm CPUID.
                 * Restore ALL hooks at once — not just this one. Other
                 * hooks may still have CPUID in their shadow pages.
                 * Without this, those hooks' CPUIDs fire and fall through
                 * to ShvHandleCpuid → corrupt registers → BSOD 0xFC.
                 *
                 * For each hook: restore original bytes in shadow page
                 * AND restore Execute on primary EPT PTE. This kills all
                 * hooks instantly — no more EPT violations, no more
                 * CPUID triggers from any shadow page. */
                shouldRearm = FALSE;
                {
                    extern NTSTATUS ShvEptRestorePageExecute(ULONG64 targetPa);
                    for (ULONG h = 0; h < g_Shv.EptHookCount; h++) {
                        /* Restore Execute on primary EPT PTE */
                        ShvEptRestorePageExecute(g_Shv.EptHooks[h].TargetPa);
                        /* Restore original bytes in shadow (atomic 16-bit write) */
                        PUCHAR sh = (PUCHAR)g_Shv.EptHooks[h].ShadowVa;
                        ULONG32 soff = g_Shv.EptHooks[h].PageOffset;
                        *(volatile USHORT*)(sh + soff) =
                            *(PUSHORT)g_Shv.EptHooks[h].OrigBytes;
                    }
                }
            }

            if (shouldRearm) {
                /* Re-write CPUID (0F A2) in the shadow page */
                PUCHAR shadow = (PUCHAR)g_Shv.EptHooks[idx].ShadowVa;
                ULONG32 off = g_Shv.EptHooks[idx].PageOffset;
                shadow[off]     = 0x0F;
                shadow[off + 1] = 0xA2;
            }
            /* else: shadow keeps original bytes — hook is dead */

            /* Always switch back to primary EPT */
            if (g_Shv.PrimaryEptp != 0) {
                __vmx_vmwrite(VMCS_CTRL_EPTP, g_Shv.PrimaryEptp);

                INVEPT_DESCRIPTOR desc;
                desc.EptPointer = g_Shv.PrimaryEptp;
                desc.Reserved = 0;
                ShvInvept(INVEPT_SINGLE_CONTEXT, &desc);
            }
        }
    }

    /* Do NOT advance RIP — MTF fires after the instruction completes */
}

/* ── EPT Misconfig Handler ───────────────────────────────────────── */

/**
 * @brief Handle an EPT misconfiguration VM-exit (fatal, does not return).
 *
 * An EPT misconfiguration occurs when an EPT entry has an architecturally
 * invalid combination of bits. Unlike EPT violations (permission failures),
 * misconfigurations mean the EPT entry itself is malformed. This always
 * indicates a bug in the EPT construction code.
 *
 * Logs the faulting guest physical address and guest RIP, then triggers
 * a bugcheck with signature "EPT\\0" and diagnostic data.
 *
 * @param GuestContext  Guest registers (unused).
 */
void
ShvHandleEptMisconfig(
    _Inout_ PGUEST_CONTEXT GuestContext
    )
{
    UNREFERENCED_PARAMETER(GuestContext);

    SIZE_T guestPhysicalAddr = 0;
    SIZE_T guestRip = 0;

    __vmx_vmread(VMCS_RO_GUEST_PHYSICAL_ADDR, &guestPhysicalAddr);
    __vmx_vmread(VMCS_GUEST_RIP, &guestRip);

    SHV_ERR("EPT MISCONFIG: GPA=0x%llX, RIP=0x%llX — BUG in EPT setup!",
            (ULONG64)guestPhysicalAddr,
            (ULONG64)guestRip);

    ShvBugCheck(
        MANUALLY_INITIATED_CRASH,
        0x45505400,         /* "EPT\0" */
        (ULONG64)guestPhysicalAddr,
        (ULONG64)guestRip,
        49                  /* EXIT_REASON_EPT_MISCONFIG */
    );
}
