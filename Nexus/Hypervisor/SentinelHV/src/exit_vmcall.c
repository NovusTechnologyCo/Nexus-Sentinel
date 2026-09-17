/**
 * @file exit_vmcall.c
 * @brief VMCALL VM-exit handler for hypercall command dispatch.
 *
 * Handles EXIT_REASON_VMCALL (18) by reading the command code from guest
 * RCX and the authentication cookie from guest RDX. Supported commands:
 *
 *   - **VMCALL_PING (0x1)**: Returns VMCALL_PING_RESPONSE ("HV_OK") in
 *     guest RAX. Used by user-mode and kernel-mode code to verify that
 *     the hypervisor is active on the current CPU.
 *
 *   - **VMCALL_DEVIRTUALIZE (0xDEADBEEF)**: Validates the magic cookie
 *     (VMCALL_MAGIC_COOKIE = "SHVM"), then exits VMX operation by calling
 *     ShvVmxOffAndRestore. This executes VMXOFF, clears CR4.VMXE, restores
 *     the guest's RSP/RFLAGS, and jumps to the instruction after VMCALL
 *     with STATUS_SUCCESS in RAX. This function does not return.
 *
 *   - **Unknown commands**: Return STATUS_INVALID_PARAMETER in guest RAX.
 *
 * The cookie validation prevents accidental or malicious devirtualization
 * from guest code that happens to execute VMCALL.
 */

#include "shv.h"

/**
 * @brief Dispatch VMCALL hypercall commands.
 *
 * Reads the command from guest RCX and the cookie from guest RDX, then
 * dispatches to the appropriate handler. For devirtualization, validates
 * the magic cookie and calls ShvVmxOffAndRestore (which does not return).
 *
 * @param GuestContext  Guest registers; RCX=command, RDX=cookie, RAX=result.
 * @param Vcpu          Per-CPU data used for logging the processor index.
 * @return TRUE if devirtualization was performed (caller must not VMRESUME).
 *         FALSE for all other commands (caller proceeds with VMRESUME).
 */
BOOLEAN
ShvHandleVmcall(
    _Inout_ PGUEST_CONTEXT GuestContext,
    _In_    PVCPU_DATA Vcpu
    )
{
    ULONG64 command = GuestContext->Rcx;
    ULONG64 cookie = GuestContext->Rdx;

    switch (command) {

    case VMCALL_PING:
        GuestContext->Rax = VMCALL_PING_RESPONSE;
        return FALSE;

    case VMCALL_EPT_REMAP:
        /*
         * EPT page remap: split 2MB page and redirect 4KB page.
         * Guest RDX = targetPa (physical address to remap)
         * Guest R8 = shadowPa (physical address of shadow buffer)
         */
        {
            ULONG64 targetPa = GuestContext->Rdx;
            ULONG64 shadowPa = GuestContext->R8;
            GuestContext->Rax = (ULONG64)ShvEptRemapPage(targetPa, shadowPa);
        }
        return FALSE;

    case VMCALL_INVEPT:
        /*
         * Flush EPT TLB entries (single-context INVEPT).
         * Must run in VMX root mode — guest issues this VMCALL after
         * modifying EPT entries to ensure stale translations are flushed.
         */
        {
            ULONG64 eptp = ShvEptGetEptp();
            if (eptp != 0) {
                INVEPT_DESCRIPTOR desc;
                desc.EptPointer = eptp;
                desc.Reserved = 0;
                UCHAR result = ShvInvept(INVEPT_SINGLE_CONTEXT, &desc);
                GuestContext->Rax = (result == 0) ? (ULONG64)STATUS_SUCCESS
                                                  : (ULONG64)STATUS_UNSUCCESSFUL;
            } else {
                GuestContext->Rax = (ULONG64)STATUS_UNSUCCESSFUL;
            }
        }
        return FALSE;

    case VMCALL_FIFO_TRAP:
        /*
         * Enable or disable the FIFO EPT read-trap.
         * Guest RDX = 1 to enable (arm), 0 to disable (disarm).
         * Runs in VMX root so INVEPT can be issued directly.
         */
        {
            BOOLEAN enable = (GuestContext->Rdx != 0);
            GuestContext->Rax = (ULONG64)ShvEptTrapFifoPage(enable);
        }
        return FALSE;

    case VMCALL_READ_FIFO_LOG:
        /*
         * Read the FIFO access log.
         * Guest RDX = guest VA of output buffer (FIFO_ACCESS_LOG_ENTRY array).
         * Guest R8 = max number of entries the buffer can hold.
         * Returns in RAX: number of entries copied (or total count if buffer is NULL).
         *
         * The log is stored in g_Shv which is in regular kernel memory,
         * so it's also readable directly from kernel mode without a VMCALL.
         * This VMCALL exists for convenience from user-mode via the mapper.
         */
        {
            ULONG64 bufferVa = GuestContext->Rdx;
            ULONG64 maxEntries = GuestContext->R8;
            LONG total = g_Shv.FifoLogTotal;

            if (bufferVa == 0 || maxEntries == 0) {
                /* Just return the total count */
                GuestContext->Rax = (ULONG64)total;
            } else {
                /* Copy entries to the guest buffer */
                ULONG count = (ULONG)total;
                if (count > FIFO_ACCESS_LOG_MAX) count = FIFO_ACCESS_LOG_MAX;
                if (count > (ULONG)maxEntries) count = (ULONG)maxEntries;

                /* The buffer is in guest kernel VA which is also valid in VMX root
                 * (we share the same CR3 for kernel addresses). */
                RtlCopyMemory(
                    (PVOID)bufferVa,
                    g_Shv.FifoLog,
                    count * sizeof(FIFO_ACCESS_LOG_ENTRY)
                );
                GuestContext->Rax = (ULONG64)count;
            }
        }
        return FALSE;

    case VMCALL_READ_SYSCALL_LOG:
        /*
         * Read the syscall trace log.
         * Guest RDX = guest VA of output buffer (SYSCALL_LOG_ENTRY array).
         * Guest R8 = max number of entries the buffer can hold.
         * Returns in RAX: number of entries copied (or total count if buffer is NULL).
         */
        {
            ULONG64 bufferVa = GuestContext->Rdx;
            ULONG64 maxEntries = GuestContext->R8;

            if (g_Shv.SyscallLog == NULL) {
                GuestContext->Rax = 0;
            } else if (bufferVa == 0 || maxEntries == 0) {
                /* Just return the total count */
                GuestContext->Rax = (ULONG64)g_Shv.SyscallLogTotal;
            } else {
                /* Copy entries to the guest buffer */
                ULONG count = (ULONG)g_Shv.SyscallLogTotal;
                if (count > SYSCALL_LOG_MAX) count = SYSCALL_LOG_MAX;
                if (count > (ULONG)maxEntries) count = (ULONG)maxEntries;

                RtlCopyMemory(
                    (PVOID)bufferVa,
                    g_Shv.SyscallLog,
                    count * sizeof(SYSCALL_LOG_ENTRY)
                );
                GuestContext->Rax = (ULONG64)count;
            }
        }
        return FALSE;

    case VMCALL_XCAP_STATUS:
        /* Return xcap diagnostic counters.
         * RAX = captured count, RBX = violation count,
         * RCX = wrong-CR3 count, RDX = active flag */
        GuestContext->Rax = (ULONG64)g_Shv.XcapCapturedCount;
        GuestContext->Rbx = (ULONG64)g_Shv.XcapViolationCount;
        GuestContext->Rcx = (ULONG64)g_Shv.XcapWrongCr3Count;
        GuestContext->Rdx = (ULONG64)g_Shv.XcapActive;
        return FALSE;

    case VMCALL_XCAP_READ:
        /* Read captured xcap pages to a user/kernel buffer.
         * RDX = destination buffer VA
         * R8  = start page index
         * R9  = max pages to read
         * Returns RAX = number of pages actually copied */
        {
            PUCHAR userBuf = (PUCHAR)GuestContext->Rdx;
            ULONG startIdx = (ULONG)GuestContext->R8;
            ULONG maxPages = (ULONG)GuestContext->R9;
            ULONG copied = 0;

            if (userBuf && g_Shv.XcapPageData) {
                for (ULONG i = startIdx; i < startIdx + maxPages && i < XCAP_MAX_PAGES; i++) {
                    ULONG wordIdx = i / 32;
                    ULONG bitIdx = i % 32;
                    if (g_Shv.XcapBitmap[wordIdx] & (1 << bitIdx)) {
                        RtlCopyMemory(
                            userBuf + (ULONG64)copied * (4096 + sizeof(XCAP_ENTRY)),
                            g_Shv.XcapPageData + (ULONG64)i * 4096,
                            4096);
                        /* Append metadata after page data */
                        RtlCopyMemory(
                            userBuf + (ULONG64)copied * (4096 + sizeof(XCAP_ENTRY)) + 4096,
                            &g_Shv.XcapEntries[i],
                            sizeof(XCAP_ENTRY));
                        copied++;
                    }
                }
            }
            GuestContext->Rax = (ULONG64)copied;
        }
        return FALSE;

    case VMCALL_XCAP_SETUP:
        /* Install xcap traps SYNCHRONOUSLY in this VMX-root handler.
         *
         * Earlier versions deferred the install by writing PendingXcap*
         * fields and letting exit_dispatch's pending check run the
         * install on the next VM exit. That created a fatal race for
         * the the observed service process case: the loader thread returns from
         * the kernel image notify, exits to user mode via SYSRET (no
         * VM exit), and runs the launcher entrypoint and unpacker
         * before any VM exit happens on its CPU. By the time a timer
         * tick forces an exit and the install finally runs, the
         * launcher has executed everything it cares about. The trap
         * arms on physical pages no one will execute again. Symptom:
         * 4621 trapped, 0 EPT violations, 0 captured.
         *
         * The fix is to install RIGHT NOW. The caller (NexusCore image
         * notify, PASSIVE_LEVEL, target context) has already populated
         * g_Shv.XcapPaTable[]. ShvEptXcapWalkAndTrap is safe in VMX
         * root: it only writes to kernel memory and uses INVEPT
         * (intrinsic). After this returns, the loader's CPU has fresh
         * EPT translations; when SYSRET drops it back to user mode,
         * the launcher entrypoint faults on first execute.
         *
         * For correctness on other CPUs (in case the launcher thread
         * migrates before its first image execute), NexusCore is
         * expected to issue KeIpiGenericCall(InveptCallback) right
         * after this VMCALL returns to broadcast INVEPT to all cores.
         *
         * RDX=CR3, R8=VaBase, R9=VaEnd, R10=isRetrap (0 fresh, 1 retrap). */
        {
            ULONG64 cr3      = GuestContext->Rdx;
            ULONG64 vaBase   = GuestContext->R8;
            ULONG64 vaEnd    = GuestContext->R9;
            BOOLEAN isRetrap = (GuestContext->R10 != 0);
            if (vaEnd > vaBase) {
                ShvEptXcapWalkAndTrap(cr3, vaBase, vaEnd, isRetrap);
                InterlockedIncrement(&g_Shv.InveptGeneration);
                GuestContext->Rax = 0; /* STATUS_SUCCESS */
            } else {
                GuestContext->Rax = (ULONG64)STATUS_INVALID_PARAMETER;
            }
        }
        return FALSE;

    case VMCALL_XCAP_GET_PATABLE:
        /* Return the kernel VA of g_Shv.XcapPaTable so NexusCore can
         * populate it directly from PASSIVE_LEVEL kernel context.
         *
         * RAX = pointer (or 0 if PrepareXcapResources hasn't run yet). */
        GuestContext->Rax = (ULONG64)(ULONG_PTR)g_Shv.XcapPaTable;
        return FALSE;

    case VMCALL_XCAP_GET_CFG:
        /* Return XCAP_MAX_PAGES so the caller can clamp its walk to the
         * largest table SentinelHV will accept. */
        GuestContext->Rax = (ULONG64)XCAP_MAX_PAGES;
        return FALSE;

    case VMCALL_XCAP_DIAG:
        /* Return one of the diagnostic counters in RAX, selected by RDX:
         *    0 = TrappedCount        (pages execute-trapped at install time)
         *    1 = NoPaCount           (entries that were 0 in XcapPaTable)
         *    2 = NoSplitCount        (pages skipped because no EPT split slot)
         *    3 = ViolationCount      (EPT execute violations on xcap pages)
         *    4 = WrongCr3Count       (violations skipped due to CR3 mismatch)
         *    5 = CapturedCount       (pages successfully copied out)
         *    6 = Active              (1 if traps currently armed)
         *    7 = RipSampleCount      (RIP samples in armed CR3)
         *    8 = RipInImageCount     (samples where RIP was inside image range)
         *    9 = FirstRipIn          (first sampled RIP inside image range)
         *   10 = FirstRipOut         (first sampled RIP outside image range)
         *   11 = LastRip             (most recently sampled RIP)
         *   12 = AnyExecViolation    (every EPT execute violation, regardless of PA match)
         *   13 = PaTable[0]          (first walked PA — sanity check)
         *   14 = PaTable[1]
         *   15 = PaTable[2]
         *   16 = PaTable[3] */
        switch (GuestContext->Rdx) {
        case 0:  GuestContext->Rax = (ULONG64)g_Shv.XcapTrappedCount;   break;
        case 1:  GuestContext->Rax = (ULONG64)g_Shv.XcapNoPaCount;      break;
        case 2:  GuestContext->Rax = (ULONG64)g_Shv.XcapNoSplitCount;   break;
        case 3:  GuestContext->Rax = (ULONG64)g_Shv.XcapViolationCount; break;
        case 4:  GuestContext->Rax = (ULONG64)g_Shv.XcapWrongCr3Count;  break;
        case 5:  GuestContext->Rax = (ULONG64)g_Shv.XcapCapturedCount;  break;
        case 6:  GuestContext->Rax = (ULONG64)g_Shv.XcapActive;         break;
        case 7:  GuestContext->Rax = (ULONG64)g_Shv.XcapRipSampleCount; break;
        case 8:  GuestContext->Rax = (ULONG64)g_Shv.XcapRipInImageCount;break;
        case 9:  GuestContext->Rax = g_Shv.XcapFirstRipIn;              break;
        case 10: GuestContext->Rax = g_Shv.XcapFirstRipOut;             break;
        case 11: GuestContext->Rax = g_Shv.XcapLastRip;                 break;
        case 12: GuestContext->Rax = (ULONG64)g_Shv.XcapAnyExecViolation; break;
        case 13: GuestContext->Rax = (g_Shv.XcapPaTable ? g_Shv.XcapPaTable[0] : 0); break;
        case 14: GuestContext->Rax = (g_Shv.XcapPaTable ? g_Shv.XcapPaTable[1] : 0); break;
        case 15: GuestContext->Rax = (g_Shv.XcapPaTable ? g_Shv.XcapPaTable[2] : 0); break;
        case 16: GuestContext->Rax = (g_Shv.XcapPaTable ? g_Shv.XcapPaTable[3] : 0); break;
        case 17: GuestContext->Rax = (ULONG64)g_Shv.XcapTotalEptViolations; break;
        case 18: GuestContext->Rax = (ULONG64)ShvEptXcapProbePtaTableExecute(0); break;
        case 19: GuestContext->Rax = (ULONG64)ShvEptXcapProbePtaTableExecute(1); break;
        case 20: GuestContext->Rax = (ULONG64)ShvEptXcapProbePtaTableExecute(2); break;
        case 21: GuestContext->Rax = (ULONG64)ShvEptXcapProbePtaTableExecute(3); break;
        case 22: {
            /* DIRECT field read — bypasses ShvEptXcapGetSplitCount()'s
             * function call indirection in case that was the gremlin.
             * Reads the LONG at &g_Shv.XcapSplitCount via volatile cast
             * so the compiler cannot fold or cache the read. */
            volatile LONG* p = &g_Shv.XcapSplitCount;
            GuestContext->Rax = (ULONG64)(*p);
            break;
        }
        case 23: GuestContext->Rax = ShvEptXcapGetSplitBase2mb(0); break;
        case 24: GuestContext->Rax = ShvEptXcapGetSplitBase2mb(1); break;
        case 25: GuestContext->Rax = ShvEptXcapGetSplitBase2mb(2); break;
        case 26: GuestContext->Rax = ShvEptXcapGetSplitBase2mb(3); break;
        case 27: GuestContext->Rax = (ULONG64)g_Shv.EptHookCount; break;
        case 28: GuestContext->Rax = g_Shv.PrimaryEptp; break;
        case 29: GuestContext->Rax = g_Shv.SecondaryEptp; break;
        case 30: GuestContext->Rax = (ULONG64)g_Shv.XcapNonPrimaryEptpCount; break;
        case 31: GuestContext->Rax = g_Shv.XcapLastNonPrimaryEptp; break;
        case 32: {
            /* Read this CPU's current VMCS_CTRL_EPTP — only valid for the
             * BSP since NexusHvIssueVmcall pins to BSP. Tells us what
             * EPTP the BSP's guest is using right now. */
            SIZE_T eptp = 0;
            __vmx_vmread(VMCS_CTRL_EPTP, &eptp);
            GuestContext->Rax = (ULONG64)eptp;
            break;
        }
        case 33: GuestContext->Rax = ShvEptXcapGetLivePdeFor(0); break;
        case 34: GuestContext->Rax = ShvEptXcapGetLivePtEntryFor(0); break;
        case 35: GuestContext->Rax = ShvEptXcapGetPml4Pa(); break;
        case 36: GuestContext->Rax = (ULONG64)g_Shv.XcapPostInstallSplitCount; break;
        case 37: GuestContext->Rax = (ULONG64)g_Shv.XcapAtCaptureSplitCount; break;
        case 38: GuestContext->Rax = (ULONG64)g_Shv.XcapSplitForIncrements; break;
        case 39: {
            /* Compute page index for XcapFirstRipIn and return PaTable[idx]. */
            if (g_Shv.XcapFirstRipIn == 0 || g_Shv.XcapPaTable == NULL ||
                g_Shv.XcapVaBase == 0 ||
                g_Shv.XcapFirstRipIn < g_Shv.XcapVaBase) {
                GuestContext->Rax = 0;
            } else {
                ULONG idx = (ULONG)((g_Shv.XcapFirstRipIn - g_Shv.XcapVaBase) >> 12);
                if (idx >= XCAP_MAX_PAGES) GuestContext->Rax = 0;
                else GuestContext->Rax = g_Shv.XcapPaTable[idx];
            }
            break;
        }
        case 40: {
            /* Probe Execute bit for the same page. */
            if (g_Shv.XcapFirstRipIn == 0 || g_Shv.XcapPaTable == NULL ||
                g_Shv.XcapVaBase == 0 ||
                g_Shv.XcapFirstRipIn < g_Shv.XcapVaBase) {
                GuestContext->Rax = 0xFF;
            } else {
                ULONG idx = (ULONG)((g_Shv.XcapFirstRipIn - g_Shv.XcapVaBase) >> 12);
                GuestContext->Rax = (ULONG64)ShvEptXcapProbePtaTableExecute(idx);
            }
            break;
        }
        case 41: {
            /* Compute and return the page index itself, for sanity. */
            if (g_Shv.XcapFirstRipIn == 0 || g_Shv.XcapVaBase == 0 ||
                g_Shv.XcapFirstRipIn < g_Shv.XcapVaBase) {
                GuestContext->Rax = 0;
            } else {
                GuestContext->Rax = (g_Shv.XcapFirstRipIn - g_Shv.XcapVaBase) >> 12;
            }
            break;
        }
        case 42:
            /* COUNT NON-ZERO SLOTS in g_XcapSplitBase2mb, independent of
             * the g_Shv.XcapSplitCount counter. If this returns N but
             * case 22 returns 0, the install loop DID populate the slot
             * table — only the counter LONG is desynced. If this returns
             * 0 too, the install loop never wrote anything to the slot
             * table either (a deeper, install-side bug). */
            GuestContext->Rax = (ULONG64)ShvEptXcapCountFilledSplits();
            break;
        case 43:
            /* Read both XcapSplitCount and XcapSplitForIncrements as a
             * single 8-byte read. After the Apr 2026 swap experiment
             * XcapSplitCount lives at the LOWER offset of the pair, so
             * read from &XcapSplitCount to capture both LONGs in one
             * atomic memory access:
             *   low 32  = XcapSplitCount
             *   high 32 = XcapSplitForIncrements */
            GuestContext->Rax = *(volatile ULONG64*)&g_Shv.XcapSplitCount;
            break;
        case 44:
            /* Live runtime address of g_Shv.XcapSplitCount — verifies
             * the diag and the install operate on the same memory. */
            GuestContext->Rax = ShvEptXcapGetSplitCountAddr();
            break;
        case 45:
            /* g_Shv.XcapTraceLastInc — the value of XcapSplitCount as
             * read from memory IMMEDIATELY after the last successful
             * InterlockedIncrement in ShvEptXcapSplitFor. */
            GuestContext->Rax = (ULONG64)g_Shv.XcapTraceLastInc;
            break;
        case 46:
            /* g_Shv.XcapTraceIncCount — bumped once per SplitFor success.
             * Independent of XcapSplitForIncrements; gives a parallel
             * count via a different InterlockedIncrement instance. */
            GuestContext->Rax = (ULONG64)g_Shv.XcapTraceIncCount;
            break;
        case 47:
            /* WRITE diag: set g_Shv.XcapPaTableCount to RDX (caller's r8d
             * via RDX after relay).
             * Wait — VMCALL_XCAP_DIAG uses RDX for the index and r8/r9
             * for write payloads in the multi-arg path. The poller sends
             * the count in the SECOND argument (R8). Read it from R8. */
            InterlockedExchange(&g_Shv.XcapPaTableCount, (LONG)GuestContext->R8);
            GuestContext->Rax = (ULONG64)g_Shv.XcapPaTableCount;
            break;
        case 48:
            /* Read back current XcapPaTableCount. */
            GuestContext->Rax = (ULONG64)g_Shv.XcapPaTableCount;
            break;
        default: GuestContext->Rax = 0; break;
        }
        return FALSE;

    case VMCALL_EPT_READ_PAGE:
        /*
         * EPT-level physical page read.
         *
         * Caller supplies a guest physical address (RDX) and a destination
         * kernel VA (R8) that must be backed by a present, writable 4 KB page.
         * The HV identity-maps GPA==HPA, so we can access the page directly
         * via the kernel's physical map without walking guest page tables.
         *
         * Used by NexusCore's HV-quality dump dispatcher to produce capture
         * snapshots of self-modifying Themida-packed binaries without
         * racing the guest's own page-protection changes.
         */
        {
            ULONG64 gpa = GuestContext->Rdx;
            ULONG64 dst = GuestContext->R8;
            if (dst == 0 || (dst & 0xFFFF800000000000ULL) != 0xFFFF800000000000ULL) {
                GuestContext->Rax = (ULONG64)STATUS_INVALID_PARAMETER;
            } else {
                BOOLEAN ok = ShvEptReadPhysicalPage(gpa, (PVOID)(ULONG_PTR)dst);
                GuestContext->Rax = ok ? (ULONG64)STATUS_SUCCESS
                                       : (ULONG64)STATUS_IO_DEVICE_ERROR;
            }
        }
        return FALSE;

    case VMCALL_CIPHER_DUMP_LOG:
        /* Dump cipher records to a kernel buffer (caller's NonPagedPool).
         * Guest RDX = kernel buffer VA, R8 = max records, R9 = start index.
         * Returns RAX = records actually copied. */
        {
            ULONG64 bufVa   = GuestContext->Rdx;
            ULONG64 maxRecs = GuestContext->R8;
            ULONG64 startIdx = GuestContext->R9;

            if (!g_Shv.CipherTrapLog || bufVa == 0 || maxRecs == 0) {
                GuestContext->Rax = 0;
            } else {
                LONG total = g_Shv.CipherTrapLogTotal;
                ULONG avail = (ULONG)((total > CIPHER_RECORD_MAX)
                                      ? CIPHER_RECORD_MAX : total);
                if ((ULONG64)avail > maxRecs) avail = (ULONG)maxRecs;
                if (startIdx >= avail) { GuestContext->Rax = 0; break; }
                ULONG toCopy = avail - (ULONG)startIdx;
                if (toCopy > (ULONG)(maxRecs - startIdx))
                    toCopy = (ULONG)(maxRecs - startIdx);

                PKM_CIPHER_RECORD dst = (PKM_CIPHER_RECORD)bufVa;
                for (ULONG i = 0; i < toCopy; i++) {
                    ULONG slot = ((ULONG)startIdx + i) % CIPHER_RECORD_MAX;
                    RtlCopyMemory(&dst[i], &g_Shv.CipherTrapLog[slot],
                                  sizeof(KM_CIPHER_RECORD));
                }
                GuestContext->Rax = (ULONG64)toCopy;
            }
        }
        return FALSE;

    case VMCALL_DEVIRTUALIZE:
        /*
         * Devirtualize this logical processor.
         * Validate the magic cookie to prevent accidental invocation.
         *
         * Item #6 stealth fix: a probe issuing VMCALL_DEVIRTUALIZE (or any
         * known command code by accident) without the signature must look
         * exactly like bare metal VMCALL outside VMX — i.e. #UD. Returning
         * STATUS_ACCESS_DENIED in RAX is a HV-presence signal. Inject #UD
         * and DO NOT advance RIP.
         */
        if (cookie != VMCALL_MAGIC_COOKIE) {
            SHV_WARN("CPU %lu: VMCALL DEVIRTUALIZE with bad cookie 0x%llX",
                     Vcpu->ProcessorIndex, cookie);
            ShvInjectException(VECTOR_UD, 0);
            return FALSE;
        }

        /* NO SHV_LOG — this runs at IPI_LEVEL in VMX root, DbgPrintEx would deadlock */

        /*
         * Read guest state needed for ShvVmxOffAndRestore.
         * After VMXOFF, we jump back to the instruction after VMCALL
         * with RAX = STATUS_SUCCESS.
         */
        SIZE_T guestRip = 0, guestRsp = 0, guestRflags = 0;
        SIZE_T instrLen = 0;

        __vmx_vmread(VMCS_GUEST_RIP, &guestRip);
        __vmx_vmread(VMCS_RO_VMEXIT_INSTRUCTION_LEN, &instrLen);
        __vmx_vmread(VMCS_GUEST_RSP, &guestRsp);
        __vmx_vmread(VMCS_GUEST_RFLAGS, &guestRflags);

        /* Return RIP = past the VMCALL instruction */
        ULONG64 returnRip = guestRip + instrLen;

        /* Restore original CR4 (without VMXE) before returning */
        /* ShvVmxOffAndRestore handles VMXOFF + CR4.VMXE clear + state restore */
        ShvVmxOffAndRestore(returnRip, guestRsp, guestRflags, STATUS_SUCCESS);

        /* Should never reach here — ShvVmxOffAndRestore jumps to guest */
        __assume(0);

    default:
        /* Item #6 — unknown VMCALL: inject #UD so probes see bare-metal
         * "VMCALL outside VMX = #UD" semantics. Returning a status code
         * in RAX is a HV-presence signal. The dispatcher in exit_dispatch.c
         * checks VMENTRY_INTERRUPTION_INFO.VALID; with the bit set, it
         * skips ShvAdvanceGuestRip — the exception delivery handles RIP. */
        SHV_WARN("Unknown VMCALL command 0x%llX (injecting #UD)", command);
        ShvInjectException(VECTOR_UD, 0);
        return FALSE;
    }
}
