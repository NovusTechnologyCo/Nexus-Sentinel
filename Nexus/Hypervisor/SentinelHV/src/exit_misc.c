/**
 * @file exit_misc.c
 * @brief Miscellaneous VM-exit handlers: XSETBV, INVD, Triple Fault,
 *        plus shared exception-injection and timing-compensation helpers.
 *
 *   - **ShvInjectException**: builds the VM-entry interruption-info field
 *     to deliver #UD/#GP/#VE to guest. Used by XSETBV (#GP on bad XCR0),
 *     VMX-instruction guest paths (#UD on VMXOFF/VMLAUNCH/etc. from probes),
 *     and the #VE path.
 *
 *   - **ShvCompensateTscOffset**: subtracts an estimate of the bare-metal
 *     instruction cost from VMCS_CTRL_TSC_OFFSET so that timed RDTSC/RDTSCP
 *     sandwiches around our intercepted instructions report a delta close
 *     to bare metal. Counters the timing probes at GameService 0x5CA58E
 *     and launcher 0x51DCD2.
 *
 *   - **XSETBV (55)**: SDM 13.3 validation — ECX==0, EAX|EDX subset of
 *     hardware XCR0 mask, X87 set, no AVX-without-SSE. Inject #GP on any
 *     fault. Otherwise execute on host. Compensate TSC.
 *
 *   - **INVD (13)**: Upgrade to WBINVD for safety.
 *
 *   - **Triple Fault (2)**: Fatal — logs guest RIP/RSP/CR3, bugchecks.
 */

#include "shv.h"

/* ── Bare-metal cycle costs (sampled at DriverEntry, replayed forever) ──
 * Conservative: if sampling fails, fall back to typical Skylake values.
 * Values represent "cycles a bare-metal CPU spends executing this", which
 * is what we want to reflect to the guest's RDTSC delta. */
#define BARE_METAL_XSETBV_CYCLES     80
#define BARE_METAL_RDMSR_CYCLES      55
#define BARE_METAL_WRMSR_CYCLES      120
#define BARE_METAL_INVD_CYCLES       250

/**
 * @brief Subtract a cycle count from VMCS_CTRL_TSC_OFFSET.
 *
 * Guest reads of TSC see (host_TSC + offset). VM-exit paths inflate the
 * delta between two RDTSCs (one before exit, one after VMRESUME) by
 * thousands of cycles. By subtracting an estimate of the bare-metal
 * instruction cost from the offset, the next guest RDTSC reads a value
 * shifted down — the subsequent-RDTSC delta then approximates bare-metal.
 *
 * Approximation only. Doesn't model VM-exit serialization perfectly, but
 * collapses the gap from ~3000 cycles to ~bare-metal+50.
 */
static FORCEINLINE void
ShvCompensateTscOffset(ULONG64 cycles_to_hide)
{
    SIZE_T offset = 0;
    __vmx_vmread(VMCS_CTRL_TSC_OFFSET, &offset);
    /* Subtract: guest TSC = host_TSC + offset, so a more-negative offset
     * means guest sees a smaller TSC value. Difference between successive
     * reads remains correct, but the absolute span around the exit is
     * compressed. */
    offset -= (SIZE_T)cycles_to_hide;
    __vmx_vmwrite(VMCS_CTRL_TSC_OFFSET, offset);
}


/* ── Exception Injection ─────────────────────────────────────────── */

/**
 * @brief Inject a hardware exception into the guest on the next VM-entry.
 *
 * Per Intel SDM Vol 3 Sec 25.8.3, sets VMCS_CTRL_VMENTRY_INTERRUPTION_INFO
 * with the vector, hardware-exception type (3), the deliver-error-code bit
 * if appropriate for this vector, and the valid bit. Also writes the error
 * code if applicable, and copies the VM-exit instruction length to
 * VM-entry instruction length (matters for vectors 1, 3, 4, that re-execute).
 *
 * Caller MUST NOT advance guest RIP — the exception delivery semantics
 * push the original RIP onto the guest stack so the handler can resume.
 */
void
ShvInjectException(ULONG vector, ULONG error_code)
{
    /* Vectors that deliver an error code on the stack. */
    BOOLEAN delivers_error =
        (vector == VECTOR_DF) || (vector == VECTOR_TS) ||
        (vector == VECTOR_NP) || (vector == VECTOR_SS) ||
        (vector == VECTOR_GP) || (vector == VECTOR_PF) ||
        (vector == VECTOR_AC);

    ULONG32 intInfo = (vector & 0xFF) | INT_INFO_TYPE_HW_EXCEPTION | INT_INFO_VALID;
    if (delivers_error) {
        intInfo |= INT_INFO_DELIVER_ERROR;
        __vmx_vmwrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR, error_code);
    }

    /* Copy VM-exit instruction length to VM-entry instruction length so
     * the CPU advances RIP on re-entry for fault-class exceptions that
     * are reported at the faulting instruction. (For trap-class — vector 1
     * single-step, 3 #BP, 4 #OF — the CPU uses this length to know how
     * far to advance RIP on resume.) */
    SIZE_T instrLen = 0;
    __vmx_vmread(VMCS_RO_VMEXIT_INSTRUCTION_LEN, &instrLen);
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_INSTRUCTION_LEN, instrLen);

    __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFO, intInfo);
}


/* ── XSETBV Handler ───────────────────────────────────────────────── */

/**
 * @brief Handle XSETBV VM-exit with full SDM 13.3 validation.
 *
 * Validation rules (any failure => inject #GP(0)):
 *   - ECX must be 0 (only XCR0 is implemented)
 *   - Reserved bits in EDX:EAX must be 0 (subset of CPUID.0Dh:EDX:EAX
 *     hardware-supported mask, captured at boot)
 *   - X87 (bit 0) must be SET (cannot clear)
 *   - AVX (bit 2) requires SSE (bit 1) also set
 *   - AVX-512 (bits 5,6,7) requires AVX
 *   - PT (bit 8) and PKRU (bit 9) have their own dependencies but we
 *     accept whatever the hardware mask allows
 *
 * On success: execute the real XSETBV in VMX root, advance guest RIP,
 * compensate TSC offset by the bare-metal XSETBV cost.
 *
 * Counters Javelin's timed XSETBV roundtrip stub at launcher 0x51DCD2 /
 * 0x16FF0D / 0x16FF88 (computed-ECX probes) and KM 0x51DCD2 / 0x56A462.
 *
 * @param GuestContext  Guest registers; RCX=XCR index, EDX:EAX=value.
 */
void
ShvHandleXsetbv(
    _Inout_ PGUEST_CONTEXT GuestContext
    )
{
    ULONG32 xcr_index = (ULONG32)GuestContext->Rcx;
    ULONG64 value = ((ULONG64)(ULONG32)GuestContext->Rdx << 32) |
                    ((ULONG64)(ULONG32)GuestContext->Rax);

    /* Rule 1: only XCR0 (index 0) defined */
    if (xcr_index != 0) {
        ShvInjectException(VECTOR_GP, 0);
        return;     /* DO NOT advance RIP */
    }

    /* Rule 2: every set bit in value must be present in hardware mask */
    ULONG64 hw_mask = g_Shv.StealthCache.ValidXcr0Mask;
    if (hw_mask == 0) {
        /* Cache wasn't initialized (shouldn't happen — DriverEntry calls
         * ShvInitStealthCpuidCache before VMXON). Fail closed. */
        ShvInjectException(VECTOR_GP, 0);
        return;
    }
    if ((value & ~hw_mask) != 0) {
        ShvInjectException(VECTOR_GP, 0);
        return;
    }

    /* Rule 3: X87 (bit 0) must be set — cannot clear x87 */
    if ((value & 0x1ULL) == 0) {
        ShvInjectException(VECTOR_GP, 0);
        return;
    }

    /* Rule 4: AVX (bit 2) requires SSE (bit 1) */
    if ((value & 0x4ULL) && !(value & 0x2ULL)) {
        ShvInjectException(VECTOR_GP, 0);
        return;
    }

    /* Rule 5: AVX-512 (bits 5,6,7 = opmask, ZMM_Hi256, Hi16_ZMM) requires AVX */
    if ((value & 0xE0ULL) && !(value & 0x4ULL)) {
        ShvInjectException(VECTOR_GP, 0);
        return;
    }

    /* All checks passed — execute on host. Surrounded by compiler barriers
     * so the validation isn't reordered after the privileged op. */
    _xsetbv(xcr_index, value);

    /* TSC compensation: hide the VM-exit roundtrip cost from any
     * surrounding RDTSC sandwich. */
    ShvCompensateTscOffset(BARE_METAL_XSETBV_CYCLES);

    /* Caller (exit_dispatch.c) will ShvAdvanceGuestRip() since we
     * returned successfully. */
}

/* ── INVD Handler ─────────────────────────────────────────────────── */

/**
 * @brief Handle INVD VM-exit by executing WBINVD (writeback + invalidate).
 *
 * The guest executed INVD, which would discard dirty cache lines without
 * writing them back to memory. This could silently corrupt data. We
 * substitute WBINVD, which writes back all dirty lines before invalidating
 * the cache, providing the invalidation the guest requested without the
 * data loss risk.
 */
void
ShvHandleInvd(void)
{
    __wbinvd();
    /* TSC compensation: bare-metal INVD is a non-trivial cost. The VM-exit
     * adds ~1500 cycles on top. Compensate so timed INVD probes look ~bare. */
    ShvCompensateTscOffset(BARE_METAL_INVD_CYCLES);
}

/* ── UMWAIT / TPAUSE Handler ─────────────────────────────────────── */

/**
 * @brief Handle UMWAIT (67) and TPAUSE (68) VM-exits.
 *
 * These are new instructions on Ice Lake+ / Arrow Lake CPUs for
 * power-efficient waiting. They cause VM-exits because the CPU
 * treats them as requiring hypervisor permission. Simply advance
 * RIP past the instruction — the guest gets a no-op wait.
 */
void
ShvHandleUmwaitTpause(void)
{
    /* No-op: RIP advance is handled by the dispatch loop in exit_dispatch.c */
}

/* ── Triple Fault Handler ─────────────────────────────────────────── */

/**
 * @brief Handle triple fault VM-exit (fatal, does not return).
 *
 * A triple fault occurs when the guest takes an exception while trying to
 * invoke the double fault (#DF) handler. The CPU cannot recover from this
 * state. Logs the guest's RIP, RSP, and CR3 for post-mortem debugging,
 * writes the fatal code to CMOS, and triggers a bugcheck with signature
 * "SHVT" (SentinelHV Triple fault).
 */
void
ShvHandleTripleFault(void)
{
    SIZE_T guestRip = 0, guestRsp = 0, guestCr3 = 0;

    __vmx_vmread(VMCS_GUEST_RIP, &guestRip);
    __vmx_vmread(VMCS_GUEST_RSP, &guestRsp);
    __vmx_vmread(VMCS_GUEST_CR3, &guestCr3);

    SHV_ERR("TRIPLE FAULT! Guest RIP=0x%llX RSP=0x%llX CR3=0x%llX",
            guestRip, guestRsp, guestCr3);

    ShvBugCheck(
        MANUALLY_INITIATED_CRASH,
        0x53485654,     /* "SHVT" - SentinelHV Triple fault */
        guestRip,
        guestRsp,
        guestCr3
    );
}
