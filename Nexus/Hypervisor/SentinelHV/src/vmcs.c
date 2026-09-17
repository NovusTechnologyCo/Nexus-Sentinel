/**
 * @file vmcs.c
 * @brief VMCS field configuration for guest state, host state, and execution controls.
 *
 * Implements the full VMCS initialization for each logical processor. The VMCS
 * (Virtual Machine Control Structure) is a 4KB hardware-managed data structure
 * that defines the complete virtual machine state:
 *
 *   - **Guest State Area**: Mirrors the current CPU's register state at the
 *     time of virtualization (CR0-CR4, all segment registers with base/limit/
 *     access rights, descriptor tables, MSRs, RIP/RSP/RFLAGS). Guest RAX is
 *     set to 1 so ShvCaptureContext's dual-return mechanism works.
 *
 *   - **Host State Area**: Defines where the CPU goes on VM-exit. HOST_RIP
 *     points to ShvVmExitStub (ASM). HOST_RSP points to the host stack with
 *     a pre-stored VCPU pointer at the top. Segment selectors have RPL cleared.
 *
 *   - **Execution Controls**: Pin-based (minimal), primary processor-based
 *     (MSR bitmaps + secondary enable), secondary (EPT + RDTSCP + XSAVES +
 *     INVPCID), VM-exit (64-bit host, EFER save/load), VM-entry (64-bit guest,
 *     EFER load). CR4.VMXE is hidden via guest-host mask and read shadow.
 *
 * Control bit adjustment uses ShvAdjustControls to apply hardware mandatory
 * fixed bits from VMX capability MSRs, with automatic selection of TRUE
 * controls when supported.
 */

#include "shv.h"

/* ── Control Adjustment ───────────────────────────────────────────── */

ULONG32
ShvAdjustControls(
    _In_ ULONG32 Requested,
    _In_ ULONG32 CapabilityMsr
    )
{
    ULONG64 cap = __readmsr(CapabilityMsr);

    /* Low 32 bits = must-be-1 bits (allowed0) */
    Requested |= (ULONG32)cap;
    /* High 32 bits = can-be-1 bits (allowed1) */
    Requested &= (ULONG32)(cap >> 32);

    return Requested;
}

/* ── Helper: Select TRUE or default capability MSR ────────────────── */

/**
 * @brief Get the correct pin-based controls capability MSR.
 *
 * Returns IA32_VMX_TRUE_PINBASED_CTLS if true controls are supported
 * (bit 55 of IA32_VMX_BASIC), otherwise IA32_VMX_PINBASED_CTLS.
 *
 * @return MSR index for pin-based controls capability.
 */
static ULONG32
ShvGetPinBasedMsr(void)
{
    ULONG64 basic = __readmsr(IA32_VMX_BASIC);
    return (basic >> 55) & 1 ? IA32_VMX_TRUE_PINBASED_CTLS : IA32_VMX_PINBASED_CTLS;
}

/** @brief Get the correct primary processor-based controls capability MSR. */
static ULONG32
ShvGetProcBasedMsr(void)
{
    ULONG64 basic = __readmsr(IA32_VMX_BASIC);
    return (basic >> 55) & 1 ? IA32_VMX_TRUE_PROCBASED_CTLS : IA32_VMX_PROCBASED_CTLS;
}

/** @brief Get the correct VM-exit controls capability MSR. */
static ULONG32
ShvGetExitMsr(void)
{
    ULONG64 basic = __readmsr(IA32_VMX_BASIC);
    return (basic >> 55) & 1 ? IA32_VMX_TRUE_EXIT_CTLS : IA32_VMX_EXIT_CTLS;
}

/** @brief Get the correct VM-entry controls capability MSR. */
static ULONG32
ShvGetEntryMsr(void)
{
    ULONG64 basic = __readmsr(IA32_VMX_BASIC);
    return (basic >> 55) & 1 ? IA32_VMX_TRUE_ENTRY_CTLS : IA32_VMX_ENTRY_CTLS;
}

/* ── MSR Bitmap Intercept Setup ───────────────────────────────────── */

/**
 * @brief Set a single bit in an MSR bitmap section (passthrough → intercept).
 *
 * Intel SDM 25.6.9 layout — bitmap is 4KB:
 *   0x0000-0x03FF : read  intercepts for MSRs 0x00000000-0x00001FFF
 *   0x0400-0x07FF : read  intercepts for MSRs 0xC0000000-0xC0001FFF
 *   0x0800-0x0BFF : write intercepts for MSRs 0x00000000-0x00001FFF
 *   0x0C00-0x0FFF : write intercepts for MSRs 0xC0000000-0xC0001FFF
 *
 * Set bit ⇒ that operation traps. Clear bit ⇒ passthrough.
 */
static FORCEINLINE void
ShvSetMsrBitmapBit(UCHAR* bitmap, ULONG msrIndex, BOOLEAN forWrite)
{
    ULONG sectionBase;
    ULONG msrOffset;

    if (msrIndex < 0x2000) {
        sectionBase = forWrite ? 0x800 : 0x000;
        msrOffset = msrIndex;
    } else if (msrIndex >= 0xC0000000 && msrIndex < 0xC0002000) {
        sectionBase = forWrite ? 0xC00 : 0x400;
        msrOffset = msrIndex - 0xC0000000;
    } else {
        return;     /* outside the bitmap-coverable ranges */
    }

    bitmap[sectionBase + (msrOffset >> 3)] |= (UCHAR)(1U << (msrOffset & 7));
}


/**
 * @brief Configure MSR bitmap intercepts for VMX-residue and EFER MSRs.
 *
 * Without these intercepts, the cached-return logic in exit_msr.c never
 * fires — guest RDMSR(0x480) reads the LIVE post-VMXON value, which
 * differs from the bare-metal value Javelin's MSR-consistency block
 * expects to see. With intercepts on, those reads VM-exit to our handler
 * which returns the cached pre-VMXON snapshot.
 */
static void
ShvSetupMsrBitmapIntercepts(UCHAR* bitmap)
{
    /* Intercept reads on every VMX-capability and EFER MSR. */
    ShvSetMsrBitmapBit(bitmap, IA32_FEATURE_CONTROL,         FALSE);
    ShvSetMsrBitmapBit(bitmap, IA32_VMX_BASIC,               FALSE);
    ShvSetMsrBitmapBit(bitmap, IA32_VMX_PINBASED_CTLS,       FALSE);
    ShvSetMsrBitmapBit(bitmap, IA32_VMX_PROCBASED_CTLS,      FALSE);
    ShvSetMsrBitmapBit(bitmap, IA32_VMX_EXIT_CTLS,           FALSE);
    ShvSetMsrBitmapBit(bitmap, IA32_VMX_ENTRY_CTLS,          FALSE);
    ShvSetMsrBitmapBit(bitmap, IA32_VMX_MISC,                FALSE);
    ShvSetMsrBitmapBit(bitmap, IA32_VMX_CR0_FIXED0,          FALSE);
    ShvSetMsrBitmapBit(bitmap, IA32_VMX_CR0_FIXED1,          FALSE);
    ShvSetMsrBitmapBit(bitmap, IA32_VMX_CR4_FIXED0,          FALSE);
    ShvSetMsrBitmapBit(bitmap, IA32_VMX_CR4_FIXED1,          FALSE);
    ShvSetMsrBitmapBit(bitmap, 0x48A,                        FALSE);  /* VMCS_ENUM */
    ShvSetMsrBitmapBit(bitmap, IA32_VMX_PROCBASED_CTLS2,     FALSE);
    ShvSetMsrBitmapBit(bitmap, 0x48C,                        FALSE);  /* EPT_VPID_CAP */
    ShvSetMsrBitmapBit(bitmap, IA32_VMX_TRUE_PINBASED_CTLS,  FALSE);
    ShvSetMsrBitmapBit(bitmap, IA32_VMX_TRUE_PROCBASED_CTLS, FALSE);
    ShvSetMsrBitmapBit(bitmap, IA32_VMX_TRUE_EXIT_CTLS,      FALSE);
    ShvSetMsrBitmapBit(bitmap, IA32_VMX_TRUE_ENTRY_CTLS,     FALSE);
    ShvSetMsrBitmapBit(bitmap, 0x491,                        FALSE);  /* VMFUNC */
    ShvSetMsrBitmapBit(bitmap, IA32_EFER,                    FALSE);
    /* Intercept writes on the same set so we can validate / inject #GP. */
    ShvSetMsrBitmapBit(bitmap, IA32_FEATURE_CONTROL,         TRUE);
    ShvSetMsrBitmapBit(bitmap, IA32_VMX_BASIC,               TRUE);
    ShvSetMsrBitmapBit(bitmap, IA32_VMX_PINBASED_CTLS,       TRUE);
    ShvSetMsrBitmapBit(bitmap, IA32_VMX_PROCBASED_CTLS,      TRUE);
    ShvSetMsrBitmapBit(bitmap, IA32_VMX_EXIT_CTLS,           TRUE);
    ShvSetMsrBitmapBit(bitmap, IA32_VMX_ENTRY_CTLS,          TRUE);
    ShvSetMsrBitmapBit(bitmap, IA32_VMX_MISC,                TRUE);
    ShvSetMsrBitmapBit(bitmap, IA32_VMX_CR0_FIXED0,          TRUE);
    ShvSetMsrBitmapBit(bitmap, IA32_VMX_CR0_FIXED1,          TRUE);
    ShvSetMsrBitmapBit(bitmap, IA32_VMX_CR4_FIXED0,          TRUE);
    ShvSetMsrBitmapBit(bitmap, IA32_VMX_CR4_FIXED1,          TRUE);
    ShvSetMsrBitmapBit(bitmap, IA32_VMX_PROCBASED_CTLS2,     TRUE);
    ShvSetMsrBitmapBit(bitmap, IA32_EFER,                    TRUE);
}


/* ── VMCS Setup ───────────────────────────────────────────────────── */

NTSTATUS
ShvSetupVmcs(
    _In_ PVCPU_DATA Vcpu,
    _In_ PGUEST_CONTEXT CapturedState
    )
{
    DESCRIPTOR_TABLE_REG gdtr, idtr;
    ShvSgdt(&gdtr);
    ShvSidt(&idtr);

    /* Item #5 — record the bare-metal NT IDTR/GDTR bases for any future
     * host-IDT/GDT port (Ophion-style hostidt.c). This SIDT/SGDT runs
     * BEFORE VMXON so what we read is unambiguously the NT-loaded base.
     * Currently we write `gdtr.Base`/`idtr.Base` directly into the
     * VMCS_GUEST_*_BASE fields below — guest SGDT/SIDT therefore reads
     * the original NT bases (item #5 satisfied). When the host-IDT port
     * swaps host IDTR/GDTR to a private structure, the per-VCPU fields
     * `OriginalGdtr` / `OriginalIdtr` (defined in shv_arch.h) remain the
     * source of truth for what to write into guest VMCS. */
    Vcpu->OriginalGdtr = gdtr;
    Vcpu->OriginalIdtr = idtr;

    ULONG64 cr0 = __readcr0();
    ULONG64 cr3 = __readcr3();
    ULONG64 cr4 = __readcr4();

    /* ────────────────────────────────────────────────────────────── */
    /* Guest State Area                                               */
    /* ────────────────────────────────────────────────────────────── */

    /* Control registers: apply VMX fixed bits */
    ULONG64 cr0Fixed0 = __readmsr(IA32_VMX_CR0_FIXED0);
    ULONG64 cr0Fixed1 = __readmsr(IA32_VMX_CR0_FIXED1);
    ULONG64 cr4Fixed0 = __readmsr(IA32_VMX_CR4_FIXED0);
    ULONG64 cr4Fixed1 = __readmsr(IA32_VMX_CR4_FIXED1);

    ULONG64 guestCr0 = (cr0 | cr0Fixed0) & cr0Fixed1;
    ULONG64 guestCr4 = (cr4 | cr4Fixed0) & cr4Fixed1;
    guestCr4 |= CR4_VMXE;  /* VMX requires VMXE=1 in guest CR4 */

    __vmx_vmwrite(VMCS_GUEST_CR0, guestCr0);
    __vmx_vmwrite(VMCS_GUEST_CR3, cr3);
    __vmx_vmwrite(VMCS_GUEST_CR4, guestCr4);
    __vmx_vmwrite(VMCS_GUEST_DR7, ShvReadDr7());

    /* Segment selectors */
    USHORT cs, ss, ds, es, fs, gs, tr, ldtr;
    cs = ShvReadCs();
    ss = ShvReadSs();
    ds = ShvReadDs();
    es = ShvReadEs();
    fs = ShvReadFs();
    gs = ShvReadGs();
    tr = ShvReadTr();
    ldtr = ShvReadLdtr();

    __vmx_vmwrite(VMCS_GUEST_CS_SELECTOR, cs);
    __vmx_vmwrite(VMCS_GUEST_SS_SELECTOR, ss);
    __vmx_vmwrite(VMCS_GUEST_DS_SELECTOR, ds);
    __vmx_vmwrite(VMCS_GUEST_ES_SELECTOR, es);
    __vmx_vmwrite(VMCS_GUEST_FS_SELECTOR, fs);
    __vmx_vmwrite(VMCS_GUEST_GS_SELECTOR, gs);
    __vmx_vmwrite(VMCS_GUEST_TR_SELECTOR, tr);
    __vmx_vmwrite(VMCS_GUEST_LDTR_SELECTOR, ldtr);

    /* Segment bases */
    __vmx_vmwrite(VMCS_GUEST_CS_BASE, ShvGetSegmentBase(gdtr.Base, cs));
    __vmx_vmwrite(VMCS_GUEST_SS_BASE, ShvGetSegmentBase(gdtr.Base, ss));
    __vmx_vmwrite(VMCS_GUEST_DS_BASE, ShvGetSegmentBase(gdtr.Base, ds));
    __vmx_vmwrite(VMCS_GUEST_ES_BASE, ShvGetSegmentBase(gdtr.Base, es));
    __vmx_vmwrite(VMCS_GUEST_FS_BASE, __readmsr(IA32_FS_BASE));
    __vmx_vmwrite(VMCS_GUEST_GS_BASE, __readmsr(IA32_GS_BASE));
    __vmx_vmwrite(VMCS_GUEST_TR_BASE, ShvGetSegmentBase(gdtr.Base, tr));
    __vmx_vmwrite(VMCS_GUEST_LDTR_BASE, ShvGetSegmentBase(gdtr.Base, ldtr));

    /* Segment limits */
    __vmx_vmwrite(VMCS_GUEST_CS_LIMIT, ShvGetSegmentLimit(gdtr.Base, cs));
    __vmx_vmwrite(VMCS_GUEST_SS_LIMIT, ShvGetSegmentLimit(gdtr.Base, ss));
    __vmx_vmwrite(VMCS_GUEST_DS_LIMIT, ShvGetSegmentLimit(gdtr.Base, ds));
    __vmx_vmwrite(VMCS_GUEST_ES_LIMIT, ShvGetSegmentLimit(gdtr.Base, es));
    __vmx_vmwrite(VMCS_GUEST_FS_LIMIT, ShvGetSegmentLimit(gdtr.Base, fs));
    __vmx_vmwrite(VMCS_GUEST_GS_LIMIT, ShvGetSegmentLimit(gdtr.Base, gs));
    __vmx_vmwrite(VMCS_GUEST_TR_LIMIT, ShvGetSegmentLimit(gdtr.Base, tr));
    __vmx_vmwrite(VMCS_GUEST_LDTR_LIMIT, ShvGetSegmentLimit(gdtr.Base, ldtr));

    /* Segment access rights */
    __vmx_vmwrite(VMCS_GUEST_CS_ACCESS_RIGHTS, ShvGetSegmentAccessRights(gdtr.Base, cs));
    __vmx_vmwrite(VMCS_GUEST_SS_ACCESS_RIGHTS, ShvGetSegmentAccessRights(gdtr.Base, ss));
    __vmx_vmwrite(VMCS_GUEST_DS_ACCESS_RIGHTS, ShvGetSegmentAccessRights(gdtr.Base, ds));
    __vmx_vmwrite(VMCS_GUEST_ES_ACCESS_RIGHTS, ShvGetSegmentAccessRights(gdtr.Base, es));
    __vmx_vmwrite(VMCS_GUEST_FS_ACCESS_RIGHTS, ShvGetSegmentAccessRights(gdtr.Base, fs));
    __vmx_vmwrite(VMCS_GUEST_GS_ACCESS_RIGHTS, ShvGetSegmentAccessRights(gdtr.Base, gs));
    __vmx_vmwrite(VMCS_GUEST_TR_ACCESS_RIGHTS, ShvGetSegmentAccessRights(gdtr.Base, tr));
    __vmx_vmwrite(VMCS_GUEST_LDTR_ACCESS_RIGHTS, ShvGetSegmentAccessRights(gdtr.Base, ldtr));

    /* Descriptor table registers */
    __vmx_vmwrite(VMCS_GUEST_GDTR_BASE, gdtr.Base);
    __vmx_vmwrite(VMCS_GUEST_GDTR_LIMIT, gdtr.Limit);
    __vmx_vmwrite(VMCS_GUEST_IDTR_BASE, idtr.Base);
    __vmx_vmwrite(VMCS_GUEST_IDTR_LIMIT, idtr.Limit);

    /*
     * Guest RIP, RSP, RFLAGS from captured context.
     * Set guest RAX = 1 so that when VMLAUNCH succeeds and guest resumes
     * at the captured RIP (return from ShvCaptureContext), the caller sees
     * a non-zero return value and knows it's running as a guest.
     */
    __vmx_vmwrite(VMCS_GUEST_RSP, CapturedState->Rsp);
    __vmx_vmwrite(VMCS_GUEST_RIP, CapturedState->Rip);
    __vmx_vmwrite(VMCS_GUEST_RFLAGS, CapturedState->Rflags);
    CapturedState->Rax = 1;  /* Guest RAX: ShvCaptureContext returns 1 on resume */

    /* MSRs */
    __vmx_vmwrite(VMCS_GUEST_IA32_SYSENTER_CS, __readmsr(IA32_SYSENTER_CS));
    __vmx_vmwrite(VMCS_GUEST_IA32_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));
    __vmx_vmwrite(VMCS_GUEST_IA32_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));
    __vmx_vmwrite(VMCS_GUEST_IA32_DEBUGCTL, __readmsr(IA32_DEBUGCTL));
    __vmx_vmwrite(VMCS_GUEST_IA32_EFER, __readmsr(IA32_EFER));

    /* Misc guest state */
    __vmx_vmwrite(VMCS_GUEST_VMCS_LINK_PTR, (ULONG64)~0ULL);
    __vmx_vmwrite(VMCS_GUEST_ACTIVITY_STATE, 0);   /* Active */
    __vmx_vmwrite(VMCS_GUEST_INTERRUPTIBILITY_STATE, 0);
    __vmx_vmwrite(VMCS_GUEST_PENDING_DBG_EXCEPTIONS, 0);

    /* ────────────────────────────────────────────────────────────── */
    /* Host State Area                                                */
    /* ────────────────────────────────────────────────────────────── */

    __vmx_vmwrite(VMCS_HOST_CR0, cr0);
    __vmx_vmwrite(VMCS_HOST_CR3, cr3);
    __vmx_vmwrite(VMCS_HOST_CR4, cr4);

    /* Host RIP = ASM exit stub */
    __vmx_vmwrite(VMCS_HOST_RIP, (ULONG64)ShvVmExitStub);

    /*
     * Host RSP: store VCPU pointer at the top of the host stack.
     * The ASM exit stub reads [HOST_RSP] to get the VCPU pointer.
     * HOST_RSP = HostStackTop - 8, and we pre-store Vcpu at that address.
     */
    ULONG64 hostRsp = Vcpu->HostStackTop - sizeof(PVOID);
    *(PVCPU_DATA*)hostRsp = Vcpu;
    __vmx_vmwrite(VMCS_HOST_RSP, hostRsp);

    /*
     * Host segment selectors: must have RPL=0 and TI=0 (GDT).
     * We mask off the lower 3 bits to ensure this, except where selector is 0.
     */
    __vmx_vmwrite(VMCS_HOST_CS_SELECTOR, cs & 0xFFF8);
    __vmx_vmwrite(VMCS_HOST_SS_SELECTOR, ss & 0xFFF8);
    __vmx_vmwrite(VMCS_HOST_DS_SELECTOR, ds & 0xFFF8);
    __vmx_vmwrite(VMCS_HOST_ES_SELECTOR, es & 0xFFF8);
    __vmx_vmwrite(VMCS_HOST_FS_SELECTOR, fs & 0xFFF8);
    __vmx_vmwrite(VMCS_HOST_GS_SELECTOR, gs & 0xFFF8);
    __vmx_vmwrite(VMCS_HOST_TR_SELECTOR, tr & 0xFFF8);

    /* Host bases */
    __vmx_vmwrite(VMCS_HOST_FS_BASE, __readmsr(IA32_FS_BASE));
    __vmx_vmwrite(VMCS_HOST_GS_BASE, __readmsr(IA32_GS_BASE));
    __vmx_vmwrite(VMCS_HOST_TR_BASE, ShvGetSegmentBase(gdtr.Base, tr));
    __vmx_vmwrite(VMCS_HOST_GDTR_BASE, gdtr.Base);
    __vmx_vmwrite(VMCS_HOST_IDTR_BASE, idtr.Base);

    /* Host MSRs */
    __vmx_vmwrite(VMCS_HOST_IA32_SYSENTER_CS, __readmsr(IA32_SYSENTER_CS));
    __vmx_vmwrite(VMCS_HOST_IA32_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));
    __vmx_vmwrite(VMCS_HOST_IA32_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));
    __vmx_vmwrite(VMCS_HOST_IA32_EFER, __readmsr(IA32_EFER));
    __vmx_vmwrite(VMCS_HOST_IA32_PAT, __readmsr(IA32_PAT));

    /* ────────────────────────────────────────────────────────────── */
    /* VM-Execution Control Fields                                    */
    /* ────────────────────────────────────────────────────────────── */

    /* Pin-based: NMI exiting + virtual NMIs for proper NMI handling. */
    ULONG32 pinBased = ShvAdjustControls(
        PIN_BASED_NMI_EXIT | PIN_BASED_VIRTUAL_NMIS,
        ShvGetPinBasedMsr()
    );
    __vmx_vmwrite(VMCS_CTRL_PIN_BASED_EXEC, pinBased);

    /* Primary proc-based: MSR bitmaps + secondary controls.
     * No HLT/MWAIT exiting — ENABLE_USER_WAIT_PAUSE in secondary controls
     * allows UMWAIT/TPAUSE (Arrow Lake idle mechanism) to work in guest.
     *
     * Item #4 — explicitly DO NOT request CR3-load/store exiting or
     * MOV-DR exiting. EPT handles paging without CR3 traps, and DR
     * access has no security purpose for our HV. Leaving them off makes
     * Javelin's KM CR3-write-then-read probes (68 sites) and DR probes
     * (~20 sites) execute natively with no VM-exit, no opportunity to
     * leak timing or value divergence. ShvAdjustControls forces the
     * must-be-1 bits from the capability MSR — modern Intel CPUs do
     * not mandate these, but if the must-be-1 set ever changes, the
     * post-adjust mask below clears them defensively. */
    ULONG32 primaryProc = ShvAdjustControls(
        CPU_BASED_USE_MSR_BITMAPS | CPU_BASED_ACTIVATE_SECONDARY,
        ShvGetProcBasedMsr()
    );
    primaryProc &= ~(CPU_BASED_CR3_LOAD_EXITING |
                     CPU_BASED_CR3_STORE_EXITING |
                     CPU_BASED_INVLPG_EXITING |
                     CPU_BASED_RDTSC_EXITING);
    /* MOV-DR EXITING re-enabled: with the case-29 handler in
     * exit_dispatch.c now also calling ShvCompensateTscOffset for each
     * MOV-DR exit (BARE_METAL_MOV_DR_CYCLES = 5), Themida's RDTSC-around-DR
     * timing probes see ~bare-metal cycle deltas. The DR0/1/2/3 reads are
     * spoofed to 0 when DrTrapInstalled, hiding our HW breakpoint. */
    primaryProc |= CPU_BASED_MOV_DR_EXITING;
    __vmx_vmwrite(VMCS_CTRL_PROC_BASED_EXEC, primaryProc);

    /* Secondary proc-based: EPT + RDTSCP + XSAVES + INVPCID + USER_WAIT_PAUSE.
     * USER_WAIT_PAUSE is CRITICAL on Arrow Lake — without it, UMWAIT/TPAUSE
     * cause #UD in guest mode, crashing the idle loop. */
    /* Secondary proc-based: EPT + RDTSCP + XSAVES + INVPCID + USER_WAIT_PAUSE
     * + VMFUNC.
     *
     * EPT_VIOLATION_VE remains DISABLED: even with the full
     * SuppressVe sweep landed (item #11) and no concrete consumer issuing
     * VMFUNC, attempting to install our handler in IDT[20] BSODs the
     * loader on every reboot at a constant module-RVA 0x11C15 in some
     * Win11 component (NOT SentinelHV.sys — module isn't even present
     * in the dump). Suspected cause: Win11 24H2 has its own #VE handler
     * at vector 20 that we clobber, OR the IDT is KCFG-protected.
     *
     * Stealth-mode hooks therefore remain unavailable until the IDT
     * install path is debugged on hardware. The SuppressVe=1 default
     * across the identity map is harmless and correct regardless. */
    ULONG32 secondaryRequest = CPU_BASED2_ENABLE_RDTSCP |
                               CPU_BASED2_ENABLE_XSAVES |
                               CPU_BASED2_ENABLE_INVPCID |
                               CPU_BASED2_ENABLE_USER_WAIT_PAUSE |
                               CPU_BASED2_ENABLE_VMFUNC;
    if (ShvEptIsEnabled()) {
        secondaryRequest |= CPU_BASED2_ENABLE_EPT;
    }
    ULONG32 secondaryProc = ShvAdjustControls(secondaryRequest, IA32_VMX_PROCBASED_CTLS2);
    /* Item #4 (cont'd) — defensively clear WBINVD-exiting (bit 6). Bare-metal
     * WBINVD costs ~1500 cycles, our exit handler adds ~1000 more. Keeping
     * it native lets Javelin's WBINVD timing checks (115 sites in KM) read
     * native cost. */
    secondaryProc &= ~CPU_BASED2_WBINVD_EXITING;
    __vmx_vmwrite(VMCS_CTRL_PROC_BASED_EXEC2, secondaryProc);

    /* Write EPTP if EPT was enabled in secondary controls */
    if (secondaryProc & CPU_BASED2_ENABLE_EPT) {
        __vmx_vmwrite(VMCS_CTRL_EPTP, ShvEptGetEptp());
        SHV_LOG("CPU %lu: EPT enabled, EPTP=0x%llX", Vcpu->ProcessorIndex, ShvEptGetEptp());
    }

    /* Item #8 — EPTP list page for VMFUNC EPTP-switching.
     * Address must be the PA of g_Shv.VmFuncEptpListPage. Allocated and
     * populated at DriverEntry (after both EPTPs exist). */
    if ((secondaryProc & CPU_BASED2_ENABLE_VMFUNC) && g_Shv.VmFuncEptpListPagePa != 0) {
        __vmx_vmwrite(VMCS_CTRL_EPTP_LIST_ADDR, g_Shv.VmFuncEptpListPagePa);
        /* VMFUNC controls — bit 0 enables EPTP-switching (leaf 0). */
        __vmx_vmwrite(VMCS_CTRL_VMFUNC_CTLS, VMFUNC_CTL_EPTP_SWITCHING);
    }

    /* Item #9 — per-VCPU #VE info area address (only meaningful when
     * EPT_VIOLATION_VE is enabled; left here for the future enable
     * path so the address is already wired). */
    if ((secondaryProc & CPU_BASED2_EPT_VIOLATION_VE) && Vcpu->VeInfoAreaPa != 0) {
        __vmx_vmwrite(VMCS_CTRL_VIRT_EXCEPTION_INFO_ADDR, Vcpu->VeInfoAreaPa);
    }

    /* VM-exit controls: 64-bit host + save debug + EFER save/load.
     * NO ACK_INTERRUPT_ON_EXIT: without it, external interrupts stay pending
     * and are delivered to the guest IDT naturally on VMRESUME (the correct
     * behavior for a pass-through hypervisor). With ACK enabled, the LAPIC
     * acknowledges the interrupt during VM-exit but the handler never
     * re-injects it → all interrupts are silently dropped → system freezes. */
    ULONG32 exitCtls = ShvAdjustControls(
        VM_EXIT_HOST_ADDR_SPACE_SIZE | VM_EXIT_SAVE_DEBUG_CTLS |
        VM_EXIT_LOAD_IA32_EFER | VM_EXIT_SAVE_IA32_EFER,
        ShvGetExitMsr()
    );
    __vmx_vmwrite(VMCS_CTRL_VMEXIT_CONTROLS, exitCtls);

    /* VM-entry controls: 64-bit guest + load debug controls + load EFER */
    ULONG32 entryCtls = ShvAdjustControls(
        VM_ENTRY_IA32E_MODE_GUEST | VM_ENTRY_LOAD_DEBUG_CTLS | VM_ENTRY_LOAD_IA32_EFER,
        ShvGetEntryMsr()
    );
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_CONTROLS, entryCtls);

    /* MSR bitmap — populate VMX/EFER intercepts so exit_msr.c cached
     * returns actually fire on guest RDMSR/WRMSR for those MSRs.
     * Items #3 + #7. Bitmap was zeroed at allocation in vmx.c; we set
     * specific bits here. Idempotent across VMCS re-launch. */
    ShvSetupMsrBitmapIntercepts(Vcpu->MsrBitmap);
    __vmx_vmwrite(VMCS_CTRL_MSR_BITMAP_ADDR, Vcpu->MsrBitmapPa);

    /* Item #3 — initialize VMCS_CTRL_TSC_OFFSET to 0. exit_misc.c and
     * exit_msr.c will subtract bare-metal-cycle estimates from this on
     * each intercepted instruction so timed RDTSC/RDTSCP sandwiches
     * around our exits report deltas close to bare metal. */
    __vmx_vmwrite(VMCS_CTRL_TSC_OFFSET, 0);

    /* Exception bitmap: intercept #BP (bit 3) from the start on ALL CPUs.
     * This ensures EPT INT3 hooks work immediately without relying on
     * lazy InveptGeneration sync — eliminates the race where a CPU
     * executes a hooked function before its exception bitmap is synced.
     * When no hooks are installed, #BP exits are re-injected to guest
     * (handled by the fall-through re-injection code in exit_dispatch.c). */
    __vmx_vmwrite(VMCS_CTRL_EXCEPTION_BITMAP, (1UL << 3));

    /*
     * CR0/CR4 guest-host masks:
     * Mask = which bits the hypervisor owns (VM-exit on write, shadow on read).
     * Shadow = what the guest sees when reading masked bits.
     *
     * We intercept CR4.VMXE to hide our presence.
     * CR0: only intercept VMX-required fixed bits.
     */
    ULONG64 cr0Mask = cr0Fixed0;   /* Only VMX-mandated bits */
    ULONG64 cr4Mask = CR4_VMXE;    /* Only hide VMXE */

    __vmx_vmwrite(VMCS_CTRL_CR0_GUEST_HOST_MASK, cr0Mask);
    __vmx_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, cr0);
    __vmx_vmwrite(VMCS_CTRL_CR4_GUEST_HOST_MASK, cr4Mask);
    __vmx_vmwrite(VMCS_CTRL_CR4_READ_SHADOW, Vcpu->OriginalCr4 & ~CR4_VMXE);

    /* No CR3 target values */
    __vmx_vmwrite(VMCS_CTRL_CR3_TARGET_COUNT, 0);

    /* Clear entry interrupt injection */
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFO, 0);
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR, 0);
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_INSTRUCTION_LEN, 0);
    __vmx_vmwrite(VMCS_CTRL_VMEXIT_MSR_STORE_COUNT, 0);
    __vmx_vmwrite(VMCS_CTRL_VMEXIT_MSR_LOAD_COUNT, 0);
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_MSR_LOAD_COUNT, 0);

    /* Save control fields for post-mortem diagnostics (readable from guest mode) */
    Vcpu->DiagPinBased = pinBased;
    Vcpu->DiagProcBased = primaryProc;
    Vcpu->DiagProcBased2 = secondaryProc;
    Vcpu->DiagExitCtls = exitCtls;
    Vcpu->DiagEntryCtls = entryCtls;

    SHV_LOG("CPU %lu: VMCS configured (pin=0x%08X, pri=0x%08X, sec=0x%08X, exit=0x%08X, entry=0x%08X)",
            Vcpu->ProcessorIndex, pinBased, primaryProc, secondaryProc, exitCtls, entryCtls);

    return STATUS_SUCCESS;
}
