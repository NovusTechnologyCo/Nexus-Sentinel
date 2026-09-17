/**
 * @file exit_msr.c
 * @brief RDMSR/WRMSR VM-exit handlers with VMX/EFER stealth + TSC compensation.
 *
 * Two stealth requirements drive this handler:
 *
 *   1. **Cached returns for VMX-residue MSRs** — IA32_FEATURE_CONTROL (0x3A),
 *      IA32_VMX_BASIC..VMFUNC (0x480-0x491), IA32_EFER (0xC0000080). Once
 *      VMXON runs, the live MSR values reflect our VMX-on state. Returning
 *      the pre-VMXON snapshot to the guest makes the system look like a
 *      VMX-capable but currently-VMX-off CPU, which is what Javelin's
 *      consistency-block expects. Cache populated by ShvInitStealthCpuidCache.
 *
 *   2. **TSC compensation** — every RDMSR/WRMSR exit costs ~1000 cycles vs.
 *      ~50-120 bare metal. A timed RDTSCP/RDMSR/RDTSCP sandwich (Javelin's
 *      stub at GameService 0x5CA58E) measures this directly. Subtract the
 *      bare-metal cost from VMCS_TSC_OFFSET on every exit so the guest's
 *      next RDTSC reads a value that approximates bare-metal-cycle progression.
 *
 * The MSR bitmap is configured to pass through most MSRs; the entries that
 * intercept are exactly the ones we need to lie about (per the cache list).
 */

#include "shv.h"

/* Bare-metal cycle estimates for TSC compensation. */
#define BARE_METAL_RDMSR_CYCLES    55
#define BARE_METAL_WRMSR_CYCLES    120

/**
 * @brief Subtract a cycle count from VMCS_CTRL_TSC_OFFSET.
 *
 * Local copy (also defined in exit_misc.c) — small and FORCEINLINE keeps
 * call overhead off the timing-critical path.
 */
static FORCEINLINE void
ShvCompensateTscOffsetMsr(ULONG64 cycles_to_hide)
{
    SIZE_T offset = 0;
    __vmx_vmread(VMCS_CTRL_TSC_OFFSET, &offset);
    offset -= (SIZE_T)cycles_to_hide;
    __vmx_vmwrite(VMCS_CTRL_TSC_OFFSET, offset);
}


/**
 * @brief Return cached pre-VMXON value for a VMX/EFER MSR, or 0 if not cached.
 *
 * @param msr_index   MSR ECX value
 * @param value_out   On hit, receives the cached value
 * @return TRUE on hit (caller returns cached value), FALSE on miss
 */
static BOOLEAN
ShvLookupCachedMsr(ULONG32 msr_index, ULONG64* value_out)
{
    if (!g_Shv.StealthCache.MsrCacheValid) {
        return FALSE;
    }

    switch (msr_index) {
    case IA32_FEATURE_CONTROL:
        *value_out = g_Shv.StealthCache.FeatureControlMsr;
        return TRUE;
    case IA32_VMX_BASIC:
        *value_out = g_Shv.StealthCache.VmxBasicMsr;
        return TRUE;
    case IA32_VMX_PINBASED_CTLS:
        *value_out = g_Shv.StealthCache.VmxPinbasedMsr;
        return TRUE;
    case IA32_VMX_PROCBASED_CTLS:
        *value_out = g_Shv.StealthCache.VmxProcbasedMsr;
        return TRUE;
    case IA32_VMX_EXIT_CTLS:
        *value_out = g_Shv.StealthCache.VmxExitCtlsMsr;
        return TRUE;
    case IA32_VMX_ENTRY_CTLS:
        *value_out = g_Shv.StealthCache.VmxEntryCtlsMsr;
        return TRUE;
    case IA32_VMX_MISC:
        *value_out = g_Shv.StealthCache.VmxMiscMsr;
        return TRUE;
    case IA32_VMX_CR0_FIXED0:
        *value_out = g_Shv.StealthCache.VmxCr0Fixed0Msr;
        return TRUE;
    case IA32_VMX_CR0_FIXED1:
        *value_out = g_Shv.StealthCache.VmxCr0Fixed1Msr;
        return TRUE;
    case IA32_VMX_CR4_FIXED0:
        *value_out = g_Shv.StealthCache.VmxCr4Fixed0Msr;
        return TRUE;
    case IA32_VMX_CR4_FIXED1:
        *value_out = g_Shv.StealthCache.VmxCr4Fixed1Msr;
        return TRUE;
    case 0x48A:    /* IA32_VMX_VMCS_ENUM */
        *value_out = g_Shv.StealthCache.VmxVmcsEnumMsr;
        return TRUE;
    case IA32_VMX_PROCBASED_CTLS2:
        *value_out = g_Shv.StealthCache.VmxProcbased2Msr;
        return TRUE;
    case 0x48C:    /* IA32_VMX_EPT_VPID_CAP */
        *value_out = g_Shv.StealthCache.VmxEptVpidCapMsr;
        return TRUE;
    case IA32_VMX_TRUE_PINBASED_CTLS:
        *value_out = g_Shv.StealthCache.VmxTruePinbasedMsr;
        return TRUE;
    case IA32_VMX_TRUE_PROCBASED_CTLS:
        *value_out = g_Shv.StealthCache.VmxTrueProcbasedMsr;
        return TRUE;
    case IA32_VMX_TRUE_EXIT_CTLS:
        *value_out = g_Shv.StealthCache.VmxTrueExitCtlsMsr;
        return TRUE;
    case IA32_VMX_TRUE_ENTRY_CTLS:
        *value_out = g_Shv.StealthCache.VmxTrueEntryCtlsMsr;
        return TRUE;
    case 0x491:    /* IA32_VMX_VMFUNC */
        *value_out = g_Shv.StealthCache.VmxVmfuncMsr;
        return TRUE;
    case IA32_EFER:
        *value_out = g_Shv.StealthCache.EferMsr;
        return TRUE;
    default:
        return FALSE;
    }
}


/**
 * @brief Handle RDMSR VM-exit.
 *
 * For cached VMX/EFER MSRs: return the pre-VMXON snapshot. For everything
 * else: __readmsr passthrough. TSC compensation on every exit.
 *
 * @param GuestContext  Guest registers; RCX=MSR index on entry.
 */
void
ShvHandleMsrRead(
    _Inout_ PGUEST_CONTEXT GuestContext
    )
{
    ULONG32 msrIndex = (ULONG32)GuestContext->Rcx;
    ULONG64 value = 0;

    if (!ShvLookupCachedMsr(msrIndex, &value)) {
        value = __readmsr(msrIndex);
    }

    GuestContext->Rax = (ULONG32)(value & 0xFFFFFFFF);
    GuestContext->Rdx = (ULONG32)(value >> 32);

    ShvCompensateTscOffsetMsr(BARE_METAL_RDMSR_CYCLES);
}

/**
 * @brief Handle WRMSR VM-exit.
 *
 * For VMX-capability MSRs: silently swallow (cannot be written from the
 * guest perspective in any case — bare-metal WRMSR to these returns #GP).
 * For IA32_EFER: validate against allowed bits and apply via VMCS guest
 * EFER (the host doesn't accept arbitrary EFER changes mid-VMX). For
 * everything else: passthrough.
 *
 * @param GuestContext  Guest registers; RCX=MSR index, EDX:EAX=value.
 */
void
ShvHandleMsrWrite(
    _Inout_ PGUEST_CONTEXT GuestContext
    )
{
    ULONG32 msrIndex = (ULONG32)GuestContext->Rcx;
    ULONG64 value = ((ULONG64)(ULONG32)GuestContext->Rdx << 32) |
                    ((ULONG64)(ULONG32)GuestContext->Rax);

    /* VMX-capability MSRs (0x480-0x491) are RO on bare metal — writing
     * raises #GP. Mirror that. */
    if (msrIndex >= 0x480 && msrIndex <= 0x491) {
        ShvInjectException(VECTOR_GP, 0);
        return;
    }

    /* IA32_FEATURE_CONTROL is RO once LOCK bit is set — which it always
     * is on a system that booted with VMX support. Inject #GP. */
    if (msrIndex == IA32_FEATURE_CONTROL) {
        ShvInjectException(VECTOR_GP, 0);
        return;
    }

    /* IA32_EFER write: write through to VMCS guest EFER so it stays
     * in sync with the guest's view, AND let the host CPU update its
     * model. The VMCS field is 64-bit but the guest write is full 64. */
    if (msrIndex == IA32_EFER) {
        __vmx_vmwrite(VMCS_GUEST_IA32_EFER, value);
        __writemsr(msrIndex, value);
        ShvCompensateTscOffsetMsr(BARE_METAL_WRMSR_CYCLES);
        return;
    }

    /* Default: passthrough. */
    __writemsr(msrIndex, value);
    ShvCompensateTscOffsetMsr(BARE_METAL_WRMSR_CYCLES);
}
