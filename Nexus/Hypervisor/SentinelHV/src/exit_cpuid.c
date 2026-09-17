/**
 * @file exit_cpuid.c
 * @brief CPUID VM-exit handler — HV-7 stealth (hides hypervisor presence).
 *
 * Replaces the previous broadcast-style handler that advertised SentinelHV
 * via "SntlHV SntlHV" at leaf 0x40000000 and set CPUID.1.ECX[31]. the target's
 * UM Launcher EXE contains the literal string "SntlHV SSntl" at offset
 * 0x1E03988 — the target blacklists this HV by name.
 *
 * New behavior:
 *   - Leaf 1: CLEAR ECX bit 31 (report no hypervisor)
 *   - Leaves 0x40000000..0x4FFFFFFF: return cached bare-metal invalid-leaf
 *     response (looks identical to no HV)
 *   - Other out-of-range leaves: same cached bare-metal response for
 *     consistency (don't leak different responses per out-of-range leaf)
 *   - Valid leaves: passthrough real CPUID
 *
 * The bare-metal invalid-leaf response is captured by
 * ShvInitStealthCpuidCache(), which runs in DriverEntry BEFORE VMXON.
 */

#include "shv.h"


VOID
ShvInitStealthCpuidCache(VOID)
{
    int cpuInfo[4] = { 0 };

    if (g_Shv.StealthCache.Initialized)
        return;

    /* Sample the bare-metal response for an out-of-range leaf. On Intel,
     * any leaf > max_std && < 0x80000000 returns a consistent value
     * (typically the response of max_std itself). Sample ONCE and replay. */
    __cpuidex(cpuInfo, 0x13371337, 0);
    g_Shv.StealthCache.InvalidLeafResponse[0] = (UINT32)cpuInfo[0];
    g_Shv.StealthCache.InvalidLeafResponse[1] = (UINT32)cpuInfo[1];
    g_Shv.StealthCache.InvalidLeafResponse[2] = (UINT32)cpuInfo[2];
    g_Shv.StealthCache.InvalidLeafResponse[3] = (UINT32)cpuInfo[3];

    __cpuidex(cpuInfo, 0, 0);
    g_Shv.StealthCache.MaxStdLeaf = (UINT32)cpuInfo[0];

    __cpuidex(cpuInfo, (int)0x80000000, 0);
    g_Shv.StealthCache.MaxExtLeaf = (UINT32)cpuInfo[0];

    /* Hardware-supported XCR0 mask for future XSETBV validation */
    __cpuidex(cpuInfo, 0x0D, 0);
    g_Shv.StealthCache.ValidXcr0Mask =
        ((UINT64)(UINT32)cpuInfo[3] << 32) | (UINT64)(UINT32)cpuInfo[0];

    /* ── Pre-VMXON MSR snapshots ────────────────────────────────────
     * Sample VMX-capability MSRs and EFER while we are still in
     * non-root. Once VMXON runs, IA32_FEATURE_CONTROL.LOCK is set and
     * the live VMX MSRs reflect our VMX-on state. Replaying the bare-
     * metal values to guest RDMSR makes the system look identical to
     * a VMX-capable but VMX-off CPU — which is what Javelin's MSR
     * consistency-block check expects on a non-virtualized box. */
    g_Shv.StealthCache.FeatureControlMsr   = __readmsr(IA32_FEATURE_CONTROL);
    g_Shv.StealthCache.VmxBasicMsr         = __readmsr(IA32_VMX_BASIC);
    g_Shv.StealthCache.VmxPinbasedMsr      = __readmsr(IA32_VMX_PINBASED_CTLS);
    g_Shv.StealthCache.VmxProcbasedMsr     = __readmsr(IA32_VMX_PROCBASED_CTLS);
    g_Shv.StealthCache.VmxExitCtlsMsr      = __readmsr(IA32_VMX_EXIT_CTLS);
    g_Shv.StealthCache.VmxEntryCtlsMsr     = __readmsr(IA32_VMX_ENTRY_CTLS);
    g_Shv.StealthCache.VmxMiscMsr          = __readmsr(IA32_VMX_MISC);
    g_Shv.StealthCache.VmxCr0Fixed0Msr     = __readmsr(IA32_VMX_CR0_FIXED0);
    g_Shv.StealthCache.VmxCr0Fixed1Msr     = __readmsr(IA32_VMX_CR0_FIXED1);
    g_Shv.StealthCache.VmxCr4Fixed0Msr     = __readmsr(IA32_VMX_CR4_FIXED0);
    g_Shv.StealthCache.VmxCr4Fixed1Msr     = __readmsr(IA32_VMX_CR4_FIXED1);
    g_Shv.StealthCache.VmxProcbased2Msr    = __readmsr(IA32_VMX_PROCBASED_CTLS2);
    g_Shv.StealthCache.VmxTruePinbasedMsr  = __readmsr(IA32_VMX_TRUE_PINBASED_CTLS);
    g_Shv.StealthCache.VmxTrueProcbasedMsr = __readmsr(IA32_VMX_TRUE_PROCBASED_CTLS);
    g_Shv.StealthCache.VmxTrueExitCtlsMsr  = __readmsr(IA32_VMX_TRUE_EXIT_CTLS);
    g_Shv.StealthCache.VmxTrueEntryCtlsMsr = __readmsr(IA32_VMX_TRUE_ENTRY_CTLS);
    /* IA32_VMX_VMCS_ENUM (0x48A), IA32_VMX_EPT_VPID_CAP (0x48C) and
     * IA32_VMX_VMFUNC (0x491) — sample if available. The first is
     * always present once VMX is supported. The latter two depend on
     * ProcBased2 capability bits but reading the MSR directly is safe
     * (returns 0 if not supported in the architecture, may #GP on some
     * pre-Sandy-Bridge silicon — we already require Skylake+). */
    g_Shv.StealthCache.VmxVmcsEnumMsr      = __readmsr(0x48A);
    g_Shv.StealthCache.VmxEptVpidCapMsr    = __readmsr(0x48C);
    g_Shv.StealthCache.VmxVmfuncMsr        = __readmsr(0x491);
    g_Shv.StealthCache.EferMsr             = __readmsr(IA32_EFER);
    g_Shv.StealthCache.MsrCacheValid       = TRUE;

    g_Shv.StealthCache.Initialized = TRUE;

    SHV_LOG("CPUID stealth cache: MaxStd=0x%X MaxExt=0x%X Invalid={0x%X,0x%X,0x%X,0x%X}",
            g_Shv.StealthCache.MaxStdLeaf,
            g_Shv.StealthCache.MaxExtLeaf,
            g_Shv.StealthCache.InvalidLeafResponse[0],
            g_Shv.StealthCache.InvalidLeafResponse[1],
            g_Shv.StealthCache.InvalidLeafResponse[2],
            g_Shv.StealthCache.InvalidLeafResponse[3]);
}


/**
 * Check if a CPUID leaf is out-of-range on bare metal and should return
 * the cached bare-metal response instead of real CPUID.
 */
static BOOLEAN
ShvIsInvalidLeaf(UINT32 leaf)
{
    if (!g_Shv.StealthCache.Initialized)
        return FALSE;

    /* Hypervisor-reserved range */
    if (leaf >= 0x40000000 && leaf <= 0x4FFFFFFF)
        return TRUE;

    /* Beyond max standard leaf but below extended range */
    if (leaf > g_Shv.StealthCache.MaxStdLeaf && leaf < 0x80000000)
        return TRUE;

    /* Beyond max extended leaf */
    if (leaf >= 0x80000000 && leaf > g_Shv.StealthCache.MaxExtLeaf)
        return TRUE;

    return FALSE;
}


/**
 * @brief CPUID VM-exit handler (stealth version).
 *
 * Key behaviors:
 *   - Invalid/HV-range leaves: cached bare-metal response
 *   - Leaf 1: CLEAR ECX bit 31 (hide HV)
 *   - Valid leaves: passthrough real CPUID
 *
 * @param GuestContext  Guest registers; RAX=leaf, RCX=subleaf on entry.
 */
void
ShvHandleCpuid(
    _Inout_ PGUEST_CONTEXT GuestContext
    )
{
    int cpuInfo[4] = { 0 };
    ULONG32 leaf = (ULONG32)GuestContext->Rax;
    ULONG32 subleaf = (ULONG32)GuestContext->Rcx;

    /* Replay bare-metal response for any out-of-range leaf. This covers
     * the hypervisor-reserved range (0x40000000..0x4FFFFFFF) and any
     * other invalid leaf — preventing the target from probing for HV presence
     * via unusual leaf numbers. */
    if (ShvIsInvalidLeaf(leaf)) {
        cpuInfo[0] = (int)g_Shv.StealthCache.InvalidLeafResponse[0];
        cpuInfo[1] = (int)g_Shv.StealthCache.InvalidLeafResponse[1];
        cpuInfo[2] = (int)g_Shv.StealthCache.InvalidLeafResponse[2];
        cpuInfo[3] = (int)g_Shv.StealthCache.InvalidLeafResponse[3];
        goto done;
    }

    /* Valid leaf — execute real CPUID */
    __cpuidex(cpuInfo, leaf, subleaf);

    /* Leaf 1: clear hypervisor-present bit. Real hardware has this = 0. */
    if (leaf == 1) {
        cpuInfo[2] &= ~(1 << 31);
    }

done:
    GuestContext->Rax = (ULONG64)(ULONG32)cpuInfo[0];
    GuestContext->Rbx = (ULONG64)(ULONG32)cpuInfo[1];
    GuestContext->Rcx = (ULONG64)(ULONG32)cpuInfo[2];
    GuestContext->Rdx = (ULONG64)(ULONG32)cpuInfo[3];
}
