/**
 * @file extract_km_ciphers.c
 * @brief KM cipher-function exit-trap: 80-site EPT exec-trap pipeline.
 *
 * Installs EPT execute-traps (X=0) on the exit page of each of the 80 the target
 * KM cipher functions. On each EPT violation:
 *   - RIP checked against function bounds and for 0xC3 (near ret)
 *   - If match: captures all 16 GPRs + 256-byte output buffer snapshot
 *   - Always: temporarily restores X, enables MTF for single-step re-arm
 *
 * Install flow (from VMX root, PendingCipherTrapOp=INSTALL):
 *   ShvCipherTrapInstall(KmBase, KmSize):
 *     for each site[i]:
 *       trap_rva  = fn_end > cipher+8 ? fn_end-1 : cipher_rva
 *       trap_pa   = MmGetPhysicalAddress(KmBase + trap_rva)
 *       pt        = ShvEptCipherSplitFor(trap_pa & ~2MB)
 *       pt[idx].Execute = 0
 *       CipherTrapSitePa[i] = trap_pa & ~0xFFF
 *
 * EPT violation flow (VMX root, execute fault):
 *   ShvCipherTrapTryHandle → scan CipherTrapSitePa[] → log if ret → rearm
 *
 * MTF flow:
 *   ShvCipherTrapRearm → find PTE → Execute = 0 → INVEPT
 */

#include "shv.h"

#define CPU_BASED_MONITOR_TRAP_FLAG  (1UL << 27)

/* ── Site table ──────────────────────────────────────────────────── */

typedef struct {
    UINT32 cipher_rva;
    UINT32 fn_start_rva;
    UINT32 fn_end_rva;
} KM_CIPHER_SITE;

#define KM_CIPHER_SITE_COUNT 80

static const KM_CIPHER_SITE g_KmCipherSites[KM_CIPHER_SITE_COUNT] = {
    /*  0 */ { 0x001795DD, 0x00179343, 0x00179C79 },
    /*  1 */ { 0x001796AE, 0x00179343, 0x00179C79 },
    /*  2 */ { 0x00179A28, 0x00179343, 0x00179C79 },
    /*  3 */ { 0x00179A84, 0x00179343, 0x00179C79 },
    /*  4 */ { 0x00213D3E, 0x00213C90, 0x00214769 },
    /*  5 */ { 0x0021429B, 0x00214202, 0x00214769 },
    /*  6 */ { 0x00214393, 0x00214202, 0x00214769 },
    /*  7 */ { 0x002143D5, 0x00214202, 0x00214769 },
    /*  8 */ { 0x002A2BDF, 0x002A2A2E, 0x002A2A2E },  /* bad bounds — use cipher page */
    /*  9 */ { 0x002A2CD1, 0x002A2A2E, 0x002A2A2E },  /* bad bounds — use cipher page */
    /* 10 */ { 0x02C45B3D, 0x02C4544D, 0x02C4644D },
    /* 11 */ { 0x00430708, 0x004306F0, 0x00430827 },
    /* 12 */ { 0x004308B5, 0x00430830, 0x00431311 },
    /* 13 */ { 0x0047F7F5, 0x0047F750, 0x00480750 },
    /* 14 */ { 0x0047F910, 0x0047F750, 0x00480750 },
    /* 15 */ { 0x0049170A, 0x00491480, 0x004918BA },
    /* 16 */ { 0x00491856, 0x00491480, 0x004918BA },
    /* 17 */ { 0x0049ABF1, 0x0049AB70, 0x0049AD51 },
    /* 18 */ { 0x0049ACF6, 0x0049AB70, 0x0049AD51 },
    /* 19 */ { 0x0049EC15, 0x0049EB70, 0x0049FB70 },
    /* 20 */ { 0x0049ED30, 0x0049EB70, 0x0049FB70 },
    /* 21 */ { 0x004A3E55, 0x004A3DB0, 0x004A4DB0 },
    /* 22 */ { 0x004A3F70, 0x004A3DB0, 0x004A4DB0 },
    /* 23 */ { 0x004C0239, 0x004C004D, 0x004C0059 },  /* cipher_rva > fn_end */
    /* 24 */ { 0x004C0354, 0x004C004D, 0x004C0059 },  /* cipher_rva > fn_end */
    /* 25 */ { 0x004D8449, 0x004D83A0, 0x004D87F2 },
    /* 26 */ { 0x004D8564, 0x004D83A0, 0x004D87F2 },
    /* 27 */ { 0x004DB099, 0x004DB00D, 0x004DC00D },
    /* 28 */ { 0x004DB1B4, 0x004DB00D, 0x004DC00D },
    /* 29 */ { 0x004E1915, 0x004E1870, 0x004E2870 },
    /* 30 */ { 0x004E1A30, 0x004E1870, 0x004E2870 },
    /* 31 */ { 0x0050AD59, 0x0050ACB0, 0x0050BCB0 },
    /* 32 */ { 0x0050AE74, 0x0050ACB0, 0x0050BCB0 },
    /* 33 */ { 0x0050C595, 0x0050C4F0, 0x0050D4F0 },
    /* 34 */ { 0x0050C6B0, 0x0050C4F0, 0x0050D4F0 },
    /* 35 */ { 0x0050C915, 0x0050C870, 0x0050D870 },
    /* 36 */ { 0x0050CA30, 0x0050C870, 0x0050D870 },
    /* 37 */ { 0x0050CC95, 0x0050CBF0, 0x0050DBF0 },
    /* 38 */ { 0x0050CDB0, 0x0050CBF0, 0x0050DBF0 },
    /* 39 */ { 0x0050D015, 0x0050CF70, 0x0050DF70 },
    /* 40 */ { 0x0050D130, 0x0050CF70, 0x0050DF70 },
    /* 41 */ { 0x0050E0C5, 0x0050E020, 0x0050F020 },
    /* 42 */ { 0x0050E1E0, 0x0050E020, 0x0050F020 },
    /* 43 */ { 0x0051C609, 0x0051C560, 0x0051C828 },
    /* 44 */ { 0x0051C724, 0x0051C560, 0x0051C828 },
    /* 45 */ { 0x00523FC1, 0x00523F40, 0x0052411A },
    /* 46 */ { 0x005240BF, 0x00523F40, 0x0052411A },
    /* 47 */ { 0x00538DE9, 0x00538CDD, 0x00538D02 },  /* cipher_rva > fn_end */
    /* 48 */ { 0x00538F04, 0x00538CDD, 0x00538D02 },  /* cipher_rva > fn_end */
    /* 49 */ { 0x00542595, 0x005424F0, 0x0054296B },
    /* 50 */ { 0x005426B0, 0x005424F0, 0x0054296B },
    /* 51 */ { 0x00551BC5, 0x00551B20, 0x00552B20 },
    /* 52 */ { 0x00551CE0, 0x00551B20, 0x00552B20 },
    /* 53 */ { 0x0055A985, 0x0055A8E0, 0x0055B8E0 },
    /* 54 */ { 0x0055AAA0, 0x0055A8E0, 0x0055B8E0 },
    /* 55 */ { 0x005706B9, 0x005704F3, 0x005704F9 },  /* cipher_rva > fn_end */
    /* 56 */ { 0x005707D4, 0x005704F3, 0x005704F9 },  /* cipher_rva > fn_end */
    /* 57 */ { 0x00573859, 0x005737B0, 0x005747B0 },
    /* 58 */ { 0x00573974, 0x005737B0, 0x005747B0 },
    /* 59 */ { 0x005757D5, 0x00575730, 0x00575E2C },
    /* 60 */ { 0x005758F0, 0x00575730, 0x00575E2C },
    /* 61 */ { 0x0057E3D5, 0x0057E330, 0x0057F330 },
    /* 62 */ { 0x0057E4F0, 0x0057E330, 0x0057F330 },
    /* 63 */ { 0x00581565, 0x005814C0, 0x005824C0 },
    /* 64 */ { 0x00581680, 0x005814C0, 0x005824C0 },
    /* 65 */ { 0x005BD495, 0x005BD3F0, 0x005BE3F0 },
    /* 66 */ { 0x005BD5B0, 0x005BD3F0, 0x005BE3F0 },
    /* 67 */ { 0x005C988A, 0x005C9731, 0x005C9739 },  /* cipher_rva > fn_end */
    /* 68 */ { 0x005C99D6, 0x005C9731, 0x005C9739 },  /* cipher_rva > fn_end */
    /* 69 */ { 0x005CA2A9, 0x005CA200, 0x005CA66B },
    /* 70 */ { 0x005CA3C4, 0x005CA200, 0x005CA66B },
    /* 71 */ { 0x0000ADE3, 0x0000AD90, 0x0000B668 },
    /* 72 */ { 0x0000AED4, 0x0000AECE, 0x0000B668 },
    /* 73 */ { 0x0000B049, 0x0000AECE, 0x0000B668 },
    /* 74 */ { 0x0000B329, 0x0000B28B, 0x0000B668 },
    /* 75 */ { 0x0000B4D4, 0x0000B3B4, 0x0000B668 },
    /* 76 */ { 0x000FAC2C, 0x000FABA0, 0x000FB65A },
    /* 77 */ { 0x000FB3C4, 0x000FB014, 0x000FB65A },
    /* 78 */ { 0x000FB47A, 0x000FB014, 0x000FB65A },
    /* 79 */ { 0x000FB53F, 0x000FB014, 0x000FB65A },
};

C_ASSERT(ARRAYSIZE(g_KmCipherSites) == KM_CIPHER_SITE_COUNT);

/* Per-site skip mask (bits 0..63 = sites 0..63, bits 64..79 = sites 64..79).
 * Sites with their bit set are still trapped but records are NOT pushed to ring.
 * Set via CIPHER_TRAP_OP_SETMASK pending-op from UM. */
static volatile ULONG64 g_CipherSkipMaskLo = 0;
static volatile ULONG64 g_CipherSkipMaskHi = 0;

VOID ShvCipherTrapSetSkipMask(ULONG64 maskLo, ULONG64 maskHi)
{
    InterlockedExchange64((volatile LONG64*)&g_CipherSkipMaskLo, (LONG64)maskLo);
    InterlockedExchange64((volatile LONG64*)&g_CipherSkipMaskHi, (LONG64)maskHi);
    SHV_LOG("CipherTrap: skip mask set lo=0x%llX hi=0x%llX", maskLo, maskHi);
}

static BOOLEAN IsSiteSkipped(ULONG siteIdx)
{
    if (siteIdx < 64)  return (g_CipherSkipMaskLo >> siteIdx) & 1;
    if (siteIdx < 128) return (g_CipherSkipMaskHi >> (siteIdx - 64)) & 1;
    return FALSE;
}

/* ── Resource preparation ────────────────────────────────────────── */

NTSTATUS
ShvCipherTrapPrepareResources(VOID)
{
    NTSTATUS st = ShvEptCipherPrepareResources();
    if (!NT_SUCCESS(st))
        return st;

    if (g_Shv.CipherTrapLog == NULL) {
        SIZE_T sz = CIPHER_RECORD_MAX * sizeof(KM_CIPHER_RECORD);
        PVOID buf = ShvAllocateContiguousMemory(sz);
        if (!buf) {
            SHV_ERR("CipherTrap: ring buffer alloc failed (%llu bytes)", (ULONG64)sz);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(buf, sz);
        g_Shv.CipherTrapLog = (PKM_CIPHER_RECORD)buf;
        SHV_LOG("CipherTrap: ring buffer allocated (%llu KB)", (ULONG64)(sz / 1024));
    }
    return STATUS_SUCCESS;
}

/* ── Helpers ─────────────────────────────────────────────────────── */

/* Safe kernel VA read — verifies page is present before dereferencing.
 * Only for CANONICAL KERNEL addresses (high half). From VMX root. */
static BOOLEAN
CipherSafeReadKva(
    ULONG64 va,
    PVOID   out,
    SIZE_T  size
)
{
    if (!out || !size) return FALSE;
    if ((va & 0xFFFF800000000000ULL) != 0xFFFF800000000000ULL) return FALSE;

    UCHAR* dst = (UCHAR*)out;
    ULONG64 rem = size;
    ULONG64 cur = va;
    while (rem > 0) {
        PHYSICAL_ADDRESS pa = MmGetPhysicalAddress((PVOID)cur);
        if (pa.QuadPart == 0) return FALSE;
        ULONG64 off   = cur & 0xFFF;
        ULONG64 chunk = 0x1000 - off;
        if (chunk > rem) chunk = rem;
        if (chunk > 1) {
            PHYSICAL_ADDRESS paLast = MmGetPhysicalAddress((PVOID)(cur + chunk - 1));
            if (paLast.QuadPart == 0) return FALSE;
        }
        RtlCopyMemory(dst, (PVOID)cur, (SIZE_T)chunk);
        dst += chunk;
        cur += chunk;
        rem -= chunk;
    }
    return TRUE;
}

/* Determine which register most likely holds the output buffer pointer.
 * Try RCX, RDX, R8, R9, R14, RDI in order — first canonical kernel VA wins. */
static ULONG64
SelectOutputBufPtr(
    const GUEST_CONTEXT* gc
)
{
    /* Priority order: args first, then callee-saved.
     * R12/R13 added for site 19 which leaves output in callee-saved regs. */
    ULONG64 candidates[] = {
        gc->Rcx, gc->Rdx, gc->R8, gc->R9,
        gc->R14, gc->R13, gc->R12,
        gc->Rdi, gc->Rsi, gc->R15
    };
    for (ULONG i = 0; i < ARRAYSIZE(candidates); i++) {
        ULONG64 v = candidates[i];
        if (v != 0 && (v & 0xFFFF800000000000ULL) == 0xFFFF800000000000ULL)
            return v;
    }
    return 0;
}

static void
PushCipherRecord(
    ULONG   siteIndex,
    ULONG64 guestRip,
    ULONG64 guestCr3,
    ULONG   cpuIndex,
    const   GUEST_CONTEXT* gc
)
{
    if (!g_Shv.CipherTrapLog) return;

    LONG slot = InterlockedIncrement(&g_Shv.CipherTrapLogIndex) - 1;
    slot = slot % CIPHER_RECORD_MAX;
    if (slot < 0) slot += CIPHER_RECORD_MAX;

    PKM_CIPHER_RECORD rec = &g_Shv.CipherTrapLog[slot];
    rec->SiteIndex = siteIndex;
    rec->CpuIndex  = cpuIndex;
    rec->Tsc       = __rdtsc();
    rec->GuestRip  = guestRip;
    rec->GuestCr3  = guestCr3;
    rec->Rax = gc->Rax; rec->Rcx = gc->Rcx; rec->Rdx = gc->Rdx; rec->Rbx = gc->Rbx;
    rec->Rsp = gc->Rsp; rec->Rbp = gc->Rbp; rec->Rsi = gc->Rsi; rec->Rdi = gc->Rdi;
    rec->R8  = gc->R8;  rec->R9  = gc->R9;  rec->R10 = gc->R10; rec->R11 = gc->R11;
    rec->R12 = gc->R12; rec->R13 = gc->R13; rec->R14 = gc->R14; rec->R15 = gc->R15;

    /* Attempt output buffer capture. */
    ULONG64 bufVa = SelectOutputBufPtr(gc);
    rec->BufVa = bufVa;
    if (bufVa) {
        BOOLEAN ok = CipherSafeReadKva(bufVa, rec->Payload, CIPHER_TRAP_PAYLOAD_BYTES);
        rec->PayloadLen = ok ? CIPHER_TRAP_PAYLOAD_BYTES : 0;
        if (!ok) InterlockedIncrement(&g_Shv.CipherTrapCapFails);
    } else {
        rec->PayloadLen = 0;
        InterlockedIncrement(&g_Shv.CipherTrapCapFails);
    }
    rec->Reserved = 0;

    InterlockedIncrement(&g_Shv.CipherTrapHits);
    InterlockedIncrement(&g_Shv.CipherTrapLogTotal);
}

/* ── Install / Uninstall ─────────────────────────────────────────── */

NTSTATUS
ShvCipherTrapInstall(
    _In_ ULONG64 KmBase,
    _In_ ULONG64 KmSize
    )
{
    if (!g_Shv.CipherTrapLog) {
        SHV_ERR("CipherTrap: ring buffer not allocated — call PrepareResources first");
        return STATUS_UNSUCCESSFUL;
    }

    g_Shv.CipherTrapKmBase = KmBase;
    g_Shv.CipherTrapKmEnd  = KmBase + KmSize;

    /* Clear any stale per-site PAs. */
    RtlZeroMemory(g_Shv.CipherTrapSitePa, sizeof(g_Shv.CipherTrapSitePa));

    ULONG installed = 0;

    for (ULONG i = 0; i < KM_CIPHER_SITE_COUNT; i++) {
        const KM_CIPHER_SITE* s = &g_KmCipherSites[i];

        /* Compute trap RVA: last byte of function if bounds are good,
         * else the cipher site itself (function end is unknown). */
        UINT32 trap_rva;
        if (s->fn_end_rva > s->cipher_rva + 8) {
            trap_rva = s->fn_end_rva - 1;
        } else {
            trap_rva = s->cipher_rva;
        }

        /* Bounds check against image size. */
        if ((ULONG64)trap_rva >= KmSize) {
            SHV_WARN("CipherTrap: site %u trap_rva 0x%X >= KmSize, skip", i, trap_rva);
            continue;
        }

        PHYSICAL_ADDRESS pa = MmGetPhysicalAddress((PVOID)(KmBase + trap_rva));
        if (pa.QuadPart == 0) {
            SHV_WARN("CipherTrap: site %u VA 0x%llX not mapped, skip",
                     i, KmBase + trap_rva);
            continue;
        }

        ULONG64 pa4k  = pa.QuadPart & ~(ULONG64)0xFFFULL;
        ULONG64 pa2mb = pa.QuadPart & ~(ULONG64)0x1FFFFFULL;  /* 2MB-align */

        /* Split the 2MB EPT page if needed and clear Execute on our 4KB page. */
        EPT_PTE* pt = ShvEptCipherSplitFor(pa2mb);
        if (!pt) {
            SHV_WARN("CipherTrap: site %u split failed (pool full?)", i);
            continue;
        }

        ULONG pteIdx = EPT_PTE_INDEX(pa.QuadPart);
        pt[pteIdx].Execute = 0;

        g_Shv.CipherTrapSitePa[i] = pa4k;
        installed++;
    }

    /* Flush EPT TLB on all logical processors. */
    INVEPT_DESCRIPTOR desc;
    desc.EptPointer = ShvEptGetEptp();
    desc.Reserved   = 0;
    if (desc.EptPointer)
        ShvInvept(INVEPT_ALL_CONTEXTS, &desc);

    InterlockedIncrement(&g_Shv.InveptGeneration);

    g_Shv.CipherTrapSitesInstalled = installed;
    g_Shv.CipherTrapActive = 1;

    SHV_LOG("CipherTrap: installed %u/%u sites (KmBase=0x%llX KmSize=0x%llX)",
            installed, KM_CIPHER_SITE_COUNT, KmBase, KmSize);
    return STATUS_SUCCESS;
}

VOID
ShvCipherTrapUninstall(VOID)
{
    for (ULONG i = 0; i < CIPHER_TRAP_MAX_SITES; i++) {
        if (g_Shv.CipherTrapSitePa[i] == 0) continue;
        EPT_PTE* pte = ShvEptCipherFindPte(g_Shv.CipherTrapSitePa[i]);
        if (pte) pte->Execute = 1;
        g_Shv.CipherTrapSitePa[i] = 0;
    }

    g_Shv.CipherTrapActive         = 0;
    g_Shv.CipherTrapSitesInstalled = 0;

    INVEPT_DESCRIPTOR desc;
    desc.EptPointer = ShvEptGetEptp();
    desc.Reserved   = 0;
    if (desc.EptPointer)
        ShvInvept(INVEPT_ALL_CONTEXTS, &desc);

    InterlockedIncrement(&g_Shv.InveptGeneration);
    SHV_LOG("CipherTrap: uninstalled");
}

/* ── EPT Violation Handler ───────────────────────────────────────── */

ULONG
ShvCipherTrapTryHandle(
    _In_ ULONG64 GuestPa,
    _In_ ULONG64 GuestRip,
    _In_ ULONG64 GuestCr3,
    _In_ ULONG64 ExitQualification,
    _In_ ULONG   CpuIndex,
    _In_ PVCPU_DATA Vcpu,
    _In_ PGUEST_CONTEXT GuestContext
    )
{
    /* Only handle instruction-fetch violations. */
    if (!(ExitQualification & EPT_VIOLATION_INSTRUCTION_FETCH))
        return 0;

    ULONG64 faultPa4k = GuestPa & ~(ULONG64)0xFFF;
    ULONG64 kmBase    = g_Shv.CipherTrapKmBase;

    /* Scan ALL sites for a page match — pairs share the same function/page,
     * so we must log for every matching site (not just the first). */
    int firstMatch = -1;
    for (int i = 0; i < CIPHER_TRAP_MAX_SITES; i++) {
        if (g_Shv.CipherTrapSitePa[i] != faultPa4k) continue;
        if (firstMatch < 0) firstMatch = i;  /* save for rearm index */

        const KM_CIPHER_SITE* s = &g_KmCipherSites[i];
        ULONG64 fnStart = kmBase + s->fn_start_rva;
        ULONG64 fnEnd   = kmBase + s->fn_end_rva;
        BOOLEAN goodBounds = (s->fn_end_rva > s->cipher_rva + 8);

        BOOLEAN inBounds;
        if (goodBounds) {
            inBounds = (GuestRip >= fnStart && GuestRip < fnEnd + 0x80);
        } else {
            ULONG64 center = kmBase + s->cipher_rva;
            inBounds = (GuestRip >= center - 0x100 && GuestRip < center + 0x400);
        }

        if (inBounds && !IsSiteSkipped((ULONG)i)) {
            volatile UCHAR* rip = (volatile PUCHAR)(ULONG_PTR)GuestRip;
            if (*rip == 0xC3) {
                PushCipherRecord((ULONG)i, GuestRip, GuestCr3, CpuIndex, GuestContext);
            }
        }
    }

    if (firstMatch < 0) return 0;  /* No page match at all — not our trap */

    /* Restore Execute on this page so the guest can proceed. MTF re-arms. */
    EPT_PTE* pte = ShvEptCipherFindPte(faultPa4k);
    if (pte) pte->Execute = 1;

    /* Enable MTF for single-step re-arm. */
    SIZE_T procBased = 0;
    __vmx_vmread(VMCS_CTRL_PROC_BASED_EXEC, &procBased);
    procBased |= (SIZE_T)CPU_BASED_MONITOR_TRAP_FLAG;
    __vmx_vmwrite(VMCS_CTRL_PROC_BASED_EXEC, procBased);

    Vcpu->MtfCipherTrapRearmPending = TRUE;
    Vcpu->MtfCipherTrapSiteIndex    = (ULONG)firstMatch;

    /* INVEPT: flush stale TLB entry so X=1 is visible to the hardware. */
    ULONG64 eptp = ShvEptGetEptp();
    if (eptp) {
        INVEPT_DESCRIPTOR desc;
        desc.EptPointer = eptp;
        desc.Reserved   = 0;
        ShvInvept(INVEPT_SINGLE_CONTEXT, &desc);
    }

    return 1;
}

/* ── MTF Re-arm ──────────────────────────────────────────────────── */

VOID
ShvCipherTrapRearm(
    _In_ PVCPU_DATA Vcpu
    )
{
    ULONG siteIdx = Vcpu->MtfCipherTrapSiteIndex;
    if (siteIdx >= CIPHER_TRAP_MAX_SITES) return;

    ULONG64 pa4k = g_Shv.CipherTrapSitePa[siteIdx];
    if (pa4k == 0) return;

    EPT_PTE* pte = ShvEptCipherFindPte(pa4k);
    if (pte) pte->Execute = 0;

    ULONG64 eptp = ShvEptGetEptp();
    if (eptp) {
        INVEPT_DESCRIPTOR desc;
        desc.EptPointer = eptp;
        desc.Reserved   = 0;
        ShvInvept(INVEPT_SINGLE_CONTEXT, &desc);
    }
}
