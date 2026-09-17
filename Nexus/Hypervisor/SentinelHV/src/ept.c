/**
 * @file ept.c
 * @brief EPT (Extended Page Tables) core implementation with MTRR-aware identity mapping.
 *
 * Implements Phase 1 of SentinelHV's EPT subsystem: a 512 GB identity-mapped
 * address space using 2MB large pages where every guest physical address maps
 * 1:1 to the same host physical address with full RWX permissions.
 *
 * Key components:
 *
 *   - **MTRR Parsing**: Reads IA32_MTRRCAP, IA32_MTRR_DEF_TYPE, fixed-range
 *     MTRRs (64K, 16K, 4K granularity for addresses below 1MB), and variable-
 *     range MTRRs. Stores the results in EPT_STATE for memory type lookups.
 *
 *   - **Memory Type Lookup**: ShvEptGetMemoryType resolves the correct EPT
 *     memory type for any physical address using the parsed MTRR state. Handles
 *     fixed-range priority below 1MB, variable-range conflict resolution (UC
 *     wins), and default type fallback.
 *
 *   - **Identity Map Construction**: Builds the 4-level EPT page table hierarchy
 *     (PML4 -> PDPT -> PDT) with 262,144 x 2MB large page entries. Each entry's
 *     memory type is derived from the MTRR map at its base address.
 *
 *   - **EPTP Construction**: Assembles the EPT Pointer with WB page walk type,
 *     4-level walk (length-1 = 3), and the PML4 physical address.
 *
 * This file compiles under both NT (Type 2) and UEFI (Type 1) builds. Platform
 * differences (VA-to-PA translation) are handled via #ifdef SHV_PLATFORM_NT.
 *
 * Future phases will add 4KB page splitting for selective R/W/X permission
 * control to support stealth hooks and memory isolation.
 */

#include "shv.h"
#include <ntimage.h>   /* IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER, IMAGE_SCN_MEM_EXECUTE */

/* ── Global EPT State ────────────────────────────────────────────── */

static PEPT_STATE g_EptState = NULL;

/* ── MTRR MSR Definitions ────────────────────────────────────────── */

#define IA32_MTRRCAP                0x000000FE
#define IA32_MTRR_DEF_TYPE          0x000002FF

#define IA32_MTRR_FIX64K_00000      0x00000250
#define IA32_MTRR_FIX16K_80000      0x00000258
#define IA32_MTRR_FIX16K_A0000      0x00000259
#define IA32_MTRR_FIX4K_C0000       0x00000268
#define IA32_MTRR_FIX4K_C8000       0x00000269
#define IA32_MTRR_FIX4K_D0000       0x0000026A
#define IA32_MTRR_FIX4K_D8000       0x0000026B
#define IA32_MTRR_FIX4K_E0000       0x0000026C
#define IA32_MTRR_FIX4K_E8000       0x0000026D
#define IA32_MTRR_FIX4K_F0000       0x0000026E
#define IA32_MTRR_FIX4K_F8000       0x0000026F

#define IA32_MTRR_PHYSBASE0         0x00000200
#define IA32_MTRR_PHYSMASK0         0x00000201

/**
 * @brief Query the maximum physical address width from CPUID leaf 0x80000008.
 *
 * @return Number of physical address bits supported by the CPU (e.g., 39, 46, 52).
 */
static ULONG ShvEptGetMaxPhysAddrBits(void)
{
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 0x80000008);
    return (ULONG)(cpuInfo[0] & 0xFF);
}

/* ── MTRR Parsing ────────────────────────────────────────────────── */

/**
 * @brief Read a fixed-range MTRR MSR and extract 8 memory type bytes.
 *
 * Each fixed-range MTRR MSR contains 8 memory type bytes packed into a
 * 64-bit value, one per sub-range within the MSR's address region.
 *
 * @param Msr    Fixed-range MTRR MSR index to read.
 * @param Types  Output array receiving the 8 extracted memory type bytes.
 */
static void
ShvEptReadFixedMtrr(
    _In_  ULONG32 Msr,
    _Out_ UCHAR Types[8]
    )
{
    ULONG64 val = __readmsr(Msr);
    for (int i = 0; i < 8; i++) {
        Types[i] = (UCHAR)(val >> (i * 8));
    }
}

/**
 * @brief Build the complete MTRR map from hardware MSRs.
 *
 * Reads IA32_MTRRCAP for capabilities, IA32_MTRR_DEF_TYPE for the default
 * memory type, all fixed-range MTRR MSRs (if supported and enabled), and
 * all valid variable-range MTRR pairs. Stores the results into EPT_STATE
 * for subsequent memory type lookups during EPT construction.
 *
 * @param State  EPT state to populate with MTRR data.
 */
static void
ShvEptBuildMtrrMap(
    _Inout_ PEPT_STATE State
    )
{
    ULONG64 mtrrCap = __readmsr(IA32_MTRRCAP);
    ULONG vcnt = (ULONG)(mtrrCap & 0xFF);
    BOOLEAN fixedSupported = (mtrrCap >> 8) & 1;

    ULONG64 mtrrDefType = __readmsr(IA32_MTRR_DEF_TYPE);
    State->MtrrDefaultType = (UCHAR)(mtrrDefType & 0xFF);
    State->MtrrFixedEnabled = (BOOLEAN)((mtrrDefType >> 10) & 1) && fixedSupported;

    /* Read fixed-range MTRRs */
    if (State->MtrrFixedEnabled) {
        ShvEptReadFixedMtrr(IA32_MTRR_FIX64K_00000, State->MtrrFixedRange64K);
        ShvEptReadFixedMtrr(IA32_MTRR_FIX16K_80000, &State->MtrrFixedRange16K[0]);
        ShvEptReadFixedMtrr(IA32_MTRR_FIX16K_A0000, &State->MtrrFixedRange16K[8]);
        ShvEptReadFixedMtrr(IA32_MTRR_FIX4K_C0000, &State->MtrrFixedRange4K[0]);
        ShvEptReadFixedMtrr(IA32_MTRR_FIX4K_C8000, &State->MtrrFixedRange4K[8]);
        ShvEptReadFixedMtrr(IA32_MTRR_FIX4K_D0000, &State->MtrrFixedRange4K[16]);
        ShvEptReadFixedMtrr(IA32_MTRR_FIX4K_D8000, &State->MtrrFixedRange4K[24]);
        ShvEptReadFixedMtrr(IA32_MTRR_FIX4K_E0000, &State->MtrrFixedRange4K[32]);
        ShvEptReadFixedMtrr(IA32_MTRR_FIX4K_E8000, &State->MtrrFixedRange4K[40]);
        ShvEptReadFixedMtrr(IA32_MTRR_FIX4K_F0000, &State->MtrrFixedRange4K[48]);
        ShvEptReadFixedMtrr(IA32_MTRR_FIX4K_F8000, &State->MtrrFixedRange4K[56]);
    }

    /* Read variable-range MTRRs */
    ULONG maxPhysAddrBits = ShvEptGetMaxPhysAddrBits();
    ULONG64 physAddrMask = ((1ULL << maxPhysAddrBits) - 1);

    State->MtrrRangeCount = 0;

    for (ULONG i = 0; i < vcnt && State->MtrrRangeCount < MAX_MTRR_RANGES; i++) {
        ULONG64 physBase = __readmsr(IA32_MTRR_PHYSBASE0 + (i * 2));
        ULONG64 physMask = __readmsr(IA32_MTRR_PHYSMASK0 + (i * 2));

        /* Check valid bit (bit 11 of PHYSMASK) */
        if (!(physMask & (1ULL << 11))) {
            continue;
        }

        UCHAR type = (UCHAR)(physBase & 0xFF);
        ULONG64 baseAddr = physBase & physAddrMask & ~0xFFFULL;
        ULONG64 maskVal = physMask & physAddrMask & ~0xFFFULL;

        /* Calculate range length from mask */
        ULONG64 rangeLength = (~maskVal & physAddrMask) + 1;

        State->MtrrRanges[State->MtrrRangeCount].PhysicalBaseAddress = baseAddr;
        State->MtrrRanges[State->MtrrRangeCount].PhysicalEndAddress = baseAddr + rangeLength;
        State->MtrrRanges[State->MtrrRangeCount].MemoryType = type;
        State->MtrrRangeCount++;
    }

    SHV_LOG("MTRR: default=%u, fixed=%s, variable ranges=%lu",
            State->MtrrDefaultType,
            State->MtrrFixedEnabled ? "yes" : "no",
            State->MtrrRangeCount);
}

/* ── Memory Type Lookup ──────────────────────────────────────────── */

/**
 * @brief Resolve the EPT memory type for a physical address using MTRR state.
 *
 * Implements the Intel MTRR precedence algorithm:
 *   1. For addresses below 1MB: use fixed-range MTRRs (64K, 16K, or 4K
 *      granularity) if enabled.
 *   2. For all addresses: check variable-range MTRRs. On overlapping matches,
 *      UC (uncacheable) always wins; WB+WT conflict resolves to WT; other
 *      conflicts resolve to UC for safety.
 *   3. If no MTRR matches, return the default memory type.
 *
 * @param State            EPT state containing parsed MTRR data.
 * @param PhysicalAddress  Guest physical address to look up.
 * @return EPT memory type constant (EPT_MEMORY_TYPE_WB, _UC, etc.).
 */
static UCHAR
ShvEptGetMemoryType(
    _In_ PEPT_STATE State,
    _In_ ULONG64 PhysicalAddress
    )
{
    /* Step 1: Fixed-range MTRRs for addresses below 1MB */
    if (State->MtrrFixedEnabled && PhysicalAddress < 0x100000) {
        if (PhysicalAddress < 0x80000) {
            /* 0x00000-0x7FFFF: 8 x 64KB ranges */
            ULONG index = (ULONG)(PhysicalAddress >> 16);  /* / 64KB */
            return State->MtrrFixedRange64K[index];
        }
        else if (PhysicalAddress < 0xC0000) {
            /* 0x80000-0xBFFFF: 16 x 16KB ranges */
            ULONG index = (ULONG)((PhysicalAddress - 0x80000) >> 14);  /* / 16KB */
            return State->MtrrFixedRange16K[index];
        }
        else {
            /* 0xC0000-0xFFFFF: 64 x 4KB ranges */
            ULONG index = (ULONG)((PhysicalAddress - 0xC0000) >> 12);  /* / 4KB */
            return State->MtrrFixedRange4K[index];
        }
    }

    /* Step 2: Variable-range MTRRs */
    UCHAR resultType = 0xFF;  /* No match */
    BOOLEAN hasMatch = FALSE;

    for (ULONG i = 0; i < State->MtrrRangeCount; i++) {
        PMTRR_RANGE_DESCRIPTOR range = &State->MtrrRanges[i];

        if (PhysicalAddress >= range->PhysicalBaseAddress &&
            PhysicalAddress < range->PhysicalEndAddress)
        {
            if (!hasMatch) {
                resultType = range->MemoryType;
                hasMatch = TRUE;
            } else {
                /*
                 * Multiple MTRR matches — Intel conflict resolution:
                 * UC (0) always wins. If both are WB and WT, WT wins.
                 * Otherwise, behavior is undefined; pick UC to be safe.
                 */
                if (range->MemoryType == EPT_MEMORY_TYPE_UC ||
                    resultType == EPT_MEMORY_TYPE_UC)
                {
                    resultType = EPT_MEMORY_TYPE_UC;
                }
                else if ((range->MemoryType == EPT_MEMORY_TYPE_WT &&
                          resultType == EPT_MEMORY_TYPE_WB) ||
                         (range->MemoryType == EPT_MEMORY_TYPE_WB &&
                          resultType == EPT_MEMORY_TYPE_WT))
                {
                    resultType = EPT_MEMORY_TYPE_WT;
                }
                else {
                    resultType = EPT_MEMORY_TYPE_UC;
                }
            }
        }
    }

    if (hasMatch) {
        return resultType;
    }

    /* Step 3: Default type */
    return State->MtrrDefaultType;
}

/* ── Identity Map Construction ───────────────────────────────────── */

/**
 * @brief Build the identity-mapped EPT page tables with MTRR-derived memory types.
 *
 * Constructs a 3-level page table hierarchy covering 512 GB of physical memory:
 *   - PML4[0] points to PDPT (single entry covers 512 GB).
 *   - PDPT[0..511] each point to a PD table (each entry covers 1 GB).
 *   - PDT[i][0..511] are 2MB large page entries with RWX permissions and
 *     memory types resolved from the MTRR map.
 *
 * Total: 262,144 x 2MB pages covering the full 512 GB address space.
 *
 * Physical addresses for page table entries are obtained via
 * MmGetPhysicalAddress on NT or direct VA=PA on UEFI.
 *
 * @param State  EPT state containing the page table arrays and MTRR data.
 */
static void
ShvEptSetupIdentityMap(
    _Inout_ PEPT_STATE State
    )
{
    /*
     * Get the physical address of the PDPT.
     * In UEFI: VA == PA (identity-mapped).
     * In NT: use MmGetPhysicalAddress.
     */
    ULONG64 pdptPa;
#ifdef SHV_PLATFORM_NT
    pdptPa = MmGetPhysicalAddress(State->Pdpt).QuadPart;
#else
    pdptPa = (ULONG64)(UINTN)State->Pdpt;
#endif

    /* PML4[0] → PDPT (2MB pages for 0-512GB) */
    State->Pml4[0].Value = 0;
    State->Pml4[0].Read = 1;
    State->Pml4[0].Write = 1;
    State->Pml4[0].Execute = 1;
    State->Pml4[0].Pfn = pdptPa >> 12;

    /* PML4[1-15] → PdptHigh[0-14] (1GB UC large pages, 512GB-8TB)
     * Covers GPU large BAR which can be mapped at multi-TB addresses. */
    for (ULONG pml4Idx = 1; pml4Idx <= 15; pml4Idx++) {
        ULONG highIdx = pml4Idx - 1;
        ULONG64 pdptHighPa;
#ifdef SHV_PLATFORM_NT
        pdptHighPa = MmGetPhysicalAddress(State->PdptHigh[highIdx]).QuadPart;
#else
        pdptHighPa = (ULONG64)(UINTN)State->PdptHigh[highIdx];
#endif
        State->Pml4[pml4Idx].Value = 0;
        State->Pml4[pml4Idx].Read = 1;
        State->Pml4[pml4Idx].Write = 1;
        State->Pml4[pml4Idx].Execute = 1;
        State->Pml4[pml4Idx].Pfn = pdptHighPa >> 12;

        for (ULONG i = 0; i < 512; i++) {
            ULONG64 gbBase = ((ULONG64)pml4Idx * 512 + i) * (1024ULL * 1024 * 1024);
            State->PdptHigh[highIdx][i].Value = 0;
            State->PdptHigh[highIdx][i].Read = 1;
            State->PdptHigh[highIdx][i].Write = 1;
            State->PdptHigh[highIdx][i].Execute = 1;
            State->PdptHigh[highIdx][i].LargePage = 1;
            State->PdptHigh[highIdx][i].MemoryType = EPT_MEMORY_TYPE_UC;
            State->PdptHigh[highIdx][i].Pfn = gbBase >> 30;
            /* Item #11 — suppress #VE on default identity-map entries.
             * Only stealth-mode hooks clear this bit to deliver #VE to
             * the in-guest VMFUNC handler. All other EPT-violation paths
             * (FIFO read-trap, xcap, write/read/exec-traps) keep
             * SuppressVe=1 so they vmexit normally as before. */
            State->PdptHigh[highIdx][i].SuppressVe = 1;
        }
    }

    /* PDPT[i] → PDT[i] */
    for (ULONG i = 0; i < 512; i++) {
        ULONG64 pdtPa;
#ifdef SHV_PLATFORM_NT
        pdtPa = MmGetPhysicalAddress(State->Pdt[i]).QuadPart;
#else
        pdtPa = (ULONG64)(UINTN)State->Pdt[i];
#endif

        State->Pdpt[i].Value = 0;
        State->Pdpt[i].Read = 1;
        State->Pdpt[i].Write = 1;
        State->Pdpt[i].Execute = 1;
        State->Pdpt[i].Pfn = pdtPa >> 12;
    }

    /* PDT[i][j] = 2MB large page at physical address (i*512 + j) * 2MB */
    for (ULONG i = 0; i < 512; i++) {
        for (ULONG j = 0; j < 512; j++) {
            ULONG64 pageBase = ((ULONG64)i * 512 + j) * EPT_LARGE_PAGE_SIZE;

            /*
             * Get memory type for this 2MB region from MTRR map.
             * Check for UC MTRR overlap to prevent caching MMIO.
             */
            ULONG64 pageEnd = pageBase + EPT_LARGE_PAGE_SIZE;
            UCHAR memType = ShvEptGetMemoryType(State, pageBase);
            if (memType != EPT_MEMORY_TYPE_UC) {
                for (ULONG k = 0; k < State->MtrrRangeCount; k++) {
                    PMTRR_RANGE_DESCRIPTOR range = &State->MtrrRanges[k];
                    if (range->MemoryType == EPT_MEMORY_TYPE_UC &&
                        pageBase < range->PhysicalEndAddress &&
                        pageEnd > range->PhysicalBaseAddress) {
                        memType = EPT_MEMORY_TYPE_UC;
                        break;
                    }
                }
            }

            State->Pdt[i][j].Value = 0;
            State->Pdt[i][j].Read = 1;
            State->Pdt[i][j].Write = 1;
            State->Pdt[i][j].Execute = 1;
            State->Pdt[i][j].LargePage = 1;
            State->Pdt[i][j].MemoryType = memType;
            State->Pdt[i][j].Pfn = pageBase >> 21;  /* 2MB-aligned PFN */
            /* Item #11 — suppress #VE on default identity-map entries
             * (see comment in PdptHigh init above). */
            State->Pdt[i][j].SuppressVe = 1;
        }
    }

    SHV_LOG("EPT: identity map built (512 GB, 262144 x 2MB pages)");
}

/* ── Public API ──────────────────────────────────────────────────── */

/**
 * @brief Initialize the EPT subsystem: allocate, parse MTRRs, build identity map.
 *
 * Allocates a single physically contiguous EPT_STATE block (contains PML4 +
 * PDPT + all PD tables + MTRR state), parses all hardware MTRRs, constructs
 * the identity-mapped page tables, and assembles the EPTP value.
 *
 * Must be called once before any VMCS setup. The resulting EPT is shared
 * across all VCPUs (single EPTP). Idempotent if already initialized.
 *
 * @return STATUS_SUCCESS on success, STATUS_INSUFFICIENT_RESOURCES on allocation failure.
 */
NTSTATUS
ShvEptInitialize(void)
{
    if (g_EptState != NULL) {
        /* Already initialized */
        return STATUS_SUCCESS;
    }

    /* Allocate EPT_STATE as a single contiguous block */
    g_EptState = (PEPT_STATE)ShvAllocateContiguousMemory(sizeof(EPT_STATE));
    if (g_EptState == NULL) {
        SHV_ERR("EPT: failed to allocate EPT_STATE (%llu bytes)",
                (ULONG64)sizeof(EPT_STATE));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(g_EptState, sizeof(EPT_STATE));

    /* Parse MTRRs */
    ShvEptBuildMtrrMap(g_EptState);

    /* Build identity-mapped page tables */
    ShvEptSetupIdentityMap(g_EptState);

    /* Construct EPTP */
    ULONG64 pml4Pa;
#ifdef SHV_PLATFORM_NT
    pml4Pa = MmGetPhysicalAddress(g_EptState->Pml4).QuadPart;
#else
    pml4Pa = (ULONG64)(UINTN)g_EptState->Pml4;
#endif

    g_EptState->EptPointer.Value = 0;
    g_EptState->EptPointer.MemoryType = EPT_MEMORY_TYPE_WB;  /* Page walk cache type */
    g_EptState->EptPointer.PageWalkLength = 3;                /* 4-level (3 = length-1) */
    g_EptState->EptPointer.AccessedDirty = 0;                 /* No A/D tracking */
    g_EptState->EptPointer.Pfn = pml4Pa >> 12;

    g_EptState->Initialized = TRUE;

    /* Log EPTP and PML4 PA to CMOS for diagnostics */
    ShvCmosWrite(SHV_CMOS_PROGRESS, 0xE0);  /* 0xE0 = EPT initialized */
    /* Store EPTP low 4 bytes in CMOS active bitmask slots */
    {
        ULONG64 eptp = g_EptState->EptPointer.Value;
        ShvCmosWrite(SHV_CMOS_ACTIVE0, (UCHAR)eptp);
        ShvCmosWrite(SHV_CMOS_ACTIVE1, (UCHAR)(eptp >> 8));
        ShvCmosWrite(SHV_CMOS_ACTIVE2, (UCHAR)(eptp >> 16));
        ShvCmosWrite(SHV_CMOS_ACTIVE3, (UCHAR)(eptp >> 24));
    }

    SHV_LOG("EPT: initialized, EPTP=0x%llX, PML4 PA=0x%llX, sizeof(EPT_STATE)=%llu",
            g_EptState->EptPointer.Value, pml4Pa, (ULONG64)sizeof(EPT_STATE));

    return STATUS_SUCCESS;
}

/* ── Secondary EPT (built from scratch, not copied) ─────────────── */

static PEPT_STATE g_SecondaryEptState = NULL;

/**
 * @brief Initialize a secondary EPT with its own independent identity mapping.
 *
 * Built from scratch using the same MTRR + identity map functions as the
 * primary. This guarantees complete independence — no shared page table
 * pages, no pointer fixup needed, no risk of cross-EPT corruption.
 *
 * Called from guest kernel context (DriverEntry or deferred thread) because
 * it allocates contiguous memory via MmAllocateContiguousMemory.
 */
NTSTATUS
ShvEptInitializeSecondary(void)
{
    if (g_SecondaryEptState != NULL)
        return STATUS_SUCCESS;

    if (g_EptState == NULL || !g_EptState->Initialized) {
        SHV_ERR("EPT secondary: primary not initialized");
        return STATUS_UNSUCCESSFUL;
    }

    /* Allocate a completely separate EPT_STATE */
    g_SecondaryEptState = (PEPT_STATE)ShvAllocateContiguousMemory(sizeof(EPT_STATE));
    if (g_SecondaryEptState == NULL) {
        SHV_ERR("EPT secondary: alloc failed (%llu bytes)", (ULONG64)sizeof(EPT_STATE));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(g_SecondaryEptState, sizeof(EPT_STATE));

    /* Build independently — same MTRR + identity map, own page tables */
    ShvEptBuildMtrrMap(g_SecondaryEptState);
    ShvEptSetupIdentityMap(g_SecondaryEptState);

    /* Construct EPTP pointing to OUR OWN PML4 */
    ULONG64 pml4Pa = MmGetPhysicalAddress(g_SecondaryEptState->Pml4).QuadPart;

    g_SecondaryEptState->EptPointer.Value = 0;
    g_SecondaryEptState->EptPointer.MemoryType = EPT_MEMORY_TYPE_WB;
    g_SecondaryEptState->EptPointer.PageWalkLength = 3;
    g_SecondaryEptState->EptPointer.AccessedDirty = 0;
    g_SecondaryEptState->EptPointer.Pfn = pml4Pa >> 12;

    g_SecondaryEptState->Initialized = TRUE;

    SHV_LOG("EPT secondary: initialized, EPTP=0x%llX, PML4 PA=0x%llX",
            g_SecondaryEptState->EptPointer.Value, pml4Pa);

    return STATUS_SUCCESS;
}

ULONG64
ShvEptGetSecondaryEptp(void)
{
    if (g_SecondaryEptState == NULL || !g_SecondaryEptState->Initialized)
        return 0;
    return g_SecondaryEptState->EptPointer.Value;
}

/**
 * Static page tables for split 2MB→4KB regions.
 * g_TpmSplitPt[0] = FIFO (0xFED10000), g_TpmSplitPt[1] = CRB (0xFED40000).
 * Each covers a distinct 2MB EPT page that has been split into 512 x 4KB entries.
 */
#define TPM_SPLIT_MAX  2
static EPT_PTE* g_TpmSplitPt[TPM_SPLIT_MAX] = { NULL, NULL };
static ULONG    g_TpmSplitPdptIdx[TPM_SPLIT_MAX] = { 0 };
static ULONG    g_TpmSplitPdtIdx[TPM_SPLIT_MAX] = { 0 };
static ULONG    g_TpmSplitCount = 0;

/* Legacy alias: FIFO trap functions use index 0 */
#define g_TpmSplitPtFifo  g_TpmSplitPt[0]

/**
 * @brief Free all EPT state and page table memory.
 *
 * Called during devirtualization after all CPUs have exited VMX operation.
 * Safe to call if EPT was never initialized (NULL check).
 */
void
ShvEptDestroy(void)
{
    if (g_EptState != NULL) {
        for (ULONG i = 0; i < TPM_SPLIT_MAX; i++) {
            if (g_TpmSplitPt[i] != NULL) {
                ShvFreeContiguousMemory(g_TpmSplitPt[i], sizeof(EPT_PTE) * 512);
                g_TpmSplitPt[i] = NULL;
            }
        }
        g_TpmSplitCount = 0;
        ShvFreeContiguousMemory(g_EptState, sizeof(EPT_STATE));
        g_EptState = NULL;
        SHV_LOG("EPT: destroyed");
    }
}

/* ── TPM Page Split + Remap ─────────────────────────────────────── */

/**
 * @brief Split a 2MB EPT page into 512 x 4KB pages and remap one page.
 *
 * Splits the 2MB page containing targetPa into 4KB identity-mapped pages,
 * then remaps the specific 4KB page at targetPa to point to shadowPa.
 *
 * @param targetPa   Physical address to remap (must be 4KB-aligned).
 * @param shadowPa   Physical address of the shadow buffer (4KB page).
 * @return STATUS_SUCCESS or error.
 */
NTSTATUS
ShvEptRemapPage(
    _In_ ULONG64 targetPa,
    _In_ ULONG64 shadowPa
    )
{
    if (g_EptState == NULL || !g_EptState->Initialized) {
        return STATUS_UNSUCCESSFUL;
    }

    /* Only support addresses in PML4[0] (0-512GB) */
    ULONG pml4Idx = EPT_PML4_INDEX(targetPa);
    if (pml4Idx != 0) {
        SHV_ERR("EPT remap: targetPa 0x%llX not in PML4[0]", targetPa);
        return STATUS_INVALID_PARAMETER;
    }

    ULONG pdptIdx = EPT_PDPT_INDEX(targetPa);  /* Which 1GB region */
    ULONG pdtIdx = EPT_PDE_INDEX(targetPa);     /* Which 2MB page */
    ULONG ptIdx = EPT_PTE_INDEX(targetPa);      /* Which 4KB page within the 2MB */

    SHV_LOG("EPT remap: target=0x%llX shadow=0x%llX (PDPT[%lu] PDT[%lu] PT[%lu])",
            targetPa, shadowPa, pdptIdx, pdtIdx, ptIdx);

    /* Find or allocate a split PT for this 2MB region.
     * If the same 2MB page was already split (e.g., FIFO and CRB in the same
     * region), reuse the existing PT. Otherwise allocate a new one. */
    EPT_PTE* splitPt = NULL;
    ULONG splitIdx = (ULONG)-1;

    for (ULONG s = 0; s < g_TpmSplitCount; s++) {
        if (g_TpmSplitPdptIdx[s] == pdptIdx && g_TpmSplitPdtIdx[s] == pdtIdx) {
            splitPt = g_TpmSplitPt[s];
            splitIdx = s;
            SHV_LOG("EPT remap: reusing existing split PT[%lu] for PDPT[%lu] PDT[%lu]",
                    s, pdptIdx, pdtIdx);
            break;
        }
    }

    if (splitPt == NULL) {
        /* Need a new split PT for this 2MB region */
        if (g_TpmSplitCount >= TPM_SPLIT_MAX) {
            SHV_ERR("EPT remap: no split PT slots available (%lu/%lu used)",
                    g_TpmSplitCount, (ULONG)TPM_SPLIT_MAX);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        splitPt = (EPT_PTE*)ShvAllocateContiguousMemory(sizeof(EPT_PTE) * 512);
        if (splitPt == NULL) {
            SHV_ERR("EPT remap: failed to allocate split PT");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        splitIdx = g_TpmSplitCount;
        g_TpmSplitPt[splitIdx] = splitPt;
        g_TpmSplitPdptIdx[splitIdx] = pdptIdx;
        g_TpmSplitPdtIdx[splitIdx] = pdtIdx;
        g_TpmSplitCount++;

        /* Fill the new PT with 512 identity-mapped 4KB entries */
        UCHAR memType = g_EptState->Pdt[pdptIdx][pdtIdx].MemoryType;
        ULONG64 pageBase2MB = ((ULONG64)pdptIdx * 512 + pdtIdx) * EPT_LARGE_PAGE_SIZE;

        for (ULONG i = 0; i < 512; i++) {
            ULONG64 pa4k = pageBase2MB + (ULONG64)i * 4096;
            splitPt[i].Value = 0;
            splitPt[i].Read = 1;
            splitPt[i].Write = 1;
            splitPt[i].Execute = 1;
            splitPt[i].MemoryType = memType;
            splitPt[i].Pfn = pa4k >> 12;
            /* Item #11 — inherit SuppressVe=1 from the parent 2MB PDE.
             * Existing trap mechanisms (FIFO read-trap, xcap, write/read/
             * exec-trap) keep vmexit-driven behavior. Stealth-mode hooks
             * explicitly clear SuppressVe AFTER split to deliver #VE. */
            splitPt[i].SuppressVe = 1;
        }

        /* Replace the 2MB large page entry with a PDE pointer to our PT */
        ULONG64 ptPa;
#ifdef SHV_PLATFORM_NT
        ptPa = MmGetPhysicalAddress(splitPt).QuadPart;
#else
        ptPa = (ULONG64)(UINTN)splitPt;
#endif

        EPT_PDE_PTR pdePtr;
        pdePtr.Value = 0;
        pdePtr.Read = 1;
        pdePtr.Write = 1;
        pdePtr.Execute = 1;
        pdePtr.Pfn = ptPa >> 12;

        /* Atomic swap: overwrite the 2MB large page entry with the PT pointer.
         * Both are ULONG64, so a single aligned write is atomic on x64. */
        *(ULONG64*)&g_EptState->Pdt[pdptIdx][pdtIdx] = pdePtr.Value;

        SHV_LOG("EPT remap: PDT[%lu][%lu] split to 4KB (PT PA=0x%llX, slot %lu)",
                pdptIdx, pdtIdx, ptPa, splitIdx);
    }

    /* Remap the target 4KB page to the shadow buffer */
    splitPt[ptIdx].Pfn = shadowPa >> 12;
    splitPt[ptIdx].MemoryType = EPT_MEMORY_TYPE_UC;  /* Shadow is UC */

    SHV_LOG("EPT remap: slot[%lu] PT[%lu] PFN changed from 0x%llX to 0x%llX",
            splitIdx, ptIdx, targetPa >> 12, shadowPa >> 12);

    /* INVEPT: flush stale EPT TLB entries on this CPU.
     * INVEPT can only run in VMX root mode, so we issue a VMCALL
     * to request it from the host. This ensures the page split is
     * visible immediately, not just after the next natural TLB flush. */
    if (g_Shv.Active) {
        NTSTATUS inveptSt = ShvDoVmcall(VMCALL_INVEPT, 0);
        if (NT_SUCCESS(inveptSt)) {
            SHV_LOG("EPT remap: INVEPT issued on current CPU");
        } else {
            SHV_WARN("EPT remap: INVEPT failed 0x%08X", inveptSt);
        }
    }

    return STATUS_SUCCESS;
}

/* g_TpmSplitPt[] cleanup is in ShvEptDestroy above */

/* ── Dual-EPT Hook Resources (pre-allocated in guest context) ────── */

#define HOOK_SPLIT_MAX 32  /* Max distinct 2MB pages that can be split for hooks
                             * (shared pool — dual-EPT hooks + UM write-traps).
                             * Bumped from 8 -> 32 after the write-trap
                             * testing session exhausted the pool mid-session with
                             * 5+ distinct 2MB regions trapped in PID 21908 + new CoW'd
                             * pages in PID 22884. Memory cost: 32 * 4KB PTs * 2 pools
                             * (primary + secondary) = 256 KB additional at boot.
                             * See memory/um_ept_writetrap_hook_split_pool_exhaustion.md */

static struct {
    /* Primary EPT split page tables */
    EPT_PTE* PriPt[HOOK_SPLIT_MAX];
    ULONG64  PriPtPa[HOOK_SPLIT_MAX];  /* Pre-computed PA of each split PT */
    ULONG64  PriBase[HOOK_SPLIT_MAX];  /* 2MB-aligned PA that was split */
    ULONG    PriCount;

    /* Secondary EPT split page tables */
    EPT_PTE* SecPt[HOOK_SPLIT_MAX];
    ULONG64  SecPtPa[HOOK_SPLIT_MAX];  /* Pre-computed PA of each split PT */
    ULONG64  SecBase[HOOK_SPLIT_MAX];
    ULONG    SecCount;

    /* Shadow pages (one per hook) */
    PVOID    ShadowVa[EPT_HOOK_MAX];
    ULONG64  ShadowPa[EPT_HOOK_MAX];
    ULONG    ShadowCount;

    BOOLEAN  Ready;
} g_HookRes;

/**
 * @brief Pre-allocate all resources needed for dual-EPT hook installation.
 *
 * Must be called from guest kernel context (PASSIVE_LEVEL) because it uses
 * MmAllocateContiguousMemory. After this, ShvEptInstallHook can run from
 * VMX root without any kernel allocations.
 *
 * Pre-allocates:
 *   - HOOK_SPLIT_MAX split page tables for primary EPT (4KB each)
 *   - HOOK_SPLIT_MAX split page tables for secondary EPT (4KB each)
 *   - EPT_HOOK_MAX shadow pages for INT3 copies (4KB each)
 *
 * @return STATUS_SUCCESS or STATUS_INSUFFICIENT_RESOURCES.
 */
NTSTATUS
ShvEptPrepareHookResources(void)
{
    if (g_HookRes.Ready)
        return STATUS_SUCCESS;

    RtlZeroMemory(&g_HookRes, sizeof(g_HookRes));

    /* Allocate split page tables for primary EPT */
    for (ULONG i = 0; i < HOOK_SPLIT_MAX; i++) {
        g_HookRes.PriPt[i] = (EPT_PTE*)ShvAllocateContiguousMemory(sizeof(EPT_PTE) * 512);
        if (!g_HookRes.PriPt[i]) {
            SHV_ERR("Hook resources: failed to alloc primary split PT %lu", i);
            goto fail;
        }
        g_HookRes.PriPtPa[i] = MmGetPhysicalAddress(g_HookRes.PriPt[i]).QuadPart;
    }

    /* Secondary split PTs + shadow pages are for dual-EPT hooks only.
     * ExecTrap needs only primary PTs (above). Mark Ready now so ExecTrap
     * works even on systems where contiguous alloc for these extras fails. */
    g_HookRes.Ready = TRUE;

    /* Allocate split page tables for secondary EPT (optional — dual-EPT hooks) */
    for (ULONG i = 0; i < HOOK_SPLIT_MAX; i++) {
        g_HookRes.SecPt[i] = (EPT_PTE*)ShvAllocateContiguousMemory(sizeof(EPT_PTE) * 512);
        if (!g_HookRes.SecPt[i]) {
            SHV_WARN("Hook resources: secondary PT %lu alloc failed — dual-EPT hooks unavailable", i);
            break;
        }
        g_HookRes.SecPtPa[i] = MmGetPhysicalAddress(g_HookRes.SecPt[i]).QuadPart;
    }

    /* Allocate shadow pages for INT3 copies (optional — dual-EPT hooks) */
    for (ULONG i = 0; i < EPT_HOOK_MAX; i++) {
        g_HookRes.ShadowVa[i] = ShvAllocateContiguousMemory(PAGE_SIZE);
        if (!g_HookRes.ShadowVa[i]) {
            SHV_WARN("Hook resources: shadow page %lu alloc failed — INT3 hooks unavailable", i);
            break;
        }
        g_HookRes.ShadowPa[i] = MmGetPhysicalAddress(g_HookRes.ShadowVa[i]).QuadPart;
    }
    SHV_LOG("Hook resources: allocated %u pri + %u sec split PTs, %u shadow pages",
            HOOK_SPLIT_MAX, HOOK_SPLIT_MAX, EPT_HOOK_MAX);
    return STATUS_SUCCESS;

fail:
    /* Free anything allocated so far */
    for (ULONG i = 0; i < HOOK_SPLIT_MAX; i++) {
        if (g_HookRes.PriPt[i]) {
            ShvFreeContiguousMemory(g_HookRes.PriPt[i], sizeof(EPT_PTE) * 512);
            g_HookRes.PriPt[i] = NULL;
        }
        if (g_HookRes.SecPt[i]) {
            ShvFreeContiguousMemory(g_HookRes.SecPt[i], sizeof(EPT_PTE) * 512);
            g_HookRes.SecPt[i] = NULL;
        }
    }
    for (ULONG i = 0; i < EPT_HOOK_MAX; i++) {
        if (g_HookRes.ShadowVa[i]) {
            ShvFreeContiguousMemory(g_HookRes.ShadowVa[i], PAGE_SIZE);
            g_HookRes.ShadowVa[i] = NULL;
        }
    }
    return STATUS_INSUFFICIENT_RESOURCES;
}

/**
 * @brief Find or create a 2MB→4KB split in the primary EPT for a given PA.
 *
 * If the 2MB page containing pa2mbBase is already split, returns the existing
 * split PT. Otherwise, takes the next pre-allocated split PT, fills it with
 * identity-mapped 4KB entries, and replaces the 2MB PDE in the primary EPT.
 *
 * Runs from VMX root — no allocations, only uses pre-allocated resources.
 *
 * @param pa2mbBase  2MB-aligned physical address to split.
 * @return Pointer to the 512-entry PT, or NULL if out of resources.
 */
static EPT_PTE*
ShvEptPrimarySplitFor(
    _In_ ULONG64 pa2mbBase
    )
{
    /* Check if already split */
    for (ULONG i = 0; i < g_HookRes.PriCount; i++) {
        if (g_HookRes.PriBase[i] == pa2mbBase)
            return g_HookRes.PriPt[i];
    }

    if (g_HookRes.PriCount >= HOOK_SPLIT_MAX || g_EptState == NULL)
        return NULL;

    ULONG slot = g_HookRes.PriCount;
    EPT_PTE* pt = g_HookRes.PriPt[slot];

    ULONG pdptIdx = EPT_PDPT_INDEX(pa2mbBase);
    ULONG pdtIdx  = EPT_PDE_INDEX(pa2mbBase);

    /* Get current 2MB page memory type */
    UCHAR memType = g_EptState->Pdt[pdptIdx][pdtIdx].MemoryType;

    /* Fill with identity-mapped 4KB entries (same permissions as original).
     * Item #11 — SuppressVe=1 by default; the dual-EPT hook installer
     * clears it on the per-page PTE for stealth-mode hooks AFTER split. */
    for (ULONG i = 0; i < 512; i++) {
        ULONG64 pa4k = pa2mbBase + (ULONG64)i * PAGE_SIZE;
        pt[i].Value = 0;
        pt[i].Read    = 1;
        pt[i].Write   = 1;
        pt[i].Execute = 1;
        pt[i].MemoryType = memType;
        pt[i].Pfn = pa4k >> 12;
        pt[i].SuppressVe = 1;
    }

    /* Replace the 2MB PDE with a pointer to our split PT.
     * Use the pre-computed PA — no MmGetPhysicalAddress from VMX root. */
    EPT_PDE_PTR pdePtr;
    pdePtr.Value = 0;
    pdePtr.Read    = 1;
    pdePtr.Write   = 1;
    pdePtr.Execute = 1;
    pdePtr.Pfn = g_HookRes.PriPtPa[slot] >> 12;

    *(volatile ULONG64*)&g_EptState->Pdt[pdptIdx][pdtIdx] = pdePtr.Value;

    g_HookRes.PriBase[slot] = pa2mbBase;
    g_HookRes.PriCount++;

    return pt;
}

/**
 * @brief Find or create a 2MB→4KB split in the secondary EPT for a given PA.
 *
 * Same as ShvEptPrimarySplitFor but operates on g_SecondaryEptState.
 *
 * @param pa2mbBase  2MB-aligned physical address to split.
 * @return Pointer to the 512-entry PT, or NULL if out of resources.
 */
static EPT_PTE*
ShvEptSecondarySplitFor(
    _In_ ULONG64 pa2mbBase
    )
{
    /* Check if already split */
    for (ULONG i = 0; i < g_HookRes.SecCount; i++) {
        if (g_HookRes.SecBase[i] == pa2mbBase)
            return g_HookRes.SecPt[i];
    }

    if (g_HookRes.SecCount >= HOOK_SPLIT_MAX || g_SecondaryEptState == NULL)
        return NULL;

    ULONG slot = g_HookRes.SecCount;
    EPT_PTE* pt = g_HookRes.SecPt[slot];

    ULONG pdptIdx = EPT_PDPT_INDEX(pa2mbBase);
    ULONG pdtIdx  = EPT_PDE_INDEX(pa2mbBase);

    /* Get current 2MB page memory type */
    UCHAR memType = g_SecondaryEptState->Pdt[pdptIdx][pdtIdx].MemoryType;

    /* Fill with identity-mapped 4KB entries (same permissions as original).
     * Item #11 — SuppressVe=1 default (see ShvEptPrimarySplitFor comment). */
    for (ULONG i = 0; i < 512; i++) {
        ULONG64 pa4k = pa2mbBase + (ULONG64)i * PAGE_SIZE;
        pt[i].Value = 0;
        pt[i].Read    = 1;
        pt[i].Write   = 1;
        pt[i].Execute = 1;
        pt[i].MemoryType = memType;
        pt[i].Pfn = pa4k >> 12;
        pt[i].SuppressVe = 1;
    }

    /* Replace the 2MB PDE in secondary EPT.
     * Use the pre-computed PA — no MmGetPhysicalAddress from VMX root. */
    EPT_PDE_PTR pdePtr;
    pdePtr.Value = 0;
    pdePtr.Read    = 1;
    pdePtr.Write   = 1;
    pdePtr.Execute = 1;
    pdePtr.Pfn = g_HookRes.SecPtPa[slot] >> 12;

    *(volatile ULONG64*)&g_SecondaryEptState->Pdt[pdptIdx][pdtIdx] = pdePtr.Value;

    g_HookRes.SecBase[slot] = pa2mbBase;
    g_HookRes.SecCount++;

    return pt;
}

/**
 * @brief Install a dual-EPT INT3 hook on a target function.
 *
 * Called from VMX root (exit_dispatch.c polling). Uses ONLY pre-allocated
 * resources — no kernel allocations.
 *
 * Steps:
 *   1. Split the 2MB page in both primary and secondary EPTs.
 *   2. Allocate a shadow page, copy the original page content.
 *   3. Write INT3 (0xCC) at the hook offset in the shadow page.
 *   4. Primary EPT: hooked 4KB page = RW, no Execute.
 *   5. Secondary EPT: hooked 4KB page = Execute only, PFN = shadow.
 *   6. Register in g_Shv.EptHooks[].
 *   7. Enable #BP interception (exception bitmap bit 3) on current VMCS.
 *
 * @param TargetVa  Guest virtual address of the function to hook.
 * @param TargetPa  Guest physical address (page-aligned from caller).
 * @return STATUS_SUCCESS or error status.
 */
NTSTATUS
ShvEptInstallHook(
    _In_ ULONG64 TargetVa,
    _In_ ULONG64 TargetPa
    )
{
    if (!g_HookRes.Ready) {
        SHV_ERR("EPT hook: resources not prepared");
        return STATUS_UNSUCCESSFUL;
    }
    if (g_EptState == NULL || g_SecondaryEptState == NULL) {
        SHV_ERR("EPT hook: EPT state not initialized");
        return STATUS_UNSUCCESSFUL;
    }
    if (g_Shv.EptHookCount >= EPT_HOOK_MAX) {
        SHV_ERR("EPT hook: max hooks (%u) reached", EPT_HOOK_MAX);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Only support PML4[0] addresses (0-512GB) */
    if (EPT_PML4_INDEX(TargetPa) != 0) {
        SHV_ERR("EPT hook: targetPa 0x%llX not in PML4[0]", TargetPa);
        return STATUS_INVALID_PARAMETER;
    }

    ULONG64 pa2mbBase = TargetPa & ~(EPT_LARGE_PAGE_SIZE - 1ULL);
    ULONG   ptIdx     = EPT_PTE_INDEX(TargetPa);
    ULONG32 pageOffset = (ULONG32)(TargetVa & 0xFFF);

    /* Step 1: Split 2MB page in both EPTs */
    EPT_PTE* priPt = ShvEptPrimarySplitFor(pa2mbBase);
    if (!priPt) {
        SHV_ERR("EPT hook: primary split failed for 0x%llX", pa2mbBase);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    EPT_PTE* secPt = ShvEptSecondarySplitFor(pa2mbBase);
    if (!secPt) {
        SHV_ERR("EPT hook: secondary split failed for 0x%llX", pa2mbBase);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Step 2: Get shadow page from pre-allocated pool */
    ULONG hookIdx = g_Shv.EptHookCount;
    PVOID   shadowVa = g_HookRes.ShadowVa[hookIdx];
    ULONG64 shadowPa = g_HookRes.ShadowPa[hookIdx];

    /* Copy the ORIGINAL page content to the shadow page.
     * Two modes:
     *   PendingHookCopyFromVa != 0: Copy from pristine buffer (NonPagedPool,
     *     safe, no anti-dump detection, correct pre-DriverEntry bytes).
     *   PendingHookCopyFromVa == 0: Copy from physical address via MmCopyMemory
     *     (bypasses guest page tables but may trigger anti-dump). */
    ULONG64 pageAlignedPa = TargetPa & ~0xFFFULL;
    ULONG64 copyFromVa = g_Shv.PendingHookCopyFromVa;
    if (copyFromVa != 0) {
        /* Validate copyFromVa is a canonical kernel address before using it.
         * A bogus VA (e.g., from bad offset math when dispatch is outside the
         * pristine buffer's module) causes a page fault in VMX root → fatal
         * BSOD 0x1AA EXCEPTION_ON_INVALID_STACK. */
        BOOLEAN vaValid = ((copyFromVa >> 47) == 0x1FFFF);
        if (vaValid) {
            PHYSICAL_ADDRESS checkPa = MmGetPhysicalAddress((PVOID)copyFromVa);
            vaValid = (checkPa.QuadPart != 0);
        }
        if (vaValid) {
            RtlCopyMemory(shadowVa, (PVOID)copyFromVa, PAGE_SIZE);
            SHV_LOG("EPT hook: shadow copied from pristine VA 0x%llX", copyFromVa);
        } else {
            SHV_ERR("EPT hook: copyFromVa 0x%llX invalid, falling back to MmCopyMemory",
                    copyFromVa);
            copyFromVa = 0;  /* Fall through to MmCopyMemory path */
        }
    }
    if (copyFromVa == 0) {
        /* Fallback: copy from physical address */
        MM_COPY_ADDRESS srcAddr;
        srcAddr.PhysicalAddress.QuadPart = (LONGLONG)pageAlignedPa;
        SIZE_T bytesCopied = 0;
        NTSTATUS cpSt = MmCopyMemory(shadowVa, srcAddr, PAGE_SIZE,
                                      MM_COPY_MEMORY_PHYSICAL, &bytesCopied);
        if (!NT_SUCCESS(cpSt) || bytesCopied != PAGE_SIZE) {
            SHV_ERR("EPT hook: MmCopyMemory failed 0x%08X (copied %llu)",
                    cpSt, (ULONG64)bytesCopied);
            return STATUS_UNSUCCESSFUL;
        }
    }

    /* Step 3: Save original 2 bytes, then write CPUID (0x0F 0xA2) at hook offset.
     * CPUID causes an UNCONDITIONAL VM exit — no exception bitmap needed.
     * This bypasses the INT3 exception bitmap race that caused BSODs. */
    UCHAR origByte0 = ((PUCHAR)shadowVa)[pageOffset];
    UCHAR origByte1 = ((PUCHAR)shadowVa)[pageOffset + 1];
    ((PUCHAR)shadowVa)[pageOffset]     = 0x0F;
    ((PUCHAR)shadowVa)[pageOffset + 1] = 0xA2;

    /* Step 4: Primary EPT — hooked page is RW, NO execute.
     * Any attempt to execute on this page → EPT violation → switch to secondary. */
    priPt[ptIdx].Execute = 0;
    /* Read+Write stay enabled so data accesses work normally */

    /* Step 5: Secondary EPT — hooked page is Read+Execute, points to shadow.
     * Execute goes to shadow page (with CPUID at hook point).
     * Read also goes to shadow (copy of original, safe for code pages).
     * Write → EPT violation → switch back to primary (rare on code pages).
     *
     * Using RX instead of X-only eliminates the per-instruction EPT bouncing
     * that happens when code on the hooked page does data reads from the same
     * page (e.g., RIP-relative loads). With X-only, each such instruction
     * caused 2 VM exits (execute→sec, read→pri) per instruction, freezing
     * the system for hot functions like NtDeviceIoControlFile. */
    secPt[ptIdx].Pfn     = shadowPa >> 12;
    secPt[ptIdx].Read    = 1;
    secPt[ptIdx].Write   = 0;
    secPt[ptIdx].Execute = 1;

    /* Step 6: Register the hook */
    g_Shv.EptHooks[hookIdx].TargetVa   = TargetVa;
    g_Shv.EptHooks[hookIdx].TargetPa   = pageAlignedPa;
    g_Shv.EptHooks[hookIdx].ShadowPa   = shadowPa;
    g_Shv.EptHooks[hookIdx].ShadowVa   = shadowVa;
    g_Shv.EptHooks[hookIdx].PageOffset   = pageOffset;
    g_Shv.EptHooks[hookIdx].OrigBytes[0] = origByte0;
    g_Shv.EptHooks[hookIdx].OrigBytes[1] = origByte1;
    g_Shv.EptHooks[hookIdx].Active       = TRUE;
    g_Shv.EptHookCount++;

    /* Step 7: Enable #BP interception in the exception bitmap (bit 3).
     * This makes INT3 cause a VM-exit instead of being delivered to guest IDT. */
    {
        SIZE_T excBitmap = 0;
        __vmx_vmread(VMCS_CTRL_EXCEPTION_BITMAP, &excBitmap);
        excBitmap |= (1UL << 3);  /* Bit 3 = #BP */
        __vmx_vmwrite(VMCS_CTRL_EXCEPTION_BITMAP, excBitmap);
    }

    SHV_LOG("EPT hook #%lu installed: VA=0x%llX PA=0x%llX shadow=0x%llX offset=0x%X",
            hookIdx, TargetVa, pageAlignedPa, shadowPa, pageOffset);

    return STATUS_SUCCESS;
}

/**
 * @brief Restore execute permission on a hooked page in the primary EPT.
 *
 * Called from VMX root when auto-stop deactivates a hook. Re-adds the
 * Execute bit to the primary EPT PTE for the page containing targetPa.
 * This eliminates ALL EPT violation overhead for that page.
 *
 * @param targetPa  Page-aligned physical address of the hooked page.
 * @return STATUS_SUCCESS or STATUS_NOT_FOUND if the split PT wasn't found.
 */
NTSTATUS
ShvEptRestorePageExecute(
    _In_ ULONG64 targetPa
    )
{
    ULONG64 pa2mbBase = targetPa & ~(EPT_LARGE_PAGE_SIZE - 1ULL);
    ULONG   ptIdx     = EPT_PTE_INDEX(targetPa);

    /* Find the primary split PT for this 2MB page */
    for (ULONG i = 0; i < g_HookRes.PriCount; i++) {
        if (g_HookRes.PriBase[i] == pa2mbBase) {
            /* Restore RWX on this 4KB PTE */
            g_HookRes.PriPt[i][ptIdx].Execute = 1;
            return STATUS_SUCCESS;
        }
    }

    return STATUS_NOT_FOUND;
}

/* ── FIFO EPT Read-Trap ─────────────────────────────────────────── */

/** FIFO page PTE index within the split page table */
#define TPM_FIFO_PT_INDEX   EPT_PTE_INDEX(0xFED10000ULL)  /* (0xFED10 >> 0) & 0x1FF = 0x110 */

/**
 * @brief Enable or disable the EPT read-trap on the TPM FIFO page.
 *
 * Removes (enable=TRUE) or restores (enable=FALSE) the Read bit on the
 * FIFO 4KB PTE in the split page table. Issues INVEPT to flush stale
 * TLB entries so the change takes effect immediately.
 *
 * @param Enable  TRUE to arm the trap, FALSE to disarm.
 * @return STATUS_SUCCESS or STATUS_UNSUCCESSFUL if prerequisites not met.
 */
NTSTATUS
ShvEptTrapFifoPage(
    _In_ BOOLEAN Enable
    )
{
    if (g_EptState == NULL || !g_EptState->Initialized || g_TpmSplitPtFifo == NULL) {
        SHV_ERR("EPT FIFO trap: prerequisites not met (EptState=%p, SplitPt=%p)",
                g_EptState, g_TpmSplitPtFifo);
        return STATUS_UNSUCCESSFUL;
    }

    ULONG ptIdx = TPM_FIFO_PT_INDEX;
    volatile EPT_PTE* pte = &g_TpmSplitPtFifo[ptIdx];

    if (Enable) {
        /* Remove Read bit to trap read accesses */
        pte->Read = 0;
        SHV_LOG("EPT FIFO trap: ARMED (PT[%lu].Read=0, PFN=0x%llX)",
                ptIdx, (ULONG64)pte->Pfn);
    } else {
        /* Restore Read bit to allow silent reads */
        pte->Read = 1;
        SHV_LOG("EPT FIFO trap: DISARMED (PT[%lu].Read=1)", ptIdx);
    }

    /* INVEPT to flush stale TLB entries for this EPT context */
    ULONG64 eptp = g_EptState->EptPointer.Value;
    if (eptp != 0) {
        INVEPT_DESCRIPTOR desc;
        desc.EptPointer = eptp;
        desc.Reserved = 0;
        ShvInvept(INVEPT_SINGLE_CONTEXT, &desc);
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Temporarily restore Read on the FIFO PTE (for MTF single-step).
 *
 * Called from the EPT violation handler in VMX root. The EPT violation
 * already flushed the TLB entry for this GPA, so no INVEPT is needed.
 */
void
ShvEptFifoRestoreRead(void)
{
    if (g_TpmSplitPtFifo != NULL) {
        g_TpmSplitPtFifo[TPM_FIFO_PT_INDEX].Read = 1;
    }
}

/**
 * @brief Re-remove Read on the FIFO PTE (re-arm the trap after MTF).
 *
 * Called from the MTF exit handler. Issues INVEPT to ensure the trap
 * is effective before the next guest instruction executes.
 */
void
ShvEptFifoRemoveRead(void)
{
    if (g_TpmSplitPtFifo == NULL || g_EptState == NULL) {
        return;
    }

    g_TpmSplitPtFifo[TPM_FIFO_PT_INDEX].Read = 0;

    /* INVEPT to flush the just-used TLB entry */
    ULONG64 eptp = g_EptState->EptPointer.Value;
    if (eptp != 0) {
        INVEPT_DESCRIPTOR desc;
        desc.EptPointer = eptp;
        desc.Reserved = 0;
        ShvInvept(INVEPT_SINGLE_CONTEXT, &desc);
    }
}

/**
 * @brief Get the 64-bit EPTP value for writing to VMCS_CTRL_EPTP.
 *
 * Returns the pre-constructed EPT Pointer encoding the PML4 physical
 * address, WB page walk memory type, and 4-level walk length.
 * Returns 0 if EPT has not been initialized.
 *
 * @return EPTP value, or 0 if not initialized.
 */
ULONG64
ShvEptGetEptp(void)
{
    if (g_EptState == NULL || !g_EptState->Initialized) {
        return 0;
    }
    return g_EptState->EptPointer.Value;
}

/**
 * @brief Check whether the EPT subsystem has been successfully initialized.
 *
 * @return TRUE if EPT state is allocated and the identity map is built, FALSE otherwise.
 */
BOOLEAN
ShvEptIsEnabled(void)
{
    return (g_EptState != NULL && g_EptState->Initialized);
}

/* ---- Xcap (Execute-Trap Page Capture) EPT Support ---- */

static EPT_PTE* g_XcapSplitPts[XCAP_SPLIT_MAX];
static ULONG64  g_XcapSplitPas[XCAP_SPLIT_MAX];
static ULONG64  g_XcapSplitBase2mb[XCAP_SPLIT_MAX];
/* The split count moved into g_Shv.XcapSplitCount. The previous
 * `static volatile LONG g_XcapSplitCount = 0;` was being mysteriously
 * reset to 0 between install (where SplitFor++ events provably reached
 * 1222 increments) and probe time. Putting it in g_Shv (entry.c BSS,
 * same struct as XcapSplitForIncrements which IS preserved) eliminates
 * per-section BSS zeroing as a hypothesis and gives us a single source
 * of truth.
 *
 * `g_XcapSplitCount` is now a #define alias so the existing logic stays
 * readable; all reads/writes go through g_Shv.XcapSplitCount. */
#define g_XcapSplitCount  (g_Shv.XcapSplitCount)

/* NOTE: XcapReadPhysQword + XcapWalkPageTables removed in favour of doing the
 * walk in NexusCore's image-load notify. The original implementation called
 * MmCopyMemory(MM_COPY_MEMORY_PHYSICAL) from VMX root, which is documented as
 * IRQL <= APC_LEVEL only and silently failed at HIGH_IRQL — every walk
 * returned 0, every page was counted as no-PA, zero traps were ever armed.
 *
 * The new architecture has the caller (NexusCore image notify, PASSIVE_LEVEL,
 * target CR3 context) populate g_Shv.XcapPaTable[] directly via
 * MmGetPhysicalAddress, then issue VMCALL_XCAP_SETUP. ShvEptXcapWalkAndTrap
 * is now an install step that just iterates the pre-populated table.
 *
 * The pointer to the table is exposed via VMCALL_XCAP_GET_PATABLE so
 * NexusCore knows where to write. */
NTSTATUS
ShvEptPrepareXcapResources(void)
{
    if (g_Shv.XcapEntries != NULL)
        return STATUS_SUCCESS;

    SIZE_T entrySize = XCAP_MAX_PAGES * sizeof(XCAP_ENTRY);
    g_Shv.XcapEntries = (PXCAP_ENTRY)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, entrySize, 'mNoI');
    if (!g_Shv.XcapEntries) {
        SHV_ERR("Xcap: entries alloc failed");
        goto fail;
    }
    RtlZeroMemory(g_Shv.XcapEntries, entrySize);

    SIZE_T dataSize = (SIZE_T)XCAP_MAX_PAGES * 4096;
    g_Shv.XcapPageData = (PUCHAR)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, dataSize, 'mNoI');
    if (!g_Shv.XcapPageData) {
        SHV_ERR("Xcap: page data alloc failed");
        goto fail;
    }
    RtlZeroMemory(g_Shv.XcapPageData, dataSize);

    SIZE_T paSize = XCAP_MAX_PAGES * sizeof(ULONG64);
    g_Shv.XcapPaTable = (ULONG64*)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, paSize, 'mNoI');
    if (!g_Shv.XcapPaTable) {
        SHV_ERR("Xcap: PA table alloc failed");
        goto fail;
    }
    RtlZeroMemory(g_Shv.XcapPaTable, paSize);

    for (ULONG i = 0; i < XCAP_SPLIT_MAX; i++) {
        g_XcapSplitPts[i] = (EPT_PTE*)ShvAllocateContiguousMemory(sizeof(EPT_PTE) * 512);
        if (!g_XcapSplitPts[i]) {
            SHV_ERR("Xcap: split PT %lu alloc failed", i);
            goto fail;
        }
        g_XcapSplitPas[i] = MmGetPhysicalAddress(g_XcapSplitPts[i]).QuadPart;
        g_XcapSplitBase2mb[i] = 0;
    }
    InterlockedExchange(&g_XcapSplitCount, 0);

    SHV_LOG("Xcap: resources allocated (%lu entries, %llu MB data, %lu splits)",
            (ULONG)XCAP_MAX_PAGES, (ULONG64)(dataSize / (1024*1024)), (ULONG)XCAP_SPLIT_MAX);
    return STATUS_SUCCESS;

fail:
    ShvEptXcapDestroy();
    return STATUS_INSUFFICIENT_RESOURCES;
}

static EPT_PTE*
ShvEptXcapSplitFor(_In_ ULONG64 pa2mbBase)
{
    /* WORKAROUND (Apr 2026): use XcapTraceIncCount as both the lookup
     * bound AND the next-slot index. The original g_XcapSplitCount field
     * gets mysteriously zeroed post-install, which would cause retraps
     * to overwrite slot 0 instead of finding existing slots. The trace
     * counter is incremented in lockstep at the bottom of this function
     * and survives the zeroing. */
    LONG curCount = (LONG)g_Shv.XcapTraceIncCount;
    if (curCount < 0) curCount = 0;
    if ((ULONG)curCount > XCAP_SPLIT_MAX) curCount = (LONG)XCAP_SPLIT_MAX;
    for (LONG i = 0; i < curCount; i++) {
        if (g_XcapSplitBase2mb[i] == pa2mbBase)
            return g_XcapSplitPts[i];
    }
    if ((ULONG)curCount >= XCAP_SPLIT_MAX || g_EptState == NULL)
        return NULL;
    LONG slot = curCount;
    EPT_PTE* pt = g_XcapSplitPts[slot];
    ULONG pdptIdx = EPT_PDPT_INDEX(pa2mbBase);
    ULONG pdtIdx  = EPT_PDE_INDEX(pa2mbBase);
    ULONG64 pdeVal = *(volatile ULONG64*)&g_EptState->Pdt[pdptIdx][pdtIdx];
    if (!(pdeVal & 0x80)) return NULL; /* already split by another subsystem */
    UCHAR memType = g_EptState->Pdt[pdptIdx][pdtIdx].MemoryType;
    for (ULONG i = 0; i < 512; i++) {
        ULONG64 pa4k = pa2mbBase + (ULONG64)i * 4096;
        pt[i].Value = 0;
        pt[i].Read = 1; pt[i].Write = 1; pt[i].Execute = 1;
        pt[i].MemoryType = memType; pt[i].Pfn = pa4k >> 12;
        /* Item #11 — inherit SuppressVe=1 from parent identity-map PDE.
         * Xcap is a vmexit-driven exec-trap; #VE delivery is not wanted. */
        pt[i].SuppressVe = 1;
    }
    EPT_PDE_PTR pdePtr;
    pdePtr.Value = 0;
    pdePtr.Read = 1; pdePtr.Write = 1; pdePtr.Execute = 1;
    pdePtr.Pfn = g_XcapSplitPas[slot] >> 12;
    *(volatile ULONG64*)&g_EptState->Pdt[pdptIdx][pdtIdx] = pdePtr.Value;
    g_XcapSplitBase2mb[slot] = pa2mbBase;
    InterlockedIncrement(&g_XcapSplitCount);
    InterlockedIncrement(&g_Shv.XcapSplitForIncrements);

    /* ── Live trace instrumentation (Apr 2026) ───────────────────────
     * Read XcapSplitCount BACK from memory IMMEDIATELY after the
     * InterlockedIncrement above. Use a volatile pointer to defeat any
     * compiler caching. Then atomically store the read value into
     * XcapTraceLastInc (so we can read it from the diag VMCALL later)
     * and bump XcapTraceIncCount.
     *
     * If at probe time XcapTraceLastInc reads as 1219 but case 22
     * (XcapSplitCount itself) reads as 0, we KNOW the increment was
     * landing in memory at the moment it happened — meaning something
     * else writes 0 to that exact 4 bytes AFTER install. If both read
     * 0, the increment isn't being committed to the cache line.
     *
     * Both fields live at the very end of SHV_GLOBAL so they cannot
     * shift the offset of XcapSplitCount itself. */
    {
        volatile LONG* p = (volatile LONG*)&g_Shv.XcapSplitCount;
        LONG postInc = *p;
        InterlockedExchange(&g_Shv.XcapTraceLastInc, postInc);
        InterlockedIncrement(&g_Shv.XcapTraceIncCount);
    }
    return pt;
}
static EPT_PTE*
ShvEptXcapFindPte(_In_ ULONG64 Pa)
{
    ULONG64 pa2mb = Pa & ~(EPT_LARGE_PAGE_SIZE - 1ULL);
    ULONG ptIdx = EPT_PTE_INDEX(Pa);

    /* WORKAROUND (Apr 2026): g_Shv.XcapSplitCount reads as 0 post-install
     * for reasons that even exhaustive disassembly + field swap experiment
     * could not uncover. The bug follows the field name across address
     * relocations, but no instruction in the linked .sys binary writes 0
     * to that exact field after the install loop. The slot table itself
     * (g_XcapSplitBase2mb) is intact — reconstructive scan returns 1226
     * non-zero entries while the counter LONG reads 0.
     *
     * g_Shv.XcapTraceIncCount is a parallel atomic that mirrors every
     * SplitFor success and DOES survive the zeroing. Use it as the
     * authoritative loop bound. We still write XcapSplitCount in SplitFor
     * for diagnostic continuity. */
    LONG curCount = (LONG)g_Shv.XcapTraceIncCount;
    if (curCount <= 0) return NULL;
    if ((ULONG)curCount > XCAP_SPLIT_MAX) curCount = (LONG)XCAP_SPLIT_MAX;
    for (LONG i = 0; i < curCount; i++) {
        if (g_XcapSplitBase2mb[i] == pa2mb)
            return &g_XcapSplitPts[i][ptIdx];
    }
    return NULL;
}

/* Diagnostic helper: probe whether the PA at XcapPaTable[Index] has its
 * EPT PTE Execute bit cleared (returns 0) or set (returns 1). Returns
 * 0xFF for out-of-range index or no matching split. Used by VMCALL_XCAP_DIAG
 * to verify our Execute=0 writes actually persisted in the live EPT. */
ULONG
ShvEptXcapProbePtaTableExecute(_In_ ULONG Index)
{
    if (g_Shv.XcapPaTable == NULL) return 0xFF;
    if (Index >= XCAP_MAX_PAGES)   return 0xFF;
    ULONG64 pa = g_Shv.XcapPaTable[Index];
    if (pa == 0) return 0xFF;
    EPT_PTE* pte = ShvEptXcapFindPte(pa);
    if (pte == NULL) return 0xFF;
    return (ULONG)(pte->Execute & 1);
}

ULONG
ShvEptXcapGetSplitCount(void)
{
    return g_XcapSplitCount;
}

/* Static analysis diag: count non-zero entries in g_XcapSplitBase2mb,
 * INDEPENDENT of g_XcapSplitCount. The install loop calls SplitFor which
 * stores pa2mbBase into g_XcapSplitBase2mb[slot] AND increments the
 * counter. If this scan returns N but g_XcapSplitCount returns 0, the
 * counter is desynced from the slot table — meaning a write to the
 * counter LONG was lost or zeroed somehow even though the slot table
 * (sibling static array, separate BSS pages) survived intact.
 *
 * Slow (XCAP_SPLIT_MAX iterations = 49152 reads) but only called from
 * the diag VMCALL when the user explicitly asks for it. */
ULONG
ShvEptXcapCountFilledSplits(void)
{
    ULONG count = 0;
    for (ULONG i = 0; i < XCAP_SPLIT_MAX; i++) {
        if (g_XcapSplitBase2mb[i] != 0) {
            count++;
        }
    }
    return count;
}

/* Diag: returns the LIVE address of g_Shv.XcapSplitCount (so we can
 * verify the diag and the install operate on the same memory location). */
ULONG64
ShvEptXcapGetSplitCountAddr(void)
{
    return (ULONG64)(ULONG_PTR)&g_Shv.XcapSplitCount;
}

ULONG64
ShvEptXcapGetSplitBase2mb(_In_ ULONG Index)
{
    if (Index >= XCAP_SPLIT_MAX) return 0;
    return g_XcapSplitBase2mb[Index];
}

/* Diagnostic: read the LIVE raw qword in g_EptState->Pdt for the 2 MB
 * region that contains XcapPaTable[Index]. This tells us what the CPU
 * EPT walker would actually see when traversing the page tables for
 * the PA we recorded. Compare against the bit layout for EPT_PDE_PTR
 * (low byte should be 0x07 = RWX, no LargePage) vs EPT_PDE_2MB
 * (low byte 0xB7 = RWX + WB MemType + LargePage). If it's 0xB7, our
 * install never overwrote the 2 MB PDE. If it's 0x07, our install
 * succeeded and the walker should descend into our split PT. */
ULONG64
ShvEptXcapGetLivePdeFor(_In_ ULONG Index)
{
    if (g_EptState == NULL || g_Shv.XcapPaTable == NULL) return 0;
    if (Index >= XCAP_MAX_PAGES) return 0;
    ULONG64 pa = g_Shv.XcapPaTable[Index];
    if (pa == 0) return 0;
    ULONG pdptIdx = EPT_PDPT_INDEX(pa);
    ULONG pdtIdx  = EPT_PDE_INDEX(pa);
    if (pdptIdx >= 512 || pdtIdx >= 512) return 0;
    return *(volatile ULONG64*)&g_EptState->Pdt[pdptIdx][pdtIdx];
}

/* Diagnostic: read the LIVE raw qword in the xcap split PT for the
 * 4 KB page corresponding to XcapPaTable[Index]. This is the PT entry
 * the install set Execute=0 on. Compare bit 2 (Execute) to verify the
 * write actually persisted in the split PT memory the walker reads from
 * when descending from a successfully-installed PDE_PTR. */
ULONG64
ShvEptXcapGetLivePtEntryFor(_In_ ULONG Index)
{
    if (g_Shv.XcapPaTable == NULL) return 0;
    if (Index >= XCAP_MAX_PAGES) return 0;
    ULONG64 pa = g_Shv.XcapPaTable[Index];
    if (pa == 0) return 0;
    EPT_PTE* pte = ShvEptXcapFindPte(pa);
    if (pte == NULL) return 0;
    return *(volatile ULONG64*)pte;
}

/* Diagnostic: physical address of g_EptState->Pml4. Compare against
 * VMCS_CTRL_EPTP's Pfn field — if they match, the CPU is walking the
 * same PML4 we're modifying. If not, our writes are going to a totally
 * different page table than what the EPT walker uses. */
ULONG64
ShvEptXcapGetPml4Pa(void)
{
    if (g_EptState == NULL) return 0;
    return MmGetPhysicalAddress(&g_EptState->Pml4[0]).QuadPart;
}

void ShvEptXcapRestoreExecuteByPa(_In_ ULONG64 Pa)
{
    EPT_PTE* pte = ShvEptXcapFindPte(Pa);
    if (pte) pte->Execute = 1;
}

/* ── Capture-on-execute path (called from EPT violation handler) ──────
 *
 * Called when an EPT violation fires on a 4 KB page that may belong to an
 * armed xcap session. Returns:
 *
 *   1  — capture handled (or wrong-CR3 skip): caller restored Execute,
 *        INVEPTed, must NOT inject #GP and must NOT advance RIP.
 *   0  — not an xcap-trapped page: caller should fall through to its
 *        existing handling (FIFO trap, dual-EPT hooks, #GP injection).
 *
 * Behaviour:
 *   - Linear-scans XcapPaTable for the matching GPA. O(n) over the active
 *     range, but only on actual EPT violations — once a page is captured,
 *     Execute is restored and no further violations fire on it.
 *   - Optional CR3 filter: if XcapTargetCr3 is non-zero, mismatched
 *     processes are still allowed to execute (Execute restored on the
 *     PTE) but no capture happens; counted in XcapWrongCr3Count.
 *   - On match + correct CR3: copies the 4 KB GPA contents into
 *     XcapPageData[i*4096] via MmCopyMemory(PHYSICAL), populates the
 *     XcapEntry, sets the bitmap bit, restores Execute on the PTE, and
 *     INVEPTs the local TLB. */
ULONG
ShvEptXcapTryCapture(
    _In_ ULONG64 GuestPa,
    _In_ ULONG64 GuestVa,
    _In_ ULONG64 GuestRip,
    _In_ ULONG64 GuestCr3,
    _In_ ULONG  CpuIndex
    )
{
    if (!g_Shv.XcapActive) return 0;
    if (g_Shv.XcapPaTable == NULL || g_Shv.XcapEntries == NULL ||
        g_Shv.XcapPageData == NULL) return 0;

    /* Look for an EPT_PTE for this PA. If there is no xcap split covering
     * this 2 MB region the page is not ours. */
    ULONG64 paAligned = GuestPa & ~0xFFFULL;
    EPT_PTE* pte = ShvEptXcapFindPte(paAligned);
    if (pte == NULL) return 0;

    /* If Execute is already 1 the trap was already cleared (race with
     * another CPU that captured first). Treat as "ours" so we don't
     * inject #GP, but skip the duplicate capture. */
    if (pte->Execute) {
        return 1;
    }

    /* Find which entry index corresponds to this PA.
     *
     * Apr 2026: prefer XcapPaTableCount (set by the multi-region poller).
     * Falls back to (VaEnd - VaBase) >> 12 for legacy single-range mode. */
    ULONG totalPages = 0;
    if (g_Shv.XcapPaTableCount > 0) {
        totalPages = (ULONG)g_Shv.XcapPaTableCount;
    } else if (g_Shv.XcapVaEnd > g_Shv.XcapVaBase) {
        totalPages = (ULONG)((g_Shv.XcapVaEnd - g_Shv.XcapVaBase) >> 12);
    }
    if (totalPages > XCAP_MAX_PAGES) totalPages = XCAP_MAX_PAGES;

    ULONG matchIdx = (ULONG)-1;
    for (ULONG i = 0; i < totalPages; i++) {
        if (g_Shv.XcapPaTable[i] == paAligned) {
            matchIdx = i;
            break;
        }
    }

    /* PA not in our table — this 2 MB region is split for xcap (so it
     * fell into our split table) but the specific 4 KB page is one we
     * never armed (a normal RWX neighbour). Not an xcap event. */
    if (matchIdx == (ULONG)-1) return 0;

    InterlockedIncrement(&g_Shv.XcapViolationCount);

    /* Snapshot the slot count at the moment of the very first capture.
     * Read via XcapTraceIncCount (the field that survives the post-install
     * zeroing of g_XcapSplitCount). */
    if (g_Shv.XcapAtCaptureSplitCount == 0) {
        InterlockedExchange(&g_Shv.XcapAtCaptureSplitCount, (LONG)g_Shv.XcapTraceIncCount);
    }

    /* CR3 filter: WARNING — used to be a hard reject (drop the capture
     * AND restore Execute on the PTE). That was wrong on at least two
     * grounds:
     *
     *   1. The CR3 we capture in NexusCore image notify (via __readcr3)
     *      is whatever the calling thread had at notify time. With KPTI
     *      enabled, that may be the launcher's KERNEL CR3, while the
     *      launcher executes its image pages with the USER CR3. The two
     *      values differ by an entire physical page allocation, so the
     *      mismatch test rejects every single legitimate launcher fault.
     *
     *   2. Restoring Execute=1 on a rejected fault PERMANENTLY DISARMS
     *      the trap on that page. Subsequent legitimate faults on the
     *      same page never fire. We end up capturing nothing while
     *      bleeding off our traps one wrong-CR3 reject at a time.
     *
     * Symptom against the observed service process: 1 violation, 1 wrong-CR3 reject,
     * 0 captures, despite RIP sampling showing real in-image executes.
     *
     * Fix: drop the reject. Capture every execute fault on a trapped
     * page regardless of CR3. The GuestCr3 is recorded in the entry
     * metadata so the user-mode side can post-filter by CR3 if false
     * positives ever appear. They almost certainly won't for a private
     * EXE — other processes don't share its physical pages. The "wrong
     * CR3" counter still increments for visibility but no longer
     * affects the capture path. */
    if (g_Shv.XcapTargetCr3 != 0 &&
        (GuestCr3 & ~0xFFFULL) != g_Shv.XcapTargetCr3) {
        InterlockedIncrement(&g_Shv.XcapWrongCr3Count);
        /* Fall through — DO NOT reject, DO NOT restore Execute here. */
    }

    /* Already captured? Bitmap bit set. Just restore Execute and bail. */
    ULONG wordIdx = matchIdx / 32;
    ULONG bitMask = 1UL << (matchIdx % 32);
    if (g_Shv.XcapBitmap[wordIdx] & bitMask) {
        pte->Execute = 1;
        if (g_EptState != NULL) {
            ULONG64 eptp = g_EptState->EptPointer.Value;
            if (eptp != 0) {
                INVEPT_DESCRIPTOR desc;
                desc.EptPointer = eptp; desc.Reserved = 0;
                ShvInvept(INVEPT_SINGLE_CONTEXT, &desc);
            }
        }
        return 1;
    }

    /* Copy the 4 KB page out via MmCopyMemory(PHYSICAL).
     * Safe from VMX root because MmCopyMemory of a physical source
     * does NOT touch the MMU pool — it remaps via a self-referencing
     * trampoline and hits no allocations or locks. */
    {
        MM_COPY_ADDRESS src;
        SIZE_T bytes = 0;
        src.PhysicalAddress.QuadPart = (LONGLONG)paAligned;
        NTSTATUS copySt = MmCopyMemory(
            g_Shv.XcapPageData + (ULONG64)matchIdx * 4096,
            src,
            4096,
            MM_COPY_MEMORY_PHYSICAL,
            &bytes);

        if (!NT_SUCCESS(copySt) || bytes != 4096) {
            /* Capture failed — leave the bitmap bit clear so a future
             * fault can retry, but restore Execute so the guest makes
             * progress on this attempt. */
            pte->Execute = 1;
            if (g_EptState != NULL) {
                ULONG64 eptp = g_EptState->EptPointer.Value;
                if (eptp != 0) {
                    INVEPT_DESCRIPTOR desc;
                    desc.EptPointer = eptp; desc.Reserved = 0;
                    ShvInvept(INVEPT_SINGLE_CONTEXT, &desc);
                }
            }
            return 1;
        }
    }

    /* Fill the metadata entry and set the bitmap bit. */
    {
        LONG seq = InterlockedIncrement(&g_Shv.XcapCapturedCount);
        PXCAP_ENTRY entry = &g_Shv.XcapEntries[matchIdx];
        entry->GuestPa   = paAligned;
        entry->GuestVa   = GuestVa & ~0xFFFULL;
        entry->GuestRip  = GuestRip;
        entry->GuestCr3  = GuestCr3;
        entry->PageIndex = matchIdx;
        entry->CpuIndex  = CpuIndex;
        entry->Counter   = (ULONG32)seq;
        entry->Reserved  = 0;
        g_Shv.XcapBitmap[wordIdx] |= bitMask;
    }

    /* Restore Execute on the PTE so subsequent runs of this code page
     * don't generate further violations, then INVEPT to flush stale TLBs. */
    pte->Execute = 1;
    if (g_EptState != NULL) {
        ULONG64 eptp = g_EptState->EptPointer.Value;
        if (eptp != 0) {
            INVEPT_DESCRIPTOR desc;
            desc.EptPointer = eptp; desc.Reserved = 0;
            ShvInvept(INVEPT_SINGLE_CONTEXT, &desc);
        }
    }
    return 1;
}

void ShvEptXcapRemoveExecuteByPa(_In_ ULONG64 Pa)
{
    EPT_PTE* pte = ShvEptXcapFindPte(Pa);
    if (pte) {
        pte->Execute = 0;
        if (g_EptState != NULL) {
            ULONG64 eptp = g_EptState->EptPointer.Value;
            if (eptp != 0) {
                INVEPT_DESCRIPTOR desc;
                desc.EptPointer = eptp; desc.Reserved = 0;
                ShvInvept(INVEPT_SINGLE_CONTEXT, &desc);
            }
        }
    }
}

void ShvEptXcapWalkAndTrap(
    _In_ ULONG64 Cr3,
    _In_ ULONG64 VaBase,
    _In_ ULONG64 VaEnd,
    _In_ BOOLEAN IsRetrap
)
{
    /* This function installs xcap traps from a pre-populated PA table.
     * The walk happens in NexusCore's image-load notify (PASSIVE_LEVEL,
     * target process context) using MmGetPhysicalAddress. NexusCore
     * writes results into g_Shv.XcapPaTable directly via the address
     * returned by VMCALL_XCAP_GET_PATABLE, then issues VMCALL_XCAP_SETUP.
     *
     * RETRAP HANDLING (the COW problem):
     * Modern user-mode EXEs are built with /DYNAMICBASE so ASLR loads
     * them at a random VA, and the loader applies base relocations.
     * Each relocation WRITE to a shared image page triggers copy-on-
     * write: the kernel allocates a new private physical page, copies
     * the shared content into it, and updates the process PTE to point
     * to the new private PA. The OLD shared PA is now orphaned for this
     * process — the launcher will never read or execute from it again.
     *
     * Image notify fires BEFORE relocations are applied (between section
     * map and LdrpInitialize), so the PAs we record at notify time are
     * the SHARED PAs that get orphaned. Trapping them does nothing.
     *
     * The fix is to re-walk after relocations are done. NexusCore knows
     * relocations are done when any other image (DLL) loads in the same
     * process, because the loader applies EXE relocations in
     * LdrpInitializeProcess BEFORE LdrpLoadImports starts pulling DLLs.
     * On each subsequent image notify in the armed process, NexusCore
     * re-walks the EXE's image VA range and calls back here with
     * IsRetrap=TRUE.
     *
     * On a retrap we must:
     *   1. Restore Execute=1 on every PTE we previously cleared so
     *      orphaned shared PAs don't stay trapped (which would cause
     *      spurious faults if those pages are later reused for other
     *      processes).
     *   2. Keep XcapBitmap and capture counters untouched so any pages
     *      already captured by a prior install accumulate across the
     *      whole session.
     *
     * On a fresh arm (IsRetrap=FALSE) we do (1) AND also reset all
     * counters and the bitmap. */
    if (g_Shv.XcapPaTable == NULL || g_Shv.XcapEntries == NULL ||
        g_Shv.XcapPageData == NULL) {
        SHV_ERR("Xcap: install called before resources allocated");
        return;
    }

    /* Step 1: restore Execute on every PTE we previously cleared.
     * Walk every xcap split table; any Execute=0 4 KB PTE was set by
     * a prior call to this function. Restore it.
     *
     * For an 18 MB image with up to 4621 splits (one per scattered 4 KB
     * physical region), this iterates ~4621 * 512 = 2.4 M PTEs. Each
     * iteration is a simple bit check; total cost ~5 ms. Acceptable
     * for an arm/retrap operation. */
    {
        /* WORKAROUND (Apr 2026): use XcapTraceIncCount instead of
         * g_XcapSplitCount — see ShvEptXcapFindPte comment for details. */
        ULONG sCount = (ULONG)g_Shv.XcapTraceIncCount;
        if (sCount > XCAP_SPLIT_MAX) sCount = XCAP_SPLIT_MAX;
        for (ULONG s = 0; s < sCount; s++) {
            EPT_PTE* pt = g_XcapSplitPts[s];
            if (pt == NULL) continue;
            for (ULONG i = 0; i < 512; i++) {
                if (pt[i].Execute == 0) {
                    pt[i].Execute = 1;
                }
            }
        }
    }

    /* Step 2: on a fresh arm, reset session state. On a retrap, leave
     * the bitmap and capture counters intact so prior captures persist. */
    if (!IsRetrap) {
        RtlZeroMemory(g_Shv.XcapBitmap, sizeof(g_Shv.XcapBitmap));
        InterlockedExchange(&g_Shv.XcapCapturedCount, 0);
        InterlockedExchange(&g_Shv.XcapViolationCount, 0);
        InterlockedExchange(&g_Shv.XcapWrongCr3Count, 0);
        /* Also reset all RIP sampling and diagnostic counters so each
         * fresh arm gets a clean per-test view. Otherwise these leak
         * across arms within the same boot and reading them later
         * shows stale data from prior tests. */
        InterlockedExchange(&g_Shv.XcapRipSampleCount, 0);
        InterlockedExchange(&g_Shv.XcapRipInImageCount, 0);
        InterlockedExchange(&g_Shv.XcapAnyExecViolation, 0);
        InterlockedExchange(&g_Shv.XcapTotalEptViolations, 0);
        InterlockedExchange(&g_Shv.XcapNonPrimaryEptpCount, 0);
        InterlockedExchange(&g_Shv.XcapPostInstallSplitCount, 0);
        InterlockedExchange(&g_Shv.XcapAtCaptureSplitCount, 0);
        InterlockedExchange(&g_Shv.XcapSplitForIncrements, 0);
        g_Shv.XcapFirstRipIn        = 0;
        g_Shv.XcapFirstRipOut       = 0;
        g_Shv.XcapLastRip           = 0;
        g_Shv.XcapLastNonPrimaryEptp = 0;
    }
    /* These three are always reset — they describe the CURRENT install,
     * not the cumulative session, so retrap should overwrite them with
     * the new install's results. */
    InterlockedExchange(&g_Shv.XcapTrappedCount, 0);
    InterlockedExchange(&g_Shv.XcapNoPaCount, 0);
    InterlockedExchange(&g_Shv.XcapNoSplitCount, 0);

    g_Shv.XcapVaBase     = VaBase;
    g_Shv.XcapVaEnd      = VaEnd;
    g_Shv.XcapTargetCr3  = Cr3 & ~0xFFFULL;  /* mask off PCID bits for compare */

    /* Step 3: install fresh traps from the pre-populated PA table.
     *
     * Apr 2026: if g_Shv.XcapPaTableCount is non-zero, use it as the
     * iteration bound. The multi-region poller in NexusCore packs PAs
     * sequentially (one per discovered exec page across all VA regions)
     * and sets PaTableCount to the total. When 0, fall back to the
     * original linear-VA install where index = (va - VaBase) / 4096. */
    ULONG totalPages;
    if (g_Shv.XcapPaTableCount > 0) {
        totalPages = (ULONG)g_Shv.XcapPaTableCount;
        if (totalPages > XCAP_MAX_PAGES) totalPages = XCAP_MAX_PAGES;
    } else {
        totalPages = (ULONG)((VaEnd - VaBase) >> 12);
        if (totalPages > XCAP_MAX_PAGES) totalPages = XCAP_MAX_PAGES;
    }
    LONG trapped = 0, noPA = 0, noSplit = 0;

    for (ULONG i = 0; i < totalPages; i++) {
        ULONG64 pa = g_Shv.XcapPaTable[i];
        if (pa == 0 || EPT_PML4_INDEX(pa) != 0) {
            noPA++;
            continue;
        }
        ULONG64 pa2mb = pa & ~(EPT_LARGE_PAGE_SIZE - 1ULL);
        EPT_PTE* pt = ShvEptXcapSplitFor(pa2mb);
        if (!pt) {
            noSplit++;
            continue;
        }
        pt[EPT_PTE_INDEX(pa)].Execute = 0;
        trapped++;
    }

    InterlockedExchange(&g_Shv.XcapTrappedCount, trapped);
    InterlockedExchange(&g_Shv.XcapNoPaCount,    noPA);
    InterlockedExchange(&g_Shv.XcapNoSplitCount, noSplit);

    /* Snapshot the slot count immediately after the install loop. Read
     * via XcapTraceIncCount (the field that survives the post-install
     * zeroing — see ShvEptXcapFindPte comment). The original
     * g_XcapSplitCount snapshot is preserved further down for diagnostic
     * comparison. */
    InterlockedExchange(&g_Shv.XcapPostInstallSplitCount, (LONG)g_Shv.XcapTraceIncCount);

    /* Step 4: INVEPT current CPU. The caller (NexusCore image notify)
     * is expected to follow with KeIpiGenericCall(XcapInveptIpiCallback)
     * to broadcast across all CPUs. */
    if (g_EptState != NULL) {
        ULONG64 eptp = g_EptState->EptPointer.Value;
        if (eptp != 0) {
            INVEPT_DESCRIPTOR desc;
            desc.EptPointer = eptp; desc.Reserved = 0;
            ShvInvept(INVEPT_SINGLE_CONTEXT, &desc);
        }
    }
    InterlockedExchange(&g_Shv.XcapActive, 1);
    SHV_LOG("Xcap: %s installed %ld traps (%ld no-PA, %ld no-split), %lu pages, %lu splits",
            IsRetrap ? "RETRAP" : "FRESH",
            trapped, noPA, noSplit, totalPages,
            (ULONG)g_Shv.XcapTraceIncCount);
}

void ShvEptXcapDestroy(void)
{
    InterlockedExchange(&g_Shv.XcapActive, 0);
    if (g_Shv.XcapPaTable && g_EptState) {
        ULONG tp = 0;
        if (g_Shv.XcapVaEnd > g_Shv.XcapVaBase)
            tp = (ULONG)((g_Shv.XcapVaEnd - g_Shv.XcapVaBase) >> 12);
        if (tp > XCAP_MAX_PAGES) tp = XCAP_MAX_PAGES;
        for (ULONG i = 0; i < tp; i++) {
            if (g_Shv.XcapPaTable[i]) {
                EPT_PTE* pte = ShvEptXcapFindPte(g_Shv.XcapPaTable[i]);
                if (pte) pte->Execute = 1;
            }
        }
    }
    for (ULONG i = 0; i < XCAP_SPLIT_MAX; i++) {
        if (g_XcapSplitPts[i]) {
            ShvFreeContiguousMemory(g_XcapSplitPts[i], sizeof(EPT_PTE) * 512);
            g_XcapSplitPts[i] = NULL;
        }
        g_XcapSplitPas[i] = 0; g_XcapSplitBase2mb[i] = 0;
    }
    InterlockedExchange(&g_XcapSplitCount, 0);
    if (g_Shv.XcapEntries) { ExFreePoolWithTag(g_Shv.XcapEntries, 'mNoI'); g_Shv.XcapEntries = NULL; }
    if (g_Shv.XcapPageData) { ExFreePoolWithTag(g_Shv.XcapPageData, 'mNoI'); g_Shv.XcapPageData = NULL; }
    if (g_Shv.XcapPaTable) { ExFreePoolWithTag(g_Shv.XcapPaTable, 'mNoI'); g_Shv.XcapPaTable = NULL; }
    SHV_LOG("Xcap: destroyed (captured %ld pages)", g_Shv.XcapCapturedCount);
}

/* ===== UM EPT Write-Trap (Phase C, Apr 2026) =================================
 * Day 1 scaffolding — struct additions and function stubs only. No behavior
 * change at runtime: WriteTrapActive stays 0 until a successful install, and
 * every stub returns STATUS_NOT_IMPLEMENTED. Day 2 fills in the real paths.
 * Spec: tools/the design notes.
 */

NTSTATUS ShvEptPrepareWriteTrapResources(void)
{
    /* Idempotent: allocate the 512 KB log ring once. */
    if (g_Shv.WriteTrapLog != NULL) {
        return STATUS_SUCCESS;
    }

    SIZE_T bytes = (SIZE_T)WRITE_TRAP_LOG_MAX * sizeof(WRITE_TRAP_LOG_ENTRY);
    g_Shv.WriteTrapLog = (PWRITE_TRAP_LOG_ENTRY)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, bytes, '0fdW');  /* mem=Wdf0 (KMDF runtime) */
    if (!g_Shv.WriteTrapLog) {
        SHV_LOG("WriteTrap: log-ring alloc failed (%llu bytes)", (ULONG64)bytes);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    InterlockedExchange(&g_Shv.WriteTrapLogIndex, 0);
    InterlockedExchange(&g_Shv.WriteTrapLogTotal, 0);
    SHV_LOG("WriteTrap: log ring allocated (%llu bytes at %p)",
            (ULONG64)bytes, g_Shv.WriteTrapLog);
    return STATUS_SUCCESS;
}

/* MTF bit in VMCS_CTRL_PROC_BASED_EXEC. Already defined at file top of
 * exit_ept.c / exit_dispatch.c but not in a shared header — re-declare
 * locally so the write-trap code here compiles without cross-file churn. */
#ifndef CPU_BASED_MONITOR_TRAP_FLAG
#define CPU_BASED_MONITOR_TRAP_FLAG  (1UL << 27)
#endif

/* -----------------------------------------------------------------------------
 * v1 scope simplification vs spec §1.1:
 *
 * Spec originally called for SECONDARY EPT only + per-process EPTP switch.
 * That requires a separate "park target process on secondary" mechanism
 * which is a feature in its own right. For v1 we clear W on the target
 * 4 KB PTE in the PRIMARY EPT instead. The trap fires on every CPU that
 * writes to the target GPA regardless of which EPT they happen to be on.
 * Correctness preserved because:
 *   - CR3 filter in ShvEptWriteTrapTryHandle drops writes from other
 *     processes (stack / heap pages are process-private, so false hits
 *     are rare; constants in .rdata are shared but never written).
 *   - Non-target writers get a trivially cheap filtered-skip path.
 *   - Primary EPT split reuses g_HookRes.PriPt (shared with dual-EPT
 *     hooks) which is already idempotent via ShvEptPrimarySplitFor.
 *
 * Upgrade path to spec secondary-only is a future v2 once we ship the
 * per-process EPTP-park mechanism.
 * ---------------------------------------------------------------------------*/

NTSTATUS ShvEptInstallWriteTrap(
    _In_ ULONG64 Cr3,
    _In_ ULONG64 TargetPa,
    _In_ ULONG64 VaBase,
    _In_ ULONG64 VaEnd,
    _In_ ULONG64 RipFilter
    )
{
    /* Sanity guard against unresolved TargetPa. A legitimate UM-backed
     * page PA is always >= 1 MB (below is BIOS ROM / reset vector) and
     * always < 256 TB. If the NexusCore pending-op shim failed to resolve
     * UM VA -> PA, stale PID values (0, small integers) arrive here and
     * proceeding would split the first 2 MB of guest physical memory,
     * corrupting EPT state for PA 0 and producing a MCE with bugcheck
     * 0x1A subtype 0x61941 (PAGE_TABLE_RESERVED_BITS_SET) on the next
     * page walk touching that region (see minidump 041726-26218-01). */
    if (TargetPa < 0x100000ULL || TargetPa >= 0x0000100000000000ULL) {
        SHV_ERR("WriteTrap: install rejected -- TargetPa=0x%llX looks unresolved "
                "(expected UM-backed PA in [1MB, 256TB); likely PID/0 leaked through)",
                TargetPa);
        return STATUS_INVALID_PARAMETER;
    }
    if (!g_HookRes.Ready) {
        SHV_ERR("WriteTrap: hook resources not prepared (split PT pool unavailable)");
        return STATUS_UNSUCCESSFUL;
    }
    if (g_EptState == NULL) {
        SHV_ERR("WriteTrap: EPT state not initialized");
        return STATUS_UNSUCCESSFUL;
    }
    if (EPT_PML4_INDEX(TargetPa) != 0) {
        SHV_ERR("WriteTrap: TargetPa 0x%llX not in PML4[0] (must be <512 GB)", TargetPa);
        return STATUS_INVALID_PARAMETER;
    }
    if (VaEnd <= VaBase) {
        SHV_ERR("WriteTrap: VaEnd (0x%llX) <= VaBase (0x%llX)", VaEnd, VaBase);
        return STATUS_INVALID_PARAMETER;
    }
    if ((VaEnd - VaBase) > PAGE_SIZE) {
        SHV_ERR("WriteTrap: range > 4 KB not supported in v1 (VA span 0x%llX)",
                VaEnd - VaBase);
        return STATUS_INVALID_PARAMETER;
    }
    if (g_Shv.WriteTrapActive) {
        SHV_ERR("WriteTrap: already armed — uninstall first");
        return STATUS_ALREADY_INITIALIZED;
    }
    if (g_Shv.WriteTrapLog == NULL) {
        SHV_ERR("WriteTrap: log ring not allocated (call Prepare first)");
        return STATUS_UNSUCCESSFUL;
    }

    ULONG64 pageAlignedPa = TargetPa & ~0xFFFULL;
    ULONG64 pa2mbBase = TargetPa & ~(EPT_LARGE_PAGE_SIZE - 1ULL);
    ULONG   ptIdx     = EPT_PTE_INDEX(TargetPa);

    /* Split the primary-EPT 2 MB page (idempotent). */
    EPT_PTE* priPt = ShvEptPrimarySplitFor(pa2mbBase);
    if (!priPt) {
        SHV_ERR("WriteTrap: primary split failed for 0x%llX (g_HookRes.PriCount=%lu/%u)",
                pa2mbBase, g_HookRes.PriCount, HOOK_SPLIT_MAX);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Populate control fields BEFORE flipping active. */
    g_Shv.WriteTrapCr3       = Cr3;
    g_Shv.WriteTrapTargetPa  = pageAlignedPa;
    g_Shv.WriteTrapVaBase    = VaBase;
    g_Shv.WriteTrapVaEnd     = VaEnd;
    g_Shv.WriteTrapRipFilter = RipFilter;

    /* Reset diagnostic counters + log ring indices. */
    InterlockedExchange(&g_Shv.WriteTrapHits,           0);
    InterlockedExchange(&g_Shv.WriteTrapFilteredCr3,    0);
    InterlockedExchange(&g_Shv.WriteTrapFilteredVa,     0);
    InterlockedExchange(&g_Shv.WriteTrapFilteredRip,    0);
    InterlockedExchange(&g_Shv.WriteTrapLogIndex,       0);
    InterlockedExchange(&g_Shv.WriteTrapLogTotal,       0);

    /* Clear W on the target 4 KB PTE. Leave R and X alone. */
    priPt[ptIdx].Write = 0;

    /* INVEPT single-context on primary EPTP. */
    ULONG64 eptp = g_EptState->EptPointer.Value;
    if (eptp != 0) {
        INVEPT_DESCRIPTOR desc;
        desc.EptPointer = eptp;
        desc.Reserved = 0;
        ShvInvept(INVEPT_SINGLE_CONTEXT, &desc);
    }

    /* Bump InveptGeneration so every CPU flushes its TLB on next VM exit. */
    InterlockedIncrement(&g_Shv.InveptGeneration);

    /* Flip active LAST. Any CPU that observes this=1 AFTER the PTE W=0
     * write and the INVEPT sees a consistent trap setup. */
    InterlockedExchange((volatile LONG*)&g_Shv.WriteTrapActive, 1);

    SHV_LOG("WriteTrap: armed pa=0x%llX cr3=0x%llX va=[0x%llX,0x%llX) rip=0x%llX ptIdx=%lu",
            pageAlignedPa, Cr3, VaBase, VaEnd, RipFilter, ptIdx);
    return STATUS_SUCCESS;
}

NTSTATUS ShvEptUninstallWriteTrap(void)
{
    if (!g_Shv.WriteTrapActive) {
        /* Idempotent no-op. */
        return STATUS_SUCCESS;
    }

    /* Freeze new logging FIRST so in-flight violation handlers stop
     * consuming log slots. Counters remain readable post-disarm. */
    InterlockedExchange((volatile LONG*)&g_Shv.WriteTrapActive, 0);

    ULONG64 pageAlignedPa = g_Shv.WriteTrapTargetPa;
    ULONG64 pa2mbBase = pageAlignedPa & ~(EPT_LARGE_PAGE_SIZE - 1ULL);
    ULONG   ptIdx     = EPT_PTE_INDEX(pageAlignedPa);

    /* Restore W=1 on the target PTE. */
    BOOLEAN restored = FALSE;
    for (ULONG i = 0; i < g_HookRes.PriCount; i++) {
        if (g_HookRes.PriBase[i] == pa2mbBase) {
            g_HookRes.PriPt[i][ptIdx].Write = 1;
            restored = TRUE;
            break;
        }
    }

    if (!restored) {
        SHV_LOG("WriteTrap: uninstall — no matching split for 2MB base 0x%llX (trap was already clean?)",
                pa2mbBase);
    }

    /* INVEPT single-context + bump InveptGeneration so every CPU sees
     * the restored W=1 before any guest instruction retries a write. */
    if (g_EptState != NULL) {
        ULONG64 eptp = g_EptState->EptPointer.Value;
        if (eptp != 0) {
            INVEPT_DESCRIPTOR desc;
            desc.EptPointer = eptp;
            desc.Reserved = 0;
            ShvInvept(INVEPT_SINGLE_CONTEXT, &desc);
        }
    }
    InterlockedIncrement(&g_Shv.InveptGeneration);

    /* Zero the control fields so a stale read doesn't look armed. */
    g_Shv.WriteTrapCr3       = 0;
    g_Shv.WriteTrapTargetPa  = 0;
    g_Shv.WriteTrapVaBase    = 0;
    g_Shv.WriteTrapVaEnd     = 0;
    g_Shv.WriteTrapRipFilter = 0;

    SHV_LOG("WriteTrap: disarmed (hits=%ld cr3-filtered=%ld va-filtered=%ld rip-filtered=%ld)",
            g_Shv.WriteTrapHits, g_Shv.WriteTrapFilteredCr3,
            g_Shv.WriteTrapFilteredVa, g_Shv.WriteTrapFilteredRip);
    return STATUS_SUCCESS;
}

ULONG ShvEptWriteTrapTryHandle(
    _In_ ULONG64 GuestPa,
    _In_ ULONG64 GuestLinearVa,
    _In_ ULONG64 GuestRip,
    _In_ ULONG64 GuestCr3,
    _In_ ULONG64 ExitQualification,
    _In_ ULONG   CpuIndex,
    _In_ struct _VCPU_DATA *Vcpu
    )
{
    /* Quick gates — pay nothing when trap is disarmed or violation is
     * unrelated. All three checks are pure reads, no atomic ops. */
    if (!g_Shv.WriteTrapActive) return 0;
    if ((GuestPa & ~0xFFFULL) != (g_Shv.WriteTrapTargetPa & ~0xFFFULL)) return 0;
    if (!(ExitQualification & EPT_VIOLATION_DATA_WRITE)) return 0;

    /* Apply filters. Any one miss → skip logging, still re-arm normally. */
    BOOLEAN shouldLog = TRUE;

    if (g_Shv.WriteTrapCr3 != 0 && GuestCr3 != g_Shv.WriteTrapCr3) {
        LONG prevFilteredCr3 = InterlockedIncrement(&g_Shv.WriteTrapFilteredCr3) - 1;
        shouldLog = FALSE;
        /* v1.2 safety: auto-disarm on FIRST CR3 mismatch. Under normal armed
         * operation the target page is process-private .data or DLL state —
         * no legitimate cross-process write. A CR3 mismatch means the target
         * process has exited and the physical page has been reassigned. Next
         * step in the bad-state chain is the OS's PFN-scrub detecting the
         * stale W=0 PTE → BugCheck 0x1A (MEMORY_MANAGEMENT / PFN inconsistency).
         *
         * Queue an immediate uninstall. exit_dispatch polling picks it up on
         * the next VM exit and restores W=1 before the OS has a chance to
         * reassign / scrub the page.
         *
         * See memory/um_ept_writetrap_bsod_process_teardown_2026_04_17.md for
         * the BSOD post-mortem that motivated this guard. */
        if (prevFilteredCr3 == 0) {
            InterlockedExchange64((volatile LONG64*)&g_Shv.PendingWriteTrapOp, 2);
        }
    }

    if (shouldLog &&
        (ExitQualification & EPT_VIOLATION_GLA_VALID) &&
        g_Shv.WriteTrapVaBase != 0 && g_Shv.WriteTrapVaEnd != 0 &&
        (GuestLinearVa < g_Shv.WriteTrapVaBase ||
         GuestLinearVa >= g_Shv.WriteTrapVaEnd)) {
        InterlockedIncrement(&g_Shv.WriteTrapFilteredVa);
        shouldLog = FALSE;
    }

    if (shouldLog &&
        g_Shv.WriteTrapRipFilter != 0 &&
        GuestRip != g_Shv.WriteTrapRipFilter) {
        InterlockedIncrement(&g_Shv.WriteTrapFilteredRip);
        shouldLog = FALSE;
    }

    if (shouldLog && g_Shv.WriteTrapLog != NULL) {
        LONG total = InterlockedIncrement(&g_Shv.WriteTrapLogTotal);
        LONG slotRaw = InterlockedIncrement(&g_Shv.WriteTrapLogIndex) - 1;
        LONG slot = slotRaw % WRITE_TRAP_LOG_MAX;
        if (slot < 0) slot += WRITE_TRAP_LOG_MAX;

        PWRITE_TRAP_LOG_ENTRY entry = &g_Shv.WriteTrapLog[slot];
        entry->WriterRip         = GuestRip;
        entry->FaultVa           = GuestLinearVa;
        entry->GuestCr3          = GuestCr3;
        /* v1: register snapshot + payload capture deferred. We have the
         * writer RIP which is already enough to identify the instruction
         * and attribute it to a target function via the cipher-caller map. */
        entry->WriterRsp         = 0;
        entry->Rax               = 0;
        entry->Rcx               = 0;
        entry->Rdx               = 0;
        entry->Rsi               = 0;
        entry->Rdi               = 0;
        entry->Tsc               = __rdtsc();
        entry->ExitQualification = (ULONG32)ExitQualification;
        entry->CpuIndex          = CpuIndex;
        entry->Counter           = (ULONG32)total;
        entry->PayloadLen        = 0;
        RtlZeroMemory(entry->Payload, sizeof(entry->Payload));

        InterlockedIncrement(&g_Shv.WriteTrapHits);

        /* iter#179 COW fix: write-trap → exec-trap auto-arm.
         * When WriteTrapAutoArmExecVaOffset is set, the FIRST logged hit reads
         * the 8-byte value being written to the trapped address (= GSL.dll
         * BaseAddress stored by preloader fn_0x2390 into qword_18000A060),
         * computes exec-trap target VA = written_value + offset, walks the
         * guest page tables to get the PA, and installs the exec-trap.
         * One-shot: clears WriteTrapAutoArmExecVaOffset after success. */
        ULONG64 autoArmOffset = g_Shv.WriteTrapAutoArmExecVaOffset;
        if (autoArmOffset != 0 &&
            InterlockedCompareExchange64(
                (volatile LONG64*)&g_Shv.WriteTrapAutoArmExecVaOffset,
                0, (LONG64)autoArmOffset) == (LONG64)autoArmOffset)
        {
            /* Read the 8-byte value the guest is writing (the new BaseAddress).
             * MmMapIoSpace is UNSAFE in VMX root (can block/raise IRQL).
             * Use MmGetVirtualForPhysical which is safe — maps via kernel's
             * direct physical mapping (always present, no allocation). */
            ULONG64 writtenVal = 0;
            {
                PHYSICAL_ADDRESS pa_phys;
                pa_phys.QuadPart = (LONG64)(GuestPa & ~0xFFFULL);
                PVOID pageVa = MmGetVirtualForPhysical(pa_phys);
                if (pageVa) {
                    ULONG pageOff = (ULONG)(GuestPa & 0xFFFULL);
                    if (pageOff + 8 <= PAGE_SIZE)
                        writtenVal = *(volatile ULONG64*)((ULONG_PTR)pageVa + pageOff);
                    /* No unmap needed — MmGetVirtualForPhysical uses direct mapping */
                }
            }

            if (writtenVal > 0x100000ULL && writtenVal < 0x0001000000000000ULL) {
                ULONG64 targetVa = writtenVal + autoArmOffset;
                ULONG64 cr3 = g_Shv.WriteTrapAutoArmExecCr3 ?
                              g_Shv.WriteTrapAutoArmExecCr3 : GuestCr3;
                ULONG64 targetPa = 0;
                if (ShvTranslateGuestVa(cr3, targetVa, &targetPa) && targetPa) {
                    NTSTATUS st = ShvEptInstallExecTrap(
                        cr3,
                        targetPa,
                        targetVa,
                        targetVa + PAGE_SIZE,
                        0    /* ripFilter — match any RIP on that page */
                    );
                    SHV_LOG("WriteTrap AutoArm: written=0x%llX offset=0x%llX "
                            "targetVa=0x%llX targetPa=0x%llX st=0x%lX",
                            writtenVal, autoArmOffset, targetVa, targetPa, st);
                } else {
                    SHV_LOG("WriteTrap AutoArm: ShvTranslateGuestVa FAILED "
                            "written=0x%llX targetVa=0x%llX cr3=0x%llX",
                            writtenVal, targetVa, cr3);
                    /* Restore offset so it retries on the next hit */
                    InterlockedExchange64(
                        (volatile LONG64*)&g_Shv.WriteTrapAutoArmExecVaOffset,
                        (LONG64)autoArmOffset);
                }
            } else {
                SHV_LOG("WriteTrap AutoArm: written value 0x%llX out of range, skip",
                        writtenVal);
            }
        }
    }

    /* Re-arm path: restore W=1 temporarily so the retrying guest
     * instruction succeeds. MTF single-step then re-removes W=0.
     * Spec §1.6: no INVEPT on the local CPU — the EPT violation already
     * flushed this GPA's TLB entry. Cross-CPU is handled by the
     * InveptGeneration bump at install + next-exit sync. */
    {
        ULONG64 pageAlignedPa = g_Shv.WriteTrapTargetPa & ~0xFFFULL;
        ULONG64 pa2mbBase = pageAlignedPa & ~(EPT_LARGE_PAGE_SIZE - 1ULL);
        ULONG   ptIdx     = EPT_PTE_INDEX(pageAlignedPa);

        for (ULONG i = 0; i < g_HookRes.PriCount; i++) {
            if (g_HookRes.PriBase[i] == pa2mbBase) {
                g_HookRes.PriPt[i][ptIdx].Write = 1;
                break;
            }
        }
    }

    /* Enable MTF for single-step. */
    {
        SIZE_T procBased = 0;
        __vmx_vmread(VMCS_CTRL_PROC_BASED_EXEC, &procBased);
        procBased |= CPU_BASED_MONITOR_TRAP_FLAG;
        __vmx_vmwrite(VMCS_CTRL_PROC_BASED_EXEC, procBased);
    }

    Vcpu->MtfWriteTrapRearmPending = TRUE;
    /* v1: sentinel value — no payload backfill at MTF exit. */
    Vcpu->MtfWriteTrapHookIndex = WRITE_TRAP_HOOK_INDEX_SENTINEL;

    return 1;  /* consumed — caller must NOT advance RIP and NOT inject #GP */
}

/**
 * @brief Re-remove W bit after MTF single-step. Called from MTF handler.
 *
 * Paired with the temporary W=1 restore in ShvEptWriteTrapTryHandle.
 * INVEPT single-context on primary EPTP to ensure the next write on
 * this CPU faults (cache from the W=1 window is still live otherwise).
 */
void ShvEptWriteTrapRearm(void)
{
    if (!g_Shv.WriteTrapActive) return;

    ULONG64 pageAlignedPa = g_Shv.WriteTrapTargetPa & ~0xFFFULL;
    ULONG64 pa2mbBase = pageAlignedPa & ~(EPT_LARGE_PAGE_SIZE - 1ULL);
    ULONG   ptIdx     = EPT_PTE_INDEX(pageAlignedPa);

    for (ULONG i = 0; i < g_HookRes.PriCount; i++) {
        if (g_HookRes.PriBase[i] == pa2mbBase) {
            g_HookRes.PriPt[i][ptIdx].Write = 0;
            break;
        }
    }

    if (g_EptState != NULL) {
        ULONG64 eptp = g_EptState->EptPointer.Value;
        if (eptp != 0) {
            INVEPT_DESCRIPTOR desc;
            desc.EptPointer = eptp;
            desc.Reserved = 0;
            ShvInvept(INVEPT_SINGLE_CONTEXT, &desc);
        }
    }
}

/* ===== UM EPT Read-Trap (Phase C-R, Apr 2026) =================================
 * Parallel to write-trap v1.2 above. Key difference: R,W,X must be cleared
 * together via a single-qword Value store (transient R=0,W=1 is reserved →
 * EPT-misconfig BugCheck under SMP). See plan §F5.
 * ---------------------------------------------------------------------------*/

/* VMX-root guest-memory read support.
 *
 * At init we allocate a 4KB scratch page and cache a pointer to its host PTE.
 * In VMX root we override that PTE's PFN to map an arbitrary guest PA, read
 * 8 bytes, then restore. This gives ShvReadGuestQwordVa a safe read path for
 * ANY guest VA (including user-mode pages that MmGetVirtualForPhysical would
 * refuse). Used to capture [RSP] (return address) in read-trap log payloads. */

DECLSPEC_ALIGN(PAGE_SIZE) static UCHAR g_GuestReadScratchBuf[PAGE_SIZE];

static PVOID    g_GuestReadScratchVa   = NULL;
static ULONG64* g_GuestReadScratchPte  = NULL;  /* 4KB PTE OR 2MB PDE for scratch VA */
static ULONG64  g_GuestReadScratchOrig = 0;     /* Original PTE/PDE value for restore */
static ULONG_PTR g_PhysDirectMapBase  = 0;      /* DirectMap base: pool_va - pool_pa */
static ULONG_PTR g_PteBase            = 0;      /* Self-ref PML4: PTE for VA v at g_PteBase + (v>>9) */

/* Standard x86-64 host PTE masks (NOT EPT PTE — Intel SDM 4.5.4). */
#define HPTE_PRESENT     (1ULL << 0)
#define HPTE_RW          (1ULL << 1)
#define HPTE_LARGE       (1ULL << 7)
#define HPTE_NX          (1ULL << 63)
#define HPTE_PFN_MASK    0x000FFFFFFFFFF000ULL  /* bits [51:12] */

/* ── VMX-root physical-read window  ──────────────────────────────
 *
 * WHY THIS EXISTS.  measured (HW run #8): ShvEptReadPhysQwordSafe
 * called MmMapIoSpaceEx from VMX root and every read returned 0 — including the
 * PML4 read off a known-good GuestCr3, with a valid user-mode stack VA.  That is
 * expected in hindsight: MmMapIoSpaceEx is an IRQL<=APC_LEVEL API that allocates
 * system PTEs and takes locks.  In VMX root we are outside the OS entirely, with
 * interrupts off and no scheduler — it returns NULL (or worse).  The whole
 * live-guest-CR3 walk was therefore dead on arrival, which is why every capture
 * logged `WALK FAILED ... livePa=0x0`.
 *
 * THE FIX (standard hypervisor technique).  Do all the API work ONCE at
 * PASSIVE_LEVEL, then use nothing but memory writes at fire time:
 *
 *   init (PASSIVE_LEVEL, APIs legal)
 *     1. ExAllocatePool2 one page  -> a page WE own, guaranteed real RAM
 *     2. MmMapIoSpaceEx(its PA)    -> a scratch VA backed by a SYSTEM PTE, which
 *                                     is always 4KB-granular (never a 2MB PDE —
 *                                     this is why we do not reuse
 *                                     g_GuestReadScratchBuf, whose PDE would
 *                                     remap 2MB of LIVE kernel data)
 *     3. walk to that VA's PTE and cache the PTE's kernel VA + original value
 *
 *   VMX root (no API calls, any IRQL, interrupts off)
 *     write PFN|P|RW|NX into the cached PTE -> __invlpg(scratchVa) -> read ->
 *     restore the original PTE -> __invlpg again.
 *
 * POSITIVE CONTROL.  A silent failure here reads as a legitimate negative result
 * and burns one of the user's capture runs (the exact pattern that cost
 * iterations #192-#197).  So ShvRootScratchSelfTest reads a magic value back
 * through the window at init and logs PASS/FAIL unambiguously.  If HVCI/VBS
 * write-protects the page tables the write fails HERE, at PASSIVE_LEVEL where
 * it is survivable, instead of in VMX root where it is not.
 *
 * CONCURRENCY.  One window shared by 24 CPUs that can all be in VMX root at
 * once, so it is guarded by a bounded-spin try-lock.  Bounded, not infinite:
 * a deadlock in VMX root with interrupts off is an unrecoverable hang, whereas
 * failing the read just retries on the next anchor fire.
 *
 * NOT DirectMapBase.  This shares nothing with the #113/#113b/#113d
 * `g_PhysDirectMapBase + Pa` premise that BSOD'd twice (see
 * ShvReadGuestPhysQword).  There we dereferenced a VA we merely ASSUMED mapped
 * the target; here we CREATE the mapping ourselves and control every bit of it.
 */
static PVOID           g_RootScratchPoolVa = NULL;  /* backing page (freed on unload) */
static PMDL            g_RootScratchMdl    = NULL;  /* MDL describing that page */
static PVOID           g_RootScratchVa     = NULL;  /* system-PTE window VA */
static volatile ULONG64* g_RootScratchPte  = NULL;  /* 4KB PTE controlling that VA */
static ULONG64         g_RootScratchOrig   = 0;     /* original PTE value, restored after each read */
static volatile LONG   g_RootScratchLock   = 0;     /* 0=free 1=held */
static BOOLEAN         g_RootScratchOk     = FALSE; /* TRUE only after the self-test PASSES */

/* ShvFindHostPteOrPdeForVa (2MB-capable resolver) DELETED.
 * Its only caller accepted a 2MB PDE as the guest-read scratch entry, which
 * would have meant repointing 512 pages of live kernel memory machine-wide.
 * Nothing ever performed that remap, and nothing should: the 4KB-strict
 * ShvFindHostPteForVa below is the only resolver now, so a large-page
 * mapping fails closed instead of tempting someone into the PDE path. */

/* At PASSIVE_LEVEL only: resolve the host PTE pointer for a kernel VA via
 * 4-level walk of the current host CR3, reading each level through
 * MmGetVirtualForPhysical (safe because page-table pages are always
 * kernel-mapped at PASSIVE_LEVEL). Returns a pointer to the L1 PTE entry
 * that maps Va, or NULL on failure. */
static PULONG64
ShvFindHostPteForVa(_In_ ULONG64 Va)
{
    ULONG64 cr3 = __readcr3() & HPTE_PFN_MASK;

    PHYSICAL_ADDRESS phys;
    phys.QuadPart = (LONGLONG)cr3;
    ULONG64* pml4 = (ULONG64*)MmGetVirtualForPhysical(phys);
    if (!pml4) return NULL;
    ULONG64 pml4e = pml4[(Va >> 39) & 0x1FF];
    if (!(pml4e & HPTE_PRESENT)) return NULL;

    phys.QuadPart = (LONGLONG)(pml4e & HPTE_PFN_MASK);
    ULONG64* pdpt = (ULONG64*)MmGetVirtualForPhysical(phys);
    if (!pdpt) return NULL;
    ULONG64 pdpte = pdpt[(Va >> 30) & 0x1FF];
    if (!(pdpte & HPTE_PRESENT)) return NULL;
    if (pdpte & HPTE_LARGE) return NULL;  /* 1GB page — no PTE */

    phys.QuadPart = (LONGLONG)(pdpte & HPTE_PFN_MASK);
    ULONG64* pd = (ULONG64*)MmGetVirtualForPhysical(phys);
    if (!pd) return NULL;
    ULONG64 pde = pd[(Va >> 21) & 0x1FF];
    if (!(pde & HPTE_PRESENT)) return NULL;
    if (pde & HPTE_LARGE) return NULL;    /* 2MB page — no PTE */

    phys.QuadPart = (LONGLONG)(pde & HPTE_PFN_MASK);
    ULONG64* pt = (ULONG64*)MmGetVirtualForPhysical(phys);
    if (!pt) return NULL;

    return &pt[(Va >> 12) & 0x1FF];
}

/* VMX-root safe: read 8 bytes from a guest physical address via the scratch
 * PTE override window. Returns FALSE if scratch infrastructure is not ready.
 * Assumes caller owns the scratch window (no concurrency — VMX root is
 * per-CPU and read-trap captures are one-shot per hit).
 *
 * HISTORY (#113/#113b/#113d — DirectMapBase-offset reads are UNSOUND, do
 * not re-attempt without a fundamentally different design):
 * - #113 dereferenced `g_PhysDirectMapBase + Pa` unconditionally. BSOD'd
 *   immediately (DRIVER_IRQL_NOT_LESS_OR_EQUAL) on a Pa with no mapping.
 * - #113b reverted to this FALSE stub, reasoning the fix was "validate Pa
 *   is backed by real RAM first" (MmGetPhysicalMemoryRanges).
 * - #113c implemented that validation (ShvPaIsBackedByRam). It BSOD'd
 *   again on the VERY NEXT reload — minidump disassembly proved the crash
 *   was inside the *validated* path: the range check PASSED (jumped past
 *   the "return FALSE" epilogue straight to the deref) and it still
 *   faulted. CONCLUSION: `g_PhysDirectMapBase = pool_va - pool_pa` (one
 *   linear offset sampled from a single nonpaged-pool allocation) does
 *   NOT generalize to `real_va = g_PhysDirectMapBase + any_valid_Pa`
 *   across the whole system — Windows' physical-memory direct map is not
 *   guaranteed to be one uniform linear window; the offset that's correct
 *   for the sampled pool page is not proven correct for an arbitrary PA
 *   elsewhere, even when that PA is confirmed to be real installed RAM.
 *   Two independent BSODs from two different mitigation attempts on the
 *   same premise = the premise itself (single global linear DirectMapBase
 *   offset) is wrong, not just missing a guard. DO NOT retry this
 *   approach. If a kernel-side read is still wanted, it needs a
 *   genuinely different mechanism (e.g. actually wiring up the scratch-
 *   PTE-override window this function's name/comment always described —
 *   g_GuestReadScratchVa/Pte/Orig/Is2mb are already prepared by
 *   ShvEptPrepareReadTrapResources but never used here) — validate that
 *   design thoroughly (not on the user's daily-driver machine) before any
 *   live retry. Capture fallback: Python reads [cap_src] via
 *   ReadProcessMemory post-fire (works today; the remaining problem is
 *   timing — the short-lived launcher can exit before Python polls). */
static BOOLEAN
ShvReadGuestPhysQword(_In_ ULONG64 Pa, _Out_ PULONG64 OutQword)
{
    ULONG64 pageOff = Pa & 0xFFFULL;
    if (pageOff + 8 > PAGE_SIZE) return FALSE;  /* qword straddles page — skip */

    (void)Pa;
    return FALSE;
}

/* VMX-root: read one QWORD from a guest user-space virtual address using the
 * kernel's self-referencing PML4 (g_PteBase) + direct physical map.
 *
 * WHY: On VBS/HVCI, page table pages live at Secure-Kernel-managed PAs above
 * normal RAM, so ShvReadGuestPhysQword / ShvTranslateGuestVa cannot reach them
 * via DirectMapBase. But the KERNEL VIRTUAL ADDRESSES for those same PTEs (the
 * self-ref range, e.g. ~0xFFFFED8000000000) ARE mapped in the host CR3 that is
 * active in VMX root. So reading the PTE at 'g_PteBase + (Va>>9)' is just a
 * kernel VA load — no physical address needed. Once we have the data page's PA
 * (which IS within normal RAM), DirectMapBase + PA reads the payload.
 *
 * g_PteBase is discovered at PASSIVE_LEVEL by scanning all 256 kernel-half
 * self-ref PML4 candidates and verifying against a known VA/PA pair. */
static BOOLEAN
ShvReadGuestVaDirect(_In_ ULONG64 Va, _Out_ PULONG64 OutQword)
{
    if (g_PteBase == 0 || g_PhysDirectMapBase == 0) return FALSE;

    /* Read the 4KB PTE for Va via the self-ref PTE_BASE virtual address.
     * Sanity: pte_va must be in [0xFFFF800000000000, 0xFFFFFF80FFFFFFFF].
     * For any user Va (<2^47) and valid PTE_BASE (k in [256..511]), this always
     * holds.  If g_PteBase is wrong the result overflows or lands outside this
     * range → return FALSE instead of BSODing in VMX root. */
    ULONG64 pte_va = (ULONG64)g_PteBase + (Va >> 9);   /* PTE/PDE slot for Va */
    if (pte_va < 0xFFFF800000000000ULL || pte_va > 0xFFFFFF80FFFFFFFFULL) return FALSE;
    ULONG64 pte    = *(volatile ULONG64*)pte_va;
    if (!(pte & HPTE_PRESENT)) return FALSE;

    /* On Windows, PTE_BASE + (Va>>9) returns the PTE for 4KB pages, OR the PDE
     * (with LARGE bit set) for 2MB large pages.  Handle both cases. */
    ULONG64 page_pa;
    if (pte & HPTE_LARGE) {
        /* 2MB large page PDE: frame = bits[51:21]; Va bits[20:12] select 4KB page */
        page_pa = (pte & 0x000FFFFFFFE00000ULL) | (Va & 0x001FF000ULL);
    } else {
        page_pa = pte & HPTE_PFN_MASK;
    }
    /* Guard: PA=0 (garbage PTE with PFN=0 or PTE walk hit wrong memory) would
     * map to g_PhysDirectMapBase+0 which can be a paged VA → 0xD1 BSOD at
     * HIGH IRQL.  Physical address 0 is BIOS/firmware reserved, never a valid
     * user-mode data page.  Also guard against suspiciously small PAs. */
    if (page_pa < 0x1000) return FALSE;
    ULONG64 pageOff = Va & 0xFFFULL;
    if (pageOff + 8 > PAGE_SIZE) return FALSE;   /* straddles page */

    *OutQword = *(volatile ULONG64*)((ULONG_PTR)g_PhysDirectMapBase + page_pa + pageOff);
    return TRUE;
}

/* VMX-root safe: 4-level walk of a guest's page tables (given guest CR3) to
 * translate a guest VA into a guest PA. Returns FALSE on any not-present or
 * large-page boundary we don't handle. */
BOOLEAN
ShvTranslateGuestVa(_In_ ULONG64 GuestCr3, _In_ ULONG64 Va, _Out_ PULONG64 OutPa)
{
    ULONG64 pml4Pa = GuestCr3 & HPTE_PFN_MASK;
    ULONG64 pml4e = 0;
    if (!ShvReadGuestPhysQword(pml4Pa + ((Va >> 39) & 0x1FF) * 8, &pml4e)) return FALSE;
    if (!(pml4e & HPTE_PRESENT)) return FALSE;

    ULONG64 pdptPa = pml4e & HPTE_PFN_MASK;
    ULONG64 pdpte = 0;
    if (!ShvReadGuestPhysQword(pdptPa + ((Va >> 30) & 0x1FF) * 8, &pdpte)) return FALSE;
    if (!(pdpte & HPTE_PRESENT)) return FALSE;
    if (pdpte & HPTE_LARGE) {
        *OutPa = (pdpte & 0x000FFFFFC0000000ULL) | (Va & 0x3FFFFFFFULL);
        return TRUE;
    }

    ULONG64 pdPa = pdpte & HPTE_PFN_MASK;
    ULONG64 pde = 0;
    if (!ShvReadGuestPhysQword(pdPa + ((Va >> 21) & 0x1FF) * 8, &pde)) return FALSE;
    if (!(pde & HPTE_PRESENT)) return FALSE;
    if (pde & HPTE_LARGE) {
        *OutPa = (pde & 0x000FFFFFFFE00000ULL) | (Va & 0x1FFFFFULL);
        return TRUE;
    }

    ULONG64 ptPa = pde & HPTE_PFN_MASK;
    ULONG64 pte = 0;
    if (!ShvReadGuestPhysQword(ptPa + ((Va >> 12) & 0x1FF) * 8, &pte)) return FALSE;
    if (!(pte & HPTE_PRESENT)) return FALSE;

    *OutPa = (pte & HPTE_PFN_MASK) | (Va & 0xFFFULL);
    return TRUE;
}

/* ── LIVE guest VA→PA translation, COW-correct  ──────────────────
 *
 * WHY THIS EXISTS.  Every other translation path on this box is dead or wrong:
 *   - ShvTranslateGuestVa (above) is correct in logic but calls
 *     ShvReadGuestPhysQword, which reads through g_PhysDirectMapBase — DISABLED
 *     here (2 D1 BSODs).  Dead.
 *   - The PTE_BASE self-map path needs g_PteBase, which is permanently 0 on this
 *     HW (all discovery methods BSOD'd), so the iter#186 CR3-swap "fix" lived
 *     inside `if (g_PteBase != 0)` and was unreachable dead code.
 *   - Python-side PA pre-resolution (ExecTrapChainTargetPa / ...Stage3Pa) maps
 *     the DLL in ANOTHER process and assumes SEC_IMAGE ViewShare gives the same
 *     physical frames.  That holds ONLY for pages never written.  MEASURED
 *     every gsl.dll capture target page IS written at runtime
 *     (relocations + self-decryption) — e.g. the reporter page 0x373000 differs
 *     in 1548/4096 bytes, disk `90 90 90...` vs runtime `ff 50 68`.  Written
 *     pages are COPY-ON-WRITE SPLIT, so the game executes a PRIVATE frame at a
 *     DIFFERENT PA.  A trap armed on the pre-resolved (pristine) PA therefore
 *     watches a page nobody executes => hits=0, which was misread for ~6
 *     iterations (#192-#197) as "the function is never called".
 *
 * THE FIX.  Walk the TARGET PROCESS's own page tables from the live GuestCr3 at
 * fire time.  That yields whatever frame the process actually has mapped right
 * now — the COW private copy if one exists — so COW becomes irrelevant.
 *
 * Physical reads go through MmMapIoSpaceEx (the same primitive
 * ShvEptReadPhysicalPage / the fork-capture walk already use in VMX root), NOT
 * DirectMapBase and NOT the PTE self-map.  Unlike ShvEptReadPhysicalPage this
 * copies only the 8 bytes needed instead of a full 4 KB page per level, which
 * keeps VMX-root time down and needs NO scratch buffer — so there is no shared
 * state, no multi-CPU scratch race, and no change to the pinned g_Shv layout.
 */
/* Reason codes so a failure is never silent — see g_RootScratch* banner. */
#define SHV_ROOTRD_OK          0
#define SHV_ROOTRD_NOTREADY    1   /* window never initialised / self-test failed */
#define SHV_ROOTRD_BADPA       2   /* PA rejected by range/straddle guards */
#define SHV_ROOTRD_BUSY        3   /* another CPU holds the window */

/* VMX-ROOT SAFE.  Read one qword from a physical address through the scratch
 * PTE window.  No API calls, no allocations, safe at any IRQL.
 * OutReason (optional) receives one of SHV_ROOTRD_* so callers can log WHY. */
static BOOLEAN
ShvRootReadPhysQword(_In_ ULONG64 PhysAddr, _Out_ PULONG64 Out, _Out_opt_ PULONG OutReason)
{
    if (OutReason) *OutReason = SHV_ROOTRD_NOTREADY;
    if (Out == NULL) return FALSE;
    *Out = 0;

    if (!g_RootScratchOk || g_RootScratchPte == NULL || g_RootScratchVa == NULL)
        return FALSE;

    /* PA 0 is firmware-reserved and never a valid page-table frame; >48-bit is
     * garbage from a bad walk.  Reject straddling reads rather than stitching
     * two pages — every caller here reads 8-byte-aligned table entries. */
    if (PhysAddr < 0x1000 || (PhysAddr >> 48) != 0 ||
        (PhysAddr & 0xFFFULL) + sizeof(ULONG64) > PAGE_SIZE) {
        if (OutReason) *OutReason = SHV_ROOTRD_BADPA;
        return FALSE;
    }

    /* Bounded spin: never block forever in VMX root with interrupts off. */
    LONG spins = 0;
    while (InterlockedCompareExchange(&g_RootScratchLock, 1, 0) != 0) {
        if (++spins > 65536) {
            if (OutReason) *OutReason = SHV_ROOTRD_BUSY;
            return FALSE;
        }
        _mm_pause();
    }

    *g_RootScratchPte = (PhysAddr & HPTE_PFN_MASK) | HPTE_PRESENT | HPTE_RW | HPTE_NX;
    __invlpg(g_RootScratchVa);

    *Out = *(volatile ULONG64*)((PUCHAR)g_RootScratchVa + (PhysAddr & 0xFFFULL));

    *g_RootScratchPte = g_RootScratchOrig;
    __invlpg(g_RootScratchVa);

    InterlockedExchange(&g_RootScratchLock, 0);
    if (OutReason) *OutReason = SHV_ROOTRD_OK;
    return TRUE;
}

/* PASSIVE_LEVEL ONLY.  Build the window and PROVE it works before any capture
 * run depends on it.  Idempotent. */
/* ── KILL SWITCH  ────────────────────────────────────────────────
 * The host hard-froze on driver load THREE times: twice with the original
 * MmMapIoSpaceEx window, and ONCE MORE after switching to the supported
 * MDL / MmMapLockedPagesSpecifyCache mapping.  So the cache-attribute aliasing
 * theory was wrong, or at least not the whole cause, and I am not going to
 * guess a third time on the user's daily driver.
 *
 * Default OFF.  With this OFF, DriverEntry does NOT allocate the window, does
 * NOT walk to a PTE and does NOT write one — the entire block of code I added
 * this session is inert, so loading the driver exercises only long-standing
 * code paths.  That makes this both the safety fix and a clean bisect:
 *   loads OK  -> the freeze IS in this window; re-enable piecewise to find it
 *   still freezes -> the freeze is NOT mine, and the search moves elsewhere
 *
 * Consequence while OFF: ShvEptReadPhysQwordSafe has no VMX-root path, so the
 * live guest-CR3 walk fails CLOSED and says so (fail=N scratchOk=0). AutoArm
 * capture still resolves its stage-2 PA at PASSIVE_LEVEL via
 * MmGetPhysicalAddress, so that path is unaffected; only the stage-3 live walk
 * degrades. */
static BOOLEAN g_RootScratchEnabled = FALSE;

static NTSTATUS
ShvRootScratchInit(void)
{
    if (!g_RootScratchEnabled) {
        SHV_LOG("RootScratch: DISABLED by kill switch (host froze on load 3x) -- "
                "VMX-root phys reads OFF; live walk will fail closed (scratchOk=0)");
        return STATUS_SUCCESS;
    }
    if (g_RootScratchOk) return STATUS_SUCCESS;

    if (g_RootScratchPoolVa == NULL) {
        g_RootScratchPoolVa = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'rcsR');
        if (g_RootScratchPoolVa == NULL) {
            SHV_ERR("RootScratch: backing page alloc FAILED — VMX-root phys reads DISABLED");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    PHYSICAL_ADDRESS backingPa = MmGetPhysicalAddress(g_RootScratchPoolVa);
    if (backingPa.QuadPart == 0) {
        SHV_ERR("RootScratch: MmGetPhysicalAddress(backing)=0 — DISABLED");
        return STATUS_UNSUCCESSFUL;
    }

    /* Second mapping of a page WE OWN, via an MDL.
     *
     * !! DO NOT USE MmMapIoSpaceEx HERE ( — this HARD-FROZE the host
     * twice, seconds after driver load, with nothing armed).  MmMapIoSpace* is
     * for DEVICE physical memory; using it on RAM the OS manages (a pool page)
     * creates an alias whose cache attributes can conflict with the direct map's
     * WB mapping.  Cache-attribute aliasing is architecturally undefined on
     * Intel and hangs the box rather than bugchecking — no dump, exactly the
     * observed symptom.  It also went unnoticed for a long time because the
     * pre-existing MmMapIoSpaceEx call only ever ran in VMX root, where it
     * returns NULL and maps nothing; this was the first call at PASSIVE_LEVEL
     * where it actually SUCCEEDS, and it left a permanent alias on every load.
     *
     * MmMapLockedPagesSpecifyCache(MmCached) is the supported way: it is backed
     * by SYSTEM PTEs (so always 4KB-granular, never a 2MB PDE over live kernel
     * data) and MmCached matches the direct map's WB attribute, so there is no
     * aliasing conflict. */
    if (g_RootScratchVa == NULL) {
        if (g_RootScratchMdl == NULL) {
            g_RootScratchMdl = IoAllocateMdl(g_RootScratchPoolVa, PAGE_SIZE,
                                             FALSE, FALSE, NULL);
            if (g_RootScratchMdl == NULL) {
                SHV_ERR("RootScratch: IoAllocateMdl FAILED — DISABLED");
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            MmBuildMdlForNonPagedPool(g_RootScratchMdl);
        }
        g_RootScratchVa = MmMapLockedPagesSpecifyCache(
            g_RootScratchMdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
        if (g_RootScratchVa == NULL) {
            SHV_ERR("RootScratch: MmMapLockedPagesSpecifyCache FAILED — DISABLED");
            return STATUS_UNSUCCESSFUL;
        }
    }

    /* Strict 4KB lookup: if this returns NULL the mapping is not what we
     * assumed and we must NOT proceed (a 2MB PDE here would be catastrophic). */
    PULONG64 pte = ShvFindHostPteForVa((ULONG64)g_RootScratchVa);
    if (pte == NULL) {
        SHV_ERR("RootScratch: no 4KB PTE for scratch VA %p — DISABLED (refusing 2MB PDE)",
                g_RootScratchVa);
        return STATUS_UNSUCCESSFUL;
    }
    /* Cross-check BEFORE we ever write it: the PTE we found must actually map
     * our backing page.  If the walk returned some other entry, writing it would
     * corrupt a live mapping -- and the damage would surface later, far from the
     * cause.  Cheaper and stricter than trusting the magic read-back alone. */
    if (((*pte) & HPTE_PFN_MASK) != ((ULONG64)backingPa.QuadPart & HPTE_PFN_MASK)) {
        SHV_ERR("RootScratch: PTE %p maps PFN 0x%llX but backing PA is 0x%llX — "
                "walk is WRONG, refusing to touch it; DISABLED",
                pte, (*pte) & HPTE_PFN_MASK,
                (ULONG64)backingPa.QuadPart & HPTE_PFN_MASK);
        return STATUS_UNSUCCESSFUL;
    }

    g_RootScratchPte  = (volatile ULONG64*)pte;
    g_RootScratchOrig = *pte;

    /* ── POSITIVE CONTROL ────────────────────────────────────────────────
     * Write a magic pattern into a probe page, then read it back BY PHYSICAL
     * ADDRESS through the window.  If HVCI/VBS write-protects kernel page
     * tables, or the PTE we found does not actually control this VA, it fails
     * HERE at PASSIVE_LEVEL instead of silently returning zeros in VMX root. */
    NTSTATUS st = STATUS_UNSUCCESSFUL;
    PVOID probe = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'bprR');
    if (probe == NULL) {
        SHV_ERR("RootScratch: probe alloc failed — cannot self-test, DISABLED");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    const ULONG64 MAGIC = 0x5348565343520001ULL;   /* "SHVSCR" + 1 */
    *(volatile ULONG64*)probe = MAGIC;
    PHYSICAL_ADDRESS probePa = MmGetPhysicalAddress(probe);

    if (probePa.QuadPart == 0) {
        SHV_ERR("RootScratch: MmGetPhysicalAddress(probe)=0 — self-test SKIPPED, DISABLED");
    } else {
        /* Temporarily allow the read so the primitive can be exercised. */
        g_RootScratchOk = TRUE;
        ULONG64 got = 0;
        ULONG   why = SHV_ROOTRD_NOTREADY;
        BOOLEAN ok  = ShvRootReadPhysQword((ULONG64)probePa.QuadPart, &got, &why);
        g_RootScratchOk = FALSE;

        if (ok && got == MAGIC) {
            g_RootScratchOk = TRUE;
            st = STATUS_SUCCESS;
            SHV_LOG("RootScratch: SELF-TEST PASS — VMX-root phys reads LIVE "
                    "(va=%p pte=%p orig=0x%llX probePa=0x%llX)",
                    g_RootScratchVa, (PVOID)g_RootScratchPte,
                    g_RootScratchOrig, (ULONG64)probePa.QuadPart);
        } else {
            SHV_ERR("RootScratch: SELF-TEST FAIL — ok=%d reason=%lu got=0x%llX want=0x%llX "
                    "(probePa=0x%llX) => VMX-root phys reads DISABLED; the live guest-CR3 "
                    "walk will fail CLOSED and say so",
                    (int)ok, why, got, MAGIC, (ULONG64)probePa.QuadPart);
        }
    }

    ExFreePool(probe);
    return st;
}

/* Tear the window down on unload: restore the PTE we may have altered, drop the
 * system-PTE mapping, free the MDL and the backing page.  Leaking a system PTE
 * mapping across driver reloads is exactly how a machine ends up unstable after
 * several load/unload cycles. */
VOID
ShvRootScratchTeardown(void)
{
    /* Nothing was ever allocated while the kill switch is off. */
    if (!g_RootScratchEnabled && g_RootScratchPoolVa == NULL) return;
    g_RootScratchOk = FALSE;
    if (g_RootScratchPte != NULL) {
        *g_RootScratchPte = g_RootScratchOrig;
        if (g_RootScratchVa) __invlpg(g_RootScratchVa);
        g_RootScratchPte = NULL;
    }
    if (g_RootScratchVa != NULL && g_RootScratchMdl != NULL) {
        MmUnmapLockedPages(g_RootScratchVa, g_RootScratchMdl);
        g_RootScratchVa = NULL;
    }
    if (g_RootScratchMdl != NULL) {
        IoFreeMdl(g_RootScratchMdl);
        g_RootScratchMdl = NULL;
    }
    if (g_RootScratchPoolVa != NULL) {
        ExFreePool(g_RootScratchPoolVa);
        g_RootScratchPoolVa = NULL;
    }
}

/* Physical qword read used by the live guest-CR3 walk.
 *
 * this used to call MmMapIoSpaceEx directly, which CANNOT work from
 * VMX root (measured: every read returned 0, including PML4 reads off a valid
 * CR3).  It now goes through the pre-built scratch window.  MmMapIoSpaceEx is
 * still correct at PASSIVE_LEVEL, so keep it as the fallback for the callers
 * that run there. */
static BOOLEAN
ShvEptReadPhysQwordSafe(_In_ ULONG64 PhysAddr, _Out_ PULONG64 Out)
{
    if (Out == NULL) return FALSE;
    *Out = 0;
    /* PA 0 is firmware-reserved and never a valid PT frame; >48-bit is garbage. */
    if (PhysAddr < 0x1000 || (PhysAddr >> 48) != 0) return FALSE;
    if ((PhysAddr & 0xFFFULL) + sizeof(ULONG64) > PAGE_SIZE) return FALSE; /* straddles page */

    /* Primary: scratch-PTE window — the only path valid in VMX root. */
    if (g_RootScratchOk) {
        ULONG why = SHV_ROOTRD_NOTREADY;
        if (ShvRootReadPhysQword(PhysAddr, Out, &why))
            return TRUE;
        /* BUSY is transient (another CPU mid-read); the caller retries on the
         * next anchor fire.  Anything else means the window is unusable. */
        return FALSE;
    }

    /* Fallback: only sound at IRQL <= APC_LEVEL (init/self-test paths). */
    if (KeGetCurrentIrql() > APC_LEVEL) return FALSE;

    PHYSICAL_ADDRESS pa;
    pa.QuadPart = (LONGLONG)(PhysAddr & ~0xFFFULL);

    PVOID mapped = MmMapIoSpaceEx(pa, PAGE_SIZE, PAGE_READWRITE);
    if (mapped == NULL) return FALSE;

    BOOLEAN ok = FALSE;
    __try {
        *Out = *(volatile ULONG64*)((PUCHAR)mapped + (PhysAddr & 0xFFFULL));
        ok = TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = FALSE;
    }
    MmUnmapIoSpace(mapped, PAGE_SIZE);
    return ok;
}

/* 4-level walk (PML4→PDPT→PD→PT) of the guest's OWN page tables using the live
 * GuestCr3.  Handles 1 GB and 2 MB large pages.  Returns the full PA including
 * the byte offset within the final page.  Fails closed on any not-present level. */
/* ── ExecTrapChainFired state values  ────────────────────────────
 * These MUST stay distinct: 1 is a transient mutex held only while a CPU is
 * inside stage-1, so step-2 must never key off it (see the CAS-RACE FIX v2
 * banner).  Values are private to the VMX-root handler; NexusDSEFix only
 * displays the field. */
/* ── PENDING STAGE-2 RETRY  ──────────────────────────────────────
 * MEASURED (shvlog13): the EP match for preloader_l fired correctly and stage-1
 * computed the right stage-2 VA (DllBase 0x7FFE32050000 + 0x2DB5), but the live
 * walk returned fail=8 -- the FINAL PTE was NOT PRESENT. preloader+0x2DB5's page
 * simply had not been faulted in yet at DllMain entry (it is rebased, so pages
 * carrying relocations are resident, but a page with no fixups stays untouched
 * until first execution).
 *
 * This is fundamental, not a bug: EPT traps are keyed on PHYSICAL addresses, and
 * a guest page with no frame yet has no PA to arm.
 *
 * The old code said "retry next fire" -- but the only fires that reach stage-1
 * are EP matches with reason==DLL_PROCESS_ATTACH, which happens ONCE per process.
 * So the retry never came (43 later preloader_l matches were all reason=2 and
 * were rejected by the filter before reaching the walk).
 *
 * FIX: remember the unresolved stage-2 VA + its CR3, and retry the walk on ANY
 * subsequent anchor fire in that SAME process -- every DLL init in gsl.exe
 * becomes a retry opportunity, which is far more frequent than waiting for a
 * specific reason code. Cleared as soon as the walk succeeds (or the chain is
 * re-armed). */
static volatile ULONG64 g_ChainPendingS2Va  = 0;
static volatile ULONG64 g_ChainPendingCr3   = 0;

/* The exact stage-2 pivot VA, published by stage-1 on a successful swap.
 *
 * WHY THIS EXISTS SEPARATELY FROM ExecTrapRipFilter: step-2 used to
 * key off ExecTrapRipFilter, which forced RipFilter to stay pinned to the pivot
 * and made the stage-2 page invisible except at that one instruction. MEASURED
 * (shvlog14): stage-2 armed correctly on a live PA and then NOTHING fired, and we
 * could not tell "the pivot already executed before we armed" from "the page is
 * never executed again" -- the trap was blind to every other instruction on it.
 *
 * Decoupling them lets stage-2 run with NO RIP filter (so every execution on the
 * page is logged, giving the RIPs that answer that question) while step-2 still
 * triggers ONLY at the true pivot, where RCX is the gsl image base. */
static volatile ULONG64 g_ChainStage2Va = 0;

#define CHAIN_IDLE       0    /* no chain activity */
#define CHAIN_S1_BUSY    1    /* a CPU is executing stage-1 RIGHT NOW (mutex) */
#define CHAIN_S2_ARMED   10   /* stage-1 swapped successfully; awaiting stage-2 site */
#define CHAIN_S2_DONE    11   /* step-2 has run; stage-3 armed */

/* Arm the chain directly at a known stage-2 pivot, bypassing stage-1 entirely.
 * Used by the image-load notify, which learns the module base at PASSIVE_LEVEL
 * BEFORE DllMain runs -- the only way to beat a one-shot instruction on a page
 * that faults in at that very instruction (see the AutoArm CHAIN HANDOFF note).
 * Publishing CHAIN_S2_ARMED here is safe: step-2 additionally requires
 * GuestRip == Stage2Va, so it can only fire at the real pivot. */
VOID
ShvEptChainSetStage2(_In_ ULONG64 Stage2Va)
{
    g_ChainPendingS2Va = 0;
    g_ChainPendingCr3  = 0;
    g_ChainStage2Va    = Stage2Va;
    InterlockedExchange64((volatile LONG64*)&g_Shv.ExecTrapChainFired, CHAIN_S2_ARMED);
}

VOID
ShvEptChainResetPending(void)
{
    g_ChainPendingS2Va = 0;
    g_ChainPendingCr3  = 0;
    g_ChainStage2Va    = 0;
}

/* Diagnostic breadcrumb for the LAST failed walk.  A walk that fails without
 * saying WHERE is indistinguishable from "my build isn't loaded" — that
 * ambiguity cost a full capture run.  Encoding:
 *   1..4 = read of the PML4/PDPT/PD/PT entry FAILED (physical read broken)
 *   5..8 = that level's entry was NOT PRESENT (a real, legitimate answer) */
static volatile LONG g_LastWalkFail = 0;

BOOLEAN
ShvTranslateGuestVaLive(_In_ ULONG64 GuestCr3, _In_ ULONG64 Va, _Out_ PULONG64 OutPa)
{
    if (OutPa == NULL) return FALSE;
    *OutPa = 0;
    g_LastWalkFail = 0;

    ULONG64 e = 0;

    /* PML4 — VA bits 47:39 */
    if (!ShvEptReadPhysQwordSafe((GuestCr3 & HPTE_PFN_MASK) + (((Va >> 39) & 0x1FF) * 8), &e))
        { g_LastWalkFail = 1; return FALSE; }
    if (!(e & HPTE_PRESENT)) { g_LastWalkFail = 5; return FALSE; }

    /* PDPT — VA bits 38:30 */
    if (!ShvEptReadPhysQwordSafe((e & HPTE_PFN_MASK) + (((Va >> 30) & 0x1FF) * 8), &e))
        { g_LastWalkFail = 2; return FALSE; }
    if (!(e & HPTE_PRESENT)) { g_LastWalkFail = 6; return FALSE; }
    if (e & HPTE_LARGE) {                      /* 1 GB page */
        *OutPa = (e & 0x000FFFFFC0000000ULL) | (Va & 0x3FFFFFFFULL);
        return TRUE;
    }

    /* PD — VA bits 29:21 */
    if (!ShvEptReadPhysQwordSafe((e & HPTE_PFN_MASK) + (((Va >> 21) & 0x1FF) * 8), &e))
        { g_LastWalkFail = 3; return FALSE; }
    if (!(e & HPTE_PRESENT)) { g_LastWalkFail = 7; return FALSE; }
    if (e & HPTE_LARGE) {                      /* 2 MB page */
        *OutPa = (e & 0x000FFFFFFFE00000ULL) | (Va & 0x1FFFFFULL);
        return TRUE;
    }

    /* PT — VA bits 20:12 */
    if (!ShvEptReadPhysQwordSafe((e & HPTE_PFN_MASK) + (((Va >> 12) & 0x1FF) * 8), &e))
        { g_LastWalkFail = 4; return FALSE; }
    if (!(e & HPTE_PRESENT)) { g_LastWalkFail = 8; return FALSE; }

    *OutPa = (e & HPTE_PFN_MASK) | (Va & 0xFFFULL);
    return TRUE;
}

/* VMX-root safe: translate any VA (user or kernel) → page PA using g_PteBase.
 *
 * ShvReadGuestPhysQword is disabled on VBS/HVCI (PT pages live above DirectMap),
 * so ShvTranslateGuestVa is dead. This function walks the SAME PTE_BASE self-ref
 * mapping but fixes the fatal overflow that kills ShvReadGuestVaDirect for kernel VAs:
 *
 *   OLD (overflow for kernel VAs):  pte_va = g_PteBase + (Va >> 9)
 *   NEW (48-bit mask, no overflow): pte_va = g_PteBase + ((Va & 0x0000FFFFFFFFF000) >> 9)
 *
 * For user VAs bits[63:48]=0, so the mask is a no-op. For kernel VAs bits[63:47]=1,
 * the raw `Va >> 9` gives a 55-bit number that overflows when added to g_PteBase;
 * masking to bits[47:12] keeps the offset ≤ 512 GB (one PML4 entry's PTE window).
 *
 * Returns the 4KB physical address of Va's page, or FALSE for non-present / 2MB
 * large pages (on HVCI, kernel code is always 4KB-mapped; 2MB case should not occur
 * for the LSTAR VA). */
BOOLEAN
ShvTranslateVaDirect(_In_ ULONG64 Va, _Out_ PULONG64 OutPa)
{
    if (g_PteBase == 0) return FALSE;

    /* Bits[47:12] only: prevents overflow for canonical kernel VAs (bit 47 = 1). */
    ULONG64 pte_va = (ULONG64)g_PteBase + ((Va & 0x0000FFFFFFFFF000ULL) >> 9);

    if (pte_va < 0xFFFF800000000000ULL || pte_va > 0xFFFFFFFF00000000ULL) return FALSE;

    ULONG64 pte = *(volatile ULONG64*)pte_va;
    if (!(pte & HPTE_PRESENT)) return FALSE;
    if   (pte & HPTE_LARGE) {
        SHV_WARN("ShvTranslateVaDirect: VA 0x%llX is 2MB large-page (pte=0x%llX) — unsupported", Va, pte);
        return FALSE;
    }

    ULONG64 page_pa = pte & HPTE_PFN_MASK;
    if (page_pa < 0x1000) return FALSE;

    *OutPa = page_pa | (Va & 0xFFFULL);
    return TRUE;
}

/* VMX-root safe: read 8 bytes from guest virtual memory via its CR3. */
static BOOLEAN
ShvReadGuestQwordVa(_In_ ULONG64 GuestCr3, _In_ ULONG64 Va, _Out_ PULONG64 OutQword)
{
    ULONG64 pa = 0;
    if (!ShvTranslateGuestVa(GuestCr3, Va, &pa)) return FALSE;
    return ShvReadGuestPhysQword(pa, OutQword);
}

NTSTATUS ShvEptPrepareReadTrapResources(void)
{
    if (g_Shv.ReadTrapLog != NULL) {
        return STATUS_SUCCESS;
    }

    SIZE_T bytes = (SIZE_T)READ_TRAP_LOG_MAX * sizeof(READ_TRAP_LOG_ENTRY);
    g_Shv.ReadTrapLog = (PREAD_TRAP_LOG_ENTRY)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, bytes, '0fdW');  /* mem=Wdf0 (KMDF runtime) */
    if (!g_Shv.ReadTrapLog) {
        SHV_LOG("ReadTrap: log-ring alloc failed (%llu bytes)", (ULONG64)bytes);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    InterlockedExchange(&g_Shv.ReadTrapLogIndex, 0);
    InterlockedExchange(&g_Shv.ReadTrapLogTotal, 0);
    SHV_LOG("ReadTrap: log ring allocated (%llu bytes at %p)",
            (ULONG64)bytes, g_Shv.ReadTrapLog);

    /* ── DirectMapBase (pool method) + PTE_BASE (ntoskrnl code scan) ────────
     * Pool allocation: DirectMapBase = pool_va - pool_pa.
     * PTE_BASE: scan ntoskrnl .text for the 3-instruction MiGetPteAddress pattern:
     *   (1) sar/shr reg64, 9  — within ±20 bytes
     *   (2) movabs reg, imm64 — imm has PTE_BASE shape (bits[63:47]=1FFFF,bits[38:0]=0)
     *   (3) or reg, reg       — immediately after movabs (within 3 bytes)
     * No runtime probing: SEH probes in guest context can trigger EPT violations
     * on VBS-protected page table pages → BSOD not catchable by SEH. */
    if (g_PhysDirectMapBase == 0 || g_PteBase == 0) {
        PVOID testBuf = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'pmsT');
        if (testBuf) {
            PHYSICAL_ADDRESS testPa = MmGetPhysicalAddress(testBuf);
            if (testPa.QuadPart != 0) {
                /* DirectMapBase */
                if (g_PhysDirectMapBase == 0) {
                    g_PhysDirectMapBase = (ULONG_PTR)testBuf - (ULONG_PTR)testPa.QuadPart;
                    SHV_LOG("ReadTrap: PhysDirectMapBase=0x%llX (pool va=%p pa=0x%llX)",
                            (ULONG64)g_PhysDirectMapBase, testBuf, testPa.QuadPart);
                }

                /* PTE_BASE: all discovered approaches (ntoskrnl code scan,
                 * PASSIVE_LEVEL PML4 brute-force, VMX-root VA brute-force,
                 * VMX-root physical brute-force) cause BSODs in this SHV
                 * environment.  Leave g_PteBase=0 — ShvReadGuestVaDirect stays
                 * disabled; payload reads fall back to ShvReadGuestQwordVa
                 * which ALSO returns FALSE unconditionally (#113/#113b/#113d:
                 * two independent attempts at a DirectMapBase+Pa dereference
                 * BOTH BSOD'd — DRIVER_IRQL_NOT_LESS_OR_EQUAL, confirmed via
                 * minidump each time. The single-linear-offset DirectMapBase
                 * premise itself is unsound on this system; do not retry it.
                 * See ShvReadGuestPhysQword's comment for the full history). */
                SHV_WARN("ReadTrap: PTE_BASE discovery skipped — using DirectMap fallback");
            } else {
                SHV_WARN("ReadTrap: MmGetPhysicalAddress(pool) returned 0");
            }
            ExFreePool(testBuf);
        } else {
            SHV_WARN("ReadTrap: pool alloc failed");
        }
    }

    /* ── Guest-read scratch entry (REFUSE THE 2MB CASE) ─────────
     *
     * This used to accept a 2MB PDE (ShvFindHostPteOrPdeForVa, is2mb=TRUE) on
     * the theory that ShvReadGuestPhysQword would "remap the entire 2MB PDE
     * instead of a 4KB PTE", and claimed that was "safe in VMX root
     * (single-threaded per CPU, immediate restore)".
     *
     * That claim is false and the code it described is gone:
     *
     *  - FALSE: page tables are shared MACHINE-WIDE. Repointing a 2MB PDE moves
     *    512 pages of live kernel memory for EVERY processor at once, not just
     *    the one in VMX root, and there is no cross-CPU TLB shootdown here. The
     *    chosen VA is the driver image or &g_Shv, so it would also yank the
     *    hypervisor's own globals out from under the code doing the remap.
     *
     *  - GONE: ShvReadGuestPhysQword is now a stub that returns FALSE
     *    unconditionally (the DirectMapBase premise was abandoned after two
     *    D1 BSODs), and nothing anywhere writes *g_GuestReadScratchPte.
     *    Verified by grep: zero assignments.
     *
     * So we only ever RESOLVE and cache the entry; the dangerous operation the
     * comment advertised was never actually implemented. Refusing 2MB here
     * costs nothing today and makes it impossible for a future caller to
     * resurrect it by accident. ShvRootScratchInit already refuses 2MB for the
     * same reason -- the two paths now agree.
     */
    if (g_GuestReadScratchVa == NULL) {
        /* Strict 4KB only. ShvFindHostPteForVa returns NULL for large pages. */
        PVOID scratchVa = (PVOID)g_GuestReadScratchBuf;
        PULONG64 entry = ShvFindHostPteForVa((ULONG64)scratchVa);
        if (!entry) {
            /* Fallback: the g_Shv pool VA, page-aligned. */
            scratchVa = (PVOID)((ULONG_PTR)&g_Shv & ~0xFFFULL);
            entry = ShvFindHostPteForVa((ULONG64)scratchVa);
        }
        if (entry) {
            g_GuestReadScratchVa     = scratchVa;
            g_GuestReadScratchPte    = entry;
            g_GuestReadScratchOrig   = *entry;
            SHV_LOG("ReadTrap: scratch ready 4KB (va=%p entry=%p orig=0x%llX)",
                    g_GuestReadScratchVa, entry, g_GuestReadScratchOrig);
        } else {
            SHV_LOG("ReadTrap: no 4KB PTE for scratch VA (2MB mapping?) — "
                    "payload capture disabled, REFUSING to touch a large-page PDE");
        }
    }

    /* VMX-root physical-read window + its positive control.  Must run at
     * PASSIVE_LEVEL; this function is called from DriverEntry/vmlaunch paths.
     * Failure is logged loudly and leaves the live guest-CR3 walk failing
     * CLOSED rather than silently returning zeros (measured HW run #8). */
    (void)ShvRootScratchInit();

    return STATUS_SUCCESS;
}

/* ── RIP-trace ring allocator  ─────────────────────────── */

NTSTATUS ShvEptPrepareRipTraceResources(void)
{
    if (g_Shv.RipTraceLog != NULL) {
        return STATUS_SUCCESS;
    }
    SIZE_T bytes = (SIZE_T)RIP_TRACE_LOG_MAX * sizeof(RIP_TRACE_ENTRY);
    g_Shv.RipTraceLog = (PRIP_TRACE_ENTRY)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, bytes, '0fdW');  /* mem=Wdf0 (KMDF runtime) */
    if (!g_Shv.RipTraceLog) {
        SHV_LOG("RipTrace: log-ring alloc failed (%llu bytes)", (ULONG64)bytes);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    InterlockedExchange(&g_Shv.RipTraceLogIndex, 0);
    InterlockedExchange(&g_Shv.RipTraceLogTotal, 0);
    g_Shv.RipTraceMagic = RIP_TRACE_MAGIC;
    SHV_LOG("RipTrace: log ring allocated (%llu bytes at %p), magic at &g_Shv+0x%llx",
            (ULONG64)bytes, g_Shv.RipTraceLog,
            (ULONG64)((ULONG_PTR)&g_Shv.RipTraceMagic - (ULONG_PTR)&g_Shv));
    return STATUS_SUCCESS;
}

NTSTATUS ShvEptInstallReadTrap(
    _In_ ULONG64 Cr3,
    _In_ ULONG64 TargetPa,
    _In_ ULONG64 VaBase,
    _In_ ULONG64 VaEnd,
    _In_ ULONG64 RipFilter
    )
{
    if (TargetPa < 0x100000ULL || TargetPa >= 0x0000100000000000ULL) {
        SHV_ERR("ReadTrap: install rejected -- TargetPa=0x%llX looks unresolved", TargetPa);
        return STATUS_INVALID_PARAMETER;
    }
    if (!g_HookRes.Ready) {
        SHV_ERR("ReadTrap: hook resources not prepared");
        return STATUS_UNSUCCESSFUL;
    }
    if (g_EptState == NULL) {
        SHV_ERR("ReadTrap: EPT state not initialized");
        return STATUS_UNSUCCESSFUL;
    }
    if (EPT_PML4_INDEX(TargetPa) != 0) {
        SHV_ERR("ReadTrap: TargetPa 0x%llX not in PML4[0]", TargetPa);
        return STATUS_INVALID_PARAMETER;
    }
    if (VaEnd <= VaBase) {
        SHV_ERR("ReadTrap: VaEnd <= VaBase");
        return STATUS_INVALID_PARAMETER;
    }
    if ((VaEnd - VaBase) > PAGE_SIZE) {
        SHV_ERR("ReadTrap: range > 4 KB not supported in v1");
        return STATUS_INVALID_PARAMETER;
    }
    if (g_Shv.ReadTrapActive) {
        SHV_ERR("ReadTrap: already armed -- uninstall first");
        return STATUS_ALREADY_INITIALIZED;
    }
    if (g_Shv.ReadTrapLog == NULL) {
        SHV_ERR("ReadTrap: log ring not allocated (call Prepare first)");
        return STATUS_UNSUCCESSFUL;
    }

    ULONG64 pageAlignedPa = TargetPa & ~0xFFFULL;
    ULONG64 pa2mbBase = TargetPa & ~(EPT_LARGE_PAGE_SIZE - 1ULL);
    ULONG   ptIdx     = EPT_PTE_INDEX(TargetPa);

    EPT_PTE* priPt = ShvEptPrimarySplitFor(pa2mbBase);
    if (!priPt) {
        SHV_ERR("ReadTrap: primary split failed for 0x%llX", pa2mbBase);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Snapshot the current PTE value for byte-exact uninstall restore.
     * Write-trap doesn't do this because it only flips one bit; we flip
     * three, and the memory-type / PFN / ignored bits must be preserved. */
    g_Shv.ReadTrapSavedPteValue = priPt[ptIdx].Value;

    /* Populate control fields BEFORE flipping active. */
    g_Shv.ReadTrapCr3       = Cr3;
    g_Shv.ReadTrapTargetPa  = pageAlignedPa;
    g_Shv.ReadTrapVaBase    = VaBase;
    g_Shv.ReadTrapVaEnd     = VaEnd;
    g_Shv.ReadTrapRipFilter = RipFilter;

    InterlockedExchange(&g_Shv.ReadTrapHits,             0);
    InterlockedExchange(&g_Shv.ReadTrapFilteredCr3,      0);
    InterlockedExchange(&g_Shv.ReadTrapFilteredVa,       0);
    InterlockedExchange(&g_Shv.ReadTrapFilteredRip,      0);
    InterlockedExchange(&g_Shv.ReadTrapNonReadSkipped,   0);
    InterlockedExchange(&g_Shv.ReadTrapLogIndex,         0);
    InterlockedExchange(&g_Shv.ReadTrapLogTotal,         0);

    /* CRITICAL: single-qword PTE store to avoid transient R=0,W=1 reserved
     * state. Build the new PTE value in a local, write as one qword. */
    {
        EPT_PTE newPte;
        newPte.Value = g_Shv.ReadTrapSavedPteValue;
        newPte.Read    = 0;
        newPte.Write   = 0;
        newPte.Execute = 0;
        priPt[ptIdx].Value = newPte.Value;
    }

    /* INVEPT single-context on primary EPTP. */
    {
        ULONG64 eptp = g_EptState->EptPointer.Value;
        if (eptp != 0) {
            INVEPT_DESCRIPTOR desc;
            desc.EptPointer = eptp;
            desc.Reserved = 0;
            ShvInvept(INVEPT_SINGLE_CONTEXT, &desc);
        }
    }
    InterlockedIncrement(&g_Shv.InveptGeneration);

    InterlockedExchange((volatile LONG*)&g_Shv.ReadTrapActive, 1);

    SHV_LOG("ReadTrap: armed pa=0x%llX cr3=0x%llX va=[0x%llX,0x%llX) rip=0x%llX ptIdx=%lu",
            pageAlignedPa, Cr3, VaBase, VaEnd, RipFilter, ptIdx);
    return STATUS_SUCCESS;
}

NTSTATUS ShvEptUninstallReadTrap(void)
{
    if (!g_Shv.ReadTrapActive) {
        return STATUS_SUCCESS;
    }

    InterlockedExchange((volatile LONG*)&g_Shv.ReadTrapActive, 0);

    ULONG64 pageAlignedPa = g_Shv.ReadTrapTargetPa;
    ULONG64 pa2mbBase = pageAlignedPa & ~(EPT_LARGE_PAGE_SIZE - 1ULL);
    ULONG   ptIdx     = EPT_PTE_INDEX(pageAlignedPa);

    BOOLEAN restored = FALSE;
    for (ULONG i = 0; i < g_HookRes.PriCount; i++) {
        if (g_HookRes.PriBase[i] == pa2mbBase) {
            /* Restore exact original PTE value (single qword). */
            g_HookRes.PriPt[i][ptIdx].Value = g_Shv.ReadTrapSavedPteValue;

            /* If write-trap is ALSO armed on this same page, re-apply its
             * W=0 after restoring the saved PTE. Otherwise uninstalling
             * read-trap would silently disarm write-trap too. */
            if (g_Shv.WriteTrapActive &&
                (pageAlignedPa == (g_Shv.WriteTrapTargetPa & ~0xFFFULL))) {
                g_HookRes.PriPt[i][ptIdx].Write = 0;
            }
            restored = TRUE;
            break;
        }
    }

    if (!restored) {
        SHV_LOG("ReadTrap: uninstall -- no matching split for 0x%llX", pa2mbBase);
    }

    if (g_EptState != NULL) {
        ULONG64 eptp = g_EptState->EptPointer.Value;
        if (eptp != 0) {
            INVEPT_DESCRIPTOR desc;
            desc.EptPointer = eptp;
            desc.Reserved = 0;
            ShvInvept(INVEPT_SINGLE_CONTEXT, &desc);
        }
    }
    InterlockedIncrement(&g_Shv.InveptGeneration);

    g_Shv.ReadTrapCr3           = 0;
    g_Shv.ReadTrapTargetPa      = 0;
    g_Shv.ReadTrapVaBase        = 0;
    g_Shv.ReadTrapVaEnd         = 0;
    g_Shv.ReadTrapRipFilter     = 0;
    g_Shv.ReadTrapSavedPteValue = 0;

    SHV_LOG("ReadTrap: disarmed (hits=%ld cr3-filt=%ld va-filt=%ld rip-filt=%ld non-read=%ld)",
            g_Shv.ReadTrapHits, g_Shv.ReadTrapFilteredCr3,
            g_Shv.ReadTrapFilteredVa, g_Shv.ReadTrapFilteredRip,
            g_Shv.ReadTrapNonReadSkipped);
    return STATUS_SUCCESS;
}

ULONG ShvEptReadTrapTryHandle(
    _In_ ULONG64 GuestPa,
    _In_ ULONG64 GuestLinearVa,
    _In_ ULONG64 GuestRip,
    _In_ ULONG64 GuestCr3,
    _In_ ULONG64 ExitQualification,
    _In_ ULONG   CpuIndex,
    _In_ struct _VCPU_DATA *Vcpu
    )
{
    if (!g_Shv.ReadTrapActive) return 0;
    ULONG64 pageAlignedPa = g_Shv.ReadTrapTargetPa & ~0xFFFULL;
    if ((GuestPa & ~0xFFFULL) != pageAlignedPa) return 0;

    /* Classify access type from exit qualification. Intel SDM vol 3 §28.2.1:
     *   bit 0 = data read, bit 1 = data write, bit 2 = instruction fetch.
     * Locked RMW instructions (cmpxchg etc.) set BOTH read and write. We
     * treat any write or exec as "not a pure read" and defer to write-trap
     * for writes where possible. */
    BOOLEAN isRead  = (ExitQualification & EPT_VIOLATION_DATA_READ)         != 0;
    BOOLEAN isWrite = (ExitQualification & EPT_VIOLATION_DATA_WRITE)        != 0;
    BOOLEAN isExec  = (ExitQualification & EPT_VIOLATION_INSTRUCTION_FETCH) != 0;

    if (!isRead || isWrite || isExec) {
        /* Not a pure read. If it's a write on a page where write-trap is
         * ALSO armed, defer so write-trap can log it properly. */
        if (isWrite && g_Shv.WriteTrapActive &&
            (pageAlignedPa == (g_Shv.WriteTrapTargetPa & ~0xFFFULL))) {
            return 0;   /* let write-trap handler run next */
        }

        /* Silent re-arm. Temp-restore PTE so instruction completes, MTF
         * will re-clear R/W/X after. */
        InterlockedIncrement(&g_Shv.ReadTrapNonReadSkipped);
        goto RearmAndConsume;
    }

    /* Apply filters. */
    BOOLEAN shouldLog = TRUE;

    if (g_Shv.ReadTrapCr3 != 0 && GuestCr3 != g_Shv.ReadTrapCr3) {
        LONG prevFilteredCr3 = InterlockedIncrement(&g_Shv.ReadTrapFilteredCr3) - 1;
        shouldLog = FALSE;
        /* Auto-disarm on first CR3 mismatch — same safety as write-trap v1.2.
         * The target process has exited and the PA is being reused. */
        if (prevFilteredCr3 == 0) {
            InterlockedExchange64((volatile LONG64*)&g_Shv.PendingReadTrapOp, 2);
        }
    }

    if (shouldLog &&
        (ExitQualification & EPT_VIOLATION_GLA_VALID) &&
        g_Shv.ReadTrapVaBase != 0 && g_Shv.ReadTrapVaEnd != 0 &&
        (GuestLinearVa < g_Shv.ReadTrapVaBase ||
         GuestLinearVa >= g_Shv.ReadTrapVaEnd)) {
        InterlockedIncrement(&g_Shv.ReadTrapFilteredVa);
        shouldLog = FALSE;
    }

    if (shouldLog &&
        g_Shv.ReadTrapRipFilter != 0 &&
        GuestRip != g_Shv.ReadTrapRipFilter) {
        InterlockedIncrement(&g_Shv.ReadTrapFilteredRip);
        shouldLog = FALSE;
    }

    if (shouldLog && g_Shv.ReadTrapLog != NULL) {
        LONG total = InterlockedIncrement(&g_Shv.ReadTrapLogTotal);
        LONG slotRaw = InterlockedIncrement(&g_Shv.ReadTrapLogIndex) - 1;
        LONG slot = slotRaw % READ_TRAP_LOG_MAX;
        if (slot < 0) slot += READ_TRAP_LOG_MAX;

        PREAD_TRAP_LOG_ENTRY entry = &g_Shv.ReadTrapLog[slot];
        entry->ReaderRip         = GuestRip;
        entry->FaultVa           = GuestLinearVa;
        entry->GuestCr3          = GuestCr3;
        ULONG64 grspQw = 0;
        {
            SIZE_T grsp = 0;
            __vmx_vmread(VMCS_GUEST_RSP, &grsp);
            grspQw = (ULONG64)grsp;
            entry->ReaderRsp     = grspQw;
        }
        entry->Rax               = 0;
        entry->Rcx               = 0;
        entry->Rdx               = 0;
        entry->Rsi               = 0;
        entry->Rdi               = 0;
        entry->Tsc               = __rdtsc();
        entry->ExitQualification = (ULONG32)ExitQualification;
        entry->CpuIndex          = CpuIndex;
        entry->Counter           = (ULONG32)total;

        /* Capture 8 qwords of guest stack starting at RSP (qword[0] = return
         * address of the caller that did the read; qwords[1..7] are context).
         * Requires scratch PTE window from ShvEptPrepareReadTrapResources.
         * Diagnostic sentinels written to PayloadLen high bits when capture
         * fails so the user-mode dumper can report why the payload is empty. */
        RtlZeroMemory(entry->Payload, sizeof(entry->Payload));
        entry->PayloadLen = 0;
        if (g_GuestReadScratchPte == NULL) {
            entry->PayloadLen = 0xE0000001;   /* sentinel: scratch unavailable */
        } else if (grspQw == 0) {
            entry->PayloadLen = 0xE0000002;   /* sentinel: RSP was zero */
        } else {
            for (ULONG i = 0; i < 8; i++) {
                ULONG64 q = 0;
                if (ShvReadGuestQwordVa(GuestCr3, grspQw + (ULONG64)i * 8, &q)) {
                    *((ULONG64*)entry->Payload + i) = q;
                    entry->PayloadLen = (i + 1) * 8;
                } else {
                    if (i == 0) {
                        entry->PayloadLen = 0xE0000003;  /* sentinel: first qword read failed */
                    }
                    break;
                }
            }
        }

        LONG newHits = InterlockedIncrement(&g_Shv.ReadTrapHits);

        /* RIP-trace arm-on-hit. If the UM has pre-armed a
         * trace (RipTraceActive==1 + RipTraceArmOnHit==1), the FIRST
         * read-trap hit flips this vcpu into trace mode. ArmOnHit is
         * cleared atomically so only ONE hit (not burst) starts logging
         * — subsequent hits on the same page during the burst don't
         * re-arm a second trace. The MTF handler takes over from here,
         * logging GuestRip each step until StepsMax or StopRange. */
        if (g_Shv.RipTraceActive == 1 &&
            InterlockedCompareExchange(
                (volatile LONG*)&g_Shv.RipTraceArmOnHit, 0, 1) == 1) {
            Vcpu->RipTracePending = TRUE;
            InterlockedExchange(&g_Shv.RipTraceStepsTaken, 0);
            SHV_LOG("RipTrace: armed on CPU %u, RIP 0x%p (max %u steps)",
                    (ULONG)Vcpu->ProcessorIndex,
                    (PVOID)GuestRip,
                    g_Shv.RipTraceStepsMax);
        }

        /* Auto-stop after N hits — INLINE disarm.
         *
         * Prior design scheduled uninstall via PendingReadTrapOp=2, which
         * runs on the NEXT non-EPT exit. That loses the race when the
         * scanner issues a burst of 100+ back-to-back EPT violations on
         * a single CPU: the pending op never gets checked until after the
         * burst, by which time the scanner has already finished hashing,
         * miscompared (due to ~1µs/violation overhead warping timings),
         * and crashed the target process. measured:
         * AutoStop=64 still logged 100 hits, game CTD'd before RSP dump.
         *
         * Fix: call ShvEptUninstallReadTrap() synchronously here. It
         * restores the PTE to its saved RWX value, INVEPTs, and clears
         * ReadTrapActive — all before we return from this exit. The
         * scanner's next read sees a normal page, its hash completes on
         * timing, and the process lives long enough for --dump-process-va
         * to chase the return address at [RSP].
         *
         * Safety:
         *   - ShvEptUninstallReadTrap is idempotent (short-circuits on
         *     !ReadTrapActive), so races between CPUs past the threshold
         *     are harmless — second caller is a no-op.
         *   - After uninstall, ShvEptReadTrapRearm (MTF handler) checks
         *     ReadTrapActive and bails, so we skip the RearmAndConsume
         *     block and return 1 directly. The PTE is already restored
         *     and INVEPT'd; the faulting instruction re-executes normally.
         *   - PendingReadTrapOp path in exit_dispatch.c is NOT used here,
         *     so UM sees the disarm by polling --status (Active=0). */
        if (g_Shv.ReadTrapAutoStop != 0 &&
            newHits >= (LONG)g_Shv.ReadTrapAutoStop) {
            ShvEptUninstallReadTrap();
            return 1;   /* consumed; PTE already restored, skip MTF re-arm */
        }
    }

RearmAndConsume:
    /* Temp-restore PTE (single-qword write). MTF will re-clear R/W/X. */
    {
        ULONG64 pa2mbBase = pageAlignedPa & ~(EPT_LARGE_PAGE_SIZE - 1ULL);
        ULONG   ptIdx     = EPT_PTE_INDEX(pageAlignedPa);

        for (ULONG i = 0; i < g_HookRes.PriCount; i++) {
            if (g_HookRes.PriBase[i] == pa2mbBase) {
                g_HookRes.PriPt[i][ptIdx].Value = g_Shv.ReadTrapSavedPteValue;
                /* If write-trap is also armed on this page, re-apply its
                 * W=0 so writes still trap after the instruction retries.
                 * Safe bitfield write: saved value has R=W=X=1, so
                 * W=0 transitions from legal R=1,W=1 to legal R=1,W=0. */
                if (g_Shv.WriteTrapActive &&
                    (pageAlignedPa == (g_Shv.WriteTrapTargetPa & ~0xFFFULL))) {
                    g_HookRes.PriPt[i][ptIdx].Write = 0;
                }
                break;
            }
        }
    }

    /* Enable MTF. */
    {
        SIZE_T procBased = 0;
        __vmx_vmread(VMCS_CTRL_PROC_BASED_EXEC, &procBased);
        procBased |= CPU_BASED_MONITOR_TRAP_FLAG;
        __vmx_vmwrite(VMCS_CTRL_PROC_BASED_EXEC, procBased);
    }

    Vcpu->MtfReadTrapRearmPending = TRUE;
    Vcpu->MtfReadTrapHookIndex    = READ_TRAP_HOOK_INDEX_SENTINEL;

    return 1;   /* consumed */
}

void ShvEptReadTrapRearm(void)
{
    if (!g_Shv.ReadTrapActive) return;

    ULONG64 pageAlignedPa = g_Shv.ReadTrapTargetPa & ~0xFFFULL;
    ULONG64 pa2mbBase = pageAlignedPa & ~(EPT_LARGE_PAGE_SIZE - 1ULL);
    ULONG   ptIdx     = EPT_PTE_INDEX(pageAlignedPa);

    for (ULONG i = 0; i < g_HookRes.PriCount; i++) {
        if (g_HookRes.PriBase[i] == pa2mbBase) {
            /* Single-qword re-clear of R/W/X to avoid reserved transient. */
            EPT_PTE newPte;
            newPte.Value   = g_Shv.ReadTrapSavedPteValue;
            newPte.Read    = 0;
            newPte.Write   = 0;
            newPte.Execute = 0;
            g_HookRes.PriPt[i][ptIdx].Value = newPte.Value;
            break;
        }
    }

    if (g_EptState != NULL) {
        ULONG64 eptp = g_EptState->EptPointer.Value;
        if (eptp != 0) {
            INVEPT_DESCRIPTOR desc;
            desc.EptPointer = eptp;
            desc.Reserved = 0;
            ShvInvept(INVEPT_SINGLE_CONTEXT, &desc);
        }
    }
}

/* ===== UM EPT Exec-Trap (Phase C-X, Apr 2026) =================================
 * Clone of read-trap but clears ONLY the Execute bit on the target PTE
 * (keeps Read and Write intact). Fires on instruction-fetch violations.
 * Use case: capture scanner's return landing page so the existing
 * RIP-trace arm-on-hit path engages at the dispatcher rather than deep
 * inside memcpy. Single-qword PTE store for safety.
 * ---------------------------------------------------------------------------*/

NTSTATUS ShvEptPrepareExecTrapResources(void)
{
    if (g_Shv.ExecTrapLog != NULL) {
        return STATUS_SUCCESS;
    }

    SIZE_T bytes = (SIZE_T)EXEC_TRAP_LOG_MAX * sizeof(EXEC_TRAP_LOG_ENTRY);
    g_Shv.ExecTrapLog = (PEXEC_TRAP_LOG_ENTRY)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, bytes, '0fdW');  /* mem=Wdf0 (KMDF runtime) */
    if (!g_Shv.ExecTrapLog) {
        SHV_LOG("ExecTrap: log-ring alloc failed (%llu bytes)", (ULONG64)bytes);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    InterlockedExchange(&g_Shv.ExecTrapLogIndex, 0);
    InterlockedExchange(&g_Shv.ExecTrapLogTotal, 0);
    SHV_LOG("ExecTrap: log ring allocated (%llu bytes at %p)",
            (ULONG64)bytes, g_Shv.ExecTrapLog);

    /* Ensure guest-read scratch window is ready for payload capture (same
     * mechanism used by read-trap payloads and xcap). ExecTrap uses the same
     * ShvReadGuestQwordVa path — without this, all cap payloads are empty. */
    ShvEptPrepareReadTrapResources();

    return STATUS_SUCCESS;
}

NTSTATUS ShvEptInstallExecTrap(
    _In_ ULONG64 Cr3,
    _In_ ULONG64 TargetPa,
    _In_ ULONG64 VaBase,
    _In_ ULONG64 VaEnd,
    _In_ ULONG64 RipFilter
    )
{
    if (TargetPa < 0x100000ULL || TargetPa >= 0x0000100000000000ULL) {
        SHV_ERR("ExecTrap: install rejected -- TargetPa=0x%llX looks unresolved", TargetPa);
        return STATUS_INVALID_PARAMETER;
    }
    if (!g_HookRes.Ready) {
        SHV_ERR("ExecTrap: hook resources not prepared");
        return STATUS_UNSUCCESSFUL;
    }
    if (g_EptState == NULL) {
        SHV_ERR("ExecTrap: EPT state not initialized");
        return STATUS_UNSUCCESSFUL;
    }
    if (EPT_PML4_INDEX(TargetPa) != 0) {
        SHV_ERR("ExecTrap: TargetPa 0x%llX not in PML4[0]", TargetPa);
        return STATUS_INVALID_PARAMETER;
    }
    if (VaEnd <= VaBase) {
        SHV_ERR("ExecTrap: VaEnd <= VaBase");
        return STATUS_INVALID_PARAMETER;
    }
    if ((VaEnd - VaBase) > PAGE_SIZE) {
        SHV_ERR("ExecTrap: range > 4 KB not supported in v1");
        return STATUS_INVALID_PARAMETER;
    }
    if (g_Shv.ExecTrapActive) {
        SHV_ERR("ExecTrap: already armed -- uninstall first");
        return STATUS_ALREADY_INITIALIZED;
    }
    if (g_Shv.ExecTrapLog == NULL) {
        SHV_ERR("ExecTrap: log ring not allocated (call Prepare first)");
        return STATUS_UNSUCCESSFUL;
    }

    ULONG64 pageAlignedPa = TargetPa & ~0xFFFULL;
    ULONG64 pa2mbBase = TargetPa & ~(EPT_LARGE_PAGE_SIZE - 1ULL);
    ULONG   ptIdx     = EPT_PTE_INDEX(TargetPa);

    EPT_PTE* priPt = ShvEptPrimarySplitFor(pa2mbBase);
    if (!priPt) {
        SHV_ERR("ExecTrap: primary split failed for 0x%llX", pa2mbBase);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    g_Shv.ExecTrapSavedPteValue = priPt[ptIdx].Value;

    g_Shv.ExecTrapCr3       = Cr3;
    g_Shv.ExecTrapTargetPa  = pageAlignedPa;
    g_Shv.ExecTrapVaBase    = VaBase;
    g_Shv.ExecTrapVaEnd     = VaEnd;
    g_Shv.ExecTrapRipFilter = RipFilter;

    InterlockedExchange(&g_Shv.ExecTrapHits,             0);
    InterlockedExchange(&g_Shv.ExecTrapFilteredCr3,      0);
    InterlockedExchange(&g_Shv.ExecTrapFilteredVa,       0);
    InterlockedExchange(&g_Shv.ExecTrapFilteredRip,      0);
    InterlockedExchange(&g_Shv.ExecTrapNonExecSkipped,   0);
    InterlockedExchange(&g_Shv.ExecTrapLogIndex,         0);
    InterlockedExchange(&g_Shv.ExecTrapLogTotal,         0);

    /* Single-qword PTE store: clear Execute only, keep R=W intact. */
    {
        EPT_PTE newPte;
        newPte.Value = g_Shv.ExecTrapSavedPteValue;
        newPte.Execute = 0;
        priPt[ptIdx].Value = newPte.Value;
    }

    {
        ULONG64 eptp = g_EptState->EptPointer.Value;
        if (eptp != 0) {
            INVEPT_DESCRIPTOR desc;
            desc.EptPointer = eptp;
            desc.Reserved = 0;
            ShvInvept(INVEPT_SINGLE_CONTEXT, &desc);
        }
    }
    InterlockedIncrement(&g_Shv.InveptGeneration);

    InterlockedExchange((volatile LONG*)&g_Shv.ExecTrapActive, 1);

    SHV_LOG("ExecTrap: armed pa=0x%llX cr3=0x%llX va=[0x%llX,0x%llX) rip=0x%llX ptIdx=%lu",
            pageAlignedPa, Cr3, VaBase, VaEnd, RipFilter, ptIdx);
    return STATUS_SUCCESS;
}

NTSTATUS ShvEptUninstallExecTrap(void)
{
    if (!g_Shv.ExecTrapActive) {
        return STATUS_SUCCESS;
    }

    InterlockedExchange((volatile LONG*)&g_Shv.ExecTrapActive, 0);

    ULONG64 pageAlignedPa = g_Shv.ExecTrapTargetPa;
    ULONG64 pa2mbBase = pageAlignedPa & ~(EPT_LARGE_PAGE_SIZE - 1ULL);
    ULONG   ptIdx     = EPT_PTE_INDEX(pageAlignedPa);

    BOOLEAN restored = FALSE;
    for (ULONG i = 0; i < g_HookRes.PriCount; i++) {
        if (g_HookRes.PriBase[i] == pa2mbBase) {
            /* Restore Execute on the live PTE (not ExecTrapSavedPteValue).
             * After a chain swap, ExecTrapTargetPa points to the chain TARGET but
             * ExecTrapSavedPteValue still holds the ANCHOR's PTE (wrong PFN for
             * the target page).  Writing it would corrupt the target's physical
             * mapping → launcher crash.  Just set X=1 on the current PTE. */
            g_HookRes.PriPt[i][ptIdx].Execute = 1;

            /* If read/write-trap is ALSO armed on this same page,
             * re-apply their clears after restoring the saved PTE. */
            if (g_Shv.ReadTrapActive &&
                (pageAlignedPa == (g_Shv.ReadTrapTargetPa & ~0xFFFULL))) {
                EPT_PTE newPte;
                newPte.Value = g_Shv.ReadTrapSavedPteValue;
                newPte.Read    = 0;
                newPte.Write   = 0;
                newPte.Execute = 0;
                g_HookRes.PriPt[i][ptIdx].Value = newPte.Value;
            } else if (g_Shv.WriteTrapActive &&
                       (pageAlignedPa == (g_Shv.WriteTrapTargetPa & ~0xFFFULL))) {
                g_HookRes.PriPt[i][ptIdx].Write = 0;
            }
            restored = TRUE;
            break;
        }
    }

    if (!restored) {
        SHV_LOG("ExecTrap: uninstall -- no matching split for 0x%llX", pa2mbBase);
    }

    if (g_EptState != NULL) {
        ULONG64 eptp = g_EptState->EptPointer.Value;
        if (eptp != 0) {
            INVEPT_DESCRIPTOR desc;
            desc.EptPointer = eptp;
            desc.Reserved = 0;
            ShvInvept(INVEPT_SINGLE_CONTEXT, &desc);
        }
    }
    InterlockedIncrement(&g_Shv.InveptGeneration);

    g_Shv.ExecTrapCr3           = 0;
    g_Shv.ExecTrapTargetPa      = 0;
    g_Shv.ExecTrapVaBase        = 0;
    g_Shv.ExecTrapVaEnd         = 0;
    g_Shv.ExecTrapRipFilter     = 0;
    g_Shv.ExecTrapSavedPteValue = 0;

    SHV_LOG("ExecTrap: disarmed (hits=%ld cr3-filt=%ld va-filt=%ld rip-filt=%ld non-exec=%ld)",
            g_Shv.ExecTrapHits, g_Shv.ExecTrapFilteredCr3,
            g_Shv.ExecTrapFilteredVa, g_Shv.ExecTrapFilteredRip,
            g_Shv.ExecTrapNonExecSkipped);
    return STATUS_SUCCESS;
}

ULONG ShvEptExecTrapTryHandle(
    _In_ ULONG64 GuestPa,
    _In_ ULONG64 GuestLinearVa,
    _In_ ULONG64 GuestRip,
    _In_ ULONG64 GuestCr3,
    _In_ ULONG64 ExitQualification,
    _In_ ULONG   CpuIndex,
    _In_ struct _VCPU_DATA *Vcpu,
    _In_opt_ struct _GUEST_CONTEXT *GuestContext
    )
{
    if (!g_Shv.ExecTrapActive) return 0;
    ULONG64 pageAlignedPa = g_Shv.ExecTrapTargetPa & ~0xFFFULL;
    if ((GuestPa & ~0xFFFULL) != pageAlignedPa) return 0;

    BOOLEAN isRead  = (ExitQualification & EPT_VIOLATION_DATA_READ)         != 0;
    BOOLEAN isWrite = (ExitQualification & EPT_VIOLATION_DATA_WRITE)        != 0;
    BOOLEAN isExec  = (ExitQualification & EPT_VIOLATION_INSTRUCTION_FETCH) != 0;

    if (!isExec) {
        /* Exec-trap only clears X, so R/W faults shouldn't happen unless
         * read/write-trap is also armed on the same page. Defer to the
         * more restrictive primitive if active. */
        if (isRead && g_Shv.ReadTrapActive &&
            (pageAlignedPa == (g_Shv.ReadTrapTargetPa & ~0xFFFULL))) {
            return 0;
        }
        if (isWrite && g_Shv.WriteTrapActive &&
            (pageAlignedPa == (g_Shv.WriteTrapTargetPa & ~0xFFFULL))) {
            return 0;
        }
        InterlockedIncrement(&g_Shv.ExecTrapNonExecSkipped);
        goto RearmAndConsume;
    }

    /* Apply filters. */
    BOOLEAN shouldLog = TRUE;

    if (g_Shv.ExecTrapCr3 != 0 && GuestCr3 != g_Shv.ExecTrapCr3) {
        LONG prevFilteredCr3 = InterlockedIncrement(&g_Shv.ExecTrapFilteredCr3) - 1;
        shouldLog = FALSE;
        if (prevFilteredCr3 == 0) {
            InterlockedExchange64((volatile LONG64*)&g_Shv.PendingExecTrapOp, 2);
        }
    }

    if (shouldLog &&
        (ExitQualification & EPT_VIOLATION_GLA_VALID) &&
        g_Shv.ExecTrapVaBase != 0 && g_Shv.ExecTrapVaEnd != 0 &&
        (GuestLinearVa < g_Shv.ExecTrapVaBase ||
         GuestLinearVa >= g_Shv.ExecTrapVaEnd)) {
        InterlockedIncrement(&g_Shv.ExecTrapFilteredVa);
        shouldLog = FALSE;
    }

    if (shouldLog &&
        g_Shv.ExecTrapRipFilter != 0 &&
        GuestRip != g_Shv.ExecTrapRipFilter) {
        InterlockedIncrement(&g_Shv.ExecTrapFilteredRip);
        shouldLog = FALSE;
    }

    /* RAX filter: when ExecTrapRaxFilter != 0, only log when
     * the guest RAX matches exactly. Primary use: LSTAR exec-trap where
     * RAX = SSN at KiSystemCall64Shadow entry — drop all non-target syscalls
     * before the 1024-entry ring overflows. */
    if (shouldLog &&
        g_Shv.ExecTrapRaxFilter != 0 &&
        GuestContext != NULL &&
        GuestContext->Rax != g_Shv.ExecTrapRaxFilter) {
        InterlockedIncrement(&g_Shv.ExecTrapRaxFiltered);
        shouldLog = FALSE;
    }

    if (shouldLog && g_Shv.ExecTrapLog != NULL) {
        LONG total = InterlockedIncrement(&g_Shv.ExecTrapLogTotal);
        LONG slotRaw = InterlockedIncrement(&g_Shv.ExecTrapLogIndex) - 1;
        LONG slot = slotRaw % EXEC_TRAP_LOG_MAX;
        if (slot < 0) slot += EXEC_TRAP_LOG_MAX;

        PEXEC_TRAP_LOG_ENTRY entry = &g_Shv.ExecTrapLog[slot];
        entry->ExecRip           = GuestRip;
        entry->FaultVa           = GuestLinearVa;
        entry->GuestCr3          = GuestCr3;
        {
            SIZE_T grsp = 0;
            __vmx_vmread(VMCS_GUEST_RSP, &grsp);
            entry->ExecRsp       = (ULONG64)grsp;
        }
        if (GuestContext != NULL) {
            entry->Rax           = GuestContext->Rax;
            entry->Rcx           = GuestContext->Rcx;
            entry->Rdx           = GuestContext->Rdx;
            entry->Rsi           = GuestContext->Rsi;
            entry->Rdi           = GuestContext->Rdi;
            entry->Rbx           = GuestContext->Rbx;
            entry->Rbp           = GuestContext->Rbp;
            entry->R8            = GuestContext->R8;
            entry->R9            = GuestContext->R9;
            entry->R10           = GuestContext->R10;
            entry->R11           = GuestContext->R11;
            entry->R12           = GuestContext->R12;
            entry->R13           = GuestContext->R13;
            entry->R14           = GuestContext->R14;
            entry->R15           = GuestContext->R15;
        } else {
            entry->Rax           = 0;
            entry->Rcx           = 0;
            entry->Rdx           = 0;
            entry->Rsi           = 0;
            entry->Rdi           = 0;
            entry->Rbx           = 0;
            entry->Rbp           = 0;
            entry->R8            = 0;
            entry->R9            = 0;
            entry->R10           = 0;
            entry->R11           = 0;
            entry->R12           = 0;
            entry->R13           = 0;
            entry->R14           = 0;
            entry->R15           = 0;
        }
        entry->Tsc               = __rdtsc();
        entry->ExitQualification = (ULONG32)ExitQualification;
        entry->CpuIndex          = CpuIndex;
        entry->Counter           = (ULONG32)total;
        entry->PayloadLen        = 0;
        RtlZeroMemory(entry->Payload, sizeof(entry->Payload));
        RtlZeroMemory(entry->Reserved, sizeof(entry->Reserved));

        /* ── Hash-capture  ─────────────────────────────
         * If armed, dump ExecTrapCapLen bytes from [ExecTrapCapSrc] (the
         * chosen GPR value, used as a guest VA) into Payload. Reads are
         * qword-granular via ShvReadGuestQwordVa; first failed read stops
         * the loop (e.g. ptr straddles a non-present page). */
        {
            ULONG32 capSrc = g_Shv.ExecTrapCapSrc;
            ULONG32 capLen = g_Shv.ExecTrapCapLen;
            if (capSrc != 0 && capLen != 0 && GuestContext != NULL) {
                ULONG64 ptr = 0;
                switch (capSrc) {
                    case EXEC_TRAP_CAP_SRC_RAX: ptr = GuestContext->Rax; break;
                    case EXEC_TRAP_CAP_SRC_RCX: ptr = GuestContext->Rcx; break;
                    case EXEC_TRAP_CAP_SRC_RDX: ptr = GuestContext->Rdx; break;
                    case EXEC_TRAP_CAP_SRC_RSI: ptr = GuestContext->Rsi; break;
                    case EXEC_TRAP_CAP_SRC_RDI: ptr = GuestContext->Rdi; break;
                    case EXEC_TRAP_CAP_SRC_RSP: {
                        SIZE_T grsp = 0;
                        __vmx_vmread(VMCS_GUEST_RSP, &grsp);
                        /* Dereference [RSP] — snapshot stack-top bytes
                         * (useful to see memcpy return context etc.). */
                        ptr = (ULONG64)grsp;
                        break;
                    }
                    case EXEC_TRAP_CAP_SRC_R12: ptr = GuestContext->R12; break;
                    case EXEC_TRAP_CAP_SRC_R13: ptr = GuestContext->R13; break;
                    case EXEC_TRAP_CAP_SRC_R9:  ptr = GuestContext->R9;  break;
                    default: ptr = 0; break;
                }

                if (ptr != 0 && capLen <= EXEC_TRAP_PAYLOAD_BYTES) {
                    /* Clamp to EXEC_TRAP_PAYLOAD_BYTES (512 B) and qword-aligned chunks. */
                    ULONG nQwords = capLen / 8;
                    if (nQwords == 0) nQwords = 1;
                    if (nQwords > EXEC_TRAP_PAYLOAD_BYTES / 8)
                        nQwords = EXEC_TRAP_PAYLOAD_BYTES / 8;

                    ULONG goodQwords = 0;
                    BOOLEAN hadFail = FALSE;
                    for (ULONG qi = 0; qi < nQwords; qi++) {
                        ULONG64 q = 0;
                        ULONG64 va = ptr + (ULONG64)qi * 8ULL;
                        /* PRIMARY: PTE_BASE virtual path — no physical page table reads.
                         * Works on VBS/HVCI where page table pages are at Secure-Kernel
                         * PAs above MaxPhysAddr (inaccessible via DirectMap in VMX root).
                         * ShvReadGuestVaDirect reads the PTE via its kernel VA, then reads
                         * the data via DirectMap (data page PA is within normal RAM). */
                        if (!ShvReadGuestVaDirect(va, &q)) {
                            /* FALLBACK: CR3-walk path (succeeds on non-VBS or when
                             * page table PAs happen to be within MaxPhysAddr). */
                            if (!ShvReadGuestQwordVa(GuestCr3, va, &q)) {
                                hadFail = TRUE;
                                break;
                            }
                        }
                        *((ULONG64*)entry->Payload + qi) = q;
                        goodQwords = qi + 1;
                    }
                    entry->PayloadLen = goodQwords * 8;
                    if (goodQwords > 0) {
                        InterlockedIncrement(&g_Shv.ExecTrapCapHits);
                    }
                    if (hadFail) {
                        InterlockedIncrement(&g_Shv.ExecTrapCapReadFails);
                    }
                }
            }
        }

        LONG newHits = InterlockedIncrement(&g_Shv.ExecTrapHits);

        /* Stage-2 page visibility.  Once stage-2 is armed we want the
         * actual RIPs executed on that page in the TEXT ring, not just counters --
         * they are what distinguish "the pivot already ran before we armed" from
         * "this page is never executed again".  Throttled so it cannot wrap the
         * 512-line ring. */
        if (g_ChainStage2Va != 0 &&
            (GuestLinearVa & ~0xFFFULL) == (g_ChainStage2Va & ~0xFFFULL)) {
            static volatile LONG s_s2PageHits = 0;
            LONG _h = InterlockedIncrement(&s_s2PageHits);
            /* THE PIVOT IS ALWAYS LOGGED -- never let the rate limiter hide the one
             * line the whole run exists to produce.  (Same mistake as the anchor
             * MISS logging: a throttle that can swallow the signal.  Run 17 hit 249
             * page executions, and with "first 24, then 1-in-1024" the entire window
             * 25..249 was invisible, so "no PIVOT line" could not be distinguished
             * from "PIVOT throttled away".)
             * Also track the HIGHEST RVA reached on the page: that says how far
             * execution actually got before bailing, which is what tells us whether
             * the pivot was even on the taken path. */
            static volatile LONG s_maxOff = 0;
            LONG _off = (LONG)(GuestRip & 0xFFF);
            LONG _prev = s_maxOff;
            while (_off > _prev) {
                LONG _seen = InterlockedCompareExchange(&s_maxOff, _off, _prev);
                if (_seen == _prev) break;
                _prev = _seen;
            }
            BOOLEAN _isPivot = (GuestRip == g_ChainStage2Va);
            if (_isPivot || _h <= 24 || (_h & 0xFF) == 0) {
                SHV_LOG("ExecTrapChain[s2-page]: hit#%ld rip=0x%llX (pivot=0x%llX, %s) "
                        "maxOff=0x%lX cr3=0x%llX",
                        _h, GuestRip, g_ChainStage2Va,
                        _isPivot ? "*** PIVOT ***" : "other insn on page",
                        s_maxOff, GuestCr3);
            }
        }

        /* RIP-trace arm-on-hit — identical hook to read-trap. First exec
         * hit starts logging; CAS keeps it single-shot per burst. This
         * is the core reason exec-trap exists: land at the scanner's
         * return (in the dispatcher) and immediately trace forward. */
        if (g_Shv.RipTraceActive == 1 &&
            InterlockedCompareExchange(
                (volatile LONG*)&g_Shv.RipTraceArmOnHit, 0, 1) == 1) {
            Vcpu->RipTracePending = TRUE;
            InterlockedExchange(&g_Shv.RipTraceStepsTaken, 0);
            SHV_LOG("RipTrace: armed on CPU %u via exec-trap, RIP 0x%p (max %u steps)",
                    (ULONG)Vcpu->ProcessorIndex,
                    (PVOID)GuestRip,
                    g_Shv.RipTraceStepsMax);
        }

        if (g_Shv.ExecTrapAutoStop != 0 &&
            newHits >= (LONG)g_Shv.ExecTrapAutoStop) {
            ShvEptUninstallExecTrap();
            return 1;
        }
    }

    /* ── Chained exec-trap: in-place anchor→target swap ──────────────
     * Fires when chain mode is active and the anchor VA is reached
     * (shouldLog TRUE = CR3 + VA-range + RIP filters all passed).
     * Swaps ExecTrapTargetPa to the pre-split chain target IN-PLACE:
     *   - Save target's original PTE → ExecTrapSavedPteValue
     *     (RearmAndConsume below writes this to the ANCHOR PTE,
     *     restoring anchor to full RWX — anchor is un-trapped after here)
     *   - Clear X on target PTE
     *   - Update live ExecTrap* state to point at the target
     *   - INVEPT to flush cached PA→permissions
     * The MTF exit handler sees the UPDATED ExecTrapTargetPa (target)
     * and re-arms X=0 on the target after the anchor instruction executes.
     * No allocation needed — target 2MB region was pre-split by the
     * guest-side setup (arm-then-uninstall on target before arming anchor). */
    if (shouldLog &&
        g_Shv.ExecTrapChainEnabled != 0 &&
        InterlockedCompareExchange64(
            (volatile LONG64*)&g_Shv.ExecTrapChainFired, 1, 0) == 0)
    {
        /* ── ANCHOR FILTER, REWRITTEN ─────────────────────────────
         * The field is still wire-named RcxLow12 (offset 0x80 is pinned), but its
         * MEANING is now:   bits[31:0]  = required EntryPoint RVA (RCX - RDX)
         *                   bits[63:32] = required fdwReason in R8D (0 = any)
         *
         * WHY THE CHANGE.  Every anchor used before today was the WRONG FUNCTION:
         * ntdll RVA 0x3F210 is LdrpInitializeThread (runs once per THREAD,
         * system-wide) and 0xAEAE4 is LdrpInitialize — neither is on the DllMain
         * path, which is why 10,240+ fires never matched and RCX always looked
         * like a stack pointer.  The real ntdll!LdrpCallInitRoutine is RVA
         * 0x3F690, verified against the matching PDB and by disassembly:
         *
         *   03F6BF  mov rdi, rcx     ; arg1 EntryPoint
         *   03F6BC  mov r15, rdx     ; arg2 DllBase
         *   03F6B9  mov r14d, r8d    ; arg3 fdwReason  (cmp r14d,1 at 0x3F7A8)
         *   03F6B6  mov rsi, r9      ; arg4 Context
         *
         * and at its process-init caller LdrpInitializeNode+0x197:
         *   08C4A4  mov r15, [rdi+0x38]   ; LDR_DATA_TABLE_ENTRY.EntryPoint -> RCX
         *   08C570  mov rdx, [rdi+0x30]   ; LDR_DATA_TABLE_ENTRY.DllBase
         *   08C56A  mov r8d, 1            ; DLL_PROCESS_ATTACH
         *
         * So RCX-RDX is the DLL's ENTRY RVA — a full 64-bit discriminator
         * (preloader_l = 0xB030) instead of the old 12 ambiguous bits, and R8D
         * separates process-attach from the thread-attach flood semantically. */
        ULONG64 _epWant     = g_Shv.ExecTrapChainRcxLow12 & 0xFFFFFFFFULL;
        ULONG32 _reasonWant = (ULONG32)(g_Shv.ExecTrapChainRcxLow12 >> 32);
        ULONG64 _epGot      = GuestContext->Rcx - GuestContext->Rdx;
        ULONG32 _reasonGot  = (ULONG32)GuestContext->R8;

        /* A pending retry bypasses the EP/reason filter: the module was already
         * identified on an earlier fire; we are only waiting for its stage-2 page
         * to become resident.  Same process only (CR3), so we cannot pick up a
         * stale VA from a different address space. */
        BOOLEAN _pendingRetry = (g_ChainPendingS2Va != 0 &&
                                 g_ChainPendingCr3 == GuestCr3);

        if (!_pendingRetry && _epWant != 0 &&
            (_epGot != _epWant ||
             (_reasonWant != 0 && _reasonGot != _reasonWant)))
        {
            /* RATE-LIMITED. This fires for EVERY DLL init in EVERY process
             * (the anchor is CR3-unfiltered by design), i.e. thousands of times per game
             * launch. Unthrottled it floods the 512-line ShvLogRing and evicts exactly the
             * lines we need -- the stage-2/stage-3 resolution results. Keep the first few
             * (proves the filter is live + shows real RCX values), then 1-in-512 as a
             * heartbeat. DbgPrintEx gets the same treatment; it was pure noise there too. */
            {
                static volatile LONG s_rcxMissCount = 0;
                LONG n = InterlockedIncrement(&s_rcxMissCount);

                /* At the REAL LdrpCallInitRoutine every fire is a genuine DllMain
                 * dispatch, so epRva is a meaningful module identity for EVERY miss.
                 *
                 * !! RATE-LIMIT LESSON (measured shvlog11). The previous
                 * revision logged every PROCESS_ATTACH unconditionally on the theory
                 * that they are "comparatively rare". That was true at the WRONG
                 * anchor (LdrpInitializeThread, dominated by thread-init). At the
                 * REAL anchor a process-attach is the COMMON case: 434 of the ring's
                 * 512 lines were PROCESS_ATTACH, the ring WRAPPED (738 written, 512
                 * retained), and ~226 lines were evicted. So "no 0xB030 in the log"
                 * was NOT evidence of absence -- the one line we hunt could have been
                 * thrown away by our own logging.
                 *
                 * Only an EP MATCH is unconditional now; everything else is a thin
                 * heartbeat that proves the filter is live without ever being able to
                 * evict the chain's own stage-1/stage-2/stage-3 lines.
                 *
                 * NOTE R8D, not R9, is fdwReason.  The old "r9 == fdwReason" reading came
                 * from LdrpInitializeThread, where R9 was uninitialised garbage that
                 * happened to be 2 every time. */
                BOOLEAN _isWanted = (_epGot == _epWant);
                if (_isWanted || n <= 4 || (n & 0xFFF) == 0) {
                    SHV_LOG("ExecTrapChain: MISS#%ld epRva=0x%llX (want 0x%llX) reason=%lu "
                            "rcx=0x%llX rdx=0x%llX cr3=0x%llX%s",
                            n, _epGot, _epWant, _reasonGot,
                            GuestContext->Rcx, GuestContext->Rdx, GuestCr3,
                            _isWanted ? "  <== EP MATCH but reason mismatch" : "");
                }
            }
            InterlockedExchange64((volatile LONG64*)&g_Shv.ExecTrapChainFired, 0);
            goto RearmAndConsume;
        }
        ULONG64 effectiveTargetVa = g_Shv.ExecTrapChainTargetVaBase;
        if (_pendingRetry) {
            /* Reuse the VA captured when the module was identified; RDX on THIS
             * fire belongs to some other DLL and must not be used. */
            effectiveTargetVa = g_ChainPendingS2Va;
        } else if (g_Shv.ExecTrapChainRdxRva != 0) {
            effectiveTargetVa = GuestContext->Rdx + g_Shv.ExecTrapChainRdxRva;
            SHV_LOG("ExecTrapChain: rdx-rva target: DllBase(RDX)=0x%llX + RVA=0x%llX -> va=0x%llX",
                    GuestContext->Rdx, g_Shv.ExecTrapChainRdxRva, effectiveTargetVa);
        }

        /* Resolve chain target PA.  Two modes:
         *   ExecTrapChainTargetPa != 0  — pre-translated by Python/NexusCore;
         *     fastest path, no EPT walk needed.
         *   ExecTrapChainTargetPa == 0  — dynamic: walk the guest page tables
         *     at anchor-fire time.  GSL.dll has been mapped by preloader_l
         *     before the anchor VA fires (guaranteed by design), so the VA
         *     resolves to a valid PA.  Retry on the next anchor hit on failure. */
        ULONG64 chainPa    = g_Shv.ExecTrapChainTargetPa;
        BOOLEAN directJump = FALSE; /* TRUE = s1 jumps directly to stage-3 (preloader PA unavailable) */

        /* LIVE WALK FIRST  — beats any pre-resolved PA.
         * ExecTrapChainTargetPa is resolved in ANOTHER process (Python) and is only
         * valid for pages never written.  gsl.dll relocates AND self-decrypts, so its
         * pages are copy-on-write split and the pre-resolved PA points at a pristine
         * frame the game never executes (measured; see ShvTranslateGuestVaLive).
         * Walking the guest's own page tables at fire time yields the frame actually
         * mapped right now, COW copy included.  If the two disagree, that disagreement
         * IS the on-hardware confirmation of the COW theory — log it loudly. */
        {
            ULONG64 livePa = 0;
            if (ShvTranslateGuestVaLive(GuestCr3, effectiveTargetVa, &livePa) &&
                (livePa & ~0xFFFULL) >= 0x1000) {
                if (chainPa != 0 && (chainPa & ~0xFFFULL) != (livePa & ~0xFFFULL)) {
                    SHV_LOG("ExecTrapChain[live]: COW MISMATCH va=0x%llX preresolved=0x%llX live=0x%llX "
                            "-- using LIVE (pre-resolved PA was a pristine frame the guest never executes)",
                            effectiveTargetVa, chainPa & ~0xFFFULL, livePa & ~0xFFFULL);
                } else {
                    SHV_LOG("ExecTrapChain[live]: va=0x%llX -> PA=0x%llX (guest CR3 walk)",
                            effectiveTargetVa, livePa & ~0xFFFULL);
                }
                chainPa = livePa;
                g_ChainPendingS2Va = 0;      /* resolved - stop retrying */
                g_ChainPendingCr3  = 0;
            } else {
                /* Arm the retry: remember WHICH VA in WHICH process we still owe a
                 * walk, so any later anchor fire in that process can finish it. */
                g_ChainPendingS2Va = effectiveTargetVa;
                g_ChainPendingCr3  = GuestCr3;
                /* Log the FIRST failure in full (that is the diagnostic one -- it
                 * names the VA, the CR3 and which walk level failed), then throttle
                 * hard.  Retries now happen on EVERY anchor fire in the process, so
                 * an unthrottled message here would wrap the 512-line ring and evict
                 * the stage-1/2/3 lines -- the exact self-inflicted blindness that
                 * cost run #11.  A retry counter is carried on the throttled lines so
                 * "how many times did we try" stays answerable. */
                static volatile LONG s_walkFailCount = 0;
                LONG _wf = InterlockedIncrement(&s_walkFailCount);
                if (_wf <= 2 || (_wf & 0xFFF) == 0) {
                    SHV_LOG("ExecTrapChain[live]: WALK FAILED#%ld va=0x%llX cr3=0x%llX fail=%ld "
                            "scratchOk=%d (page not resident yet -- will retry on any anchor "
                            "fire in this process)",
                            _wf, effectiveTargetVa, GuestCr3, g_LastWalkFail,
                            (int)g_RootScratchOk);
                }
            }
        }

        if (chainPa == 0) {
            /* Dynamic PA resolution via PTE_BASE.
             * ShvTranslateGuestVa / ShvReadGuestPhysQword permanently disabled
             * (DirectMapBase caused 2 BSODs).  Use the PTE self-map directly.
             *
             * HOST-CR3 PROBLEM FOR USER-SPACE VAs (iter#186 fix):
             * g_PteBase + (va >> 9) reads the PTE from the ACTIVE CR3's self-map.
             * In VMX-root, the active CR3 is the SHV host CR3.  The host CR3 has
             * no user-space mappings for gsl.exe, so the PTE read as 0 (not-present)
             * causing chainPa < 0x1000 and a loop-reset on every anchor fire.
             *
             * FIX: temporarily load GuestCr3 before reading the PTE so the self-map
             * reflects gsl.exe's page tables.  Interrupt-safe: VMX-root entry clears
             * RFLAGS.IF on every VM exit.  SHV code is in non-paged kernel VA,
             * which is identical (shared) across all process CR3s on Windows. */
            ULONG64 tva  = effectiveTargetVa;
            ULONG64 rpa  = 0;
            if (g_PteBase != 0) {
                ULONG64 pte_va = (ULONG64)g_PteBase + (tva >> 9);
                if (pte_va >= 0xFFFF800000000000ULL && pte_va <= 0xFFFFFF80FFFFFFFFULL) {
                    BOOLEAN guestCr3Loaded = FALSE;
                    ULONG64 savedCr3 = 0;
                    if (tva < 0x8000000000000000ULL) {
                        savedCr3 = __readcr3();
                        __writecr3(GuestCr3);
                        guestCr3Loaded = TRUE;
                    }
                    ULONG64 pte = *(volatile ULONG64*)pte_va;
                    if (guestCr3Loaded) {
                        __writecr3(savedCr3);
                    }
                    SHV_LOG("ExecTrapChain[s1] PTE pte_va=0x%llX guestCr3=0x%llX pte=0x%llX",
                            pte_va, GuestCr3, pte);
                    if ((pte & HPTE_PRESENT) && pte >= 0x1000) {
                        rpa = (pte & HPTE_LARGE)
                            ? ((pte & 0x000FFFFFFFE00000ULL) | (tva & 0x001FF000ULL))
                            : (pte & HPTE_PFN_MASK);
                    }
                }
            }
            if (rpa < 0x1000) {
                /* Stage-2 PA unavailable (g_PteBase=0 permanently on this HW; iter#188).
                 * preloader_l is a rebased DLL — its reloc pages become private CoW copies
                 * with a different PA in each process, so Python pre-resolution is wrong.
                 * Fallback: if stage-3 PA (gsl.dll) is pre-resolved via SEC_IMAGE ViewShare
                 * (shared frames, same PA everywhere), jump there directly from stage-1. */
                /* directJump DISABLED  — it was actively CORRUPTING the chain.
                 *
                 * It skipped stage-2 at preloader+RdxRva and armed the pre-resolved gsl
                 * stage3_pa instead. But `RCX = gsl_base` is ONLY true AT preloader+0x2DB5;
                 * after a direct jump the stage-2 handler reads whatever happens to be in
                 * RCX and computes stage3Va from garbage. MEASURED: run#1 RCX=0x948627F5E0,
                 * run#3 RCX=0xDC90FFF760 — neither 64KB-aligned, so neither is a module base.
                 * That one shortcut explains every bogus "gsl_base" we have ever logged.
                 * It also armed a COW-stale pristine frame (see ShvTranslateGuestVaLive).
                 *
                 * Correct behaviour: this anchor fire simply could not resolve preloader's
                 * page yet — so RETRY on the next fire rather than poisoning the chain with
                 * a jump we know produces nonsense. effectiveTargetVa is RDX(DllBase)+RdxRva,
                 * which is exactly right; it just needs a walk that succeeds. */
                ULONG64 _s3Pa = g_Shv.ExecTrapChainStage3Pa;
                if (0 && _s3Pa >= 0x1000) {   /* intentionally disabled; kept for context */
                    chainPa    = _s3Pa;
                    directJump = TRUE;
                }
                if (!directJump) {
                    /* Throttled to match the WALK FAILED line above -- this fires on
                     * every retry.  The old text blamed "g_PteBase=0", which is
                     * misleading now: the walk primitive WORKS (scratchOk=1); the
                     * page is simply not resident yet. */
                    static volatile LONG s_unresolvedCount = 0;
                    LONG _u = InterlockedIncrement(&s_unresolvedCount);
                    if (_u <= 2 || (_u & 0xFFF) == 0) {
                        SHV_LOG("ExecTrapChain[s1]: stage-2 VA=0x%llX still unresolved (#%ld) -- "
                                "retrying; preresolved s3Pa=0x%llX deliberately IGNORED "
                                "(COW-stale: preloader_l is rebased)", tva, _u, _s3Pa);
                    }
                    InterlockedExchange64((volatile LONG64*)&g_Shv.ExecTrapChainFired, CHAIN_IDLE);
                    goto RearmAndConsume;
                }
            } else {
                chainPa = rpa;
            }
        }
        chainPa &= ~0xFFFULL;

        ULONG64 chainPa2mb  = chainPa & ~(EPT_LARGE_PAGE_SIZE - 1ULL);
        ULONG   chainPtIdx  = EPT_PTE_INDEX(chainPa);
        BOOLEAN chainSwapped = FALSE;

        /* Get (or create) the split PT for the chain target's 2MB region.
         * ShvEptPrimarySplitFor returns an existing split if the region was
         * pre-split by a prior install+uninstall on this PA, or allocates a
         * new one otherwise.  Allocation here is safe in practice because
         * SentinelHV's exit handlers run at an IRQL where non-paged
         * contiguous allocation succeeds on Windows kernel builds. */
        EPT_PTE* chainPriPt = ShvEptPrimarySplitFor(chainPa2mb);
        if (!chainPriPt) {
            SHV_ERR("ExecTrapChain: ShvEptPrimarySplitFor failed for chainPa2mb=0x%llX",
                    chainPa2mb);
            InterlockedExchange64((volatile LONG64*)&g_Shv.ExecTrapChainFired, 0);
            goto RearmAndConsume;
        }

        /* Use the pre-allocated split PT directly — skip the g_HookRes loop. */
        {
            ULONG _ci = 0; /* satisfy the if-block below */
            for (_ci = 0; _ci < g_HookRes.PriCount; _ci++) {
                if (g_HookRes.PriBase[_ci] != chainPa2mb) continue;

            /* Clear Execute on the target page WITHOUT touching ExecTrapSavedPteValue.
             * ExecTrapSavedPteValue must keep the ANCHOR's original PTE so that
             * RearmAndConsume (which runs next) correctly temp-restores the anchor
             * page for the single MTF step.  Overwriting it with the target's PTE
             * would corrupt the anchor's physical mapping (wrong PFN written to anchor
             * slot → cipher executes target bytes from anchor VA → crash). */
            EPT_PTE _newPte;
            _newPte.Value   = g_HookRes.PriPt[_ci][chainPtIdx].Value;
            _newPte.Execute = 0;
            g_HookRes.PriPt[_ci][chainPtIdx].Value = _newPte.Value;

            /* Redirect trap state to target. */
            g_Shv.ExecTrapTargetPa     = chainPa;
            g_Shv.ExecTrapVaBase       = effectiveTargetVa;
            g_Shv.ExecTrapVaEnd        = effectiveTargetVa + PAGE_SIZE;
            g_Shv.ExecTrapCr3          = g_Shv.ExecTrapChainTargetCr3;
            /* When three-stage mode is active (RcxRva != 0), the stage-2 anchor
             * must fire only at the exact call-site instruction (preloader+0x2DB5),
             * not at any earlier instruction on the same page (which starts at 0x2390).
             * ExecTrapVaBase already excludes [page_base, effectiveTargetVa), so only
             * instructions at [effectiveTargetVa, effectiveTargetVa+PAGE_SIZE) reach
             * shouldLog=TRUE; the RipFilter adds a second guard for correctness. */
            /* Publish the pivot for step-2, then deliberately leave the RIP filter
             * OPEN so every instruction executed on the stage-2 page is logged.
             * step-2 keys off g_ChainStage2Va, not this filter, so widening the
             * view cannot make it fire at the wrong instruction. */
            g_ChainStage2Va            = effectiveTargetVa;
            g_Shv.ExecTrapRipFilter    = 0;
            /* Watch the WHOLE page, not [pivot, pivot+0x1000) -- the old range
             * started AT the pivot and so hid everything before it on the page,
             * which is exactly the evidence we need. */
            g_Shv.ExecTrapVaBase       = effectiveTargetVa & ~0xFFFULL;
            g_Shv.ExecTrapVaEnd        = (effectiveTargetVa & ~0xFFFULL) + PAGE_SIZE;
            if (g_Shv.ExecTrapChainAutoStop != 0)
                InterlockedExchange(&g_Shv.ExecTrapAutoStop,
                                    (LONG)g_Shv.ExecTrapChainAutoStop);
            InterlockedExchange(&g_Shv.ExecTrapHits,        0);
            InterlockedExchange(&g_Shv.ExecTrapLogIndex,    0);
            InterlockedExchange(&g_Shv.ExecTrapLogTotal,    0);
            InterlockedExchange(&g_Shv.ExecTrapFilteredCr3, 0);
            InterlockedExchange(&g_Shv.ExecTrapFilteredVa,  0);
            InterlockedExchange(&g_Shv.ExecTrapFilteredRip, 0);

            /* Flush stale PA→permissions cached by ALL CPUs' TLBs.
             * The cipher may run on a different CPU from the one that swapped the
             * chain target.  INVEPT_SINGLE_CONTEXT only flushes the current CPU;
             * the other CPU's TLB still has the target page as executable → no
             * EPT violation fires there.  Use ALL_CONTEXTS to broadcast. */
            {
                INVEPT_DESCRIPTOR _d = { 0, 0 };
                ShvInvept(INVEPT_ALL_CONTEXTS, &_d);
                InterlockedIncrement(&g_Shv.InveptGeneration);
            }

                chainSwapped = TRUE;
                if (directJump) {
                    /* Direct s1→s3: gsl_base unknown yet (preloader hasn't mapped gsl.dll).
                     * Set VA filter to whole address space so the first execution from the
                     * gsl page (which WILL be verify_with_profile once preloader runs) hits.
                     * ChainFired=2 bypasses the stage-2 CAS block on the next fire.
                     * AutoStop=1 captures RSP and stops on that first hit. */
                    g_Shv.ExecTrapVaBase    = 0;
                    g_Shv.ExecTrapVaEnd     = ~0ULL;
                    g_Shv.ExecTrapRipFilter = 0;
                    InterlockedExchange(&g_Shv.ExecTrapAutoStop, 1);
                    InterlockedExchange64((volatile LONG64*)&g_Shv.ExecTrapChainFired, 2);
                }
                SHV_LOG("ExecTrapChain: anchor 0x%llX -> target pa=0x%llX va=[0x%llX,0x%llX) direct=%d",
                        GuestLinearVa, chainPa, g_Shv.ExecTrapVaBase, g_Shv.ExecTrapVaEnd, (int)directJump);
                break;
            }
            if (!chainSwapped) {
                SHV_ERR("ExecTrapChain: split PT found but PriBase mismatch pa2mb=0x%llX",
                        chainPa2mb);
                InterlockedExchange64((volatile LONG64*)&g_Shv.ExecTrapChainFired, 0);
            }

            /* ── CRITICAL ORDERING GUARD  ────────────────────────────
             * Stage-1 (this block) and step-2 (below, ~line 3965) are SEQUENTIAL in
             * the SAME handler, gated by CAS(ChainFired,1,0) and CAS(ChainFired,2,1).
             * A successful stage-1 swap leaves ChainFired==1, so without this guard
             * control falls straight through and step-2 executes ON THE SAME FIRE --
             * i.e. still standing at the ANCHOR, reading the anchor's RCX.
             *
             * But `RCX = gsl_base` is only true at preloader+RdxRva. At the anchor RCX
             * is a DllMain EntryPoint, which is why every run logged a "gsl_base" that
             * was not 64KB-aligned: 0x948627F5E0, 0xDC90FFF760, 0x70A85FF440,
             * 0x197BFF770 -- all entry points, none module bases.
             *
             * The directJump path masked this by forcing ChainFired=2 (line ~3952), so
             * disabling directJump exposed it. Step-2 must only ever run on a LATER
             * fire, at the stage-2 site we just armed. */
            if (chainSwapped && !directJump) {
                /* Hand off to step-2 with a state value it ALONE accepts (see
                 * CHAIN_S2_ARMED banner at the step-2 block).  Publishing 10
                 * rather than leaving 1 is what makes the race impossible. */
                InterlockedExchange64((volatile LONG64*)&g_Shv.ExecTrapChainFired,
                                      CHAIN_S2_ARMED);
                SHV_LOG("ExecTrapChain[s1]: stage-2 ARMED at pa=0x%llX va=0x%llX -- step2 deferred "
                        "to a LATER fire at the stage-2 site", chainPa, effectiveTargetVa);
                goto RearmAndConsume;
            }
        }
    }
    /* ── Three-stage chain step 2: ExecTrapChainFired 1→2 (iter#185) ────
     * Fires when RcxRva!=0 and stage-1 has already pivoted (ChainFired==1).
     * At preloader+RdxRva (CALL sub_180002170): GuestRCX = gsl_base.
     * Installs the final exec-trap at gsl_base + RcxRva (verify_with_profile).
     * ExecTrapAutoStop is hardcoded to 1 here so the final trap stops after one hit,
     * regardless of the autostop value passed to setup-rva (which must be 0 so that
     * stage-2 itself does not auto-stop before this chain block runs). */
    /* ── CAS-RACE FIX v2  — DISTINCT STATE VALUES ────────────────
     * THE RACE (measured twice; the v1 RIP guard did NOT stop it):
     *   CPU A: wins CAS(1,0) -> ChainFired==1 -> evaluates the EP filter -> MISS
     *          -> writes ChainFired=0 and leaves.
     *   CPU B: concurrently fails CAS(1,0) (A briefly held 1), falls through to
     *          here, sees ChainFired==1 and wins CAS(2,1) -- running step-2 while
     *          still standing AT THE ANCHOR, reading the anchor's RCX.
     * Measured proof (shvlog11): `[step2] stage2=0x7FFA5461F690` -- that is the
     * ANCHOR VA, and no stage-1 swap line exists anywhere in the log. Origin of
     * every bogus non-64KB-aligned "gsl_base" we have ever logged.
     *
     * WHY v1 FAILED: it required GuestRip == ExecTrapRipFilter, but until stage-1
     * actually swaps, RipFilter still holds the ANCHOR VA (set at chain-enable in
     * exit_dispatch.c). At the anchor that test is TRUE, so the guard was a no-op.
     *
     * THE REAL FIX: ChainFired==1 must mean ONLY "a CPU is inside stage-1 right
     * now" (a mutex). Stage-1 publishes a DISTINCT value, CHAIN_S2_ARMED, and ONLY
     * after a successful swap. Step-2 accepts nothing else, so it is structurally
     * unable to trigger off stage-1's transient mutex value -- no ordering
     * reasoning required. The RIP equality is kept as defence in depth: after the
     * swap RipFilter genuinely IS the stage-2 site. */
    else if (shouldLog &&
             g_Shv.ExecTrapChainEnabled != 0 &&
             g_Shv.ExecTrapChainRcxRva  != 0 &&
             g_ChainStage2Va            != 0 &&
             GuestRip == g_ChainStage2Va &&
             InterlockedCompareExchange64(
                 (volatile LONG64*)&g_Shv.ExecTrapChainFired,
                 CHAIN_S2_DONE, CHAIN_S2_ARMED) == CHAIN_S2_ARMED)
    {
        ULONG64 stage3Va = GuestContext->Rcx + g_Shv.ExecTrapChainRcxRva;
        SHV_LOG("ExecTrapChain[step2]: rcx(gsl_base)=0x%llX + rcxRva=0x%llX -> stage3=0x%llX",
                GuestContext->Rcx, g_Shv.ExecTrapChainRcxRva, stage3Va);

        /* Stage-3 PA resolution.
         * Primary path (iter#187): use ExecTrapChainStage3Pa pre-resolved by Python
         * via LoadLibraryExW(DONT_RESOLVE_DLL_REFERENCES)+NexusDSEFix install+uninstall.
         * gsl.dll is mapped with NtCreateSection(SEC_IMAGE)+NtMapViewOfSection(ViewShare)
         * so its code pages are file-backed shared frames — same PA regardless of which
         * process maps the file.  Python pre-resolves PA[gsl_base+verify_rva] into
         * ExecTrapChainStage3Pa before the game launches; when non-zero it bypasses
         * the dynamic PTE walk (which is permanently disabled on this HW: g_PteBase=0).
         *
         * !!: the "file-backed shared frames - same PA regardless of which
         * process maps the file" premise above is FALSE for these pages.  It holds only
         * for pages never written; gsl.dll RELOCATES and SELF-DECRYPTS, so its code pages
         * are copy-on-write split and the game executes a PRIVATE frame at a different PA
         * than Python's pristine mapping (measured: reporter page 0x373000 differs in
         * 1548/4096 bytes).  A trap on the pre-resolved PA watches a frame nobody
         * executes => hits=0.  So try the LIVE guest-CR3 walk FIRST and only fall back to
         * the pre-resolved value. */
        ULONG64 chainPa3 = g_Shv.ExecTrapChainStage3Pa;
        {
            ULONG64 livePa3 = 0;
            if (ShvTranslateGuestVaLive(GuestCr3, stage3Va, &livePa3) &&
                (livePa3 & ~0xFFFULL) >= 0x1000) {
                if (chainPa3 != 0 && (chainPa3 & ~0xFFFULL) != (livePa3 & ~0xFFFULL)) {
                    SHV_LOG("ExecTrapChain[s3-live]: COW MISMATCH va=0x%llX preresolved=0x%llX "
                            "live=0x%llX -- using LIVE", stage3Va,
                            chainPa3 & ~0xFFFULL, livePa3 & ~0xFFFULL);
                } else {
                    SHV_LOG("ExecTrapChain[s3-live]: va=0x%llX -> PA=0x%llX (guest CR3 walk)",
                            stage3Va, livePa3 & ~0xFFFULL);
                }
                chainPa3 = livePa3;
            } else {
                /* UNCONDITIONAL — see the stage-1 note above. */
                SHV_LOG("ExecTrapChain[s3-live]: WALK FAILED va=0x%llX cr3=0x%llX fail=%ld "
                        "scratchOk=%d (fallback pre-resolved PA=0x%llX -- may be COW-stale)",
                        stage3Va, GuestCr3, g_LastWalkFail, (int)g_RootScratchOk, chainPa3);
            }
            /* Sanity: RCX at the stage-2 site is supposed to be gsl's IMAGE BASE (the callee
             * sub_2170 immediately reads [rcx+0x3c] = e_lfanew).  Windows module bases are always
             * 64KB-aligned. HW run observed RCX=0x948627F5E0 (low16=0xF5E0) => NOT a
             * module base => stage3Va was garbage.  Shout when the premise is violated instead of
             * silently arming a trap on a nonsense address. */
            if ((stage3Va - g_Shv.ExecTrapChainRcxRva) & 0xFFFFULL) {
                SHV_LOG("ExecTrapChain[s3-live]: !! RCX base 0x%llX is NOT 64KB-aligned -- "
                        "'RCX = gsl_base' premise VIOLATED; stage3Va=0x%llX is unreliable",
                        stage3Va - g_Shv.ExecTrapChainRcxRva, stage3Va);
            }
        }
        if (chainPa3 == 0 && g_PteBase != 0) {
            ULONG64 pte_va3 = (ULONG64)g_PteBase + (stage3Va >> 9);
            if (pte_va3 >= 0xFFFF800000000000ULL && pte_va3 <= 0xFFFFFF80FFFFFFFFULL) {
                BOOLEAN guestCr3Loaded3 = FALSE;
                ULONG64 savedCr33 = 0;
                if (stage3Va < 0x8000000000000000ULL) {
                    savedCr33 = __readcr3();
                    __writecr3(GuestCr3);
                    guestCr3Loaded3 = TRUE;
                }
                ULONG64 pte3 = *(volatile ULONG64*)pte_va3;
                if (guestCr3Loaded3) {
                    __writecr3(savedCr33);
                }
                SHV_LOG("ExecTrapChain[s2] PTE pte_va3=0x%llX guestCr3=0x%llX pte3=0x%llX",
                        pte_va3, GuestCr3, pte3);
                if ((pte3 & HPTE_PRESENT) && pte3 >= 0x1000) {
                    chainPa3 = (pte3 & HPTE_LARGE)
                        ? ((pte3 & 0x000FFFFFFFE00000ULL) | (stage3Va & 0x001FF000ULL))
                        : (pte3 & HPTE_PFN_MASK);
                }
            }
        }
        if (chainPa3 < 0x1000) {
            SHV_ERR("ExecTrapChain[step2]: PTE resolve failed va=0x%llX — retry", stage3Va);
            InterlockedExchange64((volatile LONG64*)&g_Shv.ExecTrapChainFired, CHAIN_S2_ARMED);
            goto RearmAndConsume;
        }
        chainPa3 &= ~0xFFFULL;

        ULONG64 chainPa3_2mb  = chainPa3 & ~(EPT_LARGE_PAGE_SIZE - 1ULL);
        ULONG   chainPt3Idx   = EPT_PTE_INDEX(chainPa3);
        BOOLEAN chain3Swapped = FALSE;

        EPT_PTE* chainPriPt3 = ShvEptPrimarySplitFor(chainPa3_2mb);
        if (!chainPriPt3) {
            SHV_ERR("ExecTrapChain[step2]: ShvEptPrimarySplitFor failed pa2mb=0x%llX", chainPa3_2mb);
            InterlockedExchange64((volatile LONG64*)&g_Shv.ExecTrapChainFired, CHAIN_S2_ARMED);
            goto RearmAndConsume;
        }

        for (ULONG _ci3 = 0; _ci3 < g_HookRes.PriCount; _ci3++) {
            if (g_HookRes.PriBase[_ci3] != chainPa3_2mb) continue;

            EPT_PTE _newPte3;
            _newPte3.Value   = g_HookRes.PriPt[_ci3][chainPt3Idx].Value;
            _newPte3.Execute = 0;
            g_HookRes.PriPt[_ci3][chainPt3Idx].Value = _newPte3.Value;

            /* Redirect exec-trap to the final capture target (stage-3). */
            g_Shv.ExecTrapTargetPa  = chainPa3;
            g_Shv.ExecTrapVaBase    = stage3Va;
            g_Shv.ExecTrapVaEnd     = stage3Va + PAGE_SIZE;
            g_Shv.ExecTrapCr3       = g_Shv.ExecTrapChainTargetCr3;
            g_Shv.ExecTrapRipFilter = stage3Va;   /* fire only at verify_with_profile entry */
            InterlockedExchange(&g_Shv.ExecTrapAutoStop,    1);
            InterlockedExchange(&g_Shv.ExecTrapHits,        0);
            InterlockedExchange(&g_Shv.ExecTrapLogIndex,    0);
            InterlockedExchange(&g_Shv.ExecTrapLogTotal,    0);
            InterlockedExchange(&g_Shv.ExecTrapFilteredCr3, 0);
            InterlockedExchange(&g_Shv.ExecTrapFilteredVa,  0);
            InterlockedExchange(&g_Shv.ExecTrapFilteredRip, 0);

            {
                INVEPT_DESCRIPTOR _d3 = { 0, 0 };
                ShvInvept(INVEPT_ALL_CONTEXTS, &_d3);
                InterlockedIncrement(&g_Shv.InveptGeneration);
            }

            chain3Swapped = TRUE;
            SHV_LOG("ExecTrapChain[step2]: stage2=0x%llX → stage3 pa=0x%llX va=0x%llX",
                    GuestLinearVa, chainPa3, stage3Va);
            break;
        }
        if (!chain3Swapped) {
            SHV_ERR("ExecTrapChain[step2]: split PT mismatch pa2mb=0x%llX", chainPa3_2mb);
            InterlockedExchange64((volatile LONG64*)&g_Shv.ExecTrapChainFired, CHAIN_S2_ARMED);
        }
    }

RearmAndConsume:
    /* Temp-restore Execute on the PTE via single-qword store. MTF will
     * re-clear X after the guest executes one instruction.
     * NOTE: do NOT use ExecTrapSavedPteValue here.  After a chain swap the
     * SavedPteValue holds the ANCHOR's original PTE (different PFN/page).
     * Writing it to the chain TARGET's PT slot corrupts the target's PA
     * mapping → cipher executes anchor bytes from target VA → crash/zeros.
     * Instead: read the LIVE PTE and set Execute=1, preserving the correct PFN. */
    {
        ULONG64 pa2mbBase = pageAlignedPa & ~(EPT_LARGE_PAGE_SIZE - 1ULL);
        ULONG   ptIdx     = EPT_PTE_INDEX(pageAlignedPa);

        for (ULONG i = 0; i < g_HookRes.PriCount; i++) {
            if (g_HookRes.PriBase[i] == pa2mbBase) {
                EPT_PTE _livePte;
                _livePte.Value   = g_HookRes.PriPt[i][ptIdx].Value;  /* current PTE (X=0) */
                _livePte.Execute = 1;  /* temp-restore X for the MTF single-step */
                g_HookRes.PriPt[i][ptIdx].Value = _livePte.Value;
                /* If read-trap is also armed on this page, its R=W=X=0
                 * dominates — re-apply after restoring. */
                if (g_Shv.ReadTrapActive &&
                    (pageAlignedPa == (g_Shv.ReadTrapTargetPa & ~0xFFFULL))) {
                    EPT_PTE newPte;
                    newPte.Value = g_Shv.ReadTrapSavedPteValue;
                    newPte.Read    = 0;
                    newPte.Write   = 0;
                    newPte.Execute = 0;
                    g_HookRes.PriPt[i][ptIdx].Value = newPte.Value;
                } else if (g_Shv.WriteTrapActive &&
                           (pageAlignedPa == (g_Shv.WriteTrapTargetPa & ~0xFFFULL))) {
                    g_HookRes.PriPt[i][ptIdx].Write = 0;
                }
                break;
            }
        }
    }

    /* Enable MTF. */
    {
        SIZE_T procBased = 0;
        __vmx_vmread(VMCS_CTRL_PROC_BASED_EXEC, &procBased);
        procBased |= CPU_BASED_MONITOR_TRAP_FLAG;
        __vmx_vmwrite(VMCS_CTRL_PROC_BASED_EXEC, procBased);
    }

    Vcpu->MtfExecTrapRearmPending = TRUE;
    Vcpu->MtfExecTrapHookIndex    = EXEC_TRAP_HOOK_INDEX_SENTINEL;

    return 1;   /* consumed */
}

void ShvEptExecTrapRearm(void)
{
    if (!g_Shv.ExecTrapActive) return;

    ULONG64 pageAlignedPa = g_Shv.ExecTrapTargetPa & ~0xFFFULL;
    ULONG64 pa2mbBase = pageAlignedPa & ~(EPT_LARGE_PAGE_SIZE - 1ULL);
    ULONG   ptIdx     = EPT_PTE_INDEX(pageAlignedPa);

    for (ULONG i = 0; i < g_HookRes.PriCount; i++) {
        if (g_HookRes.PriBase[i] == pa2mbBase) {
            /* Re-clear Execute by reading the CURRENT PTE (not ExecTrapSavedPteValue).
             * After a chain swap, ExecTrapSavedPteValue holds the ANCHOR's original PTE
             * (wrong PFN for the target page).  Reading the live PTE preserves the
             * correct PFN regardless of whether we're on the anchor or chain target. */
            EPT_PTE newPte;
            newPte.Value   = g_HookRes.PriPt[i][ptIdx].Value;
            newPte.Execute = 0;
            g_HookRes.PriPt[i][ptIdx].Value = newPte.Value;
            break;
        }
    }

    if (g_EptState != NULL) {
        ULONG64 eptp = g_EptState->EptPointer.Value;
        if (eptp != 0) {
            INVEPT_DESCRIPTOR desc;
            desc.EptPointer = eptp;
            desc.Reserved = 0;
            ShvInvept(INVEPT_SINGLE_CONTEXT, &desc);
        }
    }
}

/* ── HV-Quality Dump: EPT-Level Page Read ──────────────────────────
 *
 * Reads one 4 KB guest-physical page via the kernel's physical map,
 * bypassing the paged-VA layer. Needed because the target's Themida packer
 * rewrites code pages continuously — a VA-based read can tear, but a
 * PA-based read via MmMapIoSpaceEx gets a stable byte-wise snapshot.
 *
 * GPA == HPA in SentinelHV's identity-mapped EPT, so no GPA→HPA walk
 * is required. MmMapIoSpaceEx handles the physical-to-virtual mapping
 * via the non-paged system pool, and the subsequent RtlCopyMemory
 * reads the page content into the caller's destination buffer.
 */
BOOLEAN
ShvEptReadPhysicalPage(
    _In_  ULONG64 GuestPhysAddr,
    _Out_ PVOID   Dst
)
{
    if (Dst == NULL) {
        return FALSE;
    }

    PHYSICAL_ADDRESS pa;
    pa.QuadPart = (LONGLONG)(GuestPhysAddr & ~0xFFFULL);

    /* MmMapIoSpaceEx maps the physical page into a fresh kernel VA.
     * PAGE_READWRITE is the safe default for arbitrary page types. */
    PVOID src = MmMapIoSpaceEx(pa, PAGE_SIZE, PAGE_READWRITE);
    if (src == NULL) {
        return FALSE;
    }

    __try {
        RtlCopyMemory(Dst, src, PAGE_SIZE);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        MmUnmapIoSpace(src, PAGE_SIZE);
        return FALSE;
    }

    MmUnmapIoSpace(src, PAGE_SIZE);
    return TRUE;
}

/* ── KM Cipher Trap — Split Infrastructure  ────────
 *
 * Dedicated pool of 80 split PTs for the cipher-function exit pages.
 * Modifies the PRIMARY EPT only (cipher functions execute under the
 * primary view; secondary EPT is only active for dual-EPT hook pages).
 * Pattern mirrors the xcap split pool but far lighter (80 × 4KB = 320KB).
 */

#define CIPHER_SPLIT_MAX  CIPHER_TRAP_MAX_SITES   /* 80 */

static EPT_PTE* g_CipherSplitPts[CIPHER_SPLIT_MAX];
static ULONG64  g_CipherSplitPas[CIPHER_SPLIT_MAX];  /* physical PA of each PT */
static ULONG64  g_CipherSplitBase2mb[CIPHER_SPLIT_MAX]; /* 2MB-aligned base */
static ULONG    g_CipherSplitCount;

NTSTATUS
ShvEptCipherPrepareResources(void)
{
    if (g_CipherSplitPts[0] != NULL)
        return STATUS_SUCCESS;  /* already allocated */

    for (ULONG i = 0; i < CIPHER_SPLIT_MAX; i++) {
        g_CipherSplitPts[i] = (EPT_PTE*)ShvAllocateContiguousMemory(sizeof(EPT_PTE) * 512);
        if (!g_CipherSplitPts[i]) {
            SHV_ERR("CipherTrap: split PT alloc failed at slot %lu", i);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        g_CipherSplitPas[i]    = MmGetPhysicalAddress(g_CipherSplitPts[i]).QuadPart;
        g_CipherSplitBase2mb[i] = 0;
    }
    g_CipherSplitCount = 0;
    SHV_LOG("CipherTrap: %u split PT slots allocated (%u KB)",
            CIPHER_SPLIT_MAX, (CIPHER_SPLIT_MAX * 4));
    return STATUS_SUCCESS;
}

EPT_PTE*
ShvEptCipherSplitFor(
    _In_ ULONG64 pa2mbBase
    )
{
    if (g_EptState == NULL || g_CipherSplitPts[0] == NULL)
        return NULL;

    /* Return existing split if already done for this 2MB region. */
    for (ULONG i = 0; i < g_CipherSplitCount; i++) {
        if (g_CipherSplitBase2mb[i] == pa2mbBase)
            return g_CipherSplitPts[i];
    }

    if (g_CipherSplitCount >= CIPHER_SPLIT_MAX)
        return NULL;

    ULONG slot = g_CipherSplitCount;
    EPT_PTE* pt = g_CipherSplitPts[slot];

    ULONG pdptIdx = EPT_PDPT_INDEX(pa2mbBase);
    ULONG pdtIdx  = EPT_PDE_INDEX(pa2mbBase);

    /* Derive memory type from existing 2MB PDE. */
    UCHAR memType = g_EptState->Pdt[pdptIdx][pdtIdx].MemoryType;

    /* Fill with identity-mapped 4KB PTEs (RWX, SuppressVe=1 default). */
    for (ULONG i = 0; i < 512; i++) {
        ULONG64 pa4k = pa2mbBase + (ULONG64)i * PAGE_SIZE;
        pt[i].Value       = 0;
        pt[i].Read        = 1;
        pt[i].Write       = 1;
        pt[i].Execute     = 1;
        pt[i].MemoryType  = memType;
        pt[i].Pfn         = pa4k >> 12;
        pt[i].SuppressVe  = 1;
    }

    /* Replace the 2MB PDE with a pointer to our 4KB PT. */
    EPT_PDE_PTR pdePtr;
    pdePtr.Value   = 0;
    pdePtr.Read    = 1;
    pdePtr.Write   = 1;
    pdePtr.Execute = 1;
    pdePtr.Pfn     = g_CipherSplitPas[slot] >> 12;
    *(volatile ULONG64*)&g_EptState->Pdt[pdptIdx][pdtIdx] = pdePtr.Value;

    g_CipherSplitBase2mb[slot] = pa2mbBase;
    g_CipherSplitCount++;

    return pt;
}

EPT_PTE*
ShvEptCipherFindPte(
    _In_ ULONG64 pa4k
    )
{
    ULONG64 pa2mb = pa4k & ~(ULONG64)0x1FFFFFULL;  /* 2MB-align: clear low 21 bits */
    ULONG pteIdx  = EPT_PTE_INDEX(pa4k);

    for (ULONG i = 0; i < g_CipherSplitCount; i++) {
        if (g_CipherSplitBase2mb[i] == pa2mb)
            return &g_CipherSplitPts[i][pteIdx];
    }
    return NULL;
}
