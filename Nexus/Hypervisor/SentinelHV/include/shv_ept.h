/**
 * @file shv_ept.h
 * @brief EPT (Extended Page Tables) entry structures, state, and public API.
 *
 * Defines all data structures and constants for Intel EPT, which provides
 * a second layer of address translation (guest-physical to host-physical)
 * under VMX operation:
 *
 *   - **EPT Entry Unions**: PML4E, PDPTE, PDE (2MB large page and pointer
 *     variants), and PTE (4KB) with bitfield layouts matching Intel SDM.
 *
 *   - **EPTP**: EPT Pointer structure written to VMCS, encoding the PML4
 *     physical address, page walk length, and memory type for page walks.
 *
 *   - **MTRR_RANGE_DESCRIPTOR**: Variable-range MTRR entries used to derive
 *     per-page memory types (UC, WB, WT, etc.) for EPT entries.
 *
 *   - **EPT_STATE**: Monolithic allocation containing the full 4-level page
 *     table hierarchy (PML4 + 512 PDPTs + 512x512 PDEs), the constructed
 *     EPTP, and all parsed MTRR state (fixed + variable ranges).
 *
 *   - **EPT Violation Qualification**: Bit masks for decoding the exit
 *     qualification on EPT violation exits.
 *
 * Phase 1 implements a 512 GB identity map using 2MB large pages (262,144
 * entries). Future phases will add 4KB page splitting for selective R/W/X
 * permission control (stealth hooks, memory isolation).
 *
 *   - **INVEPT / INVVPID**: Type constants and descriptor structures for
 *     TLB invalidation of EPT/VPID-tagged entries.
 */

#pragma once

#include "shv_platform.h"

/* ── Memory Type Constants ───────────────────────────────────────── */

#define EPT_MEMORY_TYPE_UC      0   /* Uncacheable */
#define EPT_MEMORY_TYPE_WC      1   /* Write-Combining */
#define EPT_MEMORY_TYPE_WT      4   /* Write-Through */
#define EPT_MEMORY_TYPE_WP      5   /* Write-Protected */
#define EPT_MEMORY_TYPE_WB      6   /* Write-Back */

/* ── INVEPT / INVVPID Types ──────────────────────────────────────── */

#define INVEPT_SINGLE_CONTEXT   1
#define INVEPT_ALL_CONTEXTS     2

#define INVVPID_INDIVIDUAL_ADDR         0
#define INVVPID_SINGLE_CONTEXT          1
#define INVVPID_ALL_CONTEXTS            2
#define INVVPID_SINGLE_CONTEXT_RETAINING_GLOBALS 3

/* ── INVEPT / INVVPID Descriptor ─────────────────────────────────── */

typedef struct _INVEPT_DESCRIPTOR {
    ULONG64 EptPointer;
    ULONG64 Reserved;
} INVEPT_DESCRIPTOR, *PINVEPT_DESCRIPTOR;

typedef struct _INVVPID_DESCRIPTOR {
    ULONG64 Vpid;
    ULONG64 LinearAddress;
} INVVPID_DESCRIPTOR, *PINVVPID_DESCRIPTOR;

/* ── EPT Index Macros ────────────────────────────────────────────── */

/* Extract table indices from a physical address */
#define EPT_PML4_INDEX(pa)   (((pa) >> 39) & 0x1FF)
#define EPT_PDPT_INDEX(pa)   (((pa) >> 30) & 0x1FF)
#define EPT_PDE_INDEX(pa)    (((pa) >> 21) & 0x1FF)
#define EPT_PTE_INDEX(pa)    (((pa) >> 12) & 0x1FF)

/* 2MB large page size */
#define EPT_LARGE_PAGE_SIZE  (2 * 1024 * 1024)

/* ── EPT Entry Structures ────────────────────────────────────────── */

/* PML4 Entry (points to PDPT) */
typedef union _EPT_PML4E {
    ULONG64 Value;
    struct {
        ULONG64 Read        : 1;    /* [0]     */
        ULONG64 Write       : 1;    /* [1]     */
        ULONG64 Execute     : 1;    /* [2]     */
        ULONG64 Reserved0   : 5;    /* [7:3]   */
        ULONG64 Accessed    : 1;    /* [8]     */
        ULONG64 Ignored0    : 1;    /* [9]     */
        ULONG64 ExecuteUser : 1;    /* [10]    */
        ULONG64 Ignored1    : 1;    /* [11]    */
        ULONG64 Pfn         : 40;   /* [51:12] */
        ULONG64 Ignored2    : 12;   /* [63:52] */
    };
} EPT_PML4E, *PEPT_PML4E;

/* PDPT Entry (points to PD table) */
typedef union _EPT_PDPTE {
    ULONG64 Value;
    struct {
        ULONG64 Read        : 1;    /* [0]     */
        ULONG64 Write       : 1;    /* [1]     */
        ULONG64 Execute     : 1;    /* [2]     */
        ULONG64 Reserved0   : 5;    /* [7:3]   */
        ULONG64 Accessed    : 1;    /* [8]     */
        ULONG64 Ignored0    : 1;    /* [9]     */
        ULONG64 ExecuteUser : 1;    /* [10]    */
        ULONG64 Ignored1    : 1;    /* [11]    */
        ULONG64 Pfn         : 40;   /* [51:12] */
        ULONG64 Ignored2    : 12;   /* [63:52] */
    };
} EPT_PDPTE, *PEPT_PDPTE;

/* PDE for 2MB Large Page */
typedef union _EPT_PDE_2MB {
    ULONG64 Value;
    struct {
        ULONG64 Read        : 1;    /* [0]     */
        ULONG64 Write       : 1;    /* [1]     */
        ULONG64 Execute     : 1;    /* [2]     */
        ULONG64 MemoryType  : 3;    /* [5:3]   */
        ULONG64 IgnorePat   : 1;    /* [6]     */
        ULONG64 LargePage   : 1;    /* [7]  must be 1 for 2MB */
        ULONG64 Accessed    : 1;    /* [8]     */
        ULONG64 Dirty       : 1;    /* [9]     */
        ULONG64 ExecuteUser : 1;    /* [10]    */
        ULONG64 Ignored0    : 10;   /* [20:11] */
        ULONG64 Pfn         : 31;   /* [51:21] — 2MB-aligned PFN */
        ULONG64 Ignored1    : 11;   /* [62:52] */
        ULONG64 SuppressVe  : 1;    /* [63] suppress #VE delivery on this PDE */
    };
} EPT_PDE_2MB, *PEPT_PDE_2MB;

/* PDE that points to a PT (for future 4KB splitting) */
typedef union _EPT_PDE_PTR {
    ULONG64 Value;
    struct {
        ULONG64 Read        : 1;    /* [0]     */
        ULONG64 Write       : 1;    /* [1]     */
        ULONG64 Execute     : 1;    /* [2]     */
        ULONG64 Reserved0   : 5;    /* [7:3]   */
        ULONG64 Accessed    : 1;    /* [8]     */
        ULONG64 Ignored0    : 1;    /* [9]     */
        ULONG64 ExecuteUser : 1;    /* [10]    */
        ULONG64 Ignored1    : 1;    /* [11]    */
        ULONG64 Pfn         : 40;   /* [51:12] */
        ULONG64 Ignored2    : 12;   /* [63:52] */
    };
} EPT_PDE_PTR, *PEPT_PDE_PTR;

/* PTE for 4KB page.
 * Bit 63 = SuppressVe per Intel SDM 25.5.6.1: when EPT_VIOLATION_VE is
 * enabled in secondary controls AND a violation hits this PTE, bit 63
 * controls whether the violation is delivered as #VE (bit 63 = 0) or
 * causes a regular vmexit (bit 63 = 1). Used by stealth hooks: clear
 * bit 63 → fast in-guest #VE path (VMFUNC swap, ~30 cycles). Debug
 * hooks set bit 63 → vmexit path (slow but allows full HV inspection). */
typedef union _EPT_PTE {
    ULONG64 Value;
    struct {
        ULONG64 Read        : 1;    /* [0]     */
        ULONG64 Write       : 1;    /* [1]     */
        ULONG64 Execute     : 1;    /* [2]     */
        ULONG64 MemoryType  : 3;    /* [5:3]   */
        ULONG64 IgnorePat   : 1;    /* [6]     */
        ULONG64 Ignored0    : 1;    /* [7]     */
        ULONG64 Accessed    : 1;    /* [8]     */
        ULONG64 Dirty       : 1;    /* [9]     */
        ULONG64 ExecuteUser : 1;    /* [10]    */
        ULONG64 Ignored1    : 1;    /* [11]    */
        ULONG64 Pfn         : 40;   /* [51:12] */
        ULONG64 Ignored2    : 11;   /* [62:52] */
        ULONG64 SuppressVe  : 1;    /* [63] suppress #VE delivery on this PTE */
    };
} EPT_PTE, *PEPT_PTE;

/* ── EPT Pointer (EPTP) ─────────────────────────────────────────── */

typedef union _EPTP {
    ULONG64 Value;
    struct {
        ULONG64 MemoryType      : 3;    /* [2:0]   page walk memory type (6=WB) */
        ULONG64 PageWalkLength  : 3;    /* [5:3]   page walk length minus 1 (3=4-level) */
        ULONG64 AccessedDirty   : 1;    /* [6]     enable accessed/dirty flags */
        ULONG64 Reserved0       : 5;    /* [11:7]  */
        ULONG64 Pfn             : 40;   /* [51:12] PFN of PML4 table */
        ULONG64 Reserved1       : 12;   /* [63:52] */
    };
} EPTP, *PEPTP;

/* ── MTRR Range Descriptor ───────────────────────────────────────── */

#define MAX_MTRR_RANGES     32

typedef struct _MTRR_RANGE_DESCRIPTOR {
    ULONG64 PhysicalBaseAddress;
    ULONG64 PhysicalEndAddress;     /* Exclusive */
    UCHAR   MemoryType;
} MTRR_RANGE_DESCRIPTOR, *PMTRR_RANGE_DESCRIPTOR;

/* ── EPT State (single contiguous allocation) ────────────────────── */

/* PDPTE for 1GB Large Page (used for high memory > 512GB) */
typedef union _EPT_PDPTE_1GB {
    ULONG64 Value;
    struct {
        ULONG64 Read        : 1;    /* [0]     */
        ULONG64 Write       : 1;    /* [1]     */
        ULONG64 Execute     : 1;    /* [2]     */
        ULONG64 MemoryType  : 3;    /* [5:3]   */
        ULONG64 IgnorePat   : 1;    /* [6]     */
        ULONG64 LargePage   : 1;    /* [7]  must be 1 for 1GB */
        ULONG64 Accessed    : 1;    /* [8]     */
        ULONG64 Dirty       : 1;    /* [9]     */
        ULONG64 ExecuteUser : 1;    /* [10]    */
        ULONG64 Ignored0    : 19;   /* [29:11] */
        ULONG64 Pfn         : 22;   /* [51:30] — 1GB-aligned PFN */
        ULONG64 Ignored1    : 11;   /* [62:52] */
        ULONG64 SuppressVe  : 1;    /* [63] suppress #VE delivery on this PDPTE */
    };
} EPT_PDPTE_1GB, *PEPT_PDPTE_1GB;

typedef struct _EPT_STATE {
    __declspec(align(4096)) EPT_PML4E       Pml4[512];
    __declspec(align(4096)) EPT_PDPTE       Pdpt[512];        /* PML4[0]: 2MB pages via PDT */
    __declspec(align(4096)) EPT_PDPTE_1GB   PdptHigh[15][512]; /* PML4[1-15]: 1GB UC pages */
    __declspec(align(4096)) EPT_PDE_2MB     Pdt[512][512];

    EPTP    EptPointer;
    BOOLEAN Initialized;

    /* MTRR data */
    ULONG               MtrrRangeCount;
    MTRR_RANGE_DESCRIPTOR MtrrRanges[MAX_MTRR_RANGES];
    UCHAR               MtrrDefaultType;
    BOOLEAN              MtrrFixedEnabled;
    UCHAR               MtrrFixedRange64K[8];   /* 0x00000-0x7FFFF: 8 x 64KB */
    UCHAR               MtrrFixedRange16K[16];  /* 0x80000-0xBFFFF: 2 MSRs x 8 */
    UCHAR               MtrrFixedRange4K[64];   /* 0xC0000-0xFFFFF: 8 MSRs x 8 */
} EPT_STATE, *PEPT_STATE;

/* ── EPT Violation Exit Qualification Bits ───────────────────────── */

#define EPT_VIOLATION_DATA_READ         (1ULL << 0)
#define EPT_VIOLATION_DATA_WRITE        (1ULL << 1)
#define EPT_VIOLATION_INSTRUCTION_FETCH (1ULL << 2)
#define EPT_VIOLATION_ENTRY_READABLE    (1ULL << 3)
#define EPT_VIOLATION_ENTRY_WRITABLE    (1ULL << 4)
#define EPT_VIOLATION_ENTRY_EXECUTABLE  (1ULL << 5)
#define EPT_VIOLATION_ENTRY_EXEC_USER   (1ULL << 6)
#define EPT_VIOLATION_GLA_VALID         (1ULL << 7)
#define EPT_VIOLATION_GPA_ACCESS        (1ULL << 8)

/* ── Public API ──────────────────────────────────────────────────── */

/**
 * @brief Initialize the EPT subsystem: allocate state, parse MTRRs, build identity map.
 *
 * Allocates a single contiguous EPT_STATE block, reads all MTRR registers to
 * build a memory type map, constructs a 512 GB identity-mapped page table
 * hierarchy with 2MB large pages and MTRR-derived memory types, and builds
 * the EPTP value. Must be called before any VMCS setup. Called once and
 * shared across all VCPUs.
 *
 * @return STATUS_SUCCESS on success, STATUS_INSUFFICIENT_RESOURCES on allocation failure.
 */
NTSTATUS ShvEptInitialize(void);

/**
 * @brief Free the EPT state and page table allocation.
 *
 * Called during devirtualization after all CPUs have exited VMX operation.
 */
void     ShvEptDestroy(void);

/**
 * @brief Get the 64-bit EPTP value for writing to VMCS_CTRL_EPTP.
 *
 * @return The constructed EPTP value, or 0 if EPT is not initialized.
 */
ULONG64  ShvEptGetEptp(void);

/**
 * @brief Split a 2MB EPT page and remap a 4KB page to a shadow buffer.
 *
 * Used for TPM FIFO remapping: splits the 2MB page containing targetPa
 * into 512 x 4KB pages, then remaps the specific 4KB page to shadowPa.
 *
 * @param targetPa   Physical address to remap (4KB-aligned, in PML4[0]).
 * @param shadowPa   Physical address of the shadow buffer.
 * @return STATUS_SUCCESS or error.
 */
NTSTATUS ShvEptRemapPage(_In_ ULONG64 targetPa, _In_ ULONG64 shadowPa);

/**
 * @brief Check whether EPT has been successfully initialized.
 *
 * @return TRUE if EPT state is allocated and ready, FALSE otherwise.
 */
BOOLEAN  ShvEptIsEnabled(void);

/**
 * @brief Read one 4 KB guest-physical page directly via EPT identity map.
 *
 * Maps the guest PA (== host PA in SentinelHV's identity map) into the
 * kernel's physical aperture via MmGetVirtualForPhysical, copies 4096
 * bytes into the destination kernel VA, and returns. The destination
 * must be a present, writable 4 KB page.
 *
 * Used by the HV-quality dump dispatcher (VMCALL_EPT_READ_PAGE) to
 * produce race-free captures of self-modifying pages — the target's Themida
 * packers rewrite code pages continuously, and paged-VA reads can tear.
 * An EPT-level read sees the physical byte content at the instant of
 * capture, bypassing the guest's page-protection state entirely.
 *
 * @param GuestPhysAddr  Guest physical address (page-aligned masking applied).
 * @param Dst            Kernel VA of the 4 KB destination buffer.
 * @return TRUE if the copy succeeded, FALSE if the PA is unbacked.
 */
BOOLEAN  ShvEptReadPhysicalPage(ULONG64 GuestPhysAddr, PVOID Dst);

/**
 * VMX-root safe LIVE guest VA -> PA translation.
 *
 * 4-level walk (PML4->PDPT->PD->PT) of the guest's OWN page tables using the live
 * GuestCr3, reading each level via MmMapIoSpaceEx (8 bytes only, no scratch buffer)
 * -- NOT DirectMapBase and NOT the PTE_BASE self-map, both disabled on this HW.
 *
 * Use this instead of any pre-resolved PA: a PA resolved by mapping the same file in
 * another process is only valid for pages never written, and gsl.dll relocates and
 * self-decrypts, so its pages are copy-on-write split and the guest executes a
 * PRIVATE frame at a different PA. Walking the guest's own tables returns whatever
 * frame is actually mapped now, COW copy included.
 *
 * @param GuestCr3  Live guest CR3 (from the VMCS at exit time).
 * @param Va        Guest virtual address (user or kernel).
 * @param OutPa     Receives full PA including in-page byte offset.
 * @return TRUE on success; FALSE if any level is not-present (fails closed).
 */
BOOLEAN  ShvTranslateGuestVaLive(ULONG64 GuestCr3, ULONG64 Va, PULONG64 OutPa);

/* Clear the "stage-2 page was not resident, retry the walk" state.  MUST be
 * called whenever the chain is (re-)enabled, so a VA left over from a previous
 * capture run can never bypass the EP/reason filter in a new one. */
VOID     ShvEptChainResetPending(void);

/* Release the VMX-root physical-read window (restore PTE, unmap, free).
 * MUST be called only AFTER all CPUs are devirtualized. */
VOID     ShvRootScratchTeardown(void);

/* Arm the chain at a known stage-2 pivot VA, skipping stage-1.  Called from the
 * image-load notify (PASSIVE_LEVEL, before the module's DllMain runs). */
VOID     ShvEptChainSetStage2(ULONG64 Stage2Va);

/** Initialize secondary EPT (built from scratch, independent page tables). */
NTSTATUS ShvEptInitializeSecondary(void);

/** Get secondary EPTP value (0 if not initialized). */
ULONG64  ShvEptGetSecondaryEptp(void);

/**
 * @brief Enable or disable the EPT read-trap on the TPM FIFO page.
 *
 * When enabled, removes the Read bit from the FIFO 4KB PTE in the split
 * page table, causing EPT violations on guest reads. The violation handler
 * logs the access, temporarily restores Read, enables MTF for single-step,
 * and re-traps after the instruction completes.
 *
 * When disabled, restores the Read bit so guest FIFO reads proceed silently.
 *
 * Requires that ShvEptRemapPage has already been called for TPM_FIFO_PA
 * (the 2MB page must be split and g_TpmSplitPt[0] must exist).
 *
 * Issues INVEPT to flush stale TLB entries after modifying the PTE.
 * Must be called from VMX root mode (inside a VMCALL handler) or while
 * the hypervisor is not yet active.
 *
 * @param Enable  TRUE to arm the trap (remove Read), FALSE to disarm.
 * @return STATUS_SUCCESS or STATUS_UNSUCCESSFUL if EPT/split not ready.
 */
NTSTATUS ShvEptTrapFifoPage(_In_ BOOLEAN Enable);

/**
 * @brief Temporarily restore Read permission on the FIFO EPT PTE.
 *
 * Called from the EPT violation handler to allow the faulting instruction
 * to complete via MTF single-step. Does NOT issue INVEPT (the EPT violation
 * handler runs in VMX root with the current TLB already flushed for this GPA).
 */
void ShvEptFifoRestoreRead(void);

/**
 * @brief Re-remove Read permission on the FIFO EPT PTE (re-arm the trap).
 *
 * Called from the MTF exit handler after the single-stepped instruction
 * has completed. Issues INVEPT to ensure the trap is immediately effective.
 */
void ShvEptFifoRemoveRead(void);

/**
 * @brief Pre-allocate resources for dual-EPT hook installation.
 *
 * Must be called from guest kernel context (PASSIVE_LEVEL) after secondary
 * EPT has been initialized. Pre-allocates split page tables and shadow pages
 * so that ShvEptInstallHook can run from VMX root without kernel allocations.
 *
 * @return STATUS_SUCCESS or STATUS_INSUFFICIENT_RESOURCES.
 */
NTSTATUS ShvEptPrepareHookResources(void);

/**
 * @brief Install a dual-EPT INT3 hook on a target function.
 *
 * Called from VMX root (exit_dispatch polling). Splits the target 2MB page
 * in both primary and secondary EPTs, copies the original page to a shadow
 * buffer, writes INT3, and sets permissions:
 *   - Primary:   hooked page RW, no Execute (forces EPT switch to secondary)
 *   - Secondary: hooked page Execute-only, PFN = shadow (INT3 hit → #BP exit)
 *
 * @param TargetVa  Guest VA of the function to hook.
 * @param TargetPa  Guest PA of the function (caller resolved).
 * @return STATUS_SUCCESS or error.
 */
NTSTATUS ShvEptInstallHook(_In_ ULONG64 TargetVa, _In_ ULONG64 TargetPa);

/* ---- Xcap (execute-trap page capture) EPT functions ---- */

/** Pre-allocate xcap buffers (metadata + 24MB page data). PASSIVE_LEVEL. */
NTSTATUS ShvEptPrepareXcapResources(void);

/** Install xcap traps on the VA range using PAs already in g_Shv.XcapPaTable.
 *  IsRetrap=FALSE: fresh arm — reset bitmap, captured/violation/cr3-mismatch
 *                  counters, restore Execute on any leftover trapped PTEs from
 *                  prior sessions, then install fresh traps.
 *  IsRetrap=TRUE:  re-trap (e.g. after PE relocations cause COW) — restore
 *                  Execute on prior trapped PTEs (orphaned PAs) but keep the
 *                  bitmap and counters so prior captures accumulate. */
void ShvEptXcapWalkAndTrap(
    _In_ ULONG64 Cr3,
    _In_ ULONG64 VaBase,
    _In_ ULONG64 VaEnd,
    _In_ BOOLEAN IsRetrap
);

/** Restore Execute on a single xcap-trapped PTE. VMX root. */
void ShvEptXcapRestoreExecuteByPa(_In_ ULONG64 Pa);

/** Re-remove Execute on a single xcap PTE (re-arm after wrong-CR3). VMX root. */
void ShvEptXcapRemoveExecuteByPa(_In_ ULONG64 Pa);

/** Restore all xcap traps and free resources. PASSIVE_LEVEL. */
void ShvEptXcapDestroy(void);

/**
 * @brief Diagnostic probe — returns the live Execute bit of the EPT PTE
 *        corresponding to XcapPaTable[Index], or 0xFF if no such split.
 *
 * Used to verify that ShvEptXcapWalkAndTrap actually persisted Execute=0
 * into the live EPT structure. If install reports trapped pages but this
 * probe returns 1, our PTE writes are being lost or reverted somewhere
 * between the install and the read-back.
 */
ULONG ShvEptXcapProbePtaTableExecute(_In_ ULONG Index);

/** Returns the number of populated 2 MB split table entries (g_XcapSplitCount). */
ULONG ShvEptXcapGetSplitCount(void);

/** Counts non-zero entries in g_XcapSplitBase2mb, independently of the counter.
 *  Used to verify whether the slot table itself is populated when the counter
 *  reads 0. */
ULONG ShvEptXcapCountFilledSplits(void);

/** Returns the live runtime address of g_Shv.XcapSplitCount. */
ULONG64 ShvEptXcapGetSplitCountAddr(void);

/** Returns g_XcapSplitBase2mb[Index] (or 0 if out of range). */
ULONG64 ShvEptXcapGetSplitBase2mb(_In_ ULONG Index);

/** Returns the live raw qword in g_EptState->Pdt for XcapPaTable[Index]'s 2MB region. */
ULONG64 ShvEptXcapGetLivePdeFor(_In_ ULONG Index);

/** Returns the live raw qword for XcapPaTable[Index]'s split PT entry. */
ULONG64 ShvEptXcapGetLivePtEntryFor(_In_ ULONG Index);

/** Returns MmGetPhysicalAddress(g_EptState->Pml4) for cross-checking against VMCS EPTP. */
ULONG64 ShvEptXcapGetPml4Pa(void);

/**
 * @brief Try to capture an xcap-trapped page from the EPT violation handler.
 *
 * Called from VMX root inside ShvHandleEptViolation. If the faulting GPA
 * belongs to an active xcap session, copies the page contents into the
 * pre-allocated XcapPageData buffer, fills the corresponding XCAP_ENTRY,
 * sets the bitmap bit, restores Execute on the PTE, and INVEPTs.
 *
 * @return 1 if the violation was handled (caller must NOT inject #GP and
 *         must NOT advance RIP — guest will re-execute and succeed),
 *         0 if the page is not xcap-related (caller continues normally).
 */
ULONG ShvEptXcapTryCapture(
    _In_ ULONG64 GuestPa,
    _In_ ULONG64 GuestVa,
    _In_ ULONG64 GuestRip,
    _In_ ULONG64 GuestCr3,
    _In_ ULONG  CpuIndex
    );

/* ── UM EPT Write-Trap (Phase C, Apr 2026) ─────────────────────────
 * Spec: tools/the design notes
 * Day 1 deliverables: declarations + skeleton stubs returning NOT_IMPLEMENTED.
 * Day 2+ fills in secondary-EPT page split, W-bit manipulation, MTF re-arm. */

/**
 * @brief Pre-allocate the write-trap log ring. PASSIVE_LEVEL, guest context.
 *
 * Allocates 512 KB (WRITE_TRAP_LOG_MAX * sizeof(WRITE_TRAP_LOG_ENTRY))
 * from NonPagedPoolNx and stashes the pointer in g_Shv.WriteTrapLog.
 * Idempotent: safe to call multiple times.
 *
 * @return STATUS_SUCCESS or STATUS_INSUFFICIENT_RESOURCES.
 */
NTSTATUS ShvEptPrepareWriteTrapResources(void);

/**
 * @brief Install a UM-scoped write-trap on the given page PA. VMX root.
 *
 * Splits the secondary EPT 2 MB page containing TargetPa into 4 KB PTEs
 * (if not already split), clears the W bit on the 4 KB PTE for TargetPa,
 * and INVEPTs single-context on the secondary EPTP. Populates
 * g_Shv.WriteTrap{Cr3,VaBase,VaEnd,TargetPa,RipFilter} and flips
 * WriteTrapActive to 1 last. Sub-page VA filter is enforced in the
 * violation handler (spec §1.3).
 *
 * @param Cr3        Target process CR3 (kernel side resolved via
 *                   PsLookupProcessByProcessId + KPROCESS.DirectoryTableBase).
 * @param TargetPa   4 KB-aligned guest PA of the page to trap.
 * @param VaBase     Inclusive low bound of the UM VA range (sub-page filter).
 * @param VaEnd      Exclusive high bound.
 * @param RipFilter  0 = log every in-range writer; non-0 = only that RIP.
 * @return STATUS_SUCCESS or STATUS_NOT_IMPLEMENTED (Day 1 stub).
 */
NTSTATUS ShvEptInstallWriteTrap(
    _In_ ULONG64 Cr3,
    _In_ ULONG64 TargetPa,
    _In_ ULONG64 VaBase,
    _In_ ULONG64 VaEnd,
    _In_ ULONG64 RipFilter
    );

/**
 * @brief Disarm the write-trap and restore full R/W/X on the target PTE.
 *
 * Sets g_Shv.WriteTrapActive = 0 FIRST so no new violations are logged,
 * then restores the PTE W bit, INVEPTs all-contexts on the secondary EPTP,
 * and bumps g_Shv.InveptGeneration. VMX root. Zero-hit over 30 seconds
 * post-uninstall is the reversibility gate (spec §5 test plan).
 *
 * @return STATUS_SUCCESS or STATUS_NOT_IMPLEMENTED (Day 1 stub).
 */
NTSTATUS ShvEptUninstallWriteTrap(void);

/**
 * @brief Violation-handler classifier for writes on the trapped page.
 *
 * Called from ShvHandleEptViolation when the faulting GPA matches
 * WriteTrapTargetPa. Applies CR3 / VA-range / RIP filters (spec §2.3),
 * logs or skips accordingly, and returns the action the caller must take.
 *
 * Returns 0 = not a write-trap event (caller continues normal fallthrough),
 *         1 = event consumed; caller MUST set MtfWriteTrapRearmPending
 *             and enable MTF before resuming. Logging / counters already
 *             handled inside this function.
 */
/**
 * @brief Re-remove W bit after MTF single-step completes.
 *
 * Paired with the temporary W=1 restore inside ShvEptWriteTrapTryHandle.
 * Called from ShvHandleMtfExit when Vcpu->MtfWriteTrapRearmPending is set.
 * INVEPTs single-context on the primary EPTP so the next guest write
 * faults again.
 */
void ShvEptWriteTrapRearm(void);

struct _VCPU_DATA;  /* fwd decl; full definition in shv_arch.h */
ULONG ShvEptWriteTrapTryHandle(
    _In_ ULONG64 GuestPa,
    _In_ ULONG64 GuestLinearVa,
    _In_ ULONG64 GuestRip,
    _In_ ULONG64 GuestCr3,
    _In_ ULONG64 ExitQualification,
    _In_ ULONG   CpuIndex,
    _In_ struct _VCPU_DATA *Vcpu
    );

/* ── UM EPT Read-Trap (Phase C-R, Apr 2026) ─────────────────────────────
 * Parallels the write-trap but clears R/W/X on the target PTE via a
 * single-qword Value store (Intel EPT treats R=0,W=1 as reserved, so
 * we cannot flip R alone). Violation handler classifies the exit
 * qualification and only logs pure data-reads; writes and instruction
 * fetches on the trapped page get silent MTF re-arm.
 */
NTSTATUS ShvEptPrepareReadTrapResources(void);

/* Pre-allocate RIP-trace log ring.
 * Called once at HV init. 256 KB NonPagedPool. */
NTSTATUS ShvEptPrepareRipTraceResources(void);

NTSTATUS ShvEptInstallReadTrap(
    _In_ ULONG64 Cr3,
    _In_ ULONG64 TargetPa,
    _In_ ULONG64 VaBase,
    _In_ ULONG64 VaEnd,
    _In_ ULONG64 RipFilter
    );

NTSTATUS ShvEptUninstallReadTrap(void);

ULONG ShvEptReadTrapTryHandle(
    _In_ ULONG64 GuestPa,
    _In_ ULONG64 GuestLinearVa,
    _In_ ULONG64 GuestRip,
    _In_ ULONG64 GuestCr3,
    _In_ ULONG64 ExitQualification,
    _In_ ULONG   CpuIndex,
    _In_ struct _VCPU_DATA *Vcpu
    );

void ShvEptReadTrapRearm(void);

/* ── UM EPT Exec-Trap (Phase C-X, Apr 2026) ────────────────────────────
 * Parallel to read-trap, clears only Execute on the target PTE. Fires on
 * instruction-fetch violations. Used to capture post-memcpy dispatcher
 * landing RIPs without burning the MTF budget inside memcpy itself.
 */
NTSTATUS ShvEptPrepareExecTrapResources(void);

NTSTATUS ShvEptInstallExecTrap(
    _In_ ULONG64 Cr3,
    _In_ ULONG64 TargetPa,
    _In_ ULONG64 VaBase,
    _In_ ULONG64 VaEnd,
    _In_ ULONG64 RipFilter
    );

NTSTATUS ShvEptUninstallExecTrap(void);

ULONG ShvEptExecTrapTryHandle(
    _In_ ULONG64 GuestPa,
    _In_ ULONG64 GuestLinearVa,
    _In_ ULONG64 GuestRip,
    _In_ ULONG64 GuestCr3,
    _In_ ULONG64 ExitQualification,
    _In_ ULONG   CpuIndex,
    _In_ struct _VCPU_DATA *Vcpu,
    _In_opt_ struct _GUEST_CONTEXT *GuestContext
    );

void ShvEptExecTrapRearm(void);

/* ── KM Cipher Trap — EPT split infrastructure  ──
 * Dedicated split pool for the 80 cipher-function exit pages.
 * Modifies the PRIMARY EPT (cipher functions run under the primary view).
 * Pre-allocate at PASSIVE_LEVEL; split + find-PTE from VMX root. */

/** Pre-allocate 80 split PT slots for cipher traps. PASSIVE_LEVEL. */
NTSTATUS ShvEptCipherPrepareResources(void);

/**
 * @brief Find or create a 2MB→4KB split in the primary EPT for cipher trap.
 * @param pa2mbBase  2MB-aligned physical address to split.
 * @return Pointer to the 512-entry 4KB PT, or NULL if out of resources.
 */
EPT_PTE* ShvEptCipherSplitFor(_In_ ULONG64 pa2mbBase);

/**
 * @brief Find the EPT_PTE for a specific 4KB PA in the cipher split pool.
 * @param pa4k  4KB-aligned physical address.
 * @return Pointer to the PTE, or NULL if not in any cipher split.
 */
EPT_PTE* ShvEptCipherFindPte(_In_ ULONG64 pa4k);

/* ── KM Cipher Trap — main pipeline  ────────────── */

/** Pre-allocate cipher record ring buffer. PASSIVE_LEVEL. */
NTSTATUS ShvCipherTrapPrepareResources(void);

/**
 * @brief Install EPT exec-traps on all 80 cipher function exit pages.
 * Called from VMX root via PendingCipherTrapOp.
 * @param KmBase  target KM image base VA.
 * @param KmSize  target KM image size in bytes.
 */
NTSTATUS ShvCipherTrapInstall(_In_ ULONG64 KmBase, _In_ ULONG64 KmSize);

/** Uninstall all cipher exec-traps and clear state. VMX root. */
void ShvCipherTrapUninstall(void);

/**
 * @brief EPT violation handler for cipher trap pages.
 * @return 1 if consumed (handled), 0 to continue normal dispatch.
 */
ULONG ShvCipherTrapTryHandle(
    _In_ ULONG64 GuestPa,
    _In_ ULONG64 GuestRip,
    _In_ ULONG64 GuestCr3,
    _In_ ULONG64 ExitQualification,
    _In_ ULONG   CpuIndex,
    _In_ struct _VCPU_DATA *Vcpu,
    _In_ struct _GUEST_CONTEXT *GuestContext
    );

/** Re-arm a cipher exec-trap after MTF single-step. VMX root. */
void ShvCipherTrapRearm(_In_ struct _VCPU_DATA *Vcpu);

/** Set per-site skip mask (sites with bit set are trapped but not logged). VMX root. */
VOID ShvCipherTrapSetSkipMask(_In_ ULONG64 maskLo, _In_ ULONG64 maskHi);
