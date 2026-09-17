/**
 * @file shv_arch.h
 * @brief x64 architecture types: GUEST_CONTEXT, VCPU_DATA, segment descriptors.
 *
 * Defines the core data structures used throughout SentinelHV for CPU state
 * management and per-processor virtualization context:
 *
 *   - **GUEST_CONTEXT**: Register save area populated by the ASM VM-exit stub
 *     on every exit and restored before VMRESUME. Layout must match vmx_asm.asm.
 *
 *   - **SEGMENT_DESCRIPTOR / SEGMENT_DESCRIPTOR_64**: GDT entry structures for
 *     parsing segment bases, limits, and access rights during VMCS configuration.
 *
 *   - **DESCRIPTOR_TABLE_REG**: Packed 10-byte structure matching the hardware
 *     format produced by SGDT/SIDT instructions.
 *
 *   - **VCPU_DATA**: Per-logical-processor virtualization state containing the
 *     VMXON region, VMCS region, MSR bitmap, host stack, physical addresses,
 *     launch state, and saved context for both initial capture and
 *     devirtualization restore.
 *
 *   - **Segment helper functions**: ShvGetSegmentBase, ShvGetSegmentAccessRights,
 *     ShvGetSegmentLimit for translating GDT entries to VMCS format.
 */

#pragma once

#include "shv_platform.h"
#include "shv_vmx.h"

/* ── Guest Context (saved/restored by ASM on every VM-exit) ───────── */

/*
 * Layout must match vmx_asm.asm exactly.
 * Order: RAX RCX RDX RBX RSP RBP RSI RDI R8-R15 RFLAGS RIP
 */
typedef struct _GUEST_CONTEXT {
    ULONG64 Rax;        /* 0x00 */
    ULONG64 Rcx;        /* 0x08 */
    ULONG64 Rdx;        /* 0x10 */
    ULONG64 Rbx;        /* 0x18 */
    ULONG64 Rsp;        /* 0x20 — not used by exit stub (VMCS has it) */
    ULONG64 Rbp;        /* 0x28 */
    ULONG64 Rsi;        /* 0x30 */
    ULONG64 Rdi;        /* 0x38 */
    ULONG64 R8;         /* 0x40 */
    ULONG64 R9;         /* 0x48 */
    ULONG64 R10;        /* 0x50 */
    ULONG64 R11;        /* 0x58 */
    ULONG64 R12;        /* 0x60 */
    ULONG64 R13;        /* 0x68 */
    ULONG64 R14;        /* 0x70 */
    ULONG64 R15;        /* 0x78 */
    ULONG64 Rflags;     /* 0x80 — from capture only */
    ULONG64 Rip;        /* 0x88 — from capture only */
} GUEST_CONTEXT, *PGUEST_CONTEXT;

C_ASSERT(FIELD_OFFSET(GUEST_CONTEXT, Rax) == 0x00);
C_ASSERT(FIELD_OFFSET(GUEST_CONTEXT, R15) == 0x78);
C_ASSERT(FIELD_OFFSET(GUEST_CONTEXT, Rflags) == 0x80);
C_ASSERT(FIELD_OFFSET(GUEST_CONTEXT, Rip) == 0x88);

/* ── Segment Descriptor (GDT entry) ──────────────────────────────── */

#pragma pack(push, 1)
typedef struct _SEGMENT_DESCRIPTOR {
    USHORT  LimitLow;
    USHORT  BaseLow;
    UCHAR   BaseMiddle;
    UCHAR   AccessByte;
    UCHAR   Flags_LimitHigh;   /* bits 0-3 = limit[19:16], bits 4-7 = flags */
    UCHAR   BaseHigh;
} SEGMENT_DESCRIPTOR, *PSEGMENT_DESCRIPTOR;

typedef struct _SEGMENT_DESCRIPTOR_64 {
    USHORT  LimitLow;
    USHORT  BaseLow;
    UCHAR   BaseMiddle;
    UCHAR   AccessByte;
    UCHAR   Flags_LimitHigh;
    UCHAR   BaseHigh;
    ULONG32 BaseUpper;
    ULONG32 Reserved;
} SEGMENT_DESCRIPTOR_64, *PSEGMENT_DESCRIPTOR_64;
#pragma pack(pop)

/* ── Descriptor Table Register ────────────────────────────────────── */

#pragma pack(push, 1)
typedef struct _DESCRIPTOR_TABLE_REG {
    USHORT  Limit;
    ULONG64 Base;
} DESCRIPTOR_TABLE_REG, *PDESCRIPTOR_TABLE_REG;
#pragma pack(pop)

C_ASSERT(sizeof(DESCRIPTOR_TABLE_REG) == 10);

/* ── Per-CPU VCPU Data ────────────────────────────────────────────── */

#define SHV_HOST_STACK_SIZE     0x4000  /* 16 KB */

typedef struct _VCPU_DATA {
    __declspec(align(4096)) VMX_REGION VmxonRegion;
    __declspec(align(4096)) VMX_REGION VmcsRegion;
    __declspec(align(4096)) UCHAR      MsrBitmap[4096];
    /* #VE per-VCPU info area (Intel SDM 25.5.6.1):
     *   [0:31]    VirtualizationException (write-locked when delivering)
     *   [32:63]   reserved
     *   [64:95]   ExitReason (always 48 = EPT violation for #VE)
     *   [96:127]  ExitQualification
     *   [128:191] GuestLinearAddress
     *   [192:255] GuestPhysicalAddress
     *   [256:271] CurrentEptpIndex
     * The CPU sets bits in VirtualizationException when delivering #VE; the
     * in-guest handler must atomically clear it before IRETQ to allow the
     * next #VE to be delivered. If left non-zero, EPT violations on this
     * VCPU degrade silently to vmexit (still safe but defeats the speedup). */
    __declspec(align(4096)) UCHAR      VeInfoArea[4096];
    __declspec(align(16))  UCHAR      HostStack[SHV_HOST_STACK_SIZE];

    ULONG64 VmxonRegionPa;
    ULONG64 VmcsRegionPa;
    ULONG64 MsrBitmapPa;
    ULONG64 VeInfoAreaPa;
    ULONG64 HostStackTop;      /* Points to top of HostStack (stack grows down) */

    BOOLEAN Launched;           /* TRUE after first successful VMLAUNCH */
    BOOLEAN VmxActive;          /* VMX root mode active on this CPU */
    ULONG   ProcessorIndex;

    /* Original state for devirtualization */
    ULONG64 OriginalCr0;
    ULONG64 OriginalCr3;
    ULONG64 OriginalCr4;
    DESCRIPTOR_TABLE_REG OriginalGdtr;
    DESCRIPTOR_TABLE_REG OriginalIdtr;

    /* Capture context for VMLAUNCH */
    GUEST_CONTEXT CapturedContext;

    /* VMCS control fields (saved for diagnostics — readable from guest mode) */
    ULONG32 DiagPinBased;
    ULONG32 DiagProcBased;
    ULONG32 DiagProcBased2;
    ULONG32 DiagExitCtls;
    ULONG32 DiagEntryCtls;

    /* Exit counters (updated from VMX root, read from guest mode) */
    volatile LONG ExitTotal;
    volatile LONG ExitCpuid;
    volatile LONG ExitCrAccess;
    volatile LONG ExitNmi;
    volatile LONG ExitOther;
    volatile LONG ExitLastReason;

    /* MTF single-step state for FIFO EPT read-trap */
    BOOLEAN MtfFifoRearmPending;    /* After MTF exit, re-remove Read bit from FIFO PTE */

    /* MTF single-step state for dual-EPT hook recovery */
    BOOLEAN MtfHookRearmPending;    /* After MTF exit, re-arm INT3 + switch back to primary */
    ULONG   MtfHookIndex;           /* Which hook triggered (index into EptHooks[]) */

    /* DR-trap spoof state: per-VCPU "guest's intended DR0-3".
     * When DR-trap is installed, guest writes to DR0-3 are NOT executed
     * (we preserve our hooked DR0). Instead, the value is saved here. On
     * subsequent reads, we return this saved value (not 0). This defeats
     * Themida's write-then-read-DR0 detection pattern. DR6 and DR7 are
     * always spoofed to clean reset values. */
    ULONG64 GuestIntendedDr[4];     /* DR0..DR3 — what the guest "thinks" it wrote */

    /* MTF single-step state for UM write-trap recovery (Phase C, Apr 2026).
     * Symmetric to MtfHookRearmPending but re-removes W bit on the trapped
     * PTE instead of re-arming an INT3. MtfWriteTrapHookIndex uses the
     * sentinel WRITE_TRAP_HOOK_INDEX_SENTINEL (0xFF) for "filter-only, no
     * log" paths (CR3 / VA / RIP mismatch). Spec §1.5. */
    BOOLEAN MtfWriteTrapRearmPending;
    ULONG   MtfWriteTrapHookIndex;

    /* MTF single-step state for UM read-trap recovery (Phase C-R, Apr 2026).
     * Symmetric to MtfWriteTrapRearmPending but re-clears R/W/X on the
     * trapped PTE via single-qword Value store (see comment in shv.h). */
    BOOLEAN MtfReadTrapRearmPending;
    ULONG   MtfReadTrapHookIndex;

    /* MTF single-step state for KM cipher-trap recovery.
     * After logging a cipher-function ret hit, X is restored, MTF enabled.
     * MTF fires → re-clear X (re-arm). SiteIndex selects which cipher site. */
    BOOLEAN MtfCipherTrapRearmPending;
    ULONG   MtfCipherTrapSiteIndex;

    /* MTF single-step state for UM exec-trap recovery (Phase C-X, Apr 2026).
     * Used when an instruction-fetch EPT violation on the trapped page is
     * handled by ShvEptExecTrapTryHandle: X bit is temporarily restored,
     * MTF fires after the guest executes one instruction in the trapped
     * page, and ShvEptExecTrapRearm re-clears X. Routes MTF to the right
     * primitive when multiple traps are armed simultaneously. */
    BOOLEAN MtfExecTrapRearmPending;
    ULONG   MtfExecTrapHookIndex;

    /* Double-MTF state for resolver decode.
     * 0 = not active (normal hook recovery)
     * 1 = first MTF pending (after resolver RET, at call site)
     * 2 = second MTF pending (after XOR, register has decoded VA)
     * 3 = third MTF pending (extra step for call sites with add rsp) */
    ULONG   MtfResolverStep;
    ULONG64 MtfResolverEcx;        /* ECX hash value from resolver entry */
    ULONG64 MtfResolverTableVal;   /* RAX (encrypted return value) from resolver */

    /* Per-CPU INVEPT generation tracking */
    LONG    LastInveptGeneration;    /* Last synced generation (compared to g_Shv.InveptGeneration) */

    /* RIP-trace single-step state.
     * When a read-trap fires and g_Shv.RipTraceActive==1 + RipTraceArmOnHit==1,
     * this vcpu enters trace mode: every MTF exit logs GuestRip to the global
     * ring and re-enables MTF, stepping through the scanner's Griffin VM
     * execution until StepsMax or RIP leaves the allowed range. */
    BOOLEAN RipTracePending;
} VCPU_DATA, *PVCPU_DATA;

/* ── Segment Helper Functions ─────────────────────────────────────── */

/**
 * @brief Extract the base address from a GDT segment descriptor.
 *
 * Assembles the base address from the descriptor's BaseLow, BaseMiddle,
 * and BaseHigh fields. For system descriptors (S=0) in 64-bit mode (TSS,
 * LDT), extends to a full 64-bit base using the upper 32 bits from the
 * 16-byte descriptor format.
 *
 * @param GdtBase   Linear address of the Global Descriptor Table.
 * @param Selector  Segment selector (index + RPL + TI bits).
 * @return 64-bit segment base address, or 0 for null selectors.
 */
ULONG64
ShvGetSegmentBase(
    _In_ ULONG64 GdtBase,
    _In_ USHORT Selector
    );

/**
 * @brief Get segment access rights in VMCS format from a GDT descriptor.
 *
 * Converts the GDT descriptor's access byte and flags nibble into the
 * VMCS access rights format: bits [7:0] = type/S/DPL/P, bits [15:12] =
 * AVL/L/D-B/G, bit [16] = unusable. Returns 0x10000 (unusable) for null
 * or not-present segments.
 *
 * @param GdtBase   Linear address of the Global Descriptor Table.
 * @param Selector  Segment selector to look up.
 * @return VMCS-format access rights value.
 */
ULONG32
ShvGetSegmentAccessRights(
    _In_ ULONG64 GdtBase,
    _In_ USHORT Selector
    );

/**
 * @brief Get the segment limit from a GDT descriptor.
 *
 * Assembles the 20-bit limit from LimitLow and the lower nibble of
 * Flags_LimitHigh. If the granularity (G) bit is set, the limit is
 * scaled to 4KB pages (shifted left 12, OR'd with 0xFFF).
 *
 * @param GdtBase   Linear address of the Global Descriptor Table.
 * @param Selector  Segment selector to look up.
 * @return Segment limit in bytes.
 */
ULONG32
ShvGetSegmentLimit(
    _In_ ULONG64 GdtBase,
    _In_ USHORT Selector
    );
