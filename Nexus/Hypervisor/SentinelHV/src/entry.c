/**
 * @file entry.c
 * @brief Driver entry point, unload routine, and IPI-based virtualization dispatch.
 *
 * Implements the WDM driver lifecycle for SentinelHV's Type 2 (hosted) build.
 * DriverEntry creates the device object, validates VMX support, allocates
 * per-CPU VCPU structures, and virtualizes all logical processors via
 * KeIpiGenericCall. The unload routine reverses this by issuing devirtualize
 * VMCALLs on each CPU and freeing all resources.
 *
 * The IPI callbacks run at DISPATCH_LEVEL on each logical processor:
 *   - ShvVirtualizeIpiCallback: Calls ShvVirtualizeProcessor (VMXON through VMLAUNCH).
 *   - ShvDevirtualizeIpiCallback: Issues VMCALL(DEVIRTUALIZE) to exit VMX.
 *
 * This file also defines the global SHV_GLOBAL state (g_Shv) that holds the
 * VCPU array, processor count, VMX revision ID, and active flag.
 */

#include "shv.h"

/* TPM FIFO physical address targeted by the observed software (0xFED10000) */
#define TPM_FIFO_PA     0xFED10000ULL
#define TPM_FIFO_SIZE   0x1000

/* TPM CRB physical address (0xFED40000) -- 2 refs in .grfn22 */
#define TPM_CRB_PA      0xFED40000ULL
#define TPM_CRB_SIZE    0x1000

/* Global hypervisor state */
SHV_GLOBAL g_Shv = { 0 };

/**
 * @brief MacSeed for deterministic TPM identity spoofing.
 *
 * Set by the mapper (NexusCore) after locating this symbol in the PE
 * export table. If non-zero, used to derive spoofed TPM FIFO identity
 * registers. Falls back to a hardcoded seed if the mapper doesn't set it.
 */
__declspec(dllexport) volatile UINT64 g_MacSeed = 0;

/* Device name */
static const UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\SentinelHV");

/* ── Forward Declarations ─────────────────────────────────────────── */

static DRIVER_UNLOAD ShvDriverUnload;
NTSTATUS ShvVeInstall(void);
VOID     ShvVeUninstall(void);


/* ── #VE Handler Code Stub (item #9) ─────────────────────────────────
 *
 * In-guest handler for vector 20 (Virtualization Exception). Invoked by
 * the CPU when EPT violation occurs on a PTE with SuppressVe=0 and
 * VMCS.SECONDARY_PROC_BASED_CTLS.EPT_VIOLATION_VE=1.
 *
 * Layout per Intel SDM 25.5.6.1:
 *   The CPU has already pushed SS, RSP, RFLAGS, CS, RIP onto the guest
 *   kernel stack. We must NOT push an error code — #VE doesn't have one.
 *
 * Strategy: minimal handler. The fact that we got here means an EPT
 * view-mismatch — guest tried to read EPT-B (X-only) or execute EPT-A
 * (R-only). Resolution: VMFUNC EPTP-switching to the OTHER EPTP. After
 * the swap, IRETQ retries the original instruction on the new view; if
 * the access is now valid, guest proceeds; if it triggers another
 * mismatch (rare during legitimate access), we'll re-enter and swap back.
 *
 * The handler must:
 *   1. Save RAX, RCX, RDX (VMFUNC clobbers RAX, we use RCX/RDX).
 *   2. Read VMCS-supplied per-VCPU VeInfoArea via GS:[0] convention —
 *      simpler approach: use a flat global pointer table indexed by
 *      KeGetCurrentProcessorNumberEx-equivalent (PCR.Self).
 *      Even simpler: the CPU writes the *current EPTP index* into
 *      VeInfoArea+0x18 [bits 271:256]. We just toggle index 0<->1.
 *   3. Atomically clear VeInfoArea+0 (re-entry gate, low DWORD).
 *   4. Restore RAX, RCX, RDX.
 *   5. IRETQ.
 *
 * Encoded as raw machine code so we don't need a separate .asm file
 * and a vcxproj rule. Contains exactly the bytes for:
 *
 *   pushq  %rax
 *   pushq  %rcx
 *   pushq  %rdx
 *   pushq  %r10                      ; we'll use r10 to load info-area
 *
 *   ; Load this CPU's PCR.Self → r10 = KPCR. KPCR has the per-CPU
 *   ; VeInfoArea pointer at offset KPCR_VEINFO_OFFSET (we patch this
 *   ; offset at install-time after computing it from the live KPCR).
 *   ;
 *   ; For the first-cut implementation, we take a simpler route:
 *   ; the handler reads VeInfoArea via the FIXED KERNEL VA we stamp
 *   ; into the handler image at install time. This means each VCPU
 *   ; needs its OWN copy of the handler page with its own VeInfoArea
 *   ; address baked in. That's expensive (one page per VCPU * many).
 *   ;
 *   ; Compromise: single shared handler page. CPU index dispatched
 *   ; via __readgsqword(0x20) [KPCR.Self] then index into a global
 *   ; pointer table (g_Shv.VeInfoAreaTable[]) we populate at install.
 *
 *   movabs $g_Shv.VeInfoAreaTable, %r10  ; mov r10, imm64
 *   movq   %gs:0x184, %rax              ; KPCR.PrcbData.Number (CPU index, 0..N)
 *   movzwl %ax, %eax                    ; clamp to 16 bits (paranoia)
 *   movq   (%r10, %rax, 8), %r10        ; r10 = VeInfoAreaTable[cpu]
 *
 *   ; r10 = ptr to this CPU's VeInfoArea
 *   ; Read CurrentEptpIndex at offset 0x18 (low 16 bits)
 *   movzwl 0x18(%r10), %eax
 *   xor    $1, %eax                     ; toggle 0<->1
 *
 *   ; Issue VMFUNC leaf 0 (EPTP switching) with new index in ECX.
 *   movl   %eax, %ecx
 *   xor    %eax, %eax                   ; eax = 0 (VMFUNC leaf)
 *   .byte  0x0F, 0x01, 0xD4             ; vmfunc
 *
 *   ; Atomically clear VeInfoArea+0 (re-entry gate, 32-bit) so the next
 *   ; #VE on this VCPU can be delivered.
 *   movl   $0, (%r10)                   ; mov dword ptr [r10], 0
 *   ; (xchg/lock not strictly needed — single-CPU access since this is
 *   ; per-VCPU, but use mfence for ordering.)
 *   mfence
 *
 *   popq   %r10
 *   popq   %rdx
 *   popq   %rcx
 *   popq   %rax
 *   iretq
 *
 * The encoded bytes below correspond to the above. The 8-byte qword at
 * offset VE_HANDLER_TABLE_PATCH_OFFSET is patched by ShvVeInstall to
 * the kernel VA of g_Shv.VeInfoAreaTable. */
static const UCHAR g_VeHandlerStub[] = {
    /* push rax / rcx / rdx / r10 */
    0x50,                               /* push rax */
    0x51,                               /* push rcx */
    0x52,                               /* push rdx */
    0x41, 0x52,                         /* push r10 */

    /* movabs r10, imm64  (10 bytes; imm64 patched at install) */
    0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    /* mov eax, gs:[0x184]  (KPCR.PrcbData.Number on x64 NT) */
    0x65, 0x8B, 0x04, 0x25, 0x84, 0x01, 0x00, 0x00,

    /* movzx eax, ax */
    0x0F, 0xB7, 0xC0,

    /* mov r10, [r10 + rax*8]  (REX byte = 0x4D: W=1, R=1, X=0, B=1).
     * IMPORTANT: the X bit of REX is the SIB index extension. With X=0
     * the SIB index is RAX (encoded as 000). With X=1 it would extend
     * to R8, which is wrong — the BSOD on first --load-driver was
     * caused by REX=0x4F (X=1) loading an uninitialized R8 as the
     * index, leading to a bogus pointer dereference and IRETQ into
     * our own .rdata. */
    0x4D, 0x8B, 0x14, 0xC2,

    /* movzx eax, word ptr [r10 + 0x18] */
    0x41, 0x0F, 0xB7, 0x42, 0x18,

    /* xor eax, 1 */
    0x83, 0xF0, 0x01,

    /* mov ecx, eax */
    0x89, 0xC1,

    /* xor eax, eax */
    0x31, 0xC0,

    /* vmfunc */
    0x0F, 0x01, 0xD4,

    /* mov dword ptr [r10], 0 */
    0x41, 0xC7, 0x02, 0x00, 0x00, 0x00, 0x00,

    /* mfence  (0F AE F0) */
    0x0F, 0xAE, 0xF0,

    /* pop r10 / rdx / rcx / rax */
    0x41, 0x5A,                         /* pop r10 */
    0x5A,                               /* pop rdx */
    0x59,                               /* pop rcx */
    0x58,                               /* pop rax */

    /* iretq */
    0x48, 0xCF
};
#define VE_HANDLER_TABLE_PATCH_OFFSET   7   /* offset of imm64 inside movabs */
#define VE_HANDLER_STUB_LEN             (sizeof(g_VeHandlerStub))


/* ── #VE Install / Uninstall ────────────────────────────────────────
 *
 * Installs:
 *   - Allocates 4 KB executable kernel page for the handler stub.
 *   - Copies stub bytes; patches imm64 to point at g_Shv.VeInfoAreaTable.
 *   - Allocates VeInfoAreaTable[ProcessorCount] from NonPagedPool.
 *   - Populates table with each VCPU's VeInfoArea kernel VA.
 *   - Reads live IDTR via SIDT (per-CPU but they all point at the
 *     ntoskrnl shared IDT in Windows), patches IDT[20] = handler VA.
 *
 * Notes:
 *   - All CPUs share the same IDT in Windows so a single patch applies
 *     globally. This is also the SGDT/SIDT exposure surface — but
 *     Javelin already reads our shared IDT base in 263 SGDT sites
 *     (KM scan), and they don't enumerate per-vector handlers in the
 *     evidence we have.
 *   - Stub uses NonPagedPoolNx but mapped executable via the standard
 *     kernel pool (we'll request from MmAllocateNxPool with
 *     RtlSetImageMitigationPolicy bypass — actually NonPagedPoolNx does
 *     NOT set NX on the page, despite the name; Windows historic naming
 *     vs SDM. We use ExAllocatePool2 with POOL_FLAG_NON_PAGED_EXECUTE).
 *   - Stub is ~70 bytes; rest of the page is zeroed.
 */

#include <ntddk.h>
extern PUCHAR* g_VeInfoAreaTablePtr;     /* fwd, defined below */
PUCHAR g_VeInfoAreaTable[256] = { 0 };   /* up to 256 VCPUs */
PUCHAR* g_VeInfoAreaTablePtr = (PUCHAR*)g_VeInfoAreaTable;

/* IDT entry layout (x64) — 16 bytes. */
#pragma pack(push, 1)
typedef struct _IDT_ENTRY_X64 {
    USHORT  OffsetLow;
    USHORT  Selector;
    UCHAR   IstIndex;       /* low 3 bits = IST */
    UCHAR   TypeAttr;       /* P|DPL|0|TYPE */
    USHORT  OffsetMiddle;
    ULONG32 OffsetHigh;
    ULONG32 Reserved;
} IDT_ENTRY_X64, *PIDT_ENTRY_X64;
#pragma pack(pop)

C_ASSERT(sizeof(IDT_ENTRY_X64) == 16);


/* ── #VE Install Experiment Mode  ────────────────────────
 *
 * After 4 BSODs at constant module-RVA 0x11C15 in a non-SentinelHV Win11
 * kernel module, the failure is somewhere in the IDT-install path. To
 * isolate the cause, ShvVeInstall now runs in one of three phases
 * controlled by VE_EXP_PHASE:
 *
 *   Phase 1 (default — SAFE): SIDT + read IDT[20] + log original handler
 *           VA. DO NOT allocate, DO NOT patch. If this BSODs, the SIDT
 *           or IDT-read itself is the issue (very unlikely).
 *
 *   Phase 2 (TESTS IDT-WRITE): Phase 1 + allocate executable page +
 *           write minimal IRETQ-only stub (2 bytes: 0x48 0xCF) + patch
 *           IDT[20] to point at it. If Phase 1 succeeded but Phase 2
 *           BSODs, the IDT write itself is the trigger (KCFG /
 *           PatchGuard / verifier). If Phase 2 succeeds, the asm stub
 *           in Phase 3 had a bug.
 *
 *   Phase 3 (FULL — current code): same as Phase 2 but with the full
 *           VMFUNC-swap asm stub instead of bare IRETQ.
 *
 * Each phase logs progress to SHV_LOG (kernel-debug visible) AND CMOS
 * progress register so the value survives BSOD + reboot. CMOS markers:
 *   0xE1 = Phase 1 complete (IDT read + log)
 *   0xE2 = Phase 2 page allocated + stub written
 *   0xE3 = Phase 2/3 IDT patched, install complete
 * If you boot, BSOD, reboot, and run --hv-status WITHOUT the driver
 * loaded, the DXE-side CMOS readback will show the last marker reached.
 */
#define VE_EXP_PHASE     2   /* 1 = read-only, 2 = IRETQ stub, 3 = full stub */

NTSTATUS
ShvVeInstall(void)
{
    if (g_Shv.VeHandlerInstalled) {
        return STATUS_SUCCESS;
    }

    /* === All phases: SIDT + read IDT[20] === */
    DESCRIPTOR_TABLE_REG idtr_pre;
    KIRQL preIrql = KeRaiseIrqlToDpcLevel();
    _disable();
    ShvSidt(&idtr_pre);
    _enable();
    KeLowerIrql(preIrql);

    PIDT_ENTRY_X64 idtPre = (PIDT_ENTRY_X64)idtr_pre.Base;
    ULONG64 origHandler =
        ((ULONG64)idtPre[20].OffsetLow) |
        ((ULONG64)idtPre[20].OffsetMiddle << 16) |
        ((ULONG64)idtPre[20].OffsetHigh << 32);
    USHORT origSelector = idtPre[20].Selector;
    UCHAR  origTypeAttr = idtPre[20].TypeAttr;
    UCHAR  origIst      = idtPre[20].IstIndex;

    /* Stash for diagnostics + future uninstall. */
    g_Shv.VeIdtPrevHandler  = origHandler;
    g_Shv.VeIdtPrevSelector = origSelector;
    g_Shv.VeIdtPrevTypeAttr = origTypeAttr;
    g_Shv.VeIdtPrevIst      = origIst;

    SHV_LOG("VeInstall PHASE %d: IDT base=0x%llX, IDT[20] origVA=0x%llX, "
            "sel=0x%04X, typeAttr=0x%02X, IST=%u",
            VE_EXP_PHASE, (ULONG64)idtr_pre.Base,
            origHandler, origSelector, origTypeAttr, origIst);
    /* Slot 0x6E doesn't persist across BSOD+reboot on this Arrow Lake
     * board (verified empirically — Phase 2 BSOD'd, slot 0x6E
     * read 0x00 after reboot while slot 0x40 retained 0x06 RUNNING). So
     * write our marker to slot 0x40 (Progress) using a value (0x71) that
     * doesn't collide with any existing progress code. We ALSO write to
     * slot 0x6E in case it persists on future hardware. */
    ShvCmosWrite(SHV_CMOS_VE_EXP, SHV_CMOS_VE_EXP_AFTER_SIDT);
    ShvCmosWrite(SHV_CMOS_PROGRESS, 0x71);

#if VE_EXP_PHASE == 1
    /* PHASE 1 — read-only. Do NOT allocate or patch.
     * Mark "installed" so we don't redo the work, but VeHandlerCodePage
     * stays NULL and IDT stays untouched. Return success — the rest of
     * the boot continues normally and `--hv-status` should report
     * Progress 0xEF as usual. The interesting datapoint is the SHV_LOG
     * line above + CMOS 0xE1 marker. */
    g_Shv.VeHandlerInstalled = TRUE;
    SHV_LOG("VeInstall PHASE 1 complete — read-only test, no IDT patch performed");
    return STATUS_SUCCESS;

#else /* PHASE 2 or 3 */

    /* Populate per-VCPU VeInfoArea pointer table (only meaningful for
     * Phase 3, but cheap to do unconditionally). */
    for (ULONG i = 0; i < g_Shv.ProcessorCount && i < 256; i++) {
        if (g_Shv.VcpuArray[i] != NULL) {
            g_VeInfoAreaTable[i] = (PUCHAR)g_Shv.VcpuArray[i]->VeInfoArea;
        } else {
            g_VeInfoAreaTable[i] = NULL;
        }
    }

    /* Allocate executable kernel page for the handler. */
    PVOID page = ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, 4096, '0fdW');
    if (page == NULL) {
        SHV_ERR("VeInstall: failed to allocate executable handler page");
        ShvCmosWrite(SHV_CMOS_VE_EXP, SHV_CMOS_VE_EXP_FAIL);
        ShvCmosWrite(SHV_CMOS_PROGRESS, 0x7F);  /* Phase 2/3: alloc FAIL */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(page, 4096);

#if VE_EXP_PHASE == 2
    /* PHASE 2 — minimal IRETQ-only stub. Two bytes total. If interrupts
     * deliver to vector 20 (which we don't expect on a system with no
     * VBS / Hyper-V configured), the handler simply IRETQs without
     * touching any state. */
    ((PUCHAR)page)[0] = 0x48;   /* REX.W */
    ((PUCHAR)page)[1] = 0xCF;   /* IRETQ */
    SHV_LOG("VeInstall PHASE 2: IRETQ-only stub @ 0x%llX (2 bytes)",
            (ULONG64)(ULONG_PTR)page);
#else
    /* PHASE 3 — full VMFUNC-swap asm stub. */
    RtlCopyMemory(page, g_VeHandlerStub, VE_HANDLER_STUB_LEN);
    *(ULONG64*)((PUCHAR)page + VE_HANDLER_TABLE_PATCH_OFFSET) =
        (ULONG64)(ULONG_PTR)g_VeInfoAreaTable;
    SHV_LOG("VeInstall PHASE 3: full handler stub @ 0x%llX (%u bytes)",
            (ULONG64)(ULONG_PTR)page, (ULONG)VE_HANDLER_STUB_LEN);
#endif

    g_Shv.VeHandlerCodePage = page;
    g_Shv.VeHandlerCodeVa   = (ULONG64)(ULONG_PTR)page;
    ShvCmosWrite(SHV_CMOS_VE_EXP, SHV_CMOS_VE_EXP_AFTER_ALLOC);
    ShvCmosWrite(SHV_CMOS_PROGRESS, 0x72);  /* Phase 2/3: pool page allocated */

    /* === Patch IDT[20] ===
     * (idtPre / origHandler etc. were already read at function entry.) */
    USHORT origCs = ShvReadCs() & 0xFFF8;
    ULONG64 handlerVa = (ULONG64)(ULONG_PTR)page;

    KIRQL old = KeRaiseIrqlToDpcLevel();
    _disable();

    idtPre[20].OffsetLow    = (USHORT)(handlerVa & 0xFFFF);
    idtPre[20].Selector     = origCs;
    idtPre[20].IstIndex     = 0;
    idtPre[20].TypeAttr     = 0x8E;
    idtPre[20].OffsetMiddle = (USHORT)((handlerVa >> 16) & 0xFFFF);
    idtPre[20].OffsetHigh   = (ULONG32)(handlerVa >> 32);
    idtPre[20].Reserved     = 0;

    _enable();
    KeLowerIrql(old);

    g_Shv.VeHandlerInstalled = TRUE;
    ShvCmosWrite(SHV_CMOS_VE_EXP, SHV_CMOS_VE_EXP_AFTER_PATCH);
    ShvCmosWrite(SHV_CMOS_PROGRESS, 0x73);  /* Phase 2/3: IDT[20] patched */

    SHV_LOG("VeInstall PHASE %d: IDT[20] patched -> 0x%llX (origCs=0x%X)",
            VE_EXP_PHASE, handlerVa, origCs);

    return STATUS_SUCCESS;
#endif /* VE_EXP_PHASE != 1 */
}


VOID
ShvVeUninstall(void)
{
    if (!g_Shv.VeHandlerInstalled) {
        return;
    }

    /* Restore original IDT entry. */
    DESCRIPTOR_TABLE_REG idtr;
    KIRQL old = KeRaiseIrqlToDpcLevel();
    _disable();
    ShvSidt(&idtr);
    PIDT_ENTRY_X64 idt = (PIDT_ENTRY_X64)idtr.Base;

    idt[20].OffsetLow    = (USHORT)(g_Shv.VeIdtPrevHandler & 0xFFFF);
    idt[20].Selector     = g_Shv.VeIdtPrevSelector;
    idt[20].IstIndex     = g_Shv.VeIdtPrevIst;
    idt[20].TypeAttr     = g_Shv.VeIdtPrevTypeAttr;
    idt[20].OffsetMiddle = (USHORT)((g_Shv.VeIdtPrevHandler >> 16) & 0xFFFF);
    idt[20].OffsetHigh   = (ULONG32)(g_Shv.VeIdtPrevHandler >> 32);
    idt[20].Reserved     = 0;

    _enable();
    KeLowerIrql(old);

    if (g_Shv.VeHandlerCodePage) {
        ExFreePool(g_Shv.VeHandlerCodePage);
        g_Shv.VeHandlerCodePage = NULL;
    }
    g_Shv.VeHandlerCodeVa = 0;
    g_Shv.VeHandlerInstalled = FALSE;
    SHV_LOG("VeUninstall: IDT[20] restored");
}

/* ── IPI Callbacks ────────────────────────────────────────────────── */

/**
 * @brief IPI callback that issues INVEPT on the current CPU.
 *
 * Used after arming the FIFO read-trap to flush stale EPT TLB entries
 * on ALL CPUs, not just the one where the trap was armed.
 */
static ULONG_PTR NTAPI
ShvVirtualizeIpiCallback_InveptOnly(
    _In_ ULONG_PTR Context
    )
{
    UNREFERENCED_PARAMETER(Context);
    ShvDoVmcall(VMCALL_INVEPT, 0);
    return 1;
}

/**
 * @brief IPI callback that virtualizes the current logical processor.
 *
 * Invoked on each CPU at DISPATCH_LEVEL via KeIpiGenericCall. Looks up
 * the pre-allocated VCPU_DATA for this processor index and calls
 * ShvVirtualizeProcessor to perform the full VMXON-through-VMLAUNCH
 * sequence.
 *
 * @param Context  Unused IPI context parameter.
 * @return 1 on success, 0 on failure.
 */
static ULONG_PTR NTAPI
ShvVirtualizeIpiCallback(
    _In_ ULONG_PTR Context
    )
{
    UNREFERENCED_PARAMETER(Context);

    ULONG cpuIndex = KeGetCurrentProcessorNumberEx(NULL);

    if (cpuIndex >= g_Shv.ProcessorCount) {
        SHV_ERR("CPU %lu exceeds allocated count %lu", cpuIndex, g_Shv.ProcessorCount);
        return 0;
    }

    PVCPU_DATA vcpu = g_Shv.VcpuArray[cpuIndex];
    if (!vcpu) {
        SHV_ERR("CPU %lu: VCPU not allocated", cpuIndex);
        return 0;
    }

    NTSTATUS status = ShvVirtualizeProcessor(vcpu);
    if (!NT_SUCCESS(status)) {
        SHV_ERR("CPU %lu: Virtualization failed 0x%08X", cpuIndex, status);
        return 0;
    }

    return 1;
}

/**
 * @brief IPI callback that devirtualizes the current logical processor.
 *
 * Issues VMCALL(DEVIRTUALIZE) with the magic cookie to request VMX exit.
 * The VM-exit handler calls ShvVmxOffAndRestore, which executes VMXOFF,
 * clears CR4.VMXE, and returns here as if the VMCALL returned normally.
 *
 * @param Context  Unused IPI context parameter.
 * @return 1 on success, 0 if CPU was not active or devirtualization failed.
 */
static ULONG_PTR NTAPI
ShvDevirtualizeIpiCallback(
    _In_ ULONG_PTR Context
    )
{
    UNREFERENCED_PARAMETER(Context);

    ULONG cpuIndex = KeGetCurrentProcessorNumberEx(NULL);

    if (cpuIndex >= g_Shv.ProcessorCount) {
        return 0;
    }

    PVCPU_DATA vcpu = g_Shv.VcpuArray[cpuIndex];
    if (!vcpu || !vcpu->VmxActive) {
        return 0;
    }

    /*
     * Issue VMCALL with devirtualize command.
     * The exit handler calls ShvVmxOffAndRestore, which disables VMX
     * and returns here as if VMCALL returned STATUS_SUCCESS.
     */
    NTSTATUS status = ShvDoVmcall(VMCALL_DEVIRTUALIZE, VMCALL_MAGIC_COOKIE);
    if (NT_SUCCESS(status)) {
        vcpu->VmxActive = FALSE;
        vcpu->Launched = FALSE;
        /* NO SHV_LOG here — we're at IPI_LEVEL, DbgPrintEx would deadlock */
    }
    /* Failures are silent too — can't call DbgPrintEx at IPI_LEVEL */

    return 1;
}

/* ── Public API ───────────────────────────────────────────────────── */

NTSTATUS
ShvVirtualizeAllProcessors(void)
{
    /* HV-7: sample bare-metal CPUID response BEFORE VMX takes over.
     * Must happen while we're still in non-root mode so real CPUID
     * returns unhooked values. Idempotent — safe if called twice. */
    ShvInitStealthCpuidCache();

    /* Initialize EPT identity mapping before virtualizing any CPUs */
    NTSTATUS eptStatus = ShvEptInitialize();
    if (!NT_SUCCESS(eptStatus)) {
        SHV_ERR("EPT initialization failed 0x%08X", eptStatus);
        return eptStatus;
    }

    ShvCmosWrite(SHV_CMOS_PROGRESS, SHV_PROG_EPT_INIT);

    SHV_LOG("Virtualizing %lu processors...", g_Shv.ProcessorCount);
    ShvCmosWrite(SHV_CMOS_PROGRESS, SHV_PROG_IPI_DISPATCH);

    /* KeIpiGenericCall runs the callback on every logical processor.
     * All CPUs are synchronized at DISPATCH_LEVEL. */
    ULONG_PTR result = KeIpiGenericCall(ShvVirtualizeIpiCallback, 0);
    UNREFERENCED_PARAMETER(result);

    /* Check how many CPUs were successfully virtualized */
    ULONG activeCount = 0;
    for (ULONG i = 0; i < g_Shv.ProcessorCount; i++) {
        if (g_Shv.VcpuArray[i] && g_Shv.VcpuArray[i]->VmxActive) {
            activeCount++;
        }
    }

    if (activeCount == 0) {
        SHV_ERR("No processors were virtualized!");
        return STATUS_UNSUCCESSFUL;
    }

    if (activeCount < g_Shv.ProcessorCount) {
        SHV_WARN("Only %lu/%lu processors virtualized", activeCount, g_Shv.ProcessorCount);
    } else {
        SHV_LOG("All %lu processors virtualized successfully", activeCount);
    }

    InterlockedExchange(&g_Shv.Active, 1);
    return STATUS_SUCCESS;
}

NTSTATUS
ShvDevirtualizeAllProcessors(void)
{
    if (!InterlockedCompareExchange(&g_Shv.Active, 0, 1)) {
        return STATUS_SUCCESS; /* Already inactive */
    }

    SHV_LOG("Devirtualizing %lu processors...", g_Shv.ProcessorCount);

    KeIpiGenericCall(ShvDevirtualizeIpiCallback, 0);

    /* Verify all CPUs are devirtualized */
    ULONG stillActive = 0;
    for (ULONG i = 0; i < g_Shv.ProcessorCount; i++) {
        if (g_Shv.VcpuArray[i] && g_Shv.VcpuArray[i]->VmxActive) {
            stillActive++;
        }
    }
    if (stillActive) {
        SHV_ERR("%lu CPUs still active after devirtualization!", stillActive);
    }

    /* Free EPT state after all CPUs are devirtualized */
    ShvEptDestroy();

    SHV_LOG("All processors devirtualized");
    return STATUS_SUCCESS;
}

/* ── Driver Unload ────────────────────────────────────────────────── */

/**
 * @brief Driver unload routine: devirtualize all CPUs and free resources.
 *
 * Called by the I/O manager when the driver is being stopped (e.g., via
 * "sc stop SentinelHV"). Devirtualizes all processors, frees VCPU memory,
 * deletes the device object, and writes a clean shutdown marker to CMOS.
 *
 * @param DriverObject  The driver object being unloaded.
 */
static void
ShvDriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    SHV_LOG("Unloading SentinelHV...");
    ShvCmosWrite(SHV_CMOS_PROGRESS, SHV_PROG_UNLOADING);

    /* Unregister load-image notify FIRST (before any VMX teardown). */
    ShvAutoArmUnregister();

    /* Devirtualize all CPUs first */
    ShvDevirtualizeAllProcessors();

    /* AFTER devirtualization: no CPU can be in VMX root using the window. */
    ShvRootScratchTeardown();

    /* Free VCPU memory */
    ShvFreeVcpuArray();

    /* Delete device object */
    if (g_Shv.DeviceObject) {
        IoDeleteDevice(g_Shv.DeviceObject);
        g_Shv.DeviceObject = NULL;
    }

    ShvCmosWrite(SHV_CMOS_PROGRESS, SHV_PROG_CLEAN);
    SHV_LOG("SentinelHV unloaded");
}

/**
 * @brief NexusCore manual-map unload hook.
 *
 * Called by NexusCore/PeUnloadDriver when the user invokes
 * `NexusDSEFix --unload-driver <base>`. Mirrors ShvDriverUnload but returns
 * NTSTATUS (per PFN_DRIVER_UNLOAD contract) and omits the DeviceObject step
 * since manual-mapped HV never creates one.
 *
 * Devirtualizes every CPU via IPI (each VMCALLs VMCALL_DEVIRTUALIZE ->
 * ShvVmxOffAndRestore), then frees VCPU array + EPT structures. After this
 * returns NexusCore frees the image memory and removes us from the loaded
 * driver list.
 */
__declspec(dllexport) NTSTATUS NTAPI
NexusDriverUnload(VOID)
{
    SHV_LOG("NexusDriverUnload: manual-map teardown starting");
    ShvCmosWrite(SHV_CMOS_PROGRESS, SHV_PROG_UNLOADING);

    ShvAutoArmUnregister();
    ShvDevirtualizeAllProcessors();
    /* AFTER devirtualization: no CPU can be in VMX root using the window. */
    ShvRootScratchTeardown();
    ShvFreeVcpuArray();

    if (g_Shv.DeviceObject) {
        IoDeleteDevice(g_Shv.DeviceObject);
        g_Shv.DeviceObject = NULL;
    }

    ShvCmosWrite(SHV_CMOS_PROGRESS, SHV_PROG_CLEAN);
    SHV_LOG("NexusDriverUnload: complete, safe to free image");
    return STATUS_SUCCESS;
}

/* ── Auto-arm-on-module-load  ────────────────────────────
 *
 * PsSetLoadImageNotifyRoutine callback. Fires synchronously in kernel
 * context BEFORE the loaded image's entry point runs. For a kernel
 * driver load (any .sys), we get the pre-DriverEntry moment —
 * which is exactly when .grfn11 has NOT yet been decoded. Install the
 * pre-configured read/exec-trap here and catch the decoder on its
 * first access. */

static BOOLEAN
ShvAutoArmNameMatches(
    _In_ PCWSTR FullImageName,
    _In_ const CHAR* TargetAscii
    )
{
    /* Matches when TargetAscii equals the filename in FullImageName OR
     * when TargetAscii is a case-insensitive suffix of that filename.
     * Suffix match exists because g_Shv.AutoArmModuleName is only 32
     * bytes (31 chars + null), and some target module names are longer
     * (e.g. "EAAntiCheat.GameServiceLauncher.dll" = 35 chars). User
     * can pass "GameServiceLauncher.dll" (23 chars) and it will still
     * match the full loaded basename. */
    if (!FullImageName || !TargetAscii) return FALSE;
    if (TargetAscii[0] == '\0') return FALSE;

    PCWSTR p = FullImageName;
    PCWSTR fname = FullImageName;
    while (*p) {
        if (*p == L'\\' || *p == L'/') {
            fname = p + 1;
        }
        p++;
    }

    /* Measure lengths. */
    ULONG tlen = 0;
    while (TargetAscii[tlen] != '\0') tlen++;
    ULONG wlen = 0;
    PCWSTR ws = fname;
    while (*ws) { wlen++; ws++; }

    if (tlen == 0 || tlen > wlen) return FALSE;

    /* Compare TargetAscii against fname[wlen-tlen .. wlen-1]. */
    PCWSTR wstart = fname + (wlen - tlen);
    const CHAR* a = TargetAscii;
    PCWSTR w = wstart;
    while (*a && *w) {
        WCHAR wc = *w;
        CHAR ac = *a;
        if (wc >= L'A' && wc <= L'Z') wc = (WCHAR)(wc - L'A' + L'a');
        if (ac >= 'A' && ac <= 'Z') ac = (CHAR)(ac - 'A' + 'a');
        if ((WCHAR)ac != wc) return FALSE;
        a++; w++;
    }
    return (*a == '\0' && *w == L'\0');
}

static void NTAPI
ShvLoadImageNotifyCallback(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_     HANDLE          ProcessId,
    _In_     PIMAGE_INFO     ImageInfo
    )
{
    UNREFERENCED_PARAMETER(ProcessId);

    /* Fast reject: image with name + autoarm enabled + not yet fired. */
    if (!FullImageName || !ImageInfo || !ImageInfo->ImageBase) return;
    if (g_Shv.AutoArmEnabled != 1) return;
    if (g_Shv.AutoArmFired != 0) return;

    /* KM image loads are the default. UM image loads are only matched
     * when AutoArmAllowUm=1 because the trap install path needs a CR3
     * filter (UM mappings are per-process, not globally shared). */
    BOOLEAN isKm = (ImageInfo->SystemModeImage != 0);
    if (!isKm && g_Shv.AutoArmAllowUm != 1) return;

    /* Wide-string compare is finicky via ASCII; use a small stack copy. */
    if (!ShvAutoArmNameMatches(FullImageName->Buffer, g_Shv.AutoArmModuleName)) {
        return;
    }

    /* Match — latch so we don't re-fire if the same name loads twice. */
    if (InterlockedCompareExchange(&g_Shv.AutoArmFired, 1, 0) != 0) {
        return;
    }

    ULONG64 modBase = (ULONG64)(ULONG_PTR)ImageInfo->ImageBase;
    ULONG64 targetVa = modBase + g_Shv.AutoArmSectionRva;
    ULONG64 cr3 = __readcr3();

    /* Always record where the callback fired — useful even when PA
     * resolution defers, so UM can see we matched the right image. */
    g_Shv.AutoArmDetectedBase = modBase;
    g_Shv.AutoArmDetectedCr3  = cr3;

    /* Note: we cannot safely use MmProbeAndLockPages here to force-commit
     * UM pages because SHV is manual-mapped on Win11 24H2 and our
     * __try/__except handlers are silently broken (RtlAddGrowableFunctionTable
     * is a no-op for non-ntoskrnl entries — see
     * An earlier finding). MmProbeAndLockPages
     * raises on invalid VAs, so calling it without a working __try would
     * bugcheck. We rely on the deferred-poll path instead and accept the
     * race for pages that commit late in the launcher's execution. */

    /* Resolve target PA — but ONLY if the page is resident.
     *
     * CRITICAL (— fixes BSOD 0x1E KMODE_EXCEPTION_NOT_HANDLED):
     * The LoadImage notify fires from MiCallImageNotify while the image is
     * STILL being mapped (MiReferenceControlAreaFile on the stack); the
     * section's pages are not yet resident (proto-PTE, "not valid"). The
     * OLD code assumed kernel VAs were "always committed once mapped" and
     * called MmGetPhysicalAddress(targetVa) unconditionally — which on a
     * non-resident page dereferences into the not-yet-mapped image and
     * faults. Our manual-mapped SEH can't catch it (RtlAddGrowableFunction
     * table is a no-op for non-ntoskrnl entries — see
     * An earlier finding), so the #PF escalates
     * to a bugcheck. Crash dump: callback RIP in manual-mapped SHV reading
     * eaanticheat_base+0xB67000 while eaanticheat.sys was mid-load.
     *
     * The UM lazy-commit race was already handled; KM driver images
     * (eaanticheat.sys) have the SAME race during load. Guard with the
     * non-faulting MmIsAddressValid and defer BOTH KM and UM to the
     * exit_dispatch poll, which resolves via ShvTranslateGuestVa once the
     * page is resident. KM kernel VAs are global (valid in any CR3), so the
     * deferred trap filter is 0 for KM and the loading-proc CR3 for UM. */
    BOOLEAN resident = MmIsAddressValid((PVOID)(ULONG_PTR)targetVa);
    PHYSICAL_ADDRESS pa;
    pa.QuadPart = 0;
    if (resident) {
        pa = MmGetPhysicalAddress((PVOID)(ULONG_PTR)targetVa);
    }
    /* MmIsAddressValid returns FALSE for pages backed by PROTOTYPE PTEs
     * (Windows file-backed image sections like DLL code pages): the page
     * IS in the file cache but hasn't been faulted into the working set.
     * MmGetPhysicalAddress also returns 0 for prototype-PTE pages.
     *
     * Fix: if the quick check failed, use MmCopyMemory(MM_COPY_MEMORY_VIRTUAL)
     * to force-fault the target page into the working set.  MmCopyMemory
     * handles all PTE types internally (prototype, demand-zero, etc.) and
     * raises no exceptions — it returns a status code.  After a successful
     * copy, MmGetPhysicalAddress returns the real PA.
     *
     * This is safe here (PASSIVE_LEVEL, in the loading process's address
     * space for UM images; kernel context for KM images).  We read only 1
     * byte so the cost is one page-fault resolve at most. */
    if (pa.QuadPart == 0) {
        MM_COPY_ADDRESS src;
        src.VirtualAddress = (PVOID)(ULONG_PTR)(targetVa & ~0xFFFULL);
        UCHAR  dummy[1];
        SIZE_T copied = 0;
        NTSTATUS cpSt = MmCopyMemory(dummy, src, 1,
                                     MM_COPY_MEMORY_VIRTUAL, &copied);
        if (NT_SUCCESS(cpSt) && copied == 1) {
            pa = MmGetPhysicalAddress((PVOID)(ULONG_PTR)targetVa);
            resident = (pa.QuadPart != 0);
            SHV_LOG("AutoArm: prototype-PTE resolved via MmCopyMemory pa=0x%llX",
                    (ULONG64)pa.QuadPart);
        }
    }
    if (!resident || pa.QuadPart == 0) {
        /* Page not resident (or PA unresolved) — queue deferred install for
         * KM and UM alike. Never dereference targetVa here. */
        ULONG64 sz = g_Shv.AutoArmSize ? g_Shv.AutoArmSize : 0x1000ULL;
        if (sz > 0x1000) sz = 0x1000;
        g_Shv.AutoArmDeferredVa        = targetVa & ~0xFFFULL;
        g_Shv.AutoArmDeferredCr3       = cr3;
        g_Shv.AutoArmDeferredSize      = sz;
        g_Shv.AutoArmDeferredTrapType  = g_Shv.AutoArmTrapType;
        g_Shv.AutoArmDeferredFilterCr3 = 0;  /* KPTI: DTB≠UDTB — always global */
        g_Shv.AutoArmDeferredAttempts  = 0;
        InterlockedExchange(&g_Shv.AutoArmDeferredActive, 1);
        g_Shv.AutoArmInstallStatus     = (LONG)STATUS_PENDING;
        SHV_LOG("AutoArm: page not resident at 0x%llX (isKm=%d) — deferred to exit_dispatch poll",
                targetVa, (int)isKm);
        return;
    }

    SHV_LOG("AutoArm: matched '%s' base=0x%llX va=0x%llX pa=0x%llX trap=%llu",
            g_Shv.AutoArmModuleName, modBase, targetVa,
            (ULONG64)pa.QuadPart, g_Shv.AutoArmTrapType);

    /* Dispatch to the matching install path via the same Pending* slots
     * that UM writes. exit_dispatch polls those on next VMexit. */
    ULONG64 size = g_Shv.AutoArmSize ? g_Shv.AutoArmSize : 0x1000ULL;
    if (size > 0x1000) size = 0x1000;
    ULONG64 vaBasePage = targetVa & ~0xFFFULL;
    ULONG64 paPage     = (ULONG64)pa.QuadPart & ~0xFFFULL;

    /* CR3 filter policy:
     *   KM image loads:  filter=0 — kernel code runs under whatever CR3 the
     *     current thread is attached to, so mismatches are normal; the
     *     handler's auto-uninstall-on-first-filtered-CR3 path would kill
     *     the trap immediately if we filtered.
     *   UM image loads:  filter=0 — on KPTI (Windows 10/11) the CR3 stored
     *     here is the DirectoryTableBase (kernel CR3) while VM exits from
     *     user-mode code carry UserDirectoryTableBase (user CR3). These are
     *     different physical addresses, so a per-process CR3 filter causes
     *     IMMEDIATE auto-uninstall on the first hit (ExecTrapFilteredCr3==0
     *     path in ept.c → PendingExecTrapOp=2). Result: 0 hits every run.
     *     Fix: use filter=0 for UM traps. The page VA range (VaBase/VaEnd)
     *     already restricts to the specific target page; false hits from
     *     other processes sharing the same PA are extremely unlikely for
     *     launcher-specific DLLs like EAAntiCheat.GameServiceLauncher.dll. */
    ULONG64 filterCr3 = 0;  /* global — KPTI: DTB ≠ UDTB, per-proc filter breaks */
    (void)isKm;              /* both KM and UM now use filter=0 */

    if (g_Shv.AutoArmTrapType == 1) {
        /* Read-trap */
        g_Shv.PendingReadTrapCr3        = filterCr3;
        g_Shv.PendingReadTrapVaBase     = vaBasePage;
        g_Shv.PendingReadTrapSize       = size;
        g_Shv.PendingReadTrapRipFilter  = 0;
        g_Shv.PendingReadTrapTargetPid  = paPage;
        g_Shv.PendingReadTrapResult     = 0;
        g_Shv.PendingReadTrapOp         = 1;  /* install — flip last */
        if (g_Shv.AutoArmAutoStop != 0) {
            g_Shv.ReadTrapAutoStop = (LONG)g_Shv.AutoArmAutoStop;
        }
        g_Shv.AutoArmInstallStatus = (LONG)STATUS_SUCCESS;
    } else if (g_Shv.AutoArmTrapType == 2) {
        /* Exec-trap */
        g_Shv.PendingExecTrapCr3        = filterCr3;
        g_Shv.PendingExecTrapVaBase     = vaBasePage;
        g_Shv.PendingExecTrapSize       = size;
        g_Shv.PendingExecTrapRipFilter  = 0;
        g_Shv.PendingExecTrapTargetPid  = paPage;
        g_Shv.PendingExecTrapResult     = 0;
        g_Shv.PendingExecTrapOp         = 1;  /* install — flip last */
        if (g_Shv.AutoArmAutoStop != 0) {
            g_Shv.ExecTrapAutoStop = (LONG)g_Shv.AutoArmAutoStop;
        }
        g_Shv.AutoArmInstallStatus = (LONG)STATUS_SUCCESS;

        /* ── CHAIN HANDOFF  ──────────────────────────────────────
         * AutoArm REPLACES chain stage-1 (the ntdll!LdrpCallInitRoutine anchor).
         *
         * WHY.  Stage-1 could never win: preloader_l's pivot page (0x2000) has
         * ZERO base relocations, so the loader never writes it and it stays
         * non-resident until FIRST EXECUTION.  The stage-1 walk therefore saw
         * "not present", and by the time a retry saw it resident the one-shot
         * `call` at +0x2DB5 had already run -- the page became resident BECAUSE
         * it ran (MEASURED shvlog15: 6144+ hits on that page afterwards, RIPs
         * 0x2002-0x2452 incl. inside the callee sub_2170, RIP never 0x2DB5).
         * "Resolve the PA, then arm" loses that race by construction.
         *
         * THIS callback runs at PASSIVE_LEVEL, in the loading process, BEFORE
         * DllMain executes, and the MmCopyMemory above FORCE-FAULTS the page in
         * rather than waiting for it.  So the trap is armed strictly before the
         * one-shot -- the race is gone, not narrowed.
         *
         * NOTE this only works for a NORMALLY-LOADED module (preloader_l.dll).
         * gsl.dll is MANUALLY MAPPED by preloader, so no image-load notify will
         * ever fire for it -- which is exactly why the pivot still matters:
         * gsl's base comes from RCX at +0x2DB5 and from nowhere else.
         *
         * Publish the exact pivot VA and jump the chain straight to the
         * "stage-2 armed" state so step-2 fires there and pivots to
         * gsl_base + RcxRva. */
        if (g_Shv.ExecTrapChainEnabled != 0 && g_Shv.ExecTrapChainRcxRva != 0) {
            ShvEptChainSetStage2(targetVa);
            SHV_LOG("AutoArm: CHAIN HANDOFF -- stage-2 pivot=0x%llX armed pre-DllMain "
                    "(page pa=0x%llX); step2 will read gsl_base from RCX there",
                    targetVa, paPage);
        }
    } else {
        SHV_WARN("AutoArm: unknown TrapType %llu", g_Shv.AutoArmTrapType);
        g_Shv.AutoArmInstallStatus = (LONG)STATUS_INVALID_PARAMETER;
    }
}

static LONG g_AutoArmRegistered = 0;

NTSTATUS
ShvAutoArmRegister(VOID)
{
    /* Always publish the magic so UM can locate the config block, even
     * if callback registration fails (e.g. the system's 8-slot
     * notify-callback list is full). UM commands can at least query/
     * clear the block; only the auto-fire behavior is lost on failure. */
    g_Shv.AutoArmMagic = AUTO_ARM_MAGIC;

    if (InterlockedCompareExchange(&g_AutoArmRegistered, 1, 0) != 0) {
        return STATUS_SUCCESS;  /* already registered */
    }
    NTSTATUS st = PsSetLoadImageNotifyRoutine(ShvLoadImageNotifyCallback);
    if (!NT_SUCCESS(st)) {
        InterlockedExchange(&g_AutoArmRegistered, 0);
        SHV_WARN("AutoArm: PsSetLoadImageNotifyRoutine failed 0x%08X — magic still written", st);
        return st;
    }
    SHV_LOG("AutoArm: load-image callback registered");
    return STATUS_SUCCESS;
}

VOID
ShvAutoArmUnregister(VOID)
{
    if (InterlockedCompareExchange(&g_AutoArmRegistered, 0, 1) != 1) {
        return;
    }
    PsRemoveLoadImageNotifyRoutine(ShvLoadImageNotifyCallback);
    SHV_LOG("AutoArm: load-image callback unregistered");
}

/* ── Driver Entry ─────────────────────────────────────────────────── */

/**
 * @brief Driver entry point: initialize and activate the hypervisor.
 *
 * Performs the full initialization sequence:
 *   1. Clear CMOS diagnostic region from any previous boot.
 *   2. Set up the unload routine.
 *   3. Create the \\Device\\SentinelHV device object.
 *   4. Verify VMX hardware support (CPUID, IA32_FEATURE_CONTROL).
 *   5. Allocate per-CPU VCPU structures with contiguous memory.
 *   6. Initialize EPT and virtualize all processors via IPI.
 *
 * On any failure, all partially-allocated resources are cleaned up.
 * CMOS progress codes are written at each milestone for post-mortem
 * diagnosis if the system freezes during initialization.
 *
 * @param DriverObject  The driver object created by the I/O manager.
 * @param RegistryPath  Registry path for driver parameters (unused).
 * @return STATUS_SUCCESS if the hypervisor is active, error status otherwise.
 */
/**
 * @brief Spoof TPM FIFO identity registers in a shadow buffer.
 *
 * Writes deterministically-derived values to the three TPM identity
 * register offsets the target reads from FIFO MMIO:
 *   0x030: TPM_INTERFACE_ID
 *   0xF00: TPM_DID_VID (Device ID / Vendor ID)
 *   0xF04: TPM_RID (Revision ID)
 *
 * Uses g_MacSeed if set (non-zero), otherwise falls back to the
 * hardcoded "SHVM" seed (0x5348564D).
 *
 * @param shadowVa  Virtual address of the 4KB shadow buffer.
 */
static void
ShvSpoofFifoIdentity(
    _Inout_ PVOID shadowVa
    )
{
    UINT64 seed64 = g_MacSeed;
    ULONG32 seed;

    if (seed64 != 0) {
        /* Derive a 32-bit seed from the 64-bit MacSeed.
         * Mix both halves so all seed bits contribute. */
        seed = (ULONG32)(seed64 ^ (seed64 >> 32));
    } else {
        seed = 0x5348564D;  /* "SHVM" fallback */
    }

    /* XOR each register with a different hash of the seed to produce
     * unique but deterministic spoofed values per register offset. */
    *(ULONG32*)((UCHAR*)shadowVa + 0x030) ^= (seed ^ 0x030);
    *(ULONG32*)((UCHAR*)shadowVa + 0xF00) ^= (seed * 0x01000193);  /* FNV prime */
    *(ULONG32*)((UCHAR*)shadowVa + 0xF04) ^= (seed * 0x811C9DC5);  /* FNV offset basis */
}

/* Deferred VMX init — runs as a system thread at PASSIVE_LEVEL.
 * Called when the driver is manually mapped (HIGH_LEVEL context). */
static VOID NTAPI
ShvDeferredVmxInit(
    _In_ PVOID StartContext
    )
{
    UNREFERENCED_PARAMETER(StartContext);
    NTSTATUS status;

    ShvCmosWrite(SHV_CMOS_PROGRESS, 0x0F);  /* 0F = deferred thread running, before VMX check */

    /* Sleep briefly to let the mapper return */
    LARGE_INTEGER delay;
    delay.QuadPart = -10000000LL;  /* 1 second */
    KeDelayExecutionThread(KernelMode, FALSE, &delay);

    if (!ShvIsVmxSupported()) {
        ShvCmosWrite(SHV_CMOS_PROGRESS, 0xE2);
        PsTerminateSystemThread(STATUS_NOT_SUPPORTED);
        return;
    }
    ShvCmosWrite(SHV_CMOS_PROGRESS, SHV_PROG_DEFERRED_VMX_OK);

    status = ShvAllocateVcpuArray();
    if (!NT_SUCCESS(status)) {
        ShvCmosWrite(SHV_CMOS_PROGRESS, 0xE3);
        PsTerminateSystemThread(status);
        return;
    }
    ShvCmosWrite(SHV_CMOS_PROGRESS, SHV_PROG_VCPU_ALLOC);
    ShvCmosWrite(SHV_CMOS_CPU_COUNT, (UCHAR)g_Shv.ProcessorCount);

    status = ShvVirtualizeAllProcessors();
    if (!NT_SUCCESS(status)) {
        ShvFreeVcpuArray();
        ShvCmosWrite(SHV_CMOS_PROGRESS, 0xE5);
        PsTerminateSystemThread(status);
        return;
    }

    ShvCmosWrite(SHV_CMOS_PROGRESS, SHV_PROG_RUNNING);
    /* g_Shv.Active is set to 1 AFTER all resource preps below complete,
     * so the UM-side install never races with an incomplete resource pool. */
    SHV_LOG("Deferred VMX init complete — all CPUs virtualized");

    /* Allocate syscall trace log buffer (NonPagedPool, 4096 * 72 = 288KB).
     * Must be done here at PASSIVE_LEVEL before any hooks are installed. */
    {
        SIZE_T logSize = sizeof(SYSCALL_LOG_ENTRY) * SYSCALL_LOG_MAX;
        PVOID logBuf = ShvAllocateContiguousMemory(logSize);
        if (logBuf) {
            RtlZeroMemory(logBuf, logSize);
            g_Shv.SyscallLog = (PSYSCALL_LOG_ENTRY)logBuf;
            SHV_LOG("Syscall trace log allocated: %llu entries (%llu bytes)",
                    (ULONG64)SYSCALL_LOG_MAX, (ULONG64)logSize);
        } else {
            SHV_WARN("Syscall trace log allocation failed — tracing unavailable");
        }
    }

    /* Allocate secondary EPT for future dual-EPT hooks.
     * Built from scratch (not copied) — completely independent page tables.
     * This ONLY allocates; no behavior changes until hooks are installed. */
    {
        NTSTATUS secSt = ShvEptInitializeSecondary();
        if (NT_SUCCESS(secSt)) {
            g_Shv.PrimaryEptp = ShvEptGetEptp();
            g_Shv.SecondaryEptp = ShvEptGetSecondaryEptp();
            SHV_LOG("Dual-EPT ready: primary=0x%llX secondary=0x%llX",
                    g_Shv.PrimaryEptp, g_Shv.SecondaryEptp);

            /* Item #8 — populate the EPTP-list page for VMFUNC leaf 0
             * (EPTP switching). Index 0 = primary (read view), index 1
             * = secondary (exec view). Other indices left as 0 — VMFUNC
             * with an invalid index causes a regular vmexit which we'll
             * catch (treating as an unauthorized swap attempt). */
            RtlZeroMemory(g_Shv.VmFuncEptpListPage, sizeof(g_Shv.VmFuncEptpListPage));
            g_Shv.VmFuncEptpListPage[0] = g_Shv.PrimaryEptp;
            g_Shv.VmFuncEptpListPage[1] = g_Shv.SecondaryEptp;
            g_Shv.VmFuncEptpListPagePa =
                MmGetPhysicalAddress(&g_Shv.VmFuncEptpListPage).QuadPart;
            SHV_LOG("EPTP list page PA=0x%llX [0]=0x%llX [1]=0x%llX",
                    g_Shv.VmFuncEptpListPagePa,
                    g_Shv.VmFuncEptpListPage[0], g_Shv.VmFuncEptpListPage[1]);

            /* DISABLED — root cause confirmed via Progress
             * marker 0x72. The IDT[20] write itself triggers BSOD on
             * Win11 24H2: PatchGuard (or KCFG / IDT-integrity in 24H2)
             * is watching the system IDT and bug-checks on modification.
             * The pool allocation + stub write succeed cleanly; only
             * the actual IDT entry mutation triggers the crash.
             *
             * Permanent fix lives behind the host-IDT port (Ophion
             * `hostidt.c`-equivalent — currently item #10 stretch).
             * Once SentinelHV runs with its own private per-CPU IDT,
             * patching vector 20 in OUR IDT is invisible to PatchGuard
             * and #VE delivery to our handler works.
             *
             * Until then: items 8 + 9 stay plumbed but dormant. The
             * SuppressVe=1 sweep across the identity map remains
             * correct and free; CPU_BASED2_EPT_VIOLATION_VE stays off
             * in vmcs.c so no #VE deliveries can fire. */
            /* ShvVeInstall(); */

            /* Register load-image notify callback (auto-arm). */
            (void)ShvAutoArmRegister();
        } else {
            SHV_WARN("Secondary EPT alloc failed 0x%08X — hooks unavailable", secSt);
        }
    }

    /* Resource preps below are INDEPENDENT of secondary EPT — they use
     * primary EPT split-PTs only.  Placed outside the secSt block so
     * ExecTrap/ReadTrap/WriteTrap/etc. work even when secondary EPT
     * init fails (e.g. VBS/HVCI contiguous-memory constraints). */
    {
        /* Split-PT pool + g_HookRes.Ready — required by ExecTrap PrimarySplitFor. */
        NTSTATUS hookResSt = ShvEptPrepareHookResources();
        if (NT_SUCCESS(hookResSt)) {
            SHV_LOG("Hook resources pre-allocated — ready for hook install");
        } else {
            SHV_WARN("Hook resource alloc failed 0x%08X — hooks unavailable", hookResSt);
        }

        NTSTATUS xcapResSt = ShvEptPrepareXcapResources();
        if (NT_SUCCESS(xcapResSt)) {
            SHV_LOG("Xcap resources pre-allocated — ready for setup");
        } else {
            SHV_WARN("Xcap resource alloc failed 0x%08X — xcap unavailable", xcapResSt);
        }

        NTSTATUS wtResSt = ShvEptPrepareWriteTrapResources();
        if (NT_SUCCESS(wtResSt)) {
            SHV_LOG("WriteTrap resources pre-allocated — ready for install");
        } else {
            SHV_WARN("WriteTrap resource alloc failed 0x%08X — write-trap unavailable", wtResSt);
        }

        NTSTATUS rtResSt = ShvEptPrepareReadTrapResources();
        if (NT_SUCCESS(rtResSt)) {
            SHV_LOG("ReadTrap resources pre-allocated — ready for install");
        } else {
            SHV_WARN("ReadTrap resource alloc failed 0x%08X — read-trap unavailable", rtResSt);
        }

        NTSTATUS xtResSt = ShvEptPrepareExecTrapResources();
        if (NT_SUCCESS(xtResSt)) {
            SHV_LOG("ExecTrap resources pre-allocated — ready for install");
        } else {
            SHV_WARN("ExecTrap resource alloc failed 0x%08X — exec-trap unavailable", xtResSt);
        }

        NTSTATUS rtTrSt = ShvEptPrepareRipTraceResources();
        if (NT_SUCCESS(rtTrSt)) {
            SHV_LOG("RipTrace resources pre-allocated — ready for arm");
        } else {
            SHV_WARN("RipTrace resource alloc failed 0x%08X", rtTrSt);
        }

        NTSTATUS ctSt = ShvCipherTrapPrepareResources();
        if (NT_SUCCESS(ctSt)) {
            SHV_LOG("CipherTrap resources pre-allocated — ready for install");
        } else {
            SHV_WARN("CipherTrap resource alloc failed 0x%08X — trap unavailable", ctSt);
        }
    }

    /* All resource pools ready — signal UM that the HV is fully usable. */
    InterlockedExchange(&g_Shv.Active, 1);
    SHV_LOG("g_Shv.Active=1: resource pools complete, HV fully ready");

    /* TPM FIFO page remap (same as sc-start path) */
    if (ShvEptIsEnabled()) {
        PVOID shadowVa = ShvAllocateContiguousMemory(TPM_FIFO_SIZE);
        if (shadowVa) {
            RtlZeroMemory(shadowVa, TPM_FIFO_SIZE);
            *(ULONG32*)shadowVa = 0x53485654;  /* "TVHS" marker */

            /* Copy real FIFO data, then spoof identity registers */
            {
                PHYSICAL_ADDRESS fifoPhys;
                fifoPhys.QuadPart = (LONGLONG)TPM_FIFO_PA;
                PVOID fifoVa = MmMapIoSpace(fifoPhys, TPM_FIFO_SIZE, MmNonCached);
                if (fifoVa) {
                    RtlCopyMemory(shadowVa, fifoVa, TPM_FIFO_SIZE);
                    MmUnmapIoSpace(fifoVa, TPM_FIFO_SIZE);
                    SHV_LOG("TPM FIFO: copied real data to shadow (deferred)");
                }
            }
            ShvSpoofFifoIdentity(shadowVa);

            ULONG64 shadowPa = MmGetPhysicalAddress(shadowVa).QuadPart;
            NTSTATUS remapSt = ShvEptRemapPage(TPM_FIFO_PA, shadowPa);
            if (NT_SUCCESS(remapSt)) {
                ShvCmosWrite(SHV_CMOS_PROGRESS, 0xEF);
                SHV_LOG("TPM FIFO remapped to shadow (deferred path)");

                /* Arm the FIFO read-trap via VMCALL (must run in VMX root) */
                NTSTATUS trapSt = ShvDoVmcall(VMCALL_FIFO_TRAP, 1 /* enable */);
                if (NT_SUCCESS(trapSt)) {
                    InterlockedExchange(&g_Shv.FifoTrapActive, 1);
                    SHV_LOG("TPM FIFO read-trap armed (deferred path)");

                    /* CRITICAL: Flush EPT TLB on ALL CPUs via IPI.
                     * ShvEptTrapFifoPage only flushed the current CPU's TLB.
                     * Other CPUs may have stale cached EPT entries (Read=1)
                     * that let FIFO reads succeed without an EPT violation.
                     * Use KeIpiGenericCall to make every CPU do VMCALL_INVEPT. */
                    KeIpiGenericCall(ShvVirtualizeIpiCallback_InveptOnly, 0);
                    SHV_LOG("INVEPT broadcast to all %lu CPUs", g_Shv.ProcessorCount);
                } else {
                    SHV_WARN("TPM FIFO read-trap VMCALL failed: 0x%08X", trapSt);
                }
                /* Also remap CRB page to same shadow (deferred path) */
                NTSTATUS crbSt = ShvEptRemapPage(TPM_CRB_PA, shadowPa);
                if (NT_SUCCESS(crbSt)) {
                    SHV_LOG("TPM CRB remapped to shadow (deferred path)");
                } else {
                    SHV_WARN("TPM CRB remap failed (deferred): 0x%08X", crbSt);
                }
            } else {
                MmFreeContiguousMemory(shadowVa);
            }
        }
    }

    /* Register auto-arm load-image callback in the deferred/manual-map
     * path too. Safe to call twice — guarded by g_AutoArmRegistered CAS. */
    (void)ShvAutoArmRegister();

    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    SHV_LOG("SentinelHV v%d.%d.%d loading...",
            SHV_VERSION_MAJOR, SHV_VERSION_MINOR, SHV_VERSION_PATCH);

    /* HV-3: stamp the spoof-config magic so user-mode can locate
     * EptHookExtra[] via backdoor qword-scan without a hardcoded offset. */
    g_Shv.EptHookExtraMagic = EPT_HOOK_EXTRA_MAGIC;

    /* Exec-trap hash-capture magics — pair of sentinels so the UM scan
     * can disambiguate the real .data block from a MOV-imm64 in .text. */
    g_Shv.ExecTrapCapMagic    = EXEC_TRAP_CAP_MAGIC;
    g_Shv.ExecTrapCapMagicEnd = EXEC_TRAP_CAP_MAGIC_END;

    g_Shv.CipherTrapMagic    = CIPHER_TRAP_MAGIC;
    g_Shv.CipherTrapMagicEnd = CIPHER_TRAP_MAGIC_END;

    g_Shv.ExecTrapChainMagic    = EXEC_TRAP_CHAIN_MAGIC;
    g_Shv.ExecTrapChainMagicEnd = EXEC_TRAP_CHAIN_MAGIC_END;

    g_Shv.SyscallTrapMagic    = SYSCALL_TRAP_MAGIC;
    g_Shv.SyscallTrapMagicEnd = SYSCALL_TRAP_MAGIC_END;

    g_Shv.ForkCapMagic    = DLLMAIN_FORK_CAP_MAGIC;
    g_Shv.ForkCapMagicEnd = DLLMAIN_FORK_CAP_MAGIC_END;

    /* SHV log ring: self-describing so the NexusDSEFix reader never
     * hardcodes geometry. Stamp the magic LAST -- ShvLogWrite treats it as the
     * arm flag, so the ring only goes live once the geometry fields are valid. */
    g_Shv.ShvLogWriteIdx  = 0;
    g_Shv.ShvLogLines     = SHV_LOG_LINES;
    g_Shv.ShvLogLineLen   = SHV_LOG_LINE_LEN;
    g_Shv.ShvLogMagicEnd  = SHV_LOG_MAGIC_END;
    RtlZeroMemory((PVOID)g_Shv.ShvLogRing, sizeof(g_Shv.ShvLogRing));
    g_Shv.ShvLogMagic     = SHV_LOG_MAGIC;
    SHV_LOG("log ring armed: %u lines x %u chars (NexusDSEFix --shv-log to dump)",
            SHV_LOG_LINES, SHV_LOG_LINE_LEN);

    /* Pre-compute LSTAR PA at PASSIVE_LEVEL before VMX entry.
     * MmGetPhysicalAddress is safe at any IRQL and avoids the VBS/HVCI-broken
     * paths (ShvReadGuestPhysQword disabled; g_PteBase deliberately left 0). */
    {
        ULONG64 lstarVa = __readmsr(0xC0000082);  /* IA32_LSTAR = KiSystemCall64Shadow */
        if (lstarVa) {
            PHYSICAL_ADDRESS lstarPhys = MmGetPhysicalAddress((PVOID)lstarVa);
            g_Shv.LstarPa = (ULONG64)lstarPhys.QuadPart;
            SHV_LOG("DriverEntry: LSTAR VA=0x%llX PA=0x%llX", lstarVa, g_Shv.LstarPa);
        } else {
            SHV_WARN("DriverEntry: IA32_LSTAR reads 0 — LstarPa not set");
        }
    }

    /* Clear CMOS diagnostic region and set entry breadcrumb */
    ShvCmosClearAll();
    ShvCmosWrite(SHV_CMOS_PROGRESS, SHV_PROG_ENTRY);

#ifdef SHV_TEST_LOAD_ONLY
    /* Minimal test: just prove the driver loads. No VMX, no IPI. */
    DriverObject->DriverUnload = ShvDriverUnload;
    ShvCmosWrite(SHV_CMOS_PROGRESS, 0xAA);
    SHV_LOG("TEST MODE: Driver loaded successfully (no VMX)");
    return STATUS_SUCCESS;
#endif

    /* Manual map path (DriverObject == NULL): always defer VMX init to a system
     * thread. Running KeIpiGenericCall + VMLAUNCH synchronously inside the
     * mapper's SetVariable hook context causes a freeze — the newly virtualized
     * environment conflicts with the in-flight SetVariable return path.
     * The deferred thread runs in a clean context after the mapper call returns. */
    if (DriverObject == NULL) {
        ShvCmosWrite(SHV_CMOS_PROGRESS, SHV_PROG_DEFERRED_START);
        HANDLE threadHandle = NULL;
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
        NTSTATUS threadSt = PsCreateSystemThread(
            &threadHandle, THREAD_ALL_ACCESS, &oa, NULL, NULL,
            ShvDeferredVmxInit, NULL);
        if (NT_SUCCESS(threadSt) && threadHandle) {
            ZwClose(threadHandle);
            ShvCmosWrite(SHV_CMOS_PROGRESS, SHV_PROG_DEFERRED_THREAD);
            SHV_LOG("VMX init deferred to system thread (manual map)");
        } else {
            SHV_ERR("Failed to create deferred VMX thread: 0x%08X", threadSt);
            ShvCmosWrite(SHV_CMOS_PROGRESS, 0xE1);
            return threadSt;
        }
        return STATUS_SUCCESS;
    }

    ShvCmosWrite(SHV_CMOS_PROGRESS, 0x0A);  /* 0A = IRQL ok */

    /* Set up unload + device */
    if (DriverObject != NULL) {
        DriverObject->DriverUnload = ShvDriverUnload;
        status = IoCreateDevice(
            DriverObject, 0, (PUNICODE_STRING)&DeviceName,
            FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE,
            &g_Shv.DeviceObject
        );
        if (!NT_SUCCESS(status)) {
            SHV_ERR("IoCreateDevice failed 0x%08X", status);
            ShvCmosWrite(SHV_CMOS_PROGRESS, 0xED);
            return status;
        }
    }
    ShvCmosWrite(SHV_CMOS_PROGRESS, 0x0E);  /* 0E = device created */

    /* Check VMX support */
    if (!ShvIsVmxSupported()) {
        SHV_ERR("VMX not supported on this platform");
        if (g_Shv.DeviceObject) { IoDeleteDevice(g_Shv.DeviceObject); g_Shv.DeviceObject = NULL; }
        ShvCmosWrite(SHV_CMOS_PROGRESS, 0xE2);
        return STATUS_NOT_SUPPORTED;
    }
    ShvCmosWrite(SHV_CMOS_PROGRESS, SHV_PROG_VMX_OK);

    /* Allocate per-CPU VCPU structures */
    status = ShvAllocateVcpuArray();
    if (!NT_SUCCESS(status)) {
        SHV_ERR("Failed to allocate VCPU array 0x%08X", status);
        IoDeleteDevice(g_Shv.DeviceObject);
        g_Shv.DeviceObject = NULL;
        ShvCmosWrite(SHV_CMOS_PROGRESS, 0xE3);
        return status;
    }
    ShvCmosWrite(SHV_CMOS_PROGRESS, SHV_PROG_VCPU_ALLOC);
    ShvCmosWrite(SHV_CMOS_CPU_COUNT, (UCHAR)g_Shv.ProcessorCount);

    /* Virtualize ALL processors via IPI */
    ShvCmosWrite(SHV_CMOS_PROGRESS, SHV_PROG_IPI_DISPATCH);
    status = ShvVirtualizeAllProcessors();
    if (!NT_SUCCESS(status)) {
        SHV_ERR("Virtualization failed 0x%08X", status);
        ShvCmosWrite(SHV_CMOS_PROGRESS, 0xE5);
        ShvFreeVcpuArray();
        if (g_Shv.DeviceObject) { IoDeleteDevice(g_Shv.DeviceObject); g_Shv.DeviceObject = NULL; }
        return status;
    }

    ShvCmosWrite(SHV_CMOS_PROGRESS, SHV_PROG_RUNNING);
    SHV_LOG("SentinelHV loaded — all CPUs virtualized");

    /* Resource preps (mirrors ShvDeferredVmxInit). Split-PT pool and trap log
     * rings must be allocated before the first UM install request arrives. */
    {
        NTSTATUS secSt = ShvEptInitializeSecondary();
        if (NT_SUCCESS(secSt)) {
            g_Shv.PrimaryEptp   = ShvEptGetEptp();
            g_Shv.SecondaryEptp = ShvEptGetSecondaryEptp();
            SHV_LOG("Dual-EPT ready: primary=0x%llX secondary=0x%llX",
                    g_Shv.PrimaryEptp, g_Shv.SecondaryEptp);
            (void)ShvAutoArmRegister();
        } else {
            SHV_WARN("Secondary EPT alloc failed 0x%08X — hooks unavailable", secSt);
        }

        NTSTATUS hookResSt = ShvEptPrepareHookResources();
        if (!NT_SUCCESS(hookResSt))
            SHV_WARN("Hook resource alloc failed 0x%08X", hookResSt);

        NTSTATUS xcapResSt = ShvEptPrepareXcapResources();
        if (!NT_SUCCESS(xcapResSt))
            SHV_WARN("Xcap resource alloc failed 0x%08X", xcapResSt);

        NTSTATUS wtResSt = ShvEptPrepareWriteTrapResources();
        if (!NT_SUCCESS(wtResSt))
            SHV_WARN("WriteTrap resource alloc failed 0x%08X", wtResSt);

        NTSTATUS rtResSt = ShvEptPrepareReadTrapResources();
        if (!NT_SUCCESS(rtResSt))
            SHV_WARN("ReadTrap resource alloc failed 0x%08X", rtResSt);

        NTSTATUS xtResSt = ShvEptPrepareExecTrapResources();
        if (!NT_SUCCESS(xtResSt))
            SHV_WARN("ExecTrap resource alloc failed 0x%08X — exec-trap unavailable", xtResSt);

        NTSTATUS rtTrSt = ShvEptPrepareRipTraceResources();
        if (!NT_SUCCESS(rtTrSt))
            SHV_WARN("RipTrace resource alloc failed 0x%08X", rtTrSt);

        NTSTATUS ctSt = ShvCipherTrapPrepareResources();
        if (!NT_SUCCESS(ctSt))
            SHV_WARN("CipherTrap resource alloc failed 0x%08X", ctSt);

        {
            SIZE_T logSize = sizeof(SYSCALL_LOG_ENTRY) * SYSCALL_LOG_MAX;
            PVOID logBuf = ShvAllocateContiguousMemory(logSize);
            if (logBuf) {
                RtlZeroMemory(logBuf, logSize);
                g_Shv.SyscallLog = (PSYSCALL_LOG_ENTRY)logBuf;
            } else {
                SHV_WARN("Syscall trace log allocation failed");
            }
        }
    }

    /* TPM FIFO page remap: split 2MB page at 0xFED00000-0xFEEFFFFF
     * and redirect 0xFED10000 to a shadow buffer containing spoofed
     * TPM identity registers. */
    if (ShvEptIsEnabled()) {
        /* Allocate a 4KB shadow page */
        PVOID shadowVa = ShvAllocateContiguousMemory(TPM_FIFO_SIZE);
        if (shadowVa) {
            RtlZeroMemory(shadowVa, TPM_FIFO_SIZE);

            /* Step 1: Copy real FIFO data to shadow BEFORE remap.
             * After remap, reads of 0xFED10000 get the shadow. */
            {
                PHYSICAL_ADDRESS fifoPhys;
                fifoPhys.QuadPart = (LONGLONG)TPM_FIFO_PA;
                PVOID fifoVa = MmMapIoSpace(fifoPhys, TPM_FIFO_SIZE, MmNonCached);
                if (fifoVa) {
                    RtlCopyMemory(shadowVa, fifoVa, TPM_FIFO_SIZE);
                    MmUnmapIoSpace(fifoVa, TPM_FIFO_SIZE);
                    SHV_LOG("TPM FIFO: copied real data to shadow");
                }
            }

            /* Step 2: Spoof identity registers in the shadow.
             * Uses g_MacSeed if set by the mapper, else fallback seed. */
            ShvSpoofFifoIdentity(shadowVa);

            /* Step 3: Do the EPT remap */
            ULONG64 shadowPa = MmGetPhysicalAddress(shadowVa).QuadPart;
            NTSTATUS remapSt = ShvEptRemapPage(TPM_FIFO_PA, shadowPa);
            if (NT_SUCCESS(remapSt)) {
                SHV_LOG("TPM FIFO at 0x%llX remapped to shadow at PA 0x%llX",
                        TPM_FIFO_PA, shadowPa);
                ShvCmosWrite(SHV_CMOS_PROGRESS, 0xEF);  /* 0xEF = TPM remap active */

                /* Arm the FIFO read-trap via VMCALL (must run in VMX root) */
                NTSTATUS trapSt = ShvDoVmcall(VMCALL_FIFO_TRAP, 1 /* enable */);
                if (NT_SUCCESS(trapSt)) {
                    InterlockedExchange(&g_Shv.FifoTrapActive, 1);
                    SHV_LOG("TPM FIFO read-trap armed");
                    /* Broadcast INVEPT to all CPUs */
                    KeIpiGenericCall(ShvVirtualizeIpiCallback_InveptOnly, 0);
                    SHV_LOG("INVEPT broadcast to all %lu CPUs", g_Shv.ProcessorCount);
                } else {
                    SHV_WARN("TPM FIFO read-trap VMCALL failed: 0x%08X", trapSt);
                }
            } else {
                SHV_ERR("TPM FIFO remap failed: 0x%08X", remapSt);
                MmFreeContiguousMemory(shadowVa);
            }

            /* Also remap TPM CRB page (0xFED40000) to the same shadow.
             * .grfn22 has 2 CRB refs. CRB and FIFO identity registers are at
             * the same offsets, so reusing the same shadow buffer works.
             * CRB is in a DIFFERENT 2MB page than FIFO, so ShvEptRemapPage
             * will allocate a second split PT. */
            NTSTATUS crbSt = ShvEptRemapPage(TPM_CRB_PA, shadowPa);
            if (NT_SUCCESS(crbSt)) {
                SHV_LOG("TPM CRB at 0x%llX remapped to shadow at PA 0x%llX",
                        TPM_CRB_PA, shadowPa);
            } else {
                SHV_WARN("TPM CRB remap failed: 0x%08X (non-fatal, DXE hooks cover CRB)",
                         crbSt);
            }
        }
    }

    return STATUS_SUCCESS;
}
