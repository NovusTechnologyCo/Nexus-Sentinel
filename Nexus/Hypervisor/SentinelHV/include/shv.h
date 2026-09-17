/**
 * @file shv.h
 * @brief Master include header, global state, and public API for SentinelHV.
 *
 * This is the single top-level header that all SentinelHV source files include.
 * It aggregates all sub-headers (platform, VMX, architecture, VMCS, EPT, exit
 * handlers, CMOS diagnostics), defines the global hypervisor state structure,
 * and declares the public API for VMX lifecycle management, VCPU allocation,
 * utility functions, and assembly-implemented helpers.
 *
 * SentinelHV is a dual-target VMX hypervisor core that compiles as both:
 *   - Type 2 (hosted): Windows WDK kernel driver (.sys)
 *   - Type 1 (bare-metal): UEFI DXE module for NexusSentinel bootkit
 *
 * Platform selection is handled by shv_platform.h via SHV_PLATFORM_NT or
 * SHV_PLATFORM_EFI preprocessor defines.
 */

#pragma once

#include "shv_platform.h"

#include "shv_vmx.h"
#include "shv_arch.h"
#include "shv_vmcs.h"
#include "shv_exit.h"
#include "shv_ept.h"
#include "shv_cmos.h"

/* ── Version ──────────────────────────────────────────────────────── */

#define SHV_VERSION_MAJOR   0
#define SHV_VERSION_MINOR   1
#define SHV_VERSION_PATCH   0

/* ── FIFO Access Trace Log ────────────────────────────────────────── */

#define FIFO_ACCESS_LOG_MAX  64

typedef struct _FIFO_ACCESS_LOG_ENTRY {
    ULONG64  GuestRip;        /* Instruction that accessed the FIFO page */
    ULONG64  GuestCr3;        /* Process page table (identifies which process) */
    ULONG64  GuestLinearAddr; /* VA the guest used to access FIFO */
    ULONG32  GpaOffset;       /* Offset within the FIFO page (0x000-0xFFF) */
    ULONG32  CpuIndex;        /* Which logical processor */
    ULONG32  AccessType;      /* Read=1, Write=2, Execute=4 */
    ULONG32  Counter;         /* Monotonically increasing event number */
} FIFO_ACCESS_LOG_ENTRY, *PFIFO_ACCESS_LOG_ENTRY;

/* ── Syscall Trace Log (kernel API call logging) ─────────────────── */

#define SYSCALL_LOG_MAX  4096   /* 4096 * 72 = 288 KB — fills in <100ms, hooks auto-stop fast */

typedef struct _SYSCALL_LOG_ENTRY {
    ULONG64  CallerRip;    /* Return address from [RSP] — who called the function */
    ULONG64  TargetVa;     /* Function VA that was called (from hook table) */
    ULONG64  GuestCr3;     /* Process CR3 at time of call */
    ULONG64  Arg1;         /* RCX — 1st arg (x64 fastcall) */
    ULONG64  Arg2;         /* RDX — 2nd arg */
    ULONG64  Arg3;         /* R8  — 3rd arg */
    ULONG64  Arg4;         /* R9  — 4th arg */
    ULONG64  Rax;          /* RAX — return value / general state (pool tag scans need this) */
    ULONG64  Rbx;          /* RBX — callee-saved, often holds context pointers */
    ULONG32  HookIndex;    /* Index into EptHooks[] */
    ULONG32  CpuIndex;     /* Logical processor number */
    ULONG32  Counter;      /* Monotonic sequence number */
    ULONG32  CaptureFlags; /* bit 0 = IRP snapshot valid, bit 1 = CallerRip valid */
    /* IRP snapshot — populated if Arg2 (RDX) looks like an IRP pointer.
     * Captured at hook-fire time via safe VMX root read (page-table check). */
    UCHAR    IrpMajorFunction;  /* IO_STACK_LOCATION.MajorFunction */
    UCHAR    IrpMinorFunction;  /* IO_STACK_LOCATION.MinorFunction */
    UCHAR    IrpFlags;          /* IO_STACK_LOCATION.Flags */
    UCHAR    IrpControl;        /* IO_STACK_LOCATION.Control */
    ULONG32  IrpIoControlCode;  /* Parameters.DeviceIoControl.IoControlCode */
    ULONG32  IrpInputLength;    /* Parameters.DeviceIoControl.InputBufferLength */
    ULONG32  IrpOutputLength;   /* Parameters.DeviceIoControl.OutputBufferLength */
    /* Generic buffer snapshot: first 64 bytes of R8 (Arg3) if it's a kernel VA.
     * For IRP_MJ_DEVICE_CONTROL hooks: R8 is often unused (holds leftover regs).
     * For FltSendMessage hooks: R8 is SenderBuffer — the message payload. */
    UCHAR    BufferSnapshot[64];
} SYSCALL_LOG_ENTRY, *PSYSCALL_LOG_ENTRY;

#define SLOG_FLAG_IRP_VALID        0x00000001
#define SLOG_FLAG_CALLERRIP_VALID  0x00000002
#define SLOG_FLAG_BUFFER_VALID     0x00000004

C_ASSERT(sizeof(SYSCALL_LOG_ENTRY) == 168);

/* ── RIP single-step trace  ───────────────────────────
 * Tiny 16-byte entries — just RIP + CR3. Enough to reconstruct the
 * scanner's executed-instruction stream (we can re-disassemble each
 * RIP against the captured page dumps). Full register state is a
 * follow-up if needed.
 *
 * Ring size: 16K entries * 16 bytes = 256 KB. Enough to capture
 * 3x a typical Griffin-dispatched memcpy cycle (~3000-5000 insns). */
#define RIP_TRACE_LOG_MAX  16384
#define RIP_TRACE_MAGIC    0xBEEFFEEDCAFEF00DULL
#define AUTO_ARM_MAGIC     0xAEAE0A2EAEA2E000ULL  /* 'AEAR ARM' sentinel */

/* Exec-trap hash-capture  — extends the exec-trap log entry's
 * existing Payload[64] with live guest-memory bytes read from a chosen GPR's
 * target VA at exec-hit time. Built for .grfn11 handler #3 (MD5 primitive):
 * when the handler executes, capture the N-byte buffer that RCX/RDX points
 * at — that's the hash PRE-IMAGE, i.e. what the target is actually hashing. */
#define EXEC_TRAP_CAP_MAGIC      0xCAFE15EC7E700000ULL  /* exec-trap capture start sentinel */
#define EXEC_TRAP_CAP_MAGIC_END  0xCAFE15EC7E7EEEEEULL  /* end sentinel (for UM to disambiguate from code immediates) */

/* Chained exec-trap (iter#179) — anchor→target VMX-root swap.
 * UM locates this block by scanning g_Shv for EXEC_TRAP_CHAIN_MAGIC.
 * Relative offsets from magic (used by the host-side trap tool):
 *   +0x00  ExecTrapChainMagic
 *   +0x08  ExecTrapChainEnabled    (ULONG64: 0=off, 1=armed)
 *   +0x10  ExecTrapChainFired      (ULONG64: 0=pending, 1=stage1-fired, 2=stage2-fired)
 *   +0x18  ExecTrapChainAnchorVa   (exact anchor RIP, e.g. preloader_l+0x3400)
 *   +0x20  ExecTrapChainTargetPa   (4KB-aligned PA of chain target, pre-split by guest)
 *   +0x28  ExecTrapChainTargetVaBase (page-aligned VA of chain target)
 *   +0x30  ExecTrapChainTargetCr3  (launcher process CR3)
 *   +0x38  ExecTrapChainAutoStop   (auto-stop count for chained target, 0=inherit)
 *   +0x40  PendingExecTrapChainAnchorVa
 *   +0x48  PendingExecTrapChainTargetPa
 *   +0x50  PendingExecTrapChainTargetVaBase
 *   +0x58  PendingExecTrapChainTargetCr3
 *   +0x60  PendingExecTrapChainAutoStop
 *   +0x68  PendingExecTrapChainOp  (1=enable, 2=disable)
 *   +0x70  PendingExecTrapChainResult (0=none, 1=ok, 0xE5=fail)
 *   +0x78  ExecTrapChainMagicEnd */
#define EXEC_TRAP_CHAIN_MAGIC      0xC4A1D15C7E700001ULL
#define EXEC_TRAP_CHAIN_MAGIC_END  (~EXEC_TRAP_CHAIN_MAGIC)

/* Syscall SSN trap  — extends exec-trap with an optional RAX filter.
 * At KiSystemCall64Shadow entry: RAX=SSN, RSP=user RSP, [RSP+0x28]=StartRoutine.
 * ExecTrapCapSrc=RSP/capLen=0x40 captures the stack window into Payload, exposing
 * StartRoutine without needing an additional read. ExecTrapRaxFilter drops all
 * exec-trap hits where RAX != filter, keeping the 1024-entry ring from overflowing
 * at ~5000 unrelated syscalls/sec. PendingQueryLstarOp reads IA32_LSTAR in
 * VMX-root; PendingTranslateKvaOp translates a kernel VA → PA via the host CR3,
 * letting UM pass the LSTAR page's PA without the UWTR mapper (which only handles UM VAs).
 * UM locates this block by scanning g_Shv for SYSCALL_TRAP_MAGIC. */
#define SYSCALL_TRAP_MAGIC      0x5A1155CA11CAFE00ULL
#define SYSCALL_TRAP_MAGIC_END  (~SYSCALL_TRAP_MAGIC)

/* Relative offsets from SyscallTrapMagic into the SSN-trap sentinel block.
 * Used by shv.h C_ASSERTs and mirrored as ST_OFF_* in the host-side trap tool. */
#define SST_OFF_MAGIC                     0x00
#define SST_OFF_RAXFILTER                 0x08
#define SST_OFF_RAXFILTERED               0x10  /* LONG + LONG pad at +0x14 */
#define SST_OFF_QUERY_LSTAR_OP            0x18
#define SST_OFF_QUERY_LSTAR_RESULT        0x20
#define SST_OFF_TRANSLATE_KVA_VA          0x28
#define SST_OFF_TRANSLATE_KVA_OP          0x30
#define SST_OFF_TRANSLATE_KVA_RESULT      0x38
#define SST_OFF_PENDING_RAXFILTER         0x40
#define SST_OFF_PENDING_RAXFILTER_OP      0x48
#define SST_OFF_PENDING_RAXFILTER_RESULT  0x50
#define SST_OFF_LSTAR_PA                  0x58  /* PA of LSTAR page; filled at DriverEntry via MmGetPhysicalAddress */
#define SST_OFF_MAGIC_END                 0x60  /* was 0x58 before LstarPa was added */

/* Register selectors for the capture source pointer. Values picked so
 * UM-side parse is trivial (decimal). */
#define EXEC_TRAP_CAP_SRC_NONE  0
#define EXEC_TRAP_CAP_SRC_RAX   1
#define EXEC_TRAP_CAP_SRC_RCX   2
#define EXEC_TRAP_CAP_SRC_RDX   3
#define EXEC_TRAP_CAP_SRC_RSI   4
#define EXEC_TRAP_CAP_SRC_RDI   5
#define EXEC_TRAP_CAP_SRC_RSP   6   /* dereference [RSP] (stack top) */
#define EXEC_TRAP_CAP_SRC_R12   7   /* dereference [R12] (cipher state frame ptr A) */
#define EXEC_TRAP_CAP_SRC_R13   8   /* dereference [R13] (cipher state frame ptr B) */
#define EXEC_TRAP_CAP_SRC_R9    9   /* dereference [R9]  (jmp-r9 dispatch target — PAGE_EXECUTE-only, SHV reads via DirectMap) */
#define EXEC_TRAP_CAP_SRC_MAX   9

#define EXEC_TRAP_CAP_OP_SET      1
#define EXEC_TRAP_CAP_OP_DISABLE  2

typedef struct _RIP_TRACE_ENTRY {
    ULONG64 GuestRip;
    ULONG64 GuestCr3;
} RIP_TRACE_ENTRY, *PRIP_TRACE_ENTRY;

C_ASSERT(sizeof(RIP_TRACE_ENTRY) == 16);

/* ── Xcap (execute-trap page capture) ─────────────────────────────── */

/* Max pages that can be tracked in a single xcap session.
 * 49152 entries * 4 KB = 192 MB of captured page data.
 *
 * Sized for EAAntiCheat.GameService.exe which is ~172 MB (44,057 pages).
 * The earlier 8192-page limit was ~18 MB which only covered the first
 * ~18% of the GameService image — the in-image RIP samples that the
 * RIP-sampling diagnostic spotted were mostly in the unsampled tail
 * (pages 8192+).
 *
 * Memory cost (pre-allocated NonPagedPool):
 *   XcapPageData       49152 * 4 KB = 192 MB
 *   Pre-alloc splits   49152 * 4 KB = 192 MB  (worst case, one split per page)
 *   XcapEntries        49152 * 48 B = 2.25 MB
 *   XcapPaTable        49152 * 8 B  = 384 KB
 *   XcapBitmap         49152 / 8    = 6 KB
 *   ────────────────────────────────────────
 *   Total ≈ 387 MB pre-allocation at xcap init (one-time).
 *
 * If ExAllocatePool2 fails for the page-data buffer at this size on
 * lower-memory systems, the install will surface a SHV_ERR and the
 * status path will report HV xcap active = no — at which point dial
 * back to a smaller value (e.g. 32768 = 128 MB image ceiling). */
#define XCAP_MAX_PAGES   49152

/* Bitmap covering XCAP_MAX_PAGES, one bit per page (set = captured). */
#define XCAP_BITMAP_WORDS  ((XCAP_MAX_PAGES + 31) / 32)

/* Max number of distinct 2 MB EPT regions that can be split for xcap.
 *
 * IMPORTANT: this is bounded by the physical layout of the trapped pages,
 * NOT their virtual layout. User-mode image pages are demand-paged by the
 * kernel one-at-a-time and have no physical contiguity guarantee, so 4096
 * 4 KB pages can land in 4096 distinct physical 2 MB regions in the worst
 * case. Setting this lower than XCAP_MAX_PAGES means we silently drop
 * traps once the slots are full (confirmed via test: 322 trapped + 3774
 * no-split when this was 64 against an 18 MB image).
 *
 * Memory cost: each pre-allocated split is sizeof(EPT_PTE)*512 = 4 KB, so
 * XCAP_SPLIT_MAX=8192 → 32 MB of non-paged pool reserved at boot. */
#define XCAP_SPLIT_MAX   XCAP_MAX_PAGES

typedef struct _XCAP_ENTRY {
    ULONG64 GuestPa;     /* Physical address of the captured 4 KB page */
    ULONG64 GuestVa;     /* Virtual address (page-aligned) */
    ULONG64 GuestRip;    /* RIP that first executed in this page */
    ULONG64 GuestCr3;    /* CR3 at the moment of capture */
    ULONG32 PageIndex;   /* Index in XcapPageData / XcapEntries */
    ULONG32 CpuIndex;    /* Logical processor that captured the page */
    ULONG32 Counter;     /* Capture sequence number (1-based) */
    ULONG32 Reserved;    /* Pad to 48 bytes */
} XCAP_ENTRY, *PXCAP_ENTRY;

C_ASSERT(sizeof(XCAP_ENTRY) == 48);

/* ── KM Cipher Trap  ────────────────────────────
 * Multi-site EPT execute-trap that fires on the ret instruction of each
 * of the 80 KM cipher functions, capturing all GPRs + a 256-byte
 * snapshot of the output buffer (post-decryption). */

#define CIPHER_TRAP_MAGIC         0xC1FE7C0DE0000001ULL
#define CIPHER_TRAP_MAGIC_END     (~CIPHER_TRAP_MAGIC)
#define CIPHER_TRAP_MAX_SITES     80
#define CIPHER_RECORD_MAX         8192
#define CIPHER_TRAP_PAYLOAD_BYTES 256

#define CIPHER_TRAP_OP_INSTALL    1
#define CIPHER_TRAP_OP_UNINSTALL  2
#define CIPHER_TRAP_OP_STATUS     3
/* OP_SETMASK: suppress logging for specific sites (trap stays armed).
 * PendingCipherTrapKmBase = skip mask bits 0..63 (site indices 0..63)
 * PendingCipherTrapKmSize = skip mask bits 64..79 (site indices 64..79) */
#define CIPHER_TRAP_OP_SETMASK    4

typedef struct _KM_CIPHER_RECORD {
    UINT32  SiteIndex;    /* 0x000 */
    UINT32  CpuIndex;     /* 0x004 */
    UINT64  Tsc;          /* 0x008 */
    UINT64  GuestRip;     /* 0x010 */
    UINT64  GuestCr3;     /* 0x018 */
    UINT64  Rax;          /* 0x020 */
    UINT64  Rcx;          /* 0x028 */
    UINT64  Rdx;          /* 0x030 */
    UINT64  Rbx;          /* 0x038 */
    UINT64  Rsp;          /* 0x040 */
    UINT64  Rbp;          /* 0x048 */
    UINT64  Rsi;          /* 0x050 */
    UINT64  Rdi;          /* 0x058 */
    UINT64  R8;           /* 0x060 */
    UINT64  R9;           /* 0x068 */
    UINT64  R10;          /* 0x070 */
    UINT64  R11;          /* 0x078 */
    UINT64  R12;          /* 0x080 */
    UINT64  R13;          /* 0x088 */
    UINT64  R14;          /* 0x090 */
    UINT64  R15;          /* 0x098 */
    UINT64  BufVa;        /* 0x0A0 — VA we attempted to snapshot */
    UINT32  PayloadLen;   /* 0x0A8 — valid bytes in Payload */
    UINT32  Reserved;     /* 0x0AC */
    UINT8   Payload[CIPHER_TRAP_PAYLOAD_BYTES]; /* 0x0B0 */
} KM_CIPHER_RECORD, *PKM_CIPHER_RECORD;

C_ASSERT(sizeof(KM_CIPHER_RECORD) == 432);

/* ── DllMain Fork Capture  ──────────────────────────────
 * Dual-site DR-execute trap (#DB) at gsl+0x36A3A7 (Griffin VM entry,
 * fork decision input) and gsl+0x28A7314 (cipher site, 63 insns later).
 * The #DB handler captures all 16 GPRs + RSP/RIP/CR3 from GuestContext
 * and VMCS, then reads the guest stack in-VMX-root via ForkCapTranslateVa
 * (4-level page-table walk using ShvEptReadPhysicalPage / MmMapIoSpaceEx —
 * the same path already used by VMCALL_EPT_READ_PAGE; DirectMapBase and
 * g_PteBase are both disabled on this system and must not be used).
 * The Python tool reads ForkCapRecords[] via NexusDSEFix --fork-cap read
 * once ForkCapAllFired == 1. */

#define DLLMAIN_FORK_CAP_MAGIC      0xD11F07CA9E000000ULL
#define DLLMAIN_FORK_CAP_MAGIC_END  (~DLLMAIN_FORK_CAP_MAGIC)

/* ── SHV log ring  ─────────────────────────────────────
 * See the ShvLogRing block at the end of SHV_GLOBAL. 512 lines x 192 chars
 * = 96 KB; enough to hold a whole capture run's worth of chain output.
 * The magics let NexusDSEFix locate/validate the ring by scanning, exactly
 * like the syscall-trap and fork-capture blocks already do. */
#define SHV_LOG_MAGIC       0x5348564C4F471000ULL   /* "SHVLOG" + version nibble */
#define SHV_LOG_MAGIC_END   (~SHV_LOG_MAGIC)
#define SHV_LOG_LINES       512
#define SHV_LOG_LINE_LEN    192
#define DLLMAIN_FORK_CAP_SITES      2
#define DLLMAIN_FORK_OP_ARM         1ULL
#define DLLMAIN_FORK_OP_DISARM      2ULL
#define DLLMAIN_FORK_OP_STATUS      3ULL

#define DLLMAIN_FORK_STACK_BELOW    0x40   /* bytes below RSP (shadow space + red zone) */
#define DLLMAIN_FORK_STACK_BYTES    0x800  /* total stack snapshot window (2 KB) */

/* ── ForkCap block offsets relative to ForkCapMagic (NexusDSEFix / Python) ── */
#define FKC_OFF_MAGIC               0x000
#define FKC_OFF_SITE_VA_0           0x008
#define FKC_OFF_SITE_VA_1           0x010
#define FKC_OFF_TARGET_CR3          0x018
#define FKC_OFF_ARMED               0x020  /* LONG */
#define FKC_OFF_HITS                0x024  /* LONG */
#define FKC_OFF_ALL_FIRED           0x028  /* LONG */
#define FKC_OFF_RECORDS             0x030  /* DLLMAIN_FORK_RECORD[DLLMAIN_FORK_CAP_SITES] */
/* record[1] starts at FKC_OFF_RECORDS + sizeof(DLLMAIN_FORK_RECORD) = 0x030 + 0x8B0 = 0x8E0 */
#define FKC_OFF_PENDING_VA_0        0x1190
#define FKC_OFF_PENDING_VA_1        0x1198
#define FKC_OFF_PENDING_CR3         0x11A0
#define FKC_OFF_PENDING_OP          0x11A8
#define FKC_OFF_PENDING_RESULT      0x11B0
#define FKC_OFF_MAGIC_END           0x11B8

/* ── DLLMAIN_FORK_RECORD intra-record offsets ── */
#define FKC_REC_SIZE                0x8B0  /* sizeof(DLLMAIN_FORK_RECORD) */
#define FKC_REC_OFF_SITE_INDEX      0x000  /* ULONG32 */
#define FKC_REC_OFF_DR_NUM          0x004  /* ULONG32 */
#define FKC_REC_OFF_CPU_INDEX       0x008  /* ULONG32 */
#define FKC_REC_OFF_FIRED           0x00C  /* ULONG32; set LAST after all fields written */
#define FKC_REC_OFF_GUEST_RIP       0x010  /* ULONG64 */
#define FKC_REC_OFF_GUEST_CR3       0x018  /* ULONG64 */
#define FKC_REC_OFF_RAX             0x020
#define FKC_REC_OFF_RCX             0x028
#define FKC_REC_OFF_RDX             0x030
#define FKC_REC_OFF_RBX             0x038
#define FKC_REC_OFF_RSP             0x040
#define FKC_REC_OFF_RBP             0x048
#define FKC_REC_OFF_RSI             0x050
#define FKC_REC_OFF_RDI             0x058
#define FKC_REC_OFF_R8              0x060
#define FKC_REC_OFF_R9              0x068
#define FKC_REC_OFF_R10             0x070
#define FKC_REC_OFF_R11             0x078
#define FKC_REC_OFF_R12             0x080
#define FKC_REC_OFF_R13             0x088
#define FKC_REC_OFF_R14             0x090
#define FKC_REC_OFF_R15             0x098
#define FKC_REC_OFF_STACK_VA_BASE   0x0A0  /* ULONG64: RSP - DLLMAIN_FORK_STACK_BELOW */
#define FKC_REC_OFF_STACK_LEN       0x0A8  /* ULONG32: valid bytes in Stack[] */
#define FKC_REC_OFF_STACK_PAD       0x0AC  /* ULONG32: alignment */
#define FKC_REC_OFF_STACK           0x0B0  /* UCHAR[DLLMAIN_FORK_STACK_BYTES] */

typedef struct _DLLMAIN_FORK_RECORD {
    ULONG32  SiteIndex;         /* 0x000: 0 = gsl+0x36A3A7, 1 = gsl+0x28A7314 */
    ULONG32  DrNum;             /* 0x004: which DR fired (0 or 1) */
    ULONG32  CpuIndex;          /* 0x008 */
    ULONG32  Fired;             /* 0x00C: set to 1 LAST (fence) after all other fields written */
    ULONG64  GuestRip;          /* 0x010 */
    ULONG64  GuestCr3;          /* 0x018 */
    ULONG64  Rax;               /* 0x020 */
    ULONG64  Rcx;               /* 0x028 */
    ULONG64  Rdx;               /* 0x030 */
    ULONG64  Rbx;               /* 0x038 */
    ULONG64  Rsp;               /* 0x040: from VMCS_GUEST_RSP (not in GuestContext) */
    ULONG64  Rbp;               /* 0x048 */
    ULONG64  Rsi;               /* 0x050 */
    ULONG64  Rdi;               /* 0x058 */
    ULONG64  R8;                /* 0x060 */
    ULONG64  R9;                /* 0x068 */
    ULONG64  R10;               /* 0x070 */
    ULONG64  R11;               /* 0x078 */
    ULONG64  R12;               /* 0x080 */
    ULONG64  R13;               /* 0x088 */
    ULONG64  R14;               /* 0x090 */
    ULONG64  R15;               /* 0x098 */
    ULONG64  StackVaBase;       /* 0x0A0: RSP - DLLMAIN_FORK_STACK_BELOW (capture window start) */
    ULONG32  StackLen;          /* 0x0A8: valid bytes in Stack[]; 0 if VA walk failed */
    ULONG32  StackPad;          /* 0x0AC: alignment */
    UCHAR    Stack[DLLMAIN_FORK_STACK_BYTES]; /* 0x0B0 */
} DLLMAIN_FORK_RECORD, *PDLLMAIN_FORK_RECORD;

C_ASSERT(sizeof(DLLMAIN_FORK_RECORD) == 0x8B0);

/* ── UM EPT Write-Trap (D2-class) ─────────────────────────────────
 * Closes the "decoded-per-compare" gap (memory/denylist_decoded_on_compare.md).
 * Trap writes to a nominated user-mode VA inside a target process; log
 * writer RIP + payload bytes. Sub-page VA filter + per-process CR3 filter.
 * Spec: tools/the design notes.
 *
 * This block is compile-time-only until g_Shv.WriteTrapActive = 1; zero
 * runtime behavior change for existing code paths on boot. */

#define WRITE_TRAP_LOG_MAX       4096       /* 4096 * 160 B = 640 KB ring */
#define WRITE_TRAP_PAYLOAD_BYTES 64
#define WRITE_TRAP_HOOK_INDEX_SENTINEL 0xFF /* "MTF re-arm, do not log" */

/* Pending-op values for PendingWriteTrapOp (§2.2 of spec). */
#define WRITE_TRAP_OP_INSTALL   1
#define WRITE_TRAP_OP_UNINSTALL 2
#define WRITE_TRAP_OP_STATUS    3

/* UM EPT Read-Trap (Phase C-R, Apr 2026) — mirrors write-trap but traps reads.
 * Uses the same ring size / payload size. Distinct hook-index sentinel (0xFE)
 * so MTF handler can tell which trap set the pending flag. */
#define READ_TRAP_LOG_MAX              4096
#define READ_TRAP_PAYLOAD_BYTES        64
#define READ_TRAP_HOOK_INDEX_SENTINEL  0xFE

#define READ_TRAP_OP_INSTALL   1
#define READ_TRAP_OP_UNINSTALL 2
#define READ_TRAP_OP_STATUS    3

/* UM EPT Exec-Trap (Phase C-X, Apr 2026) — traps instruction fetches.
 * Clears only Execute on the target PTE (keeps R=W=1) so data reads/writes
 * pass through unchanged. Hit handler logs the RIP that executed on the
 * trapped page, then MTF re-arms X=0. Primary use: catch scanner RETURN
 * into post-memcpy dispatcher page, then arm RIP-trace for dispatcher
 * instruction capture — bypasses ~20000-step MTF waste inside memcpy. */
#define EXEC_TRAP_LOG_MAX              1024   /* 1024 × 1024 B = 1 MB ring */
#define EXEC_TRAP_PAYLOAD_BYTES        512    /* [RSP..RSP+0x200] stack window */
#define EXEC_TRAP_HOOK_INDEX_SENTINEL  0xFD

#define EXEC_TRAP_OP_INSTALL   1
#define EXEC_TRAP_OP_UNINSTALL 2
#define EXEC_TRAP_OP_STATUS    3

typedef struct _WRITE_TRAP_LOG_ENTRY {
    ULONG64  WriterRip;                         /* Instruction that wrote */
    ULONG64  FaultVa;                           /* VMCS_RO_GUEST_LINEAR_ADDR */
    ULONG64  GuestCr3;                          /* Verifies CR3 match at log time */
    ULONG64  WriterRsp;                         /* Stack base at write (locality diag) */
    ULONG64  Rax;                               /* For "mov [mem], rax" etc. */
    ULONG64  Rcx;                               /* strcpy-style src ptr */
    ULONG64  Rdx;                               /* Additional context */
    ULONG64  Rsi;                               /* memcpy src */
    ULONG64  Rdi;                               /* memcpy dst — should align with FaultVa */
    ULONG64  Tsc;                               /* __rdtsc at capture time */
    ULONG32  ExitQualification;                 /* low 32 bits — R/W/X, entry perms */
    ULONG32  CpuIndex;                          /* Logical CPU number */
    ULONG32  Counter;                           /* Monotonic sequence */
    ULONG32  PayloadLen;                        /* Bytes valid in Payload[] (0 if not captured) */
    UCHAR    Payload[WRITE_TRAP_PAYLOAD_BYTES]; /* Page-window contents after single-step */
} WRITE_TRAP_LOG_ENTRY, *PWRITE_TRAP_LOG_ENTRY;

C_ASSERT(sizeof(WRITE_TRAP_LOG_ENTRY) == 160);
/* Spec §3.1 stated 128 B; actual layout with 10 ULONG64 + 4 ULONG32 + 64 B
 * payload is 160 B. Ring size adjusted upward to 640 KB accordingly. If
 * you want to trim back to 128 B later, drop one register snapshot (e.g.
 * Rdx) and shrink Payload to 32 B — reflects the "xor-loop decoder step
 * is byte-by-byte" note in spec §7 R7. */

/* Read-trap log entry — identical layout to WRITE_TRAP_LOG_ENTRY so the
 * user-tool dumper can share field offsets. Field names differ for
 * readability (ReaderRip vs WriterRip). 160 bytes per entry. */
typedef struct _READ_TRAP_LOG_ENTRY {
    ULONG64  ReaderRip;                        /* Instruction that read */
    ULONG64  FaultVa;                          /* VMCS_RO_GUEST_LINEAR_ADDR */
    ULONG64  GuestCr3;
    ULONG64  ReaderRsp;
    ULONG64  Rax;
    ULONG64  Rcx;
    ULONG64  Rdx;
    ULONG64  Rsi;
    ULONG64  Rdi;
    ULONG64  Tsc;
    ULONG32  ExitQualification;
    ULONG32  CpuIndex;
    ULONG32  Counter;
    ULONG32  PayloadLen;
    UCHAR    Payload[READ_TRAP_PAYLOAD_BYTES];
} READ_TRAP_LOG_ENTRY, *PREAD_TRAP_LOG_ENTRY;

C_ASSERT(sizeof(READ_TRAP_LOG_ENTRY) == 160);

/* Exec-trap log entry — 256 B per entry.
 *
 * Layout history: was 160 B (identical to READ_TRAP_LOG_ENTRY), capturing
 * only RAX/RCX/RDX/RSI/RDI. Extended to capture every GPR
 * (RBX/RBP/R8-R15 added between PayloadLen and Payload). 8-reg expansion
 * is 64 B; padded to a clean 256 B with Reserved[16] for future use.
 *
 * Use case driving the expansion: capturing the full caller-passed
 * register state at a Themida-CFF-dispatched hash-function entry, so
 * JavelinEmu can diff real-Win state vs emu state without inferring
 * regs from stack reads after the prologue. Existing XTLE_OFF_* defines
 * for fields up to PayloadLen (0x5C) are unchanged; only XTLE_OFF_PAYLOAD
 * shifts from 0x60 to 0xB0.
 */
typedef struct _EXEC_TRAP_LOG_ENTRY {
    ULONG64  ExecRip;                          /* Instruction that executed */
    ULONG64  FaultVa;                          /* VMCS_RO_GUEST_LINEAR_ADDR */
    ULONG64  GuestCr3;
    ULONG64  ExecRsp;
    ULONG64  Rax;
    ULONG64  Rcx;
    ULONG64  Rdx;
    ULONG64  Rsi;
    ULONG64  Rdi;
    ULONG64  Tsc;
    ULONG32  ExitQualification;
    ULONG32  CpuIndex;
    ULONG32  Counter;
    ULONG32  PayloadLen;
    /* ── Extended GPRs (added) ── */
    ULONG64  Rbx;                              /* Non-volatile caller-pres */
    ULONG64  Rbp;                              /* Non-volatile caller-pres */
    ULONG64  R8;                               /* MS x64 ABI arg 3 (vol) */
    ULONG64  R9;                               /* MS x64 ABI arg 4 (vol) */
    ULONG64  R10;                              /* Volatile */
    ULONG64  R11;                              /* Volatile */
    ULONG64  R12;                              /* Non-volatile caller-pres */
    ULONG64  R13;                              /* Non-volatile caller-pres */
    ULONG64  R14;                              /* Non-volatile caller-pres */
    ULONG64  R15;                              /* Non-volatile caller-pres */
    UCHAR    Payload[EXEC_TRAP_PAYLOAD_BYTES]; /* Optional memory capture ([RSP..RSP+0x200]) */
    UCHAR    Reserved[336];                    /* Pad to 1024 B */
} EXEC_TRAP_LOG_ENTRY, *PEXEC_TRAP_LOG_ENTRY;

C_ASSERT(sizeof(EXEC_TRAP_LOG_ENTRY) == 1024);

/* ── HV-3: EPT hook spoof mode (Apr 2026) ─────────────────────────
 *
 * Closes the unwind-wall (memory: inline_hook_unwind_wall_2026_04_19.md):
 * the manually-mapped NexusCore inline-hook primitive cannot safely
 * service exception-throwing functions because RtlLookupFunctionEntry
 * returns NULL for our hook addresses. Solution: keep the hook body
 * in VMX root — the guest stack never contains NexusCore frames, so
 * exception unwind only walks kernel .pdata-registered functions.
 *
 * EPT_HOOK_EXTRA is a parallel metadata array to g_Shv.EptHooks[].
 * One entry per hook slot; HookKind selects per-hook dispatch behavior
 * in ShvHandleVmExit's CPUID hook match block:
 *
 *   HOOK_KIND_LOG (0)         — log args, single-step back, re-arm
 *                               (existing default behavior, no change).
 *   HOOK_KIND_SPOOF_RAX (1)   — skip the function body entirely:
 *                               read return address from [RSP] (safe-walk),
 *                               set RAX = SpoofRetValue, RIP = retaddr,
 *                               RSP += 8, switch to primary EPT, INVEPT.
 *                               MVP for HV-13 dry-run. No MTF, no re-arm
 *                               (shadow CPUID stays; next call re-triggers).
 *   HOOK_KIND_SPOOF_LICENSE (2) — future: HV-13 ZwQueryLicenseValue full spoof
 *                                (write output buffer + set RAX).
 *   HOOK_KIND_SPOOF_FIRMWARE (3) — future: HV-11 ExGetFirmwareEnvironmentVariable.
 *   HOOK_KIND_SPOOF_UEFI_VAR (4) — future: HV-12 UEFI variable spoof.
 *
 * The extra array lives at the END of SHV_GLOBAL so every existing
 * user-side offset table (cmd_ept_hook.cpp, cmd_status.cpp, cmd_xcap.cpp,
 * cmd_syscall_log.cpp, etc.) stays byte-identical. EptHookExtraMagic is
 * an 8-byte sentinel that user-mode can scan for to locate the extra
 * block without knowing the absolute offset.
 *
 * Pending-op plumbing mirrors PendingHookVa: user writes HookIdx + Kind +
 * RetValue, flips PendingSpoofOp last, VMX root picks up on next VM exit,
 * writes EptHookExtra[idx], clears PendingSpoofOp, and reports result. */
#define HOOK_KIND_LOG             0
#define HOOK_KIND_SPOOF_RAX       1
#define HOOK_KIND_SPOOF_LICENSE   2
#define HOOK_KIND_SPOOF_FIRMWARE  3
#define HOOK_KIND_SPOOF_UEFI_VAR  4

#define EPT_HOOK_EXTRA_MAGIC      0x48564558545241E7ULL   /* 'HVEXTRA\xE7' */

#define SPOOF_OP_NONE             0
#define SPOOF_OP_SET              1

typedef struct _EPT_HOOK_EXTRA {
    ULONG32  HookKind;         /* HOOK_KIND_* */
    ULONG32  SpoofHits;        /* Times spoof dispatch fired (diag) */
    ULONG64  SpoofRetValue;    /* RAX value to return in SPOOF_RAX mode */
    UCHAR    SpoofData[64];    /* Buffer contents for SPOOF_LICENSE/FIRMWARE/UEFI_VAR */
    ULONG32  SpoofDataLen;     /* Valid bytes in SpoofData[] */
    ULONG32  Reserved;
} EPT_HOOK_EXTRA, *PEPT_HOOK_EXTRA;

C_ASSERT(sizeof(EPT_HOOK_EXTRA) == 88);

/* ── Global State ─────────────────────────────────────────────────── */

#ifdef SHV_PLATFORM_NT
typedef struct _SHV_GLOBAL {
    PVCPU_DATA*    VcpuArray;       /* VcpuArray[processorIndex] */
    ULONG          ProcessorCount;
    ULONG32        VmxRevisionId;   /* From IA32_VMX_BASIC */
    volatile LONG  Active;          /* Hypervisor running? */
    PDEVICE_OBJECT DeviceObject;

    /* FIFO access trace ring buffer */
    FIFO_ACCESS_LOG_ENTRY FifoLog[FIFO_ACCESS_LOG_MAX];
    volatile LONG  FifoLogIndex;    /* Next write slot (mod FIFO_ACCESS_LOG_MAX) */
    volatile LONG  FifoLogTotal;    /* Total events logged (monotonic) */
    volatile LONG  FifoTrapActive;  /* Whether the FIFO read-trap is armed */

    /* Dual-EPT hook infrastructure */
    ULONG64  PrimaryEptp;     /* Cached primary EPTP for quick access */
    ULONG64  SecondaryEptp;   /* Secondary EPTP (0 = not initialized) */
    /* NB: VMFUNC + #VE state was originally inserted here,
     * which shifted the offsets of every subsequent g_Shv field. NexusDSEFix
     * and NexusCore have hardcoded offsets into g_Shv (per
     * hv3_spoof_rax_validated_2026_04_19.md / "GSHV_OFF_* table"), so
     * inserting in the middle BSODs the loader. The new fields have been
     * relocated to the END of SHV_GLOBAL — search for VmFuncState below. */

    /* EPT hook tracking */
#define EPT_HOOK_MAX 16
    struct {
        ULONG64  TargetVa;    /* Original function VA */
        ULONG64  TargetPa;    /* Original page PA (page-aligned) */
        ULONG64  ShadowPa;    /* Shadow page PA (with INT3) */
        PVOID    ShadowVa;    /* Shadow page VA (for cleanup) */
        ULONG32  PageOffset;  /* Offset of hook within page */
        UCHAR    OrigBytes[2]; /* Original 2 bytes at hook point (before CPUID 0F A2) */
        BOOLEAN  Active;
        BOOLEAN  CaptureR8Buffer; /* If set, attempt 64-byte safe read of R8 on hit */
        /* NB: StealthMode was originally inserted here,
         * which changed sizeof(struct EptHooks element) and shifted
         * every g_Shv offset after the EptHooks array. Loader-side
         * GSHV_OFF_* hardcoded offsets BSOD'd. The flag has been moved
         * to a parallel array at the END of g_Shv (EptHookStealthMode
         * below). Index by EptHook index. */
    } EptHooks[EPT_HOOK_MAX];
    ULONG    EptHookCount;
    volatile LONG EptHookHits;   /* Total #BP hits from hooks */

    /* Pending hook installation (shared memory polling from exit_dispatch) */
    volatile ULONG64 PendingHookVa;     /* Target VA to hook (0 = no pending) */
    volatile ULONG64 PendingHookPa;     /* Target PA (0 = resolve from VA) */
    volatile ULONG64 PendingHookResult; /* 0=none, 1=success, 0xE5=fail, 0xE7=PA fail */
    volatile ULONG64 PendingHookCopyFromVa; /* Source VA for shadow page copy (0 = use MmCopyMemory) */

    /* ── DR0 read-trap (added) ──────────────────────────────
     * Themida-safe HW-breakpoint based read trap. No memory modification.
     * On guest read of DrTrapVa, CPU raises #DB → SHV catches via exception
     * bitmap, logs RIP + GPR snapshot to SyscallLog, single-steps past,
     * resumes. UM tool arms via NexusBoot SetVariable backdoor (mirrors
     * PendingHookVa pattern). */
    volatile ULONG64 PendingDrTrapVa;        /* Target VA (0 = disarmed) */
    volatile ULONG64 PendingDrTrapCr3;       /* Match this CR3 (0 = any) */
    volatile LONG    DrTrapInstalled;        /* Bumps every CPU that arms */
    volatile LONG    DrTrapHits;             /* #DB events that matched our trap */
    volatile LONG    DrTrapMisses;           /* #DB events from other sources */
    volatile LONG    DrTrapDisarmed;         /* Set non-zero to take it down */
    volatile ULONG32 PendingDrTrapMode;      /* 0=R/W len 8, 1=EXECUTE len 1 */
    volatile ULONG32 PendingDrTrapPad;       /* alignment */

    /* Diagnostic counters for hook chain debugging */
    volatile LONG EptHookViolations;    /* EPT violations on hooked pages (execute) */
    volatile LONG EptHookSwitchToSec;   /* Switches to secondary EPT */
    volatile LONG EptHookSwitchToPri;   /* Switches back to primary EPT */
    volatile LONG BpExitsTotal;         /* Total #BP VM exits (vector 3) */
    volatile LONG BpExitsMatched;       /* #BP exits that matched a hook */
    volatile LONG BpExitsUnmatched;     /* #BP exits that didn't match */
    volatile LONG ExcBitmapSyncs;       /* CPUs that synced exception bitmap */

    /* INVEPT + exception bitmap broadcast generation counter.
     * Incremented when hooks are installed. Each CPU compares against its
     * local LastInveptGeneration on every VM exit; if behind, it does
     * INVEPT + sets exception bitmap bit 3 on its own VMCS. */
    volatile LONG InveptGeneration;

    /* ── Syscall trace log (kernel API call monitoring) ────────────── */

    /* Caller filter: only log calls where return address is within this range.
     * Set to 0/0 to log ALL callers (unfiltered). */
    volatile ULONG64 TraceFilterBase;   /* Module base VA (e.g. the target's base) */
    volatile ULONG64 TraceFilterEnd;    /* Module end VA (base + size) */

    /* Syscall log ring buffer — allocated in guest context (deferred init).
     * Written from VMX root (#BP handler), read from guest via backdoor. */
    PSYSCALL_LOG_ENTRY SyscallLog;      /* Pointer to allocated ring buffer */
    volatile LONG  SyscallLogIndex;     /* Next write slot (mod SYSCALL_LOG_MAX) */
    volatile LONG  SyscallLogTotal;     /* Total events logged (monotonic) */
    volatile LONG  SyscallLogFiltered;  /* Events skipped by caller filter */
    volatile LONG  SyscallLogAllCalls;  /* Total #BP matches (before filtering) */

    /* Auto-stop: when SyscallLogTotal >= TraceAutoStop, hooks self-disable.
     * MTF handler stops re-arming CPUID in shadow pages — each hook dies
     * on its next fire. Set to 0 to trace indefinitely (not recommended).
     * MUST be ULONG64 (not LONG) — backdoor writes are always 8 bytes.
     * If this were 4 bytes at struct end, the write overflows. */
    volatile ULONG64 TraceAutoStop;     /* 0 = no limit, >0 = stop after N entries */

    /* Caller skip list: callerRIP values that bypass hook processing.
     * When CPUID hook fires and [RSP] matches a skip entry, do normal
     * MTF recovery (restore bytes, single-step, re-arm) but DON'T log.
     * Prevents crashes from hooking functions called in sensitive contexts
     * (e.g. a registry callback calling MmCopyMemory). */
#define TRACE_SKIP_MAX 8
    volatile ULONG64 TraceSkipCallers[TRACE_SKIP_MAX];
    volatile ULONG   TraceSkipCount;
    volatile LONG    TraceSkipHits;     /* Times skip fired (diagnostic) */

    /* ── Xcap (execute-trap page capture) ──────────────────────────── */

    /* Pre-allocated capture buffers (PASSIVE_LEVEL alloc, VMX-root use). */
    PXCAP_ENTRY XcapEntries;            /* XcapEntries[XCAP_MAX_PAGES] */
    PUCHAR      XcapPageData;           /* XcapPageData[i*4096] = page i contents */
    ULONG64*    XcapPaTable;            /* XcapPaTable[i] = GPA for VA index i (or 0) */
    ULONG       XcapBitmap[XCAP_BITMAP_WORDS]; /* bit i set = page i captured */

    /* Active session parameters (set when xcap walk-and-trap arms). */
    ULONG64 XcapVaBase;                 /* Base VA of trapped range */
    ULONG64 XcapVaEnd;                  /* End VA (exclusive) of trapped range */
    ULONG64 XcapTargetCr3;              /* Target CR3 (0 = match any process) */

    /* Diagnostic / status counters (atomically updated from VMX root). */
    volatile LONG XcapActive;           /* Non-zero if traps are armed */
    volatile LONG XcapCapturedCount;    /* Pages successfully captured so far */
    volatile LONG XcapViolationCount;   /* EPT violations seen on xcap pages */
    volatile LONG XcapWrongCr3Count;    /* Violations skipped due to CR3 filter */
    volatile LONG XcapTrappedCount;     /* Pages successfully execute-trapped */
    volatile LONG XcapNoPaCount;        /* PaTable entries that were 0 (page not present) */
    volatile LONG XcapNoSplitCount;     /* Pages skipped because EPT split slot full */

    /* RIP sampling diagnostic — definitively answers "does the launcher
     * execute image pages at all?". Updated on every external-interrupt
     * VM exit while XcapActive and the guest CR3 matches XcapTargetCr3.
     * If RipInImageCount > 0 the launcher does execute image VAs and
     * the trap is wrong (PAs / COW issue). If RipInImageCount == 0 but
     * RipSampleCount > 0 the launcher is alive but fully out-of-image
     * (executes only fresh allocations) and we need NtAllocateVirtualMemory
     * monitoring to catch it. */
    volatile LONG    XcapRipSampleCount;   /* Total samples in armed CR3 */
    volatile LONG    XcapRipInImageCount;  /* Samples where RIP was inside [VaBase, VaEnd) */
    volatile ULONG64 XcapFirstRipIn;       /* First RIP that was inside the image range */
    volatile ULONG64 XcapFirstRipOut;      /* First RIP that was outside the image range */
    volatile ULONG64 XcapLastRip;          /* Most recent sampled RIP */

    /* Total EPT execute violations that fired while XcapActive — counts
     * EVERY execute violation regardless of whether the PA matched our
     * PaTable. If this is > 0 but XcapViolationCount is 0, our trap
     * mechanism is firing but on PAs we don't know about. If both are 0
     * the launcher genuinely never executes any trapped page. */
    volatile LONG    XcapAnyExecViolation;

    /* Total EPT violations of ANY type (read/write/execute) while XcapActive.
     * Even one-step deeper than XcapAnyExecViolation: includes pure read or
     * write faults too. If this is 0 but the launcher is alive (RIP samples
     * confirm), then NO EPT faulting is happening at all — meaning our
     * Execute=0 writes truly aren't producing faults, and the bug is in
     * our PTE write path or in CPU caching, not in CR3 / OOI / page count. */
    volatile LONG    XcapTotalEptViolations;

    /* Count of VM exits seen with VMCS_CTRL_EPTP != PrimaryEptp during the
     * xcap session. If non-zero, dual-EPT switching has parked some CPUs
     * on the secondary EPT and our xcap traps (which only modify the
     * primary EPT) are invisible to those CPUs. Captures the actual EPTP
     * value of the most recent off-primary observation. */
    volatile LONG    XcapNonPrimaryEptpCount;
    volatile ULONG64 XcapLastNonPrimaryEptp;

    /* Snapshot of g_XcapSplitCount taken IMMEDIATELY after the most-recent
     * install loop completes. If this differs from the live read of
     * ShvEptXcapGetSplitCount() at probe time, SOMETHING is resetting
     * g_XcapSplitCount between the install and the probe. Used to chase
     * down the impossible-looking "Trapped=44057 but SplitCount=0" case. */
    volatile LONG    XcapPostInstallSplitCount;
    /* Same idea but captured inside ShvEptXcapTryCapture the first time
     * it sees a PA in our table — proves the count was non-zero at the
     * moment a capture actually fired. */
    volatile LONG    XcapAtCaptureSplitCount;
    /* THE split count itself. Apr 2026 SWAP EXPERIMENT: previously this
     * field lived AFTER XcapSplitForIncrements (at offset 0xF664 in the
     * linked binary). At that offset every test showed the field reading
     * 0 even though the trace instrumentation captured the post-increment
     * value as the correct count. To localize whether the bug follows
     * the ADDRESS or the FIELD NAME, this field is now placed BEFORE
     * XcapSplitForIncrements — taking what used to be SplitForIncrements'
     * slot in memory. If after the swap XcapSplitCount STILL reads 0, the
     * bug is the field/source — not address-specific. If it now reads
     * correctly and XcapSplitForIncrements reads 0, the bug is locked to
     * the *physical* offset and we know to hunt for an out-of-band writer
     * to that exact 4 bytes. */
    volatile LONG    XcapSplitCount;

    /* Direct counter — incremented every time ShvEptXcapSplitFor reaches
     * its g_XcapSplitCount++ statement. If this is > 0 but SplitCount
     * is 0 at probe time, something is decrementing or zeroing the count
     * after we wrote to it. */
    volatile LONG    XcapSplitForIncrements;

    /* Pending xcap setup request (shared-memory polling from exit_dispatch).
     * Mirrors the PendingHookVa pattern: user fills these via VMCALL_XCAP_SETUP,
     * the next VM exit on any CPU picks them up and runs the walk-and-trap from
     * VMX root. PendingXcapResult signals completion (1 = ok, 0xE5 = failed). */
    volatile ULONG64 PendingXcapCr3;
    volatile ULONG64 PendingXcapVaBase;
    volatile ULONG64 PendingXcapVaEnd;
    volatile ULONG64 PendingXcapResult;

    /* ── Live SplitCount instrumentation (Apr 2026) ──────────────────
     * SplitFor writes BOTH of these AS ITS LAST ACTION on every successful
     * increment, AFTER the InterlockedIncrement of XcapSplitCount has
     * already executed. Diagnostic purpose:
     *
     *  XcapTraceIncCount: incremented once per SplitFor success. Should
     *    end at 1219 (or whatever the install loop value is). Same as
     *    XcapSplitForIncrements but with a different code path so a single
     *    bug can't hide both.
     *
     *  XcapTraceLastInc: set to `g_Shv.XcapSplitCount` IMMEDIATELY after
     *    the InterlockedIncrement of that field. If the field-read returns
     *    the post-increment value (e.g., 1219 on the last call), this
     *    captures it. Compared against case 22 / case 43 readings later:
     *      - Trace == case 22: field is stable, problem is elsewhere
     *      - Trace > 0, case 22 == 0: SOMETHING zeros the field AFTER install
     *      - Trace == 0, IncCount > 0: lock inc is firing but the read
     *        immediately after sees 0 (CPU/cache anomaly — extremely
     *        unlikely on x86 TSO, but the only remaining theory)
     *
     * These fields are at the END of SHV_GLOBAL so adding them does not
     * shift any earlier offset (especially XcapSplitCount itself). */
    volatile LONG XcapTraceIncCount;
    volatile LONG XcapTraceLastInc;

    /* ── Multi-Region Poller (Apr 2026) ───────────────────────────────
     * When the multi-region poller in NexusCore (XcapPollerThread) is
     * active, it walks the target process's user VA via ZwQueryVirtualMemory
     * and packs all executable pages' GPAs into XcapPaTable[0..XcapPaTableCount).
     * Indices are SEQUENTIAL (not VA-relative) — slot N holds the Nth
     * discovered page. The corresponding GuestVa is recorded in
     * XCAP_ENTRY[N].GuestVa at capture time.
     *
     * If XcapPaTableCount > 0, the install loop in WalkAndTrap uses it as
     * the iteration bound INSTEAD of computing (VaEnd - VaBase) >> 12.
     * Same for the linear scan in TryCapture.
     *
     * Set to 0 to fall back to the original linear-VA install path. */
    volatile LONG XcapPaTableCount;

    /* ── UM EPT Write-Trap (Phase C, Apr 2026) ────────────────────────
     * Appended AFTER XcapPaTableCount so no prior field offset shifts.
     * cmd_ept_hook.cpp / cmd_ept_trace.cpp offset tables unaffected.
     *
     * Arming rule: WriteTrapActive MUST be the last field written during
     * install (flips 0→1 only after Cr3/VaBase/VaEnd/TargetPa are all set).
     * Spec: tools/the design notes.1. */
    volatile ULONG64 WriteTrapCr3;              /* 0 = disabled; non-0 = match CR3 */
    volatile ULONG64 WriteTrapVaBase;           /* Inclusive low bound of trap range */
    volatile ULONG64 WriteTrapVaEnd;            /* Exclusive high bound */
    volatile ULONG64 WriteTrapTargetPa;         /* 4 KB-aligned PA of the trapped page */
    volatile ULONG64 WriteTrapRipFilter;        /* 0 = unfiltered; non-0 = require this RIP */
    volatile ULONG   WriteTrapActive;           /* 0 = off, 1 = armed */
    volatile LONG    WriteTrapHits;             /* In-range writes actually logged */
    volatile LONG    WriteTrapFilteredCr3;      /* Violations discarded by CR3 mismatch */
    volatile LONG    WriteTrapFilteredVa;       /* Violations discarded by VA out-of-range */
    volatile LONG    WriteTrapFilteredRip;      /* Violations discarded by RIP filter */
    volatile LONG    WriteTrapAutoStop;         /* 0 = no limit, >0 = auto-disarm after N hits */

    /* Write-trap log ring — allocated at guest init (deferred alloc path,
     * same pattern as SyscallLog). 4096 * 128 B = 512 KB NonPagedPoolNx. */
    PWRITE_TRAP_LOG_ENTRY WriteTrapLog;
    volatile LONG WriteTrapLogIndex;            /* Next write slot (mod WRITE_TRAP_LOG_MAX) */
    volatile LONG WriteTrapLogTotal;            /* Total events logged (monotonic) */

    /* Pending-request shared memory (polled by exit_dispatch.c, mirrors
     * PendingHook* shape). UM dispatcher fills these via SetVariable
     * backdoor; PendingWriteTrapOp flipped last signals "handle me". */
    volatile ULONG64 PendingWriteTrapCr3;
    volatile ULONG64 PendingWriteTrapVaBase;
    volatile ULONG64 PendingWriteTrapSize;
    volatile ULONG64 PendingWriteTrapRipFilter;
    volatile ULONG64 PendingWriteTrapTargetPid;
    volatile ULONG64 PendingWriteTrapOp;        /* 1=install, 2=uninstall, 3=status-only */
    volatile ULONG64 PendingWriteTrapResult;    /* 0=none, 1=success, 0xE5=fail */

    /* iter#179 COW fix: write-trap → exec-trap auto-arm.
     * Appended at END of write-trap block so existing WT_OFF_* offsets in
     * the host-side write-trap tool stay stable.
     * When WriteTrapAutoArmExecVaOffset != 0, the FIRST logged write-trap hit
     * reads the 8B value being written to the trapped address (= GSL.dll
     * BaseAddress from fn_0x2390 → qword_18000A060), computes exec-trap target
     * VA = written_value + WriteTrapAutoArmExecVaOffset, walks guest PT to
     * get PA, and calls ShvEptInstallExecTrap. One-shot (cleared after arm). */
    volatile ULONG64 WriteTrapAutoArmExecVaOffset; /* 0=off; non-0=RVA offset from written value */
    volatile ULONG64 WriteTrapAutoArmExecCr3;      /* 0=use current guest CR3; else forced CR3 */

    /* ── UM EPT Read-Trap (Phase C-R, Apr 2026) ───────────────────────
     * Parallels the write-trap block above. Appended here (not at end of
     * struct) to keep the host-side write-trap tool's hardcoded offsets
     * stable. EptHookExtra below uses magic-sentinel discovery so it's
     * immune to this shift. cmd_ept_hook.cpp's GSHV_OFF_* constants all
     * end at 0xD08 (TraceFilterBase) so they also stay stable.
     *
     * Distinct from write-trap: when armed, the target EPT PTE has R,
     * W, AND X all cleared together. Intel treats R=0,W=1 as reserved
     * (EPT misconfiguration → BugCheck), so we must modify the PTE via
     * a single-qword Value store (see ShvEptInstallReadTrap) instead
     * of separate bitfield assignments.
     *
     * Arming rule: ReadTrapActive MUST be the last field written during
     * install. */
    volatile ULONG64 ReadTrapCr3;
    volatile ULONG64 ReadTrapVaBase;
    volatile ULONG64 ReadTrapVaEnd;
    volatile ULONG64 ReadTrapTargetPa;
    volatile ULONG64 ReadTrapRipFilter;
    volatile ULONG   ReadTrapActive;            /* 0 = off, 1 = armed */
    volatile LONG    ReadTrapHits;              /* In-range reads logged */
    volatile LONG    ReadTrapFilteredCr3;
    volatile LONG    ReadTrapFilteredVa;
    volatile LONG    ReadTrapFilteredRip;
    volatile LONG    ReadTrapNonReadSkipped;    /* Writes/execs on trapped page — re-armed silently */
    volatile LONG    ReadTrapAutoStop;          /* 0 = no limit */

    PREAD_TRAP_LOG_ENTRY ReadTrapLog;
    volatile LONG ReadTrapLogIndex;
    volatile LONG ReadTrapLogTotal;

    /* Saved original PTE qword so uninstall can byte-restore exactly
     * what was there (memory-type bits, PFN, etc.). Write-trap doesn't
     * need this because it only touches 1 bit. */
    ULONG64 ReadTrapSavedPteValue;

    /* Pending-request shared memory. Same polling pattern as write-trap. */
    volatile ULONG64 PendingReadTrapCr3;
    volatile ULONG64 PendingReadTrapVaBase;
    volatile ULONG64 PendingReadTrapSize;
    volatile ULONG64 PendingReadTrapRipFilter;
    volatile ULONG64 PendingReadTrapTargetPid;  /* repurposed as TargetPa */
    volatile ULONG64 PendingReadTrapOp;         /* 1=install, 2=uninstall, 3=status */
    volatile ULONG64 PendingReadTrapResult;     /* 0=none, 1=success, 0xE5=fail */

    /* ── UM EPT Exec-Trap (Phase C-X, Apr 2026) ───────────────────────
     * Parallels the read-trap block above. Clears only Execute on the
     * target PTE (keeps R=W=1). Single-qword Value store for safety.
     * Primary use: capture scanner's RETURN landing page to seed the
     * RIP-trace at the dispatcher (bypasses memcpy-inside MTF burn). */
    volatile ULONG64 ExecTrapCr3;
    volatile ULONG64 ExecTrapVaBase;
    volatile ULONG64 ExecTrapVaEnd;
    volatile ULONG64 ExecTrapTargetPa;
    volatile ULONG64 ExecTrapRipFilter;
    volatile ULONG   ExecTrapActive;            /* 0 = off, 1 = armed */
    volatile LONG    ExecTrapHits;              /* In-range execs logged */
    volatile LONG    ExecTrapFilteredCr3;
    volatile LONG    ExecTrapFilteredVa;
    volatile LONG    ExecTrapFilteredRip;
    volatile LONG    ExecTrapNonExecSkipped;    /* Reads/writes on trapped page — shouldn't fire */
    volatile LONG    ExecTrapAutoStop;          /* 0 = no limit */

    PEXEC_TRAP_LOG_ENTRY ExecTrapLog;
    volatile LONG ExecTrapLogIndex;
    volatile LONG ExecTrapLogTotal;

    /* Saved original PTE qword so uninstall can byte-restore exactly
     * what was there (memory-type bits, PFN, etc.). */
    ULONG64 ExecTrapSavedPteValue;

    /* Pending-request shared memory. Same polling pattern as read-trap. */
    volatile ULONG64 PendingExecTrapCr3;
    volatile ULONG64 PendingExecTrapVaBase;
    volatile ULONG64 PendingExecTrapSize;
    volatile ULONG64 PendingExecTrapRipFilter;
    volatile ULONG64 PendingExecTrapTargetPid;  /* repurposed as TargetPa */
    volatile ULONG64 PendingExecTrapOp;         /* 1=install, 2=uninstall, 3=status */
    volatile ULONG64 PendingExecTrapResult;     /* 0=none, 1=success, 0xE5=fail */

    /* ── HV-7: CPUID stealth cache (Ophion-style) ────────────────────
     * Sampled at DriverEntry BEFORE VMXON so we can replay bare-metal
     * invalid-leaf responses for CPUID leaves that would otherwise leak
     * hypervisor presence (0x40000000..0x4FFFFFFF, or any out-of-range
     * leaf). Also tracks max std/ext leaves, valid XCR0 mask, and the
     * pre-VMXON values of VMX-capability and EFER MSRs (so guest RDMSRs
     * for those return bare-metal values, not our VMX-on values). */
    struct {
        BOOLEAN  Initialized;
        UINT32   InvalidLeafResponse[4];  /* EAX, EBX, ECX, EDX */
        UINT32   MaxStdLeaf;               /* CPUID.0 EAX */
        UINT32   MaxExtLeaf;               /* CPUID.80000000 EAX */
        UINT64   ValidXcr0Mask;            /* CPUID.0D EDX:EAX */

        /* Pre-VMXON cached MSR values. Populated by ShvInitStealthCpuidCache. */
        BOOLEAN  MsrCacheValid;
        UINT64   FeatureControlMsr;        /* 0x3A */
        UINT64   VmxBasicMsr;              /* 0x480 */
        UINT64   VmxPinbasedMsr;           /* 0x481 */
        UINT64   VmxProcbasedMsr;          /* 0x482 */
        UINT64   VmxExitCtlsMsr;           /* 0x483 */
        UINT64   VmxEntryCtlsMsr;          /* 0x484 */
        UINT64   VmxMiscMsr;               /* 0x485 */
        UINT64   VmxCr0Fixed0Msr;          /* 0x486 */
        UINT64   VmxCr0Fixed1Msr;          /* 0x487 */
        UINT64   VmxCr4Fixed0Msr;          /* 0x488 */
        UINT64   VmxCr4Fixed1Msr;          /* 0x489 */
        UINT64   VmxVmcsEnumMsr;           /* 0x48A */
        UINT64   VmxProcbased2Msr;         /* 0x48B */
        UINT64   VmxEptVpidCapMsr;         /* 0x48C */
        UINT64   VmxTruePinbasedMsr;       /* 0x48D */
        UINT64   VmxTrueProcbasedMsr;      /* 0x48E */
        UINT64   VmxTrueExitCtlsMsr;       /* 0x48F */
        UINT64   VmxTrueEntryCtlsMsr;      /* 0x490 */
        UINT64   VmxVmfuncMsr;             /* 0x491 */
        UINT64   EferMsr;                  /* 0xC0000080 (pre-VMX bits) */
    } StealthCache;

    /* ── HV-3: EPT hook spoof mode (Apr 2026) ────────────────────────
     * Placed AT END of SHV_GLOBAL so every existing field offset is
     * stable. User-mode locates this block by scanning for the magic
     * qword (see EPT_HOOK_EXTRA_MAGIC above). */
    ULONG64        EptHookExtraMagic;      /* = EPT_HOOK_EXTRA_MAGIC once init */
    EPT_HOOK_EXTRA EptHookExtra[EPT_HOOK_MAX];

    /* Pending spoof-config op (shared-memory polling, mirrors PendingHookVa).
     * Fill HookIdx + Kind + RetValue, then flip Op=SPOOF_OP_SET last. VMX
     * root consumes on next exit and writes EptHookExtra[HookIdx]; result
     * lands in PendingSpoofResult (1=ok, 0xE5=idx out of range). */
    volatile ULONG64  PendingSpoofOp;
    volatile ULONG64  PendingSpoofHookIdx;
    volatile ULONG64  PendingSpoofKind;
    volatile ULONG64  PendingSpoofRetValue;
    volatile ULONG64  PendingSpoofResult;

    /* Magic sentinel — UM scans past EptHookExtraMagic for this. All
     * RipTrace* field offsets are computed RELATIVE TO THIS MAGIC so
     * the UM tool stays immune to SHV_GLOBAL layout shifts. */
    ULONG64           RipTraceMagic;              /* = RIP_TRACE_MAGIC post-init */

    /* ── RIP-trace  ──────────────────────────────────────
     * Single-step logger piggy-backed on the read-trap. Appended at
     * very end of SHV_GLOBAL to keep all prior hardcoded offsets stable.
     *
     * Arming flow:
     *   1. UM writes PendingRipTrace{StepsMax,StopLow,StopHigh,Cr3},
     *      then flips PendingRipTraceOp=1. HV picks up, zeroes the log,
     *      sets RipTraceActive=1 + RipTraceArmOnHit=1, writes result.
     *   2. UM installs a normal read-trap on the scanner page (existing
     *      --um-read-trap install path).
     *   3. When the read-trap fires AND RipTraceArmOnHit=1, the hit
     *      handler sets Vcpu->RipTracePending=TRUE and clears ArmOnHit
     *      so only ONE trap activates tracing.
     *   4. Every subsequent MTF on that vcpu logs RIP+CR3 to the ring
     *      and re-enables MTF, until StepsTaken >= StepsMax OR (if
     *      StopOnRange!=0) RIP leaves [StopLow,StopHigh].
     *   5. UM polls PendingRipTraceOp (reusing slot) with op=3 (drain)
     *      or just reads RipTraceLogIndex/Total directly.
     *
     * Stop condition: StopOnRange=0 + StepsMax cap is the safe default.
     * Setting StopOnRange=1 + StopLow=scanner_retaddr, StopHigh=scanner_retaddr
     * (both equal) early-terminates when RIP returns through the JMP RAX
     * at the scanner's tail. */
    volatile ULONG    RipTraceActive;          /* 0=off, 1=armed (awaiting hit or logging) */
    volatile ULONG    RipTraceArmOnHit;        /* 1=next read-trap hit starts logging */
    volatile ULONG    RipTraceStepsMax;        /* cap; 0=use default 5000 */
    volatile ULONG    RipTraceStopOnRange;     /* 1=stop when RIP NOT in [StopLow,StopHigh] */
    volatile ULONG64  RipTraceStopLow;
    volatile ULONG64  RipTraceStopHigh;
    volatile ULONG64  RipTraceCr3Filter;       /* 0=any CR3; else match-only */
    PRIP_TRACE_ENTRY  RipTraceLog;             /* ring buffer (NonPagedPool, alloc at init) */
    volatile LONG     RipTraceLogIndex;        /* head (wraps at RIP_TRACE_LOG_MAX) */
    volatile LONG     RipTraceLogTotal;        /* total writes (total > MAX = wrapped) */
    volatile LONG     RipTraceStepsTaken;      /* 0..StepsMax */

    /* Pending-op slot. Op codes: 1=arm, 2=disarm, 3=status-refresh. */
    volatile ULONG64  PendingRipTraceOp;
    volatile ULONG64  PendingRipTraceStepsMax;
    volatile ULONG64  PendingRipTraceStopLow;
    volatile ULONG64  PendingRipTraceStopHigh;
    volatile ULONG64  PendingRipTraceCr3;
    volatile ULONG64  PendingRipTraceStopOnRange;
    volatile ULONG64  PendingRipTraceResult;   /* 0=none, 1=ok, 0xE5=fail */

    /* ── Auto-arm-on-module-load  ────────────────────────
     * Registered via PsSetLoadImageNotifyRoutine in DriverEntry.
     * UM configures a pending install (trap type + module name + section
     * RVA + size + autostop). When the callback fires and module name
     * matches, the HV computes module_base + RVA, fills the matching
     * PendingReadTrap* or PendingExecTrap* slot, and VMCALLs to trigger
     * install on next VMexit. AutoArmFired = 1 once consumed. */
    ULONG64           AutoArmMagic;           /* = AUTO_ARM_MAGIC once init */
    CHAR              AutoArmModuleName[32];  /* null-terminated ASCII */
    volatile ULONG64  AutoArmSectionRva;
    volatile ULONG64  AutoArmSize;
    volatile ULONG64  AutoArmTrapType;        /* 1=read, 2=exec */
    volatile ULONG64  AutoArmAutoStop;
    volatile LONG     AutoArmEnabled;         /* 0=off, 1=waiting */
    volatile LONG     AutoArmFired;           /* 0=pending, 1=fired */
    volatile LONG     AutoArmInstallStatus;   /* NTSTATUS from trap-install path */
    volatile LONG     AutoArmAllowUm;         /* 0=KM-only (default), 1=also match UM image loads */
    volatile ULONG64  AutoArmDetectedBase;    /* module base once callback fires */
    volatile ULONG64  AutoArmDetectedCr3;     /* CR3 captured at callback */

    /* Deferred PA resolution slot (used for UM image loads where the
     * target page is mapped but not yet committed — preloader_l style
     * manual mappers reserve the VA range via NtMapViewOfSection but
     * Windows doesn't fault the page in until the launcher actually
     * touches it). LoadImage callback writes these fields and sets
     * AutoArmDeferredActive=1; exit_dispatch polls every VMexit, and
     * when the guest CR3 matches AutoArmDeferredCr3 it walks the
     * guest's page tables via ShvTranslateGuestVa to get the PA,
     * then installs the trap via the same PendingExec/ReadTrap slot
     * the callback would have used directly. */
    volatile LONG     AutoArmDeferredActive;  /* 1 = resolve PA on next matching VMexit */
    volatile LONG     _AutoArmDeferredPad;    /* alignment */
    volatile ULONG64  AutoArmDeferredVa;      /* target VA = modBase + section RVA */
    volatile ULONG64  AutoArmDeferredCr3;     /* CR3 of loading process */
    volatile ULONG64  AutoArmDeferredSize;    /* trap size (PAGE_SIZE) */
    volatile ULONG64  AutoArmDeferredTrapType;/* 1=read, 2=exec */
    volatile ULONG64  AutoArmDeferredFilterCr3;/* CR3 to use for trap filter (UM=cr3, KM=0) */
    volatile ULONG64  AutoArmDeferredAttempts;/* polling counter for diagnostics */

    /* ── Exec-trap hash-capture  ──────────────────────────
     * Magic-sentinel-located block that extends exec-trap hits with a
     * guest-memory snapshot of whatever a chosen register points at.
     *
     * Wire-up when ExecTrapCapSrc != 0 and ExecTrapCapLen != 0:
     *   1. On exec-hit that passes all filters (Cr3/Va/Rip), after populating
     *      the regular log entry, read ExecTrapCapLen bytes from guest VA
     *      = [selected GPR] via ShvReadGuestQwordVa in qword chunks into
     *      entry->Payload[].
     *   2. Set entry->PayloadLen to (successfully read qwords)*8.
     *   3. Bump ExecTrapCapHits.
     *
     * Used to reveal hash PRE-IMAGES inside .grfn11 handler #3 (MD5):
     * when handler hits, RCX/RDX/RSI typically hold the input buffer
     * pointer. This lets offline analysis reproduce the hash computation
     * by replaying the actual bytes the target is hashing.
     *
     * Placed at very END of SHV_GLOBAL so all prior hardcoded user-side
     * offsets stay byte-identical. UM locates this block by scanning the
     * backdoor-readable g_Shv range for EXEC_TRAP_CAP_MAGIC. */
    ULONG64           ExecTrapCapMagic;       /* = EXEC_TRAP_CAP_MAGIC once init */
    volatile ULONG32  ExecTrapCapSrc;         /* 0=off, 1..6 = RAX/RCX/RDX/RSI/RDI/[RSP] */
    volatile ULONG32  ExecTrapCapLen;         /* bytes, 1..EXEC_TRAP_PAYLOAD_BYTES */
    volatile LONG     ExecTrapCapHits;        /* successful captures */
    volatile LONG     ExecTrapCapReadFails;   /* ShvReadGuestQwordVa failures */

    /* Pending-request slot (UM writes Src+Len+Op, flips Op last). */
    volatile ULONG64  PendingExecTrapCapSrc;
    volatile ULONG64  PendingExecTrapCapLen;
    volatile ULONG64  PendingExecTrapCapOp;     /* 1=SET, 2=DISABLE */
    volatile ULONG64  PendingExecTrapCapResult; /* 0=none, 1=ok, 0xE5=fail */

    /* End-sentinel immediately after the pending-result field. UM scans for
     * the pair (MAGIC at offset 0, MAGIC_END at fixed offset 0x38) so a
     * MOVABS-immediate in .text can't be mistaken for the real .data block. */
    ULONG64           ExecTrapCapMagicEnd;      /* = EXEC_TRAP_CAP_MAGIC_END once init */

    /* ── VMFUNC + #VE state (relocated) ─────────────────────
     * Originally inserted in the middle of g_Shv after PrimaryEptp/
     * SecondaryEptp, which shifted offsets of every subsequent field
     * and BSOD'd loaders that index g_Shv via hardcoded offsets
     * (NexusDSEFix GSHV_OFF_* table). Relocated here AFTER the
     * MagicEnd sentinel so all prior offsets stay byte-stable.
     *
     * VMFUNC leaf 0 (EPTP switching) reads VMCS_CTRL_EPTP_LIST_ADDR
     * which points at a 4 KB page of 512 candidate EPTPs:
     *   index 0 = PrimaryEptp   (read view)
     *   index 1 = SecondaryEptp (exec view)
     * Page populated at DriverEntry. The #VE handler is a NonPagedPoolNx
     * 4 KB page; system IDT vector 20 is patched to point at it. Only
     * activated once item #11 sweeps SuppressVe across the identity
     * map; until then EPT_VIOLATION_VE stays off in VMCS controls. */
    __declspec(align(4096)) ULONG64 VmFuncEptpListPage[512];
    ULONG64                         VmFuncEptpListPagePa;

    PVOID    VeHandlerCodePage;
    ULONG64  VeHandlerCodeVa;
    BOOLEAN  VeHandlerInstalled;
    USHORT   VeIdtPrevSelector;
    ULONG64  VeIdtPrevHandler;
    UCHAR    VeIdtPrevTypeAttr;
    UCHAR    VeIdtPrevIst;

    /* Parallel array of stealth-mode flags for EptHooks[]. Indexed by
     * the same EptHook index. Kept SEPARATE from EptHooks[] so the
     * EptHooks struct size stays byte-identical (loader-side hardcoded
     * offsets into EptHooks rely on unchanged sizeof(struct)). */
    BOOLEAN           EptHookStealthMode[EPT_HOOK_MAX];

    /* ── KM Cipher Trap  ────────────────────────────
     * Appended at END so every prior hardcoded GSHV_OFF_* stays stable.
     * UM locates this block by scanning g_Shv for CIPHER_TRAP_MAGIC. */
    ULONG64                CipherTrapMagic;                    /* = CIPHER_TRAP_MAGIC */
    volatile ULONG         CipherTrapActive;                   /* 0=off, 1=armed */
    volatile ULONG         CipherTrapSitesInstalled;           /* sites successfully trapped */
    volatile ULONG64       CipherTrapKmBase;                   /* target KM image base VA */
    volatile ULONG64       CipherTrapKmEnd;                    /* base + image size */
    volatile LONG          CipherTrapHits;                     /* total fires logged */
    volatile LONG          CipherTrapCapFails;                 /* failed buffer reads */
    PKM_CIPHER_RECORD    CipherTrapLog;                      /* ring buffer (NonPagedPool) */
    volatile LONG          CipherTrapLogIndex;                 /* next write slot */
    volatile LONG          CipherTrapLogTotal;                 /* total records written */
    /* Per-site page-aligned PAs; 0 = not trapped. UM-readable for status. */
    UINT64                 CipherTrapSitePa[CIPHER_TRAP_MAX_SITES];
    /* Pending op (polled from exit_dispatch.c). */
    volatile ULONG64       PendingCipherTrapKmBase;
    volatile ULONG64       PendingCipherTrapKmSize;
    volatile ULONG64       PendingCipherTrapOp;    /* 1=install, 2=uninstall, 3=status */
    volatile ULONG64       PendingCipherTrapResult;
    ULONG64                CipherTrapMagicEnd;     /* = CIPHER_TRAP_MAGIC_END — UM end anchor */

    /* ── Chained exec-trap (iter#179) ───────────────────────
     * When ExecTrap fires at ExecTrapChainAnchorVa (anchor page), the
     * handler atomically swaps ExecTrapTargetPa to the pre-split target
     * PA without any allocation. RearmAndConsume restores X on the anchor
     * (using its local pageAlignedPa); the MTF exit re-arms X=0 on the new
     * target. Result: cipher-VM exec-trap installed BEFORE hub fires.
     * Appended at END so all prior GSHV_OFF_* stay stable.
     * UM locates via EXEC_TRAP_CHAIN_MAGIC scan. */
    ULONG64                ExecTrapChainMagic;             /* = EXEC_TRAP_CHAIN_MAGIC */
    volatile ULONG64       ExecTrapChainEnabled;           /* 0=off, 1=chain mode active */
    volatile ULONG64       ExecTrapChainFired;             /* 0=not yet, 1=swapped to target */
    volatile ULONG64       ExecTrapChainAnchorVa;          /* exact anchor RIP (preloader+0x3400) */
    volatile ULONG64       ExecTrapChainTargetPa;          /* 4KB-aligned target PA (pre-split) */
    volatile ULONG64       ExecTrapChainTargetVaBase;      /* page-aligned target VA */
    volatile ULONG64       ExecTrapChainTargetCr3;         /* launcher CR3 (0=any) */
    volatile ULONG64       ExecTrapChainAutoStop;          /* auto-stop for chained target */
    /* Pending config from guest (written by NexusDSEFix backdoor). */
    volatile ULONG64       PendingExecTrapChainAnchorVa;
    volatile ULONG64       PendingExecTrapChainTargetPa;
    volatile ULONG64       PendingExecTrapChainTargetVaBase;
    volatile ULONG64       PendingExecTrapChainTargetCr3;
    volatile ULONG64       PendingExecTrapChainAutoStop;
    volatile ULONG64       PendingExecTrapChainOp;         /* 1=enable, 2=disable */
    volatile ULONG64       PendingExecTrapChainResult;     /* 0=none, 1=ok, 0xE5=fail */
    ULONG64                ExecTrapChainMagicEnd;          /* = EXEC_TRAP_CHAIN_MAGIC_END */

    /* ── Chain extensions (iter#180/185) ──────────────────────────────────────
     * iter#180: RcxLow12 + RdxRva — two-stage chain via ntdll anchor.
     * iter#185: RcxRva — three-stage chain for gsl.dll (manually mapped).
     *
     * THREE-STAGE FLOW (preloader_l.dll is an import of gsl.exe; gsl.dll is
     * manually mapped by preloader, never going through LdrpCallInitRoutine):
     *
     *   Stage-1 anchor: ntdll!LdrpCallInitRoutine ENTRY (RVA 0x3F690 on 26200).
     *     RCX = EntryPoint, RDX = DllBase, R8D = fdwReason, R9 = Context.
     *     EP filter (field below): (RCX-RDX) == epRva && R8D == reason.
     *     RdxRva pivot:    GuestRDX = preloader_base → trap installed at preloader+0x2DB5.
     *
     *     !! CORRECTION. This used to say "LdrpRunInitRoutines CALL at
     *     +0xA2" with an (RCX & 0xFFF) filter. BOTH were wrong: ntdll 0xAEAE4 is
     *     LdrpInitialize and its +0xA2 call targets LdrpInitializeThread (0x3F210),
     *     a PER-THREAD function that never touches DllMain. That is why the anchor
     *     fired 10,240+ times system-wide and never matched. LdrpRunInitRoutines
     *     does not exist in this build.
     *
     *   Stage-2 anchor: preloader+0x2DB5 (CALL sub_180002170 with RCX=gsl_base).
     *     When ChainFired==1 && RcxRva!=0: second pivot fires.
     *     RcxRva pivot:    GuestRCX = gsl_base → trap installed at gsl+0x125850.
     *     ExecTrapRipFilter set to effectiveTargetVa (preloader+0x2DB5) for precision.
     *
     *   Stage-3 capture: gsl+0x125850 = verify_with_profile entry.
     *     RSP captured in-VMX-root, autostop=1 (set by stage-2 pivot code).
     *
     * Offsets from ExecTrapChainMagic (NexusDSEFix --exec-trap-chain setup-rva):
     *   +0x80  ExecTrapChainRcxLow12         (EP FILTER: bits[31:0]=epRva (RCX-RDX),
     *                                          bits[63:32]=fdwReason for R8D (0=any);
     *                                          whole field 0 = filter disabled.
     *                                          Wire name kept: offset 0x80 is pinned.)
     *   +0x88  ExecTrapChainRdxRva            (stage-1 pivot: target = GuestRDX+RdxRva)
     *   +0x90  PendingExecTrapChainRcxLow12
     *   +0x98  PendingExecTrapChainRdxRva
     *   +0xA0  ExecTrapChainRcxRva            (stage-2 pivot: target = GuestRCX+RcxRva; 0=disabled)
     *   +0xA8  PendingExecTrapChainRcxRva
     *   +0xB0  ExecTrapChainStage3Pa          (pre-resolved 4KB-aligned PA for stage-3; 0=dynamic PTE-walk)
     *   +0xB8  PendingExecTrapChainStage3Pa   */
    volatile ULONG64       ExecTrapChainRcxLow12;          /* EP filter: (reason<<32)|epRva; 0=any. See banner. */
    volatile ULONG64       ExecTrapChainRdxRva;             /* stage-1 pivot: target = GuestRDX + RdxRva */
    volatile ULONG64       PendingExecTrapChainRcxLow12;
    volatile ULONG64       PendingExecTrapChainRdxRva;
    volatile ULONG64       ExecTrapChainRcxRva;             /* stage-2 pivot: target = GuestRCX + RcxRva (0=none) */
    volatile ULONG64       PendingExecTrapChainRcxRva;
    volatile ULONG64       ExecTrapChainStage3Pa;           /* pre-resolved PA for stage-3; bypasses dead PTE-walk (g_PteBase=0 on this HW) */
    volatile ULONG64       PendingExecTrapChainStage3Pa;

    /* ── Syscall SSN trap  ─────────────────────────────────────
     * Relative offsets from SyscallTrapMagic (used by the host-side trap tool):
     *   +0x00  SyscallTrapMagic
     *   +0x08  ExecTrapRaxFilter           UINT64  0=off; log only when RAX==this
     *   +0x10  ExecTrapRaxFiltered         LONG    hits dropped by RAX filter
     *   +0x14  ExecTrapRaxPad              LONG    alignment
     *   +0x18  PendingQueryLstarOp         UINT64  1=query IA32_LSTAR; HV clears
     *   +0x20  PendingQueryLstarResult     UINT64  LSTAR VA written by HV
     *   +0x28  PendingTranslateKvaVa       UINT64  kernel VA to translate
     *   +0x30  PendingTranslateKvaOp       UINT64  1=translate; HV clears
     *   +0x38  PendingTranslateKvaResult   UINT64  PA result (~0=failure)
     *   +0x40  PendingExecTrapRaxFilter    UINT64  desired filter value
     *   +0x48  PendingExecTrapRaxFilterOp  UINT64  1=set, 2=clear
     *   +0x50  PendingExecTrapRaxFilterResult  UINT64  0=none, 1=ok, 0xE5=fail
     *   +0x58  LstarPa                         UINT64  PA of LSTAR page; MmGetPhysicalAddress at DriverEntry
     *   +0x60  SyscallTrapMagicEnd */
    ULONG64           SyscallTrapMagic;               /* = SYSCALL_TRAP_MAGIC */
    volatile ULONG64  ExecTrapRaxFilter;              /* 0=off; only log when RAX==this */
    volatile LONG     ExecTrapRaxFiltered;            /* hits dropped by the RAX filter */
    volatile LONG     ExecTrapRaxPad;                 /* alignment */
    volatile ULONG64  PendingQueryLstarOp;            /* 1=query IA32_LSTAR; HV clears */
    volatile ULONG64  PendingQueryLstarResult;        /* LSTAR VA written by HV */
    volatile ULONG64  PendingTranslateKvaVa;          /* kernel VA to translate */
    volatile ULONG64  PendingTranslateKvaOp;          /* 1=translate; HV clears */
    volatile ULONG64  PendingTranslateKvaResult;      /* PA result (~0ULL = failure) */
    volatile ULONG64  PendingExecTrapRaxFilter;       /* desired RAX filter value */
    volatile ULONG64  PendingExecTrapRaxFilterOp;     /* 1=set, 2=clear */
    volatile ULONG64  PendingExecTrapRaxFilterResult; /* 0=none, 1=ok, 0xE5=fail */
    ULONG64           LstarPa;                        /* PA of KiSystemCall64Shadow page; filled at DriverEntry */
    ULONG64           SyscallTrapMagicEnd;            /* = SYSCALL_TRAP_MAGIC_END */

    /* ── DllMain Fork Capture sentinel block  ──────────
     * Dual-site DR-execute trap captures all guest GPRs + 2 KB stack
     * at gsl+0x36A3A7 (site 0) and gsl+0x28A7314 (site 1).  Stack is
     * captured in-VMX-root via 4-level PT walk + ShvEptReadPhysicalPage
     * (MmMapIoSpaceEx) — DirectMapBase and g_PteBase disabled on this
     * system. ForkCapPageScratch is the per-page read buffer reused
     * for each PT level; single-thread DllMain capture: no race.
     *
     * Block offsets from ForkCapMagic are pinned in FKC_OFF_* defines:
     *   +0x000  ForkCapMagic
     *   +0x008  ForkCapSiteVa[2]
     *   +0x018  ForkCapTargetCr3
     *   +0x020  ForkCapArmed (LONG)
     *   +0x024  ForkCapHits  (LONG)
     *   +0x028  ForkCapAllFired (LONG)
     *   +0x02C  ForkCapPad
     *   +0x030  ForkCapRecords[2]  (each 0x8B0 bytes = 2224)
     *   +0x1190 PendingForkCapSiteVa[2]
     *   +0x11A0 PendingForkCapTargetCr3
     *   +0x11A8 PendingForkCapOp
     *   +0x11B0 PendingForkCapResult
     *   +0x11B8 ForkCapMagicEnd */
    ULONG64                  ForkCapMagic;                              /* = DLLMAIN_FORK_CAP_MAGIC */
    volatile ULONG64         ForkCapSiteVa[DLLMAIN_FORK_CAP_SITES];    /* armed VAs; 0 = not armed */
    volatile ULONG64         ForkCapTargetCr3;                          /* 0 = any process */
    volatile LONG            ForkCapArmed;                              /* 0 = disarmed */
    volatile LONG            ForkCapHits;                               /* total #DB fires from our DRs */
    volatile LONG            ForkCapAllFired;                           /* 1 when both sites captured */
    volatile LONG            ForkCapPad;                                /* alignment */
    DLLMAIN_FORK_RECORD      ForkCapRecords[DLLMAIN_FORK_CAP_SITES];   /* 2 × 0x8B0 = 0x1160 */
    volatile ULONG64         PendingForkCapSiteVa[DLLMAIN_FORK_CAP_SITES]; /* written by UM before op */
    volatile ULONG64         PendingForkCapTargetCr3;
    volatile ULONG64         PendingForkCapOp;     /* DLLMAIN_FORK_OP_ARM / DISARM / STATUS */
    volatile ULONG64         PendingForkCapResult; /* 0 = none, 1 = ok, 0xE5 = fail, 0xE2 = conflict */
    ULONG64                  ForkCapMagicEnd;                           /* = DLLMAIN_FORK_CAP_MAGIC_END */
    UCHAR                    ForkCapPageScratch[PAGE_SIZE];             /* reused per-page PT walk buffer */

    /* ── SHV log ring  ──────────────────────────────────────────
     * SHV_LOG goes to DbgPrintEx, which in practice requires DebugView AND buries
     * our lines under unrelated kernel spam (NexusCore TPM retries, Intel XTU,
     * Edge.). The HW run needed 4 lines out of hundreds. Mirror every
     * SHV_LOG/WARN/ERR into this ring so `NexusDSEFix --shv-log` can dump just our
     * output to console or a file -- no DebugView, no noise.
     *
     * SAFE TO APPEND HERE: every C_ASSERT in this header pins RELATIVE offsets
     * (FIELD_OFFSET(x) - FIELD_OFFSET(<magic>)), and nothing asserts
     * sizeof(SHV_GLOBAL), so tail fields cannot disturb the pinned layout.
     *
     * Lock-free: writers InterlockedIncrement a monotonic counter and own
     * (idx % SHV_LOG_LINES). A reader may catch a torn line while it is being
     * written; that is acceptable for a diagnostic and never blocks VMX-root. */
    ULONG64                  ShvLogMagic;        /* = SHV_LOG_MAGIC once initialized */
    volatile LONG            ShvLogWriteIdx;     /* monotonic; slot = (idx-1) % SHV_LOG_LINES */
    ULONG                    ShvLogLines;        /* = SHV_LOG_LINES   (self-describing for the reader) */
    ULONG                    ShvLogLineLen;      /* = SHV_LOG_LINE_LEN */
    ULONG                    ShvLogPad;
    CHAR                     ShvLogRing[SHV_LOG_LINES][SHV_LOG_LINE_LEN];
    ULONG64                  ShvLogMagicEnd;     /* = SHV_LOG_MAGIC_END */
} SHV_GLOBAL, *PSHV_GLOBAL;

/* ── RIP-trace offsets (relative to RipTraceMagic) ─────────────────
 * UM tool uses these to compute field VAs after scanning for the magic.
 * Pinned via C_ASSERT to catch any accidental layout shift. */
#define RTR_OFF_MAGIC              0x00
#define RTR_OFF_ACTIVE             0x08
#define RTR_OFF_ARM_ON_HIT         0x0C
#define RTR_OFF_STEPS_MAX          0x10
#define RTR_OFF_STOP_ON_RANGE      0x14
#define RTR_OFF_STOP_LOW           0x18
#define RTR_OFF_STOP_HIGH          0x20
#define RTR_OFF_CR3_FILTER         0x28
#define RTR_OFF_LOG_PTR            0x30
#define RTR_OFF_LOG_INDEX          0x38
#define RTR_OFF_LOG_TOTAL          0x3C
#define RTR_OFF_STEPS_TAKEN        0x40
/* 0x44..0x47 alignment padding */
#define RTR_OFF_PENDING_OP         0x48
#define RTR_OFF_PENDING_STEPS_MAX  0x50
#define RTR_OFF_PENDING_STOP_LOW   0x58
#define RTR_OFF_PENDING_STOP_HIGH  0x60
#define RTR_OFF_PENDING_CR3        0x68
#define RTR_OFF_PENDING_STOP_RANGE 0x70
#define RTR_OFF_PENDING_RESULT     0x78

C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, RipTraceMagic)              == FIELD_OFFSET(SHV_GLOBAL, RipTraceMagic));
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, RipTraceActive)             - FIELD_OFFSET(SHV_GLOBAL, RipTraceMagic) == RTR_OFF_ACTIVE);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, RipTraceArmOnHit)           - FIELD_OFFSET(SHV_GLOBAL, RipTraceMagic) == RTR_OFF_ARM_ON_HIT);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, RipTraceStepsMax)           - FIELD_OFFSET(SHV_GLOBAL, RipTraceMagic) == RTR_OFF_STEPS_MAX);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, RipTraceStopOnRange)        - FIELD_OFFSET(SHV_GLOBAL, RipTraceMagic) == RTR_OFF_STOP_ON_RANGE);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, RipTraceStopLow)            - FIELD_OFFSET(SHV_GLOBAL, RipTraceMagic) == RTR_OFF_STOP_LOW);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, RipTraceStopHigh)           - FIELD_OFFSET(SHV_GLOBAL, RipTraceMagic) == RTR_OFF_STOP_HIGH);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, RipTraceCr3Filter)          - FIELD_OFFSET(SHV_GLOBAL, RipTraceMagic) == RTR_OFF_CR3_FILTER);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, RipTraceLog)                - FIELD_OFFSET(SHV_GLOBAL, RipTraceMagic) == RTR_OFF_LOG_PTR);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, RipTraceLogIndex)           - FIELD_OFFSET(SHV_GLOBAL, RipTraceMagic) == RTR_OFF_LOG_INDEX);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, RipTraceLogTotal)           - FIELD_OFFSET(SHV_GLOBAL, RipTraceMagic) == RTR_OFF_LOG_TOTAL);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, RipTraceStepsTaken)         - FIELD_OFFSET(SHV_GLOBAL, RipTraceMagic) == RTR_OFF_STEPS_TAKEN);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, PendingRipTraceOp)          - FIELD_OFFSET(SHV_GLOBAL, RipTraceMagic) == RTR_OFF_PENDING_OP);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, PendingRipTraceStepsMax)    - FIELD_OFFSET(SHV_GLOBAL, RipTraceMagic) == RTR_OFF_PENDING_STEPS_MAX);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, PendingRipTraceStopLow)     - FIELD_OFFSET(SHV_GLOBAL, RipTraceMagic) == RTR_OFF_PENDING_STOP_LOW);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, PendingRipTraceStopHigh)    - FIELD_OFFSET(SHV_GLOBAL, RipTraceMagic) == RTR_OFF_PENDING_STOP_HIGH);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, PendingRipTraceCr3)         - FIELD_OFFSET(SHV_GLOBAL, RipTraceMagic) == RTR_OFF_PENDING_CR3);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, PendingRipTraceStopOnRange) - FIELD_OFFSET(SHV_GLOBAL, RipTraceMagic) == RTR_OFF_PENDING_STOP_RANGE);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, PendingRipTraceResult)      - FIELD_OFFSET(SHV_GLOBAL, RipTraceMagic) == RTR_OFF_PENDING_RESULT);

/* ── Exec-trap hash-capture offsets (relative to ExecTrapCapMagic) ── */
#define ETC_OFF_MAGIC               0x00
#define ETC_OFF_SRC                 0x08  /* ULONG32 */
#define ETC_OFF_LEN                 0x0C  /* ULONG32 */
#define ETC_OFF_HITS                0x10  /* LONG    */
#define ETC_OFF_READ_FAILS          0x14  /* LONG    */
#define ETC_OFF_PENDING_SRC         0x18
#define ETC_OFF_PENDING_LEN         0x20
#define ETC_OFF_PENDING_OP          0x28
#define ETC_OFF_PENDING_RESULT      0x30
#define ETC_OFF_MAGIC_END           0x38

/* ── Cipher-trap offsets (relative to CipherTrapMagic) ──────────── */
#define CTR_OFF_MAGIC              0x00  /* CipherTrapMagic        (ULONG64) */
#define CTR_OFF_ACTIVE             0x08  /* CipherTrapActive       (ULONG)   */
#define CTR_OFF_SITES_INSTALLED    0x0C  /* CipherTrapSitesInstalled (ULONG) */
#define CTR_OFF_KMBASE             0x10  /* CipherTrapKmBase       (ULONG64) */
#define CTR_OFF_KMEND              0x18  /* CipherTrapKmEnd        (ULONG64) */
#define CTR_OFF_HITS               0x20  /* CipherTrapHits         (LONG)    */
#define CTR_OFF_CAPFAILS           0x24  /* CipherTrapCapFails     (LONG)    */
/* 0x28 = CipherTrapLog PVOID (8 bytes, 8-byte aligned) */
#define CTR_OFF_LOG_PTR            0x28
#define CTR_OFF_LOG_INDEX          0x30  /* CipherTrapLogIndex     (LONG)    */
#define CTR_OFF_LOG_TOTAL          0x34  /* CipherTrapLogTotal     (LONG)    */
/* 0x38 = CipherTrapSitePa[0] (80 * 8 = 640 bytes) */
#define CTR_OFF_SITE_PA_BASE       0x38
/* 0x2B8 = PendingCipherTrapKmBase */
#define CTR_OFF_PENDING_KMBASE     0x2B8
#define CTR_OFF_PENDING_KMSIZE     0x2C0
#define CTR_OFF_PENDING_OP         0x2C8
#define CTR_OFF_PENDING_RESULT     0x2D0
#define CTR_OFF_MAGIC_END          0x2D8

/* ── Exec-trap / Read-trap absolute offset assertions ──────────────────
 * These catch any future struct growth that shifts the pending-op region.
 * NexusDSEFix XT_OFF_* and RT_OFF_* must stay in sync with these values.
 * Last bumped: +0x10 for WriteTrapAutoArmExecVaOffset/Cr3 pair
 * inserted between PendingWriteTrapResult and ReadTrapCr3. */
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, ReadTrapCr3)           == 0x2708);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, PendingReadTrapCr3)    == 0x2768);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, PendingReadTrapOp)     == 0x2790);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, PendingReadTrapResult) == 0x2798);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, ExecTrapCr3)           == 0x27A0);

C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, ExecTrapActive)        == 0x27C8);

C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, ExecTrapSavedPteValue) == 0x27F8);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, PendingExecTrapCr3)    == 0x2800);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, PendingExecTrapVaBase) == 0x2808);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, PendingExecTrapOp)     == 0x2828);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, PendingExecTrapResult) == 0x2830);

C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, ExecTrapCapSrc)              - FIELD_OFFSET(SHV_GLOBAL, ExecTrapCapMagic) == ETC_OFF_SRC);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, ExecTrapCapLen)              - FIELD_OFFSET(SHV_GLOBAL, ExecTrapCapMagic) == ETC_OFF_LEN);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, ExecTrapCapHits)             - FIELD_OFFSET(SHV_GLOBAL, ExecTrapCapMagic) == ETC_OFF_HITS);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, ExecTrapCapReadFails)        - FIELD_OFFSET(SHV_GLOBAL, ExecTrapCapMagic) == ETC_OFF_READ_FAILS);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, PendingExecTrapCapSrc)       - FIELD_OFFSET(SHV_GLOBAL, ExecTrapCapMagic) == ETC_OFF_PENDING_SRC);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, PendingExecTrapCapLen)       - FIELD_OFFSET(SHV_GLOBAL, ExecTrapCapMagic) == ETC_OFF_PENDING_LEN);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, PendingExecTrapCapOp)        - FIELD_OFFSET(SHV_GLOBAL, ExecTrapCapMagic) == ETC_OFF_PENDING_OP);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, PendingExecTrapCapResult)    - FIELD_OFFSET(SHV_GLOBAL, ExecTrapCapMagic) == ETC_OFF_PENDING_RESULT);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, ExecTrapCapMagicEnd)         - FIELD_OFFSET(SHV_GLOBAL, ExecTrapCapMagic) == ETC_OFF_MAGIC_END);

/* ── Cipher-trap field offset assertions ───────────────────────────── */
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, CipherTrapActive)           - FIELD_OFFSET(SHV_GLOBAL, CipherTrapMagic) == CTR_OFF_ACTIVE);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, CipherTrapSitesInstalled)   - FIELD_OFFSET(SHV_GLOBAL, CipherTrapMagic) == CTR_OFF_SITES_INSTALLED);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, CipherTrapKmBase)           - FIELD_OFFSET(SHV_GLOBAL, CipherTrapMagic) == CTR_OFF_KMBASE);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, CipherTrapKmEnd)            - FIELD_OFFSET(SHV_GLOBAL, CipherTrapMagic) == CTR_OFF_KMEND);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, CipherTrapHits)             - FIELD_OFFSET(SHV_GLOBAL, CipherTrapMagic) == CTR_OFF_HITS);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, CipherTrapCapFails)         - FIELD_OFFSET(SHV_GLOBAL, CipherTrapMagic) == CTR_OFF_CAPFAILS);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, CipherTrapLog)              - FIELD_OFFSET(SHV_GLOBAL, CipherTrapMagic) == CTR_OFF_LOG_PTR);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, CipherTrapLogIndex)         - FIELD_OFFSET(SHV_GLOBAL, CipherTrapMagic) == CTR_OFF_LOG_INDEX);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, CipherTrapLogTotal)         - FIELD_OFFSET(SHV_GLOBAL, CipherTrapMagic) == CTR_OFF_LOG_TOTAL);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, CipherTrapSitePa)           - FIELD_OFFSET(SHV_GLOBAL, CipherTrapMagic) == CTR_OFF_SITE_PA_BASE);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, PendingCipherTrapKmBase)    - FIELD_OFFSET(SHV_GLOBAL, CipherTrapMagic) == CTR_OFF_PENDING_KMBASE);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, PendingCipherTrapKmSize)    - FIELD_OFFSET(SHV_GLOBAL, CipherTrapMagic) == CTR_OFF_PENDING_KMSIZE);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, PendingCipherTrapOp)        - FIELD_OFFSET(SHV_GLOBAL, CipherTrapMagic) == CTR_OFF_PENDING_OP);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, PendingCipherTrapResult)    - FIELD_OFFSET(SHV_GLOBAL, CipherTrapMagic) == CTR_OFF_PENDING_RESULT);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, CipherTrapMagicEnd)         - FIELD_OFFSET(SHV_GLOBAL, CipherTrapMagic) == CTR_OFF_MAGIC_END);

/* ── SSN-trap sentinel block offset assertions  ─────────── */
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, ExecTrapRaxFilter)              - FIELD_OFFSET(SHV_GLOBAL, SyscallTrapMagic) == SST_OFF_RAXFILTER);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, ExecTrapRaxFiltered)            - FIELD_OFFSET(SHV_GLOBAL, SyscallTrapMagic) == SST_OFF_RAXFILTERED);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, PendingQueryLstarOp)            - FIELD_OFFSET(SHV_GLOBAL, SyscallTrapMagic) == SST_OFF_QUERY_LSTAR_OP);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, PendingQueryLstarResult)        - FIELD_OFFSET(SHV_GLOBAL, SyscallTrapMagic) == SST_OFF_QUERY_LSTAR_RESULT);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, PendingTranslateKvaVa)          - FIELD_OFFSET(SHV_GLOBAL, SyscallTrapMagic) == SST_OFF_TRANSLATE_KVA_VA);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, PendingTranslateKvaOp)          - FIELD_OFFSET(SHV_GLOBAL, SyscallTrapMagic) == SST_OFF_TRANSLATE_KVA_OP);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, PendingTranslateKvaResult)      - FIELD_OFFSET(SHV_GLOBAL, SyscallTrapMagic) == SST_OFF_TRANSLATE_KVA_RESULT);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, PendingExecTrapRaxFilter)       - FIELD_OFFSET(SHV_GLOBAL, SyscallTrapMagic) == SST_OFF_PENDING_RAXFILTER);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, PendingExecTrapRaxFilterOp)     - FIELD_OFFSET(SHV_GLOBAL, SyscallTrapMagic) == SST_OFF_PENDING_RAXFILTER_OP);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, PendingExecTrapRaxFilterResult) - FIELD_OFFSET(SHV_GLOBAL, SyscallTrapMagic) == SST_OFF_PENDING_RAXFILTER_RESULT);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, LstarPa)                        - FIELD_OFFSET(SHV_GLOBAL, SyscallTrapMagic) == SST_OFF_LSTAR_PA);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, SyscallTrapMagicEnd)            - FIELD_OFFSET(SHV_GLOBAL, SyscallTrapMagic) == SST_OFF_MAGIC_END);

/* ── DllMain fork-capture sentinel block offset assertions  ── */
C_ASSERT(sizeof(DLLMAIN_FORK_RECORD) == FKC_REC_SIZE);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, ForkCapSiteVa)          - FIELD_OFFSET(SHV_GLOBAL, ForkCapMagic) == FKC_OFF_SITE_VA_0);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, ForkCapTargetCr3)       - FIELD_OFFSET(SHV_GLOBAL, ForkCapMagic) == FKC_OFF_TARGET_CR3);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, ForkCapArmed)           - FIELD_OFFSET(SHV_GLOBAL, ForkCapMagic) == FKC_OFF_ARMED);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, ForkCapRecords)         - FIELD_OFFSET(SHV_GLOBAL, ForkCapMagic) == FKC_OFF_RECORDS);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, PendingForkCapSiteVa)   - FIELD_OFFSET(SHV_GLOBAL, ForkCapMagic) == FKC_OFF_PENDING_VA_0);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, PendingForkCapTargetCr3)- FIELD_OFFSET(SHV_GLOBAL, ForkCapMagic) == FKC_OFF_PENDING_CR3);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, PendingForkCapOp)       - FIELD_OFFSET(SHV_GLOBAL, ForkCapMagic) == FKC_OFF_PENDING_OP);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, PendingForkCapResult)   - FIELD_OFFSET(SHV_GLOBAL, ForkCapMagic) == FKC_OFF_PENDING_RESULT);
C_ASSERT(FIELD_OFFSET(SHV_GLOBAL, ForkCapMagicEnd)        - FIELD_OFFSET(SHV_GLOBAL, ForkCapMagic) == FKC_OFF_MAGIC_END);

extern SHV_GLOBAL g_Shv;

/* Auto-arm-on-module-load (entry.c) — registers/unregisters the
 * PsSetLoadImageNotifyRoutine callback that consumes g_Shv.AutoArm*. */
NTSTATUS ShvAutoArmRegister(VOID);
VOID     ShvAutoArmUnregister(VOID);

/* VMX-root safe: walk guest CR3's page tables to translate VA -> PA.
 * Returns FALSE if any level is not-present or hits an unhandled
 * large-page boundary. Used by exit_dispatch to resolve the target PA
 * for a deferred UM auto-arm install (the LoadImage callback can't
 * resolve it because the page hasn't been faulted in yet). */
BOOLEAN ShvTranslateGuestVa(_In_ ULONG64 GuestCr3, _In_ ULONG64 Va,
                            _Out_ PULONG64 OutPa);

/* VMX-root safe physical page read via MmMapIoSpaceEx (NOT DirectMapBase).
 * Maps the 4KB page at GuestPhysAddr (page-aligned), copies into Dst[4096],
 * then unmaps. Called from VMCALL_EPT_READ_PAGE and the ForkCap #DB handler.
 * GPA==HPA in SentinelHV's identity-mapped EPT; pass the physical address. */
BOOLEAN ShvEptReadPhysicalPage(_In_ ULONG64 GuestPhysAddr, _Out_ PVOID Dst);

/* VMX-root safe VA→PA via PTE_BASE self-ref. Works on VBS/HVCI where
 * ShvReadGuestPhysQword (and therefore ShvTranslateGuestVa) is disabled.
 * Fixes the kernel-VA uint64 overflow in ShvReadGuestVaDirect. 4KB only. */
BOOLEAN ShvTranslateVaDirect(_In_ ULONG64 Va, _Out_ PULONG64 OutPa);

#endif /* SHV_PLATFORM_NT */

/* ── VMX Core API ─────────────────────────────────────────────────── */

/**
 * @brief Detect whether the CPU supports Intel VMX and BIOS has enabled it.
 *
 * Checks CPUID leaf 1 for VMX support, verifies IA32_FEATURE_CONTROL is
 * locked with VMXON-outside-SMX enabled, reads the VMX revision ID from
 * IA32_VMX_BASIC, and validates the VMCS region size fits in 4KB.
 *
 * @return TRUE if VMX is fully supported and ready, FALSE otherwise.
 */
BOOLEAN ShvIsVmxSupported(void);

#ifdef SHV_PLATFORM_NT
/**
 * @brief HV-7: Sample bare-metal CPUID responses before VMXON.
 *
 * MUST be called from DriverEntry BEFORE any VMX bring-up so the CPU is
 * still in bare-metal (non-hypervised) state. Captures:
 *   - Max std leaf (CPUID.0 EAX)
 *   - Max ext leaf (CPUID.80000000 EAX)
 *   - Bare-metal response for out-of-range invalid leaves
 *   - Valid XCR0 mask from CPUID.0D
 * Results are cached in g_Shv.StealthCache and replayed by
 * ShvHandleCpuid for 0x40000000..0x4FFFFFFF and any other invalid leaf.
 */
VOID
ShvInitStealthCpuidCache(VOID);

/**
 * @brief Initialize EPT and virtualize all logical processors via IPI.
 *
 * Builds the identity-mapped EPT, then dispatches an IPI (Inter-Processor
 * Interrupt) to every logical processor via KeIpiGenericCall. Each CPU
 * executes VMXON, configures its VMCS, and enters VMX non-root operation
 * via VMLAUNCH. Sets g_Shv.Active on success.
 *
 * @return STATUS_SUCCESS if at least one CPU was virtualized.
 */
NTSTATUS
ShvVirtualizeAllProcessors(void);

/**
 * @brief Devirtualize all logical processors and tear down EPT.
 *
 * Dispatches an IPI that issues VMCALL(DEVIRTUALIZE) on each CPU.
 * The VM-exit handler executes VMXOFF, clears CR4.VMXE, and returns
 * control to non-VMX operation. EPT state is freed after all CPUs
 * are devirtualized.
 *
 * @return STATUS_SUCCESS on completion.
 */
NTSTATUS
ShvDevirtualizeAllProcessors(void);
#endif /* SHV_PLATFORM_NT */

/**
 * @brief Virtualize a single logical processor (VMXON through VMLAUNCH).
 *
 * Called from IPI context on NT or directly on EFI. Captures the current
 * CPU context, adjusts CR0/CR4 per VMX fixed-bit MSRs, executes VMXON,
 * initializes the VMCS via VMCLEAR + VMPTRLD + ShvSetupVmcs, and performs
 * VMLAUNCH. On success, execution resumes as a VMX guest at the captured
 * return address with ShvCaptureContext returning 1.
 *
 * @param Vcpu  Pre-allocated per-CPU VCPU_DATA structure.
 * @return STATUS_SUCCESS when running as guest, error status on failure.
 */
NTSTATUS
ShvVirtualizeProcessor(
    _In_ PVCPU_DATA Vcpu
    );

/* ── VCPU Allocation ──────────────────────────────────────────────── */

#ifdef SHV_PLATFORM_NT
/**
 * @brief Allocate the VCPU array and per-CPU VCPU_DATA structures.
 *
 * Queries the active processor count, allocates a pointer array, then
 * allocates each VCPU_DATA as physically contiguous memory (required for
 * 4KB-aligned VMXON/VMCS regions). Initializes revision IDs, physical
 * addresses, host stack pointers, and MSR bitmaps.
 *
 * @return STATUS_SUCCESS on success, STATUS_INSUFFICIENT_RESOURCES on failure.
 */
NTSTATUS
ShvAllocateVcpuArray(void);

/**
 * @brief Free all VCPU_DATA structures and the VCPU pointer array.
 *
 * Releases the contiguous memory for each VCPU and the pool-allocated
 * pointer array. Safe to call if allocation was partial (NULL entries
 * are skipped).
 */
void
ShvFreeVcpuArray(void);
#endif /* SHV_PLATFORM_NT */

/* ── Utility ──────────────────────────────────────────────────────── */

/**
 * @brief Allocate physically contiguous, zero-initialized memory.
 *
 * Used for VCPU_DATA and EPT_STATE which require physically contiguous
 * backing (4KB-aligned physical addresses for VMXON/VMCS regions and
 * EPT page tables). Implementation is platform-specific (MmAllocate on NT).
 *
 * @param Size  Number of bytes to allocate.
 * @return Pointer to the allocated memory, or NULL on failure.
 */
PVOID
ShvAllocateContiguousMemory(
    _In_ SIZE_T Size
    );

/**
 * @brief Free memory previously allocated by ShvAllocateContiguousMemory.
 *
 * @param Address  Pointer returned by ShvAllocateContiguousMemory.
 * @param Size     Original allocation size (may be ignored by platform).
 */
void
ShvFreeContiguousMemory(
    _In_ PVOID Address,
    _In_ SIZE_T Size
    );

/* ── ASM Segment/Descriptor Helpers ───────────────────────────────── */

/** @brief Read the CS (Code Segment) selector register. */
USHORT ShvReadCs(void);
/** @brief Read the SS (Stack Segment) selector register. */
USHORT ShvReadSs(void);
/** @brief Read the DS (Data Segment) selector register. */
USHORT ShvReadDs(void);
/** @brief Read the ES (Extra Segment) selector register. */
USHORT ShvReadEs(void);
/** @brief Read the FS segment selector register. */
USHORT ShvReadFs(void);
/** @brief Read the GS segment selector register. */
USHORT ShvReadGs(void);
/** @brief Read the TR (Task Register) selector via STR instruction. */
USHORT ShvReadTr(void);
/** @brief Read the LDTR (Local Descriptor Table Register) via SLDT. */
USHORT ShvReadLdtr(void);

/**
 * @brief Execute SGDT and store the result in the output structure.
 * @param Out  Receives the 10-byte GDTR value (2-byte limit + 8-byte base).
 */
void ShvSgdt(_Out_ PDESCRIPTOR_TABLE_REG Out);

/**
 * @brief Execute SIDT and store the result in the output structure.
 * @param Out  Receives the 10-byte IDTR value (2-byte limit + 8-byte base).
 */
void ShvSidt(_Out_ PDESCRIPTOR_TABLE_REG Out);

/** @brief Read the DR7 (Debug Control) register. */
ULONG64 ShvReadDr7(void);

/* ── ASM Externals ────────────────────────────────────────────────── */

/**
 * @brief Capture current CPU context for VMCS guest state initialization.
 *
 * Saves all general-purpose registers, the caller's RSP, the return address
 * (RIP), and RFLAGS into the provided GUEST_CONTEXT structure. This captured
 * state becomes the VMCS guest state so that after VMLAUNCH, execution
 * resumes at the captured RIP as if this function returned.
 *
 * Uses a setjmp-like dual-return mechanism:
 *   - First call: returns 0 (caller proceeds with VMX setup and VMLAUNCH).
 *   - After VMLAUNCH: guest resumes at captured RIP with RAX=1 (set by VMCS
 *     setup), so the caller sees a non-zero return indicating guest mode.
 *
 * @param Context  Output structure receiving the captured register state.
 * @return 0 on initial capture, non-zero when resumed as VMX guest.
 */
ULONG64
ShvCaptureContext(
    _Out_ PGUEST_CONTEXT Context
    );

/**
 * @brief ASM entry point for all VM-exits (written to VMCS HOST_RIP).
 *
 * On every VM-exit, the CPU loads HOST_RSP and jumps to this address.
 * The stub saves all guest GPRs onto the host stack to form a GUEST_CONTEXT,
 * retrieves the VCPU pointer from the pre-stored host stack slot, calls
 * ShvHandleVmExit, then restores guest GPRs and executes VMRESUME.
 *
 * If ShvHandleVmExit returns TRUE (devirtualize), the stub does not
 * VMRESUME; instead ShvVmxOffAndRestore has already jumped to guest code.
 *
 * This function's address is only taken for VMCS configuration; it is
 * never called directly from C code.
 */
void ShvVmExitStub(void);

/**
 * @brief Load guest GPRs from context and execute VMLAUNCH.
 *
 * Restores all general-purpose registers from the provided GUEST_CONTEXT
 * and executes the VMLAUNCH instruction. On success, execution transfers
 * to the guest at VMCS_GUEST_RIP and this function never returns.
 *
 * On failure (CF or ZF set in RFLAGS), returns the RFLAGS value to the
 * caller for error diagnosis. The VMCS instruction error field should be
 * read via __vmx_vmread to determine the specific failure reason.
 *
 * @param Context  Guest register state to load before VMLAUNCH.
 * @return RFLAGS value on failure; does not return on success.
 */
ULONG64
ShvVmxLaunch(
    _In_ PGUEST_CONTEXT Context
    );

/**
 * @brief Execute a VMCALL hypercall from guest mode.
 *
 * Issues the VMCALL instruction with the specified command and authentication
 * cookie. The VM-exit handler reads these from the guest's RCX and RDX
 * registers, processes the command, and sets RAX as the return value.
 *
 * For VMCALL_DEVIRTUALIZE, the handler calls ShvVmxOffAndRestore which
 * disables VMX and returns STATUS_SUCCESS as if VMCALL returned normally.
 *
 * @param Command  Hypercall command code (e.g., VMCALL_PING, VMCALL_DEVIRTUALIZE).
 * @param Cookie   Authentication value (must be VMCALL_MAGIC_COOKIE for privileged ops).
 * @return NTSTATUS set by the VM-exit handler in guest RAX.
 */
NTSTATUS
ShvDoVmcall(
    _In_ ULONG64 Command,
    _In_ ULONG64 Cookie
    );

/**
 * @brief Execute VMXOFF, clear CR4.VMXE, restore guest state, and jump to guest.
 *
 * Called from the VMCALL(DEVIRTUALIZE) exit handler to permanently exit VMX
 * root operation on the current CPU. Executes VMXOFF, clears the VMXE bit
 * in CR4, restores the guest's RSP and RFLAGS, places ReturnValue in RAX,
 * and jumps to GuestRip (past the VMCALL instruction).
 *
 * This function does not return -- it performs a direct jump to guest code.
 *
 * @param GuestRip     Address to jump to (VMCALL instruction + length).
 * @param GuestRsp     Guest stack pointer to restore.
 * @param GuestRflags  Guest RFLAGS to restore via POPFQ.
 * @param ReturnValue  Value placed in RAX (typically STATUS_SUCCESS).
 */
void
ShvVmxOffAndRestore(
    _In_ ULONG64 GuestRip,
    _In_ ULONG64 GuestRsp,
    _In_ ULONG64 GuestRflags,
    _In_ ULONG64 ReturnValue
    );

/**
 * @brief Invalidate EPT-derived TLB entries via the INVEPT instruction.
 *
 * @param Type        Invalidation type (INVEPT_SINGLE_CONTEXT or INVEPT_ALL_CONTEXTS).
 * @param Descriptor  Pointer to INVEPT_DESCRIPTOR containing the EPTP value.
 * @return 0 on success, 1 on failure (CF or ZF set).
 */
UCHAR ShvInvept(_In_ ULONG64 Type, _In_ void* Descriptor);

/**
 * @brief Invalidate VPID-tagged TLB entries via the INVVPID instruction.
 *
 * @param Type        Invalidation type (INVVPID_SINGLE_CONTEXT, INVVPID_ALL_CONTEXTS, etc.).
 * @param Descriptor  Pointer to INVVPID_DESCRIPTOR containing VPID and linear address.
 * @return 0 on success, 1 on failure (CF or ZF set).
 */
UCHAR ShvInvvpid(_In_ ULONG64 Type, _In_ void* Descriptor);
