/**
 * @file shv_vmx.h
 * @brief VMX constants, VMCS field encodings, MSR definitions, and control bits.
 *
 * Comprehensive definitions for Intel VMX (Virtual Machine Extensions) operation:
 *
 *   - **MSR Definitions**: IA32_VMX_BASIC, IA32_FEATURE_CONTROL, capability MSRs
 *     for pin/proc/exit/entry controls, SYSENTER/EFER/FS/GS base MSRs.
 *
 *   - **VMCS Field Encodings**: All 16-bit, 32-bit, 64-bit, and natural-width
 *     VMCS fields for guest state, host state, control, and read-only areas.
 *
 *   - **VM-Execution Controls**: Pin-based, primary/secondary processor-based
 *     control bits (EPT, RDTSCP, VPID, MSR bitmaps, etc.).
 *
 *   - **VM-Exit/Entry Controls**: Host address space size, EFER save/load,
 *     debug controls, IA-32e mode guest.
 *
 *   - **Exit Reasons**: All VMX exit reason codes (CPUID, CR access, MSR,
 *     VMCALL, EPT violation, triple fault, etc.).
 *
 *   - **CR Access Qualification**: Macros to decode exit qualification for
 *     MOV to/from CR, CLTS, and LMSW operations.
 *
 *   - **VMCALL Protocol**: Command codes and magic cookie for hypervisor
 *     communication (ping, devirtualize).
 *
 *   - **VMX_REGION**: 4KB-aligned structure for VMXON and VMCS regions.
 */

#pragma once

#include "shv_platform.h"

/* ── Intel MSR Definitions ────────────────────────────────────────── */

#define IA32_FEATURE_CONTROL            0x0000003A
#define IA32_DEBUGCTL                   0x000001D9
#define IA32_SYSENTER_CS                0x00000174
#define IA32_SYSENTER_ESP               0x00000175
#define IA32_SYSENTER_EIP               0x00000176
#define IA32_PAT                        0x00000277

#define IA32_VMX_BASIC                  0x00000480
#define IA32_VMX_PINBASED_CTLS          0x00000481
#define IA32_VMX_PROCBASED_CTLS         0x00000482
#define IA32_VMX_EXIT_CTLS              0x00000483
#define IA32_VMX_ENTRY_CTLS             0x00000484
#define IA32_VMX_MISC                   0x00000485
#define IA32_VMX_CR0_FIXED0             0x00000486
#define IA32_VMX_CR0_FIXED1             0x00000487
#define IA32_VMX_CR4_FIXED0             0x00000488
#define IA32_VMX_CR4_FIXED1             0x00000489
#define IA32_VMX_PROCBASED_CTLS2        0x0000048B
#define IA32_VMX_TRUE_PINBASED_CTLS     0x0000048D
#define IA32_VMX_TRUE_PROCBASED_CTLS    0x0000048E
#define IA32_VMX_TRUE_EXIT_CTLS         0x0000048F
#define IA32_VMX_TRUE_ENTRY_CTLS        0x00000490

#define IA32_EFER                       0xC0000080
#define IA32_STAR                       0xC0000081
#define IA32_LSTAR                      0xC0000082
#define IA32_FS_BASE                    0xC0000100
#define IA32_GS_BASE                    0xC0000101
#define IA32_KERNEL_GS_BASE             0xC0000102

/* ── IA32_FEATURE_CONTROL bits ────────────────────────────────────── */

#define FEATURE_CONTROL_LOCK            (1ULL << 0)
#define FEATURE_CONTROL_VMXON_OUTSIDE   (1ULL << 2)

/* ── CR4 bits ─────────────────────────────────────────────────────── */

#define CR4_VMXE                        (1ULL << 13)

/* ── EFER bits ────────────────────────────────────────────────────── */

#ifndef EFER_SCE
#define EFER_SCE                        (1ULL << 0)
#endif
#ifndef EFER_LME
#define EFER_LME                        (1ULL << 8)
#endif
#ifndef EFER_LMA
#define EFER_LMA                        (1ULL << 10)
#endif
#ifndef EFER_NXE
#define EFER_NXE                        (1ULL << 11)
#endif

/* ── Pin-Based VM-Execution Controls ──────────────────────────────── */

#define PIN_BASED_EXT_INTERRUPT_EXIT    (1UL << 0)
#define PIN_BASED_NMI_EXIT              (1UL << 3)
#define PIN_BASED_VIRTUAL_NMIS          (1UL << 5)

/* ── Primary Processor-Based VM-Execution Controls ────────────────── */

#define CPU_BASED_HLT_EXITING           (1UL << 7)
#define CPU_BASED_MWAIT_EXITING         (1UL << 10)
#define CPU_BASED_INVLPG_EXITING        (1UL << 9)
#define CPU_BASED_RDTSC_EXITING         (1UL << 12)
#define CPU_BASED_CR3_LOAD_EXITING      (1UL << 15)
#define CPU_BASED_CR3_STORE_EXITING     (1UL << 16)
#define CPU_BASED_MOV_DR_EXITING        (1UL << 23)
#define CPU_BASED_UNCOND_IO_EXITING     (1UL << 24)
#define CPU_BASED_USE_MSR_BITMAPS       (1UL << 28)
#define CPU_BASED_ACTIVATE_SECONDARY    (1UL << 31)

/* ── Secondary Processor-Based VM-Execution Controls ──────────────── */

#define CPU_BASED2_ENABLE_EPT           (1UL << 1)
#define CPU_BASED2_ENABLE_RDTSCP        (1UL << 3)
#define CPU_BASED2_ENABLE_VPID          (1UL << 5)
#define CPU_BASED2_UNRESTRICTED_GUEST   (1UL << 7)
#define CPU_BASED2_ENABLE_INVPCID       (1UL << 12)
#define CPU_BASED2_ENABLE_VMFUNC        (1UL << 13)
#define CPU_BASED2_EPT_VIOLATION_VE     (1UL << 18)
#define CPU_BASED2_ENABLE_XSAVES       (1UL << 20)
#define CPU_BASED2_ENABLE_USER_WAIT_PAUSE (1UL << 26)

/* WBINVD-exiting bit (secondary controls bit 6). */
#define CPU_BASED2_WBINVD_EXITING       (1UL << 6)

/* VM-Function controls (VMCS_CTRL_VMFUNC_CTLS). Bit 0 = EPTP switching. */
#define VMFUNC_CTL_EPTP_SWITCHING       (1UL << 0)

/* ── Exception vectors (for VM-entry interruption-info) ───────────── */
#define VECTOR_DE                       0
#define VECTOR_DB                       1
#define VECTOR_BP                       3
#define VECTOR_UD                       6
#define VECTOR_NM                       7
#define VECTOR_DF                       8
#define VECTOR_TS                       10
#define VECTOR_NP                       11
#define VECTOR_SS                       12
#define VECTOR_GP                       13
#define VECTOR_PF                       14
#define VECTOR_AC                       17
#define VECTOR_VE                       20

/* VM-entry interruption-info encoding (Intel SDM Vol 3 Sec 25.8.3).
 * [7:0]   vector
 * [10:8]  type (0=ext-int, 2=NMI, 3=hw-exception, 4=sw-int, 5=priv-sw-exc, 6=sw-exc)
 * [11]    deliver error code (set for #DF, #TS, #NP, #SS, #GP, #PF, #AC)
 * [31]    valid bit
 */
#define INT_INFO_TYPE_HW_EXCEPTION      (3UL << 8)
#define INT_INFO_DELIVER_ERROR          (1UL << 11)
#define INT_INFO_VALID                  (1UL << 31)

/* ── VM-Entry Controls ────────────────────────────────────────────── */

#define VM_ENTRY_LOAD_DEBUG_CTLS        (1UL << 2)
#define VM_ENTRY_IA32E_MODE_GUEST       (1UL << 9)
#define VM_ENTRY_LOAD_IA32_EFER         (1UL << 15)

/* ── VM-Exit Controls ─────────────────────────────────────────────── */

#define VM_EXIT_SAVE_DEBUG_CTLS         (1UL << 2)
#define VM_EXIT_HOST_ADDR_SPACE_SIZE    (1UL << 9)
#define VM_EXIT_ACK_INTERRUPT_ON_EXIT   (1UL << 15)
#define VM_EXIT_LOAD_IA32_EFER          (1UL << 20)
#define VM_EXIT_SAVE_IA32_EFER          (1UL << 21)

/* ── VMCS Field Encodings ─────────────────────────────────────────── */

/* 16-bit Control Fields */
#define VMCS_CTRL_VPID                              0x00000000

/* 16-bit Guest State Fields */
#define VMCS_GUEST_ES_SELECTOR                      0x00000800
#define VMCS_GUEST_CS_SELECTOR                      0x00000802
#define VMCS_GUEST_SS_SELECTOR                      0x00000804
#define VMCS_GUEST_DS_SELECTOR                      0x00000806
#define VMCS_GUEST_FS_SELECTOR                      0x00000808
#define VMCS_GUEST_GS_SELECTOR                      0x0000080A
#define VMCS_GUEST_LDTR_SELECTOR                    0x0000080C
#define VMCS_GUEST_TR_SELECTOR                      0x0000080E

/* 16-bit Host State Fields */
#define VMCS_HOST_ES_SELECTOR                       0x00000C00
#define VMCS_HOST_CS_SELECTOR                       0x00000C02
#define VMCS_HOST_SS_SELECTOR                       0x00000C04
#define VMCS_HOST_DS_SELECTOR                       0x00000C06
#define VMCS_HOST_FS_SELECTOR                       0x00000C08
#define VMCS_HOST_GS_SELECTOR                       0x00000C0A
#define VMCS_HOST_TR_SELECTOR                       0x00000C0C

/* 64-bit Control Fields */
#define VMCS_CTRL_MSR_BITMAP_ADDR                   0x00002004
#define VMCS_CTRL_TSC_OFFSET                        0x00002010
#define VMCS_CTRL_VMFUNC_CTLS                       0x00002018
#define VMCS_CTRL_EPTP                              0x0000201A
#define VMCS_CTRL_EPTP_LIST_ADDR                    0x00002024
#define VMCS_CTRL_VIRT_EXCEPTION_INFO_ADDR          0x0000202A

/* 64-bit Guest State Fields */
#define VMCS_GUEST_VMCS_LINK_PTR                    0x00002800
#define VMCS_GUEST_IA32_DEBUGCTL                    0x00002802
#define VMCS_GUEST_IA32_EFER                        0x00002806

/* 64-bit Host State Fields */
#define VMCS_HOST_IA32_PAT                          0x00002C00
#define VMCS_HOST_IA32_EFER                         0x00002C02

/* 32-bit Control Fields */
#define VMCS_CTRL_PIN_BASED_EXEC                    0x00004000
#define VMCS_CTRL_PROC_BASED_EXEC                   0x00004002
#define VMCS_CTRL_EXCEPTION_BITMAP                  0x00004004
#define VMCS_CTRL_CR3_TARGET_COUNT                  0x0000400A
#define VMCS_CTRL_VMEXIT_CONTROLS                   0x0000400C
#define VMCS_CTRL_VMEXIT_MSR_STORE_COUNT            0x0000400E
#define VMCS_CTRL_VMEXIT_MSR_LOAD_COUNT             0x00004010
#define VMCS_CTRL_VMENTRY_CONTROLS                  0x00004012
#define VMCS_CTRL_VMENTRY_MSR_LOAD_COUNT            0x00004014
#define VMCS_CTRL_VMENTRY_INTERRUPTION_INFO         0x00004016
#define VMCS_CTRL_VMENTRY_EXCEPTION_ERROR           0x00004018
#define VMCS_CTRL_VMENTRY_INSTRUCTION_LEN           0x0000401A
#define VMCS_CTRL_PROC_BASED_EXEC2                  0x0000401E

/* 64-bit Read-Only Fields */
#define VMCS_RO_GUEST_PHYSICAL_ADDR                 0x00002400

/* 32-bit Read-Only Fields */
#define VMCS_RO_VM_INSTRUCTION_ERROR                0x00004400
#define VMCS_RO_EXIT_REASON                         0x00004402
#define VMCS_RO_VMEXIT_INTERRUPTION_INFO            0x00004404
#define VMCS_RO_VMEXIT_INTERRUPTION_ERROR           0x00004406
#define VMCS_RO_IDT_VECTORING_INFO                  0x00004408
#define VMCS_RO_IDT_VECTORING_ERROR                 0x0000440A
#define VMCS_RO_VMEXIT_INSTRUCTION_LEN              0x0000440C
#define VMCS_RO_VMEXIT_INSTRUCTION_INFO             0x0000440E

/* 32-bit Guest State Fields */
#define VMCS_GUEST_ES_LIMIT                         0x00004800
#define VMCS_GUEST_CS_LIMIT                         0x00004802
#define VMCS_GUEST_SS_LIMIT                         0x00004804
#define VMCS_GUEST_DS_LIMIT                         0x00004806
#define VMCS_GUEST_FS_LIMIT                         0x00004808
#define VMCS_GUEST_GS_LIMIT                         0x0000480A
#define VMCS_GUEST_LDTR_LIMIT                       0x0000480C
#define VMCS_GUEST_TR_LIMIT                         0x0000480E
#define VMCS_GUEST_GDTR_LIMIT                       0x00004810
#define VMCS_GUEST_IDTR_LIMIT                       0x00004812
#define VMCS_GUEST_ES_ACCESS_RIGHTS                 0x00004814
#define VMCS_GUEST_CS_ACCESS_RIGHTS                 0x00004816
#define VMCS_GUEST_SS_ACCESS_RIGHTS                 0x00004818
#define VMCS_GUEST_DS_ACCESS_RIGHTS                 0x0000481A
#define VMCS_GUEST_FS_ACCESS_RIGHTS                 0x0000481C
#define VMCS_GUEST_GS_ACCESS_RIGHTS                 0x0000481E
#define VMCS_GUEST_LDTR_ACCESS_RIGHTS               0x00004820
#define VMCS_GUEST_TR_ACCESS_RIGHTS                 0x00004822
#define VMCS_GUEST_INTERRUPTIBILITY_STATE           0x00004824
#define VMCS_GUEST_ACTIVITY_STATE                   0x00004826
#define VMCS_GUEST_SMBASE                           0x00004828
#define VMCS_GUEST_IA32_SYSENTER_CS                 0x0000482A
#define VMCS_GUEST_VMX_PREEMPTION_TIMER             0x0000482E

/* Natural-Width Control Fields */
#define VMCS_CTRL_CR0_GUEST_HOST_MASK               0x00006000
#define VMCS_CTRL_CR4_GUEST_HOST_MASK               0x00006002
#define VMCS_CTRL_CR0_READ_SHADOW                   0x00006004
#define VMCS_CTRL_CR4_READ_SHADOW                   0x00006006

/* Natural-Width Read-Only Fields */
#define VMCS_RO_EXIT_QUALIFICATION                  0x00006400
#define VMCS_RO_GUEST_LINEAR_ADDR                   0x0000640A

/* Natural-Width Guest State Fields */
#define VMCS_GUEST_CR0                              0x00006800
#define VMCS_GUEST_CR3                              0x00006802
#define VMCS_GUEST_CR4                              0x00006804
#define VMCS_GUEST_ES_BASE                          0x00006806
#define VMCS_GUEST_CS_BASE                          0x00006808
#define VMCS_GUEST_SS_BASE                          0x0000680A
#define VMCS_GUEST_DS_BASE                          0x0000680C
#define VMCS_GUEST_FS_BASE                          0x0000680E
#define VMCS_GUEST_GS_BASE                          0x00006810
#define VMCS_GUEST_LDTR_BASE                        0x00006812
#define VMCS_GUEST_TR_BASE                          0x00006814
#define VMCS_GUEST_GDTR_BASE                        0x00006816
#define VMCS_GUEST_IDTR_BASE                        0x00006818
#define VMCS_GUEST_DR7                              0x0000681A
#define VMCS_GUEST_RSP                              0x0000681C
#define VMCS_GUEST_RIP                              0x0000681E
#define VMCS_GUEST_RFLAGS                           0x00006820
#define VMCS_GUEST_PENDING_DBG_EXCEPTIONS           0x00006822
#define VMCS_GUEST_IA32_SYSENTER_ESP                0x00006824
#define VMCS_GUEST_IA32_SYSENTER_EIP                0x00006826

/* Natural-Width Host State Fields */
#define VMCS_HOST_CR0                               0x00006C00
#define VMCS_HOST_CR3                               0x00006C02
#define VMCS_HOST_CR4                               0x00006C04
#define VMCS_HOST_FS_BASE                           0x00006C06
#define VMCS_HOST_GS_BASE                           0x00006C08
#define VMCS_HOST_TR_BASE                           0x00006C0A
#define VMCS_HOST_GDTR_BASE                         0x00006C0C
#define VMCS_HOST_IDTR_BASE                         0x00006C0E
#define VMCS_HOST_IA32_SYSENTER_ESP                 0x00006C10
#define VMCS_HOST_IA32_SYSENTER_EIP                 0x00006C12
#define VMCS_HOST_RSP                               0x00006C14
#define VMCS_HOST_RIP                               0x00006C16
#define VMCS_HOST_IA32_SYSENTER_CS                  0x00004C00

/* ── VM-Exit Reasons ──────────────────────────────────────────────── */

#define EXIT_REASON_EXCEPTION_NMI                   0
#define EXIT_REASON_EXTERNAL_INTERRUPT              1
#define EXIT_REASON_TRIPLE_FAULT                    2
#define EXIT_REASON_CPUID                           10
#define EXIT_REASON_HLT                             12
#define EXIT_REASON_INVD                            13
#define EXIT_REASON_MWAIT                           36
#define EXIT_REASON_VMCALL                          18
#define EXIT_REASON_VMCLEAR                         19
#define EXIT_REASON_VMLAUNCH                        20
#define EXIT_REASON_VMPTRLD                         21
#define EXIT_REASON_VMPTRST                         22
#define EXIT_REASON_VMREAD                          23
#define EXIT_REASON_VMRESUME                        24
#define EXIT_REASON_VMWRITE                         25
#define EXIT_REASON_VMXOFF                          26
#define EXIT_REASON_VMXON                           27
#define EXIT_REASON_CR_ACCESS                       28
#define EXIT_REASON_DR_ACCESS                       29
#define EXIT_REASON_IO_INSTRUCTION                  30
#define EXIT_REASON_MSR_READ                        31
#define EXIT_REASON_MSR_WRITE                       32
#define EXIT_REASON_MONITOR_TRAP_FLAG               37
#define EXIT_REASON_EPT_VIOLATION                   48
#define EXIT_REASON_EPT_MISCONFIG                   49
#define EXIT_REASON_INVEPT                          50
#define EXIT_REASON_RDTSCP                          51
#define EXIT_REASON_INVVPID                         53
#define EXIT_REASON_XSETBV                          55
#define EXIT_REASON_XSAVES                          63
#define EXIT_REASON_XRSTORS                         64

/* ── CR Access Exit Qualification ─────────────────────────────────── */

#define CR_ACCESS_CR_NUMBER(q)      ((ULONG)((q) & 0xF))
#define CR_ACCESS_TYPE(q)           ((ULONG)(((q) >> 4) & 0x3))
#define CR_ACCESS_REG(q)            ((ULONG)(((q) >> 8) & 0xF))
#define CR_ACCESS_LMSW_SOURCE(q)    ((ULONG)(((q) >> 16) & 0xFFFF))

#define CR_ACCESS_TYPE_MOV_TO_CR    0
#define CR_ACCESS_TYPE_MOV_FROM_CR  1
#define CR_ACCESS_TYPE_CLTS         2
#define CR_ACCESS_TYPE_LMSW         3

/* ── VMX Instruction Result (RFLAGS) ──────────────────────────────── */

#define VMX_OK      0   /* No error */
#define VMX_FAIL_CF 1   /* CF=1: VMCS pointer invalid */
#define VMX_FAIL_ZF 2   /* ZF=1: VMCS error code valid */

/* ── VMCALL Commands ──────────────────────────────────────────────── */

#define VMCALL_PING             0x00000001
#define VMCALL_EPT_REMAP        0x00000002  /* RDX=targetPa, R8=shadowPa */
#define VMCALL_INVEPT           0x00000003  /* Flush EPT TLBs (single-context) */
#define VMCALL_FIFO_TRAP        0x00000004  /* RDX=1 enable, RDX=0 disable */
#define VMCALL_READ_FIFO_LOG    0x00000005  /* RDX=guest VA of buffer, R8=max entries */
#define VMCALL_READ_SYSCALL_LOG 0x00000006  /* RDX=guest VA of buffer, R8=max entries */
/* Magic CPUID leaf for bulk log dump (user-mode → VMX root → memcpy).
 * RAX=leaf, RBX=user buffer VA, RCX=max entries. Returns count in RAX. */
#define CPUID_LEAF_DUMP_LOG     0x4E585443  /* "NXTC" */

#define VMCALL_XCAP_STATUS      0x00000007  /* RAX=CapturedCount */
#define VMCALL_XCAP_READ        0x00000008  /* RDX=buf VA, R8=start idx, R9=max pages */
#define VMCALL_XCAP_SETUP       0x00000009  /* RDX=CR3, R8=VaBase, R9=VaEnd */
#define VMCALL_XCAP_GET_PATABLE 0x0000000A  /* RAX=g_Shv.XcapPaTable kernel VA */
#define VMCALL_XCAP_DIAG        0x0000000B  /* RDX=which (0=trapped 1=noPa 2=noSplit 3=violation 4=wrongCr3) → RAX */
#define VMCALL_XCAP_GET_CFG     0x0000000C  /* RAX=XCAP_MAX_PAGES (so caller can size walks) */

/* HV-quality dump — EPT-level physical page read (bypasses paged VA layer).
 * Used by the NexusCore kernel dispatcher to produce race-free captures
 * of self-modifying binaries (Themida-style packers in particular).
 * See docs/kernel_evolution/the design notes for the full pipeline.
 *   RDX = guest physical address (page-aligned)
 *   R8  = destination kernel VA (must be present, 4 KB writable)
 *   RAX = STATUS_SUCCESS / STATUS_IO_DEVICE_ERROR / STATUS_INVALID_ADDRESS */
#define VMCALL_EPT_READ_PAGE    0x0000000D

/* Cipher record dump: RDX=kernel-buf VA, R8=max records, R9=start_idx → RAX=count copied */
#define VMCALL_CIPHER_DUMP_LOG  0x0000000E

#define VMCALL_DEVIRTUALIZE     0xDEADBEEF
#define VMCALL_MAGIC_COOKIE     0x5348564DUL    /* "SHVM" */
#define VMCALL_PING_RESPONSE    0x48565F4F4BUL  /* "HV_OK" */

/* ── VMX Region ───────────────────────────────────────────────────── */

typedef struct _VMX_REGION {
    ULONG32 RevisionId;
    ULONG32 AbortIndicator;
    UCHAR   Data[4096 - 8];
} VMX_REGION, *PVMX_REGION;

C_ASSERT(sizeof(VMX_REGION) == 4096);
