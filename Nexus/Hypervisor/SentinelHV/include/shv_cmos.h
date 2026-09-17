/**
 * @file shv_cmos.h
 * @brief CMOS NVRAM diagnostic subsystem for post-mortem hypervisor debugging.
 *
 * Uses STANDARD CMOS bank (ports 0x70/0x71) at addresses 0x40-0x6F.
 * Extended CMOS (0x72/0x73 for 0x80+) does NOT work on Arrow Lake PCH.
 *
 * CMOS layout (48 bytes at 0x40-0x6F):
 *   0x40        Progress byte (init phase / milestone)
 *   0x41-0x42   Total exit count (16-bit LE)
 *   0x43        Last exit reason (basic, 8-bit)
 *   0x44        CPU index being tracked
 *   0x45        VMLAUNCH attempt count
 *   0x46        HLT exit count (8-bit, saturating)
 *   0x47        CPUID exit count (8-bit, saturating)
 *   0x48-0x4F   First 8 exit reasons (filled once, never overwritten)
 *   0x50        Circular buffer write index (0-7)
 *   0x51-0x58   Last 8 exit reasons (circular buffer)
 *   0x59        Fatal error indicator
 *   0x5A-0x5D   Last guest RIP (low 32 bits, LE)
 *   0x5E-0x5F   Last exit reason (16-bit, for reasons > 255)
 *   0x60-0x63   Last exit qualification (32-bit LE)
 *   0x64        First-exit buffer fill count (0-8)
 *   0x65-0x66   VMCS instruction error (16-bit LE)
 *   0x67        Active processor count at init
 *   0x68-0x6B   Successful virtualization bitmask (bits 0-31)
 *   0x6C        Unhandled exit count
 *   0x6D        IPI failure bitmask (bits 0-7)
 *   0x6E-0x6F   Reserved
 */

#pragma once

#include <intrin.h>

/*
 * Force intrinsic expansion of CLI/STI even in Debug builds where /Oi is off.
 * Without this pragma, Debug builds degrade _disable/_enable to CRT calls
 * that are not linked in kernel-mode drivers, producing:
 *   error LNK2019: unresolved external symbol _disable referenced in ShvCmosWrite
 */
#pragma intrinsic(_disable, _enable)

/* CMOS I/O ports — standard bank only (0x70/0x71) */
#define SHV_CMOS_INDEX      0x70
#define SHV_CMOS_DATA       0x71

/* CMOS address range for SentinelHV diagnostics (standard bank 0x40-0x6F) */
#define SHV_CMOS_BASE       0x40
#define SHV_CMOS_PROGRESS   0x40
#define SHV_CMOS_EXIT_LO    0x41
#define SHV_CMOS_EXIT_HI    0x42
#define SHV_CMOS_LAST_RSN   0x43
#define SHV_CMOS_CPU_IDX    0x44
#define SHV_CMOS_LAUNCH_CNT 0x45
#define SHV_CMOS_HLT_CNT    0x46
#define SHV_CMOS_CPUID_CNT  0x47
#define SHV_CMOS_FIRST_BASE 0x48  /* 0x48-0x4F: first 8 exits */
#define SHV_CMOS_CIRC_IDX   0x50
#define SHV_CMOS_CIRC_BASE  0x51  /* 0x51-0x58: circular buffer */
#define SHV_CMOS_FATAL      0x59
#define SHV_CMOS_RIP0       0x5A
#define SHV_CMOS_RIP1       0x5B
#define SHV_CMOS_RIP2       0x5C
#define SHV_CMOS_RIP3       0x5D
#define SHV_CMOS_RSN16_LO   0x5E
#define SHV_CMOS_RSN16_HI   0x5F
#define SHV_CMOS_QUAL0      0x60
#define SHV_CMOS_QUAL1      0x61
#define SHV_CMOS_QUAL2      0x62
#define SHV_CMOS_QUAL3      0x63
#define SHV_CMOS_FIRST_FILL 0x64
#define SHV_CMOS_VMERR_LO   0x65
#define SHV_CMOS_VMERR_HI   0x66
#define SHV_CMOS_CPU_COUNT  0x67
#define SHV_CMOS_ACTIVE0    0x68
#define SHV_CMOS_ACTIVE1    0x69
#define SHV_CMOS_ACTIVE2    0x6A
#define SHV_CMOS_ACTIVE3    0x6B
#define SHV_CMOS_UNHANDLED  0x6C
#define SHV_CMOS_IPI_FAIL   0x6D
/* Dedicated slot for the #VE-install experiment phase markers (item #14).
 * Battery-backed — survives BSOD + reboot. Read via DXE-side CMOS access. */
#define SHV_CMOS_VE_EXP             0x6E

#define SHV_CMOS_VE_EXP_AFTER_SIDT  0xC1   /* SIDT + IDT[20] read complete */
#define SHV_CMOS_VE_EXP_AFTER_ALLOC 0xC2   /* Pool page allocated, stub written */
#define SHV_CMOS_VE_EXP_AFTER_PATCH 0xC3   /* IDT[20] patched (install complete) */
#define SHV_CMOS_VE_EXP_FAIL        0xCF   /* Failure path (allocation failed) */

/* Progress codes (written to SHV_CMOS_PROGRESS) */
#define SHV_PROG_ENTRY          0x01  /* DriverEntry started */
#define SHV_PROG_VMX_OK         0x02  /* VMX supported and enabled */
#define SHV_PROG_VCPU_ALLOC     0x03  /* VCPU array allocated */
#define SHV_PROG_EPT_INIT       0x04  /* EPT initialized */
#define SHV_PROG_IPI_DISPATCH   0x05  /* IPI dispatched to all CPUs */
#define SHV_PROG_RUNNING        0x06  /* All CPUs virtualized, HV active */
#define SHV_PROG_UNLOADING      0xF0  /* Unload in progress */
#define SHV_PROG_CLEAN          0x00  /* Clean shutdown (cleared on unload) */

/* Per-CPU progress (OR'd with CPU index in low nibble) */
#define SHV_PROG_CPU_VMXON      0x10  /* VMXON on CPU N */
#define SHV_PROG_CPU_VMCS       0x20  /* VMCS setup on CPU N */
#define SHV_PROG_CPU_LAUNCH     0x30  /* VMLAUNCH on CPU N */
#define SHV_PROG_CPU_GUEST      0x40  /* Running as guest on CPU N */

/* Deferred-init progress codes (manual map path) */
#define SHV_PROG_DEFERRED_START   0x55  /* Manual map: deferred thread started */
#define SHV_PROG_DEFERRED_THREAD  0x56  /* Manual map: deferred thread created */
#define SHV_PROG_DEFERRED_VMX_OK  0x57  /* Deferred: VMX support confirmed */

/* Fatal error codes (written to SHV_CMOS_FATAL) */
#define SHV_FATAL_NONE          0x00
#define SHV_FATAL_LAUNCH_FAIL   0xFF
#define SHV_FATAL_UNHANDLED     0xAA
#define SHV_FATAL_TRIPLE        0xEE

/* ── Inline helpers ────────────────────────────────────────────────── */

/**
 * @brief Write a single byte to CMOS NVRAM via standard bank (0x70/0x71).
 * Disables interrupts to prevent HAL RTC driver from changing the index
 * register between our index write and data write.
 */
static __forceinline void
ShvCmosWrite(UCHAR Addr, UCHAR Value)
{
    unsigned long long flags = __readeflags();
    _disable();
    __outbyte(SHV_CMOS_INDEX, Addr);
    __outbyte(SHV_CMOS_DATA, Value);
    if (flags & 0x200) _enable();
}

/**
 * @brief Read a single byte from CMOS NVRAM via standard bank (0x70/0x71).
 */
static __forceinline UCHAR
ShvCmosRead(UCHAR Addr)
{
    unsigned long long flags = __readeflags();
    _disable();
    __outbyte(SHV_CMOS_INDEX, Addr);
    UCHAR val = __inbyte(SHV_CMOS_DATA);
    if (flags & 0x200) _enable();
    return val;
}

/**
 * @brief Clear the SentinelHV CMOS diagnostic region (0x40-0x6F).
 */
static __forceinline void
ShvCmosClearAll(void)
{
    for (UCHAR a = 0x40; a <= 0x6F; a++) {
        ShvCmosWrite(a, 0);
    }
}

/**
 * @brief Record a VM-exit in the CMOS diagnostic region.
 */
static __forceinline void
ShvCmosLogExit(ULONG32 BasicReason, ULONG64 GuestRip)
{
    /* Increment 16-bit exit counter */
    USHORT cnt = (USHORT)ShvCmosRead(SHV_CMOS_EXIT_LO) |
                 ((USHORT)ShvCmosRead(SHV_CMOS_EXIT_HI) << 8);
    cnt++;
    ShvCmosWrite(SHV_CMOS_EXIT_LO, (UCHAR)cnt);
    ShvCmosWrite(SHV_CMOS_EXIT_HI, (UCHAR)(cnt >> 8));

    /* Last exit reason */
    ShvCmosWrite(SHV_CMOS_LAST_RSN, (UCHAR)BasicReason);

    /* First-8 buffer (write-once) */
    UCHAR fill = ShvCmosRead(SHV_CMOS_FIRST_FILL);
    if (fill < 8) {
        ShvCmosWrite(SHV_CMOS_FIRST_BASE + fill, (UCHAR)BasicReason);
        ShvCmosWrite(SHV_CMOS_FIRST_FILL, fill + 1);
    }

    /* Circular buffer of last 8 */
    UCHAR idx = ShvCmosRead(SHV_CMOS_CIRC_IDX);
    ShvCmosWrite(SHV_CMOS_CIRC_BASE + idx, (UCHAR)BasicReason);
    ShvCmosWrite(SHV_CMOS_CIRC_IDX, (idx + 1) & 0x07);

    /* Guest RIP (low 32 bits) */
    ShvCmosWrite(SHV_CMOS_RIP0, (UCHAR)GuestRip);
    ShvCmosWrite(SHV_CMOS_RIP1, (UCHAR)(GuestRip >> 8));
    ShvCmosWrite(SHV_CMOS_RIP2, (UCHAR)(GuestRip >> 16));
    ShvCmosWrite(SHV_CMOS_RIP3, (UCHAR)(GuestRip >> 24));
}

/**
 * @brief Record a fatal VM-exit event.
 */
static __forceinline void
ShvCmosLogFatal(UCHAR FatalCode, ULONG32 Reason, ULONG64 Qualification, ULONG64 GuestRip)
{
    ShvCmosWrite(SHV_CMOS_FATAL, FatalCode);
    ShvCmosWrite(SHV_CMOS_RSN16_LO, (UCHAR)Reason);
    ShvCmosWrite(SHV_CMOS_RSN16_HI, (UCHAR)(Reason >> 8));
    ShvCmosWrite(SHV_CMOS_QUAL0, (UCHAR)Qualification);
    ShvCmosWrite(SHV_CMOS_QUAL1, (UCHAR)(Qualification >> 8));
    ShvCmosWrite(SHV_CMOS_QUAL2, (UCHAR)(Qualification >> 16));
    ShvCmosWrite(SHV_CMOS_QUAL3, (UCHAR)(Qualification >> 24));
    ShvCmosWrite(SHV_CMOS_RIP0, (UCHAR)GuestRip);
    ShvCmosWrite(SHV_CMOS_RIP1, (UCHAR)(GuestRip >> 8));
    ShvCmosWrite(SHV_CMOS_RIP2, (UCHAR)(GuestRip >> 16));
    ShvCmosWrite(SHV_CMOS_RIP3, (UCHAR)(GuestRip >> 24));

    UCHAR u = ShvCmosRead(SHV_CMOS_UNHANDLED);
    if (u < 0xFF) ShvCmosWrite(SHV_CMOS_UNHANDLED, u + 1);
}
