/**
 * @file platform_nt.c
 * @brief Windows kernel (NT) platform implementation for contiguous memory allocation.
 *
 * Provides the NT-specific implementation of ShvAllocateContiguousMemory and
 * ShvFreeContiguousMemory, which are used to allocate physically contiguous
 * memory for VCPU_DATA structures and EPT_STATE.
 *
 * VMX requires several data structures to reside in physically contiguous,
 * page-aligned memory:
 *   - VMXON region (4KB, 4KB-aligned physical address)
 *   - VMCS region (4KB, 4KB-aligned physical address)
 *   - MSR bitmap (4KB, 4KB-aligned physical address)
 *   - EPT page tables (4KB-aligned physical addresses for all levels)
 *
 * MmAllocateContiguousMemorySpecifyCache is used with MmCached type and
 * no alignment boundary constraint. The allocated memory is zero-initialized
 * before return.
 *
 * This file is only compiled for Type 2 (SHV_PLATFORM_NT) builds. The UEFI
 * platform uses EfiRuntimeServicesData allocations via gBS->AllocatePages.
 */

#include "shv.h"
#include <stdarg.h>   /* va_list/va_start/va_end -- SHV had no varargs user before ShvLogWrite,
                       * so nothing pulled this in and they linked as externals (LNK2019). */

/* ntoskrnl exports _vsnprintf; use it directly rather than <ntstrsafe.h>, whose
 * inline variant drags in the user-mode CRT (__stdio_common_vsprintf -> LNK2019)
 * unless NTSTRSAFE_LIB + ntstrsafe.lib are wired up. This keeps SentinelHV free
 * of extra link deps. Note _vsnprintf does NOT guarantee NUL-termination on
 * truncation, so we terminate the buffer ourselves below. */
_Success_(return >= 0)
NTSYSAPI int __cdecl _vsnprintf(_Out_writes_(_Count) char* _Buf, _In_ size_t _Count,
                                _In_z_ const char* _Format, va_list _ArgList);

/* ── SHV log ring writer  ──────────────────────────────
 *
 * Every SHV_LOG/SHV_WARN/SHV_ERR routes here (see shv_platform.h). We do two
 * things: the original DbgPrintEx (behaviour unchanged), and a copy into
 * g_Shv.ShvLogRing so `NexusDSEFix --shv-log` can dump ONLY SentinelHV output
 * to console or a file.
 *
 * Why: diagnosing the exec-trap chain required finding 4 relevant
 * lines inside hundreds of unrelated kernel prints (NexusCore TPM retries, Intel
 * XTU, Edge) in DebugView. A hypervisor diagnostic that can only be read through
 * DebugView, mixed with everyone else's spam, is not a usable diagnostic.
 *
 * IRQL: called from VMX-root as well as PASSIVE. DbgPrintEx was already being
 * called from those paths, so that is not new risk. RtlStringCchVPrintfA does no
 * allocation and touches only non-paged memory (g_Shv is non-paged; format
 * strings are .rdata literals), so it is safe at any IRQL here.
 *
 * Lock-free: InterlockedIncrement hands each writer a unique monotonic index and
 * it owns slot (idx-1) % SHV_LOG_LINES. A reader can observe a partially written
 * line; acceptable for a diagnostic, and it never blocks or spins in VMX-root.
 */
VOID
ShvLogWrite(
    _In_ ULONG Level,
    _In_ PCSTR Fmt,
    ...
    )
{
    va_list ap;

    va_start(ap, Fmt);
    vDbgPrintEx(DPFLTR_IHVDRIVER_ID, Level, Fmt, ap);
    va_end(ap);

    /* Ring is opt-in: stays inert until DriverEntry stamps the magic, so any
     * logging that happens before/after teardown simply skips it. */
    if (g_Shv.ShvLogMagic != SHV_LOG_MAGIC) {
        return;
    }

    LONG next = InterlockedIncrement(&g_Shv.ShvLogWriteIdx);
    ULONG slot = ((ULONG)(next - 1)) % SHV_LOG_LINES;

    va_start(ap, Fmt);
    (VOID)_vsnprintf(g_Shv.ShvLogRing[slot], SHV_LOG_LINE_LEN - 1, Fmt, ap);
    va_end(ap);
    g_Shv.ShvLogRing[slot][SHV_LOG_LINE_LEN - 1] = '\0';   /* _vsnprintf may not NUL-terminate */
}

/* ── Contiguous Memory Allocation ─────────────────────────────────── */

/**
 * @brief Allocate physically contiguous, zero-initialized, cached memory.
 *
 * Uses MmAllocateContiguousMemorySpecifyCache with the full physical address
 * range (0 to MAXULONG64) and no alignment boundary. The memory is cached
 * (MmCached) and zero-initialized on success.
 *
 * @param Size  Number of bytes to allocate.
 * @return Virtual address of the allocated memory, or NULL on failure.
 */
PVOID
ShvAllocateContiguousMemory(
    _In_ SIZE_T Size
    )
{
    PHYSICAL_ADDRESS lowest, highest, boundary;

    lowest.QuadPart = 0;
    highest.QuadPart = MAXULONG64;
    boundary.QuadPart = 0;    /* No alignment boundary requirement */

    PVOID mem = MmAllocateContiguousMemorySpecifyCache(
        Size,
        lowest,
        highest,
        boundary,
        MmCached
    );

    if (mem) {
        RtlZeroMemory(mem, Size);
    }

    return mem;
}

/**
 * @brief Free physically contiguous memory allocated by ShvAllocateContiguousMemory.
 *
 * Calls MmFreeContiguousMemory to release the allocation. The Size parameter
 * is accepted for API symmetry but is not used by MmFreeContiguousMemory
 * (the allocation size is tracked internally by the memory manager).
 *
 * @param Address  Virtual address returned by ShvAllocateContiguousMemory.
 * @param Size     Original allocation size (unused by NT implementation).
 */
void
ShvFreeContiguousMemory(
    _In_ PVOID Address,
    _In_ SIZE_T Size
    )
{
    UNREFERENCED_PARAMETER(Size);

    if (Address) {
        MmFreeContiguousMemory(Address);
    }
}
