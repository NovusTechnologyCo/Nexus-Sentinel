// <file>
// <summary>
// P/Invoke bindings for memory page protection operations. Query and modify page
// protection attributes (read/write/execute), set guard pages, and analyze memory
// region protection maps.
// </summary>
// </file>

using System.Runtime.InteropServices;

namespace Nexus.UI.Interop;

public static partial class NexusEngine
{
    #region Page Protection Access

    /// <summary>
    /// Get page protection for address.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PageGetProtection(
        IntPtr processHandle,
        ulong address,
        out NexusPageProtection protection);

    /// <summary>
    /// Get page protection as string.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PageGetProtectionString(
        IntPtr processHandle,
        ulong address,
        [Out, MarshalAs(UnmanagedType.LPStr)] System.Text.StringBuilder protString,
        nuint protStringSize);

    /// <summary>
    /// Get detailed page information.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PageGetInfo(
        IntPtr processHandle,
        ulong address,
        out NexusPageInfo pageInfo);

    /// <summary>
    /// Get pages in address range.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PageGetRange(
        IntPtr processHandle,
        ulong startAddress,
        ulong endAddress,
        [In, Out] NexusPageInfo[]? buffer,
        nuint bufferCount,
        out nuint count);

    #endregion

    #region Page Protection Modification

    /// <summary>
    /// Set page protection.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PageSetProtection(
        IntPtr processHandle,
        ulong address,
        nuint size,
        NexusPageProtection newProtection,
        out NexusPageProtection oldProtection);

    /// <summary>
    /// Make page executable.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PageMakeExecutable(
        IntPtr processHandle,
        ulong address,
        nuint size);

    /// <summary>
    /// Make page writable.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PageMakeWritable(
        IntPtr processHandle,
        ulong address,
        nuint size);

    /// <summary>
    /// Make page read-only.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PageMakeReadOnly(
        IntPtr processHandle,
        ulong address,
        nuint size);

    /// <summary>
    /// Remove all protection (PAGE_EXECUTE_READWRITE).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PageMakeFullAccess(
        IntPtr processHandle,
        ulong address,
        nuint size);

    /// <summary>
    /// Set PAGE_GUARD on page.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PageSetGuard(
        IntPtr processHandle,
        ulong address,
        nuint size);

    /// <summary>
    /// Remove PAGE_GUARD from page.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PageRemoveGuard(
        IntPtr processHandle,
        ulong address,
        nuint size);

    #endregion

    #region Page Analysis

    /// <summary>
    /// Find pages with specific protection.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PageFindByProtection(
        IntPtr processHandle,
        NexusPageProtection protection,
        [In, Out] NexusPageInfo[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Find executable pages.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PageFindExecutable(
        IntPtr processHandle,
        [In, Out] NexusPageInfo[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Find writable+executable pages (RWX).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PageFindRwx(
        IntPtr processHandle,
        [In, Out] NexusPageInfo[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Get page statistics for process.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PageGetStats(
        IntPtr processHandle,
        out NexusPageStats stats);

    /// <summary>
    /// Check if address is readable.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PageIsReadable(
        IntPtr processHandle,
        ulong address,
        out uint isReadable);

    /// <summary>
    /// Check if address is writable.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PageIsWritable(
        IntPtr processHandle,
        ulong address,
        out uint isWritable);

    /// <summary>
    /// Check if address is executable.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PageIsExecutable(
        IntPtr processHandle,
        ulong address,
        out uint isExecutable);

    #endregion

    #region Memory Protection Events

    /// <summary>
    /// Set callback for page protection changes.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PageSetChangeCallback(
        IntPtr debuggerHandle,
        NexusPageChangeCallback? callback);

    /// <summary>
    /// Monitor page protection changes in range.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PageMonitorRange(
        IntPtr debuggerHandle,
        ulong startAddress,
        ulong endAddress,
        out uint monitorId);

    /// <summary>
    /// Stop monitoring page protection.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PageStopMonitor(
        IntPtr debuggerHandle,
        uint monitorId);

    #endregion

    #region Working Set

    /// <summary>
    /// Get working set information.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PageGetWorkingSet(
        IntPtr processHandle,
        [In, Out] NexusWorkingSetPage[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Get working set statistics.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PageGetWorkingSetStats(
        IntPtr processHandle,
        out NexusWorkingSetStats stats);

    /// <summary>
    /// Check if page is in working set.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PageIsInWorkingSet(
        IntPtr processHandle,
        ulong address,
        out uint isInWorkingSet);

    /// <summary>
    /// Lock pages in working set.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PageLock(
        IntPtr processHandle,
        ulong address,
        nuint size);

    /// <summary>
    /// Unlock pages from working set.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PageUnlock(
        IntPtr processHandle,
        ulong address,
        nuint size);

    #endregion

    #region DEP/NX

    /// <summary>
    /// Check if DEP is enabled for process.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PageGetDepPolicy(
        IntPtr processHandle,
        out uint depEnabled,
        out uint permanentDep);

    /// <summary>
    /// Set DEP policy for process (if allowed).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PageSetDepPolicy(
        IntPtr processHandle,
        uint enable);

    /// <summary>
    /// Add DEP exception for address range.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PageAddDepException(
        IntPtr processHandle,
        ulong address,
        nuint size);

    #endregion
}

#region Page Protection Enums and Structs

/// <summary>
/// Page protection flags.
/// </summary>
[Flags]
public enum NexusPageProtection : uint
{
    NoAccess = 0x01,
    ReadOnly = 0x02,
    ReadWrite = 0x04,
    WriteCopy = 0x08,
    Execute = 0x10,
    ExecuteRead = 0x20,
    ExecuteReadWrite = 0x40,
    ExecuteWriteCopy = 0x80,
    Guard = 0x100,
    NoCache = 0x200,
    WriteCombine = 0x400,
    TargetsInvalid = 0x40000000,
    TargetsNoUpdate = 0x40000000
}

/// <summary>
/// Memory state.
/// </summary>
public enum NexusMemoryState : uint
{
    Commit = 0x1000,
    Reserve = 0x2000,
    Free = 0x10000
}

/// <summary>
/// Memory type.
/// </summary>
public enum NexusMemoryType : uint
{
    Private = 0x20000,
    Mapped = 0x40000,
    Image = 0x1000000
}

/// <summary>
/// Page information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusPageInfo
{
    public ulong BaseAddress;           // Page base address
    public ulong AllocationBase;        // Allocation base
    public NexusPageProtection AllocationProtect; // Initial protection
    public nuint RegionSize;            // Region size
    public NexusMemoryState State;      // Commit/reserve/free
    public NexusPageProtection Protect; // Current protection
    public NexusMemoryType Type;        // Private/mapped/image
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string ModuleName;           // Module (if image)
    public uint PartitionId;            // Partition ID
}

/// <summary>
/// Page statistics.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusPageStats
{
    public nuint TotalVirtualSize;      // Total virtual size
    public nuint CommittedSize;         // Committed memory
    public nuint ReservedSize;          // Reserved memory
    public nuint FreeSize;              // Free space
    public nuint PrivateSize;           // Private pages
    public nuint MappedSize;            // Mapped pages
    public nuint ImageSize;             // Image pages
    public uint ExecutablePages;        // Pages with execute
    public uint WritablePages;          // Pages with write
    public uint RwxPages;               // Pages with RWX
    public uint GuardedPages;           // Pages with guard
    public uint RegionCount;            // Number of regions
}

/// <summary>
/// Working set page entry.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusWorkingSetPage
{
    public ulong VirtualAddress;        // Virtual address
    public ulong PhysicalAddress;       // Physical address (if available)
    public NexusPageProtection Protection; // Page protection
    public uint ShareCount;             // Share count
    public uint IsShared;               // Is shared page
    public uint IsModified;             // Page modified (dirty)
    public uint IsLocked;               // Page locked
    public uint WsIndex;                // Working set index
}

/// <summary>
/// Working set statistics.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusWorkingSetStats
{
    public nuint WorkingSetSize;        // Current working set
    public nuint PeakWorkingSetSize;    // Peak working set
    public nuint MinimumWorkingSet;     // Minimum allowed
    public nuint MaximumWorkingSet;     // Maximum allowed
    public uint PageFaultCount;         // Page faults
    public nuint SharedWorkingSet;      // Shared pages size
    public nuint PrivateWorkingSet;     // Private pages size
    public uint PageCount;              // Total page count
    public uint SharedPageCount;        // Shared page count
    public uint PrivatePageCount;       // Private page count
}

/// <summary>
/// Page change callback delegate.
/// </summary>
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate void NexusPageChangeCallback(
    ulong address,
    nuint size,
    NexusPageProtection oldProtection,
    NexusPageProtection newProtection);

#endregion
