// <file>
// <summary>
// P/Invoke bindings for window and heap enumeration. List windows owned by a process,
// enumerate heap allocations and segments, and query GDI/USER object handles for
// resource leak detection and analysis.
// </summary>
// </file>

using System.Runtime.InteropServices;

namespace Nexus.UI.Interop;

public static partial class NexusEngine
{
    #region Window Enumeration

    /// <summary>
    /// Enumerate windows for a process.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_WindowEnumerate(
        uint processId,
        [In, Out] NexusWindowInfo[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Enumerate all windows on the system.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_WindowEnumerateAll(
        [In, Out] NexusWindowInfo[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Enumerate child windows.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_WindowEnumerateChildren(
        ulong parentHandle,
        [In, Out] NexusWindowInfo[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Get window information by handle.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_WindowGetInfo(
        ulong windowHandle,
        out NexusWindowInfo windowInfo);

    /// <summary>
    /// Find window by title.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_WindowFindByTitle(
        string title,
        uint exactMatch,
        [In, Out] NexusWindowInfo[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Find window by class name.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_WindowFindByClass(
        string className,
        [In, Out] NexusWindowInfo[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Get window tree (parent/child hierarchy).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_WindowGetTree(
        ulong rootHandle,
        [In, Out] NexusWindowTreeNode[]? buffer,
        nuint bufferCount,
        out nuint count);

    #endregion

    #region Window Manipulation

    /// <summary>
    /// Get window text.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_WindowGetText(
        ulong windowHandle,
        [Out, MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder text,
        nuint textSize);

    /// <summary>
    /// Set window text.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_WindowSetText(
        ulong windowHandle,
        string text);

    /// <summary>
    /// Get window position and size.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_WindowGetRect(
        ulong windowHandle,
        out NexusRect rect);

    /// <summary>
    /// Set window position and size.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_WindowSetRect(
        ulong windowHandle,
        ref NexusRect rect);

    /// <summary>
    /// Get window style flags.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_WindowGetStyle(
        ulong windowHandle,
        out uint style,
        out uint exStyle);

    /// <summary>
    /// Set window visibility.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_WindowSetVisible(
        ulong windowHandle,
        uint visible);

    /// <summary>
    /// Get window procedure address.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_WindowGetProc(
        ulong windowHandle,
        out ulong wndProcAddress);

    #endregion

    #region Heap Enumeration

    /// <summary>
    /// Enumerate heaps in a process.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HeapEnumerate(
        IntPtr processHandle,
        [In, Out] NexusHeapInfo[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Get heap information.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HeapGetInfo(
        IntPtr processHandle,
        ulong heapHandle,
        out NexusHeapInfo heapInfo);

    /// <summary>
    /// Enumerate heap blocks.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HeapEnumerateBlocks(
        IntPtr processHandle,
        ulong heapHandle,
        [In, Out] NexusHeapBlock[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Get heap block containing address.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HeapGetBlockAt(
        IntPtr processHandle,
        ulong address,
        out NexusHeapBlock block);

    /// <summary>
    /// Get heap statistics.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HeapGetStats(
        IntPtr processHandle,
        out NexusHeapStats stats);

    /// <summary>
    /// Validate heap integrity.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HeapValidate(
        IntPtr processHandle,
        ulong heapHandle,
        out uint isValid,
        [In, Out] NexusHeapCorruption[]? corruptionBuffer,
        nuint bufferCount,
        out nuint corruptionCount);

    /// <summary>
    /// Find heap allocations by size.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HeapFindBySize(
        IntPtr processHandle,
        nuint minSize,
        nuint maxSize,
        [In, Out] NexusHeapBlock[]? buffer,
        nuint bufferCount,
        out nuint count);

    #endregion

    #region GDI Object Enumeration

    /// <summary>
    /// Enumerate GDI objects for a process.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_GdiEnumerate(
        uint processId,
        [In, Out] NexusGdiObject[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Get GDI object counts.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_GdiGetCounts(
        uint processId,
        out NexusGdiCounts counts);

    /// <summary>
    /// Get USER object counts.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_UserGetCounts(
        uint processId,
        out NexusUserCounts counts);

    #endregion

    #region Timer Enumeration

    /// <summary>
    /// Enumerate timers for a window.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_TimerEnumerate(
        ulong windowHandle,
        [In, Out] NexusTimerInfo[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Enumerate all timers for a process.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_TimerEnumerateProcess(
        uint processId,
        [In, Out] NexusTimerInfo[]? buffer,
        nuint bufferCount,
        out nuint count);

    #endregion
}

#region Window/Heap Enums and Structs

/// <summary>
/// Window information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusWindowInfo
{
    public ulong Handle;                // Window handle
    public ulong ParentHandle;          // Parent window
    public ulong OwnerHandle;           // Owner window
    public uint ProcessId;              // Owning process
    public uint ThreadId;               // Owning thread
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string Title;                // Window title
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
    public string ClassName;            // Window class
    public NexusRect Rect;              // Position and size
    public uint Style;                  // Window style
    public uint ExStyle;                // Extended style
    public uint IsVisible;              // Is visible
    public uint IsEnabled;              // Is enabled
    public uint IsUnicode;              // Unicode window
    public ulong WndProcAddress;        // Window procedure
}

/// <summary>
/// Rectangle structure.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusRect
{
    public int Left;
    public int Top;
    public int Right;
    public int Bottom;

    public int Width => Right - Left;
    public int Height => Bottom - Top;
}

/// <summary>
/// Window tree node.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusWindowTreeNode
{
    public ulong Handle;                // Window handle
    public ulong ParentHandle;          // Parent handle
    public uint Depth;                  // Tree depth
    public uint ChildCount;             // Number of children
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
    public string ClassName;            // Window class
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
    public string Title;                // Window title (truncated)
}

/// <summary>
/// Heap information.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusHeapInfo
{
    public ulong Handle;                // Heap handle
    public ulong BaseAddress;           // Heap base address
    public nuint CommittedSize;         // Committed memory
    public nuint ReservedSize;          // Reserved memory
    public nuint AllocatedSize;         // Allocated bytes
    public uint BlockCount;             // Number of blocks
    public uint FreeBlockCount;         // Free blocks
    public uint Flags;                  // Heap flags
    public uint IsProcessHeap;          // Is default process heap
    public uint IsLfhEnabled;           // Low Fragmentation Heap
    public uint ClassNumber;            // Heap class
}

/// <summary>
/// Heap block information.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusHeapBlock
{
    public ulong Address;               // Block address
    public nuint Size;                  // Block size
    public nuint RequestedSize;         // Requested allocation size
    public uint IsAllocated;            // Is allocated (not free)
    public uint IsMoveable;             // Is moveable
    public uint Flags;                  // Block flags
    public ulong HeapHandle;            // Parent heap
    public uint SegmentIndex;           // Heap segment
}

/// <summary>
/// Heap corruption information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusHeapCorruption
{
    public ulong Address;               // Corruption address
    public uint Type;                   // Corruption type
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string Description;          // Description
    public ulong ExpectedValue;         // Expected value
    public ulong ActualValue;           // Actual value
}

/// <summary>
/// Heap statistics.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusHeapStats
{
    public uint HeapCount;              // Number of heaps
    public nuint TotalCommitted;        // Total committed
    public nuint TotalReserved;         // Total reserved
    public nuint TotalAllocated;        // Total allocated
    public nuint TotalFree;             // Total free
    public uint TotalBlocks;            // Total blocks
    public uint TotalFreeBlocks;        // Total free blocks
    public nuint LargestFreeBlock;      // Largest free block
    public double FragmentationRatio;   // Fragmentation ratio
}

/// <summary>
/// GDI object information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusGdiObject
{
    public ulong Handle;                // GDI handle
    public uint Type;                   // Object type
    public uint OwnerPid;               // Owner process
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
    public string TypeName;             // Type name
    public ulong KernelAddress;         // Kernel address
}

/// <summary>
/// GDI object counts.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusGdiCounts
{
    public uint Total;                  // Total GDI objects
    public uint Dc;                     // Device contexts
    public uint Region;                 // Regions
    public uint Bitmap;                 // Bitmaps
    public uint Palette;                // Palettes
    public uint Font;                   // Fonts
    public uint Brush;                  // Brushes
    public uint Pen;                    // Pens
    public uint ExtPen;                 // Extended pens
    public uint Other;                  // Other types
}

/// <summary>
/// USER object counts.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusUserCounts
{
    public uint Total;                  // Total USER objects
    public uint Windows;                // Windows
    public uint Menus;                  // Menus
    public uint Cursors;                // Cursors
    public uint Icons;                  // Icons
    public uint Hooks;                  // Hooks
    public uint Accelerators;           // Accelerator tables
    public uint DeferWindowPos;         // Deferred window positions
}

/// <summary>
/// Timer information.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusTimerInfo
{
    public ulong TimerId;               // Timer ID
    public ulong WindowHandle;          // Associated window
    public uint Interval;               // Timer interval (ms)
    public ulong CallbackAddress;       // Timer callback
    public uint IsActive;               // Timer is active
    public ulong LastFired;             // Last fire time
    public uint FireCount;              // Times fired
}

#endregion
