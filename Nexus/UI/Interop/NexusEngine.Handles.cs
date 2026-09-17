// <file>
// <summary>
// P/Invoke bindings for process handle enumeration and analysis. Lists all open handles
// in a process (files, registry keys, events, mutexes, sections, etc.) with type names,
// object names, and access masks. Supports handle closing and duplication.
// </summary>
// </file>

using System.Runtime.InteropServices;

namespace Nexus.UI.Interop;

public static partial class NexusEngine
{
    #region Handle Enumeration

    /// <summary>
    /// Create a handle enumerator for a process.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HandleEnumCreate(
        IntPtr processHandle,
        out IntPtr enumHandle);

    /// <summary>
    /// Destroy a handle enumerator.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern void Nexus_HandleEnumDestroy(IntPtr enumHandle);

    /// <summary>
    /// Refresh the handle list.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HandleEnumRefresh(IntPtr enumHandle);

    /// <summary>
    /// Get the total number of handles.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HandleEnumGetCount(
        IntPtr enumHandle,
        out nuint count);

    /// <summary>
    /// Get handles by type.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HandleEnumGetByType(
        IntPtr enumHandle,
        NexusHandleType type,
        [In, Out] NexusHandleInfo[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Get all handles.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HandleEnumGetAll(
        IntPtr enumHandle,
        [In, Out] NexusHandleInfo[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Get detailed handle information.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HandleGetInfo(
        IntPtr enumHandle,
        IntPtr handleValue,
        out NexusHandleInfoEx info);

    /// <summary>
    /// Find handles by name pattern.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_HandleFindByName(
        IntPtr enumHandle,
        string pattern,
        [In, Out] NexusHandleInfo[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Close a handle in the target process.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HandleClose(
        IntPtr enumHandle,
        IntPtr handleValue);

    /// <summary>
    /// Duplicate a handle from the target process.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HandleDuplicate(
        IntPtr enumHandle,
        IntPtr handleValue,
        out IntPtr duplicatedHandle);

    #endregion

    #region File Handle Operations

    /// <summary>
    /// Get file handles in the process.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HandleEnumFiles(
        IntPtr enumHandle,
        [In, Out] NexusFileHandleInfo[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Find file handles by path pattern.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_HandleFindFiles(
        IntPtr enumHandle,
        string pathPattern,
        [In, Out] NexusFileHandleInfo[]? buffer,
        nuint bufferCount,
        out nuint count);

    #endregion

    #region Registry Handle Operations

    /// <summary>
    /// Get registry key handles in the process.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HandleEnumRegistry(
        IntPtr enumHandle,
        [In, Out] NexusRegistryHandleInfo[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Find registry handles by key pattern.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_HandleFindRegistry(
        IntPtr enumHandle,
        string keyPattern,
        [In, Out] NexusRegistryHandleInfo[]? buffer,
        nuint bufferCount,
        out nuint count);

    #endregion

    #region Synchronization Handle Operations

    /// <summary>
    /// Get synchronization object handles (mutexes, semaphores, events).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HandleEnumSync(
        IntPtr enumHandle,
        [In, Out] NexusSyncHandleInfo[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Find synchronization handles by name.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_HandleFindSync(
        IntPtr enumHandle,
        string namePattern,
        [In, Out] NexusSyncHandleInfo[]? buffer,
        nuint bufferCount,
        out nuint count);

    #endregion

    #region Section/Memory Handle Operations

    /// <summary>
    /// Get section (shared memory) handles.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HandleEnumSections(
        IntPtr enumHandle,
        [In, Out] NexusSectionHandleInfo[]? buffer,
        nuint bufferCount,
        out nuint count);

    #endregion

    #region Thread/Process Handle Operations

    /// <summary>
    /// Get process handles held by the target.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HandleEnumProcesses(
        IntPtr enumHandle,
        [In, Out] NexusProcessHandleInfo[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Get thread handles held by the target.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HandleEnumThreads(
        IntPtr enumHandle,
        [In, Out] NexusThreadHandleInfo[]? buffer,
        nuint bufferCount,
        out nuint count);

    #endregion
}

#region Handle Enums and Structs

/// <summary>
/// Handle type classification.
/// </summary>
public enum NexusHandleType : uint
{
    Unknown = 0,
    File = 1,
    Directory = 2,
    Event = 3,
    Mutant = 4,             // Mutex
    Semaphore = 5,
    Timer = 6,
    Key = 7,                // Registry key
    Section = 8,            // Shared memory
    Process = 9,
    Thread = 10,
    Token = 11,
    WindowStation = 12,
    Desktop = 13,
    IoCompletion = 14,
    Socket = 15,
    Pipe = 16,
    SymbolicLink = 17,
    Job = 18,
    All = 0xFFFFFFFF
}

/// <summary>
/// Basic handle information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusHandleInfo
{
    public IntPtr HandleValue;          // Handle value
    public NexusHandleType Type;        // Handle type
    public uint AccessMask;             // Granted access rights
    public uint Attributes;             // Object attributes
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string TypeName;             // Type name string
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 520)]
    public string Name;                 // Object name (if available)
}

/// <summary>
/// Extended handle information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusHandleInfoEx
{
    public NexusHandleInfo Basic;       // Basic info
    public ulong ObjectAddress;         // Kernel object address
    public uint ReferenceCount;         // Reference count
    public uint HandleCount;            // Handle count (system-wide)
    public ulong CreationTime;          // When handle was created
    public uint PointerCount;           // Pointer count
}

/// <summary>
/// File handle information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusFileHandleInfo
{
    public IntPtr HandleValue;          // Handle value
    public uint AccessMask;             // Access rights (READ, WRITE, etc.)
    public uint ShareMode;              // Share mode flags
    public ulong FileSize;              // File size in bytes
    public ulong FilePosition;          // Current position
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 520)]
    public string FilePath;             // Full file path
    public uint IsDirectory;            // Is this a directory
    public uint IsDevice;               // Is this a device
}

/// <summary>
/// Registry handle information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusRegistryHandleInfo
{
    public IntPtr HandleValue;          // Handle value
    public uint AccessMask;             // Access rights
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 520)]
    public string KeyPath;              // Full registry key path
    public uint ValueCount;             // Number of values
    public uint SubkeyCount;            // Number of subkeys
    public ulong LastWriteTime;         // Last modification time
}

/// <summary>
/// Synchronization object handle information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusSyncHandleInfo
{
    public IntPtr HandleValue;          // Handle value
    public NexusHandleType Type;        // Mutant, Semaphore, Event, Timer
    public uint AccessMask;             // Access rights
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string Name;                 // Object name
    public uint Signaled;               // Current signal state
    // Mutex-specific
    public uint MutexOwnerThreadId;     // Thread that owns the mutex
    public uint MutexAbandonedState;    // Is mutex abandoned
    // Semaphore-specific
    public int SemaphoreCurrentCount;   // Current count
    public int SemaphoreMaxCount;       // Maximum count
    // Event-specific
    public uint EventType;              // Manual-reset or auto-reset
}

/// <summary>
/// Section (shared memory) handle information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusSectionHandleInfo
{
    public IntPtr HandleValue;          // Handle value
    public uint AccessMask;             // Access rights
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string Name;                 // Section name
    public ulong Size;                  // Section size
    public uint Protection;             // Page protection
    public uint Attributes;             // Section attributes (commit, reserve, image)
    public ulong MappedAddress;         // Address where mapped in this process
}

/// <summary>
/// Process handle information (handles to other processes).
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusProcessHandleInfo
{
    public IntPtr HandleValue;          // Handle value
    public uint AccessMask;             // Granted access (PROCESS_VM_READ, etc.)
    public uint TargetProcessId;        // PID of the target process
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string TargetProcessName;    // Name of target process
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 520)]
    public string TargetImagePath;      // Full path of target process
}

/// <summary>
/// Thread handle information (handles to threads).
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusThreadHandleInfo
{
    public IntPtr HandleValue;          // Handle value
    public uint AccessMask;             // Granted access
    public uint TargetThreadId;         // TID of the target thread
    public uint TargetProcessId;        // PID of owning process
    public ulong StartAddress;          // Thread start address
    public uint ThreadState;            // Current thread state
}

#endregion
