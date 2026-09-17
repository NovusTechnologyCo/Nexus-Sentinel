// <file>
// <summary>
// P/Invoke bindings for miscellaneous engine operations: ETW (Event Tracing for Windows)
// session management, speedhack (time manipulation), address table management, kernel
// module enumeration, and process suspension/resume.
// </summary>
// </file>

using System.Runtime.InteropServices;

namespace Nexus.UI.Interop;

public static partial class NexusEngine
{
    #region Cheat Table Operations

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_TableCreate(out IntPtr tableHandle);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern void Nexus_TableDestroy(IntPtr tableHandle);

    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_TableLoad(
        IntPtr tableHandle,
        string path);

    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_TableSave(
        IntPtr tableHandle,
        string path);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_TableAddEntry(
        IntPtr tableHandle,
        ref NexusTableEntry entry,
        out int index);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_TableGetEntry(
        IntPtr tableHandle,
        int index,
        out NexusTableEntry entry);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_TableGetEntryCount(
        IntPtr tableHandle,
        out nuint count);

    #endregion

    #region Kernel Operations

    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_KernelCreate(
        string? driverPath,
        out IntPtr kernelHandle);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern void Nexus_KernelDestroy(IntPtr kernelHandle);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_KernelGetStatus(
        IntPtr kernelHandle,
        out NexusKernelStatus status);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_KernelReadMemory(
        IntPtr kernelHandle,
        uint processId,
        ulong address,
        IntPtr buffer,
        nuint size,
        out nuint bytesRead);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_KernelWriteMemory(
        IntPtr kernelHandle,
        uint processId,
        ulong address,
        IntPtr buffer,
        nuint size,
        out nuint bytesWritten);

    #endregion

    #region ETW (Event Tracing for Windows) Operations

    /// <summary>
    /// Create an ETW tracing session.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_EtwCreate(
        ref NexusEtwConfig config,
        out IntPtr handle);

    /// <summary>
    /// Create an ETW tracing session with default configuration.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_EtwCreate(
        IntPtr configNull,
        out IntPtr handle);

    /// <summary>
    /// Destroy an ETW tracing session.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern void Nexus_EtwDestroy(IntPtr handle);

    /// <summary>
    /// Start ETW tracing.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_EtwStart(IntPtr handle);

    /// <summary>
    /// Stop ETW tracing.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_EtwStop(IntPtr handle);

    /// <summary>
    /// Check if tracing is currently active.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_EtwIsRunning(IntPtr handle, out uint isRunning);

    /// <summary>
    /// Poll for events.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_EtwPollEvents(
        IntPtr handle,
        [In, Out] NexusEtwEvent[] events,
        nuint maxEvents,
        out nuint eventCount);

    /// <summary>
    /// Get the number of pending events in the queue.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_EtwGetPendingCount(IntPtr handle, out nuint count);

    /// <summary>
    /// Clear all pending events from the queue.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_EtwClearEvents(IntPtr handle);

    /// <summary>
    /// Update providers while tracing.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_EtwSetProviders(IntPtr handle, uint providers);

    /// <summary>
    /// Update PID filter while tracing.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_EtwSetTargetPid(IntPtr handle, uint targetPid);

    /// <summary>
    /// Get current statistics.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_EtwGetStats(IntPtr handle, out NexusEtwStats stats);

    /// <summary>
    /// Check if the current process has admin privileges.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_EtwCheckAdminPrivilege(out uint isAdmin);

    /// <summary>
    /// Get human-readable operation name.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern IntPtr Nexus_EtwGetOperationName(uint operation);

    /// <summary>
    /// Get human-readable category name.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern IntPtr Nexus_EtwGetCategoryName(uint category);

    /// <summary>
    /// Helper to get operation name as a string.
    /// </summary>
    public static string GetEtwOperationName(NexusEtwOperation operation)
    {
        var ptr = Nexus_EtwGetOperationName((uint)operation);
        return ptr != IntPtr.Zero ? Marshal.PtrToStringAnsi(ptr) ?? "Unknown" : "Unknown";
    }

    /// <summary>
    /// Helper to get category name as a string.
    /// </summary>
    public static string GetEtwCategoryName(NexusEtwEventCategory category)
    {
        var ptr = Nexus_EtwGetCategoryName((uint)category);
        return ptr != IntPtr.Zero ? Marshal.PtrToStringAnsi(ptr) ?? "Unknown" : "Unknown";
    }

    #endregion

    #region Speedhack Operations

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_SpeedhackCreate(
        IntPtr processHandle,
        uint method,
        out IntPtr speedhackHandle);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern void Nexus_SpeedhackDestroy(IntPtr speedhackHandle);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_SpeedhackSetSpeed(
        IntPtr speedhackHandle,
        double speed);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_SpeedhackGetSpeed(
        IntPtr speedhackHandle,
        out double speed);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_SpeedhackSetEnabled(
        IntPtr speedhackHandle,
        uint enable);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_SpeedhackGetStatus(
        IntPtr speedhackHandle,
        out NexusSpeedhackStatus status);

    #endregion

    #region Injection Operations

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_InjectDll(
        IntPtr processHandle,
        [MarshalAs(UnmanagedType.LPWStr)] string dllPath,
        out ulong moduleBase);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_InjectShellcode(
        IntPtr processHandle,
        IntPtr shellcode,
        nuint size,
        out ulong executionAddress);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CreateRemoteThread(
        IntPtr processHandle,
        ulong startAddress,
        ulong parameter,
        out uint threadId);

    #endregion
}
