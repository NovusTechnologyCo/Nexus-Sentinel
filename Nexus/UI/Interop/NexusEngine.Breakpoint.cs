// <file>
// <summary>
// P/Invoke bindings for enhanced breakpoint operations: conditional breakpoints with
// expression evaluation, hardware breakpoints (DR0-DR3), memory breakpoints (page guard),
// DLL load breakpoints, and breakpoint hit counting/logging.
// </summary>
// </file>

using System.Runtime.InteropServices;

namespace Nexus.UI.Interop;

public static partial class NexusEngine
{
    #region Conditional Breakpoints

    /// <summary>
    /// Set a break condition for a breakpoint.
    /// The condition is an expression that must evaluate to true for the debugger to break.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_BreakpointSetCondition(
        IntPtr debuggerHandle,
        ulong breakpointId,
        string? condition);

    /// <summary>
    /// Set the log text for a breakpoint.
    /// When the breakpoint is hit, this text is logged (can include expressions like {rax}).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_BreakpointSetLogText(
        IntPtr debuggerHandle,
        ulong breakpointId,
        string? logText);

    /// <summary>
    /// Set a condition for logging. Log text is only written if this condition is true.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_BreakpointSetLogCondition(
        IntPtr debuggerHandle,
        ulong breakpointId,
        string? condition);

    /// <summary>
    /// Set a command to execute when the breakpoint is hit.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_BreakpointSetCommand(
        IntPtr debuggerHandle,
        ulong breakpointId,
        string? command);

    /// <summary>
    /// Set a condition for command execution.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_BreakpointSetCommandCondition(
        IntPtr debuggerHandle,
        ulong breakpointId,
        string? condition);

    /// <summary>
    /// Set the log file for a breakpoint. Log text is written to this file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_BreakpointSetLogFile(
        IntPtr debuggerHandle,
        ulong breakpointId,
        string? filePath);

    /// <summary>
    /// Set fast resume mode for a breakpoint.
    /// When enabled, the debugger resumes without GUI/script interaction.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_BreakpointSetFastResume(
        IntPtr debuggerHandle,
        ulong breakpointId,
        uint fastResume);

    /// <summary>
    /// Set silent mode for a breakpoint.
    /// Silent breakpoints don't display the default message when hit.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_BreakpointSetSilent(
        IntPtr debuggerHandle,
        ulong breakpointId,
        uint silent);

    /// <summary>
    /// Set single-shot mode for a breakpoint.
    /// Single-shot breakpoints are automatically deleted after being hit once.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_BreakpointSetSingleShot(
        IntPtr debuggerHandle,
        ulong breakpointId,
        uint singleShot);

    /// <summary>
    /// Get the hit count for a breakpoint.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_BreakpointGetHitCount(
        IntPtr debuggerHandle,
        ulong breakpointId,
        out uint hitCount);

    /// <summary>
    /// Reset or set the hit count for a breakpoint.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_BreakpointSetHitCount(
        IntPtr debuggerHandle,
        ulong breakpointId,
        uint hitCount);

    /// <summary>
    /// Set the breakpoint name/description.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_BreakpointSetName(
        IntPtr debuggerHandle,
        ulong breakpointId,
        string? name);

    /// <summary>
    /// Get extended breakpoint information.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_BreakpointGetEx(
        IntPtr debuggerHandle,
        ulong breakpointId,
        out NexusBreakpointEx breakpoint);

    #endregion

    #region Memory Breakpoints (Guard Pages)

    /// <summary>
    /// Set a memory breakpoint using PAGE_GUARD protection.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_SetMemoryBreakpoint(
        IntPtr debuggerHandle,
        ulong address,
        nuint size,
        NexusMemoryBreakpointType type,
        out ulong breakpointId);

    /// <summary>
    /// Set a memory breakpoint on a memory region.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_SetMemoryBreakpointRange(
        IntPtr debuggerHandle,
        ulong startAddress,
        ulong endAddress,
        NexusMemoryBreakpointType type,
        out ulong breakpointId);

    /// <summary>
    /// Remove a memory breakpoint and restore original page protection.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_RemoveMemoryBreakpoint(
        IntPtr debuggerHandle,
        ulong breakpointId);

    /// <summary>
    /// Get all memory breakpoints.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_GetMemoryBreakpoints(
        IntPtr debuggerHandle,
        [In, Out] NexusMemoryBreakpoint[]? buffer,
        nuint bufferCount,
        out nuint count);

    #endregion

    #region Hardware Breakpoints

    /// <summary>
    /// Set a hardware breakpoint using debug registers (DR0-DR3).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_SetHardwareBreakpoint(
        IntPtr debuggerHandle,
        uint threadId,
        ulong address,
        NexusHardwareBreakpointType type,
        NexusHardwareBreakpointSize size,
        out ulong breakpointId);

    /// <summary>
    /// Remove a hardware breakpoint and free the debug register.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_RemoveHardwareBreakpoint(
        IntPtr debuggerHandle,
        ulong breakpointId);

    /// <summary>
    /// Get the status of hardware breakpoints (DR0-DR3 usage).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_GetHardwareBreakpointStatus(
        IntPtr debuggerHandle,
        uint threadId,
        out NexusHardwareBreakpointStatus status);

    #endregion

    #region DLL Breakpoints

    /// <summary>
    /// Set a breakpoint that triggers when a DLL is loaded.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_SetDllLoadBreakpoint(
        IntPtr debuggerHandle,
        string moduleName,
        uint breakOnLoad,
        uint breakOnUnload,
        out ulong breakpointId);

    /// <summary>
    /// Remove a DLL load breakpoint.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_RemoveDllBreakpoint(
        IntPtr debuggerHandle,
        ulong breakpointId);

    /// <summary>
    /// Get all DLL breakpoints.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_GetDllBreakpoints(
        IntPtr debuggerHandle,
        [In, Out] NexusDllBreakpoint[]? buffer,
        nuint bufferCount,
        out nuint count);

    #endregion

    #region Exception Breakpoints

    /// <summary>
    /// Set a breakpoint that triggers on a specific exception code.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_SetExceptionBreakpoint(
        IntPtr debuggerHandle,
        uint exceptionCode,
        NexusExceptionBreakMode firstChance,
        NexusExceptionBreakMode secondChance,
        out ulong breakpointId);

    /// <summary>
    /// Remove an exception breakpoint.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_RemoveExceptionBreakpoint(
        IntPtr debuggerHandle,
        ulong breakpointId);

    /// <summary>
    /// Get all exception breakpoints.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_GetExceptionBreakpoints(
        IntPtr debuggerHandle,
        [In, Out] NexusExceptionBreakpoint[]? buffer,
        nuint bufferCount,
        out nuint count);

    #endregion

    #region Breakpoint Groups

    /// <summary>
    /// Create a breakpoint group for managing related breakpoints.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_BreakpointGroupCreate(
        IntPtr debuggerHandle,
        string name,
        out uint groupId);

    /// <summary>
    /// Delete a breakpoint group (does not delete contained breakpoints).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_BreakpointGroupDelete(
        IntPtr debuggerHandle,
        uint groupId);

    /// <summary>
    /// Add a breakpoint to a group.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_BreakpointGroupAdd(
        IntPtr debuggerHandle,
        uint groupId,
        ulong breakpointId);

    /// <summary>
    /// Remove a breakpoint from a group.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_BreakpointGroupRemove(
        IntPtr debuggerHandle,
        uint groupId,
        ulong breakpointId);

    /// <summary>
    /// Enable or disable all breakpoints in a group.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_BreakpointGroupSetEnabled(
        IntPtr debuggerHandle,
        uint groupId,
        uint enabled);

    #endregion
}

#region Enhanced Breakpoint Enums and Structs

/// <summary>
/// Memory breakpoint type (what access triggers the break).
/// </summary>
[Flags]
public enum NexusMemoryBreakpointType : uint
{
    Read = 1,           // Break on read access
    Write = 2,          // Break on write access
    Execute = 4,        // Break on execute access
    ReadWrite = Read | Write,
    All = Read | Write | Execute
}

/// <summary>
/// Hardware breakpoint type.
/// </summary>
public enum NexusHardwareBreakpointType : uint
{
    Execute = 0,        // Break on execution
    Write = 1,          // Break on write
    ReadWrite = 3       // Break on read or write (IO on some CPUs)
}

/// <summary>
/// Hardware breakpoint size.
/// </summary>
public enum NexusHardwareBreakpointSize : uint
{
    Byte = 0,           // 1 byte
    Word = 1,           // 2 bytes
    Dword = 3,          // 4 bytes
    Qword = 2           // 8 bytes (x64 only)
}

/// <summary>
/// Exception break mode.
/// </summary>
public enum NexusExceptionBreakMode : uint
{
    DontBreak = 0,      // Don't break on this exception
    Break = 1,          // Break on this exception
    Log = 2,            // Log but don't break
    PassToDebugger = 3  // Pass to the application's exception handler
}

/// <summary>
/// Extended breakpoint information with conditional data.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusBreakpointEx
{
    public ulong Id;                    // Breakpoint ID
    public ulong Address;               // Breakpoint address
    public uint Type;                   // Breakpoint type
    public uint Size;                   // Breakpoint size
    public uint Enabled;                // Whether enabled
    public uint Active;                 // Whether currently active
    public uint SingleShot;             // Delete after first hit
    public uint Silent;                 // Don't display default message
    public uint FastResume;             // Resume without GUI interaction
    public uint HitCount;               // Number of times hit

    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string Name;                 // Breakpoint name

    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string ModuleName;           // Module name (for module-relative)

    public ulong Rva;                   // RVA within module

    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string Condition;            // Break condition expression

    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)]
    public string LogText;              // Text to log when hit

    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string LogCondition;         // Condition for logging

    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)]
    public string Command;              // Command to execute

    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string CommandCondition;     // Condition for command

    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string LogFile;              // File to log to
}

/// <summary>
/// Memory breakpoint information.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusMemoryBreakpoint
{
    public ulong Id;                    // Breakpoint ID
    public ulong StartAddress;          // Start of memory range
    public ulong EndAddress;            // End of memory range
    public NexusMemoryBreakpointType Type;  // Access type
    public uint Enabled;                // Whether enabled
    public uint HitCount;               // Number of times hit
    public uint OriginalProtection;     // Original page protection
}

/// <summary>
/// Hardware breakpoint status.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusHardwareBreakpointStatus
{
    public ulong Dr0Address;            // DR0 address (0 if free)
    public ulong Dr1Address;            // DR1 address (0 if free)
    public ulong Dr2Address;            // DR2 address (0 if free)
    public ulong Dr3Address;            // DR3 address (0 if free)
    public uint Dr0InUse;               // DR0 in use
    public uint Dr1InUse;               // DR1 in use
    public uint Dr2InUse;               // DR2 in use
    public uint Dr3InUse;               // DR3 in use
}

/// <summary>
/// DLL load/unload breakpoint.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusDllBreakpoint
{
    public ulong Id;                    // Breakpoint ID
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string ModuleName;           // DLL name to watch
    public uint BreakOnLoad;            // Break when loaded
    public uint BreakOnUnload;          // Break when unloaded
    public uint Enabled;                // Whether enabled
}

/// <summary>
/// Exception breakpoint.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusExceptionBreakpoint
{
    public ulong Id;                    // Breakpoint ID
    public uint ExceptionCode;          // Exception code to watch
    public NexusExceptionBreakMode FirstChance;   // Action on first chance
    public NexusExceptionBreakMode SecondChance;  // Action on second chance
    public uint Enabled;                // Whether enabled
    public uint HitCount;               // Number of times hit
}

#endregion
