// <file>
// <summary>
// P/Invoke bindings for the scripting and command system. Execute text commands,
// run script files, register custom commands, and automate debugging workflows.
// Supports conditional execution, variables, labels, and breakpoint-triggered scripts.
// </summary>
// </file>

using System.Runtime.InteropServices;

namespace Nexus.UI.Interop;

public static partial class NexusEngine
{
    #region Command Execution

    /// <summary>
    /// Create a command context for a debugger.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CommandCreate(
        IntPtr debuggerHandle,
        out IntPtr commandHandle);

    /// <summary>
    /// Destroy a command context.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern void Nexus_CommandDestroy(IntPtr commandHandle);

    /// <summary>
    /// Execute a single command.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_CommandExecute(
        IntPtr commandHandle,
        string command,
        out NexusCommandResult result);

    /// <summary>
    /// Execute a command and get string output.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_CommandExecuteString(
        IntPtr commandHandle,
        string command,
        [Out, MarshalAs(UnmanagedType.LPStr)] System.Text.StringBuilder output,
        nuint outputSize);

    /// <summary>
    /// Execute multiple commands (separated by newlines).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_CommandExecuteBatch(
        IntPtr commandHandle,
        string commands,
        out uint successCount,
        out uint failCount);

    /// <summary>
    /// Get list of available commands.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_CommandGetList(
        IntPtr commandHandle,
        [In, Out] NexusCommandInfo[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Get help for a specific command.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_CommandGetHelp(
        IntPtr commandHandle,
        string command,
        [Out, MarshalAs(UnmanagedType.LPStr)] System.Text.StringBuilder help,
        nuint helpSize);

    /// <summary>
    /// Register a custom command callback (raw P/Invoke - prefer RegisterCommand wrapper).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    private static extern NexusResult Nexus_CommandRegister(
        IntPtr commandHandle,
        string name,
        NexusCommandCallback callback,
        string? description);

    /// <summary>
    /// Unregister a custom command (raw P/Invoke - prefer UnregisterCommand wrapper).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    private static extern NexusResult Nexus_CommandUnregister(
        IntPtr commandHandle,
        string name);

    // GC roots for delegates passed to native code (prevent collection while native holds pointer)
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, NexusCommandCallback> _commandCallbacks = new();
    private static NexusLogCallback? _logCallback;

    /// <summary>
    /// Register a custom command callback. Delegate is rooted to prevent GC collection.
    /// </summary>
    public static NexusResult RegisterCommand(IntPtr commandHandle, string name, NexusCommandCallback callback, string? description = null)
    {
        _commandCallbacks[name] = callback; // Root the delegate
        return Nexus_CommandRegister(commandHandle, name, callback, description);
    }

    /// <summary>
    /// Unregister a custom command and release the delegate root.
    /// </summary>
    public static NexusResult UnregisterCommand(IntPtr commandHandle, string name)
    {
        var result = Nexus_CommandUnregister(commandHandle, name);
        _commandCallbacks.TryRemove(name, out _); // Allow GC after native releases
        return result;
    }

    #endregion

    #region Script Execution

    /// <summary>
    /// Load a script from file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_ScriptLoad(
        IntPtr commandHandle,
        string filePath,
        out IntPtr scriptHandle);

    /// <summary>
    /// Load a script from string.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_ScriptLoadString(
        IntPtr commandHandle,
        string scriptText,
        out IntPtr scriptHandle);

    /// <summary>
    /// Unload a script.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern void Nexus_ScriptUnload(IntPtr scriptHandle);

    /// <summary>
    /// Run a loaded script.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ScriptRun(
        IntPtr scriptHandle,
        out NexusScriptResult result);

    /// <summary>
    /// Run a script from file directly.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_ScriptRunFile(
        IntPtr commandHandle,
        string filePath,
        out NexusScriptResult result);

    /// <summary>
    /// Abort a running script.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ScriptAbort(IntPtr scriptHandle);

    /// <summary>
    /// Check if script is running.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ScriptIsRunning(
        IntPtr scriptHandle,
        out uint isRunning);

    /// <summary>
    /// Step through script (debug mode).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ScriptStep(
        IntPtr scriptHandle,
        out NexusScriptState state);

    #endregion

    #region Script Variables

    /// <summary>
    /// Set a script variable.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_ScriptSetVariable(
        IntPtr commandHandle,
        string name,
        ulong value);

    /// <summary>
    /// Get a script variable.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_ScriptGetVariable(
        IntPtr commandHandle,
        string name,
        out ulong value);

    /// <summary>
    /// Delete a script variable.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_ScriptDeleteVariable(
        IntPtr commandHandle,
        string name);

    /// <summary>
    /// Get all script variables.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ScriptGetVariables(
        IntPtr commandHandle,
        [In, Out] NexusScriptVariable[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Clear all script variables.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ScriptClearVariables(IntPtr commandHandle);

    #endregion

    #region Logging

    /// <summary>
    /// Log a message.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_Log(
        IntPtr commandHandle,
        NexusLogLevel level,
        string message);

    /// <summary>
    /// Log a formatted message.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_LogFormat(
        IntPtr commandHandle,
        NexusLogLevel level,
        string format,
        ulong arg1,
        ulong arg2,
        ulong arg3,
        ulong arg4);

    /// <summary>
    /// Get log entries.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_LogGetEntries(
        IntPtr commandHandle,
        [In, Out] NexusLogEntry[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Clear log.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_LogClear(IntPtr commandHandle);

    /// <summary>
    /// Set log file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_LogSetFile(
        IntPtr commandHandle,
        string? filePath);

    /// <summary>
    /// Set log callback (raw P/Invoke - prefer SetLogCallback wrapper).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    private static extern NexusResult Nexus_LogSetCallback(
        IntPtr commandHandle,
        NexusLogCallback? callback);

    /// <summary>
    /// Set log callback. Delegate is rooted to prevent GC collection.
    /// Pass null to clear the callback.
    /// </summary>
    public static NexusResult SetLogCallback(IntPtr commandHandle, NexusLogCallback? callback)
    {
        _logCallback = callback; // Root (or clear) the delegate
        return Nexus_LogSetCallback(commandHandle, callback);
    }

    #endregion

    #region History

    /// <summary>
    /// Add command to history.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_HistoryAdd(
        IntPtr commandHandle,
        string command);

    /// <summary>
    /// Get command history.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HistoryGet(
        IntPtr commandHandle,
        [In, Out] NexusHistoryEntry[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Clear command history.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HistoryClear(IntPtr commandHandle);

    /// <summary>
    /// Save history to file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_HistorySave(
        IntPtr commandHandle,
        string filePath);

    /// <summary>
    /// Load history from file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_HistoryLoad(
        IntPtr commandHandle,
        string filePath);

    #endregion
}

#region Script Enums, Delegates, and Structs

/// <summary>
/// Log level.
/// </summary>
public enum NexusLogLevel : uint
{
    Debug = 0,
    Info = 1,
    Warning = 2,
    Error = 3,
    Fatal = 4
}

/// <summary>
/// Command callback delegate.
/// </summary>
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate int NexusCommandCallback(
    int argc,
    [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.LPStr)] string[] argv);

/// <summary>
/// Log callback delegate.
/// </summary>
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate void NexusLogCallback(
    NexusLogLevel level,
    [MarshalAs(UnmanagedType.LPStr)] string message);

/// <summary>
/// Command execution result.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusCommandResult
{
    public int ReturnCode;                  // Return code (0 = success)
    public ulong ResultValue;               // Numeric result value
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)]
    public string ResultString;             // String result
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string ErrorMessage;             // Error message (if failed)
}

/// <summary>
/// Command information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusCommandInfo
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string Name;                     // Command name
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string Description;              // Short description
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
    public string Syntax;                   // Usage syntax
    public uint MinArgs;                    // Minimum arguments
    public uint MaxArgs;                    // Maximum arguments
    public uint IsBuiltin;                  // Is built-in command
}

/// <summary>
/// Script execution result.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusScriptResult
{
    public int ReturnCode;                  // Script return code
    public uint LinesExecuted;              // Number of lines executed
    public uint Errors;                     // Number of errors
    public uint Warnings;                   // Number of warnings
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)]
    public string LastError;                // Last error message
    public uint FailedLine;                 // Line number that failed
}

/// <summary>
/// Script execution state (for debugging).
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusScriptState
{
    public uint CurrentLine;                // Current line number
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string CurrentCommand;           // Current command text
    public uint IsRunning;                  // Script is running
    public uint IsPaused;                   // Script is paused
    public uint InLabel;                    // Inside a label block
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string CurrentLabel;             // Current label name
}

/// <summary>
/// Script variable.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusScriptVariable
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string Name;                     // Variable name
    public ulong Value;                     // Variable value
    public uint IsReadOnly;                 // Is read-only
    public uint IsSystem;                   // Is system variable
}

/// <summary>
/// Log entry.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusLogEntry
{
    public ulong Timestamp;                 // Entry timestamp
    public NexusLogLevel Level;             // Log level
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 1024)]
    public string Message;                  // Log message
    public uint ThreadId;                   // Thread that logged
}

/// <summary>
/// Command history entry.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusHistoryEntry
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)]
    public string Command;                  // Command text
    public ulong Timestamp;                 // When executed
    public int ReturnCode;                  // Result code
}

#endregion
