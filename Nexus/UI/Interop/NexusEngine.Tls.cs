// <file>
// <summary>
// P/Invoke bindings for TLS (Thread Local Storage) manipulation. Read and modify TLS
// directory entries, enumerate TLS callbacks, and manage TLS indices in PE modules.
// </summary>
// </file>

using System.Runtime.InteropServices;

namespace Nexus.UI.Interop;

public static partial class NexusEngine
{
    #region TLS Directory Access

    /// <summary>
    /// Check if PE has TLS directory.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_TlsHasDirectory(
        string filePath,
        out uint hasTls);

    /// <summary>
    /// Get TLS directory information.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_TlsGetDirectory(
        string filePath,
        out NexusTlsDirectory directory);

    /// <summary>
    /// Get TLS directory from memory.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_TlsGetDirectoryMem(
        IntPtr processHandle,
        ulong moduleBase,
        out NexusTlsDirectory directory);

    /// <summary>
    /// Set TLS directory fields.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_TlsSetDirectory(
        string filePath,
        ref NexusTlsDirectory directory);

    #endregion

    #region TLS Callbacks

    /// <summary>
    /// Get TLS callback addresses.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_TlsGetCallbacks(
        string filePath,
        [In, Out] ulong[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Get TLS callbacks from memory.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_TlsGetCallbacksMem(
        IntPtr processHandle,
        ulong moduleBase,
        [In, Out] ulong[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Add a TLS callback.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_TlsAddCallback(
        string filePath,
        ulong callbackRva);

    /// <summary>
    /// Remove a TLS callback.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_TlsRemoveCallback(
        string filePath,
        ulong callbackRva);

    /// <summary>
    /// Clear all TLS callbacks.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_TlsClearCallbacks(
        string filePath);

    /// <summary>
    /// Replace TLS callback address.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_TlsReplaceCallback(
        string filePath,
        ulong oldCallbackRva,
        ulong newCallbackRva);

    #endregion

    #region TLS Data

    /// <summary>
    /// Get TLS raw data.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_TlsGetData(
        string filePath,
        [In, Out] byte[]? buffer,
        nuint bufferSize,
        out nuint dataSize);

    /// <summary>
    /// Set TLS raw data.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_TlsSetData(
        string filePath,
        [In] byte[] data,
        nuint dataSize);

    /// <summary>
    /// Get TLS index variable address.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_TlsGetIndexAddress(
        string filePath,
        out ulong addressRva);

    /// <summary>
    /// Set TLS index variable address.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_TlsSetIndexAddress(
        string filePath,
        ulong addressRva);

    #endregion

    #region TLS Creation

    /// <summary>
    /// Add TLS directory to PE that doesn't have one.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_TlsCreate(
        string filePath,
        nuint dataSize);

    /// <summary>
    /// Remove TLS directory from PE.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_TlsRemove(
        string filePath);

    /// <summary>
    /// Backup TLS directory to file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_TlsBackup(
        string filePath,
        string backupPath);

    /// <summary>
    /// Restore TLS directory from backup.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_TlsRestore(
        string filePath,
        string backupPath);

    #endregion

    #region TLS Callback Interception

    /// <summary>
    /// Set breakpoint before TLS callbacks execute.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_TlsBreakOnCallbacks(
        IntPtr debuggerHandle,
        uint enable);

    /// <summary>
    /// Skip TLS callbacks during debugging.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_TlsSkipCallbacks(
        IntPtr debuggerHandle,
        uint enable);

    /// <summary>
    /// Get TLS callback execution log.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_TlsGetCallbackLog(
        IntPtr debuggerHandle,
        [In, Out] NexusTlsCallbackLog[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Clear TLS callback log.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_TlsClearCallbackLog(
        IntPtr debuggerHandle);

    #endregion

    #region TLS Analysis

    /// <summary>
    /// Analyze TLS for anti-debug techniques.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_TlsAnalyze(
        string filePath,
        out NexusTlsAnalysis analysis);

    /// <summary>
    /// Analyze TLS in memory.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_TlsAnalyzeMem(
        IntPtr processHandle,
        ulong moduleBase,
        out NexusTlsAnalysis analysis);

    #endregion
}

#region TLS Enums and Structs

/// <summary>
/// TLS callback reason.
/// </summary>
public enum NexusTlsReason : uint
{
    ProcessAttach = 1,          // DLL_PROCESS_ATTACH
    ThreadAttach = 2,           // DLL_THREAD_ATTACH
    ThreadDetach = 3,           // DLL_THREAD_DETACH
    ProcessDetach = 0           // DLL_PROCESS_DETACH
}

/// <summary>
/// TLS directory information.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusTlsDirectory
{
    public ulong StartAddressOfRawData;     // Start of TLS data
    public ulong EndAddressOfRawData;       // End of TLS data
    public ulong AddressOfIndex;            // TLS index variable
    public ulong AddressOfCallbacks;        // Callback array address
    public uint SizeOfZeroFill;             // Zero-fill size
    public uint Characteristics;            // Alignment flags
    public uint DataSize;                   // Raw data size
    public uint CallbackCount;              // Number of callbacks
    public uint Is64Bit;                    // 64-bit TLS directory
}

/// <summary>
/// TLS callback execution log entry.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusTlsCallbackLog
{
    public ulong CallbackAddress;           // Callback function address
    public NexusTlsReason Reason;           // Callback reason
    public uint ThreadId;                   // Thread ID
    public ulong ModuleBase;                // Module base address
    public ulong ReturnValue;               // Callback return value
    public ulong Timestamp;                 // Execution timestamp
    public uint WasSkipped;                 // 1 if skipped
}

/// <summary>
/// TLS analysis results.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusTlsAnalysis
{
    public uint HasTls;                     // Has TLS directory
    public uint CallbackCount;              // Number of callbacks
    public uint DataSize;                   // TLS data size
    public uint HasAntiDebug;               // Contains anti-debug code
    public uint HasChecksum;                // Performs checksum validation
    public uint HasTimingCheck;             // Has timing-based checks
    public uint HasProcessEnum;             // Enumerates processes
    public uint HasDebuggerDetect;          // Detects debuggers
    public uint HasSelfModify;              // Self-modifying code
    public uint RiskLevel;                  // Risk level (0-100)
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)]
    public string Analysis;                 // Analysis description
}

#endregion
