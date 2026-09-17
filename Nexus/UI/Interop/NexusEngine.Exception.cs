// <file>
// <summary>
// P/Invoke bindings for debugger exception configuration. Controls how the debugger
// handles specific exception codes (first-chance vs. second-chance, pass to application
// vs. swallow). Allows customizing behavior for access violations, breakpoints, etc.
// </summary>
// </file>

using System.Runtime.InteropServices;

namespace Nexus.UI.Interop;

public static partial class NexusEngine
{
    #region Exception Configuration

    /// <summary>
    /// Create an exception configuration for a debugger.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ExceptionConfigCreate(
        IntPtr debuggerHandle,
        out IntPtr configHandle);

    /// <summary>
    /// Destroy an exception configuration.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern void Nexus_ExceptionConfigDestroy(IntPtr configHandle);

    /// <summary>
    /// Set exception handling behavior for a specific exception.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ExceptionSetBehavior(
        IntPtr configHandle,
        uint exceptionCode,
        NexusExceptionAction firstChance,
        NexusExceptionAction secondChance);

    /// <summary>
    /// Get exception handling behavior for a specific exception.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ExceptionGetBehavior(
        IntPtr configHandle,
        uint exceptionCode,
        out NexusExceptionBehavior behavior);

    /// <summary>
    /// Reset an exception to default handling.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ExceptionResetToDefault(
        IntPtr configHandle,
        uint exceptionCode);

    /// <summary>
    /// Reset all exceptions to default handling.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ExceptionResetAllToDefault(
        IntPtr configHandle);

    /// <summary>
    /// Get all configured exceptions.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ExceptionGetList(
        IntPtr configHandle,
        [In, Out] NexusExceptionEntry[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Add a custom exception definition.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_ExceptionAddCustom(
        IntPtr configHandle,
        uint exceptionCode,
        string name,
        NexusExceptionAction firstChance,
        NexusExceptionAction secondChance);

    /// <summary>
    /// Remove a custom exception definition.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ExceptionRemoveCustom(
        IntPtr configHandle,
        uint exceptionCode);

    #endregion

    #region Exception Logging

    /// <summary>
    /// Enable/disable exception logging.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ExceptionSetLogging(
        IntPtr configHandle,
        uint exceptionCode,
        uint enable);

    /// <summary>
    /// Set log file for exceptions.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_ExceptionSetLogFile(
        IntPtr configHandle,
        string? filePath);

    /// <summary>
    /// Get exception log.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ExceptionGetLog(
        IntPtr configHandle,
        [In, Out] NexusExceptionLogEntry[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Clear exception log.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ExceptionClearLog(IntPtr configHandle);

    #endregion

    #region Exception Statistics

    /// <summary>
    /// Get exception statistics.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ExceptionGetStats(
        IntPtr configHandle,
        out NexusExceptionStats stats);

    /// <summary>
    /// Get hit count for a specific exception.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ExceptionGetHitCount(
        IntPtr configHandle,
        uint exceptionCode,
        out uint firstChanceCount,
        out uint secondChanceCount);

    /// <summary>
    /// Reset exception statistics.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ExceptionResetStats(IntPtr configHandle);

    #endregion

    #region Exception Persistence

    /// <summary>
    /// Save exception configuration to file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_ExceptionSaveConfig(
        IntPtr configHandle,
        string filePath);

    /// <summary>
    /// Load exception configuration from file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_ExceptionLoadConfig(
        IntPtr configHandle,
        string filePath);

    #endregion

    #region Exception Information

    /// <summary>
    /// Get exception name from code.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ExceptionGetName(
        uint exceptionCode,
        [Out, MarshalAs(UnmanagedType.LPStr)] System.Text.StringBuilder name,
        nuint nameSize);

    /// <summary>
    /// Get exception code from name.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_ExceptionGetCode(
        string name,
        out uint exceptionCode);

    /// <summary>
    /// Get all known exception definitions.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ExceptionGetKnownList(
        [In, Out] NexusExceptionDef[]? buffer,
        nuint bufferCount,
        out nuint count);

    #endregion
}

#region Exception Enums and Structs

/// <summary>
/// Exception handling action.
/// </summary>
public enum NexusExceptionAction : uint
{
    Break = 0,              // Break into debugger
    Pass = 1,               // Pass to application handler
    Log = 2,                // Log but don't break
    LogAndBreak = 3,        // Log and break
    Ignore = 4              // Silently ignore
}

/// <summary>
/// Common exception codes.
/// </summary>
public static class NexusExceptionCodes
{
    public const uint AccessViolation = 0xC0000005;
    public const uint ArrayBoundsExceeded = 0xC000008C;
    public const uint Breakpoint = 0x80000003;
    public const uint DataTypeMisalignment = 0x80000002;
    public const uint FloatDenormalOperand = 0xC000008D;
    public const uint FloatDivideByZero = 0xC000008E;
    public const uint FloatInexactResult = 0xC000008F;
    public const uint FloatInvalidOperation = 0xC0000090;
    public const uint FloatOverflow = 0xC0000091;
    public const uint FloatStackCheck = 0xC0000092;
    public const uint FloatUnderflow = 0xC0000093;
    public const uint GuardPageViolation = 0x80000001;
    public const uint IllegalInstruction = 0xC000001D;
    public const uint InPageError = 0xC0000006;
    public const uint IntegerDivideByZero = 0xC0000094;
    public const uint IntegerOverflow = 0xC0000095;
    public const uint InvalidDisposition = 0xC0000026;
    public const uint InvalidHandle = 0xC0000008;
    public const uint NonContinuableException = 0xC0000025;
    public const uint PrivilegedInstruction = 0xC0000096;
    public const uint SingleStep = 0x80000004;
    public const uint StackOverflow = 0xC00000FD;
    public const uint UnwindConsolidate = 0x80000029;

    // C++ Exceptions
    public const uint CppException = 0xE06D7363;

    // CLR Exceptions
    public const uint ClrException = 0xE0434352;

    // Delphi Exceptions
    public const uint DelphiException = 0x0EEDFADE;

    // Visual Basic Exceptions
    public const uint VBException = 0x0EEDFADE;

    // x64dbg-specific
    public const uint OutputDebugString = 0x40010006;
    public const uint RipEvent = 0x40010007;
}

/// <summary>
/// Exception behavior configuration.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusExceptionBehavior
{
    public uint ExceptionCode;              // Exception code
    public NexusExceptionAction FirstChance;  // First chance action
    public NexusExceptionAction SecondChance; // Second chance action
    public uint LogEnabled;                 // Log this exception
    public uint BreakpointEnabled;          // Break on this exception
}

/// <summary>
/// Exception configuration entry.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusExceptionEntry
{
    public uint ExceptionCode;              // Exception code
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string Name;                     // Exception name
    public NexusExceptionAction FirstChance;  // First chance action
    public NexusExceptionAction SecondChance; // Second chance action
    public uint LogEnabled;                 // Log this exception
    public uint FirstChanceCount;           // Times hit (first chance)
    public uint SecondChanceCount;          // Times hit (second chance)
    public uint IsCustom;                   // User-defined exception
}

/// <summary>
/// Exception log entry.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusExceptionLogEntry
{
    public ulong Timestamp;                 // When exception occurred
    public uint ExceptionCode;              // Exception code
    public uint ThreadId;                   // Thread that caused exception
    public ulong Address;                   // Exception address
    public ulong ExceptionInfo0;            // First parameter
    public ulong ExceptionInfo1;            // Second parameter
    public uint IsFirstChance;              // 1 if first chance
    public uint WasContinued;               // 1 if continued past

    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string ExceptionName;            // Exception name

    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string ModuleName;               // Module at address
}

/// <summary>
/// Exception statistics.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusExceptionStats
{
    public uint TotalFirstChance;           // Total first chance exceptions
    public uint TotalSecondChance;          // Total second chance exceptions
    public uint UniqueExceptionTypes;       // Number of unique exception codes
    public uint MostCommonCode;             // Most frequently occurring
    public uint MostCommonCount;            // Count of most common
    public ulong LastExceptionTime;         // Time of last exception
    public uint LastExceptionCode;          // Code of last exception
    public uint LastExceptionThread;        // Thread of last exception
}

/// <summary>
/// Exception definition (known exceptions).
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusExceptionDef
{
    public uint ExceptionCode;              // Exception code
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string Name;                     // Exception name
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string Description;              // Description
    public uint Severity;                   // 0=Info, 1=Warning, 2=Error, 3=Fatal
    public uint DefaultFirstChance;         // Default first chance action
    public uint DefaultSecondChance;        // Default second chance action
}

#endregion
