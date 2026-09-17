// <file>
// <summary>
// P/Invoke bindings for cross-reference (xref) analysis. Scan code and data sections
// for references to a target address, find all callers of a function, and enumerate
// string references within a module.
// </summary>
// </file>

using System.Runtime.InteropServices;

namespace Nexus.UI.Interop;

public static partial class NexusEngine
{
    #region Reference Scanning Operations

    /// <summary>
    /// Create a reference scanner for a process.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_XrefCreate(
        IntPtr processHandle,
        out IntPtr xrefHandle);

    /// <summary>
    /// Destroy a reference scanner and free resources.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern void Nexus_XrefDestroy(IntPtr xrefHandle);

    /// <summary>
    /// Find all references to a specific address.
    /// Scans code for instructions that reference the target address.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_XrefFindRefsTo(
        IntPtr xrefHandle,
        ulong targetAddress,
        ulong scanStart,
        ulong scanEnd,
        NexusXrefType refTypes,
        [In, Out] NexusXref[]? results,
        nuint maxResults,
        out nuint resultCount);

    /// <summary>
    /// Find all references from a specific address.
    /// Analyzes an instruction to find what addresses it references.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_XrefFindRefsFrom(
        IntPtr xrefHandle,
        ulong sourceAddress,
        [In, Out] NexusXref[]? results,
        nuint maxResults,
        out nuint resultCount);

    /// <summary>
    /// Find all string references in a memory range.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_XrefFindStrings(
        IntPtr xrefHandle,
        ulong scanStart,
        ulong scanEnd,
        uint minLength,
        [In, Out] NexusStringRef[]? results,
        nuint maxResults,
        out nuint resultCount);

    /// <summary>
    /// Find all call references to a function.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_XrefFindCalls(
        IntPtr xrefHandle,
        ulong functionAddress,
        ulong scanStart,
        ulong scanEnd,
        [In, Out] NexusXref[]? results,
        nuint maxResults,
        out nuint resultCount);

    /// <summary>
    /// Analyze a module for all cross-references.
    /// This performs comprehensive xref analysis on a module.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_XrefAnalyzeModule(
        IntPtr xrefHandle,
        ulong moduleBase,
        ulong moduleSize,
        NexusXrefAnalysisFlags flags,
        out IntPtr analysisHandle);

    /// <summary>
    /// Get results from a module analysis.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_XrefGetAnalysisResults(
        IntPtr analysisHandle,
        [In, Out] NexusXref[]? results,
        nuint maxResults,
        out nuint resultCount);

    /// <summary>
    /// Free analysis results.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern void Nexus_XrefFreeAnalysis(IntPtr analysisHandle);

    /// <summary>
    /// Find all imports used by a module.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_XrefFindImportRefs(
        IntPtr xrefHandle,
        ulong moduleBase,
        [In, Out] NexusImportRef[]? results,
        nuint maxResults,
        out nuint resultCount);

    #endregion
}

#region Xref Enums and Structs

/// <summary>
/// Types of cross-references.
/// </summary>
[Flags]
public enum NexusXrefType : uint
{
    None = 0,
    Call = 1,           // CALL instruction
    Jump = 2,           // JMP/Jcc instruction
    Data = 4,           // Data reference (MOV, LEA, etc.)
    String = 8,         // String reference
    Import = 16,        // Import reference
    All = 0xFFFFFFFF
}

/// <summary>
/// Flags for xref analysis.
/// </summary>
[Flags]
public enum NexusXrefAnalysisFlags : uint
{
    None = 0,
    IncludeCalls = 1,
    IncludeJumps = 2,
    IncludeData = 4,
    IncludeStrings = 8,
    FollowCalls = 16,       // Recursively analyze called functions
    AnalyzeExports = 32,    // Start analysis from exports
    All = 0xFFFFFFFF
}

/// <summary>
/// Cross-reference entry.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusXref
{
    public ulong FromAddress;       // Address of the referencing instruction
    public ulong ToAddress;         // Address being referenced
    public NexusXrefType Type;      // Type of reference
    public uint InstructionSize;    // Size of the referencing instruction
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string Mnemonic;         // Instruction mnemonic (e.g., "call", "mov")
}

/// <summary>
/// String reference entry.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusStringRef
{
    public ulong Address;           // Address of the string
    public ulong RefAddress;        // Address of code referencing the string
    public uint Length;             // String length
    public uint IsWide;             // 1 if wide string (UTF-16), 0 if ASCII
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string Preview;          // First 255 chars of the string
}

/// <summary>
/// Import reference entry.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusImportRef
{
    public ulong IATAddress;        // Address in Import Address Table
    public ulong RefAddress;        // Address of code referencing the import
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string ModuleName;       // DLL name
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
    public string FunctionName;     // Function name
    public ushort Ordinal;          // Ordinal if imported by ordinal
}

#endregion
