// <file>
// <summary>
// P/Invoke bindings for source-level mapping. Resolves virtual addresses to source
// file paths and line numbers using PDB debug information. Supports navigating from
// disassembly to source code when debug symbols are available.
// </summary>
// </file>

using System.Runtime.InteropServices;

namespace Nexus.UI.Interop;

public static partial class NexusEngine
{
    #region Source File Mapping

    /// <summary>
    /// Get source file and line for an address.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_SourceGetFromAddress(
        IntPtr processHandle,
        ulong address,
        out NexusSourceLocation location);

    /// <summary>
    /// Get address from source file and line.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_SourceGetAddress(
        IntPtr processHandle,
        string filePath,
        uint lineNumber,
        out ulong address);

    /// <summary>
    /// Get all addresses for a source line.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_SourceGetAllAddresses(
        IntPtr processHandle,
        string filePath,
        uint lineNumber,
        [In, Out] ulong[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Get source files for a module.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_SourceGetFiles(
        IntPtr processHandle,
        ulong moduleBase,
        [In, Out] NexusSourceFile[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Get line numbers in a source file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_SourceGetLines(
        IntPtr processHandle,
        ulong moduleBase,
        string filePath,
        [In, Out] NexusSourceLine[]? buffer,
        nuint bufferCount,
        out nuint count);

    #endregion

    #region Function Source Mapping

    /// <summary>
    /// Get source range for a function.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_SourceGetFunctionRange(
        IntPtr processHandle,
        ulong functionAddress,
        out NexusSourceRange range);

    /// <summary>
    /// Get functions in a source file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_SourceGetFunctions(
        IntPtr processHandle,
        ulong moduleBase,
        string filePath,
        [In, Out] NexusSourceFunction[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Find function by name in source.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_SourceFindFunction(
        IntPtr processHandle,
        ulong moduleBase,
        string functionName,
        out NexusSourceFunction function);

    #endregion

    #region Inline Information

    /// <summary>
    /// Get inline call stack at address.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_SourceGetInlineFrames(
        IntPtr processHandle,
        ulong address,
        [In, Out] NexusInlineFrame[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Check if address is in inlined code.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_SourceIsInlined(
        IntPtr processHandle,
        ulong address,
        out uint isInlined,
        out NexusInlineFrame frame);

    #endregion

    #region Source Loading

    /// <summary>
    /// Load source file content.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_SourceLoad(
        string filePath,
        [Out, MarshalAs(UnmanagedType.LPStr)] System.Text.StringBuilder content,
        nuint contentSize,
        out nuint lineCount);

    /// <summary>
    /// Get specific line from source file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_SourceGetLine(
        string filePath,
        uint lineNumber,
        [Out, MarshalAs(UnmanagedType.LPStr)] System.Text.StringBuilder line,
        nuint lineSize);

    /// <summary>
    /// Get source lines around an address.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_SourceGetContext(
        IntPtr processHandle,
        ulong address,
        uint linesBefore,
        uint linesAfter,
        out NexusSourceContext context);

    /// <summary>
    /// Set source search paths.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_SourceSetSearchPaths(
        IntPtr processHandle,
        string paths);

    /// <summary>
    /// Add source search path.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_SourceAddSearchPath(
        IntPtr processHandle,
        string path);

    #endregion

    #region PDB Information

    /// <summary>
    /// Get PDB information for module.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_SourceGetPdbInfo(
        IntPtr processHandle,
        ulong moduleBase,
        out NexusPdbInfo pdbInfo);

    /// <summary>
    /// Check if source information is available.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_SourceHasSourceInfo(
        IntPtr processHandle,
        ulong moduleBase,
        out uint hasSourceInfo);

    /// <summary>
    /// Get source server information.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_SourceGetServerInfo(
        IntPtr processHandle,
        ulong moduleBase,
        out NexusSourceServerInfo serverInfo);

    /// <summary>
    /// Download source from source server.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_SourceDownload(
        IntPtr processHandle,
        string sourceFile,
        string outputPath);

    #endregion

    #region Compiland Information

    /// <summary>
    /// Get compilands (object files) for a module.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_SourceGetCompilands(
        IntPtr processHandle,
        ulong moduleBase,
        [In, Out] NexusCompilandInfo[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Get source files for a compiland.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_SourceGetCompilandFiles(
        IntPtr processHandle,
        ulong moduleBase,
        string compilandName,
        [In, Out] NexusSourceFile[]? buffer,
        nuint bufferCount,
        out nuint count);

    #endregion
}

#region Source Mapping Enums and Structs

/// <summary>
/// Source location information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusSourceLocation
{
    public ulong Address;               // Code address
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)]
    public string FilePath;             // Source file path
    public uint LineNumber;             // Line number
    public uint ColumnNumber;           // Column number
    public uint LineEnd;                // End line (for multi-line)
    public uint ColumnEnd;              // End column
    public uint HasSource;              // Source file exists
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string FunctionName;         // Containing function
}

/// <summary>
/// Source file information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusSourceFile
{
    public uint Id;                     // File ID
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)]
    public string Path;                 // File path
    public uint LineCount;              // Number of lines with code
    public uint FunctionCount;          // Functions in this file
    public uint HasChecksum;            // Has checksum info
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] Checksum;             // MD5 checksum
    public uint ChecksumType;           // Checksum algorithm
}

/// <summary>
/// Source line information.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusSourceLine
{
    public uint LineNumber;             // Line number
    public ulong Address;               // Start address
    public ulong EndAddress;            // End address
    public uint Length;                 // Code length
    public uint IsStatement;            // Is statement (vs expression)
    public uint IsEpilog;               // Is function epilog
    public uint IsProlog;               // Is function prolog
}

/// <summary>
/// Source range for function.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusSourceRange
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)]
    public string FilePath;             // Source file
    public uint StartLine;              // Start line
    public uint EndLine;                // End line
    public uint StartColumn;            // Start column
    public uint EndColumn;              // End column
    public ulong StartAddress;          // Start code address
    public ulong EndAddress;            // End code address
}

/// <summary>
/// Source function information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusSourceFunction
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string Name;                 // Function name
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)]
    public string Signature;            // Full signature
    public ulong Address;               // Function address
    public nuint Size;                  // Function size
    public uint StartLine;              // First line
    public uint EndLine;                // Last line
    public uint IsPublic;               // Is public symbol
    public uint IsStatic;               // Is static
    public uint IsInlined;              // Has inlined instances
}

/// <summary>
/// Inline frame information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusInlineFrame
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string FunctionName;         // Inlined function
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)]
    public string FilePath;             // Source file
    public uint LineNumber;             // Line number
    public uint ColumnNumber;           // Column
    public ulong CallSiteAddress;       // Where it was inlined
    public uint InlineDepth;            // Nesting depth
}

/// <summary>
/// Source context (lines around address).
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusSourceContext
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)]
    public string FilePath;             // Source file
    public uint FirstLine;              // First line number
    public uint LastLine;               // Last line number
    public uint CurrentLine;            // Line of address
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 4096)]
    public string Content;              // Source text
    public uint HasSource;              // Source was loaded
}

/// <summary>
/// PDB information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusPdbInfo
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)]
    public string Path;                 // PDB file path
    public Guid Guid;                   // PDB GUID
    public uint Age;                    // PDB age
    public uint IsLoaded;               // PDB is loaded
    public uint IsStripped;             // Symbols stripped
    public uint HasSource;              // Has source info
    public uint HasLines;               // Has line info
    public uint HasPublics;             // Has public symbols
    public uint HasGlobals;             // Has global symbols
    public uint HasTypes;               // Has type info
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string Format;               // PDB format version
}

/// <summary>
/// Source server information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusSourceServerInfo
{
    public uint HasSrcSrv;              // Has source server data
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string ServerType;           // Server type (http, vsts, etc)
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)]
    public string ServerUrl;            // Server URL
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string Version;              // Version control system
    public uint FileCount;              // Files in index
}

/// <summary>
/// Compiland (object file) information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusCompilandInfo
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string Name;                 // Object file name
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string Language;             // Source language
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string Compiler;             // Compiler name
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
    public string CompilerVersion;      // Compiler version
    public uint FunctionCount;          // Functions from this obj
    public uint SourceFileCount;        // Source files
    public uint HasLineInfo;            // Has line numbers
}

#endregion
