// <file>
// <summary>
// P/Invoke bindings for PE parsing, pattern scanning, code cave detection, and utility APIs.
// Includes PE header reading, section enumeration, import/export listing, AOB (array of bytes)
// pattern scanning, code cave discovery, and general helper functions.
// </summary>
// </file>

using System.Runtime.InteropServices;

namespace Nexus.UI.Interop;

/// <summary>
/// P/Invoke declarations for PE parsing, pattern scanning, code caves, and utilities.
/// </summary>
public static partial class NexusEngine
{
    #region PE Parsing

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_GetModuleExports(
        IntPtr handle,
        ulong moduleBase,
        [In, Out] NexusExportInfo[]? buffer,
        nuint bufferCount,
        out nuint exportCount);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_GetModuleSections(
        IntPtr handle,
        ulong moduleBase,
        [In, Out] NexusSectionInfo[]? buffer,
        nuint bufferCount,
        out nuint sectionCount);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_GetModuleImports(
        IntPtr handle,
        ulong moduleBase,
        [In, Out] NexusImportInfo[]? buffer,
        nuint bufferCount,
        out nuint importCount);

    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_FindExportByName(
        IntPtr handle,
        ulong moduleBase,
        string exportName,
        out NexusExportInfo exportInfo);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_FindExportByOrdinal(
        IntPtr handle,
        ulong moduleBase,
        uint ordinal,
        out NexusExportInfo exportInfo);

    #endregion

    #region Code Cave Scanner

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ScanCodeCaves(
        IntPtr process,
        ref NexusCodeCaveScanConfig config,
        [In, Out] NexusCodeCaveEntry[]? results,
        nuint maxResults,
        out nuint resultCount);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ScanCodeCavesEx(
        IntPtr process,
        ref NexusCodeCaveScanConfig config,
        [In, Out] NexusCodeCaveEntry[]? results,
        nuint maxResults,
        out nuint resultCount,
        out NexusCodeCaveScanStats stats);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_FindBestCodeCave(
        IntPtr process,
        nuint requiredSize,
        ulong nearAddress,
        long maxDistance,
        out NexusCodeCaveEntry cave);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_GetCodeCaveScanDefaultConfig(
        out NexusCodeCaveScanConfig config);

    #endregion

    #region Pattern Scanning

    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_PatternScan(
        IntPtr process,
        string pattern,
        ulong startAddress,
        ulong endAddress,
        uint options,
        [In, Out] ulong[]? results,
        nuint maxResults,
        out nuint resultCount);

    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_PatternScanModule(
        IntPtr process,
        string pattern,
        string moduleName,
        uint options,
        [In, Out] ulong[]? results,
        nuint maxResults,
        out nuint resultCount);

    #endregion

    #region Address Resolution

    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_ResolveAddressExpression(
        IntPtr process,
        string expression,
        out ulong address);

    #endregion

    #region Type Detection

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_GuessValueType(
        IntPtr process,
        ulong address,
        out NexusGuessedType result);

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_AutoAnalyzeStructure(
        IntPtr process,
        ulong baseAddress,
        nuint size,
        [In, Out] NexusGuessedField[]? fields,
        nuint maxFields,
        out nuint fieldCount);

    #endregion

    #region Memory Dump

    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_DumpMemoryRegion(
        IntPtr process,
        ulong address,
        nuint size,
        string filePath);

    // Nexus_DumpModule is defined in NexusEngine.Dumper.cs

    #endregion

    #region Fill Memory (with protection handling)

    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_FillMemory(
        IntPtr process,
        ulong address,
        nuint size,
        byte fillByte);

    #endregion

    #region Helper Methods

    /// <summary>
    /// Get all imports for a module using the engine API.
    /// </summary>
    public static NexusImportInfo[] GetModuleImports(IntPtr processHandle, ulong moduleBase)
    {
        // First call to get count
        Nexus_GetModuleImports(processHandle, moduleBase, null, 0, out nuint count);
        if (count == 0) return [];

        var imports = new NexusImportInfo[count];
        var result = Nexus_GetModuleImports(processHandle, moduleBase, imports, count, out _);
        return result == NexusResult.OK ? imports : [];
    }

    /// <summary>
    /// Get all exports for a module using the engine API.
    /// </summary>
    public static NexusExportInfo[] GetModuleExports(IntPtr processHandle, ulong moduleBase)
    {
        // First call to get count
        Nexus_GetModuleExports(processHandle, moduleBase, null, 0, out nuint count);
        if (count == 0) return [];

        var exports = new NexusExportInfo[count];
        var result = Nexus_GetModuleExports(processHandle, moduleBase, exports, count, out _);
        return result == NexusResult.OK ? exports : [];
    }

    /// <summary>
    /// Get all sections for a module using the engine API.
    /// </summary>
    public static NexusSectionInfo[] GetModuleSections(IntPtr processHandle, ulong moduleBase)
    {
        // First call to get count
        Nexus_GetModuleSections(processHandle, moduleBase, null, 0, out nuint count);
        if (count == 0) return [];

        var sections = new NexusSectionInfo[count];
        var result = Nexus_GetModuleSections(processHandle, moduleBase, sections, count, out _);
        return result == NexusResult.OK ? sections : [];
    }

    /// <summary>
    /// Scan for code caves in process memory.
    /// </summary>
    public static NexusCodeCaveEntry[] ScanCodeCaves(IntPtr processHandle, int minSize = 16, bool executableOnly = true, bool modulesOnly = false)
    {
        Nexus_GetCodeCaveScanDefaultConfig(out var config);
        config.MinSize = (nuint)minSize;
        config.Options = 0;
        if (executableOnly) config.Options |= 0x0001; // NEXUS_CAVE_OPT_EXECUTABLE
        if (modulesOnly) config.Options |= 0x0004;    // NEXUS_CAVE_OPT_MODULE_ONLY

        // First call to get count
        Nexus_ScanCodeCaves(processHandle, ref config, null, 0, out nuint count);
        if (count == 0) return [];

        var caves = new NexusCodeCaveEntry[Math.Min((int)count, 10000)];
        var result = Nexus_ScanCodeCaves(processHandle, ref config, caves, (nuint)caves.Length, out nuint actualCount);
        if (result != NexusResult.OK) return [];

        return caves[..(int)actualCount];
    }

    /// <summary>
    /// Pattern scan with wildcard support.
    /// Pattern format: "DE AD ?? EF" or "DEAD??EF" (wildcards: ??, **, *)
    /// </summary>
    public static ulong[] PatternScan(IntPtr processHandle, string pattern, ulong startAddress = 0, ulong endAddress = 0, int maxResults = 100)
    {
        var results = new ulong[maxResults];
        var result = Nexus_PatternScan(processHandle, pattern, startAddress, endAddress, 0, results, (nuint)maxResults, out nuint count);
        if (result != NexusResult.OK) return [];
        return results[..(int)count];
    }

    /// <summary>
    /// Pattern scan within a specific module.
    /// </summary>
    public static ulong[] PatternScanModule(IntPtr processHandle, string pattern, string moduleName, int maxResults = 100)
    {
        var results = new ulong[maxResults];
        var result = Nexus_PatternScanModule(processHandle, pattern, moduleName, 0, results, (nuint)maxResults, out nuint count);
        if (result != NexusResult.OK) return [];
        return results[..(int)count];
    }

    /// <summary>
    /// Resolve an address expression like "kernel32+0x1234" or "[rax+10]".
    /// </summary>
    public static ulong? ResolveAddressExpression(IntPtr processHandle, string expression)
    {
        var result = Nexus_ResolveAddressExpression(processHandle, expression, out ulong address);
        return result == NexusResult.OK ? address : null;
    }

    /// <summary>
    /// Fill memory with a byte value, handling protection changes.
    /// </summary>
    public static bool FillMemory(IntPtr processHandle, ulong address, ulong size, byte fillByte)
    {
        return Nexus_FillMemory(processHandle, address, (nuint)size, fillByte) == NexusResult.OK;
    }

    /// <summary>
    /// Dump a memory region to file.
    /// </summary>
    public static bool DumpMemory(IntPtr processHandle, ulong address, int size, string filePath)
    {
        return Nexus_DumpMemoryRegion(processHandle, address, (nuint)size, filePath) == NexusResult.OK;
    }

    /// <summary>
    /// Dump an entire module to file.
    /// </summary>
    public static bool DumpModule(IntPtr processHandle, ulong moduleBase, string filePath)
    {
        return Nexus_DumpModule(processHandle, moduleBase, filePath) == NexusResult.OK;
    }

    #endregion
}

#region PE Structures

/// <summary>
/// Export information structure.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusExportInfo
{
    public ulong Address;           // RVA of the export
    public uint Ordinal;            // Export ordinal
    public uint IsForwarded;        // 1 if forwarded to another DLL
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string Name;             // Export name
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string ForwardName;      // Forwarded name (DLL.Function)
}

/// <summary>
/// Section information structure.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusSectionInfo
{
    public ulong VirtualAddress;    // RVA of section
    public ulong VirtualSize;       // Virtual size
    public ulong RawAddress;        // File offset
    public ulong RawSize;           // Size in file
    public uint Characteristics;    // Section flags
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 16)]
    public string Name;             // Section name

    /// <summary>Section is executable.</summary>
    public readonly bool IsExecutable => (Characteristics & 0x20000000) != 0;
    /// <summary>Section is readable.</summary>
    public readonly bool IsReadable => (Characteristics & 0x40000000) != 0;
    /// <summary>Section is writable.</summary>
    public readonly bool IsWritable => (Characteristics & 0x80000000) != 0;
    /// <summary>Section contains code.</summary>
    public readonly bool ContainsCode => (Characteristics & 0x00000020) != 0;
    /// <summary>Section contains initialized data.</summary>
    public readonly bool ContainsData => (Characteristics & 0x00000040) != 0;
}

/// <summary>
/// Import information structure.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusImportInfo
{
    public ulong IatAddress;        // Address in IAT
    public uint Ordinal;            // Import ordinal (0 if by name)
    public uint IsOrdinal;          // 1 if imported by ordinal
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string ModuleName;       // DLL name
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string FunctionName;     // Function name
}

#endregion

#region Code Cave Structures

/// <summary>
/// Code cave fill byte type.
/// </summary>
public enum NexusCodeCaveFillType
{
    Zeros = 0,      // Scan for 00 bytes
    Nops = 1,       // Scan for 90 (NOP) bytes
    Ints = 2,       // Scan for CC (INT3) bytes
    AnyFill = 3     // Any repeating byte pattern
}

/// <summary>
/// Code cave scan options.
/// </summary>
[Flags]
public enum NexusCodeCaveOptions : uint
{
    None = 0,
    Executable = 0x0001,        // Only scan executable regions
    Writable = 0x0002,          // Only scan writable regions
    ModuleOnly = 0x0004,        // Only scan within modules
    Private = 0x0008,           // Only scan private memory
    Align16 = 0x0010,           // Align results to 16-byte boundary
    NearAddress = 0x0020        // Prefer caves near a target address
}

/// <summary>
/// Code cave result entry.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusCodeCaveEntry
{
    public ulong Address;           // Starting address of the cave
    public nuint Size;              // Size of the cave in bytes
    public byte FillByte;           // The fill byte found (00, 90, CC, etc.)
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
    public byte[] Reserved;
    public uint Protection;         // Memory protection flags
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string ModuleName;       // Module name if within a module
    public ulong ModuleBase;        // Module base address
}

/// <summary>
/// Code cave scan configuration.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusCodeCaveScanConfig
{
    public nuint MinSize;           // Minimum cave size in bytes (default: 16)
    public nuint MaxSize;           // Maximum cave size to report (0 = unlimited)
    public uint FillType;           // NexusCodeCaveFillType
    public uint Options;            // NexusCodeCaveOptions
    public ulong StartAddress;      // Start address (0 = process start)
    public ulong EndAddress;        // End address (0 = process end)
    public ulong NearAddress;       // Target address for NEAR_ADDRESS option
    public long MaxDistance;        // Max distance from nearAddress
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string ModuleFilter;     // Only scan this module (empty = all)
}

/// <summary>
/// Code cave scan statistics.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusCodeCaveScanStats
{
    public ulong BytesScanned;      // Total bytes scanned
    public nuint RegionsScanned;    // Memory regions scanned
    public nuint CavesFound;        // Total caves found
    public nuint TotalCaveBytes;    // Total bytes in all caves
    public nuint LargestCave;       // Size of largest cave
    public double ElapsedMs;        // Scan time in milliseconds
}

#endregion

#region Type Detection Structures

/// <summary>
/// Guessed value type result.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusGuessedType
{
    public int PrimaryType;         // Most likely type (NexusScanValueType)
    public int SecondaryType;       // Alternative type
    public float Confidence;        // Confidence level (0.0 - 1.0)
    public uint Flags;              // Detection flags

    /// <summary>Might be a pointer.</summary>
    public readonly bool MightBePointer => (Flags & 0x0001) != 0;
    /// <summary>Might be a float.</summary>
    public readonly bool MightBeFloat => (Flags & 0x0002) != 0;
    /// <summary>Is likely a string.</summary>
    public readonly bool MightBeString => (Flags & 0x0004) != 0;
    /// <summary>Value is zero/null.</summary>
    public readonly bool IsZero => (Flags & 0x0008) != 0;
}

/// <summary>
/// Auto-analyzed structure field.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusGuessedField
{
    public uint Offset;             // Offset from base address
    public int Type;                // Guessed type (NexusScanValueType)
    public uint Size;               // Size in bytes
    public float Confidence;        // Confidence level
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string Comment;          // Description/comment
}

#endregion
