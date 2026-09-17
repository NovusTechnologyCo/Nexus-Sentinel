// <file>
// <summary>
// P/Invoke bindings for process dumping: dump full process image, individual modules,
// or arbitrary memory regions to disk as PE files with optional import reconstruction.
// </summary>
// </file>

using System.Runtime.InteropServices;

namespace Nexus.UI.Interop;

public static partial class NexusEngine
{
    #region Process Dumping

    /// <summary>
    /// Dump entire process to disk.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_DumpProcess(
        IntPtr processHandle,
        ulong imageBase,
        string dumpFileName,
        ulong entryPoint);

    /// <summary>
    /// Dump process with advanced options.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_DumpProcessEx(
        IntPtr processHandle,
        ulong imageBase,
        string dumpFileName,
        ulong entryPoint,
        NexusDumpOptions options);

    /// <summary>
    /// Dump a specific module.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_DumpModule(
        IntPtr processHandle,
        ulong moduleBase,
        string dumpFileName);

    /// <summary>
    /// Dump memory region to file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_DumpMemory(
        IntPtr processHandle,
        ulong startAddress,
        nuint size,
        string dumpFileName);

    /// <summary>
    /// Dump multiple memory regions to file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_DumpRegions(
        IntPtr processHandle,
        [In] NexusDumpRegion[] regions,
        nuint regionCount,
        string dumpFileName);

    /// <summary>
    /// Dump memory to buffer.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_DumpMemoryToBuffer(
        IntPtr processHandle,
        ulong startAddress,
        nuint size,
        [In, Out] byte[] buffer,
        out nuint bytesWritten);

    #endregion

    #region PE Reconstruction

    /// <summary>
    /// Fix dump headers after dumping.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_DumpFixHeaders(
        string dumpFileName);

    /// <summary>
    /// Realign PE sections after dump.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_DumpRealignSections(
        string dumpFileName,
        uint fileAlignment);

    /// <summary>
    /// Fix section permissions after dump.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_DumpFixSectionPermissions(
        string dumpFileName);

    /// <summary>
    /// Set new entry point in dumped file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_DumpSetEntryPoint(
        string dumpFileName,
        ulong entryPointRva);

    /// <summary>
    /// Strip overlay from dumped file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_DumpStripOverlay(
        string dumpFileName);

    /// <summary>
    /// Wipe section headers names (anti-analysis).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_DumpWipeSectionNames(
        string dumpFileName);

    #endregion

    #region Import Reconstruction

    /// <summary>
    /// Find imports in dumped process.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_DumpFindImports(
        IntPtr processHandle,
        ulong imageBase,
        out IntPtr importHandle);

    /// <summary>
    /// Destroy import reconstruction handle.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern void Nexus_DumpImportDestroy(IntPtr importHandle);

    /// <summary>
    /// Get discovered imports.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_DumpGetImports(
        IntPtr importHandle,
        [In, Out] NexusDumpImport[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Fix single import thunk.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_DumpFixImport(
        IntPtr importHandle,
        ulong thunkAddress,
        ulong resolvedAddress);

    /// <summary>
    /// Write fixed imports to file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_DumpWriteImports(
        IntPtr importHandle,
        string dumpFileName,
        ulong iatRva,
        ulong importDirectoryRva);

    /// <summary>
    /// Auto-fix imports using known module exports.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_DumpAutoFixImports(
        IntPtr importHandle,
        out uint fixedCount,
        out uint unresolvedCount);

    #endregion

    #region OEP Finding

    /// <summary>
    /// Trace to original entry point.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_DumpFindOep(
        IntPtr debuggerHandle,
        NexusOepMethod method,
        uint timeout,
        out ulong oepAddress);

    /// <summary>
    /// Set OEP heuristic parameters.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_DumpSetOepHeuristics(
        IntPtr debuggerHandle,
        NexusOepHeuristics heuristics);

    /// <summary>
    /// Get OEP detection status.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_DumpGetOepStatus(
        IntPtr debuggerHandle,
        out NexusOepStatus status);

    #endregion

    #region Unpacker Support

    /// <summary>
    /// Detect packer/protector.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_DumpDetectPacker(
        IntPtr processHandle,
        ulong imageBase,
        out NexusPackerInfo packerInfo);

    /// <summary>
    /// Apply unpacker-specific fixes.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_DumpApplyUnpackerFix(
        string dumpFileName,
        NexusPackerType packerType);

    /// <summary>
    /// Rebuild unpacked executable.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_DumpRebuildExecutable(
        string dumpFileName,
        NexusRebuildOptions options);

    #endregion
}

#region Dumper Enums and Structs

/// <summary>
/// Dump options flags.
/// </summary>
[Flags]
public enum NexusDumpOptions : uint
{
    None = 0,
    FixHeaders = 1,             // Fix PE headers
    RealignSections = 2,        // Realign section data
    FixImports = 4,             // Attempt import reconstruction
    StripOverlay = 8,           // Remove overlay data
    WipeSectionNames = 16,      // Clear section names
    PreserveTimestamp = 32,     // Keep original timestamp
    CompressSections = 64,      // Compress section data
    IncludeResources = 128,     // Include resource section
    SkipInvalidSections = 256,  // Skip unmapped sections
    All = 0xFFFFFFFF
}

/// <summary>
/// OEP detection method.
/// </summary>
public enum NexusOepMethod : uint
{
    None = 0,
    SingleStep = 1,             // Single-step until OEP pattern
    BreakOnAccess = 2,          // Break on code section access
    BreakOnEntry = 3,           // Break on entry code pattern
    ApiMonitor = 4,             // Monitor API calls for OEP hint
    Custom = 5                  // Custom detection script
}

/// <summary>
/// Packer/protector type.
/// </summary>
public enum NexusPackerType : uint
{
    Unknown = 0,
    Upx = 1,
    Aspack = 2,
    Fsg = 3,
    Pecompact = 4,
    Petite = 5,
    Nspack = 6,
    Mew = 7,
    Upack = 8,
    Yzpack = 9,
    Themida = 10,
    Vmprotect = 11,
    Obsidium = 12,
    Armadillo = 13,
    Asprotect = 14,
    ExeCryptor = 15,
    DotNet = 16,
    Custom = 255
}

/// <summary>
/// Rebuild options.
/// </summary>
[Flags]
public enum NexusRebuildOptions : uint
{
    None = 0,
    OptimizeSize = 1,           // Minimize file size
    RemoveRelocations = 2,      // Strip relocation data
    RemoveDebugInfo = 4,        // Strip debug directory
    RemoveBoundImports = 8,     // Remove bound imports
    FixChecksum = 16,           // Recalculate PE checksum
    MakeAllRwx = 32,            // Set all sections RWX
    All = 0xFFFFFFFF
}

/// <summary>
/// Memory region for multi-region dump.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusDumpRegion
{
    public ulong StartAddress;          // Region start
    public nuint Size;                  // Region size
    public uint IncludeInDump;          // Include in output
    public uint IsCode;                 // Is code section
}

/// <summary>
/// Discovered import information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusDumpImport
{
    public ulong ThunkAddress;          // Import thunk address
    public ulong ResolvedAddress;       // Resolved function address
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string ModuleName;           // Module name
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string FunctionName;         // Function name
    public ushort Ordinal;              // Import by ordinal
    public uint IsResolved;             // Successfully resolved
    public uint IsForwarded;            // Is forwarded export
}

/// <summary>
/// OEP heuristic parameters.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusOepHeuristics
{
    public uint MaxInstructions;        // Max instructions to trace
    public uint StackThreshold;         // Stack depth threshold
    public uint CodeSectionOnly;        // Only stop in code section
    public uint SkipSystemCalls;        // Skip system API calls
    public ulong MinAddress;            // Minimum valid OEP address
    public ulong MaxAddress;            // Maximum valid OEP address
}

/// <summary>
/// OEP detection status.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusOepStatus
{
    public uint IsSearching;            // Currently searching
    public uint InstructionsTraced;     // Instructions traced so far
    public ulong CurrentAddress;        // Current trace address
    public ulong CandidateOep;          // Best OEP candidate
    public uint Confidence;             // Confidence percentage
    public uint TimeElapsed;            // Time elapsed (ms)
}

/// <summary>
/// Packer detection info.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusPackerInfo
{
    public NexusPackerType Type;        // Detected packer type
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string Name;                 // Packer name
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
    public string Version;              // Packer version (if known)
    public uint Confidence;             // Detection confidence (0-100)
    public uint IsVirtualized;          // Uses virtualization
    public uint HasAntiDebug;           // Has anti-debug
    public uint HasAntiDump;            // Has anti-dump measures
    public ulong EntryPointType;        // Entry point analysis result
}

#endregion
