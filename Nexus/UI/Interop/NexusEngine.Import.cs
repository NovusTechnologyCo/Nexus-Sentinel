// <file>
// <summary>
// P/Invoke bindings for import/export table reconstruction. Rebuilds IAT entries from
// runtime state, reconstructs import directories for dumped modules, and handles export
// table enumeration and modification.
// </summary>
// </file>

using System.Runtime.InteropServices;

namespace Nexus.UI.Interop;

public static partial class NexusEngine
{
    #region Import Table Access

    /// <summary>
    /// Initialize import reconstructor.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ImportInit(
        IntPtr processHandle,
        ulong moduleBase,
        out IntPtr importHandle);

    /// <summary>
    /// Initialize import reconstructor from file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_ImportInitFile(
        string filePath,
        out IntPtr importHandle);

    /// <summary>
    /// Destroy import reconstructor.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern void Nexus_ImportDestroy(IntPtr importHandle);

    /// <summary>
    /// Get imported modules.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ImportGetModules(
        IntPtr importHandle,
        [In, Out] NexusImportModule[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Get imports from a specific module.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_ImportGetFunctions(
        IntPtr importHandle,
        string moduleName,
        [In, Out] NexusImportFunction[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Get all imports.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ImportGetAll(
        IntPtr importHandle,
        [In, Out] NexusImportFunction[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Get import statistics.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ImportGetStats(
        IntPtr importHandle,
        out NexusImportStats stats);

    #endregion

    #region IAT Scanning

    /// <summary>
    /// Scan IAT for imports.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ImportScanIat(
        IntPtr importHandle,
        ulong iatAddress,
        nuint iatSize);

    /// <summary>
    /// Auto-detect IAT location.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ImportAutoDetectIat(
        IntPtr importHandle,
        out ulong iatAddress,
        out nuint iatSize);

    /// <summary>
    /// Resolve single IAT entry.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ImportResolveThunk(
        IntPtr importHandle,
        ulong thunkAddress,
        out NexusImportFunction function);

    /// <summary>
    /// Resolve address to import.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ImportResolveAddress(
        IntPtr importHandle,
        ulong functionAddress,
        out NexusImportFunction function);

    /// <summary>
    /// Fix invalid/unresolved imports.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ImportFixInvalid(
        IntPtr importHandle,
        out uint fixedCount);

    #endregion

    #region Import Modification

    /// <summary>
    /// Add an import.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_ImportAdd(
        IntPtr importHandle,
        string moduleName,
        string functionName,
        ulong thunkAddress);

    /// <summary>
    /// Add import by ordinal.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_ImportAddOrdinal(
        IntPtr importHandle,
        string moduleName,
        ushort ordinal,
        ulong thunkAddress);

    /// <summary>
    /// Remove an import.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ImportRemove(
        IntPtr importHandle,
        ulong thunkAddress);

    /// <summary>
    /// Remove all imports from a module.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_ImportRemoveModule(
        IntPtr importHandle,
        string moduleName);

    /// <summary>
    /// Clear all imports.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ImportClear(IntPtr importHandle);

    #endregion

    #region Import Writing

    /// <summary>
    /// Write import table to file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_ImportWrite(
        IntPtr importHandle,
        string filePath,
        ulong newIatRva);

    /// <summary>
    /// Write import table with options.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_ImportWriteEx(
        IntPtr importHandle,
        string filePath,
        NexusImportWriteOptions options);

    /// <summary>
    /// Get required space for import table.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ImportGetRequiredSize(
        IntPtr importHandle,
        out nuint iatSize,
        out nuint descriptorSize,
        out nuint namesSize);

    #endregion

    #region Export Table Access

    /// <summary>
    /// Initialize export enumerator.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ExportInit(
        IntPtr processHandle,
        ulong moduleBase,
        out IntPtr exportHandle);

    /// <summary>
    /// Initialize export enumerator from file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_ExportInitFile(
        string filePath,
        out IntPtr exportHandle);

    /// <summary>
    /// Destroy export handle.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern void Nexus_ExportDestroy(IntPtr exportHandle);

    /// <summary>
    /// Get export directory info.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ExportGetDirectory(
        IntPtr exportHandle,
        out NexusExportDirectory directory);

    /// <summary>
    /// Get all exports.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ExportGetAll(
        IntPtr exportHandle,
        [In, Out] NexusExportFunction[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Find export by name.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_ExportFindByName(
        IntPtr exportHandle,
        string functionName,
        out NexusExportFunction function);

    /// <summary>
    /// Find export by ordinal.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ExportFindByOrdinal(
        IntPtr exportHandle,
        ushort ordinal,
        out NexusExportFunction function);

    /// <summary>
    /// Find export by address.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ExportFindByAddress(
        IntPtr exportHandle,
        ulong address,
        out NexusExportFunction function);

    #endregion

    #region Export Modification

    /// <summary>
    /// Add an export.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_ExportAdd(
        IntPtr exportHandle,
        string functionName,
        ulong functionRva,
        ushort ordinal);

    /// <summary>
    /// Remove an export by name.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_ExportRemove(
        IntPtr exportHandle,
        string functionName);

    /// <summary>
    /// Remove an export by ordinal.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ExportRemoveOrdinal(
        IntPtr exportHandle,
        ushort ordinal);

    /// <summary>
    /// Rename an export.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_ExportRename(
        IntPtr exportHandle,
        string oldName,
        string newName);

    /// <summary>
    /// Set module name in export directory.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_ExportSetModuleName(
        IntPtr exportHandle,
        string moduleName);

    /// <summary>
    /// Add forwarded export.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_ExportAddForward(
        IntPtr exportHandle,
        string functionName,
        string forwardString,
        ushort ordinal);

    #endregion

    #region Export Writing

    /// <summary>
    /// Write export table to file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_ExportWrite(
        IntPtr exportHandle,
        string filePath,
        ulong newExportRva);

    /// <summary>
    /// Get required space for export table.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ExportGetRequiredSize(
        IntPtr exportHandle,
        out nuint totalSize);

    #endregion
}

#region Import/Export Enums and Structs

/// <summary>
/// Import write options.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusImportWriteOptions
{
    public ulong IatRva;                    // New IAT RVA
    public ulong DescriptorRva;             // Import descriptor RVA (0 = auto)
    public uint CreateNewSection;           // Create new section for imports
    public uint PreserveOriginalIat;        // Keep original IAT intact
    public uint UpdateDataDirectory;        // Update import directory entry
    public uint BindImports;                // Create bound imports
}

/// <summary>
/// Imported module information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusImportModule
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string Name;                     // Module name
    public ulong FirstThunk;                // IAT address
    public ulong OriginalFirstThunk;        // INT address
    public uint FunctionCount;              // Number of imports
    public uint IsBound;                    // Has bound imports
    public uint TimeDateStamp;              // Bound timestamp
    public uint ForwarderChain;             // Forwarder chain
}

/// <summary>
/// Imported function information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusImportFunction
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string ModuleName;               // Containing module
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string FunctionName;             // Function name
    public ushort Ordinal;                  // Import ordinal
    public ushort Hint;                     // Name table hint
    public ulong ThunkAddress;              // IAT entry address
    public ulong ResolvedAddress;           // Resolved function address
    public uint IsByOrdinal;                // Imported by ordinal
    public uint IsForwarded;                // Is forwarded import
    public uint IsValid;                    // Successfully resolved
}

/// <summary>
/// Import table statistics.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusImportStats
{
    public uint ModuleCount;                // Number of imported modules
    public uint FunctionCount;              // Total imported functions
    public uint ByNameCount;                // Imports by name
    public uint ByOrdinalCount;             // Imports by ordinal
    public uint ResolvedCount;              // Successfully resolved
    public uint UnresolvedCount;            // Failed to resolve
    public uint ForwardedCount;             // Forwarded imports
    public ulong IatAddress;                // IAT address
    public nuint IatSize;                   // IAT size
}

/// <summary>
/// Export directory information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusExportDirectory
{
    public uint Characteristics;            // Reserved
    public uint TimeDateStamp;              // Export timestamp
    public ushort MajorVersion;             // Major version
    public ushort MinorVersion;             // Minor version
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string ModuleName;               // Module name
    public uint OrdinalBase;                // Ordinal base
    public uint NumberOfFunctions;          // Total functions
    public uint NumberOfNames;              // Named functions
    public ulong AddressOfFunctions;        // Functions RVA
    public ulong AddressOfNames;            // Names RVA
    public ulong AddressOfNameOrdinals;     // Ordinals RVA
}

/// <summary>
/// Exported function information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusExportFunction
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string Name;                     // Function name
    public ushort Ordinal;                  // Export ordinal
    public ushort NameOrdinal;              // Name table ordinal
    public ulong Address;                   // Function address (RVA)
    public ulong AbsoluteAddress;           // Absolute address
    public uint IsForwarded;                // Is forwarded export
    public uint HasName;                    // Has name (not ordinal-only)
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string ForwardString;            // Forward target (if forwarded)
}

#endregion
