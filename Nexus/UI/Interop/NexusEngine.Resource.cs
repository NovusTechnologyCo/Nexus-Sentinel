// <file>
// <summary>
// P/Invoke bindings for PE resource handling. Enumerate resource types and entries,
// extract resource data (icons, strings, version info, manifests), and modify or add
// resources in PE files.
// </summary>
// </file>

using System.Runtime.InteropServices;

namespace Nexus.UI.Interop;

public static partial class NexusEngine
{
    #region Resource Loading

    /// <summary>
    /// Load PE file for resource operations.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_ResourceLoad(
        string filePath,
        out IntPtr resourceHandle);

    /// <summary>
    /// Load resources from memory-mapped module.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ResourceLoadMem(
        IntPtr processHandle,
        ulong moduleBase,
        out IntPtr resourceHandle);

    /// <summary>
    /// Unload resource handle.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern void Nexus_ResourceUnload(IntPtr resourceHandle);

    #endregion

    #region Resource Enumeration

    /// <summary>
    /// Get all resource types.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ResourceEnumTypes(
        IntPtr resourceHandle,
        [In, Out] NexusResourceType[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Get resources of a specific type.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ResourceEnumNames(
        IntPtr resourceHandle,
        uint type,
        [In, Out] NexusResourceName[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Get all language versions of a resource.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ResourceEnumLanguages(
        IntPtr resourceHandle,
        uint type,
        uint name,
        [In, Out] NexusResourceLanguage[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Enumerate all resources in the file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ResourceEnumAll(
        IntPtr resourceHandle,
        [In, Out] NexusResourceEntry[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Get resource tree statistics.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ResourceGetStats(
        IntPtr resourceHandle,
        out NexusResourceStats stats);

    #endregion

    #region Resource Access

    /// <summary>
    /// Find a specific resource.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ResourceFind(
        IntPtr resourceHandle,
        uint type,
        uint name,
        ushort language,
        out NexusResourceEntry entry);

    /// <summary>
    /// Find resource by string name.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_ResourceFindByName(
        IntPtr resourceHandle,
        string type,
        string name,
        ushort language,
        out NexusResourceEntry entry);

    /// <summary>
    /// Get resource data.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ResourceGetData(
        IntPtr resourceHandle,
        uint type,
        uint name,
        ushort language,
        [In, Out] byte[]? buffer,
        nuint bufferSize,
        out nuint dataSize);

    /// <summary>
    /// Get resource data by entry.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ResourceGetDataEx(
        IntPtr resourceHandle,
        ref NexusResourceEntry entry,
        [In, Out] byte[]? buffer,
        nuint bufferSize,
        out nuint dataSize);

    #endregion

    #region Resource Extraction

    /// <summary>
    /// Extract resource to file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_ResourceExtract(
        IntPtr resourceHandle,
        uint type,
        uint name,
        ushort language,
        string outputPath);

    /// <summary>
    /// Extract all resources to directory.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_ResourceExtractAll(
        IntPtr resourceHandle,
        string outputDirectory);

    /// <summary>
    /// Extract resources of a specific type.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_ResourceExtractType(
        IntPtr resourceHandle,
        uint type,
        string outputDirectory);

    /// <summary>
    /// Extract icon resources to ICO files.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_ResourceExtractIcons(
        IntPtr resourceHandle,
        string outputDirectory);

    /// <summary>
    /// Extract bitmap resources to BMP files.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_ResourceExtractBitmaps(
        IntPtr resourceHandle,
        string outputDirectory);

    #endregion

    #region Resource Modification

    /// <summary>
    /// Begin resource update transaction.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_ResourceBeginUpdate(
        string filePath,
        out IntPtr updateHandle);

    /// <summary>
    /// Add or replace a resource.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ResourceUpdate(
        IntPtr updateHandle,
        uint type,
        uint name,
        ushort language,
        [In] byte[] data,
        nuint dataSize);

    /// <summary>
    /// Add resource from file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_ResourceUpdateFromFile(
        IntPtr updateHandle,
        uint type,
        uint name,
        ushort language,
        string sourceFile);

    /// <summary>
    /// Delete a resource.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ResourceDelete(
        IntPtr updateHandle,
        uint type,
        uint name,
        ushort language);

    /// <summary>
    /// Delete all resources of a type.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ResourceDeleteType(
        IntPtr updateHandle,
        uint type);

    /// <summary>
    /// Commit resource changes.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ResourceEndUpdate(
        IntPtr updateHandle,
        uint discard);

    #endregion

    #region Version Info

    /// <summary>
    /// Get file version info.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ResourceGetVersionInfo(
        IntPtr resourceHandle,
        out NexusVersionInfo versionInfo);

    /// <summary>
    /// Get string file info.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_ResourceGetVersionString(
        IntPtr resourceHandle,
        string stringName,
        [Out, MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder value,
        nuint valueSize);

    /// <summary>
    /// Get all version strings.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ResourceEnumVersionStrings(
        IntPtr resourceHandle,
        [In, Out] NexusVersionString[]? buffer,
        nuint bufferCount,
        out nuint count);

    #endregion

    #region Manifest

    /// <summary>
    /// Get application manifest XML.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ResourceGetManifest(
        IntPtr resourceHandle,
        [Out, MarshalAs(UnmanagedType.LPStr)] System.Text.StringBuilder manifest,
        nuint manifestSize);

    /// <summary>
    /// Set application manifest.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_ResourceSetManifest(
        IntPtr updateHandle,
        string manifestXml);

    /// <summary>
    /// Remove application manifest.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ResourceRemoveManifest(
        IntPtr updateHandle);

    #endregion
}

#region Resource Enums and Structs

/// <summary>
/// Standard resource types.
/// </summary>
public enum NexusResourceTypeId : uint
{
    Cursor = 1,
    Bitmap = 2,
    Icon = 3,
    Menu = 4,
    Dialog = 5,
    String = 6,
    FontDir = 7,
    Font = 8,
    Accelerator = 9,
    RcData = 10,
    MessageTable = 11,
    GroupCursor = 12,
    GroupIcon = 14,
    Version = 16,
    DlgInclude = 17,
    PlugPlay = 19,
    Vxd = 20,
    AniCursor = 21,
    AniIcon = 22,
    Html = 23,
    Manifest = 24
}

/// <summary>
/// Resource type entry.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusResourceType
{
    public uint Id;                     // Type ID or ordinal
    public uint IsString;               // 1 if name is string
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string Name;                 // Type name (if string)
    public uint NameCount;              // Number of resources of this type
}

/// <summary>
/// Resource name entry.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusResourceName
{
    public uint Id;                     // Name ID or ordinal
    public uint IsString;               // 1 if name is string
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string Name;                 // Resource name (if string)
    public uint LanguageCount;          // Number of language versions
}

/// <summary>
/// Resource language entry.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusResourceLanguage
{
    public ushort LanguageId;           // Language identifier
    public ushort Sublanguage;          // Sublanguage
    public uint Size;                   // Data size
    public uint CodePage;               // Code page
}

/// <summary>
/// Full resource entry.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusResourceEntry
{
    public uint TypeId;                 // Resource type
    public uint NameId;                 // Resource name
    public ushort Language;             // Language ID
    public uint Size;                   // Data size
    public uint Offset;                 // File offset
    public uint Rva;                    // RVA in memory
    public uint CodePage;               // Code page
    public uint IsTypeString;           // Type is string name
    public uint IsNameString;           // Name is string
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string TypeName;             // Type name (if string)
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string NameString;           // Name (if string)
}

/// <summary>
/// Resource statistics.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusResourceStats
{
    public uint TotalTypes;             // Number of resource types
    public uint TotalNames;             // Number of resource names
    public uint TotalEntries;           // Total resource entries
    public uint TotalSize;              // Total resource data size
    public uint HasIcons;               // Contains icons
    public uint HasBitmaps;             // Contains bitmaps
    public uint HasManifest;            // Contains manifest
    public uint HasVersionInfo;         // Contains version info
    public uint HasStrings;             // Contains string tables
    public uint IconCount;              // Number of icons
    public uint BitmapCount;            // Number of bitmaps
}

/// <summary>
/// Version information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusVersionInfo
{
    public ushort FileVersionMajor;     // File version major
    public ushort FileVersionMinor;     // File version minor
    public ushort FileVersionBuild;     // File version build
    public ushort FileVersionRevision;  // File version revision
    public ushort ProductVersionMajor;  // Product version major
    public ushort ProductVersionMinor;  // Product version minor
    public ushort ProductVersionBuild;  // Product version build
    public ushort ProductVersionRevision; // Product version revision
    public uint FileFlagsMask;          // Valid flags
    public uint FileFlags;              // File flags
    public uint FileOs;                 // Target OS
    public uint FileType;               // File type (exe, dll, etc)
    public uint FileSubtype;            // File subtype
    public uint FileDateHigh;           // File date high
    public uint FileDateLow;            // File date low
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string FileVersionString;    // Version as string
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string ProductVersionString; // Product version as string
}

/// <summary>
/// Version string entry.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusVersionString
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string Name;                 // String name
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string Value;                // String value
    public uint Language;               // Language ID
    public uint CodePage;               // Code page
}

#endregion
