// <file>
// <summary>
// P/Invoke bindings for PE file manipulation: add/remove/resize sections, modify
// PE headers, handle overlay data, validate PE structure integrity, and fix checksums.
// </summary>
// </file>

using System.Runtime.InteropServices;

namespace Nexus.UI.Interop;

public static partial class NexusEngine
{
    #region PE Header Access

    /// <summary>
    /// Get PE header data from file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_PeGetData(
        string filePath,
        NexusPeDataField field,
        out ulong value);

    /// <summary>
    /// Set PE header data in file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_PeSetData(
        string filePath,
        NexusPeDataField field,
        ulong value);

    /// <summary>
    /// Get PE header data from memory.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PeGetDataMem(
        IntPtr processHandle,
        ulong imageBase,
        NexusPeDataField field,
        out ulong value);

    /// <summary>
    /// Get full PE headers structure.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_PeGetHeaders(
        string filePath,
        out NexusPeHeaders headers);

    /// <summary>
    /// Get full PE headers from memory.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PeGetHeadersMem(
        IntPtr processHandle,
        ulong imageBase,
        out NexusPeHeaders headers);

    #endregion

    #region Section Management

    /// <summary>
    /// Get section information.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_PeGetSections(
        string filePath,
        [In, Out] NexusPeSection[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Get section at RVA.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_PeGetSectionAtRva(
        string filePath,
        ulong rva,
        out NexusPeSection section);

    /// <summary>
    /// Add a new section to PE file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_PeAddSection(
        string filePath,
        [MarshalAs(UnmanagedType.LPStr)] string sectionName,
        nuint virtualSize,
        nuint rawSize,
        uint characteristics);

    /// <summary>
    /// Add section with data.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_PeAddSectionEx(
        string filePath,
        [MarshalAs(UnmanagedType.LPStr)] string sectionName,
        [In] byte[] data,
        nuint dataSize,
        uint characteristics);

    /// <summary>
    /// Delete the last section.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_PeDeleteLastSection(
        string filePath);

    /// <summary>
    /// Resize the last section.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_PeResizeLastSection(
        string filePath,
        nuint newSize,
        uint isSizeRaw);

    /// <summary>
    /// Set section characteristics.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_PeSetSectionCharacteristics(
        string filePath,
        uint sectionIndex,
        uint characteristics);

    /// <summary>
    /// Rename a section.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_PeRenameSection(
        string filePath,
        uint sectionIndex,
        [MarshalAs(UnmanagedType.LPStr)] string newName);

    /// <summary>
    /// Make all sections RWX.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_PeMakeAllSectionsRwx(
        string filePath);

    /// <summary>
    /// Merge sections (combine multiple into one).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_PeMergeSections(
        string filePath,
        uint firstSection,
        uint lastSection,
        [MarshalAs(UnmanagedType.LPStr)] string newName);

    #endregion

    #region Overlay Management

    /// <summary>
    /// Find overlay data in PE file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_PeFindOverlay(
        string filePath,
        out ulong overlayOffset,
        out nuint overlaySize);

    /// <summary>
    /// Extract overlay to file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_PeExtractOverlay(
        string filePath,
        string outputPath);

    /// <summary>
    /// Add overlay from file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_PeAddOverlay(
        string filePath,
        string overlayPath);

    /// <summary>
    /// Add overlay from buffer.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_PeAddOverlayData(
        string filePath,
        [In] byte[] data,
        nuint dataSize);

    /// <summary>
    /// Remove overlay from PE file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_PeRemoveOverlay(
        string filePath);

    #endregion

    #region PE Validation

    /// <summary>
    /// Check if file is valid PE.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_PeIsValid(
        string filePath,
        out uint isValid);

    /// <summary>
    /// Extended PE validation with details.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_PeValidate(
        string filePath,
        out NexusPeValidation validation);

    /// <summary>
    /// Check if PE is 64-bit.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_PeIs64Bit(
        string filePath,
        out uint is64Bit);

    /// <summary>
    /// Check if PE is DLL.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_PeIsDll(
        string filePath,
        out uint isDll);

    /// <summary>
    /// Check if PE is .NET assembly.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_PeIsDotNet(
        string filePath,
        out uint isDotNet);

    /// <summary>
    /// Fix broken PE file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_PeFixBroken(
        string filePath,
        NexusPeFixOptions options);

    #endregion

    #region PE Conversion

    /// <summary>
    /// Convert RVA to file offset.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_PeRvaToOffset(
        string filePath,
        ulong rva,
        out ulong offset);

    /// <summary>
    /// Convert file offset to RVA.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_PeOffsetToRva(
        string filePath,
        ulong offset,
        out ulong rva);

    /// <summary>
    /// Convert VA to RVA.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PeVaToRva(
        ulong imageBase,
        ulong va,
        out ulong rva);

    /// <summary>
    /// Convert RVA to VA.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PeRvaToVa(
        ulong imageBase,
        ulong rva,
        out ulong va);

    #endregion

    #region Data Directory

    /// <summary>
    /// Get data directory information.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_PeGetDataDirectory(
        string filePath,
        NexusPeDirectory directory,
        out ulong rva,
        out uint size);

    /// <summary>
    /// Set data directory information.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_PeSetDataDirectory(
        string filePath,
        NexusPeDirectory directory,
        ulong rva,
        uint size);

    /// <summary>
    /// Clear a data directory.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_PeClearDataDirectory(
        string filePath,
        NexusPeDirectory directory);

    #endregion

    #region Checksum and Timestamp

    /// <summary>
    /// Calculate PE checksum.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_PeCalculateChecksum(
        string filePath,
        out uint checksum);

    /// <summary>
    /// Fix PE checksum.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_PeFixChecksum(
        string filePath);

    /// <summary>
    /// Set PE timestamp.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_PeSetTimestamp(
        string filePath,
        uint timestamp);

    /// <summary>
    /// Get PE timestamp.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_PeGetTimestamp(
        string filePath,
        out uint timestamp);

    #endregion
}

#region PE Manipulation Enums and Structs

/// <summary>
/// PE header data fields.
/// </summary>
public enum NexusPeDataField : uint
{
    // DOS Header
    MagicDos = 0,
    PeHeaderOffset = 1,

    // File Header
    Machine = 10,
    NumberOfSections = 11,
    TimeDateStamp = 12,
    PointerToSymbolTable = 13,
    NumberOfSymbols = 14,
    SizeOfOptionalHeader = 15,
    Characteristics = 16,

    // Optional Header
    Magic = 20,
    MajorLinkerVersion = 21,
    MinorLinkerVersion = 22,
    SizeOfCode = 23,
    SizeOfInitializedData = 24,
    SizeOfUninitializedData = 25,
    AddressOfEntryPoint = 26,
    BaseOfCode = 27,
    BaseOfData = 28,         // PE32 only
    ImageBase = 29,
    SectionAlignment = 30,
    FileAlignment = 31,
    MajorOperatingSystemVersion = 32,
    MinorOperatingSystemVersion = 33,
    MajorImageVersion = 34,
    MinorImageVersion = 35,
    MajorSubsystemVersion = 36,
    MinorSubsystemVersion = 37,
    Win32VersionValue = 38,
    SizeOfImage = 39,
    SizeOfHeaders = 40,
    CheckSum = 41,
    Subsystem = 42,
    DllCharacteristics = 43,
    SizeOfStackReserve = 44,
    SizeOfStackCommit = 45,
    SizeOfHeapReserve = 46,
    SizeOfHeapCommit = 47,
    LoaderFlags = 48,
    NumberOfRvaAndSizes = 49
}

/// <summary>
/// PE data directory indices.
/// </summary>
public enum NexusPeDirectory : uint
{
    Export = 0,
    Import = 1,
    Resource = 2,
    Exception = 3,
    Security = 4,
    Relocation = 5,
    Debug = 6,
    Architecture = 7,
    GlobalPtr = 8,
    Tls = 9,
    LoadConfig = 10,
    BoundImport = 11,
    Iat = 12,
    DelayImport = 13,
    ComDescriptor = 14,
    Reserved = 15
}

/// <summary>
/// PE fix options.
/// </summary>
[Flags]
public enum NexusPeFixOptions : uint
{
    None = 0,
    FixHeaders = 1,
    FixChecksum = 2,
    FixSizeOfImage = 4,
    FixSectionAlignment = 8,
    FixEntryPoint = 16,
    RemoveInvalidDirs = 32,
    All = 0xFFFFFFFF
}

/// <summary>
/// Section characteristics.
/// </summary>
[Flags]
public enum NexusSectionFlags : uint
{
    TypeNoPad = 0x00000008,
    ContainsCode = 0x00000020,
    ContainsInitializedData = 0x00000040,
    ContainsUninitializedData = 0x00000080,
    LinkInfo = 0x00000200,
    LinkRemove = 0x00000800,
    LinkComdat = 0x00001000,
    NoDeferSpecExc = 0x00004000,
    GlobalRel = 0x00008000,
    MemPurgeable = 0x00020000,
    MemLocked = 0x00040000,
    MemPreload = 0x00080000,
    Align1Bytes = 0x00100000,
    Align2Bytes = 0x00200000,
    Align4Bytes = 0x00300000,
    Align8Bytes = 0x00400000,
    Align16Bytes = 0x00500000,
    Align32Bytes = 0x00600000,
    Align64Bytes = 0x00700000,
    Align128Bytes = 0x00800000,
    Align256Bytes = 0x00900000,
    Align512Bytes = 0x00A00000,
    Align1024Bytes = 0x00B00000,
    Align2048Bytes = 0x00C00000,
    Align4096Bytes = 0x00D00000,
    Align8192Bytes = 0x00E00000,
    LinkRelocOverflow = 0x01000000,
    MemDiscardable = 0x02000000,
    MemNotCached = 0x04000000,
    MemNotPaged = 0x08000000,
    MemShared = 0x10000000,
    MemExecute = 0x20000000,
    MemRead = 0x40000000,
    MemWrite = 0x80000000
}

/// <summary>
/// PE headers structure.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusPeHeaders
{
    public ushort Machine;              // Target machine
    public ushort NumberOfSections;     // Section count
    public uint TimeDateStamp;          // Build timestamp
    public uint Characteristics;        // File characteristics
    public ushort Magic;                // PE32 or PE32+
    public ulong ImageBase;             // Preferred load address
    public uint SectionAlignment;       // Section alignment
    public uint FileAlignment;          // File alignment
    public uint SizeOfImage;            // Total image size
    public uint SizeOfHeaders;          // Headers size
    public uint AddressOfEntryPoint;    // Entry point RVA
    public uint BaseOfCode;             // Code section RVA
    public uint CheckSum;               // PE checksum
    public ushort Subsystem;            // Target subsystem
    public ushort DllCharacteristics;   // DLL flags
    public uint Is64Bit;                // 1 if PE32+
}

/// <summary>
/// PE section information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusPeSection
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 9)]
    public string Name;                 // Section name (8 chars max)
    public uint VirtualSize;            // Size in memory
    public uint VirtualAddress;         // RVA in memory
    public uint SizeOfRawData;          // Size on disk
    public uint PointerToRawData;       // Offset on disk
    public uint Characteristics;        // Section flags
    public uint Index;                  // Section index
}

/// <summary>
/// PE validation result.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusPeValidation
{
    public uint IsValid;                // Overall validity
    public uint HasValidDosHeader;      // DOS header OK
    public uint HasValidPeSignature;    // PE signature OK
    public uint HasValidOptionalHeader; // Optional header OK
    public uint HasValidSections;       // Sections valid
    public uint HasValidEntryPoint;     // Entry point in valid section
    public uint HasValidChecksum;       // Checksum matches
    public uint HasOverlay;             // Has overlay data
    public uint Is64Bit;                // Is PE32+
    public uint IsDll;                  // Is DLL
    public uint IsDriver;               // Is driver
    public uint IsDotNet;               // Is .NET assembly
    public uint IsSigned;               // Has digital signature
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string ErrorMessage;         // Validation error (if any)
}

#endregion
