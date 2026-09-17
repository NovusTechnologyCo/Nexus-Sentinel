// <file>
// <summary>
// P/Invoke bindings for PE relocation table management. Read, modify, add, and remove
// base relocation entries. Supports ASLR-aware rebasing for dumped modules.
// </summary>
// </file>

using System.Runtime.InteropServices;

namespace Nexus.UI.Interop;

public static partial class NexusEngine
{
    #region Relocation Table Access

    /// <summary>
    /// Initialize relocator for a PE file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_RelocInit(
        string filePath,
        out IntPtr relocHandle);

    /// <summary>
    /// Initialize relocator from memory.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_RelocInitMem(
        IntPtr processHandle,
        ulong imageBase,
        out IntPtr relocHandle);

    /// <summary>
    /// Destroy relocator handle.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern void Nexus_RelocDestroy(IntPtr relocHandle);

    /// <summary>
    /// Get all relocation entries.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_RelocGetEntries(
        IntPtr relocHandle,
        [In, Out] NexusRelocationEntry[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Get relocation blocks.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_RelocGetBlocks(
        IntPtr relocHandle,
        [In, Out] NexusRelocationBlock[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Get relocation statistics.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_RelocGetStats(
        IntPtr relocHandle,
        out NexusRelocationStats stats);

    #endregion

    #region Relocation Modification

    /// <summary>
    /// Add a new relocation entry.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_RelocAdd(
        IntPtr relocHandle,
        ulong rva,
        NexusRelocationType type);

    /// <summary>
    /// Add multiple relocation entries.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_RelocAddMultiple(
        IntPtr relocHandle,
        [In] NexusRelocationEntry[] entries,
        nuint count);

    /// <summary>
    /// Remove a relocation entry.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_RelocRemove(
        IntPtr relocHandle,
        ulong rva);

    /// <summary>
    /// Remove all relocations in range.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_RelocRemoveRange(
        IntPtr relocHandle,
        ulong startRva,
        ulong endRva);

    /// <summary>
    /// Clear all relocation entries.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_RelocClear(IntPtr relocHandle);

    /// <summary>
    /// Change relocation type.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_RelocChangeType(
        IntPtr relocHandle,
        ulong rva,
        NexusRelocationType newType);

    #endregion

    #region Relocation Application

    /// <summary>
    /// Apply relocations to new base address (in-memory).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_RelocApply(
        IntPtr relocHandle,
        ulong oldBase,
        ulong newBase);

    /// <summary>
    /// Apply relocations to buffer.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_RelocApplyToBuffer(
        IntPtr relocHandle,
        ulong oldBase,
        ulong newBase,
        [In, Out] byte[] buffer,
        nuint bufferSize);

    /// <summary>
    /// Calculate delta for relocation.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_RelocCalculateDelta(
        ulong originalBase,
        ulong newBase,
        out long delta);

    #endregion

    #region Relocation Writing

    /// <summary>
    /// Write relocation table to file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_RelocWrite(
        IntPtr relocHandle,
        string filePath);

    /// <summary>
    /// Write relocation table with options.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_RelocWriteEx(
        IntPtr relocHandle,
        string filePath,
        NexusRelocWriteOptions options);

    /// <summary>
    /// Get required size for relocation table.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_RelocGetRequiredSize(
        IntPtr relocHandle,
        out nuint requiredSize);

    /// <summary>
    /// Export relocations to buffer.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_RelocExport(
        IntPtr relocHandle,
        [In, Out] byte[] buffer,
        nuint bufferSize,
        out nuint bytesWritten);

    #endregion

    #region Relocation Scanning

    /// <summary>
    /// Scan code for missing relocations (heuristic).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_RelocScanForMissing(
        IntPtr relocHandle,
        IntPtr processHandle,
        ulong startAddress,
        nuint size,
        [In, Out] NexusRelocationEntry[]? buffer,
        nuint bufferCount,
        out nuint foundCount);

    /// <summary>
    /// Verify all relocations are valid.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_RelocValidate(
        IntPtr relocHandle,
        IntPtr processHandle,
        [In, Out] NexusRelocationEntry[]? invalidBuffer,
        nuint bufferCount,
        out nuint invalidCount);

    /// <summary>
    /// Find relocations pointing to specific section.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_RelocFindForSection(
        IntPtr relocHandle,
        uint sectionIndex,
        [In, Out] NexusRelocationEntry[]? buffer,
        nuint bufferCount,
        out nuint count);

    #endregion

    #region ASLR Support

    /// <summary>
    /// Check if module has ASLR enabled.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_RelocIsAslrEnabled(
        string filePath,
        out uint isEnabled);

    /// <summary>
    /// Enable/disable ASLR for PE file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_RelocSetAslr(
        string filePath,
        uint enable);

    /// <summary>
    /// Check if dynamic base is supported.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_RelocHasDynamicBase(
        string filePath,
        out uint hasDynamicBase);

    /// <summary>
    /// Enable/disable high entropy ASLR (64-bit).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_RelocSetHighEntropyAslr(
        string filePath,
        uint enable);

    #endregion
}

#region Relocation Enums and Structs

/// <summary>
/// Relocation type (IMAGE_REL_BASED_*).
/// </summary>
public enum NexusRelocationType : ushort
{
    Absolute = 0,           // No relocation
    High = 1,               // High 16 bits
    Low = 2,                // Low 16 bits
    HighLow = 3,            // Full 32-bit address (x86)
    HighAdj = 4,            // High 16 bits + adjustment
    MipsJmpAddr = 5,        // MIPS jump address
    ArmMov32 = 5,           // ARM MOV32
    RiscvHigh20 = 5,        // RISC-V high 20 bits
    ThumbMov32 = 7,         // ARM Thumb MOV32
    RiscvLow12I = 7,        // RISC-V low 12 bits I-type
    RiscvLow12S = 8,        // RISC-V low 12 bits S-type
    MipsJmpAddr16 = 9,      // MIPS16 jump address
    Dir64 = 10              // Full 64-bit address (x64)
}

/// <summary>
/// Relocation write options.
/// </summary>
[Flags]
public enum NexusRelocWriteOptions : uint
{
    None = 0,
    Optimize = 1,           // Remove duplicate/unnecessary entries
    Sort = 2,               // Sort by RVA
    Align = 4,              // Pad to alignment
    UpdateDirectory = 8,    // Update data directory
    All = 0xFFFFFFFF
}

/// <summary>
/// Single relocation entry.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusRelocationEntry
{
    public ulong Rva;                   // Relative virtual address
    public NexusRelocationType Type;    // Relocation type
    public ushort BlockIndex;           // Block this entry belongs to
    public uint SectionIndex;           // Target section
    public ulong TargetValue;           // Current value at location
}

/// <summary>
/// Relocation block header.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusRelocationBlock
{
    public uint PageRva;                // Page RVA
    public uint BlockSize;              // Block size in bytes
    public uint EntryCount;             // Number of entries in block
    public uint Index;                  // Block index
}

/// <summary>
/// Relocation table statistics.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusRelocationStats
{
    public uint TotalEntries;           // Total relocation entries
    public uint BlockCount;             // Number of blocks
    public uint TableSize;              // Total table size
    public uint AbsoluteCount;          // Padding entries
    public uint HighLowCount;           // 32-bit relocations
    public uint Dir64Count;             // 64-bit relocations
    public uint OtherCount;             // Other types
    public ulong LowestRva;             // Lowest relocated RVA
    public ulong HighestRva;            // Highest relocated RVA
}

#endregion
