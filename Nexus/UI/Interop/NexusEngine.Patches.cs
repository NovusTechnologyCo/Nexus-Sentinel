// <file>
// <summary>
// P/Invoke bindings for the patch manager. Tracks memory modifications (patches) applied
// to the target process, stores original bytes for restoration, and supports enable/disable
// toggling of individual patches.
// </summary>
// </file>

using System.Runtime.InteropServices;

namespace Nexus.UI.Interop;

public static partial class NexusEngine
{
    #region Patch Manager

    /// <summary>
    /// Create a patch manager for a process.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PatchCreate(
        IntPtr processHandle,
        out IntPtr patchHandle);

    /// <summary>
    /// Destroy a patch manager.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern void Nexus_PatchDestroy(IntPtr patchHandle);

    /// <summary>
    /// Apply a patch (write bytes and track the change).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PatchApply(
        IntPtr patchHandle,
        ulong address,
        [In] byte[] newBytes,
        nuint size,
        out ulong patchId);

    /// <summary>
    /// Restore original bytes for a patch.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PatchRestore(
        IntPtr patchHandle,
        ulong patchId);

    /// <summary>
    /// Restore all patches (revert to original state).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PatchRestoreAll(IntPtr patchHandle);

    /// <summary>
    /// Re-apply a previously restored patch.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PatchReapply(
        IntPtr patchHandle,
        ulong patchId);

    /// <summary>
    /// Re-apply all patches.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PatchReapplyAll(IntPtr patchHandle);

    /// <summary>
    /// Delete a patch record (doesn't restore original bytes).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PatchDelete(
        IntPtr patchHandle,
        ulong patchId);

    /// <summary>
    /// Clear all patch records.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PatchClear(IntPtr patchHandle);

    /// <summary>
    /// Get patch information.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PatchGetInfo(
        IntPtr patchHandle,
        ulong patchId,
        out NexusPatchInfo info);

    /// <summary>
    /// Get all patches.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PatchGetList(
        IntPtr patchHandle,
        [In, Out] NexusPatchInfo[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Get patches in an address range.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PatchGetInRange(
        IntPtr patchHandle,
        ulong startAddress,
        ulong endAddress,
        [In, Out] NexusPatchInfo[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Check if an address is patched.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PatchIsPatched(
        IntPtr patchHandle,
        ulong address,
        out uint isPatched);

    /// <summary>
    /// Set patch name/description.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_PatchSetName(
        IntPtr patchHandle,
        ulong patchId,
        string? name);

    /// <summary>
    /// Set patch group for organization.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_PatchSetGroup(
        IntPtr patchHandle,
        ulong patchId,
        string? group);

    #endregion

    #region Patch File Operations

    /// <summary>
    /// Save patches to file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_PatchSave(
        IntPtr patchHandle,
        string filePath,
        NexusPatchFileFormat format);

    /// <summary>
    /// Load patches from file.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_PatchLoad(
        IntPtr patchHandle,
        string filePath,
        uint applyImmediately);

    /// <summary>
    /// Export patches as executable patcher.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_PatchExportPatcher(
        IntPtr patchHandle,
        string outputPath,
        string? targetExeName);

    #endregion

    #region NOP/Fill Operations

    /// <summary>
    /// Fill an address range with NOPs.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PatchNop(
        IntPtr patchHandle,
        ulong address,
        nuint size,
        out ulong patchId);

    /// <summary>
    /// Fill an address range with a byte value.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PatchFill(
        IntPtr patchHandle,
        ulong address,
        nuint size,
        byte fillByte,
        out ulong patchId);

    /// <summary>
    /// Replace a CALL instruction with NOPs.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PatchNopCall(
        IntPtr patchHandle,
        ulong callAddress,
        out ulong patchId);

    /// <summary>
    /// Replace a conditional jump with unconditional or NOP.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PatchJump(
        IntPtr patchHandle,
        ulong jumpAddress,
        NexusJumpPatchType patchType,
        out ulong patchId);

    #endregion

    #region Code Injection

    /// <summary>
    /// Inject code at an address (with trampoline).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PatchInjectCode(
        IntPtr patchHandle,
        ulong address,
        [In] byte[] code,
        nuint codeSize,
        out ulong patchId,
        out ulong trampolineAddress);

    /// <summary>
    /// Create a code cave (allocate memory and redirect).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PatchCreateCodeCave(
        IntPtr patchHandle,
        ulong hookAddress,
        nuint caveSize,
        out ulong patchId,
        out ulong caveAddress);

    /// <summary>
    /// Hook a function (redirect to custom code).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PatchHookFunction(
        IntPtr patchHandle,
        ulong functionAddress,
        ulong hookAddress,
        NexusPatchHookType hookType,
        out ulong patchId,
        out ulong originalAddress);

    #endregion

    #region Comparison/Analysis

    /// <summary>
    /// Compare current memory with original (find all changes).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PatchFindChanges(
        IntPtr patchHandle,
        ulong startAddress,
        ulong endAddress,
        [In, Out] NexusPatchInfo[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Take a snapshot of a memory region for comparison.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PatchSnapshot(
        IntPtr patchHandle,
        ulong startAddress,
        ulong endAddress,
        out ulong snapshotId);

    /// <summary>
    /// Compare current memory with a snapshot.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PatchCompareSnapshot(
        IntPtr patchHandle,
        ulong snapshotId,
        [In, Out] NexusPatchDiff[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Delete a snapshot.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_PatchDeleteSnapshot(
        IntPtr patchHandle,
        ulong snapshotId);

    #endregion
}

#region Patch Enums and Structs

/// <summary>
/// Patch file format.
/// </summary>
public enum NexusPatchFileFormat : uint
{
    Binary = 0,             // Native binary format
    Json = 1,               // JSON format
    Ips = 2,                // IPS patch format
    Ups = 3,                // UPS patch format
    Text = 4                // Human-readable text
}

/// <summary>
/// Jump patch type.
/// </summary>
public enum NexusJumpPatchType : uint
{
    Nop = 0,                // Replace with NOPs (never jump)
    AlwaysJump = 1,         // Make unconditional (always jump)
    InvertCondition = 2     // Invert the condition
}

/// <summary>
/// Patch hook type (for function hooking via patch system).
/// </summary>
public enum NexusPatchHookType : uint
{
    Jmp = 0,                // Direct JMP hook
    Call = 1,               // CALL hook (return to original)
    VTable = 2,             // VTable entry replacement
    Import = 3,             // IAT hook
    Inline = 4              // Inline patch with trampoline
}

/// <summary>
/// Patch state.
/// </summary>
public enum NexusPatchState : uint
{
    Applied = 0,            // Patch is currently applied
    Restored = 1,           // Original bytes restored
    Pending = 2             // Patch defined but not yet applied
}

/// <summary>
/// Patch information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusPatchInfo
{
    public ulong Id;                    // Patch ID
    public ulong Address;               // Patch address
    public nuint Size;                  // Patch size in bytes
    public NexusPatchState State;       // Current state
    public ulong Rva;                   // RVA within module

    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string ModuleName;           // Module name

    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
    public string Name;                 // Patch name/description

    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string Group;                // Patch group

    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
    public byte[] OriginalBytes;        // Original bytes (first 64)

    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
    public byte[] PatchedBytes;         // Patched bytes (first 64)

    public ulong CreatedTime;           // When patch was created
    public ulong AppliedTime;           // When patch was last applied
}

/// <summary>
/// Memory difference entry.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusPatchDiff
{
    public ulong Address;               // Address of change
    public nuint Size;                  // Size of changed region
    public byte OriginalByte;           // Original value (for single byte)
    public byte CurrentByte;            // Current value (for single byte)
}

#endregion
