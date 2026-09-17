// <file>
// <summary>
// P/Invoke bindings for hook detection and installation. Scans modules for inline hooks
// (JMP/CALL patches), IAT hooks (import table redirections), EAT hooks (export table
// modifications), and syscall hooks. Can also install user-defined hooks.
// </summary>
// </file>

using System.Runtime.InteropServices;

namespace Nexus.UI.Interop;

public static partial class NexusEngine
{
    #region Hook Scanning

    /// <summary>
    /// Scan module for inline hooks.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HookScanModule(
        IntPtr processHandle,
        ulong moduleBase,
        [In, Out] NexusHookInfo[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Scan specific function for hooks.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HookScanFunction(
        IntPtr processHandle,
        ulong functionAddress,
        nuint scanSize,
        out NexusHookInfo hookInfo);

    /// <summary>
    /// Scan entire process for hooks.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HookScanProcess(
        IntPtr processHandle,
        NexusHookScanOptions options,
        [In, Out] NexusHookInfo[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Scan IAT for hooks.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HookScanIat(
        IntPtr processHandle,
        ulong moduleBase,
        [In, Out] NexusIatHook[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Scan EAT for hooks.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HookScanEat(
        IntPtr processHandle,
        ulong moduleBase,
        [In, Out] NexusEatHook[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Scan for SSDT hooks (requires driver).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HookScanSsdt(
        [In, Out] NexusSsdtHook[]? buffer,
        nuint bufferCount,
        out nuint count);

    #endregion

    #region Hook Analysis

    /// <summary>
    /// Analyze detected hook.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HookAnalyze(
        IntPtr processHandle,
        ref NexusHookInfo hookInfo,
        out NexusHookAnalysis analysis);

    /// <summary>
    /// Get original bytes before hook.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HookGetOriginalBytes(
        IntPtr processHandle,
        ulong hookAddress,
        [In, Out] byte[]? buffer,
        nuint bufferSize,
        out nuint bytesRead);

    /// <summary>
    /// Follow hook chain to final destination.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HookFollowChain(
        IntPtr processHandle,
        ulong hookAddress,
        [In, Out] ulong[]? chainBuffer,
        nuint bufferCount,
        out nuint chainLength,
        out ulong finalDestination);

    /// <summary>
    /// Compare module with disk image.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HookCompareWithDisk(
        IntPtr processHandle,
        ulong moduleBase,
        [In, Out] NexusMemoryDiff[]? buffer,
        nuint bufferCount,
        out nuint diffCount);

    #endregion

    #region Hook Restoration

    /// <summary>
    /// Restore hooked function to original.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HookRestore(
        IntPtr processHandle,
        ulong hookAddress);

    /// <summary>
    /// Restore all hooks in module.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HookRestoreModule(
        IntPtr processHandle,
        ulong moduleBase,
        out uint restoredCount);

    /// <summary>
    /// Restore IAT entry.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HookRestoreIat(
        IntPtr processHandle,
        ulong moduleBase,
        ulong iatEntry);

    /// <summary>
    /// Restore from disk image.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_HookRestoreFromDisk(
        IntPtr processHandle,
        ulong moduleBase,
        string diskPath);

    #endregion

    #region Hook Installation

    /// <summary>
    /// Install inline hook.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HookInstallInline(
        IntPtr processHandle,
        ulong targetAddress,
        ulong hookAddress,
        out NexusHookHandle hookHandle);

    /// <summary>
    /// Install IAT hook.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Ansi)]
    public static extern NexusResult Nexus_HookInstallIat(
        IntPtr processHandle,
        ulong moduleBase,
        string functionName,
        ulong hookAddress,
        out NexusHookHandle hookHandle);

    /// <summary>
    /// Install VTable hook.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HookInstallVTable(
        IntPtr processHandle,
        ulong vtableAddress,
        uint methodIndex,
        ulong hookAddress,
        out NexusHookHandle hookHandle);

    /// <summary>
    /// Remove installed hook.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HookRemove(
        ref NexusHookHandle hookHandle);

    #endregion

    #region Trampoline Generation

    /// <summary>
    /// Generate trampoline for hook.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HookCreateTrampoline(
        IntPtr processHandle,
        ulong targetAddress,
        nuint trampolineSize,
        out ulong trampolineAddress);

    /// <summary>
    /// Free trampoline memory.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HookFreeTrampoline(
        IntPtr processHandle,
        ulong trampolineAddress);

    /// <summary>
    /// Get minimum bytes to copy for trampoline.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HookGetTrampolineSize(
        IntPtr processHandle,
        ulong targetAddress,
        nuint requiredJumpSize,
        out nuint bytesToCopy);

    #endregion

    #region Hardware Breakpoint Hooks

    /// <summary>
    /// Install hardware breakpoint hook (stealth).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HookInstallHwbp(
        IntPtr debuggerHandle,
        ulong targetAddress,
        NexusHwbpCallback callback,
        out NexusHookHandle hookHandle);

    /// <summary>
    /// Install page guard hook.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_HookInstallPageGuard(
        IntPtr processHandle,
        ulong targetAddress,
        nuint regionSize,
        out NexusHookHandle hookHandle);

    #endregion
}

#region Hook Enums and Structs

/// <summary>
/// Hook type.
/// </summary>
public enum NexusHookType : uint
{
    None = 0,
    InlineJmp = 1,              // JMP instruction
    InlineCall = 2,             // CALL instruction
    InlinePush = 3,             // PUSH/RET combination
    InlineMov = 4,              // MOV RAX, addr; JMP RAX
    IatHook = 5,                // IAT entry modified
    EatHook = 6,                // EAT entry modified
    VTableHook = 7,             // Virtual table hook
    HardwareBreakpoint = 8,     // DR hook
    PageGuard = 9,              // PAGE_GUARD hook
    Trampoline = 10,            // Trampoline-based hook
    Detour = 11,                // Microsoft Detours style
    Unknown = 255
}

/// <summary>
/// Hook scan options.
/// </summary>
[Flags]
public enum NexusHookScanOptions : uint
{
    None = 0,
    ScanCode = 1,               // Scan code sections
    ScanIat = 2,                // Scan IAT entries
    ScanEat = 4,                // Scan EAT entries
    ScanVTables = 8,            // Scan virtual tables
    CompareWithDisk = 16,       // Compare with on-disk image
    DeepScan = 32,              // Thorough scanning
    IgnoreKnown = 64,           // Ignore known hooks (AV, etc)
    All = 0xFFFFFFFF
}

/// <summary>
/// Detected hook information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusHookInfo
{
    public ulong Address;               // Hook location
    public ulong Destination;           // Hook target
    public NexusHookType Type;          // Hook type
    public uint Size;                   // Hook size in bytes
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
    public byte[] OriginalBytes;        // Original bytes
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
    public byte[] HookBytes;            // Current (hooked) bytes
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string ModuleName;           // Module containing hook
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string FunctionName;         // Hooked function name
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string DestinationModule;    // Destination module
}

/// <summary>
/// IAT hook information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusIatHook
{
    public ulong IatEntry;              // IAT entry address
    public ulong OriginalAddress;       // Original function address
    public ulong HookedAddress;         // Current (hooked) address
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string ImportModule;         // Imported DLL name
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string FunctionName;         // Imported function name
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string HookModule;           // Module containing hook code
}

/// <summary>
/// EAT hook information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusEatHook
{
    public ulong EatEntry;              // EAT entry address
    public ulong OriginalRva;           // Original RVA
    public ulong HookedRva;             // Current (hooked) RVA
    public ushort Ordinal;              // Export ordinal
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string FunctionName;         // Exported function name
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string HookModule;           // Module containing hook
}

/// <summary>
/// SSDT hook information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusSsdtHook
{
    public uint SyscallNumber;          // Syscall number
    public ulong OriginalAddress;       // Original handler
    public ulong HookedAddress;         // Current handler
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string SyscallName;          // Syscall name
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string HookModule;           // Hooking module
}

/// <summary>
/// Hook analysis result.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusHookAnalysis
{
    public uint IsKnownSoftware;        // Known AV/security software
    public uint IsMalicious;            // Potentially malicious
    public uint ChainLength;            // Hook chain length
    public ulong FinalDestination;      // Final destination after chain
    public uint UsesRop;                // Uses ROP gadgets
    public uint IsPolymorph;            // Polymorphic hook
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string DetectedAs;           // Detected hook library/software
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)]
    public string Description;          // Analysis description
}

/// <summary>
/// Memory difference entry.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusMemoryDiff
{
    public ulong Address;               // Difference address
    public nuint Size;                  // Difference size
    public byte DiskByte;               // Byte on disk
    public byte MemoryByte;             // Byte in memory
    public uint IsSectionStart;         // At section boundary
}

/// <summary>
/// Installed hook handle.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusHookHandle
{
    public ulong TargetAddress;         // Original target
    public ulong HookAddress;           // Hook handler
    public ulong TrampolineAddress;     // Trampoline (if any)
    public NexusHookType Type;          // Hook type
    public uint IsActive;               // Hook is active
    public IntPtr InternalHandle;       // Internal handle
}

/// <summary>
/// Hardware breakpoint callback delegate.
/// </summary>
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate int NexusHwbpCallback(
    uint threadId,
    ulong address,
    IntPtr context);

#endregion
