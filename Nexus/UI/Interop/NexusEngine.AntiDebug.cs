// <file>
// <summary>
// P/Invoke bindings for anti-debug bypass techniques. Patches NtQueryInformationProcess,
// hides debug objects, and applies other techniques to prevent the target process from
// detecting that a debugger is attached.
// </summary>
// </file>

using System.Runtime.InteropServices;

namespace Nexus.UI.Interop;

public static partial class NexusEngine
{
    #region Anti-Debug Detection

    /// <summary>
    /// Check if the target has anti-debug protection.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_AntiDebugDetect(
        IntPtr processHandle,
        out NexusAntiDebugInfo info);

    /// <summary>
    /// Scan for specific anti-debug technique.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_AntiDebugScan(
        IntPtr processHandle,
        NexusAntiDebugType type,
        out uint detected);

    #endregion

    #region PEB Manipulation

    /// <summary>
    /// Hide debugger by patching PEB.BeingDebugged flag.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_AntiDebugHidePEB(
        IntPtr processHandle,
        uint enable);

    /// <summary>
    /// Patch PEB.NtGlobalFlag to hide debugger.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_AntiDebugHideNtGlobalFlag(
        IntPtr processHandle,
        uint enable);

    /// <summary>
    /// Clear heap flags that indicate debugging.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_AntiDebugHideHeapFlags(
        IntPtr processHandle,
        uint enable);

    /// <summary>
    /// Get the PEB address of the target process.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_GetProcessPEB(
        IntPtr processHandle,
        out ulong pebAddress);

    /// <summary>
    /// Get the TEB address for a thread.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_GetThreadTEB(
        IntPtr processHandle,
        uint threadId,
        out ulong tebAddress);

    #endregion

    #region API Hooking Bypass

    /// <summary>
    /// Hook NtQueryInformationProcess to hide debugger.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_AntiDebugHookNtQIP(
        IntPtr debuggerHandle,
        uint enable);

    /// <summary>
    /// Hook NtQuerySystemInformation to hide debugger.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_AntiDebugHookNtQSI(
        IntPtr debuggerHandle,
        uint enable);

    /// <summary>
    /// Hook NtSetInformationThread to prevent thread hiding.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_AntiDebugHookNtSIT(
        IntPtr debuggerHandle,
        uint enable);

    /// <summary>
    /// Hook NtClose to prevent handle validation detection.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_AntiDebugHookNtClose(
        IntPtr debuggerHandle,
        uint enable);

    /// <summary>
    /// Hook GetTickCount/QueryPerformanceCounter for timing attacks.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_AntiDebugHookTiming(
        IntPtr debuggerHandle,
        uint enable);

    /// <summary>
    /// Hook RDTSC instruction for timing attacks.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_AntiDebugHookRDTSC(
        IntPtr debuggerHandle,
        uint enable);

    #endregion

    #region Exception-Based Detection

    /// <summary>
    /// Configure exception handling for anti-debug bypass.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_AntiDebugConfigureExceptions(
        IntPtr debuggerHandle,
        NexusExceptionConfig config);

    /// <summary>
    /// Skip INT3/INT2D detection traps.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_AntiDebugSkipInt3(
        IntPtr debuggerHandle,
        uint enable);

    /// <summary>
    /// Handle OutputDebugString detection.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_AntiDebugHandleODS(
        IntPtr debuggerHandle,
        uint enable);

    #endregion

    #region Hardware-Based Detection

    /// <summary>
    /// Hide hardware breakpoints from detection.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_AntiDebugHideHWBP(
        IntPtr debuggerHandle,
        uint enable);

    /// <summary>
    /// Prevent hardware breakpoint clearing by target.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_AntiDebugProtectDR(
        IntPtr debuggerHandle,
        uint enable);

    #endregion

    #region Window/Process Detection

    /// <summary>
    /// Hide debugger window from FindWindow enumeration.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_AntiDebugHideWindow(
        IntPtr debuggerHandle,
        uint enable);

    /// <summary>
    /// Hide debugger process from process enumeration.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_AntiDebugHideProcess(
        IntPtr debuggerHandle,
        uint enable);

    /// <summary>
    /// Prevent parent process ID spoofing detection.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_AntiDebugHideParent(
        IntPtr processHandle,
        uint spoofPid);

    #endregion

    #region Comprehensive Bypass

    /// <summary>
    /// Enable all anti-debug bypasses (comprehensive hiding).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_AntiDebugEnableAll(
        IntPtr debuggerHandle);

    /// <summary>
    /// Disable all anti-debug bypasses.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_AntiDebugDisableAll(
        IntPtr debuggerHandle);

    /// <summary>
    /// Get current anti-debug bypass status.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_AntiDebugGetStatus(
        IntPtr debuggerHandle,
        out NexusAntiDebugStatus status);

    /// <summary>
    /// Set anti-debug options.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_AntiDebugSetOptions(
        IntPtr debuggerHandle,
        NexusAntiDebugOptions options);

    #endregion

    #region Virtualization Detection

    /// <summary>
    /// Detect if running in a virtual machine.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_DetectVirtualMachine(
        out NexusVMInfo vmInfo);

    /// <summary>
    /// Hide VM artifacts from detection.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_AntiDebugHideVM(
        IntPtr debuggerHandle,
        uint enable);

    #endregion
}

#region Anti-Debug Enums and Structs

/// <summary>
/// Types of anti-debug techniques.
/// </summary>
[Flags]
public enum NexusAntiDebugType : uint
{
    None = 0,
    PEBBeingDebugged = 1,
    NtGlobalFlag = 2,
    HeapFlags = 4,
    NtQueryInformationProcess = 8,
    NtQuerySystemInformation = 16,
    CheckRemoteDebuggerPresent = 32,
    OutputDebugString = 64,
    CloseHandle = 128,
    Int3 = 256,
    Int2D = 512,
    TimingCheck = 1024,
    RDTSC = 2048,
    HardwareBreakpoints = 4096,
    VEH = 8192,
    ThreadHiding = 16384,
    ParentProcess = 32768,
    WindowEnumeration = 65536,
    ProcessEnumeration = 131072,
    All = 0xFFFFFFFF
}

/// <summary>
/// Exception handling configuration for anti-debug.
/// </summary>
[Flags]
public enum NexusExceptionConfig : uint
{
    None = 0,
    PassInt3 = 1,               // Pass INT3 to application
    PassInt2D = 2,              // Pass INT2D to application
    PassSingleStep = 4,         // Pass single-step to application
    PassGuardPage = 8,          // Pass guard page to application
    PassAll = 0xFFFFFFFF
}

/// <summary>
/// Anti-debug options.
/// </summary>
[Flags]
public enum NexusAntiDebugOptions : uint
{
    None = 0,
    AutoHidePEB = 1,
    AutoHideHeap = 2,
    AutoHideHWBP = 4,
    AutoHookAPIs = 8,
    AutoHideTiming = 16,
    StealthMode = 32,           // Maximum stealth
    All = 0xFFFFFFFF
}

/// <summary>
/// Anti-debug detection results.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusAntiDebugInfo
{
    public NexusAntiDebugType DetectedTechniques;
    public uint TechniqueCount;
    public uint SeverityLevel;          // 0-10 difficulty rating
    public ulong PEBAddress;
    public uint PEBBeingDebugged;
    public uint NtGlobalFlag;
    public uint HeapFlags;
    public uint IsProtected;            // Likely using packer/protector
}

/// <summary>
/// Current anti-debug bypass status.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusAntiDebugStatus
{
    public uint PEBHidden;
    public uint NtGlobalFlagHidden;
    public uint HeapFlagsHidden;
    public uint NtQIPHooked;
    public uint NtQSIHooked;
    public uint NtSITHooked;
    public uint NtCloseHooked;
    public uint TimingHooked;
    public uint RDTSCHooked;
    public uint HWBPHidden;
    public uint DRProtected;
    public uint WindowHidden;
    public uint ProcessHidden;
    public uint Int3Skipped;
    public uint ODSHandled;
    public uint ActiveBypassCount;
}

/// <summary>
/// Virtual machine detection information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct NexusVMInfo
{
    public uint IsVirtualMachine;       // 1 if VM detected
    public uint VMType;                 // 0=Unknown, 1=VMware, 2=VBox, 3=Hyper-V, 4=QEMU, etc.
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string VMName;               // VM product name
    public uint DetectionMethod;        // How it was detected
    public uint ConfidenceLevel;        // 0-100% confidence
}

#endregion
