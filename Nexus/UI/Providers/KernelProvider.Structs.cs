// <file>
// <summary>
// Kernel event and callback structures for NexusKernel.sys communication.
// Includes ProcMon-like monitoring event types, CI/SecureBoot structures,
// memory monitor structures, and process watch structures.
// </summary>
// </file>

using System.Runtime.InteropServices;
using Nexus.UI.Interop;

namespace Nexus.UI.Providers;

#region Kernel Event Structures (ProcMon-like monitoring)

/// <summary>
/// Event types from kernel driver callbacks.
/// </summary>
public static class NexusEventType
{
    public const uint ProcessCreate = 1;
    public const uint ProcessExit = 2;
    public const uint ThreadCreate = 3;
    public const uint ThreadExit = 4;
    public const uint ImageLoad = 5;
    public const uint Debug = 6;
    public const uint RegistryOp = 7;
    public const uint HandleOp = 8;
    public const uint MemoryOp = 9;
    public const uint FileOp = 10;
    public const uint Syscall = 11;  // SecureBoot/CI/Debugger queries
}

/// <summary>
/// Syscall subtypes for NEXUS_EVENT_SYSCALL.
/// </summary>
public static class NexusSyscallType
{
    public const uint QuerySystemInfo = 1;      // NtQuerySystemInformation
    public const uint SetSystemInfo = 2;        // NtSetSystemInformation
    public const uint GetFirmwareEnv = 3;       // NtQuerySystemEnvironmentValueEx
    public const uint QueryLicense = 4;         // NtQueryLicenseValue
}

/// <summary>
/// SystemInformationClass values of interest.
/// </summary>
public static class SystemInfoClass
{
    public const uint SecureBootInformation = 0x91;     // 145
    public const uint CodeIntegrityInformation = 0x67;  // 103
    public const uint KernelDebuggerInfo = 0x23;        // 35
    public const uint BootEnvironmentInfo = 0x5A;       // 90
}

/// <summary>
/// Registry operation subtypes.
/// </summary>
public static class NexusRegOp
{
    public const uint OpenKey = 1;
    public const uint CreateKey = 2;
    public const uint DeleteKey = 3;
    public const uint QueryValue = 4;
    public const uint SetValue = 5;
    public const uint DeleteValue = 6;
    public const uint EnumKey = 7;
    public const uint EnumValue = 8;
}

/// <summary>
/// Handle operation subtypes.
/// </summary>
public static class NexusHandleOp
{
    public const uint OpenProcess = 1;
    public const uint OpenThread = 2;
    public const uint Duplicate = 3;
}

/// <summary>
/// Memory operation subtypes.
/// </summary>
public static class NexusMemOp
{
    public const uint Read = 1;
    public const uint Write = 2;
    public const uint Alloc = 3;
    public const uint Free = 4;
    public const uint Protect = 5;
}

/// <summary>
/// Callback configuration for event filtering.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct KernelCallbackConfig
{
    public uint EventMask;      // Bitmask of enabled event types (1 << NEXUS_EVENT_*)
    public uint ProcessFilter;  // Filter to specific PID (0 = all processes)
}

/// <summary>
/// Event header from kernel driver.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct KernelEventHeader
{
    public uint EventType;
    public uint ProcessId;
    public uint ThreadId;
    public uint DataSize;
    public ulong Timestamp;
}

/// <summary>
/// Registry operation event from kernel.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Unicode)]
public struct KernelRegistryEvent
{
    public KernelEventHeader Header;
    public uint Operation;
    public uint Status;
    public uint ValueType;
    public uint DataSize;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)]
    public string KeyPath;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string ValueName;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
    public byte[] ValueData;
}

/// <summary>
/// Handle/object operation event from kernel.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Unicode)]
public struct KernelHandleEvent
{
    public KernelEventHeader Header;
    public uint Operation;
    public uint TargetProcessId;
    public uint TargetThreadId;
    public uint DesiredAccess;
    public uint GrantedAccess;
    public uint Status;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string SourceProcessName;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string TargetProcessName;
}

/// <summary>
/// Cross-process memory operation event from kernel.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Unicode)]
public struct KernelMemoryEvent
{
    public KernelEventHeader Header;
    public uint Operation;
    public uint TargetProcessId;
    public ulong Address;
    public ulong Size;
    public uint Protection;
    public uint Status;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string SourceProcessName;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string TargetProcessName;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
    public byte[] DataPreview;
}

/// <summary>
/// File operation event from kernel (requires minifilter).
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Unicode)]
public struct KernelFileEvent
{
    public KernelEventHeader Header;
    public uint Operation;
    public uint Status;
    public uint DesiredAccess;
    public uint ShareMode;
    public uint CreateDisposition;
    public uint CreateOptions;
    public ulong FileOffset;
    public ulong Length;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 520)]
    public string FilePath;
}

/// <summary>
/// Syscall event from kernel hook.
/// Captures NtQuerySystemInformation calls for SecureBoot/CI/Debugger.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Unicode)]
public struct KernelSyscallEvent
{
    public KernelEventHeader Header;
    public uint SyscallType;        // NEXUS_SYSCALL_* subtype
    public uint InfoClass;          // SystemInformationClass
    public uint Status;             // NTSTATUS result
    public uint ReturnLength;       // Bytes returned
    public ulong InputBuffer;       // Input buffer address
    public ulong OutputBuffer;      // Output buffer address
    public uint InputLength;        // Input buffer size
    public uint OutputLength;       // Output buffer size
    public ulong ReturnValue;       // Return value (e.g., SecureBoot state)
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
    public string Description;      // Human-readable description
}

/// <summary>
/// Input structure for setting process watch pattern.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Unicode)]
public struct NexusProcessWatchInput
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string ProcessNamePattern;   // Substring to match
    public uint Flags;                  // Reserved
    public uint Reserved;
}

/// <summary>
/// Information about a watched (suspended) process.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Unicode)]
public struct NexusWatchedProcessInfo
{
    public uint ProcessId;              // PID of suspended process (0 if none)
    public uint ParentProcessId;        // Parent PID
    public uint IsSuspended;            // 1 if currently suspended
    public uint Reserved;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string ImageName;            // Full image path
}

/// <summary>
/// CI.dll / g_CiOptions information from kernel.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct NexusCiInfo
{
    public ulong CiDllBase;             // Base address of CI.dll
    public ulong CiDllSize;             // Size of CI.dll
    public ulong CiOptionsAddress;      // Address of g_CiOptions global
    public uint CiOptionsValue;         // Current value of g_CiOptions
    public uint SecureBootEnabled;      // 1 if SecureBoot flag is set in g_CiOptions
    public ulong CiValidateAddress;     // Address of CiValidateImageHeader (if found)
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
    public ulong[] Reserved;
}

/// <summary>
/// Input for spoofing g_CiOptions value.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct NexusSpoofCiInput
{
    public uint NewCiOptions;           // New value to write to g_CiOptions
    public uint Flags;                  // Reserved flags
}

/// <summary>
/// CI Options flags (from Code Integrity).
/// </summary>
public static class CiOptionsFlags
{
    public const uint CI_OPTION_ENABLED = 0x00000001;           // CI enforcement enabled
    public const uint CI_OPTION_TESTSIGN = 0x00000002;          // Test signing enabled
    public const uint CI_OPTION_UMCI = 0x00000004;              // User-mode CI enabled
    public const uint CI_OPTION_DEBUGGER_ENABLED = 0x00000080;  // Kernel debugger detected
    public const uint CI_OPTION_FLIGHT_SIGNING = 0x00000100;    // Flight signing
    public const uint CI_OPTION_SECURE_BOOT = 0x00020000;       // SecureBoot is ENABLED
}

/// <summary>
/// Syscall hook status from kernel.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct NexusSyscallHookStatus
{
    public uint HookInstalled;          // 1 if hook is installed
    public uint HookEnabled;            // 1 if spoofing is active
    public ulong HookAddress;           // Address of hooked function
    public ulong TrampolineAddress;     // Address of trampoline
    public uint CallCount;              // Total calls through hook
    public uint SpoofCount;             // Calls that were spoofed
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
    public ulong[] Reserved;
}

/// <summary>
/// Input for enabling/disabling syscall hook.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct NexusEnableHookInput
{
    public uint Enable;                 // 1 to enable, 0 to disable
    public uint Reserved;
}

/// <summary>
/// Memory monitor types.
/// </summary>
public static class MemoryMonitorType
{
    public const uint Write = 1;        // Monitor writes only
    public const uint ReadWrite = 3;    // Monitor reads and writes
}

/// <summary>
/// Input for starting a memory monitor.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Unicode)]
public struct NexusStartMonitorInput
{
    public ulong Address;               // Kernel address to monitor
    public uint Size;                   // Size: 1, 2, 4, or 8 bytes
    public uint Type;                   // MemoryMonitorType.Write or ReadWrite
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string Description;          // Optional description
}

/// <summary>
/// Output from starting a memory monitor.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct NexusStartMonitorOutput
{
    public uint MonitorIndex;           // Assigned monitor index (0-3)
    public uint Status;                 // NTSTATUS
}

/// <summary>
/// Input for stopping a memory monitor.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct NexusStopMonitorInput
{
    public uint MonitorIndex;           // Monitor index to stop
    public uint Reserved;
}

/// <summary>
/// Single monitor entry status.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct NexusMonitorEntryStatus
{
    public uint Active;                 // 1 if monitor is active
    public ulong Address;               // Monitored address
    public uint Size;                   // Monitor size
    public uint Type;                   // Monitor type
    public uint HitCount;               // Number of accesses detected
}

/// <summary>
/// Overall memory monitor status.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct NexusMemoryMonitorStatus
{
    public uint MonitoringActive;       // 1 if any monitor is active
    public uint TotalHits;              // Total accesses across all monitors
    public uint LogEntryCount;          // Number of log entries available
    public uint Reserved;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
    public NexusMonitorEntryStatus[] Monitors;
}

/// <summary>
/// Access log entry - records who accessed the monitored address.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct NexusMemoryAccessEntry
{
    public ulong Timestamp;             // Performance counter value
    public ulong AccessAddress;         // Address that was accessed
    public ulong CallerRip;             // RIP of the instruction that accessed
    public ulong CallerModule;          // Base address of caller's module
    public uint DrIndex;                // Which DR register triggered (0-3)
    public uint ProcessorNumber;        // Which CPU
    public uint ProcessId;              // Process context (0 = kernel)
    public uint Reserved;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
    public byte[] ModuleName;           // Name of the module containing RIP

    /// <summary>
    /// Get module name as string.
    /// </summary>
    public string ModuleNameString =>
        ModuleName != null ? System.Text.Encoding.ASCII.GetString(ModuleName).TrimEnd('\0') : "";
}

/// <summary>
/// Input for getting access log.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct NexusGetAccessLogInput
{
    public uint MaxEntries;             // Maximum entries to retrieve
    public uint Reserved;
}

/// <summary>
/// Output header for getting access log.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct NexusGetAccessLogOutput
{
    public uint EntryCount;             // Actual entries returned
    public uint Reserved;
    // Followed by NexusMemoryAccessEntry array
}

#endregion
