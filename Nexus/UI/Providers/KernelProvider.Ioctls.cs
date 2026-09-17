// <file>
// <summary>
// IOCTL code definitions (NexusKernelIoctl) and basic operation structures
// for communicating with NexusKernel.sys. These mirror nexus_kernel.h.
// </summary>
// </file>

using System.Runtime.InteropServices;
using Nexus.UI.Interop;

namespace Nexus.UI.Providers;

#region IOCTL Definitions

/// <summary>
/// IOCTL codes for NexusKernel.sys communication.
/// These values are computed using the CTL_CODE macro and must match the
/// definitions in nexus_kernel.h exactly. Uses device type 0x8000 with
/// METHOD_BUFFERED and FILE_ANY_ACCESS for all IOCTLs.
/// </summary>
public static class NexusKernelIoctl
{
    // Device type matching nexus_kernel.h
    private const uint NEXUS_DEVICE_TYPE = 0x8000;
    private const uint NEXUS_IOCTL_BASE = 0x800;

    // All IOCTLs use METHOD_BUFFERED and FILE_ANY_ACCESS per nexus_kernel.h
    private const uint METHOD_BUFFERED = 0;
    private const uint FILE_ANY_ACCESS = 0;

    // Helper to create IOCTL code (CTL_CODE macro) - matches Windows SDK
    private static uint CTL_CODE(uint deviceType, uint function, uint method, uint access)
        => (deviceType << 16) | (access << 14) | (function << 2) | method;

    // Helper matching NEXUS_CTL_CODE macro from nexus_kernel.h
    private static uint NEXUS_CTL_CODE(uint code)
        => CTL_CODE(NEXUS_DEVICE_TYPE, NEXUS_IOCTL_BASE + code, METHOD_BUFFERED, FILE_ANY_ACCESS);

    // Foundation IOCTLs (0x00 - 0x0F)
    public static readonly uint IOCTL_NEXUS_GET_VERSION = NEXUS_CTL_CODE(0x00);
    public static readonly uint IOCTL_NEXUS_CHECK_PRIVILEGE = NEXUS_CTL_CODE(0x01);
    public static readonly uint IOCTL_NEXUS_INIT_COMPLETE = NEXUS_CTL_CODE(0x02);

    // Process IOCTLs (0x10 - 0x1F)
    public static readonly uint IOCTL_NEXUS_OPEN_PROCESS = NEXUS_CTL_CODE(0x10);
    public static readonly uint IOCTL_NEXUS_CLOSE_PROCESS = NEXUS_CTL_CODE(0x11);
    public static readonly uint IOCTL_NEXUS_GET_PEPROCESS = NEXUS_CTL_CODE(0x12);
    public static readonly uint IOCTL_NEXUS_ENUM_PROCESSES = NEXUS_CTL_CODE(0x13);
    public static readonly uint IOCTL_NEXUS_ENUM_MODULES = NEXUS_CTL_CODE(0x14);
    public static readonly uint IOCTL_NEXUS_SUSPEND_PROCESS = NEXUS_CTL_CODE(0x15);
    public static readonly uint IOCTL_NEXUS_RESUME_PROCESS = NEXUS_CTL_CODE(0x16);
    public static readonly uint IOCTL_NEXUS_HIDE_PROCESS = NEXUS_CTL_CODE(0x17);
    public static readonly uint IOCTL_NEXUS_QUERY_PROCESS_INFO = NEXUS_CTL_CODE(0x18);
    public static readonly uint IOCTL_NEXUS_TERMINATE_PROCESS = NEXUS_CTL_CODE(0x19);
    public static readonly uint IOCTL_NEXUS_ENUM_HANDLES = NEXUS_CTL_CODE(0x1A);
    public static readonly uint IOCTL_NEXUS_CLOSE_HANDLE = NEXUS_CTL_CODE(0x1B);

    // Memory IOCTLs (0x20 - 0x3F)
    public static readonly uint IOCTL_NEXUS_READ_MEMORY = NEXUS_CTL_CODE(0x20);
    public static readonly uint IOCTL_NEXUS_WRITE_MEMORY = NEXUS_CTL_CODE(0x21);
    public static readonly uint IOCTL_NEXUS_READ_PHYSICAL = NEXUS_CTL_CODE(0x22);
    public static readonly uint IOCTL_NEXUS_WRITE_PHYSICAL = NEXUS_CTL_CODE(0x23);
    public static readonly uint IOCTL_NEXUS_VA_TO_PA = NEXUS_CTL_CODE(0x24);
    public static readonly uint IOCTL_NEXUS_ALLOC_MEMORY = NEXUS_CTL_CODE(0x25);
    public static readonly uint IOCTL_NEXUS_FREE_MEMORY = NEXUS_CTL_CODE(0x26);
    public static readonly uint IOCTL_NEXUS_PROTECT_MEMORY = NEXUS_CTL_CODE(0x27);
    public static readonly uint IOCTL_NEXUS_QUERY_MEMORY = NEXUS_CTL_CODE(0x28);
    public static readonly uint IOCTL_NEXUS_MDL_READ = NEXUS_CTL_CODE(0x29);
    public static readonly uint IOCTL_NEXUS_MDL_WRITE = NEXUS_CTL_CODE(0x2A);
    public static readonly uint IOCTL_NEXUS_KERNEL_READ = NEXUS_CTL_CODE(0x2B);
    public static readonly uint IOCTL_NEXUS_KERNEL_WRITE = NEXUS_CTL_CODE(0x2C);
    public static readonly uint IOCTL_NEXUS_SCAN_MEMORY = NEXUS_CTL_CODE(0x2D);

    // Thread IOCTLs (0x40 - 0x4F)
    public static readonly uint IOCTL_NEXUS_OPEN_THREAD = NEXUS_CTL_CODE(0x40);
    public static readonly uint IOCTL_NEXUS_ENUM_THREADS = NEXUS_CTL_CODE(0x41);
    public static readonly uint IOCTL_NEXUS_SUSPEND_THREAD = NEXUS_CTL_CODE(0x42);
    public static readonly uint IOCTL_NEXUS_RESUME_THREAD = NEXUS_CTL_CODE(0x43);
    public static readonly uint IOCTL_NEXUS_GET_THREAD_CONTEXT = NEXUS_CTL_CODE(0x44);
    public static readonly uint IOCTL_NEXUS_SET_THREAD_CONTEXT = NEXUS_CTL_CODE(0x45);
    public static readonly uint IOCTL_NEXUS_QUEUE_APC = NEXUS_CTL_CODE(0x46);
    public static readonly uint IOCTL_NEXUS_CREATE_REMOTE_THREAD = NEXUS_CTL_CODE(0x47);
    public static readonly uint IOCTL_NEXUS_TERMINATE_THREAD = NEXUS_CTL_CODE(0x48);

    // Debug IOCTLs (0x50 - 0x6F)
    public static readonly uint IOCTL_NEXUS_DEBUG_PROCESS = NEXUS_CTL_CODE(0x50);
    public static readonly uint IOCTL_NEXUS_STOP_DEBUG = NEXUS_CTL_CODE(0x51);
    public static readonly uint IOCTL_NEXUS_SET_BREAKPOINT = NEXUS_CTL_CODE(0x52);
    public static readonly uint IOCTL_NEXUS_CLEAR_BREAKPOINT = NEXUS_CTL_CODE(0x53);
    public static readonly uint IOCTL_NEXUS_GET_DEBUG_REGS = NEXUS_CTL_CODE(0x54);
    public static readonly uint IOCTL_NEXUS_SET_DEBUG_REGS = NEXUS_CTL_CODE(0x55);
    public static readonly uint IOCTL_NEXUS_WAIT_DEBUG_EVENT = NEXUS_CTL_CODE(0x56);
    public static readonly uint IOCTL_NEXUS_CONTINUE_DEBUG = NEXUS_CTL_CODE(0x57);
    public static readonly uint IOCTL_NEXUS_SET_GLOBAL_DEBUG = NEXUS_CTL_CODE(0x58);
    public static readonly uint IOCTL_NEXUS_GET_DEBUG_STATE = NEXUS_CTL_CODE(0x59);
    public static readonly uint IOCTL_NEXUS_SET_DEBUG_STATE = NEXUS_CTL_CODE(0x5A);
    public static readonly uint IOCTL_NEXUS_ENABLE_LBR = NEXUS_CTL_CODE(0x5B);
    public static readonly uint IOCTL_NEXUS_GET_LBR = NEXUS_CTL_CODE(0x5C);

    // Interrupt/Exception IOCTLs (0x70 - 0x7F)
    public static readonly uint IOCTL_NEXUS_HOOK_INTERRUPT = NEXUS_CTL_CODE(0x70);
    public static readonly uint IOCTL_NEXUS_UNHOOK_INTERRUPT = NEXUS_CTL_CODE(0x71);
    public static readonly uint IOCTL_NEXUS_SET_INT1_HANDLER = NEXUS_CTL_CODE(0x72);
    public static readonly uint IOCTL_NEXUS_SET_INT3_HANDLER = NEXUS_CTL_CODE(0x73);
    public static readonly uint IOCTL_NEXUS_SET_INT14_HANDLER = NEXUS_CTL_CODE(0x74);

    // Trace/Performance IOCTLs (0x80 - 0x9F)
    public static readonly uint IOCTL_NEXUS_BRANCHTRACE_INIT = NEXUS_CTL_CODE(0x80);
    public static readonly uint IOCTL_NEXUS_BRANCHTRACE_START = NEXUS_CTL_CODE(0x81);
    public static readonly uint IOCTL_NEXUS_BRANCHTRACE_STOP = NEXUS_CTL_CODE(0x82);
    public static readonly uint IOCTL_NEXUS_BRANCHTRACE_WAIT = NEXUS_CTL_CODE(0x83);
    public static readonly uint IOCTL_NEXUS_BRANCHTRACE_GET_DATA = NEXUS_CTL_CODE(0x84);
    public static readonly uint IOCTL_NEXUS_BRANCHTRACE_PAUSE = NEXUS_CTL_CODE(0x85);
    public static readonly uint IOCTL_NEXUS_BRANCHTRACE_CONTINUE = NEXUS_CTL_CODE(0x86);

    // Callback/Notification IOCTLs (0xA0 - 0xAF)
    public static readonly uint IOCTL_NEXUS_REGISTER_CALLBACK = NEXUS_CTL_CODE(0xA0);
    public static readonly uint IOCTL_NEXUS_UNREGISTER_CALLBACK = NEXUS_CTL_CODE(0xA1);
    public static readonly uint IOCTL_NEXUS_WAIT_FOR_EVENT = NEXUS_CTL_CODE(0xA2);
    public static readonly uint IOCTL_NEXUS_GET_PENDING_EVENTS = NEXUS_CTL_CODE(0xA3);

    // Security IOCTLs (0xB0 - 0xBF)
    public static readonly uint IOCTL_NEXUS_VALIDATE_SIGNATURE = NEXUS_CTL_CODE(0xB0);
    public static readonly uint IOCTL_NEXUS_SET_SIGNATURE_KEY = NEXUS_CTL_CODE(0xB1);
    public static readonly uint IOCTL_NEXUS_CONFIGURE_REG_SPOOF = NEXUS_CTL_CODE(0xB2);

    // Process Watch IOCTLs (0xC0 - 0xCF) - Intercept process creation for hooking
    public static readonly uint IOCTL_NEXUS_SET_PROCESS_WATCH = NEXUS_CTL_CODE(0xC0);
    public static readonly uint IOCTL_NEXUS_CLEAR_PROCESS_WATCH = NEXUS_CTL_CODE(0xC1);
    public static readonly uint IOCTL_NEXUS_GET_WATCHED_PROCESS = NEXUS_CTL_CODE(0xC2);
    public static readonly uint IOCTL_NEXUS_RESUME_WATCHED = NEXUS_CTL_CODE(0xC3);

    // CI / SecureBoot Tracing IOCTLs (0xD0 - 0xDF)
    public static readonly uint IOCTL_NEXUS_GET_CI_INFO = NEXUS_CTL_CODE(0xD0);
    public static readonly uint IOCTL_NEXUS_ENABLE_SB_TRACE = NEXUS_CTL_CODE(0xD1);
    public static readonly uint IOCTL_NEXUS_DISABLE_SB_TRACE = NEXUS_CTL_CODE(0xD2);
    public static readonly uint IOCTL_NEXUS_GET_SB_TRACE = NEXUS_CTL_CODE(0xD3);
    public static readonly uint IOCTL_NEXUS_SPOOF_CI_OPTIONS = NEXUS_CTL_CODE(0xD4);
    public static readonly uint IOCTL_NEXUS_INSTALL_SYSCALL_HOOK = NEXUS_CTL_CODE(0xD5);
    public static readonly uint IOCTL_NEXUS_REMOVE_SYSCALL_HOOK = NEXUS_CTL_CODE(0xD6);
    public static readonly uint IOCTL_NEXUS_ENABLE_SYSCALL_HOOK = NEXUS_CTL_CODE(0xD7);
    public static readonly uint IOCTL_NEXUS_GET_SYSCALL_HOOK_STATUS = NEXUS_CTL_CODE(0xD8);

    // Memory Monitor IOCTLs (0xE0 - 0xEF) - Global HW breakpoint monitoring
    public static readonly uint IOCTL_NEXUS_START_MEMORY_MONITOR = NEXUS_CTL_CODE(0xE0);
    public static readonly uint IOCTL_NEXUS_STOP_MEMORY_MONITOR = NEXUS_CTL_CODE(0xE1);
    public static readonly uint IOCTL_NEXUS_STOP_ALL_MONITORS = NEXUS_CTL_CODE(0xE2);
    public static readonly uint IOCTL_NEXUS_GET_MONITOR_STATUS = NEXUS_CTL_CODE(0xE3);
    public static readonly uint IOCTL_NEXUS_GET_MEMORY_ACCESS_LOG = NEXUS_CTL_CODE(0xE4);
    public static readonly uint IOCTL_NEXUS_CLEAR_ACCESS_LOG = NEXUS_CTL_CODE(0xE5);

    // Comm Channel IOCTLs (0xF0 - 0xFF) - Shared memory communication
    public static readonly uint IOCTL_NEXUS_MAP_COMM_CHANNEL = NEXUS_CTL_CODE(0xF0);
    public static readonly uint IOCTL_NEXUS_UNMAP_COMM_CHANNEL = NEXUS_CTL_CODE(0xF1);
    public static readonly uint IOCTL_NEXUS_GET_COMM_INFO = NEXUS_CTL_CODE(0xF2);
}

#endregion

#region IOCTL Structures (matching nexus_kernel.h)

/// <summary>
/// Version information output structure.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct NexusVersionInfo
{
    public uint Major;
    public uint Minor;
    public uint Patch;
    public uint Reserved;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
    public byte[] VersionString;
}

/// <summary>
/// Input structure for process open IOCTL.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct NexusOpenProcessInput
{
    public uint ProcessId;
    public uint DesiredAccess;
}

/// <summary>
/// Output structure for process open IOCTL.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct NexusOpenProcessOutput
{
    public ulong ProcessHandle; // Kernel handle or PEPROCESS
    public uint Status;
    public uint Reserved;
}

/// <summary>
/// Input structure for memory read IOCTL.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct NexusReadMemoryInput
{
    public uint ProcessId;
    public uint Reserved;
    public ulong Address;
    public ulong Size;
}

/// <summary>
/// Output header for memory read IOCTL (followed by data).
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct NexusReadMemoryOutput
{
    public ulong BytesRead;
    public uint Status;
    public uint Reserved;
    // Followed by data buffer
}

/// <summary>
/// Input structure for memory write IOCTL (followed by data).
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct NexusWriteMemoryInput
{
    public uint ProcessId;
    public uint Reserved;
    public ulong Address;
    public ulong Size;
    // Followed by data buffer
}

/// <summary>
/// Output structure for memory write IOCTL.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct NexusWriteMemoryOutput
{
    public ulong BytesWritten;
    public uint Status;
    public uint Reserved;
}

/// <summary>
/// Input structure for memory query IOCTL.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct NexusQueryMemoryInput
{
    public uint ProcessId;
    public uint Reserved;
    public ulong Address;
}

/// <summary>
/// Output structure for memory query IOCTL.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct NexusQueryMemoryOutput
{
    public ulong BaseAddress;
    public ulong AllocationBase;
    public ulong RegionSize;
    public uint State;
    public uint Protection;
    public uint Type;
    public uint Status;
}

/// <summary>
/// Input for physical memory operations.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct NexusPhysicalMemoryInput
{
    public ulong PhysicalAddress;
    public ulong Size;
}

/// <summary>
/// Input structure for setting hardware breakpoint.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct NexusSetBreakpointInput
{
    public uint ThreadId;
    public uint Register;       // DR0-DR3 (0-3)
    public ulong Address;
    public uint Type;           // Execute=0, Write=1, IO=2, ReadWrite=3
    public uint Size;           // 1, 2, 4, 8 bytes
}

/// <summary>
/// Debug registers structure.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct NexusDebugRegisters
{
    public ulong Dr0;
    public ulong Dr1;
    public ulong Dr2;
    public ulong Dr3;
    public ulong Dr6;
    public ulong Dr7;
}

/// <summary>
/// Input for thread context operations.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct NexusThreadContextInput
{
    public uint ThreadId;
    public uint ContextFlags;
}

/// <summary>
/// Full debug state structure (matches NEXUS_DEBUG_STATE in nexus_kernel.h).
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public unsafe struct NexusDebugState
{
    // General purpose registers
    public ulong Rax, Rbx, Rcx, Rdx;
    public ulong Rsi, Rdi, Rbp, Rsp, Rip;
    public ulong R8, R9, R10, R11, R12, R13, R14, R15;

    // Segment registers
    public ushort Cs, Ds, Es, Fs, Gs, Ss;
    public fixed ushort Padding[2];

    // Flags
    public ulong Rflags;

    // Debug registers
    public ulong Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;

    // FPU/SSE state (512 bytes - FXSAVE format)
    public fixed byte FpuState[512];

    // Last Branch Recording (16 entries x 2 addresses)
    public fixed ulong LbrFrom[16];
    public fixed ulong LbrTo[16];
    public uint LbrCount;
    public uint Reserved;
}

/// <summary>
/// Thread enumerate input.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct NexusEnumThreadsInput
{
    public uint ProcessId;
    public uint Reserved;
}

/// <summary>
/// Module enumerate input.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct NexusEnumModulesInput
{
    public uint ProcessId;
    public uint Reserved;
}

/// <summary>
/// Input for process/thread suspend/resume operations.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct NexusSuspendResumeInput
{
    public uint ProcessId;
    public uint ThreadId;  // 0 for process-level operations
}

/// <summary>
/// Module info structure from driver (must match NEXUS_MODULE_INFO).
/// Named KernelModuleInfo to avoid conflict with Interop.NexusModuleInfo.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Unicode)]
public struct KernelModuleInfo
{
    public ulong BaseAddress;
    public ulong Size;
    public ulong EntryPoint;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string ModuleName;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string ModulePath;
}

/// <summary>
/// Thread info structure from driver (must match NEXUS_THREAD_INFO).
/// Named KernelThreadInfo to avoid conflict with Interop.NexusThreadInfo.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct KernelThreadInfo
{
    public uint ThreadId;
    public uint ProcessId;
    public ulong StartAddress;
    public ulong Teb;
    public uint Priority;
    public uint State;
    public ulong KernelTime;
    public ulong UserTime;
}

/// <summary>
/// Process info structure from driver (must match NEXUS_PROCESS_INFO).
/// Named KernelProcessInfo to avoid conflict with Interop.NexusProcessInfo.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Unicode)]
public struct KernelProcessInfo
{
    public uint ProcessId;
    public uint ParentProcessId;
    public uint SessionId;
    public uint ThreadCount;
    public ulong PebAddress;
    public ulong BaseAddress;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string ImageName;
}

/// <summary>
/// Thread suspend/resume input (just thread ID).
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct KernelThreadIdInput
{
    public uint ThreadId;
}

/// <summary>
/// Input for terminate process IOCTL.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct KernelTerminateProcessInput
{
    public uint ProcessId;
    public uint ExitCode;
}

/// <summary>
/// Input for terminate thread IOCTL.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct KernelTerminateThreadInput
{
    public uint ThreadId;
    public uint ExitCode;
}

/// <summary>
/// Input for close handle IOCTL.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct KernelCloseHandleInput
{
    public uint ProcessId;
    public uint Reserved;
    public ulong Handle;
}

/// <summary>
/// Input for enum handles IOCTL.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct KernelEnumHandlesInput
{
    public uint ProcessId;
    public uint Reserved;
}

/// <summary>
/// Handle info structure from driver (must match NEXUS_HANDLE_INFO).
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Unicode)]
public struct KernelHandleInfo
{
    public ulong Handle;
    public uint ProcessId;
    public uint ObjectTypeIndex;
    public uint GrantedAccess;
    public uint HandleAttributes;
    public ulong Object;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string TypeName;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string ObjectName;
}

// Keep legacy aliases for compatibility with existing provider code
[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct KernelOpenProcessInput
{
    public uint ProcessId;
    public uint DesiredAccess;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct KernelOpenProcessOutput
{
    public ulong ProcessHandle;
    public uint Status;
    public uint Reserved;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct KernelMemoryInput
{
    public uint ProcessId;
    public uint Reserved;
    public ulong Address;
    public ulong Size;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct KernelMemoryQueryInput
{
    public uint ProcessId;
    public uint Reserved;
    public ulong Address;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct KernelMemoryQueryOutput
{
    public ulong BaseAddress;
    public ulong AllocationBase;
    public ulong RegionSize;
    public uint State;
    public uint Protect;
    public uint Type;
    public uint Status;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct KernelBreakpointInput
{
    public uint ThreadId;
    public uint Register;
    public ulong Address;
    public uint Type;
    public uint Size;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct KernelContextInput
{
    public uint ThreadId;
    public uint ContextFlags;
}

[StructLayout(LayoutKind.Sequential, Pack = 8)]
public struct KernelContext64
{
    public ulong Rax, Rbx, Rcx, Rdx;
    public ulong Rsi, Rdi, Rbp, Rsp;
    public ulong R8, R9, R10, R11;
    public ulong R12, R13, R14, R15;
    public ulong Rip;
    public uint EFlags;
    public ushort Cs, Ds, Es, Fs, Gs, Ss;
    public ulong Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
}

#endregion
