// <file>
// <summary>
// P/Invoke bindings for thread operations: enumerate threads in a process, get/set thread
// names, suspend/resume threads, terminate threads, and query thread start addresses.
// </summary>
// </file>

using System.Runtime.InteropServices;

namespace Nexus.UI.Interop;

public static partial class NexusEngine
{
    #region Thread Enumeration

    /// <summary>
    /// Get all threads in the process.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ThreadEnumerate(
        IntPtr processHandle,
        [In, Out] NexusThreadInfoDetailed[]? buffer,
        nuint bufferCount,
        out nuint count);

    /// <summary>
    /// Get detailed thread information.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ThreadGetInfo(
        IntPtr processHandle,
        uint threadId,
        out NexusThreadInfoFull info);

    /// <summary>
    /// Get the main thread of a process.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ThreadGetMain(
        IntPtr processHandle,
        out uint mainThreadId);

    /// <summary>
    /// Get the currently selected/active thread for debugging.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ThreadGetActive(
        IntPtr debuggerHandle,
        out uint activeThreadId);

    /// <summary>
    /// Set the active thread for debugging operations.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ThreadSetActive(
        IntPtr debuggerHandle,
        uint threadId);

    #endregion

    #region Thread Naming

    /// <summary>
    /// Set a custom name for a thread.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv, CharSet = CharSet.Unicode)]
    public static extern NexusResult Nexus_ThreadSetName(
        IntPtr processHandle,
        uint threadId,
        string name);

    /// <summary>
    /// Get the name of a thread.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ThreadGetName(
        IntPtr processHandle,
        uint threadId,
        [Out, MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder name,
        nuint nameSize);

    /// <summary>
    /// Clear a thread's custom name.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ThreadClearName(
        IntPtr processHandle,
        uint threadId);

    /// <summary>
    /// Get all thread names.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ThreadGetNames(
        IntPtr processHandle,
        [In, Out] NexusThreadName[]? buffer,
        nuint bufferCount,
        out nuint count);

    #endregion

    #region Thread Control

    /// <summary>
    /// Suspend a thread.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ThreadSuspend(
        IntPtr processHandle,
        uint threadId,
        out uint previousSuspendCount);

    /// <summary>
    /// Resume a thread.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ThreadResume(
        IntPtr processHandle,
        uint threadId,
        out uint previousSuspendCount);

    /// <summary>
    /// Suspend all threads except one.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ThreadSuspendOthers(
        IntPtr processHandle,
        uint exceptThreadId);

    /// <summary>
    /// Resume all threads.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ThreadResumeAll(IntPtr processHandle);

    /// <summary>
    /// Terminate a thread.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ThreadTerminate(
        IntPtr processHandle,
        uint threadId,
        uint exitCode);

    #endregion

    #region Thread Priority

    /// <summary>
    /// Get thread priority.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ThreadGetPriority(
        IntPtr processHandle,
        uint threadId,
        out NexusThreadPriority priority);

    /// <summary>
    /// Set thread priority.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ThreadSetPriority(
        IntPtr processHandle,
        uint threadId,
        NexusThreadPriority priority);

    /// <summary>
    /// Get thread affinity mask.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ThreadGetAffinity(
        IntPtr processHandle,
        uint threadId,
        out ulong affinityMask);

    /// <summary>
    /// Set thread affinity mask.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ThreadSetAffinity(
        IntPtr processHandle,
        uint threadId,
        ulong affinityMask);

    #endregion

    #region Thread Timing

    /// <summary>
    /// Get thread times (creation, exit, kernel, user).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ThreadGetTimes(
        IntPtr processHandle,
        uint threadId,
        out NexusThreadTimes times);

    /// <summary>
    /// Get thread CPU usage percentage.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ThreadGetCpuUsage(
        IntPtr processHandle,
        uint threadId,
        out double cpuUsage);

    #endregion

    #region Thread Entry Point

    /// <summary>
    /// Get thread start address.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ThreadGetStartAddress(
        IntPtr processHandle,
        uint threadId,
        out ulong startAddress);

    /// <summary>
    /// Get thread entry point (Win32StartAddress).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ThreadGetEntryPoint(
        IntPtr processHandle,
        uint threadId,
        out ulong entryPoint);

    /// <summary>
    /// Get thread's current instruction pointer.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ThreadGetIP(
        IntPtr processHandle,
        uint threadId,
        out ulong instructionPointer);

    /// <summary>
    /// Set thread's instruction pointer (requires suspended thread).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ThreadSetIP(
        IntPtr processHandle,
        uint threadId,
        ulong instructionPointer);

    #endregion

    #region Thread Wait Analysis

    /// <summary>
    /// Get what a thread is waiting on.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ThreadGetWaitInfo(
        IntPtr processHandle,
        uint threadId,
        out NexusThreadWaitInfo waitInfo);

    /// <summary>
    /// Get thread wait chain (deadlock detection).
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ThreadGetWaitChain(
        IntPtr processHandle,
        uint threadId,
        [In, Out] NexusWaitChainNode[]? buffer,
        nuint bufferCount,
        out nuint count,
        out uint isDeadlocked);

    #endregion

    #region Thread Local Storage

    /// <summary>
    /// Get TLS directory address.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ThreadGetTlsDirectory(
        IntPtr processHandle,
        out ulong tlsDirectoryAddress);

    /// <summary>
    /// Read TLS slot value for a thread.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ThreadReadTlsSlot(
        IntPtr processHandle,
        uint threadId,
        uint slotIndex,
        out ulong value);

    /// <summary>
    /// Write TLS slot value for a thread.
    /// </summary>
    [DllImport(DllName, CallingConvention = CallConv)]
    public static extern NexusResult Nexus_ThreadWriteTlsSlot(
        IntPtr processHandle,
        uint threadId,
        uint slotIndex,
        ulong value);

    #endregion
}

#region Thread Enums and Structs

/// <summary>
/// Extended thread state (detailed kernel states).
/// </summary>
public enum NexusThreadStateEx : uint
{
    Initialized = 0,
    Ready = 1,
    Running = 2,
    Standby = 3,
    Terminated = 4,
    Waiting = 5,
    Transition = 6,
    DeferredReady = 7,
    GateWait = 8,
    Unknown = 255
}

/// <summary>
/// Thread wait reason.
/// </summary>
public enum NexusThreadWaitReason : uint
{
    Executive = 0,
    FreePage = 1,
    PageIn = 2,
    PoolAllocation = 3,
    DelayExecution = 4,
    Suspended = 5,
    UserRequest = 6,
    WrExecutive = 7,
    WrFreePage = 8,
    WrPageIn = 9,
    WrPoolAllocation = 10,
    WrDelayExecution = 11,
    WrSuspended = 12,
    WrUserRequest = 13,
    WrEventPair = 14,
    WrQueue = 15,
    WrLpcReceive = 16,
    WrLpcReply = 17,
    WrVirtualMemory = 18,
    WrPageOut = 19,
    WrRendezvous = 20,
    Spare2 = 21,
    WrGuardedMutex = 22,
    WrRundown = 23,
    Unknown = 255
}

/// <summary>
/// Thread priority.
/// </summary>
public enum NexusThreadPriority : int
{
    Idle = -15,
    Lowest = -2,
    BelowNormal = -1,
    Normal = 0,
    AboveNormal = 1,
    Highest = 2,
    TimeCritical = 15
}

/// <summary>
/// Extended thread information (detailed).
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusThreadInfoDetailed
{
    public uint ThreadId;                   // Thread ID
    public ulong StartAddress;              // Thread start address
    public NexusThreadStateEx State;        // Current state
    public NexusThreadWaitReason WaitReason;// Wait reason (if waiting)
    public uint SuspendCount;               // Suspend count
    public NexusThreadPriority Priority;    // Thread priority
    public uint BasePriority;               // Base priority
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
    public string Name;                     // Thread name (if set)
}

/// <summary>
/// Full thread information with all details.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusThreadInfoFull
{
    public NexusThreadInfoDetailed Basic;   // Basic info
    public ulong TebAddress;                // Thread Environment Block
    public ulong StackBase;                 // Stack base address
    public ulong StackLimit;                // Stack limit (end)
    public ulong StackPointer;              // Current stack pointer
    public ulong InstructionPointer;        // Current instruction pointer
    public ulong AffinityMask;              // CPU affinity
    public uint IdealProcessor;             // Ideal processor number
    public uint ContextSwitches;            // Number of context switches
    public uint KernelTime;                 // Time in kernel mode (100ns)
    public uint UserTime;                   // Time in user mode (100ns)
    public ulong CycleTime;                 // CPU cycles consumed
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string ModuleName;               // Module of start address
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string FunctionName;             // Function of start address
}

/// <summary>
/// Thread name entry.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusThreadName
{
    public uint ThreadId;                   // Thread ID
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string Name;                     // Thread name
    public uint IsCustom;                   // User-set name (vs auto-detected)
}

/// <summary>
/// Thread times.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct NexusThreadTimes
{
    public ulong CreationTime;              // When thread was created
    public ulong ExitTime;                  // When thread exited (0 if running)
    public ulong KernelTime;                // Time in kernel mode (100ns)
    public ulong UserTime;                  // Time in user mode (100ns)
}

/// <summary>
/// Thread wait information.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusThreadWaitInfo
{
    public uint IsWaiting;                  // Thread is in wait state
    public NexusThreadWaitReason Reason;    // Wait reason
    public uint WaitType;                   // Kernel/User wait
    public ulong WaitObjectAddress;         // Address of wait object
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
    public string WaitObjectName;           // Name of wait object (if named)
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string WaitObjectType;           // Type of wait object
    public uint WaitingThreadId;            // Thread we're waiting on (if applicable)
}

/// <summary>
/// Wait chain node (for deadlock detection).
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusWaitChainNode
{
    public uint ObjectType;                 // Type of object in chain
    public uint ObjectStatus;               // Status (blocked, running, etc.)
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
    public string ObjectName;               // Object name
    public uint ProcessId;                  // Process ID
    public uint ThreadId;                   // Thread ID
    public uint WaitTime;                   // Time spent waiting (ms)
    public uint ContextSwitches;            // Context switches while waiting
}

#endregion
