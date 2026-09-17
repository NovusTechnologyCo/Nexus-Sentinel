// <file>
// <summary>
// Process provider interface for enumerating processes, retrieving process information,
// and listing modules. Implementations can use user-mode APIs, kernel driver, or
// hypervisor to enumerate processes (including hidden ones at higher privilege levels).
// </summary>
// </file>

namespace Nexus.UI.Providers;

/// <summary>
/// Process information.
/// </summary>
public class ProcessInfo
{
    public int ProcessId { get; init; }
    public int ParentProcessId { get; init; }
    public string Name { get; init; } = "";
    public string Path { get; init; } = "";
    public bool Is64Bit { get; init; }
    public int ThreadCount { get; init; }
    public IntPtr Handle { get; init; }
}

/// <summary>
/// Thread information.
/// </summary>
public class ThreadInfo
{
    public int ThreadId { get; init; }
    public int ProcessId { get; init; }
    public ulong StartAddress { get; init; }
    public int Priority { get; init; }
    public uint State { get; init; }
    public bool IsSuspended { get; init; }
}

/// <summary>
/// Handle information.
/// </summary>
public class HandleInfo
{
    public IntPtr Handle { get; init; }
    public int ProcessId { get; init; }
    public string TypeName { get; init; } = "";
    public string Name { get; init; } = "";
    public uint GrantedAccess { get; init; }
}

/// <summary>
/// Abstraction for process operations.
/// Implementations can use user-mode APIs, kernel driver, or hypervisor.
/// </summary>
public interface IProcessProvider : IDisposable
{
    /// <summary>
    /// Display name of this provider.
    /// </summary>
    string Name { get; }

    /// <summary>
    /// Privilege level of this provider.
    /// </summary>
    ProviderPrivilege Privilege { get; }

    /// <summary>
    /// Whether this provider is available.
    /// </summary>
    bool IsAvailable { get; }

    /// <summary>
    /// Enumerate all running processes.
    /// </summary>
    IEnumerable<ProcessInfo> GetProcesses();

    /// <summary>
    /// Get information about a specific process.
    /// </summary>
    ProcessInfo? GetProcessInfo(int processId);

    /// <summary>
    /// Get all threads for a process.
    /// </summary>
    IEnumerable<ThreadInfo> GetThreads(int processId);

    /// <summary>
    /// Get all handles for a process.
    /// </summary>
    IEnumerable<HandleInfo> GetHandles(int processId);

    /// <summary>
    /// Suspend a process.
    /// </summary>
    bool SuspendProcess(int processId);

    /// <summary>
    /// Resume a process.
    /// </summary>
    bool ResumeProcess(int processId);

    /// <summary>
    /// Suspend a thread.
    /// </summary>
    bool SuspendThread(int threadId);

    /// <summary>
    /// Resume a thread.
    /// </summary>
    bool ResumeThread(int threadId);

    /// <summary>
    /// Terminate a process.
    /// </summary>
    bool TerminateProcess(int processId);

    /// <summary>
    /// Terminate a thread.
    /// </summary>
    bool TerminateThread(int threadId);

    /// <summary>
    /// Close a handle in a process.
    /// </summary>
    bool CloseHandle(int processId, IntPtr handle);
}
