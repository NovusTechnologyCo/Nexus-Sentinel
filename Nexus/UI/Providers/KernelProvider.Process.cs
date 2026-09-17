using System.Runtime.InteropServices;
using Nexus.UI.Interop;

namespace Nexus.UI.Providers;

/// <summary>
/// Kernel-mode implementation of IProcessProvider using NexusKernel.sys.
/// Provides capabilities beyond user-mode:
/// - Enumerate hidden processes
/// - Access protected processes
/// - Hide processes from user-mode
/// </summary>
public class KernelProcessProvider : IProcessProvider
{
    private readonly NexusKernelDriver _driver = NexusKernelDriver.Instance;
    private bool _disposed;

    public string Name => "Kernel Mode";
    public ProviderPrivilege Privilege => ProviderPrivilege.Kernel;
    public bool IsAvailable => _driver.IsAvailable || _driver.Connect();

    public IEnumerable<ProcessInfo> GetProcesses()
    {
        if (!IsAvailable) yield break;

        var processes = _driver.EnumProcesses();
        foreach (var proc in processes)
        {
            yield return new ProcessInfo
            {
                ProcessId = (int)proc.ProcessId,
                ParentProcessId = (int)proc.ParentProcessId,
                Name = proc.ImageName ?? "",
                ThreadCount = (int)proc.ThreadCount
            };
        }
    }

    public ProcessInfo? GetProcessInfo(int processId)
    {
        if (!IsAvailable) return null;

        // Use the kernel enumeration and find the specific process
        var processes = _driver.EnumProcesses();
        foreach (var proc in processes)
        {
            if (proc.ProcessId == processId)
            {
                return new ProcessInfo
                {
                    ProcessId = (int)proc.ProcessId,
                    ParentProcessId = (int)proc.ParentProcessId,
                    Name = proc.ImageName ?? "",
                    ThreadCount = (int)proc.ThreadCount
                };
            }
        }

        return null;
    }

    public IEnumerable<ThreadInfo> GetThreads(int processId)
    {
        if (!IsAvailable) yield break;

        var threads = _driver.EnumThreads(processId);
        foreach (var thread in threads)
        {
            yield return new ThreadInfo
            {
                ThreadId = (int)thread.ThreadId,
                ProcessId = (int)thread.ProcessId,
                StartAddress = thread.StartAddress,
                Priority = (int)thread.Priority,
                State = thread.State
            };
        }
    }

    public IEnumerable<HandleInfo> GetHandles(int processId)
    {
        if (!IsAvailable) yield break;

        var handles = _driver.EnumHandles(processId);
        foreach (var handle in handles)
        {
            yield return new HandleInfo
            {
                Handle = (IntPtr)(long)handle.Handle,
                ProcessId = (int)handle.ProcessId,
                TypeName = handle.TypeName ?? "",
                Name = handle.ObjectName ?? "",
                GrantedAccess = handle.GrantedAccess
            };
        }
    }

    public bool SuspendProcess(int processId)
    {
        if (!IsAvailable) return false;

        var input = new KernelOpenProcessInput { ProcessId = (uint)processId };
        return _driver.SendIoctl(NexusKernelIoctl.IOCTL_NEXUS_SUSPEND_PROCESS, ref input);
    }

    public bool ResumeProcess(int processId)
    {
        if (!IsAvailable) return false;

        var input = new KernelOpenProcessInput { ProcessId = (uint)processId };
        return _driver.SendIoctl(NexusKernelIoctl.IOCTL_NEXUS_RESUME_PROCESS, ref input);
    }

    public bool SuspendThread(int threadId)
    {
        if (!IsAvailable) return false;
        return _driver.SuspendThread(threadId);
    }

    public bool ResumeThread(int threadId)
    {
        if (!IsAvailable) return false;
        return _driver.ResumeThread(threadId);
    }

    public bool TerminateProcess(int processId)
    {
        if (!IsAvailable) return false;
        return _driver.TerminateProcess(processId);
    }

    public bool TerminateThread(int threadId)
    {
        if (!IsAvailable) return false;
        return _driver.TerminateThread(threadId);
    }

    public bool CloseHandle(int processId, IntPtr handle)
    {
        if (!IsAvailable) return false;
        return _driver.CloseRemoteHandle(processId, handle);
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _disposed = true;
        }
        GC.SuppressFinalize(this);
    }
}
