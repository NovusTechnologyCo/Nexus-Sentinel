// <file>
// <summary>
// User-mode process provider using engine.dll for process/module/thread/handle enumeration.
// </summary>
// </file>

using System.Runtime.InteropServices;
using Nexus.UI.Interop;

namespace Nexus.UI.Providers;

/// <summary>
/// User-mode implementation of IProcessProvider using engine.dll.
/// </summary>
public class UserModeProcessProvider : IProcessProvider
{
    private bool _disposed;

    // Win32 API for process termination (not exposed by engine.dll)
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    public string Name => "User Mode";
    public ProviderPrivilege Privilege => ProviderPrivilege.UserMode;
    public bool IsAvailable => true;

    public IEnumerable<ProcessInfo> GetProcesses()
    {
        var processes = new NexusProcessInfo[1024];
        var result = NexusEngine.Nexus_EnumerateProcesses(processes, 1024, out var count);
        if (result != NexusResult.OK)
            yield break;

        var safeCount = (int)Math.Min(count, (nuint)processes.Length);
        for (int i = 0; i < safeCount; i++)
        {
            yield return new ProcessInfo
            {
                ProcessId = (int)processes[i].Pid,
                ParentProcessId = (int)processes[i].ParentPid,
                Name = processes[i].Name,
                Path = processes[i].Path,
                Is64Bit = processes[i].Is32Bit == 0, // Is32Bit == 0 means 64-bit
                ThreadCount = 0 // Not available in NexusProcessInfo
            };
        }
    }

    public ProcessInfo? GetProcessInfo(int processId)
    {
        var result = NexusEngine.Nexus_OpenProcess((uint)processId, out var handle);
        if (result != NexusResult.OK)
            return null;

        try
        {
            result = NexusEngine.Nexus_GetProcessInfo(handle, out var info);
            if (result != NexusResult.OK)
                return null;

            return new ProcessInfo
            {
                ProcessId = (int)info.Pid,
                ParentProcessId = (int)info.ParentPid,
                Name = info.Name,
                Path = info.Path,
                Is64Bit = info.Is32Bit == 0,
                ThreadCount = 0,
                Handle = handle
            };
        }
        finally
        {
            NexusEngine.Nexus_CloseProcess(handle);
        }
    }

    public IEnumerable<ThreadInfo> GetThreads(int processId)
    {
        var result = NexusEngine.Nexus_OpenProcess((uint)processId, out var handle);
        if (result != NexusResult.OK)
            yield break;

        try
        {
            var threads = new NexusThreadInfo[256];
            result = NexusEngine.Nexus_EnumerateThreads(handle, threads, 256, out var count);
            if (result != NexusResult.OK)
                yield break;

            var safeCount = (int)Math.Min(count, (nuint)threads.Length);
            for (int i = 0; i < safeCount; i++)
            {
                yield return new ThreadInfo
                {
                    ThreadId = (int)threads[i].ThreadId,
                    ProcessId = processId,
                    StartAddress = threads[i].StartAddress,
                    Priority = threads[i].BasePriority,
                    State = threads[i].State,
                    IsSuspended = (threads[i].State & 0x0002) != 0 // NEXUS_THREAD_SUSPENDED
                };
            }
        }
        finally
        {
            NexusEngine.Nexus_CloseProcess(handle);
        }
    }

    public IEnumerable<HandleInfo> GetHandles(int processId)
    {
        var result = NexusEngine.Nexus_OpenProcess((uint)processId, out var handle);
        if (result != NexusResult.OK)
            yield break;

        try
        {
            result = NexusEngine.Nexus_HandleEnumCreate(handle, out var enumHandle);
            if (result != NexusResult.OK)
                yield break;

            try
            {
                result = NexusEngine.Nexus_HandleEnumRefresh(enumHandle);
                if (result != NexusResult.OK)
                    yield break;

                result = NexusEngine.Nexus_HandleEnumGetCount(enumHandle, out var count);
                if (result != NexusResult.OK || count == 0)
                    yield break;

                var handles = new NexusHandleInfo[(int)Math.Min(count, 10000)];
                result = NexusEngine.Nexus_HandleEnumGetAll(enumHandle, handles, (nuint)handles.Length, out var actualCount);
                if (result != NexusResult.OK)
                    yield break;

                var safeActualCount = (int)Math.Min(actualCount, (nuint)handles.Length);
                for (int i = 0; i < safeActualCount; i++)
                {
                    var h = handles[i];
                    yield return new HandleInfo
                    {
                        Handle = h.HandleValue,
                        TypeName = h.TypeName ?? "Unknown",
                        Name = h.Name ?? string.Empty,
                        GrantedAccess = h.AccessMask
                    };
                }
            }
            finally
            {
                NexusEngine.Nexus_HandleEnumDestroy(enumHandle);
            }
        }
        finally
        {
            NexusEngine.Nexus_CloseProcess(handle);
        }
    }

    public bool SuspendProcess(int processId)
    {
        var result = NexusEngine.Nexus_OpenProcess((uint)processId, out var handle);
        if (result != NexusResult.OK)
            return false;

        try
        {
            NexusHelper.Nexus_SuspendProcess(handle);
            return true;
        }
        finally
        {
            NexusEngine.Nexus_CloseProcess(handle);
        }
    }

    public bool ResumeProcess(int processId)
    {
        var result = NexusEngine.Nexus_OpenProcess((uint)processId, out var handle);
        if (result != NexusResult.OK)
            return false;

        try
        {
            NexusHelper.Nexus_ResumeProcess(handle);
            return true;
        }
        finally
        {
            NexusEngine.Nexus_CloseProcess(handle);
        }
    }

    public bool SuspendThread(int threadId)
    {
        return NexusEngine.Nexus_SuspendThread((uint)threadId) == NexusResult.OK;
    }

    public bool ResumeThread(int threadId)
    {
        return NexusEngine.Nexus_ResumeThread((uint)threadId) == NexusResult.OK;
    }

    public bool TerminateProcess(int processId)
    {
        // Open process with full access (includes terminate)
        var result = NexusEngine.Nexus_OpenProcessEx((uint)processId, NexusProcessAccess.Full, out var handle);
        if (result != NexusResult.OK || handle == IntPtr.Zero)
            return false;

        try
        {
            return TerminateProcess(handle, 0);
        }
        finally
        {
            NexusEngine.Nexus_CloseProcess(handle);
        }
    }

    public bool TerminateThread(int threadId)
    {
        return NexusEngine.Nexus_TerminateThread((uint)threadId, 0) == NexusResult.OK;
    }

    public bool CloseHandle(int processId, IntPtr handleToClose)
    {
        var result = NexusEngine.Nexus_OpenProcess((uint)processId, out var handle);
        if (result != NexusResult.OK)
            return false;

        try
        {
            result = NexusEngine.Nexus_HandleEnumCreate(handle, out var enumHandle);
            if (result != NexusResult.OK)
                return false;

            try
            {
                return NexusEngine.Nexus_HandleClose(enumHandle, handleToClose) == NexusResult.OK;
            }
            finally
            {
                NexusEngine.Nexus_HandleEnumDestroy(enumHandle);
            }
        }
        finally
        {
            NexusEngine.Nexus_CloseProcess(handle);
        }
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
