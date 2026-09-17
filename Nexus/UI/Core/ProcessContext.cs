// <file>
// <summary>
// Singleton process context providing centralized state for the currently attached process.
// Holds the active process ID, name, path, bitness, native handle, and the current set of
// providers (memory, process, debug). All panels and forms access process state through
// this shared context. Fires events on attach, detach, and provider changes.
// </summary>
// </file>

using Nexus.UI.Providers;

namespace Nexus.UI.Core;

/// <summary>
/// Shared process context accessible by all modules.
/// Provides centralized access to providers and process state.
/// </summary>
public class ProcessContext : IDisposable
{
    private static ProcessContext? _current;
    private bool _disposed;

    /// <summary>
    /// Current active process context (singleton for the application).
    /// </summary>
    public static ProcessContext Current => _current ??= new ProcessContext();

    // Providers
    public IMemoryProvider? MemoryProvider { get; private set; }
    public IProcessProvider? ProcessProvider { get; private set; }
    public IDebugProvider? DebugProvider { get; private set; }

    // Process state
    public int ProcessId { get; private set; }
    public string ProcessName { get; private set; } = "";
    public string ProcessPath { get; private set; } = "";
    public bool Is64Bit { get; private set; }
    public bool IsAttached => ProcessId > 0 && MemoryProvider?.IsAttached == true;

    // Events
    public event EventHandler<ProcessAttachedEventArgs>? ProcessAttached;
    public event EventHandler<ProcessDetachedEventArgs>? ProcessDetached;
    public event EventHandler<ProviderChangedEventArgs>? ProviderChanged;

    private ProcessContext()
    {
        // Initialize with user-mode providers by default
        ProcessProvider = new UserModeProcessProvider();
    }

    // Native process handle (from NexusEngine)
    public IntPtr NativeProcessHandle { get; private set; }

    /// <summary>
    /// Attach to a process by PID.
    /// </summary>
    public bool Attach(int processId) => Attach(processId, IntPtr.Zero);

    /// <summary>
    /// Attach to a process by PID with an existing native handle.
    /// </summary>
    public bool Attach(int processId, IntPtr nativeHandle)
    {
        if (processId <= 0)
            return false;

        // Detach from current process first
        Detach();

        // Get process info
        var processInfo = ProcessProvider?.GetProcessInfo(processId);
        if (processInfo == null)
            return false;

        // Create memory provider and attach
        var memoryProvider = new UserModeMemoryProvider();
        if (!memoryProvider.Attach(processId))
        {
            memoryProvider.Dispose();
            return false;
        }

        MemoryProvider = memoryProvider;
        ProcessId = processId;
        ProcessName = processInfo.Name;
        ProcessPath = processInfo.Path;
        Is64Bit = processInfo.Is64Bit;
        NativeProcessHandle = nativeHandle;

        ProcessAttached?.Invoke(this, new ProcessAttachedEventArgs(processId, ProcessName, ProcessPath, Is64Bit, nativeHandle));
        return true;
    }

    /// <summary>
    /// Detach from the current process.
    /// </summary>
    public void Detach()
    {
        if (ProcessId <= 0)
            return;

        // Capture state before clearing so event handlers know which process detached
        var detachedPid = ProcessId;
        var detachedName = ProcessName;

        DebugProvider?.Detach();
        MemoryProvider?.Dispose();
        MemoryProvider = null;

        ProcessId = 0;
        ProcessName = "";
        ProcessPath = "";
        Is64Bit = false;

        ProcessDetached?.Invoke(this, new ProcessDetachedEventArgs(detachedPid, detachedName));
    }

    /// <summary>
    /// Set the memory provider (for switching between user/kernel/hypervisor).
    /// </summary>
    public void SetMemoryProvider(IMemoryProvider provider)
    {
        var oldProvider = MemoryProvider;
        var wasAttached = IsAttached;
        var pid = ProcessId;

        // Detach old provider
        oldProvider?.Dispose();

        // Set new provider
        MemoryProvider = provider;

        // Re-attach if we were attached
        if (wasAttached && pid > 0)
        {
            provider.Attach(pid);
        }

        ProviderChanged?.Invoke(this, new ProviderChangedEventArgs(ProviderType.Memory, provider.Name, provider.Privilege));
    }

    /// <summary>
    /// Set the debug provider (for switching between user/kernel/hypervisor).
    /// </summary>
    public void SetDebugProvider(IDebugProvider provider)
    {
        var oldProvider = DebugProvider;
        oldProvider?.Dispose();

        DebugProvider = provider;
        ProviderChanged?.Invoke(this, new ProviderChangedEventArgs(ProviderType.Debug, provider.Name, provider.Privilege));
    }

    /// <summary>
    /// Set the process provider (for switching between user/kernel/hypervisor).
    /// </summary>
    public void SetProcessProvider(IProcessProvider provider)
    {
        var oldProvider = ProcessProvider;
        oldProvider?.Dispose();

        ProcessProvider = provider;
        ProviderChanged?.Invoke(this, new ProviderChangedEventArgs(ProviderType.Process, provider.Name, provider.Privilege));
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            Detach();
            DebugProvider?.Dispose();
            ProcessProvider?.Dispose();
            _disposed = true;
        }
        GC.SuppressFinalize(this);
    }
}

/// <summary>
/// Event args for process attachment.
/// </summary>
public class ProcessAttachedEventArgs : EventArgs
{
    public int ProcessId { get; }
    public string ProcessName { get; }
    public string ProcessPath { get; }
    public bool Is64Bit { get; }
    public IntPtr ProcessHandle { get; }

    public ProcessAttachedEventArgs(int processId, string name, string path, bool is64Bit, IntPtr processHandle = default)
    {
        ProcessId = processId;
        ProcessName = name;
        ProcessHandle = processHandle;
        ProcessPath = path;
        Is64Bit = is64Bit;
    }
}

/// <summary>
/// Event args for process detachment.
/// </summary>
public class ProcessDetachedEventArgs : EventArgs
{
    public int ProcessId { get; }
    public string ProcessName { get; }

    public ProcessDetachedEventArgs(int processId, string processName)
    {
        ProcessId = processId;
        ProcessName = processName;
    }
}

/// <summary>
/// Event args for provider changes.
/// </summary>
public class ProviderChangedEventArgs : EventArgs
{
    public ProviderType Type { get; }
    public string ProviderName { get; }
    public ProviderPrivilege Privilege { get; }

    public ProviderChangedEventArgs(ProviderType type, string name, ProviderPrivilege privilege)
    {
        Type = type;
        ProviderName = name;
        Privilege = privilege;
    }
}

/// <summary>
/// Provider types.
/// </summary>
public enum ProviderType
{
    Memory,
    Process,
    Debug
}
