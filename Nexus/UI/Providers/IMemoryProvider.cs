// <file>
// <summary>
// Memory provider interface abstraction enabling hot-swappable backends for memory access.
// The application can switch between User Mode (ReadProcessMemory), Kernel Mode
// (NexusKernel.sys IOCTL), and Hypervisor (SentinelHV EPT) providers at runtime without
// changing any consuming code. Also defines MemoryRegionInfo, ModuleInfo, and
// ProviderPrivilege types used across all providers.
// </summary>
// </file>

namespace Nexus.UI.Providers;

/// <summary>
/// Memory region information.
/// </summary>
public class MemoryRegionInfo
{
    public ulong BaseAddress { get; init; }
    public ulong Size { get; init; }
    public uint State { get; init; }      // MEM_COMMIT, MEM_RESERVE, MEM_FREE
    public uint Protect { get; init; }    // PAGE_* flags
    public uint Type { get; init; }       // MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE

    public bool IsCommitted => State == 0x1000;  // MEM_COMMIT
    public bool IsReadable => (Protect & 0x02) != 0 || (Protect & 0x04) != 0 || (Protect & 0x20) != 0 || (Protect & 0x40) != 0;
    public bool IsWritable => (Protect & 0x04) != 0 || (Protect & 0x08) != 0 || (Protect & 0x40) != 0 || (Protect & 0x80) != 0;
    public bool IsExecutable => (Protect & 0x10) != 0 || (Protect & 0x20) != 0 || (Protect & 0x40) != 0 || (Protect & 0x80) != 0;
}

/// <summary>
/// Module information.
/// </summary>
public class ModuleInfo
{
    public string Name { get; init; } = "";
    public string Path { get; init; } = "";
    public ulong BaseAddress { get; init; }
    public ulong Size { get; init; }
    public ulong EntryPoint { get; init; }
}

/// <summary>
/// Privilege level for the provider.
/// </summary>
public enum ProviderPrivilege
{
    UserMode,
    Kernel,
    Hypervisor
}

/// <summary>
/// Abstraction for memory operations.
/// Implementations can use user-mode APIs, kernel driver, or hypervisor.
/// </summary>
public interface IMemoryProvider : IDisposable
{
    /// <summary>
    /// Display name of this provider (e.g., "User Mode", "Kernel", "Hypervisor").
    /// </summary>
    string Name { get; }

    /// <summary>
    /// Privilege level of this provider.
    /// </summary>
    ProviderPrivilege Privilege { get; }

    /// <summary>
    /// Whether this provider is available and can be used.
    /// </summary>
    bool IsAvailable { get; }

    /// <summary>
    /// Whether currently attached to a process.
    /// </summary>
    bool IsAttached { get; }

    /// <summary>
    /// Currently attached process ID, or 0 if not attached.
    /// </summary>
    int ProcessId { get; }

    /// <summary>
    /// Attach to a process by PID.
    /// </summary>
    bool Attach(int processId);

    /// <summary>
    /// Detach from the current process.
    /// </summary>
    void Detach();

    /// <summary>
    /// Read memory from the attached process.
    /// </summary>
    byte[] ReadMemory(ulong address, int size);

    /// <summary>
    /// Write memory to the attached process.
    /// </summary>
    bool WriteMemory(ulong address, byte[] data);

    /// <summary>
    /// Read a specific value type from memory.
    /// </summary>
    T Read<T>(ulong address) where T : unmanaged;

    /// <summary>
    /// Write a specific value type to memory.
    /// </summary>
    bool Write<T>(ulong address, T value) where T : unmanaged;

    /// <summary>
    /// Check if an address is valid (committed memory).
    /// </summary>
    bool IsValidAddress(ulong address);

    /// <summary>
    /// Get all memory regions for the attached process.
    /// </summary>
    IEnumerable<MemoryRegionInfo> GetMemoryRegions();

    /// <summary>
    /// Get all loaded modules for the attached process.
    /// </summary>
    IEnumerable<ModuleInfo> GetModules();

    /// <summary>
    /// Query information about a specific memory region.
    /// </summary>
    MemoryRegionInfo? QueryMemory(ulong address);
}
