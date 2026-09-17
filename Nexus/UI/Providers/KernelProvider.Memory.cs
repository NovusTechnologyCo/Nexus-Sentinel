using System.Runtime.InteropServices;
using Nexus.UI.Interop;

namespace Nexus.UI.Providers;

/// <summary>
/// Kernel-mode implementation of IMemoryProvider using NexusKernel.sys.
/// Provides capabilities beyond user-mode:
/// - Read/write protected process memory
/// - Access kernel memory
/// - Physical memory access
/// - Bypass memory protections
/// </summary>
public class KernelMemoryProvider : IMemoryProvider
{
    private readonly NexusKernelDriver _driver = NexusKernelDriver.Instance;
    private int _processId;
    private bool _disposed;

    public string Name => "Kernel Mode";
    public ProviderPrivilege Privilege => ProviderPrivilege.Kernel;
    public bool IsAvailable => _driver.IsAvailable || _driver.Connect();
    public bool IsAttached => _processId != 0;
    public int ProcessId => _processId;

    public bool Attach(int processId)
    {
        Detach();

        if (!IsAvailable) return false;

        // The driver uses ProcessId directly in each IOCTL, not a handle
        // Just verify the process exists
        try
        {
            _ = System.Diagnostics.Process.GetProcessById(processId);
            _processId = processId;
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    public void Detach()
    {
        _processId = 0;
    }

    public byte[] ReadMemory(ulong address, int size)
    {
        if (!IsAttached || size <= 0) return [];
        return _driver.ReadProcessMemory(_processId, address, size);
    }

    public bool WriteMemory(ulong address, byte[] data)
    {
        if (!IsAttached || data == null || data.Length == 0) return false;
        return _driver.WriteProcessMemory(_processId, address, data);
    }

    public T Read<T>(ulong address) where T : unmanaged
    {
        var size = Marshal.SizeOf<T>();
        var bytes = ReadMemory(address, size);
        if (bytes.Length != size) return default;

        var handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
        try
        {
            return Marshal.PtrToStructure<T>(handle.AddrOfPinnedObject());
        }
        finally
        {
            handle.Free();
        }
    }

    public bool Write<T>(ulong address, T value) where T : unmanaged
    {
        var size = Marshal.SizeOf<T>();
        var bytes = new byte[size];
        var handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
        try
        {
            Marshal.StructureToPtr(value, handle.AddrOfPinnedObject(), false);
        }
        finally
        {
            handle.Free();
        }
        return WriteMemory(address, bytes);
    }

    public bool IsValidAddress(ulong address)
    {
        var region = QueryMemory(address);
        return region?.IsCommitted == true;
    }

    public IEnumerable<MemoryRegionInfo> GetMemoryRegions()
    {
        if (!IsAttached) yield break;

        ulong address = 0;
        while (address < 0x7FFFFFFFFFFF)
        {
            var region = QueryMemory(address);
            if (region == null || region.Size == 0) break;

            yield return region;
            address = region.BaseAddress + region.Size;
        }
    }

    public IEnumerable<ModuleInfo> GetModules()
    {
        if (!IsAttached) yield break;

        var modules = _driver.EnumModules(_processId);
        foreach (var mod in modules)
        {
            yield return new ModuleInfo
            {
                Name = mod.ModuleName ?? "",
                Path = mod.ModulePath ?? "",
                BaseAddress = mod.BaseAddress,
                Size = mod.Size,
                EntryPoint = mod.EntryPoint
            };
        }
    }

    public MemoryRegionInfo? QueryMemory(ulong address)
    {
        if (!IsAttached) return null;

        var input = new NexusQueryMemoryInput
        {
            ProcessId = (uint)_processId,
            Reserved = 0,
            Address = address
        };

        if (_driver.SendIoctl(NexusKernelIoctl.IOCTL_NEXUS_QUERY_MEMORY, ref input, out NexusQueryMemoryOutput output))
        {
            if (output.Status != 0) return null;

            return new MemoryRegionInfo
            {
                BaseAddress = output.BaseAddress,
                Size = output.RegionSize,
                State = output.State,
                Protect = output.Protection,
                Type = output.Type
            };
        }

        return null;
    }

    /// <summary>
    /// Read physical memory directly (kernel-only capability).
    /// </summary>
    public byte[] ReadPhysicalMemory(ulong physicalAddress, int size)
    {
        if (!_driver.IsLoaded || size <= 0) return [];
        return _driver.ReadPhysicalMemory(physicalAddress, size);
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            Detach();
            _disposed = true;
        }
        GC.SuppressFinalize(this);
    }
}
