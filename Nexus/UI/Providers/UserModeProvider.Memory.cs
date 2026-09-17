// <file>
// <summary>
// User-mode memory provider using engine.dll's ReadProcessMemory/WriteProcessMemory wrappers.
// This is the default provider that works on any Windows system without elevation requirements
// (though some processes may require admin privileges to access).
// </summary>
// </file>

using System.Runtime.InteropServices;
using Nexus.UI.Interop;

namespace Nexus.UI.Providers;

/// <summary>
/// User-mode memory provider using engine.dll's ReadProcessMemory/WriteProcessMemory wrappers.
/// This is the default provider that works on any Windows system without elevation requirements
/// (though some processes may require admin privileges to access).
/// </summary>
public class UserModeMemoryProvider : IMemoryProvider
{
    private IntPtr _processHandle;
    private int _processId;
    private bool _disposed;

    public string Name => "User Mode";
    public ProviderPrivilege Privilege => ProviderPrivilege.UserMode;
    public bool IsAvailable => true; // Always available
    public bool IsAttached => _processHandle != IntPtr.Zero;
    public int ProcessId => _processId;

    public bool Attach(int processId)
    {
        Detach();

        var result = NexusEngine.Nexus_OpenProcess((uint)processId, out _processHandle);
        if (result == NexusResult.OK)
        {
            _processId = processId;
            return true;
        }

        _processHandle = IntPtr.Zero;
        _processId = 0;
        return false;
    }

    public void Detach()
    {
        if (_processHandle != IntPtr.Zero)
        {
            NexusEngine.Nexus_CloseProcess(_processHandle);
            _processHandle = IntPtr.Zero;
            _processId = 0;
        }
    }

    public byte[] ReadMemory(ulong address, int size)
    {
        if (!IsAttached || size <= 0)
            return [];

        return NexusEngine.ReadBytes(_processHandle, address, size);
    }

    public bool WriteMemory(ulong address, byte[] data)
    {
        if (!IsAttached || data == null || data.Length == 0)
            return false;

        return NexusEngine.WriteBytes(_processHandle, address, data);
    }

    public T Read<T>(ulong address) where T : unmanaged
    {
        var size = Marshal.SizeOf<T>();
        var bytes = ReadMemory(address, size);
        if (bytes.Length != size)
            return default;

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
        if (!IsAttached)
            return false;

        var result = NexusEngine.Nexus_QueryMemory(_processHandle, address, out var region);
        return result == NexusResult.OK && region.State == 0x1000; // MEM_COMMIT
    }

    public IEnumerable<MemoryRegionInfo> GetMemoryRegions()
    {
        if (!IsAttached)
            yield break;

        ulong address = 0;
        while (address < 0x7FFFFFFFFFFF)
        {
            var result = NexusEngine.Nexus_QueryMemory(_processHandle, address, out var region);
            if (result != NexusResult.OK)
                break;

            if (region.Size == 0)
                break;

            yield return new MemoryRegionInfo
            {
                BaseAddress = region.BaseAddress,
                Size = region.Size,
                State = region.State,
                Protect = region.Protection,
                Type = region.Type
            };

            address = region.BaseAddress + region.Size;
        }
    }

    public IEnumerable<ModuleInfo> GetModules()
    {
        if (!IsAttached)
            yield break;

        var modules = new NexusModuleInfo[512];
        var result = NexusEngine.Nexus_EnumerateModules(_processHandle, modules, 512, out var count);
        if (result != NexusResult.OK)
            yield break;

        var safeCount = (int)Math.Min(count, (nuint)modules.Length);
        for (int i = 0; i < safeCount; i++)
        {
            yield return new ModuleInfo
            {
                Name = modules[i].Name,
                Path = modules[i].Path,
                BaseAddress = modules[i].BaseAddress,
                Size = modules[i].Size,
                EntryPoint = 0 // Not available in NexusModuleInfo
            };
        }
    }

    public MemoryRegionInfo? QueryMemory(ulong address)
    {
        if (!IsAttached)
            return null;

        var result = NexusEngine.Nexus_QueryMemory(_processHandle, address, out var region);
        if (result != NexusResult.OK)
            return null;

        return new MemoryRegionInfo
        {
            BaseAddress = region.BaseAddress,
            Size = region.Size,
            State = region.State,
            Protect = region.Protection,
            Type = region.Type
        };
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
