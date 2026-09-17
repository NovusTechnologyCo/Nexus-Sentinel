// Bootkit mapper operations: driver loading, unloading, comm channels, and kernel caller registration.
// Split from NexusEngine.Bootkit.cs for maintainability.

using System.Runtime.InteropServices;

namespace Nexus.UI.Interop;

public static partial class NexusEngine
{
    #region Mapper Operations

    /// <summary>
    /// Queries the NexusMapper status via the simple protocol.
    /// Uses "NexusMapperQuery" variable name with Command in Status field.
    /// </summary>
    public static BootkitResult QueryMapperStatus(out MapperStatusResponse status)
    {
        status = default;

        var result = AcquireBootkitPrivileges();
        if (result != BootkitResult.Success)
            return result;

        // Build query request - Command goes in Status field
        var response = new MapperStatusResponse
        {
            Status = NEXUS_MAPPER_CMD_QUERY,  // Command in Status field initially
            MapperState = 0,
            MapperBase = 0,
            MapperSize = 0,
            LoadedDriverCount = 0
        };

        var varName = CreateUnicodeString("NexusCoreQuery");
        var guid = NexusMapperGuid;
        var dataSize = Marshal.SizeOf<MapperStatusResponse>();
        var dataPtr = Marshal.AllocHGlobal(dataSize);

        try
        {
            Marshal.StructureToPtr(response, dataPtr, false);

            int ntStatus = NtSetSystemEnvironmentValueEx(
                ref varName,
                ref guid,
                dataPtr,
                (uint)dataSize,
                NexusVariableAttributes);

            if (ntStatus != 0)
            {
                return BootkitResult.NtError;
            }

            status = Marshal.PtrToStructure<MapperStatusResponse>(dataPtr);
            return BootkitResult.Success;
        }
        finally
        {
            Marshal.FreeHGlobal(dataPtr);
            FreeUnicodeString(ref varName);
        }
    }

    /// <summary>
    /// Initializes the NexusMapper driver with the ntoskrnl base address.
    /// Uses "NexusMapperInit" variable name.
    /// </summary>
    public static BootkitResult InitializeMapper(ulong ntoskrnlBase)
    {
        var result = AcquireBootkitPrivileges();
        if (result != BootkitResult.Success)
            return result;

        var request = new NEXUS_MAPPER_INIT_REQUEST
        {
            Command = NEXUS_MAPPER_CMD_INIT,
            NtoskrnlBase = ntoskrnlBase
        };

        var varName = CreateUnicodeString("NexusCoreInit");
        var guid = NexusMapperGuid;
        var dataPtr = Marshal.AllocHGlobal(Marshal.SizeOf<NEXUS_MAPPER_INIT_REQUEST>());

        try
        {
            Marshal.StructureToPtr(request, dataPtr, false);

            int ntStatus = NtSetSystemEnvironmentValueEx(
                ref varName,
                ref guid,
                dataPtr,
                (uint)Marshal.SizeOf<NEXUS_MAPPER_INIT_REQUEST>(),
                NexusVariableAttributes);

            if (ntStatus != 0)
            {
                return BootkitResult.NtError;
            }

            // Check result (returned in Command field)
            request = Marshal.PtrToStructure<NEXUS_MAPPER_INIT_REQUEST>(dataPtr);
            if (request.Command != 0)  // 0 = success
            {
                return BootkitResult.MapperNotReady;
            }

            return BootkitResult.Success;
        }
        finally
        {
            Marshal.FreeHGlobal(dataPtr);
            FreeUnicodeString(ref varName);
        }
    }

    /// <summary>
    /// Registers a kernel driver as a trusted caller for the mapper.
    /// After registration, the kernel driver can send commands to the mapper.
    /// </summary>
    public static BootkitResult RegisterKernelCaller(ulong callerToken, ulong callerBase)
    {
        var result = AcquireBootkitPrivileges();
        if (result != BootkitResult.Success)
            return result;

        var request = new MAPPER_REGISTER_REQUEST
        {
            Header = new MAPPER_CMD_HEADER
            {
                Magic = MAPPER_CMD_REGISTER_CALLER,
                Size = (uint)Marshal.SizeOf<MAPPER_REGISTER_REQUEST>(),
                Flags = 0,
                Reserved = 0
            },
            CallerToken = callerToken,
            CallerBase = callerBase
        };

        var varName = CreateUnicodeString(MapperVariableName);
        var guid = NexusMapperGuid;
        var dataPtr = Marshal.AllocHGlobal(Marshal.SizeOf<MAPPER_REGISTER_REQUEST>());

        try
        {
            Marshal.StructureToPtr(request, dataPtr, false);

            int ntStatus = NtSetSystemEnvironmentValueEx(
                ref varName,
                ref guid,
                dataPtr,
                (uint)Marshal.SizeOf<MAPPER_REGISTER_REQUEST>(),
                NexusVariableAttributes);

            if (ntStatus != 0)
            {
                return BootkitResult.NtError;
            }

            return BootkitResult.Success;
        }
        finally
        {
            Marshal.FreeHGlobal(dataPtr);
            FreeUnicodeString(ref varName);
        }
    }

    /// <summary>
    /// Unregisters the kernel caller.
    /// </summary>
    public static BootkitResult UnregisterKernelCaller()
    {
        var result = AcquireBootkitPrivileges();
        if (result != BootkitResult.Success)
            return result;

        var header = new MAPPER_CMD_HEADER
        {
            Magic = MAPPER_CMD_UNREGISTER_CALLER,
            Size = (uint)Marshal.SizeOf<MAPPER_CMD_HEADER>(),
            Flags = 0,
            Reserved = 0
        };

        var varName = CreateUnicodeString(MapperVariableName);
        var guid = NexusMapperGuid;
        var dataPtr = Marshal.AllocHGlobal(Marshal.SizeOf<MAPPER_CMD_HEADER>());

        try
        {
            Marshal.StructureToPtr(header, dataPtr, false);

            int ntStatus = NtSetSystemEnvironmentValueEx(
                ref varName,
                ref guid,
                dataPtr,
                (uint)Marshal.SizeOf<MAPPER_CMD_HEADER>(),
                NexusVariableAttributes);

            if (ntStatus != 0)
            {
                return BootkitResult.NtError;
            }

            return BootkitResult.Success;
        }
        finally
        {
            Marshal.FreeHGlobal(dataPtr);
            FreeUnicodeString(ref varName);
        }
    }

    /// <summary>
    /// Maps a driver into kernel memory using the mapper's native protocol.
    /// </summary>
    /// <param name="driverBytes">The driver file bytes</param>
    /// <param name="eraseHeader">Whether to erase PE headers after mapping</param>
    /// <param name="randomizePoolTag">Whether to use a random pool tag</param>
    /// <param name="response">The mapping response with base address</param>
    public static BootkitResult MapDriver(byte[] driverBytes, bool eraseHeader, bool randomizePoolTag, out MapperLoadResponse response)
    {
        response = default;

        var result = AcquireBootkitPrivileges();
        if (result != BootkitResult.Success)
            return result;

        // Build flags - LOAD_FLAG_FROM_BUFFER is required
        uint flags = LOAD_FLAG_FROM_BUFFER;
        if (eraseHeader) flags |= LOAD_FLAG_ERASE_HEADER;
        if (randomizePoolTag) flags |= LOAD_FLAG_RANDOMIZE_TAG;

        // Build request using mapper's native format: MAPPER_LOAD_REQUEST
        // { Magic(4), Size(4), Flags(4), Reserved(4), ImageSize(8), Reserved1(8), Reserved2(8), Data[] }
        var headerSize = Marshal.SizeOf<MAPPER_LOAD_REQUEST_HEADER>();
        var totalSize = headerSize + driverBytes.Length;

        var header = new MAPPER_LOAD_REQUEST_HEADER
        {
            Header = new MAPPER_CMD_HEADER
            {
                Magic = MAPPER_CMD_LOAD_DRIVER,  // 'LOAD' = 0x4C4F4144
                Size = (uint)totalSize,
                Flags = flags,
                Reserved = 0
            },
            ImageSize = (ulong)driverBytes.Length,
            Reserved1 = 0,
            Reserved2 = 0
        };

        var varName = CreateUnicodeString(MapperVariableName);
        var guid = NexusMapperGuid;

        // Allocate buffer for request + response
        var responseSize = Marshal.SizeOf<MapperLoadResponse>();
        var bufferSize = Math.Max(totalSize, responseSize);
        var dataPtr = Marshal.AllocHGlobal(bufferSize);

        try
        {
            // Copy header
            Marshal.StructureToPtr(header, dataPtr, false);

            // Copy driver bytes after header
            Marshal.Copy(driverBytes, 0, dataPtr + headerSize, driverBytes.Length);

            int ntStatus = NtSetSystemEnvironmentValueEx(
                ref varName,
                ref guid,
                dataPtr,
                (uint)totalSize,
                NexusVariableAttributes);

            if (ntStatus != 0)
            {
                return BootkitResult.NtError;
            }

            // Read response - mapper writes MAPPER_LOAD_RESPONSE back to buffer
            response = Marshal.PtrToStructure<MapperLoadResponse>(dataPtr);

            if (response.Status != 0)
            {
                LastMapperStatus = response.Status;
                return BootkitResult.LoadFailed;
            }

            LastMapperStatus = 0;

            return BootkitResult.Success;
        }
        finally
        {
            Marshal.FreeHGlobal(dataPtr);
            FreeUnicodeString(ref varName);
        }
    }

    /// <summary>
    /// Queries a loaded driver's communication channel info.
    /// Used to discover the shared memory address for mapped drivers.
    /// </summary>
    /// <param name="info">The comm channel info if successful</param>
    /// <param name="driverBase">Base address of driver to query (0 = last loaded)</param>
    public static BootkitResult QueryDriverCommInfo(out DriverCommInfo info, ulong driverBase = 0)
    {
        info = default;

        var result = AcquireBootkitPrivileges();
        if (result != BootkitResult.Success)
            return result;

        // Build COMM query request
        var request = new MAPPER_QUERY_COMM_REQUEST
        {
            Header = new MAPPER_CMD_HEADER
            {
                Magic = MAPPER_CMD_QUERY_DRIVER_COMM,  // 'COMM'
                Size = (uint)Marshal.SizeOf<MAPPER_QUERY_COMM_REQUEST>(),
                Flags = 0,
                Reserved = 0
            },
            DriverBase = driverBase  // 0 = last loaded driver
        };

        var varName = CreateUnicodeString(MapperVariableName);
        var guid = NexusMapperGuid;

        // Response may be larger than request
        var responseSize = Marshal.SizeOf<DriverCommInfo>();
        var bufferSize = Math.Max(Marshal.SizeOf<MAPPER_QUERY_COMM_REQUEST>(), responseSize + 16);
        var dataPtr = Marshal.AllocHGlobal(bufferSize);

        try
        {
            Marshal.StructureToPtr(request, dataPtr, false);

            int ntStatus = NtSetSystemEnvironmentValueEx(
                ref varName,
                ref guid,
                dataPtr,
                (uint)bufferSize,
                NexusVariableAttributes);

            if (ntStatus != 0)
                return BootkitResult.NtError;

            // Read response - first 4 bytes is Status
            info = Marshal.PtrToStructure<DriverCommInfo>(dataPtr);

            if (info.Status != 0)
                return BootkitResult.DriverError;

            return BootkitResult.Success;
        }
        finally
        {
            Marshal.FreeHGlobal(dataPtr);
        }
    }

    /// <summary>
    /// Maps the driver's comm channel into the calling process's address space.
    /// Returns a user-mode pointer to the shared memory region.
    /// </summary>
    /// <param name="mappedAddress">Receives the user-mode virtual address of the mapped memory</param>
    /// <param name="size">Receives the size of the mapped region</param>
    /// <param name="driverBase">Base address of the driver (0 = last loaded driver)</param>
    /// <returns>Success if mapping succeeded</returns>
    public static BootkitResult MapDriverCommChannel(out IntPtr mappedAddress, out ulong size, ulong driverBase = 0)
    {
        return MapDriverCommChannel(out mappedAddress, out size, out _, driverBase);
    }

    /// <summary>
    /// Maps the driver's comm channel into the calling process's address space.
    /// Returns a user-mode pointer to the shared memory region.
    /// </summary>
    /// <param name="mappedAddress">Receives the user-mode virtual address of the mapped memory</param>
    /// <param name="size">Receives the size of the mapped region</param>
    /// <param name="ntStatus">Receives the NTSTATUS from the driver on failure</param>
    /// <param name="driverBase">Base address of the driver (0 = last loaded driver)</param>
    /// <returns>Success if mapping succeeded</returns>
    public static BootkitResult MapDriverCommChannel(out IntPtr mappedAddress, out ulong size, out int ntStatus, ulong driverBase = 0)
    {
        mappedAddress = IntPtr.Zero;
        size = 0;
        ntStatus = 0;

        var result = AcquireBootkitPrivileges();
        if (result != BootkitResult.Success)
            return result;

        // Build MAP_COMM request
        var request = new MAPPER_MAP_COMM_REQUEST
        {
            Header = new MAPPER_CMD_HEADER
            {
                Magic = MAPPER_CMD_MAP_COMM,  // 'MAPC'
                Size = (uint)Marshal.SizeOf<MAPPER_MAP_COMM_REQUEST>(),
                Flags = 0,
                Reserved = 0
            },
            DriverBase = driverBase  // 0 = last loaded driver
        };

        var varName = CreateUnicodeString(MapperVariableName);
        var guid = NexusMapperGuid;

        // Response may be larger than request
        var responseSize = Marshal.SizeOf<MapCommResponse>();
        var bufferSize = Math.Max(Marshal.SizeOf<MAPPER_MAP_COMM_REQUEST>(), responseSize + 16);
        var dataPtr = Marshal.AllocHGlobal(bufferSize);

        try
        {
            Marshal.StructureToPtr(request, dataPtr, false);

            int sysStatus = NtSetSystemEnvironmentValueEx(
                ref varName,
                ref guid,
                dataPtr,
                (uint)bufferSize,
                NexusVariableAttributes);

            if (sysStatus != 0)
                return BootkitResult.NtError;

            // Read response
            var response = Marshal.PtrToStructure<MapCommResponse>(dataPtr);

            ntStatus = response.Status;
            if (response.Status != 0)
                return BootkitResult.DriverError;

            mappedAddress = new IntPtr((long)response.MappedAddress);
            size = response.Size;

            return BootkitResult.Success;
        }
        finally
        {
            Marshal.FreeHGlobal(dataPtr);
        }
    }

    /// <summary>
    /// Queries the full mapper status using the new command protocol.
    /// </summary>
    public static BootkitResult QueryMapperFullStatus(out MapperFullStatus status)
    {
        status = default;

        var result = AcquireBootkitPrivileges();
        if (result != BootkitResult.Success)
            return result;

        var header = new MAPPER_CMD_HEADER
        {
            Magic = MAPPER_CMD_QUERY_STATUS,
            Size = (uint)Marshal.SizeOf<MAPPER_CMD_HEADER>(),
            Flags = 0,
            Reserved = 0
        };

        var varName = CreateUnicodeString(MapperVariableName);
        var guid = NexusMapperGuid;

        var responseSize = Marshal.SizeOf<MapperFullStatus>();
        var bufferSize = Math.Max(Marshal.SizeOf<MAPPER_CMD_HEADER>(), responseSize);
        var dataPtr = Marshal.AllocHGlobal(bufferSize);

        try
        {
            Marshal.StructureToPtr(header, dataPtr, false);

            int ntStatus = NtSetSystemEnvironmentValueEx(
                ref varName,
                ref guid,
                dataPtr,
                (uint)Marshal.SizeOf<MAPPER_CMD_HEADER>(),
                NexusVariableAttributes);

            if (ntStatus != 0)
            {
                return BootkitResult.NtError;
            }

            status = Marshal.PtrToStructure<MapperFullStatus>(dataPtr);
            return BootkitResult.Success;
        }
        finally
        {
            Marshal.FreeHGlobal(dataPtr);
            FreeUnicodeString(ref varName);
        }
    }

    #endregion

    #region High-Level Convenience Methods

    /// <summary>
    /// Loads a driver from a file path.
    /// </summary>
    public static BootkitResult MapDriverFromFile(string filePath, bool eraseHeader, bool randomizePoolTag, out MapperLoadResponse response)
    {
        response = default;

        if (!File.Exists(filePath))
            return BootkitResult.InvalidParameter;

        byte[] driverBytes;
        try
        {
            driverBytes = File.ReadAllBytes(filePath);
        }
        catch
        {
            return BootkitResult.InvalidParameter;
        }

        return MapDriver(driverBytes, eraseHeader, randomizePoolTag, out response);
    }

    /// <summary>
    /// Unloads (unmaps) a previously mapped driver.
    /// If the driver exports NexusDriverUnload, it will be called for clean shutdown.
    /// Otherwise the memory is force-freed (may BSOD if driver has active hooks).
    /// </summary>
    /// <param name="driverBase">Base address of the mapped driver to unload</param>
    public static BootkitResult UnloadDriver(ulong driverBase)
    {
        if (driverBase == 0)
            return BootkitResult.InvalidParameter;

        var result = AcquireBootkitPrivileges();
        if (result != BootkitResult.Success)
            return result;

        var request = new MAPPER_UNLOAD_REQUEST
        {
            Header = new MAPPER_CMD_HEADER
            {
                Magic = MAPPER_CMD_UNLOAD_DRIVER,  // 'UNLD' = 0x554E4C44
                Size = (uint)Marshal.SizeOf<MAPPER_UNLOAD_REQUEST>(),
                Flags = 0,
                Reserved = 0
            },
            DriverBase = driverBase
        };

        var varName = CreateUnicodeString(MapperVariableName);
        var guid = NexusMapperGuid;
        var dataSize = Marshal.SizeOf<MAPPER_UNLOAD_REQUEST>();
        var dataPtr = Marshal.AllocHGlobal(dataSize);

        try
        {
            Marshal.StructureToPtr(request, dataPtr, false);

            int ntStatus = NtSetSystemEnvironmentValueEx(
                ref varName,
                ref guid,
                dataPtr,
                (uint)dataSize,
                NexusVariableAttributes);

            if (ntStatus != 0)
                return BootkitResult.NtError;

            // On error, the first 4 bytes contain NTSTATUS from the mapper
            uint mapperStatus = (uint)Marshal.ReadInt32(dataPtr);
            if (mapperStatus != 0 && mapperStatus != MAPPER_CMD_UNLOAD_DRIVER)
            {
                LastMapperStatus = mapperStatus;
                return BootkitResult.DriverError;
            }

            return BootkitResult.Success;
        }
        finally
        {
            Marshal.FreeHGlobal(dataPtr);
            FreeUnicodeString(ref varName);
        }
    }

    /// <summary>
    /// Gets a human-readable status string for a bootkit result.
    /// </summary>
    public static string GetBootkitResultString(BootkitResult result)
    {
        return result switch
        {
            BootkitResult.Success => "Success",
            BootkitResult.AccessDenied => "Access denied - run as administrator",
            BootkitResult.HookNotInstalled => "SetVariable hook not installed - boot with NexusBoot",
            BootkitResult.VbsEnabled => "VBS (Virtualization Based Security) is enabled",
            BootkitResult.InvalidParameter => "Invalid parameter",
            BootkitResult.NotInitialized => "Mapper not initialized",
            BootkitResult.AlreadyInitialized => "Mapper already initialized",
            BootkitResult.MapperNotReady => "Mapper not ready",
            BootkitResult.LoadFailed => "Driver load failed",
            BootkitResult.PrivilegeError => "Failed to acquire required privileges",
            BootkitResult.NtError => "NT API call failed",
            _ => $"Unknown error ({result})"
        };
    }

    #endregion
}
