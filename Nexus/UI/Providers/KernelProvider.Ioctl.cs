using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using Nexus.UI.Interop;

namespace Nexus.UI.Providers;

public partial class NexusKernelDriver
{
    #region Process Watch - Intercept process creation for hooking

    /// <summary>
    /// Set a process watch pattern. When a process matching the pattern is created,
    /// it will be suspended immediately, allowing user-mode to apply hooks.
    /// </summary>
    /// <param name="processNamePattern">Substring to match in process name (case-insensitive)</param>
    /// <returns>True if watch was set successfully</returns>
    public bool SetProcessWatch(string processNamePattern)
    {
        if (!IsLoaded || string.IsNullOrEmpty(processNamePattern)) return false;

        var input = new NexusProcessWatchInput
        {
            ProcessNamePattern = processNamePattern,
            Flags = 0,
            Reserved = 0
        };

        var inSize = Marshal.SizeOf<NexusProcessWatchInput>();
        var inPtr = Marshal.AllocHGlobal(inSize);

        try
        {
            Marshal.StructureToPtr(input, inPtr, false);

            bool result = DeviceIoControl(
                _deviceHandle!,
                NexusKernelIoctl.IOCTL_NEXUS_SET_PROCESS_WATCH,
                inPtr,
                (uint)inSize,
                IntPtr.Zero,
                0,
                out _,
                IntPtr.Zero);

            if (!result)
            {
                int error = Marshal.GetLastWin32Error();
                System.Diagnostics.Trace.WriteLine($"SetProcessWatch failed: Win32 error {error} (0x{error:X})");
            }

            return result;
        }
        finally
        {
            Marshal.FreeHGlobal(inPtr);
        }
    }

    /// <summary>
    /// Clear the process watch. Does NOT resume any suspended process.
    /// </summary>
    public bool ClearProcessWatch()
    {
        if (!IsLoaded) return false;
        return SendIoctlNoInput(NexusKernelIoctl.IOCTL_NEXUS_CLEAR_PROCESS_WATCH);
    }

    /// <summary>
    /// Get information about the watched (suspended) process, if any.
    /// </summary>
    /// <returns>Info about suspended process, or null if no process is watched</returns>
    public NexusWatchedProcessInfo? GetWatchedProcess()
    {
        if (!IsLoaded) return null;

        var outPtr = Marshal.AllocHGlobal(Marshal.SizeOf<NexusWatchedProcessInfo>());
        try
        {
            bool result = DeviceIoControl(
                _deviceHandle!,
                NexusKernelIoctl.IOCTL_NEXUS_GET_WATCHED_PROCESS,
                IntPtr.Zero,
                0,
                outPtr,
                (uint)Marshal.SizeOf<NexusWatchedProcessInfo>(),
                out uint bytesReturned,
                IntPtr.Zero);

            if (!result || bytesReturned < Marshal.SizeOf<NexusWatchedProcessInfo>())
                return null;

            return Marshal.PtrToStructure<NexusWatchedProcessInfo>(outPtr);
        }
        finally
        {
            Marshal.FreeHGlobal(outPtr);
        }
    }

    /// <summary>
    /// Resume the watched (suspended) process. Call this after applying hooks.
    /// </summary>
    public bool ResumeWatchedProcess()
    {
        if (!IsLoaded) return false;
        return SendIoctlNoInput(NexusKernelIoctl.IOCTL_NEXUS_RESUME_WATCHED);
    }

    /// <summary>
    /// Helper to send IOCTL with no input.
    /// </summary>
    private bool SendIoctlNoInput(uint ioctlCode)
    {
        return DeviceIoControl(
            _deviceHandle!,
            ioctlCode,
            IntPtr.Zero,
            0,
            IntPtr.Zero,
            0,
            out _,
            IntPtr.Zero);
    }

    #endregion

    #region CI / SecureBoot Operations

    /// <summary>
    /// Get CI.dll information including g_CiOptions address and value.
    /// </summary>
    /// <returns>CI info if successful, null otherwise</returns>
    public NexusCiInfo? GetCiInfo()
    {
        if (!IsLoaded) return null;

        var outPtr = Marshal.AllocHGlobal(Marshal.SizeOf<NexusCiInfo>());
        try
        {
            bool result = DeviceIoControl(
                _deviceHandle!,
                NexusKernelIoctl.IOCTL_NEXUS_GET_CI_INFO,
                IntPtr.Zero,
                0,
                outPtr,
                (uint)Marshal.SizeOf<NexusCiInfo>(),
                out uint bytesReturned,
                IntPtr.Zero);

            if (!result || bytesReturned < Marshal.SizeOf<NexusCiInfo>())
            {
                int error = Marshal.GetLastWin32Error();
                System.Diagnostics.Trace.WriteLine($"GetCiInfo failed: Win32 error {error} (0x{error:X})");
                return null;
            }

            return Marshal.PtrToStructure<NexusCiInfo>(outPtr);
        }
        finally
        {
            Marshal.FreeHGlobal(outPtr);
        }
    }

    /// <summary>
    /// Spoof g_CiOptions to a new value.
    /// Use this to enable SecureBoot flag: newValue = currentValue | CI_OPTION_SECURE_BOOT
    /// </summary>
    /// <param name="newCiOptions">New value to write to g_CiOptions</param>
    /// <param name="flags">Reserved flags (pass 0)</param>
    /// <returns>True if successful</returns>
    public bool SpoofCiOptions(uint newCiOptions, uint flags = 0)
    {
        if (!IsLoaded) return false;

        var input = new NexusSpoofCiInput
        {
            NewCiOptions = newCiOptions,
            Flags = flags
        };

        var inSize = Marshal.SizeOf<NexusSpoofCiInput>();
        var inPtr = Marshal.AllocHGlobal(inSize);

        try
        {
            Marshal.StructureToPtr(input, inPtr, false);

            bool result = DeviceIoControl(
                _deviceHandle!,
                NexusKernelIoctl.IOCTL_NEXUS_SPOOF_CI_OPTIONS,
                inPtr,
                (uint)inSize,
                IntPtr.Zero,
                0,
                out _,
                IntPtr.Zero);

            if (!result)
            {
                int error = Marshal.GetLastWin32Error();
                System.Diagnostics.Trace.WriteLine($"SpoofCiOptions failed: Win32 error {error} (0x{error:X})");
            }

            return result;
        }
        finally
        {
            Marshal.FreeHGlobal(inPtr);
        }
    }

    /// <summary>
    /// Enable SecureBoot flag in g_CiOptions.
    /// </summary>
    /// <returns>True if successful</returns>
    public bool EnableSecureBootFlag()
    {
        var ciInfo = GetCiInfo();
        if (ciInfo == null || ciInfo.Value.CiOptionsAddress == 0)
        {
            System.Diagnostics.Trace.WriteLine("Cannot enable SecureBoot flag: g_CiOptions not found");
            return false;
        }

        uint newValue = ciInfo.Value.CiOptionsValue | CiOptionsFlags.CI_OPTION_SECURE_BOOT;
        return SpoofCiOptions(newValue);
    }

    /// <summary>
    /// Format CI options value as human-readable string.
    /// </summary>
    public static string FormatCiOptions(uint ciOptions)
    {
        var flags = new List<string>();

        if ((ciOptions & CiOptionsFlags.CI_OPTION_ENABLED) != 0)
            flags.Add("CI_ENABLED");
        if ((ciOptions & CiOptionsFlags.CI_OPTION_TESTSIGN) != 0)
            flags.Add("TESTSIGN");
        if ((ciOptions & CiOptionsFlags.CI_OPTION_UMCI) != 0)
            flags.Add("UMCI");
        if ((ciOptions & CiOptionsFlags.CI_OPTION_DEBUGGER_ENABLED) != 0)
            flags.Add("DEBUGGER");
        if ((ciOptions & CiOptionsFlags.CI_OPTION_FLIGHT_SIGNING) != 0)
            flags.Add("FLIGHTSIGN");
        if ((ciOptions & CiOptionsFlags.CI_OPTION_SECURE_BOOT) != 0)
            flags.Add("SECUREBOOT");

        return flags.Count > 0 ? string.Join(" | ", flags) : "NONE";
    }

    #endregion

    #region Syscall Hook Operations

    /// <summary>
    /// Install the NtQuerySystemInformation hook for SecureBoot spoofing.
    /// </summary>
    public bool InstallSyscallHook()
    {
        if (!IsLoaded) return false;

        bool result = DeviceIoControl(
            _deviceHandle!,
            NexusKernelIoctl.IOCTL_NEXUS_INSTALL_SYSCALL_HOOK,
            IntPtr.Zero,
            0,
            IntPtr.Zero,
            0,
            out _,
            IntPtr.Zero);

        if (!result)
        {
            int error = Marshal.GetLastWin32Error();
            System.Diagnostics.Trace.WriteLine($"InstallSyscallHook failed: Win32 error {error} (0x{error:X})");
        }

        return result;
    }

    /// <summary>
    /// Remove the syscall hook.
    /// </summary>
    public bool RemoveSyscallHook()
    {
        if (!IsLoaded) return false;

        bool result = DeviceIoControl(
            _deviceHandle!,
            NexusKernelIoctl.IOCTL_NEXUS_REMOVE_SYSCALL_HOOK,
            IntPtr.Zero,
            0,
            IntPtr.Zero,
            0,
            out _,
            IntPtr.Zero);

        return result;
    }

    /// <summary>
    /// Enable or disable the syscall hook spoofing.
    /// </summary>
    public bool EnableSyscallHook(bool enable)
    {
        if (!IsLoaded) return false;

        var input = new NexusEnableHookInput { Enable = enable ? 1u : 0u, Reserved = 0 };
        var inSize = Marshal.SizeOf<NexusEnableHookInput>();
        var inPtr = Marshal.AllocHGlobal(inSize);

        try
        {
            Marshal.StructureToPtr(input, inPtr, false);

            bool result = DeviceIoControl(
                _deviceHandle!,
                NexusKernelIoctl.IOCTL_NEXUS_ENABLE_SYSCALL_HOOK,
                inPtr,
                (uint)inSize,
                IntPtr.Zero,
                0,
                out _,
                IntPtr.Zero);

            return result;
        }
        finally
        {
            Marshal.FreeHGlobal(inPtr);
        }
    }

    /// <summary>
    /// Get syscall hook status.
    /// </summary>
    public NexusSyscallHookStatus? GetSyscallHookStatus()
    {
        if (!IsLoaded) return null;

        var outPtr = Marshal.AllocHGlobal(Marshal.SizeOf<NexusSyscallHookStatus>());
        try
        {
            bool result = DeviceIoControl(
                _deviceHandle!,
                NexusKernelIoctl.IOCTL_NEXUS_GET_SYSCALL_HOOK_STATUS,
                IntPtr.Zero,
                0,
                outPtr,
                (uint)Marshal.SizeOf<NexusSyscallHookStatus>(),
                out uint bytesReturned,
                IntPtr.Zero);

            if (!result || bytesReturned < Marshal.SizeOf<NexusSyscallHookStatus>())
            {
                return null;
            }

            return Marshal.PtrToStructure<NexusSyscallHookStatus>(outPtr);
        }
        finally
        {
            Marshal.FreeHGlobal(outPtr);
        }
    }

    #endregion

    #region Memory Monitor Methods

    /// <summary>
    /// Start monitoring reads/writes to a kernel address.
    /// Uses global hardware breakpoints (DR0-DR3) to detect access.
    /// </summary>
    /// <param name="address">Kernel address to monitor (e.g., g_CiOptions)</param>
    /// <param name="size">Size: 1, 2, 4, or 8 bytes</param>
    /// <param name="type">MemoryMonitorType.Write or ReadWrite</param>
    /// <param name="description">Optional description for logging</param>
    /// <returns>Monitor index (0-3) or -1 on failure</returns>
    public int StartMemoryMonitor(ulong address, uint size, uint type, string description = "")
    {
        if (!IsLoaded) return -1;

        var input = new NexusStartMonitorInput
        {
            Address = address,
            Size = size,
            Type = type,
            Description = description ?? ""
        };

        var inPtr = IntPtr.Zero;
        var outPtr = IntPtr.Zero;

        try
        {
            inPtr = Marshal.AllocHGlobal(Marshal.SizeOf<NexusStartMonitorInput>());
            outPtr = Marshal.AllocHGlobal(Marshal.SizeOf<NexusStartMonitorOutput>());

            Marshal.StructureToPtr(input, inPtr, false);

            bool result = DeviceIoControl(
                _deviceHandle!,
                NexusKernelIoctl.IOCTL_NEXUS_START_MEMORY_MONITOR,
                inPtr,
                (uint)Marshal.SizeOf<NexusStartMonitorInput>(),
                outPtr,
                (uint)Marshal.SizeOf<NexusStartMonitorOutput>(),
                out uint bytesReturned,
                IntPtr.Zero);

            if (!result || bytesReturned < Marshal.SizeOf<NexusStartMonitorOutput>())
            {
                return -1;
            }

            var output = Marshal.PtrToStructure<NexusStartMonitorOutput>(outPtr);
            return output.Status == 0 ? (int)output.MonitorIndex : -1;
        }
        finally
        {
            if (inPtr != IntPtr.Zero) Marshal.FreeHGlobal(inPtr);
            if (outPtr != IntPtr.Zero) Marshal.FreeHGlobal(outPtr);
        }
    }

    /// <summary>
    /// Stop monitoring a specific address.
    /// </summary>
    /// <param name="monitorIndex">Monitor index to stop (0-3)</param>
    /// <returns>True on success</returns>
    public bool StopMemoryMonitor(uint monitorIndex)
    {
        if (!IsLoaded) return false;

        var input = new NexusStopMonitorInput
        {
            MonitorIndex = monitorIndex,
            Reserved = 0
        };

        var inPtr = Marshal.AllocHGlobal(Marshal.SizeOf<NexusStopMonitorInput>());

        try
        {
            Marshal.StructureToPtr(input, inPtr, false);

            return DeviceIoControl(
                _deviceHandle!,
                NexusKernelIoctl.IOCTL_NEXUS_STOP_MEMORY_MONITOR,
                inPtr,
                (uint)Marshal.SizeOf<NexusStopMonitorInput>(),
                IntPtr.Zero,
                0,
                out _,
                IntPtr.Zero);
        }
        finally
        {
            Marshal.FreeHGlobal(inPtr);
        }
    }

    /// <summary>
    /// Stop all memory monitors.
    /// </summary>
    /// <returns>True on success</returns>
    public bool StopAllMemoryMonitors()
    {
        if (!IsLoaded) return false;

        return DeviceIoControl(
            _deviceHandle!,
            NexusKernelIoctl.IOCTL_NEXUS_STOP_ALL_MONITORS,
            IntPtr.Zero,
            0,
            IntPtr.Zero,
            0,
            out _,
            IntPtr.Zero);
    }

    /// <summary>
    /// Get memory monitor status.
    /// </summary>
    public NexusMemoryMonitorStatus? GetMemoryMonitorStatus()
    {
        if (!IsLoaded) return null;

        var outPtr = Marshal.AllocHGlobal(Marshal.SizeOf<NexusMemoryMonitorStatus>());

        try
        {
            bool result = DeviceIoControl(
                _deviceHandle!,
                NexusKernelIoctl.IOCTL_NEXUS_GET_MONITOR_STATUS,
                IntPtr.Zero,
                0,
                outPtr,
                (uint)Marshal.SizeOf<NexusMemoryMonitorStatus>(),
                out uint bytesReturned,
                IntPtr.Zero);

            if (!result || bytesReturned < Marshal.SizeOf<NexusMemoryMonitorStatus>())
            {
                return null;
            }

            return Marshal.PtrToStructure<NexusMemoryMonitorStatus>(outPtr);
        }
        finally
        {
            Marshal.FreeHGlobal(outPtr);
        }
    }

    /// <summary>
    /// Get memory access log entries.
    /// Returns who accessed monitored addresses (module name, RIP, etc.)
    /// </summary>
    /// <param name="maxEntries">Maximum entries to retrieve</param>
    public List<NexusMemoryAccessEntry> GetMemoryAccessLog(uint maxEntries = 64)
    {
        var entries = new List<NexusMemoryAccessEntry>();
        if (!IsLoaded) return entries;

        var input = new NexusGetAccessLogInput
        {
            MaxEntries = maxEntries,
            Reserved = 0
        };

        int headerSize = Marshal.SizeOf<NexusGetAccessLogOutput>();
        int entrySize = Marshal.SizeOf<NexusMemoryAccessEntry>();
        int bufferSize = headerSize + (int)maxEntries * entrySize;

        var inPtr = IntPtr.Zero;
        var outPtr = IntPtr.Zero;

        try
        {
            inPtr = Marshal.AllocHGlobal(Marshal.SizeOf<NexusGetAccessLogInput>());
            outPtr = Marshal.AllocHGlobal(bufferSize);

            Marshal.StructureToPtr(input, inPtr, false);

            bool result = DeviceIoControl(
                _deviceHandle!,
                NexusKernelIoctl.IOCTL_NEXUS_GET_MEMORY_ACCESS_LOG,
                inPtr,
                (uint)Marshal.SizeOf<NexusGetAccessLogInput>(),
                outPtr,
                (uint)bufferSize,
                out uint bytesReturned,
                IntPtr.Zero);

            if (!result || bytesReturned < headerSize)
            {
                return entries;
            }

            var header = Marshal.PtrToStructure<NexusGetAccessLogOutput>(outPtr);

            for (int i = 0; i < header.EntryCount; i++)
            {
                var entryPtr = IntPtr.Add(outPtr, headerSize + i * entrySize);
                var entry = Marshal.PtrToStructure<NexusMemoryAccessEntry>(entryPtr);
                entries.Add(entry);
            }

            return entries;
        }
        finally
        {
            if (inPtr != IntPtr.Zero) Marshal.FreeHGlobal(inPtr);
            if (outPtr != IntPtr.Zero) Marshal.FreeHGlobal(outPtr);
        }
    }

    /// <summary>
    /// Clear the memory access log.
    /// </summary>
    public bool ClearMemoryAccessLog()
    {
        if (!IsLoaded) return false;

        return DeviceIoControl(
            _deviceHandle!,
            NexusKernelIoctl.IOCTL_NEXUS_CLEAR_ACCESS_LOG,
            IntPtr.Zero,
            0,
            IntPtr.Zero,
            0,
            out _,
            IntPtr.Zero);
    }

    #endregion

    /// <summary>
    /// Get pending events from kernel driver.
    /// Returns raw event data buffer.
    /// </summary>
    public byte[]? GetPendingEvents()
    {
        if (!IsLoaded) return null;

        const int bufferSize = 65536; // 64KB buffer for events
        var outPtr = Marshal.AllocHGlobal(bufferSize);

        try
        {
            var result = DeviceIoControl(
                _deviceHandle!,
                NexusKernelIoctl.IOCTL_NEXUS_GET_PENDING_EVENTS,
                IntPtr.Zero,
                0,
                outPtr,
                bufferSize,
                out var bytesReturned,
                IntPtr.Zero);

            if (!result || bytesReturned == 0) return null;

            var buffer = new byte[bytesReturned];
            Marshal.Copy(outPtr, buffer, 0, (int)bytesReturned);
            return buffer;
        }
        finally
        {
            Marshal.FreeHGlobal(outPtr);
        }
    }

    /// <summary>
    /// Parse events from raw buffer into typed events.
    /// </summary>
    public IEnumerable<KernelEventHeader> ParseEvents(byte[] buffer)
    {
        if (buffer == null || buffer.Length < Marshal.SizeOf<KernelEventHeader>())
            yield break;

        int offset = 0;
        var headerSize = Marshal.SizeOf<KernelEventHeader>();

        while (offset + headerSize <= buffer.Length)
        {
            var headerBytes = new byte[headerSize];
            Array.Copy(buffer, offset, headerBytes, 0, headerSize);

            var handle = GCHandle.Alloc(headerBytes, GCHandleType.Pinned);
            try
            {
                var header = Marshal.PtrToStructure<KernelEventHeader>(handle.AddrOfPinnedObject());
                yield return header;

                // Move to next event
                var eventSize = headerSize + (int)header.DataSize;
                offset += eventSize;
            }
            finally
            {
                handle.Free();
            }
        }
    }

    /// <summary>
    /// Parse a registry event from buffer at given offset.
    /// </summary>
    public KernelRegistryEvent? ParseRegistryEvent(byte[] buffer, int offset)
    {
        var size = Marshal.SizeOf<KernelRegistryEvent>();
        if (offset + size > buffer.Length) return null;

        var eventBytes = new byte[size];
        Array.Copy(buffer, offset, eventBytes, 0, size);

        var handle = GCHandle.Alloc(eventBytes, GCHandleType.Pinned);
        try
        {
            return Marshal.PtrToStructure<KernelRegistryEvent>(handle.AddrOfPinnedObject());
        }
        finally
        {
            handle.Free();
        }
    }

    /// <summary>
    /// Parse a handle event from buffer at given offset.
    /// </summary>
    public KernelHandleEvent? ParseHandleEvent(byte[] buffer, int offset)
    {
        var size = Marshal.SizeOf<KernelHandleEvent>();
        if (offset + size > buffer.Length) return null;

        var eventBytes = new byte[size];
        Array.Copy(buffer, offset, eventBytes, 0, size);

        var handle = GCHandle.Alloc(eventBytes, GCHandleType.Pinned);
        try
        {
            return Marshal.PtrToStructure<KernelHandleEvent>(handle.AddrOfPinnedObject());
        }
        finally
        {
            handle.Free();
        }
    }

    /// <summary>
    /// Parse a memory event from buffer at given offset.
    /// </summary>
    public KernelMemoryEvent? ParseMemoryEvent(byte[] buffer, int offset)
    {
        var size = Marshal.SizeOf<KernelMemoryEvent>();
        if (offset + size > buffer.Length) return null;

        var eventBytes = new byte[size];
        Array.Copy(buffer, offset, eventBytes, 0, size);

        var handle = GCHandle.Alloc(eventBytes, GCHandleType.Pinned);
        try
        {
            return Marshal.PtrToStructure<KernelMemoryEvent>(handle.AddrOfPinnedObject());
        }
        finally
        {
            handle.Free();
        }
    }

    /// <summary>
    /// Get operation name for registry operation.
    /// </summary>
    public static string GetRegOpName(uint op) => op switch
    {
        NexusRegOp.OpenKey => "RegOpenKey",
        NexusRegOp.CreateKey => "RegCreateKey",
        NexusRegOp.DeleteKey => "RegDeleteKey",
        NexusRegOp.QueryValue => "RegQueryValue",
        NexusRegOp.SetValue => "RegSetValue",
        NexusRegOp.DeleteValue => "RegDeleteValue",
        NexusRegOp.EnumKey => "RegEnumKey",
        NexusRegOp.EnumValue => "RegEnumValue",
        _ => $"RegOp_{op}"
    };

    /// <summary>
    /// Get operation name for handle operation.
    /// </summary>
    public static string GetHandleOpName(uint op) => op switch
    {
        NexusHandleOp.OpenProcess => "OpenProcess",
        NexusHandleOp.OpenThread => "OpenThread",
        NexusHandleOp.Duplicate => "DuplicateHandle",
        _ => $"HandleOp_{op}"
    };

    /// <summary>
    /// Get operation name for memory operation.
    /// </summary>
    public static string GetMemOpName(uint op) => op switch
    {
        NexusMemOp.Read => "ReadProcessMemory",
        NexusMemOp.Write => "WriteProcessMemory",
        NexusMemOp.Alloc => "VirtualAllocEx",
        NexusMemOp.Free => "VirtualFreeEx",
        NexusMemOp.Protect => "VirtualProtectEx",
        _ => $"MemOp_{op}"
    };

    /// <summary>
    /// Get syscall type name.
    /// </summary>
    public static string GetSyscallTypeName(uint type) => type switch
    {
        NexusSyscallType.QuerySystemInfo => "NtQuerySystemInformation",
        NexusSyscallType.SetSystemInfo => "NtSetSystemInformation",
        NexusSyscallType.GetFirmwareEnv => "NtQuerySystemEnvironmentValueEx",
        NexusSyscallType.QueryLicense => "NtQueryLicenseValue",
        _ => $"Syscall_{type}"
    };

    /// <summary>
    /// Get SystemInformationClass name for security-sensitive queries.
    /// </summary>
    public static string GetSystemInfoClassName(uint infoClass) => infoClass switch
    {
        SystemInfoClass.SecureBootInformation => "SecureBoot",
        SystemInfoClass.CodeIntegrityInformation => "CodeIntegrity",
        SystemInfoClass.KernelDebuggerInfo => "KernelDebugger",
        SystemInfoClass.BootEnvironmentInfo => "BootEnvironment",
        _ => $"SystemInfo_0x{infoClass:X}"
    };

    #region Comm Channel Methods

    /// <summary>
    /// Map the communication channel shared memory into this process.
    /// </summary>
    /// <param name="mappedAddress">Output: mapped address in user-mode</param>
    /// <param name="size">Output: size of mapped region</param>
    /// <returns>True on success</returns>
    public bool MapCommChannel(out IntPtr mappedAddress, out ulong size)
    {
        mappedAddress = IntPtr.Zero;
        size = 0;

        if (!IsLoaded) return false;

        var outPtr = Marshal.AllocHGlobal(Marshal.SizeOf<NexusMapCommOutput>());
        try
        {
            bool result = DeviceIoControl(
                _deviceHandle!,
                NexusKernelIoctl.IOCTL_NEXUS_MAP_COMM_CHANNEL,
                IntPtr.Zero,
                0,
                outPtr,
                (uint)Marshal.SizeOf<NexusMapCommOutput>(),
                out uint bytesReturned,
                IntPtr.Zero);

            if (!result || bytesReturned < Marshal.SizeOf<NexusMapCommOutput>())
                return false;

            var output = Marshal.PtrToStructure<NexusMapCommOutput>(outPtr);
            if (output.Status != 0)
                return false;

            mappedAddress = (IntPtr)output.MappedAddress;
            size = output.Size;
            return true;
        }
        finally
        {
            Marshal.FreeHGlobal(outPtr);
        }
    }

    /// <summary>
    /// Unmap the communication channel shared memory.
    /// </summary>
    /// <param name="mappedAddress">The address previously returned by MapCommChannel</param>
    public void UnmapCommChannel(IntPtr mappedAddress)
    {
        if (!IsLoaded || mappedAddress == IntPtr.Zero) return;

        var input = new NexusUnmapCommInput { MappedAddress = (ulong)mappedAddress };
        var inPtr = Marshal.AllocHGlobal(Marshal.SizeOf<NexusUnmapCommInput>());

        try
        {
            Marshal.StructureToPtr(input, inPtr, false);
            DeviceIoControl(
                _deviceHandle!,
                NexusKernelIoctl.IOCTL_NEXUS_UNMAP_COMM_CHANNEL,
                inPtr,
                (uint)Marshal.SizeOf<NexusUnmapCommInput>(),
                IntPtr.Zero,
                0,
                out _,
                IntPtr.Zero);
        }
        finally
        {
            Marshal.FreeHGlobal(inPtr);
        }
    }

    // Structures for comm channel IOCTLs
    [StructLayout(LayoutKind.Sequential)]
    private struct NexusMapCommOutput
    {
        public ulong MappedAddress;
        public ulong Size;
        public uint Status;
        public uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NexusUnmapCommInput
    {
        public ulong MappedAddress;
    }

    #endregion
}
