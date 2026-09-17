// <file>
// <summary>
// Kernel monitor service providing a polling loop over NexusKernel.sys IOCTL callbacks.
// Reads kernel events (registry, process, handle, image load, memory, file, syscall)
// from the driver's ring buffer and dispatches them to the UI via callback delegates.
// Handles driver loading (via SC or bootkit mapper), shared singleton device handle,
// and event type filtering.
// </summary>
// </file>

using System.Diagnostics;
using System.Runtime.InteropServices;
using Nexus.UI.Providers;

namespace Nexus.UI.Services;

/// <summary>
/// Indicates how NexusKernel.sys was loaded into the system.
/// </summary>
public enum DriverLoadMethod
{
    None,
    /// <summary>Loaded via sc.exe (requires DSE disabled or test signing).</summary>
    ServiceControl,
    /// <summary>Loaded via NexusCore.sys bootkit mapper.</summary>
    Mapper
}

/// <summary>
/// Service for polling kernel callback events from NexusKernel.sys.
/// <para>
/// Supports registry, process, handle, image load, memory, file, and syscall events.
/// Runs a background polling thread that reads events from the driver's ring buffer
/// via IOCTL and dispatches them to registered callback delegates.
/// </para>
/// <remarks>
/// Uses <see cref="NexusKernelDriver.Instance"/> (singleton) for device communication.
/// The kernel driver enforces single-client access -- only one CreateFile handle is
/// allowed at a time. The provider system and this service share the singleton handle.
/// </remarks>
/// </summary>
public sealed class KernelMonitorService : IDisposable
{
    private const string SERVICE_NAME = "NexusKernel";

    // Polling interval when no events are pending (ms)
    private const int POLL_INTERVAL_MS = 10;

    // Reference to the shared singleton driver instance
    private readonly NexusKernelDriver _driver = NexusKernelDriver.Instance;

    private Thread? _eventThread;
    private volatile bool _stopping;
    private bool _disposed;
    private bool _scServiceCreated;

    /// <summary>Whether the driver device is open and usable.</summary>
    public bool IsConnected => _driver.IsLoaded;

    /// <summary>Whether monitoring is actively running.</summary>
    public bool IsMonitoring => _eventThread?.IsAlive == true && !_stopping;

    /// <summary>How the driver was loaded.</summary>
    public DriverLoadMethod LoadMethod { get; private set; }

    // Events
    public event Action<KernelRegistryEvent>? OnRegistryEvent;
    public event Action<KernelProcessEvent>? OnProcessEvent;
    public event Action<KernelHandleEvent>? OnHandleEvent;
    public event Action<KernelImageLoadEvent>? OnImageLoadEvent;
    public event Action<KernelMemoryEvent>? OnMemoryEvent;
    public event Action<KernelFileEvent>? OnFileEvent;
    public event Action<KernelSyscallEvent>? OnSyscallEvent;
    public event Action<string>? OnError;
    public event Action? OnDisconnected;

    /// <summary>
    /// Load the driver via SC (service control manager) and open the device.
    /// Requires DSE to be disabled or test signing to be enabled.
    /// Returns a user-facing error message on failure, or null on success.
    /// </summary>
    public string? ConnectViaSc(string driverPath)
    {
        if (IsConnected) return null;

        // First, check if the device is already available (driver already loaded)
        // Uses the singleton - if ShellForm already opened it, this returns true immediately
        if (_driver.Connect())
        {
            LoadMethod = DriverLoadMethod.ServiceControl;
            return null;
        }

        // Verify driver file exists
        if (!File.Exists(driverPath))
            return $"Driver file not found: {driverPath}\n\nBuild NexusKernel.sys first.";

        // Try to create and start the service
        string? error = ScCreateAndStart(driverPath);
        if (error != null)
            return error;

        // Retry connecting through the singleton with increasing delays.
        // DriverEntry runs synchronously before sc start returns, but the
        // symbolic link may take a moment to propagate to user-mode.
        for (int i = 0; i < 10; i++)
        {
            Thread.Sleep(100);
            if (_driver.Connect())
            {
                LoadMethod = DriverLoadMethod.ServiceControl;
                return null;
            }
        }

        // Device still not available - gather diagnostics
        var queryResult = RunSc($"query {SERVICE_NAME}");
        string serviceState = queryResult.Output;

        // If service is in STOPPED state, DriverEntry returned an error
        if (serviceState.Contains("STOPPED", StringComparison.OrdinalIgnoreCase))
        {
            return "NexusKernel.sys DriverEntry failed (service stopped immediately).\n\n" +
                   "Possible causes:\n" +
                   "  - Driver crashed during initialization (check Event Viewer > System)\n" +
                   "  - NexusGlobalsInit or NexusCommInitialize failed\n" +
                   "  - Incompatible Windows version\n\n" +
                   "Run 'sc query NexusKernel' from an admin cmd for details.\n\n" +
                   "Service state:\n" + serviceState;
        }

        // Service is RUNNING but no device - DriverEntry succeeded but device creation failed
        return "Service is running but device \\\\.\\NexusKernel was not created.\n\n" +
               "This means DriverEntry returned success but IoCreateDevice or\n" +
               "IoCreateSymbolicLink failed inside the driver.\n\n" +
               "Try:\n" +
               "  1. sc stop NexusKernel && sc delete NexusKernel\n" +
               "  2. Reconnect from Nexus\n\n" +
               "Service state:\n" + serviceState;
    }

    /// <summary>
    /// Load the driver via the NexusCore.sys bootkit mapper and open the device.
    /// Requires the bootkit mapper to be initialized (--mapper-init).
    /// Returns a user-facing error message on failure, or null on success.
    /// </summary>
    public string? ConnectViaMapper(string driverPath)
    {
        if (IsConnected) return null;

        // Try connecting through the singleton (checks both IOCTL and mapped modes)
        if (_driver.Connect())
        {
            LoadMethod = DriverLoadMethod.Mapper;
            return null;
        }

        return "Mapper loading for NexusKernel.sys is not yet implemented.\n\n" +
               "The mapper approach has limitations for monitoring drivers:\n" +
               "  - CmRegisterCallbackEx requires a valid DriverObject\n" +
               "  - ObRegisterCallbacks needs PsLoadedModuleList entry\n" +
               "  - IOCTL dispatch requires a device object\n\n" +
               "Recommendation: Use SC (Service) loading instead.\n" +
               "Requires a signed driver, or test signing:\n" +
               "  bcdedit /set testsigning on  (requires reboot)\n" +
               "Then reconnect with SC method.";
    }

    /// <summary>
    /// Stop monitoring and optionally unload the SC service.
    /// Does NOT disconnect the singleton driver handle since other modules may use it.
    /// </summary>
    public void Disconnect()
    {
        StopMonitoring();

        // Clean up service if we created it
        if (LoadMethod == DriverLoadMethod.ServiceControl && _scServiceCreated)
        {
            // Don't disconnect the singleton - other panels may still need it.
            // Only clean up the SC service entry if nobody else needs the driver.
            // For now, leave the service running - it will be cleaned up on app exit or next connect.
        }

        LoadMethod = DriverLoadMethod.None;
        OnDisconnected?.Invoke();
    }

    #region SC (Service Control) Helpers

    private string? ScCreateAndStart(string driverPath)
    {
        string absPath = Path.GetFullPath(driverPath);

        // First, clean up any stale service from a previous session.
        // This ensures the binPath is correct and the service is in a clean state.
        var queryResult = RunSc($"query {SERVICE_NAME}");
        if (queryResult.ExitCode == 0)
        {
            // Service exists. Check if it's running with a valid device.
            if (queryResult.Output.Contains("RUNNING", StringComparison.OrdinalIgnoreCase))
            {
                // Already running - caller will try _driver.Connect() after we return
                return null;
            }

            // Service exists but is stopped/other state - delete and recreate
            // to ensure binPath points to the right binary
            RunSc($"stop {SERVICE_NAME}");
            RunSc($"delete {SERVICE_NAME}");
            Thread.Sleep(100); // Give SCM time to clean up
        }

        // Create the service
        var createResult = RunSc($"create {SERVICE_NAME} type=kernel binPath=\"{absPath}\"");
        if (createResult.ExitCode != 0)
        {
            // Error 1073 = service still exists (delete didn't fully propagate)
            if (createResult.Output.Contains("1073"))
            {
                // Try one more time after a longer delay
                Thread.Sleep(500);
                RunSc($"stop {SERVICE_NAME}");
                RunSc($"delete {SERVICE_NAME}");
                Thread.Sleep(500);

                createResult = RunSc($"create {SERVICE_NAME} type=kernel binPath=\"{absPath}\"");
                if (createResult.ExitCode != 0)
                {
                    return $"sc create failed - stale service could not be removed.\n\n" +
                           "Run these commands manually in an admin cmd:\n" +
                           $"  sc stop {SERVICE_NAME}\n" +
                           $"  sc delete {SERVICE_NAME}\n\n" +
                           $"Then try connecting again.\n\nsc output: {createResult.Output}";
                }
            }
            else
            {
                return $"sc create failed (exit {createResult.ExitCode}):\n{createResult.Output}\n\n" +
                       "Make sure you're running as Administrator.";
            }
        }

        _scServiceCreated = true;

        // Start the service
        var startResult = RunSc($"start {SERVICE_NAME}");
        if (startResult.ExitCode != 0)
        {
            // Error 1056 = already running (race condition - fine)
            if (startResult.Output.Contains("1056"))
                return null;

            // Error 577 = DSE blocked the driver
            if (startResult.Output.Contains("577"))
            {
                ScStopAndDelete();
                _scServiceCreated = false;

                return "Windows blocked the driver because it is not digitally signed.\n\n" +
                       "DSE (Driver Signature Enforcement) is enabled.\n" +
                       "Enable test signing:\n" +
                       "  bcdedit /set testsigning on  (requires reboot)\n\n" +
                       "Or load the driver by a route that does not go through\n" +
                       "Windows' driver-load path at all.";
            }

            // Error 1275 = driver has been blocked from loading
            if (startResult.Output.Contains("1275"))
            {
                ScStopAndDelete();
                _scServiceCreated = false;

                return "Driver has been blocked from loading by the system.\n\n" +
                       "This can happen when:\n" +
                       "  - Memory Integrity (HVCI) is enabled\n" +
                       "  - The driver binary is corrupt or incompatible\n\n" +
                       "Check Event Viewer > System log for details.";
            }

            // Generic failure
            string hint = "";
            if (startResult.Output.Contains("5") && !startResult.Output.Contains("577"))
                hint = "\nMake sure you're running as Administrator.";

            ScStopAndDelete();
            _scServiceCreated = false;

            return $"sc start failed (exit {startResult.ExitCode}):\n{startResult.Output}{hint}";
        }

        return null;
    }

    private void ScStopAndDelete()
    {
        RunSc($"stop {SERVICE_NAME}");
        RunSc($"delete {SERVICE_NAME}");
    }

    private static (int ExitCode, string Output) RunSc(string arguments)
    {
        try
        {
            using var proc = new Process();
            proc.StartInfo = new ProcessStartInfo
            {
                FileName = "sc.exe",
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            proc.Start();
            string stdout = proc.StandardOutput.ReadToEnd();
            string stderr = proc.StandardError.ReadToEnd();
            proc.WaitForExit(10000);
            return (proc.ExitCode, (stdout + "\n" + stderr).Trim());
        }
        catch (Exception ex)
        {
            return (-1, ex.Message);
        }
    }

    #endregion

    /// <summary>
    /// Register kernel callbacks and start draining events on a background thread.
    /// </summary>
    /// <param name="eventMask">Bitmask of (1 &lt;&lt; NexusEventType.*) values to capture.</param>
    /// <param name="filterPid">Filter to specific PID (0 = all processes).</param>
    public bool StartMonitoring(uint eventMask, uint filterPid = 0)
    {
        if (!IsConnected) return false;
        if (IsMonitoring) return true;

        // Register callbacks via the singleton
        var config = new KernelCallbackConfig
        {
            EventMask = eventMask,
            ProcessFilter = filterPid
        };

        if (!_driver.SendIoctl(NexusKernelIoctl.IOCTL_NEXUS_REGISTER_CALLBACK, ref config))
        {
            OnError?.Invoke("Failed to register kernel callbacks (IOCTL_NEXUS_REGISTER_CALLBACK)");
            return false;
        }

        // Start background drain thread
        _stopping = false;
        _eventThread = new Thread(EventDrainThread)
        {
            Name = "KernelMon-EventDrain",
            IsBackground = true
        };
        _eventThread.Start();
        return true;
    }

    /// <summary>
    /// Update the PID filter while monitoring is active.
    /// </summary>
    public bool UpdateFilter(uint eventMask, uint filterPid)
    {
        if (!IsConnected) return false;

        var config = new KernelCallbackConfig
        {
            EventMask = eventMask,
            ProcessFilter = filterPid
        };

        return _driver.SendIoctl(NexusKernelIoctl.IOCTL_NEXUS_REGISTER_CALLBACK, ref config);
    }

    /// <summary>
    /// Stop monitoring and unregister callbacks.
    /// </summary>
    public void StopMonitoring()
    {
        _stopping = true;

        // Wait for drain thread to exit
        if (_eventThread?.IsAlive == true)
        {
            _eventThread.Join(2000);
        }
        _eventThread = null;

        // Unregister callbacks via the singleton
        if (IsConnected)
        {
            var config = new KernelCallbackConfig { EventMask = 0, ProcessFilter = 0 };
            _driver.SendIoctl(NexusKernelIoctl.IOCTL_NEXUS_UNREGISTER_CALLBACK, ref config);
        }
    }

    /// <summary>
    /// Get driver version to verify connectivity.
    /// </summary>
    public bool GetVersion(out NexusVersionInfo version)
    {
        version = default;
        if (!IsConnected) return false;

        var dummy = 0u;
        return _driver.SendIoctl(NexusKernelIoctl.IOCTL_NEXUS_GET_VERSION, ref dummy, out version);
    }

    /// <summary>
    /// Background thread: polls GetPendingEvents via the singleton and dispatches to event handlers.
    /// </summary>
    private void EventDrainThread()
    {
        try
        {
            while (!_stopping && IsConnected)
            {
                bool gotEvents = DrainPendingEvents();

                if (!gotEvents)
                {
                    Thread.Sleep(POLL_INTERVAL_MS);
                }
            }
        }
        catch (Exception ex)
        {
            if (!_stopping)
                OnError?.Invoke($"Event drain thread error: {ex.Message}");
        }
    }

    /// <summary>
    /// Drain all pending events from the driver via the singleton's GetPendingEvents.
    /// Returns true if at least one event was dispatched.
    /// </summary>
    private bool DrainPendingEvents()
    {
        if (!IsConnected) return false;

        var buffer = _driver.GetPendingEvents();
        if (buffer == null || buffer.Length == 0) return false;

        bool dispatched = false;
        int offset = 0;
        int headerSize = Marshal.SizeOf<KernelEventHeader>();

        // Pin the buffer ONCE for the entire parsing pass
        var gcHandle = System.Runtime.InteropServices.GCHandle.Alloc(buffer, GCHandleType.Pinned);
        try
        {
            var bufferBase = gcHandle.AddrOfPinnedObject();

            while (offset + headerSize <= buffer.Length)
            {
                var header = Marshal.PtrToStructure<KernelEventHeader>(bufferBase + offset);

                int eventTotalSize = headerSize + (int)header.DataSize;
                if (eventTotalSize < headerSize || offset + eventTotalSize > buffer.Length)
                    break; // Corrupted DataSize or truncated event

                try
                {
                    DispatchEvent(header.EventType, buffer, offset, eventTotalSize);
                    dispatched = true;
                }
                catch
                {
                    // Skip malformed events
                }

                offset += eventTotalSize;
            }
        }
        finally
        {
            gcHandle.Free();
        }

        return dispatched;
    }

    /// <summary>
    /// Get the expected C# struct size for an event type.
    /// Returns 0 for unknown types (event is skipped).
    /// </summary>
    private static int GetStructSize(uint eventType) => eventType switch
    {
        NexusEventType.RegistryOp => Marshal.SizeOf<KernelRegistryEvent>(),
        NexusEventType.ProcessCreate or NexusEventType.ProcessExit => Marshal.SizeOf<KernelProcessEvent>(),
        NexusEventType.HandleOp => Marshal.SizeOf<KernelHandleEvent>(),
        NexusEventType.ImageLoad => Marshal.SizeOf<KernelImageLoadEvent>(),
        NexusEventType.MemoryOp => Marshal.SizeOf<KernelMemoryEvent>(),
        NexusEventType.FileOp => Marshal.SizeOf<KernelFileEvent>(),
        NexusEventType.Syscall => Marshal.SizeOf<KernelSyscallEvent>(),
        _ => 0
    };

    /// <summary>
    /// Dispatch a single event to the appropriate handler.
    /// Copies event bytes into a zero-padded buffer of the correct struct size
    /// before marshaling, preventing reads past the source buffer.
    /// </summary>
    private void DispatchEvent(uint eventType, byte[] buffer, int offset, int eventBytes)
    {
        int structSize = GetStructSize(eventType);
        if (structSize == 0) return; // Unknown event type

        // Copy event bytes into a correctly-sized zero-padded buffer.
        // This prevents Marshal.PtrToStructure from reading past the
        // source data if the kernel event is smaller than the C# struct.
        int copyBytes = Math.Min(eventBytes, structSize);
        var tempBuffer = new byte[structSize];
        Buffer.BlockCopy(buffer, offset, tempBuffer, 0, copyBytes);

        var tempHandle = System.Runtime.InteropServices.GCHandle.Alloc(tempBuffer, GCHandleType.Pinned);
        try
        {
            var ptr = tempHandle.AddrOfPinnedObject();
            switch (eventType)
            {
                case NexusEventType.RegistryOp:
                    OnRegistryEvent?.Invoke(Marshal.PtrToStructure<KernelRegistryEvent>(ptr));
                    break;
                case NexusEventType.ProcessCreate:
                case NexusEventType.ProcessExit:
                    OnProcessEvent?.Invoke(Marshal.PtrToStructure<KernelProcessEvent>(ptr));
                    break;
                case NexusEventType.HandleOp:
                    OnHandleEvent?.Invoke(Marshal.PtrToStructure<KernelHandleEvent>(ptr));
                    break;
                case NexusEventType.ImageLoad:
                    OnImageLoadEvent?.Invoke(Marshal.PtrToStructure<KernelImageLoadEvent>(ptr));
                    break;
                case NexusEventType.MemoryOp:
                    OnMemoryEvent?.Invoke(Marshal.PtrToStructure<KernelMemoryEvent>(ptr));
                    break;
                case NexusEventType.FileOp:
                    OnFileEvent?.Invoke(Marshal.PtrToStructure<KernelFileEvent>(ptr));
                    break;
                case NexusEventType.Syscall:
                    OnSyscallEvent?.Invoke(Marshal.PtrToStructure<KernelSyscallEvent>(ptr));
                    break;
            }
        }
        finally
        {
            tempHandle.Free();
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Disconnect();
    }

    /// <summary>
    /// Send registry spoof configuration to NexusKernel.sys.
    /// Call after the driver is loaded to enable path-based identifier spoofing
    /// in the CmRegisterCallbackEx registry filter.
    /// </summary>
    /// <param name="config">Pre-populated config struct with original/spoofed identifier pairs.</param>
    /// <returns>True if IOCTL succeeded.</returns>
    public bool ConfigureRegistrySpoof(ref NexusRegSpoofConfig config)
    {
        if (!_driver.IsLoaded)
        {
            OnError?.Invoke("Cannot configure reg spoof: driver not loaded");
            return false;
        }

        bool ok = _driver.SendIoctl(NexusKernelIoctl.IOCTL_NEXUS_CONFIGURE_REG_SPOOF, ref config);
        if (!ok)
            OnError?.Invoke("Failed to send IOCTL_NEXUS_CONFIGURE_REG_SPOOF");
        return ok;
    }
}

#region Missing Event Structures

/// <summary>
/// Process create/exit event from kernel.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Unicode)]
public struct KernelProcessEvent
{
    public KernelEventHeader Header;
    public uint ParentProcessId;
    public uint ExitCode;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string ImageName;
}

/// <summary>
/// Image/module load event from kernel.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Unicode)]
public struct KernelImageLoadEvent
{
    public KernelEventHeader Header;
    public ulong ImageBase;
    public ulong ImageSize;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string ImageName;
}

#endregion

#region Registry Spoof Configuration

/// <summary>
/// USB serial number original/spoofed pair.
/// Must match NEXUS_USB_SERIAL_PAIR in nexus_kernel.h (NEXUS_REG_SPOOF_MAX_SERIAL_LEN = 64).
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct NexusUsbSerialPair
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string Original;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string Spoofed;
}

/// <summary>
/// Registry spoof configuration sent to NexusKernel.sys via IOCTL_NEXUS_CONFIGURE_REG_SPOOF.
/// Must match NEXUS_REG_SPOOF_CONFIG in nexus_kernel.h.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Unicode)]
public struct NexusRegSpoofConfig
{
    public ulong MasterSeed;

    // Bluetooth MAC spoofing (SWD\RADIO paths)
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
    public byte[] OriginalBtMac;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
    public byte[] SpoofedBtMac;

    // Machine SID spoofing (ProfileList paths)
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 48)]
    public string OriginalMachineSid;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 48)]
    public string SpoofedMachineSid;

    // USB serial number spoofing
    public uint UsbSerialCount;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public NexusUsbSerialPair[] UsbSerials;

    // SWD\COMPUTER SMBIOS identity spoofing
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string OriginalComputerIdentity;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string SpoofedComputerIdentity;

    // Flags
    public uint Enable;
    public uint Reserved;
}

#endregion
