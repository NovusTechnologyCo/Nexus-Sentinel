using System.Collections.Concurrent;
using Nexus.UI.Core;
using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using Nexus.UI.Services;
using Nexus.UI.Styles;

namespace Nexus.UI.Panels;

public partial class ProcMonPanel
{
    #region Capture Control

    private void StartCapture()
    {
        // Allow capture without an attached process if the watchlist has entries
        var watchlist = ProcessWatchlist.Instance;
        if (!Context.IsAttached && _monitoredPids.Count == 0 && watchlist.Entries.Count == 0)
        {
            MessageBox.Show("Please attach to a process or add entries to the watchlist first.",
                "No Targets", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        // Subscribe to watchlist events for auto-detection
        watchlist.ProcessDiscovered += OnWatchlistProcessDiscovered;
        watchlist.ProcessExited += OnWatchlistProcessExited;
        watchlist.DriverLoaded += OnWatchlistDriverLoaded;
        watchlist.DriverUnloaded += OnWatchlistDriverUnloaded;

        // Add any already-active watchlist PIDs
        foreach (var kvp in watchlist.ActivePids)
        {
            AddMonitoredProcess(kvp.Key, kvp.Value.Name);
        }

        // Add driver names for ETW System process filtering
        foreach (var entry in watchlist.Entries)
        {
            if (entry.Type == Models.WatchlistEntryType.Driver && entry.Enabled)
            {
                _watchedDriverNames.Add(entry.Name);
                if (entry.IsActive)
                {
                    // Include System PID for driver events
                    if (!_monitoredPids.Contains(4))
                        AddMonitoredProcess(4, "System");
                }
            }
        }

        // Start watchlist polling if not already running
        if (!watchlist.IsRunning && watchlist.Entries.Count > 0)
            watchlist.Start();

        _isCapturing = true;
        _btnStartStop.Text = "Stop";
        _updateTimer.Start();

        // Start ETW tracing
        StartEtwTracing();

        // Start kernel driver monitoring (registry, handle, memory events)
        StartKernelMonitoring();

        // Start API hooking (placeholder - would need actual hook implementation)
        StartApiHooking();

        var pidCount = _monitoredPids.Count;
        var sourceInfo = _useKernelMonitoring ? " [Kernel+ETW]" : " [ETW]";
        UpdateStatus($"Capturing events for {pidCount} process(es){sourceInfo}...");
    }

    private void StartKernelMonitoring()
    {
        _useKernelMonitoring = false;

        if (!_kernelDriver.Connect())
        {
            // Kernel driver not available - continue with ETW only
            return;
        }

        // Enable kernel monitoring for registry, handle, and memory events
        // Filter to monitored processes if any
        uint processFilter = _monitoredPids.Count == 1 ? (uint)_monitoredPids.First() : 0;

        if (_kernelDriver.EnableAllMonitoring(processFilter))
        {
            _useKernelMonitoring = true;
            UpdateStatus("Kernel monitoring enabled");
        }
    }

    private void StopKernelMonitoring()
    {
        if (_useKernelMonitoring)
        {
            _kernelDriver.DisableMonitoring();
            _useKernelMonitoring = false;
        }
    }

    private void StopCapture()
    {
        _isCapturing = false;
        _btnStartStop.Text = "Start";
        _updateTimer.Stop();

        // Unsubscribe from watchlist events
        var watchlist = ProcessWatchlist.Instance;
        watchlist.ProcessDiscovered -= OnWatchlistProcessDiscovered;
        watchlist.ProcessExited -= OnWatchlistProcessExited;
        watchlist.DriverLoaded -= OnWatchlistDriverLoaded;
        watchlist.DriverUnloaded -= OnWatchlistDriverUnloaded;
        _watchedDriverNames.Clear();

        StopEtwTracing();
        StopKernelMonitoring();
        StopApiHooking();

        ProcessEventQueue(); // Process remaining events
        UpdateStatus($"Capture stopped - {_events.Count} events captured");
    }

    private void StartEtwTracing()
    {
        if (_etwHandle != IntPtr.Zero) return;

        // Check admin privilege
        var adminResult = NexusEngine.Nexus_EtwCheckAdminPrivilege(out uint isAdmin);
        if (adminResult != NexusResult.OK || isAdmin == 0)
        {
            UpdateStatus("ETW tracing requires administrator privileges");
            return;
        }

        // Create ETW config - use TargetPid=0 to capture all processes, filter client-side
        // This enables multi-process monitoring (launcher -> game scenarios)
        var config = new NexusEtwConfig
        {
            Providers = 0xFFFF, // Enable all providers (File, Registry, Network, Process, Thread, Image)
            TargetPid = 0, // Capture all processes, filter client-side for multi-process support
            BufferSizeKb = 64,
            MinBuffers = 8,
            MaxBuffers = 32,
            FlushTimerMs = 100,
            MaxEventsPerSecond = 0, // No rate limit
            Flags = 0
        };

        // Create ETW session
        var createResult = NexusEngine.Nexus_EtwCreate(ref config, out _etwHandle);
        if (createResult != NexusResult.OK && createResult != NexusResult.Success)
        {
            UpdateStatus($"Failed to create ETW session: {createResult}");
            _etwHandle = IntPtr.Zero;
            return;
        }

        // Start tracing
        var startResult = NexusEngine.Nexus_EtwStart(_etwHandle);
        if (startResult != NexusResult.OK && startResult != NexusResult.Success)
        {
            UpdateStatus($"Failed to start ETW tracing: {startResult}");
            NexusEngine.Nexus_EtwDestroy(_etwHandle);
            _etwHandle = IntPtr.Zero;
            return;
        }

        UpdateStatus("ETW tracing started");
    }

    private void StopEtwTracing()
    {
        if (_etwHandle == IntPtr.Zero) return;

        NexusEngine.Nexus_EtwStop(_etwHandle);
        NexusEngine.Nexus_EtwDestroy(_etwHandle);
        _etwHandle = IntPtr.Zero;
    }

    private void PollEtwEvents()
    {
        if (_etwHandle == IntPtr.Zero) return;

        var result = NexusEngine.Nexus_EtwPollEvents(_etwHandle, _etwEventBuffer, (nuint)_etwEventBuffer.Length, out nuint eventCount);
        if (result != NexusResult.OK && result != NexusResult.Success) return;

        for (int i = 0; i < (int)eventCount; i++)
        {
            var etwEvent = _etwEventBuffer[i];
            var pid = (int)etwEvent.ProcessId;
            var category = ConvertEtwCategory((NexusEtwEventCategory)etwEvent.Category);
            var operation = NexusEngine.GetEtwOperationName((NexusEtwOperation)etwEvent.Operation);

            // Check for child process creation from a monitored process
            if (category == EventCategory.Process && operation.Contains("Create", StringComparison.OrdinalIgnoreCase))
            {
                // The event's ProcessId is the parent, the path/details contain info about the child
                // Try to extract child PID from the event data
                var parentPid = pid;
                if (_monitoredPids.Contains(parentPid))
                {
                    // Parse child process info from the event
                    // The child PID might be in the event's extra data or parsed from path
                    TryHandleProcessCreateEvent(etwEvent, parentPid);
                }
            }

            // Filter: include System (PID 4) events matching watched driver paths
            if (pid == 4 && _watchedDriverNames.Count > 0)
            {
                var path = etwEvent.Path ?? "";
                var details = ExtractEtwEventDetails(etwEvent);
                var detailsStr = string.Join(" ", details.Values);
                if (!_watchedDriverNames.Any(d =>
                    path.Contains(d, StringComparison.OrdinalIgnoreCase) ||
                    detailsStr.Contains(d, StringComparison.OrdinalIgnoreCase)))
                {
                    continue; // System event doesn't match any watched driver
                }
            }
            else if (!IsMonitoredProcess(pid)) continue;

            // Convert ETW event to ProcMonEvent with enhanced details
            var procEvent = new ProcMonEvent
            {
                Timestamp = etwEvent.Time,
                ProcessId = pid,
                ThreadId = (int)etwEvent.ThreadId,
                ProcessName = GetProcessDisplayName(pid),
                Category = category,
                Operation = operation,
                Path = etwEvent.Path ?? "",
                Result = etwEvent.Status == 0 ? "SUCCESS" : $"0x{etwEvent.Status:X8}",
                Duration = TimeSpan.FromTicks((long)etwEvent.Duration),
                Details = ExtractEtwEventDetails(etwEvent)
            };

            AddEvent(procEvent);
        }
    }

    private void TryHandleProcessCreateEvent(NexusEtwEvent etwEvent, int parentPid)
    {
        // Process create events typically contain info about the new process
        // The new process PID might be embedded in the event data
        // For now, we'll try to parse it from available data

        // ETW Process Start events have the child PID as the subject of the event
        // In many ETW providers, for process create, the ProcessId IS the new process
        // and the parent is in extended data. This depends on the specific provider.

        // Try extracting from the path which might contain "PID: XXXX" or similar
        var path = etwEvent.Path ?? "";

        // Look for PID pattern in path
        var pidMatch = System.Text.RegularExpressions.Regex.Match(path, @"PID[:\s]+(\d+)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        if (pidMatch.Success && int.TryParse(pidMatch.Groups[1].Value, out var childPid) && childPid != parentPid)
        {
            // Extract process name if available
            var nameMatch = System.Text.RegularExpressions.Regex.Match(path, @"([^\\/:*?""<>|\r\n]+\.exe)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            var childName = nameMatch.Success ? nameMatch.Groups[1].Value : $"Process {childPid}";

            HandleChildProcessCreated(parentPid, childPid, childName);
            return;
        }

        // Alternative: If the event ProcessId differs from parent and we know parent spawned something
        // This is a heuristic approach - real implementation would need proper ETW event parsing
        if (etwEvent.ProcessId != (uint)parentPid)
        {
            var childPidFromEvent = (int)etwEvent.ProcessId;
            try
            {
                var proc = System.Diagnostics.Process.GetProcessById(childPidFromEvent);
                HandleChildProcessCreated(parentPid, childPidFromEvent, proc.ProcessName);
            }
            catch
            {
                // Process may have already exited
            }
        }
    }

    private static EventCategory ConvertEtwCategory(NexusEtwEventCategory etwCategory)
    {
        return etwCategory switch
        {
            NexusEtwEventCategory.File => EventCategory.File,
            NexusEtwEventCategory.Registry => EventCategory.Registry,
            NexusEtwEventCategory.Network => EventCategory.Network,
            NexusEtwEventCategory.Process => EventCategory.Process,
            NexusEtwEventCategory.Thread => EventCategory.Thread,
            NexusEtwEventCategory.Image => EventCategory.File, // Module loads -> File category
            NexusEtwEventCategory.Memory => EventCategory.Memory,
            _ => EventCategory.File
        };
    }

    /// <summary>
    /// Extract additional details from ETW event data based on event type.
    /// </summary>
    private static Dictionary<string, string> ExtractEtwEventDetails(NexusEtwEvent etwEvent)
    {
        var details = new Dictionary<string, string>
        {
            ["Source"] = "ETW"
        };

        var category = (NexusEtwEventCategory)etwEvent.Category;
        var operation = (NexusEtwOperation)etwEvent.Operation;

        // Parse Data field based on event type
        if (etwEvent.Data == null || etwEvent.DataSize == 0)
            return details;

        try
        {
            switch (category)
            {
                case NexusEtwEventCategory.File:
                    ExtractFileEventDetails(etwEvent, operation, details);
                    break;
                case NexusEtwEventCategory.Registry:
                    ExtractRegistryEventDetails(etwEvent, operation, details);
                    break;
                case NexusEtwEventCategory.Network:
                    ExtractNetworkEventDetails(etwEvent, operation, details);
                    break;
                case NexusEtwEventCategory.Memory:
                    ExtractMemoryEventDetails(etwEvent, operation, details);
                    break;
            }
        }
        catch
        {
            // Ignore parsing errors
        }

        return details;
    }

    private static void ExtractFileEventDetails(NexusEtwEvent evt, NexusEtwOperation op, Dictionary<string, string> details)
    {
        var data = evt.Data;
        if (data == null || data.Length < 8) return;

        // Common ETW file event structure often has:
        // - Offset 0: IrpPtr (8 bytes)
        // - Offset 8: FileObject/FileKey (8 bytes)
        // - Offset 16: IRQL, Flags, etc.
        // This varies by provider and event type

        switch (op)
        {
            case NexusEtwOperation.FileCreate:
                // FileCreate often includes CreateOptions, ShareAccess, etc.
                if (data.Length >= 24)
                {
                    var createOptions = BitConverter.ToUInt32(data, 16);
                    var shareAccess = BitConverter.ToUInt32(data, 20);
                    details["CreateOptions"] = $"0x{createOptions:X8}";
                    details["ShareAccess"] = FormatShareAccess(shareAccess);
                    details["CreateDisposition"] = FormatCreateDisposition((createOptions >> 24) & 0xFF);
                }
                break;

            case NexusEtwOperation.FileRead:
            case NexusEtwOperation.FileWrite:
                // Read/Write often includes offset and size
                if (data.Length >= 24)
                {
                    var offset = BitConverter.ToInt64(data, 8);
                    var size = BitConverter.ToUInt32(data, 16);
                    details["Offset"] = $"0x{offset:X}";
                    details["Size"] = $"{size} bytes";
                }
                break;

            case NexusEtwOperation.FileQueryInfo:
            case NexusEtwOperation.FileSetInfo:
                // Info class operations
                if (data.Length >= 20)
                {
                    var infoClass = BitConverter.ToUInt32(data, 16);
                    details["InfoClass"] = FormatFileInfoClass(infoClass);
                }
                break;
        }

        // Try to detect suspicious patterns
        var path = evt.Path?.ToLowerInvariant() ?? "";
        if (IsSuspiciousFilePath(path))
        {
            details["Warning"] = "Suspicious file access";
        }
    }

    private static void ExtractRegistryEventDetails(NexusEtwEvent evt, NexusEtwOperation op, Dictionary<string, string> details)
    {
        var data = evt.Data;
        if (data == null || data.Length < 8) return;

        switch (op)
        {
            case NexusEtwOperation.RegQuery:
            case NexusEtwOperation.RegSet:
                // Registry value operations may include value type
                if (data.Length >= 12)
                {
                    var valueType = BitConverter.ToUInt32(data, 8);
                    details["ValueType"] = GetValueTypeName(valueType);
                }
                break;
        }

        // Detect SecureBoot check patterns
        var path = evt.Path?.ToLowerInvariant() ?? "";
        if (path.Contains("secureboot") || path.Contains("uefi") ||
            path.Contains("secure boot") || path.Contains("codeintegrity"))
        {
            details["Warning"] = "SecureBoot/UEFI check detected";
        }
        else if (path.Contains("debugger") || path.Contains("kernel\\debug"))
        {
            details["Warning"] = "Debugger detection check";
        }
    }

    private static void ExtractNetworkEventDetails(NexusEtwEvent evt, NexusEtwOperation op, Dictionary<string, string> details)
    {
        var data = evt.Data;
        if (data == null || data.Length < 16) return;

        // Network events typically include IP addresses and ports
        switch (op)
        {
            case NexusEtwOperation.TcpConnect:
            case NexusEtwOperation.TcpAccept:
            case NexusEtwOperation.UdpSend:
            case NexusEtwOperation.UdpRecv:
                if (data.Length >= 16)
                {
                    // Parse IP (assuming IPv4 at offset 0) and port (offset 4)
                    var ip = new byte[4];
                    Array.Copy(data, 0, ip, 0, 4);
                    var port = BitConverter.ToUInt16(data, 4);
                    details["RemoteAddress"] = $"{ip[0]}.{ip[1]}.{ip[2]}.{ip[3]}:{port}";
                }
                break;
        }
    }

    private static void ExtractMemoryEventDetails(NexusEtwEvent evt, NexusEtwOperation op, Dictionary<string, string> details)
    {
        var data = evt.Data;
        if (data == null || data.Length < 16) return;

        switch (op)
        {
            case NexusEtwOperation.MemAlloc:
            case NexusEtwOperation.MemFree:
                if (data.Length >= 24)
                {
                    var address = BitConverter.ToUInt64(data, 0);
                    var size = BitConverter.ToUInt64(data, 8);
                    details["Address"] = $"0x{address:X}";
                    details["Size"] = $"0x{size:X} ({size} bytes)";
                }
                break;
            case NexusEtwOperation.MemProtect:
                if (data.Length >= 28)
                {
                    var address = BitConverter.ToUInt64(data, 0);
                    var size = BitConverter.ToUInt64(data, 8);
                    var protect = BitConverter.ToUInt32(data, 16);
                    details["Address"] = $"0x{address:X}";
                    details["Size"] = $"0x{size:X}";
                    details["Protection"] = FormatMemoryProtection(protect);
                }
                break;
        }
    }

    private static bool IsSuspiciousFilePath(string path)
    {
        // Anti-cheat and malware common targets
        return path.Contains("cheatengine") ||
               path.Contains(".ct") ||           // CE cheat tables
               path.Contains(".cetrainer") ||
               path.Contains("x64dbg") ||
               path.Contains("ollydbg") ||
               path.Contains("ida") ||
               path.Contains("wireshark") ||
               path.Contains("fiddler") ||
               path.Contains("procmon") ||
               path.Contains("processhacker") ||
               path.Contains(".dll") && (path.Contains("inject") || path.Contains("hook"));
    }

    private static string FormatShareAccess(uint shareAccess)
    {
        var parts = new List<string>();
        if ((shareAccess & 0x01) != 0) parts.Add("Read");
        if ((shareAccess & 0x02) != 0) parts.Add("Write");
        if ((shareAccess & 0x04) != 0) parts.Add("Delete");
        return parts.Count > 0 ? string.Join("|", parts) : "None";
    }

    private static string FormatCreateDisposition(uint disposition)
    {
        return disposition switch
        {
            0 => "SUPERSEDE",
            1 => "OPEN",
            2 => "CREATE",
            3 => "OPEN_IF",
            4 => "OVERWRITE",
            5 => "OVERWRITE_IF",
            _ => $"0x{disposition:X}"
        };
    }

    private static string FormatFileInfoClass(uint infoClass)
    {
        return infoClass switch
        {
            1 => "FileDirectoryInformation",
            4 => "FileBasicInformation",
            5 => "FileStandardInformation",
            6 => "FileInternalInformation",
            7 => "FileEaInformation",
            9 => "FileNameInformation",
            18 => "FileAllInformation",
            34 => "FileNetworkOpenInformation",
            35 => "FileAttributeTagInformation",
            _ => $"Class_{infoClass}"
        };
    }

    private static string FormatMemoryProtection(uint protect)
    {
        return protect switch
        {
            0x01 => "NOACCESS",
            0x02 => "READONLY",
            0x04 => "READWRITE",
            0x08 => "WRITECOPY",
            0x10 => "EXECUTE",
            0x20 => "EXECUTE_READ",
            0x40 => "EXECUTE_READWRITE",
            0x80 => "EXECUTE_WRITECOPY",
            _ => $"0x{protect:X}"
        };
    }


    private void StartApiHooking()
    {
        // API hooking requires injecting a hook DLL into the target process
        // This is not implemented - would need a separate hook DLL that communicates
        // back via shared memory or named pipes
        // For now, ETW tracing provides system-wide event visibility
    }

    private void StopApiHooking()
    {
        // No-op since API hooking is not implemented
    }

    #endregion
}
