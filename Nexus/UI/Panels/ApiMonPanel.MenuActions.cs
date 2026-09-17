// <file>
// <summary>
// Partial class for ApiMonPanel handling toolbar and menu actions: start/stop monitoring,
// clear events, save captures to CSV/JSON, save/load API selection profiles, and
// multi-process service orchestration via ProcessWatchlist integration.
// </summary>
// </file>

using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Nexus.UI.Core;
using Nexus.UI.Interop;
using Nexus.UI.Models;
using Nexus.UI.Services;

namespace Nexus.UI.Panels;

public partial class ApiMonPanel
{
    #region Capture Control

    private void BtnStartStop_Click(object? sender, EventArgs e) => ToggleCapture();

    private void ToggleCapture()
    {
        if (_isCapturing)
            StopCapture();
        else
            StartCapture();
    }

    private void StartCapture()
    {
        // Check for targets: either attached process or watchlist entries
        var watchlist = ProcessWatchlist.Instance;
        var hasWatchlistTargets = watchlist.Entries.Any(e =>
            e.Type == WatchlistEntryType.Process && e.Enabled);

        _statusLabel.Text = $"StartCapture: attached={Context.IsAttached}, PID={Context.ProcessId}, watchlist={hasWatchlistTargets}, selectedApis={_selectedApis.Count}";

        if (!Context.IsAttached && !hasWatchlistTargets)
        {
            _statusLabel.Text = "No process attached and no watchlist entries";
            UpdateStatus("No process attached and no watchlist entries - attach a process, click 'Watchlist...' on the API Monitor toolbar, or use Tools > Process Watchlist", StatusType.Warning);
            return;
        }

        if (_selectedApis.Count == 0)
        {
            _statusLabel.Text = "No APIs selected - check APIs in the tree to monitor them";
            UpdateStatus("No APIs selected - check APIs in the tree to monitor them", StatusType.Warning);
            return;
        }

        // Resolve and cache selected API definitions
        _resolvedApis = ResolveSelectedApiDefinitions();
        if (_resolvedApis.Count == 0)
        {
            _statusLabel.Text = "Could not resolve selected API definitions";
            UpdateStatus("Could not resolve selected API definitions", StatusType.Warning);
            return;
        }

        _statusLabel.Text = $"Resolved {_resolvedApis.Count} APIs, starting services...";

        _isCapturing = true;
        _btnStartStop.Text = "Stop";
        _updateTimer.Start();

        int serviceCount = 0;

        // Start service for the attached process if any
        if (Context.IsAttached)
        {
            _statusLabel.Text = $"Starting service for {Context.ProcessName} (PID: {Context.ProcessId})...";
            if (StartServiceForPid(Context.ProcessId, Context.ProcessName, IntPtr.Zero))
                serviceCount++;
            else
                _statusLabel.Text = $"StartServiceForPid FAILED for PID {Context.ProcessId}";
        }

        // Start services for all active watchlist PIDs
        // NOTE: API monitoring always injects regardless of watchlist passive mode,
        // since the entire point of this panel is DLL-based API capture.
        foreach (var kvp in watchlist.ActivePids)
        {
            if (!_monitorServices.ContainsKey(kvp.Key))
            {
                if (StartServiceForPid(kvp.Key, kvp.Value.Name, IntPtr.Zero))
                    serviceCount++;
            }
        }

        // Subscribe to watchlist events for future process discovery
        watchlist.ProcessDiscovered += OnWatchlistProcessDiscovered;
        watchlist.ProcessExited += OnWatchlistProcessExited;

        // Start watchlist polling if not already running.
        // Use fast 50ms poll with native toolhelp for API monitoring — we need to detect
        // new processes ASAP. Native CreateToolhelp32Snapshot is fast enough for 50ms polling
        // without significant CPU overhead (no managed Process objects allocated).
        if (hasWatchlistTargets)
        {
            watchlist.PollIntervalMs = 50;
            if (!watchlist.IsRunning)
                watchlist.Start();
        }

        var pidList = string.Join(", ", _monitorServices.Keys);
        _statusLabel.Text = serviceCount > 0
            ? $"Monitoring {_resolvedApis.Count} APIs across {serviceCount} process(es) [{pidList}]..."
            : $"Waiting for watchlist processes ({_resolvedApis.Count} APIs configured)...";
    }

    #region SeDebugPrivilege

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID_AND_ATTRIBUTES Privileges;
    }

    private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    private const uint TOKEN_QUERY = 0x0008;
    private const uint SE_PRIVILEGE_ENABLED = 0x00000002;

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeValue(string? lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr hObject);

    private static bool _debugPrivilegeEnabled;

    private static bool EnableSeDebugPrivilege()
    {
        if (_debugPrivilegeEnabled) return true;

        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out var tokenHandle))
            return false;

        try
        {
            if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out var luid))
                return false;

            var tp = new TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1,
                Privileges = new LUID_AND_ATTRIBUTES { Luid = luid, Attributes = SE_PRIVILEGE_ENABLED }
            };

            if (!AdjustTokenPrivileges(tokenHandle, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
                return false;

            // AdjustTokenPrivileges returns true even if not all privileges were enabled
            _debugPrivilegeEnabled = Marshal.GetLastWin32Error() == 0;
            return _debugPrivilegeEnabled;
        }
        finally
        {
            CloseHandle(tokenHandle);
        }
    }

    #endregion

    /// <summary>
    /// Starts a monitoring service for a specific PID.
    /// Always opens its own process handle to avoid dangling references
    /// when the main ShellForm handle is closed during process switching.
    /// </summary>
    private bool StartServiceForPid(int pid, string processName, IntPtr existingHandle)
    {
        if (_monitorServices.ContainsKey(pid) || _resolvedApis == null)
            return false;

        // Enable SeDebugPrivilege — required for opening protected service processes
        // like EAAntiCheat. The privilege exists in admin tokens but is disabled by default.
        EnableSeDebugPrivilege();

        // Open a process handle with Full access (required for DLL injection).
        // ReadWrite (default) lacks PROCESS_CREATE_THREAD needed for injection.
        // EAC blocks PROCESS_VM_OPERATION on EAAntiCheat.GameService.exe and a few
        // other protected processes — we fall through to kernel-APC injection in
        // that case (NexusCore opens its own kernel handle, bypassing ObCallbacks).
        IntPtr handle = existingHandle;
        bool useKernelApcInject = false;
        if (handle == IntPtr.Zero)
        {
            var result = NexusEngine.Nexus_OpenProcessEx((uint)pid, NexusProcessAccess.Full, out handle);
            if (result != NexusResult.OK || handle == IntPtr.Zero)
            {
                // Fall back to Debug access
                result = NexusEngine.Nexus_OpenProcessEx((uint)pid, NexusProcessAccess.Debug, out handle);
            }
            if (result != NexusResult.OK || handle == IntPtr.Zero)
            {
                useKernelApcInject = true;
            }
            else
            {
                // Check actual access level — engine silently falls back on AccessDenied.
                // Injection requires at least Full (PROCESS_CREATE_THREAD).
                NexusEngine.Nexus_GetProcessAccess(handle, out var actualAccess);
                if (actualAccess < NexusProcessAccess.Full)
                {
                    NexusEngine.Nexus_CloseProcess(handle);
                    handle = IntPtr.Zero;
                    useKernelApcInject = true;
                }
                else
                {
                    _openedHandles[pid] = handle;
                }
            }
        }

        if (useKernelApcInject)
        {
            // EAC-protected target — try kernel-APC injection via NexusCore.
            // Requires NexusCore mapper to be initialized (mapperState >= 3).
            if (StartServiceViaKernelApc(pid, processName))
                return true;

            UpdateStatus($"Failed to inject into {processName} (PID: {pid}) — NexusCore not initialized? Boot via NexusBoot and run NexusDSEFix --mapper-init.", StatusType.Warning);
            return false;
        }

        var service = new ApiMonitorService();
        service.OnApiCalled += evt =>
        {
            // Tag event with process display name
            evt.ProcessDisplayName = $"{processName} ({pid})";
            OnApiCalled(evt);
        };
        service.OnError += OnServiceError;
        service.OnReady += (total, success, fail) =>
        {
            if (!IsHandleCreated || IsDisposed) return;
            if (InvokeRequired)
            {
                BeginInvoke(() => OnServiceReadyForPid(pid, processName, total, success, fail));
                return;
            }
            OnServiceReadyForPid(pid, processName, total, success, fail);
        };
        service.OnChildCreated += childPid =>
        {
            if (!IsHandleCreated || IsDisposed) return;
            if (InvokeRequired)
            {
                BeginInvoke(() => HandleChildProcessCreated(childPid, processName));
                return;
            }
            HandleChildProcessCreated(childPid, processName);
        };

        if (!service.StartMonitoring(pid, handle, _resolvedApis))
        {
            var dllAvailable = service.IsHookDllAvailable;
            service.Dispose();
            var reason = dllAvailable ? "injection failed" : "NexusApiHook.dll not found";
            UpdateStatus($"Failed to start monitoring {processName} (PID: {pid}) - {reason}", StatusType.Warning);
            return false;
        }

        _monitorServices[pid] = service;
        return true;
    }

    /// <summary>
    /// Starts monitoring an EAC-protected process via NexusCore kernel APC injection.
    /// Pre-creates the named pipe (StartMonitoringChild path — no host-side injection),
    /// then calls NexusCore via SetVariable to allocate a shellcode page in the target
    /// and queue an APC that runs LdrLoadDll(NexusApiHook.dll). NexusCore opens the
    /// target with OBJ_KERNEL_HANDLE which bypasses EAC's ObCallbacks.
    ///
    /// Used when the host cannot get PROCESS_VM_OPERATION on the target (e.g.
    /// EAAntiCheat.GameService.exe). The whole flow returns within milliseconds —
    /// fast enough to catch the short-lived GameService process from the watchlist.
    /// </summary>
    private bool StartServiceViaKernelApc(int pid, string processName)
    {
        var dllPath = ApiMonitorService.GetHookDll64Path();
        if (string.IsNullOrEmpty(dllPath))
        {
            UpdateStatus("NexusApiHook.dll not found — build Nexus/Native/ApiHook first", StatusType.Warning);
            return false;
        }

        var service = new ApiMonitorService();
        service.OnApiCalled += evt =>
        {
            evt.ProcessDisplayName = $"{processName} ({pid})";
            OnApiCalled(evt);
        };
        service.OnError += OnServiceError;
        service.OnReady += (total, success, fail) =>
        {
            if (!IsHandleCreated || IsDisposed) return;
            if (InvokeRequired)
            {
                BeginInvoke(() => OnServiceReadyForPid(pid, processName, total, success, fail));
                return;
            }
            OnServiceReadyForPid(pid, processName, total, success, fail);
        };
        service.OnChildCreated += childPid =>
        {
            if (!IsHandleCreated || IsDisposed) return;
            if (InvokeRequired)
            {
                BeginInvoke(() => HandleChildProcessCreated(childPid, processName));
                return;
            }
            HandleChildProcessCreated(childPid, processName);
        };

        // Create the pipe BEFORE the inject so the DLL can connect immediately
        // when LdrLoadDll fires from the queued APC.
        if (!service.StartMonitoringChild(pid, _resolvedApis!))
        {
            service.Dispose();
            return false;
        }

        // Send INJD to NexusCore. The kernel allocates a shellcode page in the
        // target and queues a user-mode APC that calls LdrLoadDll. The DLL fires
        // on the next alertable wait in the target — typically <10ms.
        var bk = NexusEngine.InjectDllViaKernelApc((uint)pid, dllPath, out var injResult);
        if (bk != NexusEngine.BootkitResult.Success || !injResult.ApcQueued)
        {
            service.StopMonitoring();
            service.Dispose();
            UpdateStatus(
                $"Kernel APC inject failed for {processName} (PID: {pid}): NTSTATUS=0x{injResult.NtStatus:X8} apcQueued={injResult.ApcQueued}",
                StatusType.Warning);
            return false;
        }

        _monitorServices[pid] = service;
        UpdateStatus($"Kernel APC inject queued for {processName} (PID: {pid}) — DLL load on next alertable wait", StatusType.Info);
        return true;
    }

    /// <summary>
    /// Stops and cleans up the service for a specific PID.
    /// </summary>
    private void StopServiceForPid(int pid)
    {
        if (_monitorServices.TryGetValue(pid, out var service))
        {
            service.OnApiCalled -= OnApiCalled;
            service.OnError -= OnServiceError;
            service.StopMonitoring();
            service.Dispose();
            _monitorServices.Remove(pid);
        }

        if (_openedHandles.TryGetValue(pid, out var handle))
        {
            if (handle != IntPtr.Zero)
                NexusEngine.Nexus_CloseProcess(handle);
            _openedHandles.Remove(pid);
        }
    }

    /// <summary>
    /// Resolves selected API key strings (e.g. "kernel32.dll!CreateFileW") back to
    /// full ApiDefinition objects from the loaded module groups.
    /// </summary>
    private List<ApiDefinition> ResolveSelectedApiDefinitions()
    {
        var result = new List<ApiDefinition>();
        CollectSelectedDefinitions(_apiTree.Nodes, result);
        return result;
    }

    private void CollectSelectedDefinitions(TreeNodeCollection nodes, List<ApiDefinition> result)
    {
        foreach (TreeNode node in nodes)
        {
            if (node.Tag is ApiDefinition api && node.Checked && _selectedApis.Contains(api.Key))
            {
                result.Add(api);
            }
            CollectSelectedDefinitions(node.Nodes, result);
        }
    }

    private void OnServiceError(string message)
    {
        if (!IsHandleCreated || IsDisposed) return;
        if (InvokeRequired)
        {
            BeginInvoke(() => OnServiceError(message));
            return;
        }
        _statusLabel.Text = $"Hook: {message}";
        UpdateStatus($"Hook error: {message}", StatusType.Error);
    }

    private void OnServiceReadyForPid(int pid, string processName, int total, int success, int fail)
    {
        var msg = $"Hooks: {success}/{total} ({fail} failed) in {processName} (PID: {pid}) | {_monitorServices.Count} process(es)";
        _statusLabel.Text = msg;
        UpdateStatus(msg, fail > total / 2 ? StatusType.Warning : StatusType.Success);
    }

    private void StopCapture()
    {
        _isCapturing = false;
        _btnStartStop.Text = "Start";

        // Unsubscribe from watchlist events and restore normal poll interval
        var watchlist = ProcessWatchlist.Instance;
        watchlist.ProcessDiscovered -= OnWatchlistProcessDiscovered;
        watchlist.ProcessExited -= OnWatchlistProcessExited;
        watchlist.PollIntervalMs = 1000;

        // Stop all services (this waits for DLL to drain remaining events)
        foreach (var pid in _monitorServices.Keys.ToList())
        {
            StopServiceForPid(pid);
        }

        // Flush any remaining events that arrived during shutdown
        ProcessEventQueue();
        _updateTimer.Stop();

        // Auto-save any remaining events (all PIDs combined)
        AutoSaveAllRemainingEvents();

        _resolvedApis = null;
        _statusLabel.Text = $"Stopped - events saved to captures/";
    }

    /// <summary>
    /// Auto-saves all remaining events to a combined JSON file on Stop.
    /// </summary>
    private void AutoSaveAllRemainingEvents()
    {
        List<ApiCallEvent> snapshot;
        lock (_eventsLock)
        {
            if (_events.Count == 0) return;
            snapshot = [.. _events];
        }

        try
        {
            var capturesDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "captures");
            Directory.CreateDirectory(capturesDir);

            var fileName = $"all_events_{DateTime.Now:yyyyMMdd_HHmmss}.json";
            var filePath = Path.Combine(capturesDir, fileName);

            var options = new JsonSerializerOptions { WriteIndented = true };
            var json = JsonSerializer.Serialize(snapshot.Select(e => new
            {
                e.SequenceNumber,
                Timestamp = e.Timestamp.ToString("O"),
                e.ProcessId,
                e.ProcessDisplayName,
                e.ThreadId,
                e.Module,
                e.Function,
                e.Category,
                Parameters = e.Parameters.Select(p => new { Direction = p.DirectionString, p.Name, p.Type, p.Value }).ToArray(),
                e.ReturnValue,
                e.Success,
                Duration = e.Duration.TotalMilliseconds,
            }), options);

            File.WriteAllText(filePath, json);
            UpdateStatus($"Auto-saved {snapshot.Count:N0} events to captures/{fileName}", StatusType.Success);
        }
        catch (Exception ex)
        {
            UpdateStatus($"Auto-save on stop failed: {ex.Message}", StatusType.Error);
        }
    }

    private void OnApiCalled(ApiCallEvent evt)
    {
        _eventQueue.Enqueue(evt);
    }

    private void ToggleAutoScroll()
    {
        _autoScroll = !_autoScroll;
        _chkAutoScroll.Checked = _autoScroll;
    }

    #endregion

    #region Watchlist Integration

    private void OnWatchlistProcessDiscovered(object? sender, WatchlistProcessEventArgs e)
    {
        if (!IsHandleCreated || IsDisposed) return;
        if (InvokeRequired)
        {
            BeginInvoke(() => OnWatchlistProcessDiscovered(sender, e));
            return;
        }

        // API monitoring always injects regardless of watchlist passive mode
        if (_isCapturing && _resolvedApis != null && !_monitorServices.ContainsKey(e.ProcessId))
        {
            if (StartServiceForPid(e.ProcessId, e.ProcessName, IntPtr.Zero))
            {
                UpdateStatus($"Auto-started API monitoring for {e.ProcessName} (PID: {e.ProcessId})", StatusType.Success);
            }
        }
    }

    private void OnWatchlistProcessExited(object? sender, WatchlistProcessEventArgs e)
    {
        if (!IsHandleCreated || IsDisposed) return;
        if (InvokeRequired)
        {
            BeginInvoke(() => OnWatchlistProcessExited(sender, e));
            return;
        }

        // Auto-save events for this PID before stopping the service
        AutoSaveEventsForPid(e.ProcessId, e.ProcessName);

        StopServiceForPid(e.ProcessId);
        UpdateStatus($"API monitoring stopped for {e.ProcessName} (PID: {e.ProcessId}) - process exited", StatusType.Info);
    }

    /// <summary>
    /// Handles a child process created by a monitored parent.
    /// The hook DLL has already been APC-injected into the child — we just need
    /// to create the pipe and service so the child can connect and receive config.
    /// </summary>
    private void HandleChildProcessCreated(int childPid, string parentName)
    {
        if (_monitorServices.ContainsKey(childPid) || _resolvedApis == null || !_isCapturing)
            return;

        // Try to get child process name
        string childName;
        try
        {
            using var proc = System.Diagnostics.Process.GetProcessById(childPid);
            childName = proc.ProcessName;
        }
        catch
        {
            childName = $"child-{childPid}";
        }

        var childService = new ApiMonitorService();
        childService.OnApiCalled += evt =>
        {
            evt.ProcessDisplayName = $"{childName} ({childPid})";
            OnApiCalled(evt);
        };
        childService.OnError += OnServiceError;
        childService.OnReady += (total, success, fail) =>
        {
            if (!IsHandleCreated || IsDisposed) return;
            if (InvokeRequired)
            {
                BeginInvoke(() => OnServiceReadyForPid(childPid, childName, total, success, fail));
                return;
            }
            OnServiceReadyForPid(childPid, childName, total, success, fail);
        };
        // Recursive: if the child spawns grandchildren, handle them too
        childService.OnChildCreated += grandchildPid =>
        {
            if (!IsHandleCreated || IsDisposed) return;
            if (InvokeRequired)
            {
                BeginInvoke(() => HandleChildProcessCreated(grandchildPid, childName));
                return;
            }
            HandleChildProcessCreated(grandchildPid, childName);
        };

        if (childService.StartMonitoringChild(childPid, _resolvedApis))
        {
            _monitorServices[childPid] = childService;
            UpdateStatus($"Child process detected: {childName} (PID: {childPid}) from {parentName} — hooks propagated via APC", StatusType.Success);
        }
        else
        {
            childService.Dispose();
            UpdateStatus($"Failed to start monitoring child {childName} (PID: {childPid})", StatusType.Warning);
        }
    }

    /// <summary>
    /// Auto-saves events for a specific PID to a JSON file in the captures/ directory,
    /// then removes those events from the display list.
    /// </summary>
    private void AutoSaveEventsForPid(int pid, string processName)
    {
        // Drain pending events from the queue so nothing is lost
        ProcessEventQueue();

        List<ApiCallEvent> eventsToSave;

        lock (_eventsLock)
        {
            // Save events for this PID but keep them in the display list.
            // Previously we removed them, which caused events to vanish when
            // short-lived processes (like the anti-cheat launcher) exited.
            eventsToSave = _events.Where(e => e.ProcessId == pid).ToList();
            if (eventsToSave.Count == 0)
                return;
        }

        // Write to captures directory
        try
        {
            var capturesDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "captures");
            Directory.CreateDirectory(capturesDir);

            var safeName = string.Join("_", processName.Split(Path.GetInvalidFileNameChars()));
            var fileName = $"{safeName}_{pid}_{DateTime.Now:yyyyMMdd_HHmmss}.json";
            var filePath = Path.Combine(capturesDir, fileName);

            var options = new JsonSerializerOptions { WriteIndented = true };
            var json = JsonSerializer.Serialize(eventsToSave.Select(e => new
            {
                e.SequenceNumber,
                Timestamp = e.Timestamp.ToString("O"),
                e.ProcessId,
                e.ProcessDisplayName,
                e.ThreadId,
                e.Module,
                e.Function,
                e.Category,
                Parameters = e.Parameters.Select(p => new { Direction = p.DirectionString, p.Name, p.Type, p.Value }).ToArray(),
                e.ReturnValue,
                e.Success,
                Duration = e.Duration.TotalMilliseconds,
            }), options);

            File.WriteAllText(filePath, json);

            UpdateStatus($"Auto-saved {eventsToSave.Count:N0} events for {processName} to captures/{fileName}", StatusType.Success);
        }
        catch (Exception ex)
        {
            UpdateStatus($"Auto-save failed for {processName}: {ex.Message}", StatusType.Error);
        }
    }

    #endregion

    #region Clear

    private void BtnClear_Click(object? sender, EventArgs e) => ClearEvents();

    private void ClearEvents()
    {
        lock (_eventsLock)
        {
            _events.Clear();
            _captureList.VirtualListSize = 0;
        }

        // Drain the queue
        while (_eventQueue.TryDequeue(out _)) { }

        ClearDetailPanel();
        ApiCallEvent.ResetSequence();
        _eventCountLabel.Text = "Events: 0" +
            (_selectedApis.Count > 0 ? $" | Selected: {_selectedApis.Count}" : "");
    }

    #endregion

    #region Save

    private void BtnSave_Click(object? sender, EventArgs e)
    {
        var menu = new ContextMenuStrip();
        menu.Items.Add("Save to JSON...", null, (s, e) => SaveEventsToJson());
        menu.Items.Add("Save to CSV...", null, (s, e) => SaveEventsToCsv());
        menu.Closed += (s, e) => BeginInvoke(() => menu.Dispose());
        menu.Show(_btnSave, new Point(0, _btnSave.Height));
    }

    private void SaveEventsToJson()
    {
        using var dialog = new SaveFileDialog
        {
            Title = "Save API Events",
            Filter = "JSON Files (*.json)|*.json",
            DefaultExt = "json",
            FileName = $"api_events_{DateTime.Now:yyyyMMdd_HHmmss}.json"
        };

        if (dialog.ShowDialog() != DialogResult.OK) return;

        List<ApiCallEvent> snapshot;
        lock (_eventsLock)
        {
            snapshot = [.. _events];
        }

        try
        {
            var options = new JsonSerializerOptions { WriteIndented = true };
            var json = JsonSerializer.Serialize(snapshot.Select(e => new
            {
                e.SequenceNumber,
                Timestamp = e.Timestamp.ToString("O"),
                e.ProcessId,
                e.ProcessDisplayName,
                e.ThreadId,
                e.Module,
                e.Function,
                e.Category,
                Parameters = e.Parameters.Select(p => new { Direction = p.DirectionString, p.Name, p.Type, p.Value }).ToArray(),
                e.ReturnValue,
                e.Success,
                Duration = e.Duration.TotalMilliseconds,
            }), options);

            File.WriteAllText(dialog.FileName, json);
            UpdateStatus($"Saved {snapshot.Count} events to {dialog.FileName}", StatusType.Success);
        }
        catch (Exception ex)
        {
            UpdateStatus($"Failed to save: {ex.Message}", StatusType.Error);
        }
    }

    private void SaveEventsToCsv()
    {
        using var dialog = new SaveFileDialog
        {
            Title = "Save API Events",
            Filter = "CSV Files (*.csv)|*.csv",
            DefaultExt = "csv",
            FileName = $"api_events_{DateTime.Now:yyyyMMdd_HHmmss}.csv"
        };

        if (dialog.ShowDialog() != DialogResult.OK) return;

        List<ApiCallEvent> snapshot;
        lock (_eventsLock)
        {
            snapshot = [.. _events];
        }

        try
        {
            var sb = new StringBuilder();
            sb.AppendLine("#,Time,Process,TID,Module,Function,Parameters,Return,Duration(ms),Success");

            foreach (var evt in snapshot)
            {
                sb.AppendLine(string.Join(",",
                    evt.SequenceNumber,
                    evt.Timestamp.ToString("HH:mm:ss.fff"),
                    CsvEscape(evt.ProcessDisplayName),
                    evt.ThreadId,
                    CsvEscape(evt.Module),
                    CsvEscape(evt.Function),
                    CsvEscape(evt.ParameterSummary),
                    CsvEscape(evt.ReturnValue),
                    evt.Duration.TotalMilliseconds.ToString("F3"),
                    evt.Success));
            }

            File.WriteAllText(dialog.FileName, sb.ToString());
            UpdateStatus($"Saved {snapshot.Count} events to {dialog.FileName}", StatusType.Success);
        }
        catch (Exception ex)
        {
            UpdateStatus($"Failed to save: {ex.Message}", StatusType.Error);
        }
    }

    private static string CsvEscape(string value)
    {
        if (string.IsNullOrEmpty(value)) return "";
        if (value.Contains(',') || value.Contains('"') || value.Contains('\n'))
            return $"\"{value.Replace("\"", "\"\"")}\"";
        return value;
    }

    #endregion

    #region Profiles

    private void BtnSaveProfile_Click(object? sender, EventArgs e) => SaveProfile();
    private void BtnLoadProfile_Click(object? sender, EventArgs e) => LoadProfile();

    private void SaveProfile()
    {
        using var dialog = new SaveFileDialog
        {
            Title = "Save API Selection Profile",
            Filter = "JSON Profile (*.apiprofile.json)|*.apiprofile.json",
            DefaultExt = "apiprofile.json",
            FileName = "default.apiprofile.json"
        };

        if (dialog.ShowDialog() != DialogResult.OK) return;

        try
        {
            var profile = new ApiMonitorProfile
            {
                Name = Path.GetFileNameWithoutExtension(dialog.FileName),
                SelectedApis = [.. _selectedApis],
            };

            var options = new JsonSerializerOptions { WriteIndented = true };
            var json = JsonSerializer.Serialize(profile, options);
            File.WriteAllText(dialog.FileName, json);
            UpdateStatus($"Profile saved: {_selectedApis.Count} APIs", StatusType.Success);
        }
        catch (Exception ex)
        {
            UpdateStatus($"Failed to save profile: {ex.Message}", StatusType.Error);
        }
    }

    private void LoadProfile()
    {
        using var dialog = new OpenFileDialog
        {
            Title = "Load API Selection Profile",
            Filter = "JSON Profile (*.apiprofile.json)|*.apiprofile.json|All JSON (*.json)|*.json",
            FilterIndex = 1
        };

        if (dialog.ShowDialog() != DialogResult.OK) return;

        try
        {
            var json = File.ReadAllText(dialog.FileName);
            var profile = JsonSerializer.Deserialize<ApiMonitorProfile>(json);
            if (profile?.SelectedApis == null || profile.SelectedApis.Count == 0)
            {
                UpdateStatus("Profile is empty or invalid", StatusType.Warning);
                return;
            }

            // Apply profile to tree
            var apiKeys = new HashSet<string>(profile.SelectedApis, StringComparer.OrdinalIgnoreCase);
            ApplyProfileToTree(_apiTree.Nodes, apiKeys);
            UpdateSelectedApis();

            UpdateStatus($"Profile loaded: {_selectedApis.Count} APIs selected", StatusType.Success);
        }
        catch (Exception ex)
        {
            UpdateStatus($"Failed to load profile: {ex.Message}", StatusType.Error);
        }
    }

    private void ApplyProfileToTree(TreeNodeCollection nodes, HashSet<string> apiKeys)
    {
        _suppressCheckEvents = true;
        try
        {
            ApplyProfileToTreeRecursive(nodes, apiKeys);

            // Update parent check states bottom-up
            foreach (TreeNode node in nodes)
            {
                UpdateParentCheckBottomUp(node);
            }
        }
        finally
        {
            _suppressCheckEvents = false;
        }
    }

    private static void ApplyProfileToTreeRecursive(TreeNodeCollection nodes, HashSet<string> apiKeys)
    {
        foreach (TreeNode node in nodes)
        {
            if (node.Tag is ApiDefinition api)
            {
                node.Checked = apiKeys.Contains(api.Key);
            }
            else
            {
                ApplyProfileToTreeRecursive(node.Nodes, apiKeys);
            }
        }
    }

    private static void UpdateParentCheckBottomUp(TreeNode node)
    {
        // First recurse to children
        foreach (TreeNode child in node.Nodes)
        {
            UpdateParentCheckBottomUp(child);
        }

        // Then update this node based on children
        if (node.Nodes.Count > 0)
        {
            bool anyChecked = false;
            foreach (TreeNode child in node.Nodes)
            {
                if (child.Checked)
                {
                    anyChecked = true;
                    break;
                }
            }
            node.Checked = anyChecked;
        }
    }

    #endregion
}
