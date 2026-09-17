using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using Nexus.UI.Core;
using Nexus.UI.Forms;
using Nexus.UI.Models;
using Nexus.UI.Providers;
using Nexus.UI.Services;
using Nexus.UI.Styles;

namespace Nexus.UI.Panels;

public partial class KernelMonPanel
{
    #region Event Handlers (from KernelMonitorService - background thread)

    private void OnRegistryEvent(KernelRegistryEvent evt)
    {
        _pendingQueue.Enqueue(new KernelMonEvent
        {
            Type = KernelMonEventType.Registry,
            Timestamp = DateTime.Now,
            ProcessId = evt.Header.ProcessId,
            ThreadId = evt.Header.ThreadId,
            ProcessName = ResolveProcessName(evt.Header.ProcessId),
            Operation = RegOpName(evt.Operation),
            Path = evt.KeyPath ?? "",
            Result = $"0x{evt.Status:X8}",
            Details = FormatRegistryDetails(evt)
        });
    }

    private void OnProcessEvent(KernelProcessEvent evt)
    {
        bool isCreate = evt.Header.EventType == NexusEventType.ProcessCreate;

        if (isCreate && !string.IsNullOrEmpty(evt.ImageName))
        {
            string name = System.IO.Path.GetFileNameWithoutExtension(evt.ImageName);
            _processNames[evt.Header.ProcessId] = name;
        }

        _pendingQueue.Enqueue(new KernelMonEvent
        {
            Type = KernelMonEventType.Process,
            Timestamp = DateTime.Now,
            ProcessId = evt.Header.ProcessId,
            ThreadId = evt.Header.ThreadId,
            ProcessName = ResolveProcessName(evt.Header.ProcessId),
            Operation = isCreate ? "CreateProcess" : "ExitProcess",
            Path = evt.ImageName ?? "",
            Result = isCreate ? $"Parent: {evt.ParentProcessId}" : $"Exit: {evt.ExitCode}",
            Details = $"PID: {evt.Header.ProcessId}, Parent: {evt.ParentProcessId}, Image: {evt.ImageName}"
        });

        if (!isCreate)
            _processNames.TryRemove(evt.Header.ProcessId, out _);
    }

    private void OnHandleEvent(KernelHandleEvent evt)
    {
        _pendingQueue.Enqueue(new KernelMonEvent
        {
            Type = KernelMonEventType.Handle,
            Timestamp = DateTime.Now,
            ProcessId = evt.Header.ProcessId,
            ThreadId = evt.Header.ThreadId,
            ProcessName = ResolveProcessName(evt.Header.ProcessId),
            Operation = HandleOpName(evt.Operation),
            Path = $"{evt.SourceProcessName} -> {evt.TargetProcessName} (PID {evt.TargetProcessId})",
            Result = $"0x{evt.Status:X8}",
            Details = FormatHandleDetails(evt)
        });
    }

    private void OnImageLoadEvent(KernelImageLoadEvent evt)
    {
        _pendingQueue.Enqueue(new KernelMonEvent
        {
            Type = KernelMonEventType.ImageLoad,
            Timestamp = DateTime.Now,
            ProcessId = evt.Header.ProcessId,
            ThreadId = evt.Header.ThreadId,
            ProcessName = ResolveProcessName(evt.Header.ProcessId),
            Operation = "LoadImage",
            Path = evt.ImageName ?? "",
            Result = $"0x{evt.ImageBase:X}",
            Details = $"Base: 0x{evt.ImageBase:X16}, Size: 0x{evt.ImageSize:X}"
        });
    }

    private void OnMemoryEvent(KernelMemoryEvent evt)
    {
        _pendingQueue.Enqueue(new KernelMonEvent
        {
            Type = KernelMonEventType.Memory,
            Timestamp = DateTime.Now,
            ProcessId = evt.Header.ProcessId,
            ThreadId = evt.Header.ThreadId,
            ProcessName = ResolveProcessName(evt.Header.ProcessId),
            Operation = MemOpName(evt.Operation),
            Path = $"{evt.SourceProcessName} -> {evt.TargetProcessName} @ 0x{evt.Address:X}",
            Result = $"0x{evt.Status:X8}",
            Details = $"Target PID: {evt.TargetProcessId}, Address: 0x{evt.Address:X16}, Size: 0x{evt.Size:X}"
        });
    }

    private void OnFileEvent(KernelFileEvent evt)
    {
        _pendingQueue.Enqueue(new KernelMonEvent
        {
            Type = KernelMonEventType.File,
            Timestamp = DateTime.Now,
            ProcessId = evt.Header.ProcessId,
            ThreadId = evt.Header.ThreadId,
            ProcessName = ResolveProcessName(evt.Header.ProcessId),
            Operation = FileOpName(evt.Operation),
            Path = evt.FilePath ?? "",
            Result = $"0x{evt.Status:X8}",
            Details = $"Access: 0x{evt.DesiredAccess:X}, Share: 0x{evt.ShareMode:X}"
        });
    }

    private void OnSyscallEvent(KernelSyscallEvent evt)
    {
        _pendingQueue.Enqueue(new KernelMonEvent
        {
            Type = KernelMonEventType.Syscall,
            Timestamp = DateTime.Now,
            ProcessId = evt.Header.ProcessId,
            ThreadId = evt.Header.ThreadId,
            ProcessName = ResolveProcessName(evt.Header.ProcessId),
            Operation = SyscallTypeName(evt.SyscallType),
            Path = evt.Description ?? $"InfoClass: 0x{evt.InfoClass:X}",
            Result = $"0x{evt.Status:X8}",
            Details = $"InfoClass: 0x{evt.InfoClass:X}, RetVal: 0x{evt.ReturnValue:X}"
        });
    }

    #endregion
    #region UI Event Handlers

    private void BtnConnect_Click(object? sender, EventArgs e)
    {
        if (_service.IsConnected)
        {
            _service.Disconnect();
            return;
        }

        // Show context menu with loading options
        using var menu = new ContextMenuStrip();
        menu.BackColor = NexusTheme.BackgroundControl;
        menu.ForeColor = NexusTheme.TextPrimary;

        var scItem = menu.Items.Add("SC (Service) - Recommended", null, (s, ev) => ConnectViaSc());
        scItem!.ToolTipText = "Load via sc.exe. Requires a signed driver or test signing.";

        var mapperItem = menu.Items.Add("Mapper (Bootkit)", null, (s, ev) => ConnectViaMapper());
        mapperItem!.ToolTipText = "Load via bootkit mapper. Limited: no CmRegisterCallbackEx, no IOCTL.";

        menu.Show(_btnConnect, new Point(0, _btnConnect.Height));
    }

    private void ConnectViaSc()
    {
        string driverPath = FindDriverPath();
        if (string.IsNullOrEmpty(driverPath))
        {
            MessageBox.Show(
                "Could not find NexusKernel.sys.\n\n" +
                "Expected locations:\n" +
                "  - Nexus\\Kernel\\bin\\Release\\NexusKernel.sys\n" +
                "  - Nexus\\bin\\NexusKernel.sys\n\n" +
                "Build it first:\n" +
                "  cd Nexus\\Kernel && MSBuild NexusKernel.vcxproj -p:Configuration=Release -p:Platform=x64",
                "Driver Not Found", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        _statusLabel.Text = "Loading NexusKernel.sys via SC...";
        Application.DoEvents();

        string? error = _service.ConnectViaSc(driverPath);
        if (error != null)
        {
            MessageBox.Show(error, "SC Load Failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
            _statusLabel.Text = "SC load failed";
            return;
        }

        OnConnected();
    }

    private void ConnectViaMapper()
    {
        string driverPath = FindDriverPath();

        _statusLabel.Text = "Loading NexusKernel.sys via Mapper...";
        Application.DoEvents();

        string? error = _service.ConnectViaMapper(driverPath);
        if (error != null)
        {
            MessageBox.Show(error, "Mapper Load", MessageBoxButtons.OK, MessageBoxIcon.Information);
            _statusLabel.Text = "Mapper load not available";
            return;
        }

        OnConnected();
    }

    private void OnConnected()
    {
        _btnConnect.Text = "Disconnect";

        string method = _service.LoadMethod == DriverLoadMethod.ServiceControl ? "SC" : "Mapper";
        if (_service.GetVersion(out var ver))
            _statusLabel.Text = $"Connected ({method}) - NexusKernel v{ver.Major}.{ver.Minor}.{ver.Patch} - Click Start";
        else
            _statusLabel.Text = $"Connected ({method}) - Click Start to begin monitoring";
    }

    private void BtnStartStop_Click(object? sender, EventArgs e)
    {
        ToggleMonitoring();
    }

    private void BtnClear_Click(object? sender, EventArgs e)
    {
        ClearEvents();
    }

    private void BtnExport_Click(object? sender, EventArgs e)
    {
        ExportToCsv();
    }

    /// <summary>
    /// Start: auto-connect via SC if needed, register callbacks for ALL events (no PID filter),
    /// subscribe to watchlist, start polling.
    /// Stop: unregister callbacks, unsubscribe from watchlist.
    /// </summary>
    private void ToggleMonitoring()
    {
        if (_isMonitoring)
        {
            StopMonitoring();
            return;
        }

        // Auto-connect via SC if not connected
        if (!_service.IsConnected)
        {
            string driverPath = FindDriverPath();
            if (string.IsNullOrEmpty(driverPath))
            {
                MessageBox.Show(
                    "Could not find NexusKernel.sys.\n\n" +
                    "Build it first, then try again.",
                    "Driver Not Found", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            _statusLabel.Text = "Auto-loading NexusKernel.sys via SC...";
            Application.DoEvents();

            string? error = _service.ConnectViaSc(driverPath);
            if (error != null)
            {
                MessageBox.Show(error, "SC Load Failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
                _statusLabel.Text = "Failed to auto-load driver";
                return;
            }

            _btnConnect.Text = "Disconnect";
        }

        StartMonitoring();
    }

    private void StartMonitoring()
    {
        // Always capture ALL events with NO driver-side PID filter.
        // Client-side filtering (watchlist, PID box, text search) narrows the display.
        // This ensures we never miss early events before watchlist detects processes.
        uint mask = BuildEventMask();
        if (!_service.StartMonitoring(mask, 0))
        {
            _statusLabel.Text = "Failed to start monitoring - IOCTL_NEXUS_REGISTER_CALLBACK failed";
            return;
        }

        _isMonitoring = true;
        _btnStartStop.Text = "Stop";
        NexusTheme.StylePrimaryButton(_btnStartStop);

        // Subscribe to watchlist events
        var watchlist = ProcessWatchlist.Instance;
        watchlist.ProcessDiscovered += OnWatchlistProcessDiscovered;
        watchlist.ProcessExited += OnWatchlistProcessExited;
        watchlist.DriverLoaded += OnWatchlistDriverLoaded;
        watchlist.DriverUnloaded += OnWatchlistDriverUnloaded;

        // Seed with already-active watchlist PIDs
        foreach (var kvp in watchlist.ActivePids)
        {
            _watchlistPids.Add((uint)kvp.Key);
            _processNames[(uint)kvp.Key] = kvp.Value.Name;
        }

        // Seed driver names
        foreach (var entry in watchlist.Entries)
        {
            if (entry.Type == WatchlistEntryType.Driver && entry.Enabled)
            {
                _watchlistDriverNames.Add(entry.Name);
                if (entry.IsActive)
                    _watchlistPids.Add(4); // System PID for driver events
            }
        }

        // Start watchlist polling if it has entries
        if (!watchlist.IsRunning && watchlist.Entries.Count > 0)
            watchlist.Start();

        int watchCount = watchlist.Entries.Count;
        int activeCount = _watchlistPids.Count;
        _statusLabel.Text = watchCount > 0
            ? $"Monitoring ALL events | Watchlist: {watchCount} entries, {activeCount} active PIDs | Launch target app now"
            : "Monitoring ALL events | No watchlist entries - configure watchlist or use PID/Search filter";
    }

    private void StopMonitoring()
    {
        _service.StopMonitoring();
        _isMonitoring = false;
        _btnStartStop.Text = "Start";
        NexusTheme.StyleButton(_btnStartStop);

        // Unsubscribe from watchlist
        var watchlist = ProcessWatchlist.Instance;
        watchlist.ProcessDiscovered -= OnWatchlistProcessDiscovered;
        watchlist.ProcessExited -= OnWatchlistProcessExited;
        watchlist.DriverLoaded -= OnWatchlistDriverLoaded;
        watchlist.DriverUnloaded -= OnWatchlistDriverUnloaded;

        _watchlistPids.Clear();
        _watchlistDriverNames.Clear();

        _statusLabel.Text = $"Stopped - {_events.Count:N0} events captured";
    }

    private void ClearEvents()
    {
        lock (_eventsLock)
        {
            _events.Clear();
            _filteredIndices.Clear();
            while (_pendingQueue.TryDequeue(out _)) { }
        }
        _eventList.VirtualListSize = 0;
        _detailText.Clear();
        _filterDirty = false;
        _statusLabel.Text = _isMonitoring ? "Monitoring..." : "Cleared";
    }

    private void ApplyPidFilter()
    {
        _filterPid = uint.TryParse(_pidBox.Text.Trim(), out uint pid) ? pid : 0;
        if (_filterPid == 0) _pidBox.Text = "";
        _filterDirty = true;
    }

    private void ExportToCsv()
    {
        using var dialog = new SaveFileDialog
        {
            Title = "Export Kernel Events",
            Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*",
            DefaultExt = "csv",
            FileName = $"kernel_events_{DateTime.Now:yyyyMMdd_HHmmss}"
        };

        if (dialog.ShowDialog() != DialogResult.OK) return;

        try
        {
            lock (_eventsLock)
            {
                using var writer = new StreamWriter(dialog.FileName, false, Encoding.UTF8);
                writer.WriteLine("#,Time,PID,TID,Process,Type,Operation,Path,Result,Details");

                foreach (var evt in _events)
                {
                    writer.WriteLine(
                        $"{evt.SequenceNumber}," +
                        $"{evt.Timestamp:HH:mm:ss.fff}," +
                        $"{evt.ProcessId}," +
                        $"{evt.ThreadId}," +
                        $"\"{Escape(evt.ProcessName)}\"," +
                        $"{evt.Type}," +
                        $"\"{Escape(evt.Operation)}\"," +
                        $"\"{Escape(evt.Path)}\"," +
                        $"\"{Escape(evt.Result)}\"," +
                        $"\"{Escape(evt.Details)}\"");
                }
            }

            _statusLabel.Text = $"Exported {_events.Count:N0} events to {Path.GetFileName(dialog.FileName)}";
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Export failed: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private static string Escape(string s) => s?.Replace("\"", "\"\"") ?? "";

    #endregion
}
