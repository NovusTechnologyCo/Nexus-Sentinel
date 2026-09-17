using System.Collections.Concurrent;
using Nexus.UI.Core;
using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using Nexus.UI.Services;
using Nexus.UI.Styles;

namespace Nexus.UI.Panels;
    public partial class ProcMonPanel
    {
    #region Event Processing

    private void AddEvent(ProcMonEvent evt)
    {
        _eventQueue.Enqueue(evt);
    }

    private void ProcessEventQueue()
    {
        var newEvents = new List<ProcMonEvent>();

        while (_eventQueue.TryDequeue(out var evt))
        {
            if (ShouldShowEvent(evt))
            {
                newEvents.Add(evt);
            }
        }

        if (newEvents.Count == 0) return;

        lock (_eventsLock)
        {
            _events.AddRange(newEvents);

            // Trim if over max
            while (_events.Count > _maxEvents)
            {
                _events.RemoveAt(0);
            }

            _eventList.VirtualListSize = _events.Count;

            if (_autoScroll && _events.Count > 0)
            {
                _eventList.EnsureVisible(_events.Count - 1);
            }
        }

        var limitWarning = _events.Count >= _maxEvents ? " [LIMIT REACHED - oldest events dropped]" :
                           _events.Count >= _maxEvents * 0.9 ? " [90% full]" : "";
        UpdateStatus($"Capturing... {_events.Count:N0} events{limitWarning}");
    }

    private bool ShouldShowEvent(ProcMonEvent evt)
    {
        // Category filter
        var showByCategory = evt.Category switch
        {
            EventCategory.File => _showFileEvents,
            EventCategory.Registry => _showRegistryEvents,
            EventCategory.Network => _showNetworkEvents,
            EventCategory.Process => _showProcessEvents,
            EventCategory.Thread => _showThreadEvents,
            EventCategory.ApiCall => _showApiCalls,
            EventCategory.Memory => _showMemoryEvents,
            EventCategory.Handle => _showHandleEvents,
            _ => true
        };

        if (!showByCategory) return false;

        // Text filter
        if (!string.IsNullOrWhiteSpace(_filterText))
        {
            var filter = _filterText.ToLowerInvariant();
            return evt.Operation.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                   evt.Path.Contains(filter, StringComparison.OrdinalIgnoreCase);
        }

        return true;
    }

    private void ApplyFilter()
    {
        lock (_eventsLock)
        {
            _eventList.VirtualListSize = 0;
            var filtered = _events.Where(ShouldShowEvent).ToList();
            _events.Clear();
            _events.AddRange(filtered);
            _eventList.VirtualListSize = _events.Count;
        }
    }

    private ListViewItem CreateListViewItem(ProcMonEvent evt, int index)
    {
        var item = new ListViewItem(new[]
        {
            (index + 1).ToString(),
            evt.Timestamp.ToString("HH:mm:ss.fff"),
            evt.ProcessName,
            evt.Category.ToString(),
            evt.Operation,
            evt.Path,
            evt.Result,
            evt.Duration.TotalMilliseconds.ToString("F2") + " ms"
        })
        {
            Tag = evt
        };
        return item;
    }

    private static string FormatEventDetails(ProcMonEvent evt)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"Event #{evt.SequenceNumber}");
        sb.AppendLine(new string('-', 50));
        sb.AppendLine($"Timestamp:  {evt.Timestamp:yyyy-MM-dd HH:mm:ss.fff}");
        sb.AppendLine($"Process:    {evt.ProcessName}");
        sb.AppendLine($"Category:   {evt.Category}");
        sb.AppendLine($"Operation:  {evt.Operation}");
        sb.AppendLine($"Path:       {evt.Path}");
        sb.AppendLine($"Result:     {evt.Result}");
        sb.AppendLine($"Duration:   {evt.Duration.TotalMilliseconds:F3} ms");
        sb.AppendLine($"Process ID: {evt.ProcessId}");
        sb.AppendLine($"Thread ID:  {evt.ThreadId}");

        if (evt.Details.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("Additional Details:");
            sb.AppendLine(new string('-', 50));
            foreach (var kv in evt.Details)
            {
                sb.AppendLine($"  {kv.Key}: {kv.Value}");
            }
        }

        if (!string.IsNullOrEmpty(evt.StackTrace))
        {
            sb.AppendLine();
            sb.AppendLine("Stack Trace:");
            sb.AppendLine(new string('-', 50));
            sb.AppendLine(evt.StackTrace);
        }

        return sb.ToString();
    }

    #endregion

    #region Helpers

    private void UpdateStatus(string message)
    {
        if (InvokeRequired)
        {
            Invoke(() => UpdateStatus(message));
            return;
        }
        _statusLabel.Text = message;
    }

    #endregion

    #region Multi-Process Monitoring

    private void AddMonitoredProcess(int pid, string name)
    {
        if (_monitoredPids.Contains(pid)) return;

        _monitoredPids.Add(pid);
        _pidNames[pid] = name;

        var item = new MonitoredProcessItem(pid, name);
        _cmbMonitoredPids.Items.Add(item);
        _cmbMonitoredPids.SelectedItem = item;

        UpdateMonitoredProcessCount();
    }

    private void RemoveMonitoredProcess(int pid)
    {
        if (!_monitoredPids.Contains(pid)) return;

        _monitoredPids.Remove(pid);
        _pidNames.Remove(pid);

        // Remove any children that were auto-followed from this process
        var childrenToRemove = _parentChildMap.Where(kv => kv.Value == pid).Select(kv => kv.Key).ToList();
        foreach (var childPid in childrenToRemove)
        {
            _monitoredPids.Remove(childPid);
            _pidNames.Remove(childPid);
            _parentChildMap.Remove(childPid);
        }

        // Update ComboBox
        RefreshMonitoredProcessComboBox();
        UpdateMonitoredProcessCount();
    }

    private void ClearMonitoredProcesses()
    {
        _monitoredPids.Clear();
        _pidNames.Clear();
        _parentChildMap.Clear();
        _cmbMonitoredPids.Items.Clear();
        UpdateMonitoredProcessCount();
    }

    private void RefreshMonitoredProcessComboBox()
    {
        _cmbMonitoredPids.Items.Clear();
        foreach (var pid in _monitoredPids)
        {
            var name = _pidNames.GetValueOrDefault(pid, "Unknown");
            var item = new MonitoredProcessItem(pid, name);
            if (_parentChildMap.TryGetValue(pid, out var parentPid))
            {
                item.IsChild = true;
                item.ParentPid = parentPid;
            }
            _cmbMonitoredPids.Items.Add(item);
        }
        if (_cmbMonitoredPids.Items.Count > 0)
            _cmbMonitoredPids.SelectedIndex = 0;
    }

    private void UpdateMonitoredProcessCount()
    {
        var childCount = _parentChildMap.Count;
        var rootCount = _monitoredPids.Count - childCount;
        var countText = childCount > 0
            ? $"{rootCount} process(es) + {childCount} child(ren)"
            : $"{rootCount} process(es)";
        // Could display this in status or elsewhere
    }

    private void HandleChildProcessCreated(int parentPid, int childPid, string childName)
    {
        if (!_followChildProcesses) return;
        if (!_monitoredPids.Contains(parentPid)) return;
        if (_monitoredPids.Contains(childPid)) return;

        _monitoredPids.Add(childPid);
        _pidNames[childPid] = childName;
        _parentChildMap[childPid] = parentPid;

        if (InvokeRequired)
        {
            Invoke(() =>
            {
                var item = new MonitoredProcessItem(childPid, childName) { IsChild = true, ParentPid = parentPid };
                _cmbMonitoredPids.Items.Add(item);
                UpdateStatus($"Auto-following child process: {childName} (PID: {childPid})");
            });
        }
        else
        {
            var item = new MonitoredProcessItem(childPid, childName) { IsChild = true, ParentPid = parentPid };
            _cmbMonitoredPids.Items.Add(item);
            UpdateStatus($"Auto-following child process: {childName} (PID: {childPid})");
        }
    }

    private bool IsMonitoredProcess(int pid)
    {
        return _monitoredPids.Contains(pid);
    }

    private string GetProcessDisplayName(int pid)
    {
        return _pidNames.TryGetValue(pid, out var name) ? $"{name} ({pid})" : $"PID {pid}";
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
        AddMonitoredProcess(e.ProcessId, e.ProcessName);
        UpdateStatus($"Watchlist: Detected {e.ProcessName} (PID: {e.ProcessId})");
    }

    private void OnWatchlistProcessExited(object? sender, WatchlistProcessEventArgs e)
    {
        if (!IsHandleCreated || IsDisposed) return;
        if (InvokeRequired)
        {
            BeginInvoke(() => OnWatchlistProcessExited(sender, e));
            return;
        }
        RemoveMonitoredProcess(e.ProcessId);
        UpdateStatus($"Watchlist: {e.ProcessName} (PID: {e.ProcessId}) exited");
    }

    private void OnWatchlistDriverLoaded(object? sender, WatchlistDriverEventArgs e)
    {
        if (!IsHandleCreated || IsDisposed) return;
        if (InvokeRequired)
        {
            BeginInvoke(() => OnWatchlistDriverLoaded(sender, e));
            return;
        }

        _watchedDriverNames.Add(e.Entry.Name);

        // Include System (PID 4) to capture driver-related events
        if (!_monitoredPids.Contains(4))
            AddMonitoredProcess(4, "System");

        UpdateStatus($"Watchlist: Driver {e.Entry.Name} loaded at 0x{e.Entry.DriverBase:X}");
    }

    private void OnWatchlistDriverUnloaded(object? sender, WatchlistDriverEventArgs e)
    {
        if (!IsHandleCreated || IsDisposed) return;
        if (InvokeRequired)
        {
            BeginInvoke(() => OnWatchlistDriverUnloaded(sender, e));
            return;
        }

        _watchedDriverNames.Remove(e.Entry.Name);

        // Remove System PID if no more drivers are being watched
        if (_watchedDriverNames.Count == 0)
            RemoveMonitoredProcess(4);

        UpdateStatus($"Watchlist: Driver {e.Entry.Name} unloaded");
    }

    #endregion
    }
