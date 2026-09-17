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
    #region Timer / UI Update

    private readonly ConcurrentQueue<string> _statusQueue = new();

    private void EnqueueStatus(string msg)
    {
        _statusQueue.Enqueue(msg);
    }

    private void UpdateTimer_Tick(object? sender, EventArgs e)
    {
        // Drain status messages
        while (_statusQueue.TryDequeue(out var msg))
        {
            _statusLabel.Text = msg;
        }

        // Drain pending events into main list
        int added = 0;
        lock (_eventsLock)
        {
            while (_pendingQueue.TryDequeue(out var evt))
            {
                evt.SequenceNumber = _events.Count + 1;
                _events.Add(evt);
                added++;

                // Trim if over max
                if (_events.Count > _maxEvents)
                {
                    int removeCount = _events.Count - _maxEvents;
                    _events.RemoveRange(0, removeCount);
                    _filterDirty = true;
                }
            }

            if (added > 0)
                _filterDirty = true;
        }

        if (_filterDirty)
        {
            RebuildFilteredView();
            _filterDirty = false;
        }
    }

    private void RebuildFilteredView()
    {
        lock (_eventsLock)
        {
            _filteredIndices.Clear();
            bool hasTextFilter = !string.IsNullOrEmpty(_filterText);
            bool hasPidFilter = _filterPid > 0;
            bool hasWatchlistFilter = _watchlistOnly;

            for (int i = 0; i < _events.Count; i++)
            {
                var evt = _events[i];
                if (!PassesTypeFilter(evt.Type)) continue;
                if (hasPidFilter && evt.ProcessId != _filterPid) continue;
                if (hasWatchlistFilter && !_watchlistPids.Contains(evt.ProcessId)) continue;
                if (hasTextFilter && !PassesTextFilter(evt)) continue;
                _filteredIndices.Add(i);
            }

            _eventList.VirtualListSize = _filteredIndices.Count;

            if (_autoScroll && _filteredIndices.Count > 0)
            {
                _eventList.EnsureVisible(_filteredIndices.Count - 1);
            }
        }
    }

    private bool PassesTypeFilter(KernelMonEventType type) => type switch
    {
        KernelMonEventType.Registry => _showRegistry,
        KernelMonEventType.Process => _showProcess,
        KernelMonEventType.Handle => _showHandle,
        KernelMonEventType.ImageLoad => _showImageLoad,
        KernelMonEventType.Memory => _showMemory,
        KernelMonEventType.File => _showFile,
        KernelMonEventType.Syscall => _showSyscall,
        _ => true
    };

    private bool PassesTextFilter(KernelMonEvent evt)
    {
        return evt.Operation.Contains(_filterText, StringComparison.OrdinalIgnoreCase)
            || evt.Path.Contains(_filterText, StringComparison.OrdinalIgnoreCase)
            || evt.Result.Contains(_filterText, StringComparison.OrdinalIgnoreCase)
            || evt.ProcessName.Contains(_filterText, StringComparison.OrdinalIgnoreCase);
    }

    #endregion
    #region ListView Drawing

    private void EventList_RetrieveVirtualItem(object? sender, RetrieveVirtualItemEventArgs e)
    {
        lock (_eventsLock)
        {
            if (e.ItemIndex >= 0 && e.ItemIndex < _filteredIndices.Count)
            {
                int realIndex = _filteredIndices[e.ItemIndex];
                if (realIndex < _events.Count)
                {
                    e.Item = CreateListViewItem(_events[realIndex]);
                    return;
                }
            }
            e.Item = new ListViewItem();
        }
    }

    private static ListViewItem CreateListViewItem(KernelMonEvent evt)
    {
        var item = new ListViewItem(evt.SequenceNumber.ToString());
        item.SubItems.Add(evt.Timestamp.ToString("HH:mm:ss.fff"));
        item.SubItems.Add(evt.ProcessId.ToString());
        item.SubItems.Add(evt.ProcessName);
        item.SubItems.Add(evt.Type.ToString());
        item.SubItems.Add(evt.Operation);
        item.SubItems.Add(evt.Path);
        item.SubItems.Add(evt.Result);
        item.Tag = evt;
        return item;
    }

    private void EventList_DrawColumnHeader(object? sender, DrawListViewColumnHeaderEventArgs e)
    {
        using var brush = new SolidBrush(NexusTheme.BackgroundHeader);
        e.Graphics.FillRectangle(brush, e.Bounds);

        var flags = TextFormatFlags.Left | TextFormatFlags.VerticalCenter;
        TextRenderer.DrawText(e.Graphics, e.Header?.Text, _eventList.Font, e.Bounds, NexusTheme.TextPrimary, flags);
    }

    private void EventList_DrawSubItem(object? sender, DrawListViewSubItemEventArgs e)
    {
        if (e.Item == null) return;

        bool isWatched = e.Item.Tag is KernelMonEvent evt2 && _watchlistPids.Contains(evt2.ProcessId);

        // Background: highlight watched PIDs with a subtle tint
        var backColor = e.Item.Selected
            ? NexusTheme.Selection
            : isWatched
                ? Color.FromArgb(35, 45, 35) // subtle green tint for watchlist hits
                : NexusTheme.BackgroundControl;
        using (var brush = new SolidBrush(backColor))
        {
            e.Graphics.FillRectangle(brush, e.Bounds);
        }

        // Color the Type column (index 4) by event type
        var foreColor = NexusTheme.TextPrimary;
        if (e.Item.Tag is KernelMonEvent evt && e.ColumnIndex == 4)
        {
            foreColor = EventColors.GetValueOrDefault(evt.Type, NexusTheme.TextPrimary);
        }

        var flags = TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis;
        TextRenderer.DrawText(e.Graphics, e.SubItem?.Text, _eventList.Font, e.Bounds, foreColor, flags);
    }

    private void EventList_SelectedIndexChanged(object? sender, EventArgs e)
    {
        if (_eventList.SelectedIndices.Count == 0)
        {
            _detailText.Clear();
            return;
        }

        var viewIndex = _eventList.SelectedIndices[0];
        lock (_eventsLock)
        {
            if (viewIndex >= 0 && viewIndex < _filteredIndices.Count)
            {
                int realIndex = _filteredIndices[viewIndex];
                if (realIndex < _events.Count)
                    _detailText.Text = _events[realIndex].Details;
            }
        }
    }

    #endregion
    #region Helpers

    private static string FindDriverPath()
    {
        string baseDir = AppDomain.CurrentDomain.BaseDirectory;
        string[] candidates =
        [
            Path.Combine(baseDir, "NexusKernel.sys"),
            Path.Combine(baseDir, "..", "Kernel", "bin", "Release", "NexusKernel.sys"),
            Path.Combine(baseDir, "..", "Kernel", "bin", "Debug", "NexusKernel.sys"),
            Path.Combine(baseDir, "..", "..", "..", "..", "Kernel", "bin", "Release", "NexusKernel.sys"),
            Path.Combine(baseDir, "..", "..", "..", "..", "Kernel", "bin", "Debug", "NexusKernel.sys"),
        ];

        foreach (string path in candidates)
        {
            string full = Path.GetFullPath(path);
            if (File.Exists(full))
                return full;
        }
        return "";
    }

    private uint BuildEventMask()
    {
        uint mask = 0;
        if (_showRegistry) mask |= (1u << (int)NexusEventType.RegistryOp);
        if (_showProcess) mask |= (1u << (int)NexusEventType.ProcessCreate) | (1u << (int)NexusEventType.ProcessExit);
        if (_showHandle) mask |= (1u << (int)NexusEventType.HandleOp);
        if (_showImageLoad) mask |= (1u << (int)NexusEventType.ImageLoad);
        if (_showMemory) mask |= (1u << (int)NexusEventType.MemoryOp);
        if (_showFile) mask |= (1u << (int)NexusEventType.FileOp);
        if (_showSyscall) mask |= (1u << (int)NexusEventType.Syscall);
        return mask;
    }

    private string ResolveProcessName(uint pid)
    {
        if (pid == 0) return "System Idle";
        if (pid == 4) return "System";

        return _processNames.GetOrAdd(pid, id =>
        {
            try
            {
                using var proc = Process.GetProcessById((int)id);
                return proc.ProcessName;
            }
            catch
            {
                return $"<{id}>";
            }
        });
    }

    private void BeginInvokeIfNeeded(Action action)
    {
        if (!IsHandleCreated || IsDisposed) return;
        if (InvokeRequired) BeginInvoke(action); else action();
    }

    private static string RegOpName(uint op) => op switch
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

    private static string HandleOpName(uint op) => op switch
    {
        NexusHandleOp.OpenProcess => "OpenProcess",
        NexusHandleOp.OpenThread => "OpenThread",
        NexusHandleOp.Duplicate => "DuplicateHandle",
        _ => $"HandleOp_{op}"
    };

    private static string MemOpName(uint op) => op switch
    {
        NexusMemOp.Read => "ReadMemory",
        NexusMemOp.Write => "WriteMemory",
        NexusMemOp.Alloc => "AllocMemory",
        NexusMemOp.Free => "FreeMemory",
        NexusMemOp.Protect => "ProtectMemory",
        _ => $"MemOp_{op}"
    };

    private static string FileOpName(uint op) => op switch
    {
        1 => "CreateFile", 2 => "ReadFile", 3 => "WriteFile",
        4 => "DeleteFile", 5 => "RenameFile", 6 => "QueryFile",
        _ => $"FileOp_{op}"
    };

    private static string SyscallTypeName(uint type) => type switch
    {
        NexusSyscallType.QuerySystemInfo => "NtQuerySystemInfo",
        NexusSyscallType.SetSystemInfo => "NtSetSystemInfo",
        NexusSyscallType.GetFirmwareEnv => "NtQueryFirmwareEnv",
        NexusSyscallType.QueryLicense => "NtQueryLicenseValue",
        _ => $"Syscall_{type}"
    };

    private static string FormatRegistryDetails(KernelRegistryEvent evt)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Operation: {RegOpName(evt.Operation)}");
        sb.AppendLine($"Key: {evt.KeyPath}");
        if (!string.IsNullOrEmpty(evt.ValueName))
            sb.AppendLine($"Value: {evt.ValueName}");
        sb.AppendLine($"Status: 0x{evt.Status:X8}");
        if (evt.ValueType != 0)
            sb.AppendLine($"Type: {RegTypeName(evt.ValueType)}");
        if (evt.DataSize > 0 && evt.ValueData != null)
        {
            sb.AppendLine($"Data Size: {evt.DataSize} bytes");
            int showBytes = Math.Min((int)evt.DataSize, 64);
            sb.Append("Data: ");
            for (int i = 0; i < showBytes; i++)
                sb.Append($"{evt.ValueData[i]:X2} ");
            sb.AppendLine();

            if (evt.ValueType is 1 or 2) // REG_SZ or REG_EXPAND_SZ
            {
                try
                {
                    int strLen = Math.Min((int)evt.DataSize, 256);
                    string val = Encoding.Unicode.GetString(evt.ValueData, 0, strLen).TrimEnd('\0');
                    if (!string.IsNullOrEmpty(val))
                        sb.AppendLine($"String: {val}");
                }
                catch { }
            }
        }
        return sb.ToString();
    }

    private static string FormatHandleDetails(KernelHandleEvent evt)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Operation: {HandleOpName(evt.Operation)}");
        sb.AppendLine($"Source: {evt.SourceProcessName} (PID {evt.Header.ProcessId})");
        sb.AppendLine($"Target: {evt.TargetProcessName} (PID {evt.TargetProcessId})");
        sb.AppendLine($"Desired Access: 0x{evt.DesiredAccess:X8}");
        sb.AppendLine($"Granted Access: 0x{evt.GrantedAccess:X8}");
        sb.AppendLine($"Status: 0x{evt.Status:X8}");

        if (evt.Operation == NexusHandleOp.OpenProcess)
        {
            var rights = new List<string>();
            if ((evt.DesiredAccess & 0x0010) != 0) rights.Add("VM_READ");
            if ((evt.DesiredAccess & 0x0020) != 0) rights.Add("VM_WRITE");
            if ((evt.DesiredAccess & 0x0008) != 0) rights.Add("VM_OPERATION");
            if ((evt.DesiredAccess & 0x0400) != 0) rights.Add("QUERY_INFORMATION");
            if ((evt.DesiredAccess & 0x1000) != 0) rights.Add("QUERY_LIMITED_INFORMATION");
            if ((evt.DesiredAccess & 0x0001) != 0) rights.Add("TERMINATE");
            if ((evt.DesiredAccess & 0x0002) != 0) rights.Add("CREATE_THREAD");
            if ((evt.DesiredAccess & 0x001F0FFF) == 0x001F0FFF) { rights.Clear(); rights.Add("ALL_ACCESS"); }
            if (rights.Count > 0)
                sb.AppendLine($"Access Rights: {string.Join(" | ", rights)}");
        }

        return sb.ToString();
    }

    private static string RegTypeName(uint type) => type switch
    {
        0 => "REG_NONE", 1 => "REG_SZ", 2 => "REG_EXPAND_SZ",
        3 => "REG_BINARY", 4 => "REG_DWORD", 7 => "REG_MULTI_SZ",
        11 => "REG_QWORD", _ => $"Type_{type}"
    };

    #endregion
}
