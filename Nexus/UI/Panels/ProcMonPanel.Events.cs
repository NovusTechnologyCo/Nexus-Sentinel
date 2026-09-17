using System.Collections.Concurrent;
using Nexus.UI.Core;
using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using Nexus.UI.Services;
using Nexus.UI.Styles;

namespace Nexus.UI.Panels;
    public partial class ProcMonPanel
    {
    #region Event Handlers

    protected override void OnProcessAttached(object? sender, ProcessAttachedEventArgs e)
    {
        base.OnProcessAttached(sender, e);
        AddMonitoredProcess(e.ProcessId, e.ProcessName);

        // Auto-start capture if enabled
        if (_autoStartOnAttach && !_isCapturing)
        {
            StartCapture();
            UpdateStatus($"Attached to PID {e.ProcessId} - Auto-started capture");
        }
        else
        {
            UpdateStatus($"Attached to PID {e.ProcessId} - Ready to capture");
        }
    }

    protected override void OnProcessDetached(object? sender, ProcessDetachedEventArgs e)
    {
        base.OnProcessDetached(sender, e);

        // Don't stop capture if the watchlist still has active entries
        var watchlist = ProcessWatchlist.Instance;
        if (_isCapturing && watchlist.Entries.Any(entry => entry.IsActive))
        {
            // Only remove the detached process PID, keep capture running
            // Use PID from event args since Context.ProcessId is already cleared
            if (e.ProcessId > 0)
                RemoveMonitoredProcess(e.ProcessId);
            UpdateStatus("Process detached - watchlist monitoring continues");
            return;
        }

        StopCapture();
        ClearMonitoredProcesses();
        UpdateStatus("No process attached");
    }

    private void BtnAddProcess_Click(object? sender, EventArgs e)
    {
        // Show context menu: Add Process (direct) or Manage Watchlist
        using var menu = new ContextMenuStrip();
        menu.Items.Add("Add Process...", null, (s, ev) =>
        {
            using var dialog = new AddProcessDialog();
            if (dialog.ShowDialog(this) == DialogResult.OK && dialog.SelectedProcessId > 0)
            {
                AddMonitoredProcess(dialog.SelectedProcessId, dialog.SelectedProcessName);
            }
        });
        menu.Items.Add("Process Watchlist...", null, (s, ev) =>
        {
            using var form = new Forms.ProcessWatchlistForm();
            form.ShowDialog(this);
        });
        menu.Show(_btnAddProcess, new Point(0, _btnAddProcess.Height));
    }

    private void BtnRemoveProcess_Click(object? sender, EventArgs e)
    {
        if (_cmbMonitoredPids.SelectedItem is MonitoredProcessItem item)
        {
            RemoveMonitoredProcess(item.ProcessId);
        }
    }

    private void BtnStartStop_Click(object? sender, EventArgs e)
    {
        if (_isCapturing)
        {
            StopCapture();
        }
        else
        {
            StartCapture();
        }
    }

    private void BtnClear_Click(object? sender, EventArgs e)
    {
        lock (_eventsLock)
        {
            _events.Clear();
            while (_eventQueue.TryDequeue(out _)) { }
        }
        _eventList.VirtualListSize = 0;
        _detailText.Clear();
        UpdateStatus(_isCapturing ? "Capturing..." : "Ready");
    }

    private void BtnSave_Click(object? sender, EventArgs e)
    {
        using var dialog = new SaveFileDialog
        {
            Title = "Save Event Log",
            Filter = "JSON files (*.json)|*.json|CSV files (*.csv)|*.csv|Text files (*.txt)|*.txt|All files (*.*)|*.*",
            DefaultExt = "json",
            FileName = $"procmon_log_{DateTime.Now:yyyyMMdd_HHmmss}"
        };

        if (dialog.ShowDialog() != DialogResult.OK) return;

        var ext = Path.GetExtension(dialog.FileName).ToLowerInvariant();
        switch (ext)
        {
            case ".json":
                SaveEventsToJson(dialog.FileName);
                break;
            case ".csv":
                SaveEventsToCsv(dialog.FileName);
                break;
            default:
                SaveEventsToText(dialog.FileName);
                break;
        }
    }

    private void SaveEventsToJson(string? filePath = null)
    {
        if (filePath == null)
        {
            using var dialog = new SaveFileDialog
            {
                Title = "Save Event Log as JSON",
                Filter = "JSON files (*.json)|*.json",
                DefaultExt = "json",
                FileName = $"procmon_log_{DateTime.Now:yyyyMMdd_HHmmss}.json"
            };
            if (dialog.ShowDialog() != DialogResult.OK) return;
            filePath = dialog.FileName;
        }

        try
        {
            List<ProcMonEvent> eventsToSave;
            lock (_eventsLock)
            {
                eventsToSave = [.. _events];
            }

            var options = new System.Text.Json.JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase
            };

            var json = System.Text.Json.JsonSerializer.Serialize(new
            {
                ExportTime = DateTime.Now,
                EventCount = eventsToSave.Count,
                MonitoredProcesses = _pidNames.Select(kv => new { Pid = kv.Key, Name = kv.Value }),
                Events = eventsToSave.Select(e => new
                {
                    e.SequenceNumber,
                    Timestamp = e.Timestamp.ToString("o"),
                    e.ProcessId,
                    e.ThreadId,
                    e.ProcessName,
                    Category = e.Category.ToString(),
                    e.Operation,
                    e.Path,
                    e.Result,
                    DurationMs = e.Duration.TotalMilliseconds,
                    e.Details,
                    e.StackTrace
                })
            }, options);

            File.WriteAllText(filePath, json);
            UpdateStatus($"Saved {eventsToSave.Count} events to {Path.GetFileName(filePath)}");
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Failed to save: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void SaveEventsToCsv(string? filePath = null)
    {
        if (filePath == null)
        {
            using var dialog = new SaveFileDialog
            {
                Title = "Save Event Log as CSV",
                Filter = "CSV files (*.csv)|*.csv",
                DefaultExt = "csv",
                FileName = $"procmon_log_{DateTime.Now:yyyyMMdd_HHmmss}.csv"
            };
            if (dialog.ShowDialog() != DialogResult.OK) return;
            filePath = dialog.FileName;
        }

        try
        {
            List<ProcMonEvent> eventsToSave;
            lock (_eventsLock)
            {
                eventsToSave = [.. _events];
            }

            var sb = new System.Text.StringBuilder();
            sb.AppendLine("Seq,Timestamp,PID,TID,ProcessName,Category,Operation,Path,Result,DurationMs,Details");

            foreach (var evt in eventsToSave)
            {
                var details = evt.Details.Count > 0
                    ? string.Join("; ", evt.Details.Select(kv => $"{kv.Key}={kv.Value}"))
                    : "";

                sb.AppendLine($"{evt.SequenceNumber}," +
                    $"\"{evt.Timestamp:yyyy-MM-dd HH:mm:ss.fff}\"," +
                    $"{evt.ProcessId}," +
                    $"{evt.ThreadId}," +
                    $"\"{EscapeCsv(evt.ProcessName)}\"," +
                    $"{evt.Category}," +
                    $"\"{EscapeCsv(evt.Operation)}\"," +
                    $"\"{EscapeCsv(evt.Path)}\"," +
                    $"\"{EscapeCsv(evt.Result)}\"," +
                    $"{evt.Duration.TotalMilliseconds:F3}," +
                    $"\"{EscapeCsv(details)}\"");
            }

            File.WriteAllText(filePath, sb.ToString());
            UpdateStatus($"Saved {eventsToSave.Count} events to {Path.GetFileName(filePath)}");
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Failed to save: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void SaveEventsToText(string? filePath = null)
    {
        if (filePath == null)
        {
            using var dialog = new SaveFileDialog
            {
                Title = "Save Event Log as Text",
                Filter = "Text files (*.txt)|*.txt",
                DefaultExt = "txt",
                FileName = $"procmon_log_{DateTime.Now:yyyyMMdd_HHmmss}.txt"
            };
            if (dialog.ShowDialog() != DialogResult.OK) return;
            filePath = dialog.FileName;
        }

        try
        {
            List<ProcMonEvent> eventsToSave;
            lock (_eventsLock)
            {
                eventsToSave = [.. _events];
            }

            var sb = new System.Text.StringBuilder();
            sb.AppendLine($"Nexus Sentinel ProcMon Export");
            sb.AppendLine($"Export Time: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"Event Count: {eventsToSave.Count}");
            sb.AppendLine($"Monitored Processes: {string.Join(", ", _pidNames.Select(kv => $"{kv.Value} ({kv.Key})"))}");
            sb.AppendLine(new string('=', 80));
            sb.AppendLine();

            foreach (var evt in eventsToSave)
            {
                sb.AppendLine($"[{evt.SequenceNumber}] {evt.Timestamp:HH:mm:ss.fff} | {evt.ProcessName} | {evt.Category} | {evt.Operation}");
                sb.AppendLine($"    Path: {evt.Path}");
                sb.AppendLine($"    Result: {evt.Result} | Duration: {evt.Duration.TotalMilliseconds:F3}ms");
                if (evt.Details.Count > 0)
                {
                    foreach (var kv in evt.Details)
                    {
                        sb.AppendLine($"    {kv.Key}: {kv.Value}");
                    }
                }
                sb.AppendLine();
            }

            File.WriteAllText(filePath, sb.ToString());
            UpdateStatus($"Saved {eventsToSave.Count} events to {Path.GetFileName(filePath)}");
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Failed to save: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private static string EscapeCsv(string value)
    {
        if (string.IsNullOrEmpty(value)) return "";
        return value.Replace("\"", "\"\"");
    }

    private void FilterBox_TextChanged(object? sender, EventArgs e)
    {
        _filterText = _filterBox.Text;
        ApplyFilter();
    }

    private void UpdateTimer_Tick(object? sender, EventArgs e)
    {
        // Poll ETW events
        PollEtwEvents();

        // Poll kernel driver events (registry, handle, memory)
        if (_useKernelMonitoring)
        {
            PollKernelEvents();
        }

        ProcessEventQueue();
    }

    private void PollKernelEvents()
    {
        if (!_kernelDriver.IsLoaded) return;

        var buffer = _kernelDriver.GetPendingEvents();
        if (buffer == null || buffer.Length == 0) return;

        int offset = 0;
        var headerSize = System.Runtime.InteropServices.Marshal.SizeOf<Providers.KernelEventHeader>();

        while (offset + headerSize <= buffer.Length)
        {
            // Read header first
            var headerBytes = new byte[headerSize];
            Array.Copy(buffer, offset, headerBytes, 0, headerSize);

            var handle = System.Runtime.InteropServices.GCHandle.Alloc(headerBytes, System.Runtime.InteropServices.GCHandleType.Pinned);
            Providers.KernelEventHeader header;
            try
            {
                header = System.Runtime.InteropServices.Marshal.PtrToStructure<Providers.KernelEventHeader>(handle.AddrOfPinnedObject());
            }
            finally
            {
                handle.Free();
            }

            // Filter by monitored processes
            if (!IsMonitoredProcess((int)header.ProcessId))
            {
                offset += headerSize + (int)header.DataSize;
                continue;
            }

            // Parse based on event type
            ProcMonEvent? procEvent = null;

            switch (header.EventType)
            {
                case Providers.NexusEventType.RegistryOp:
                    procEvent = ParseKernelRegistryEvent(buffer, offset, header);
                    break;
                case Providers.NexusEventType.HandleOp:
                    procEvent = ParseKernelHandleEvent(buffer, offset, header);
                    break;
                case Providers.NexusEventType.MemoryOp:
                    procEvent = ParseKernelMemoryEvent(buffer, offset, header);
                    break;
            }

            if (procEvent != null)
            {
                AddEvent(procEvent);
            }

            // Move to next event
            offset += headerSize + (int)header.DataSize;
        }
    }

    private ProcMonEvent? ParseKernelRegistryEvent(byte[] buffer, int offset, Providers.KernelEventHeader header)
    {
        var regEvent = _kernelDriver.ParseRegistryEvent(buffer, offset);
        if (regEvent == null) return null;

        var evt = regEvent.Value;
        return new ProcMonEvent
        {
            Timestamp = DateTime.UtcNow,  // Could convert from kernel timestamp
            ProcessId = (int)header.ProcessId,
            ThreadId = (int)header.ThreadId,
            ProcessName = GetProcessDisplayName((int)header.ProcessId),
            Category = EventCategory.Registry,
            Operation = Providers.NexusKernelDriver.GetRegOpName(evt.Operation),
            Path = evt.KeyPath ?? "",
            Result = evt.Status == 0 ? "SUCCESS" : $"0x{evt.Status:X8}",
            Duration = TimeSpan.Zero,
            Details = new Dictionary<string, string>
            {
                ["ValueName"] = evt.ValueName ?? "",
                ["ValueType"] = GetValueTypeName(evt.ValueType),
                ["Source"] = "Kernel"
            }
        };
    }

    private ProcMonEvent? ParseKernelHandleEvent(byte[] buffer, int offset, Providers.KernelEventHeader header)
    {
        var handleEvent = _kernelDriver.ParseHandleEvent(buffer, offset);
        if (handleEvent == null) return null;

        var evt = handleEvent.Value;
        return new ProcMonEvent
        {
            Timestamp = DateTime.UtcNow,
            ProcessId = (int)header.ProcessId,
            ThreadId = (int)header.ThreadId,
            ProcessName = evt.SourceProcessName ?? GetProcessDisplayName((int)header.ProcessId),
            Category = EventCategory.Handle,
            Operation = Providers.NexusKernelDriver.GetHandleOpName(evt.Operation),
            Path = $"{evt.TargetProcessName ?? "?"} (PID: {evt.TargetProcessId})",
            Result = evt.Status == 0 ? "SUCCESS" : $"0x{evt.Status:X8}",
            Duration = TimeSpan.Zero,
            Details = new Dictionary<string, string>
            {
                ["TargetPID"] = evt.TargetProcessId.ToString(),
                ["TargetProcess"] = evt.TargetProcessName ?? "",
                ["DesiredAccess"] = $"0x{evt.DesiredAccess:X8}",
                ["GrantedAccess"] = $"0x{evt.GrantedAccess:X8}",
                ["Source"] = "Kernel"
            }
        };
    }

    private ProcMonEvent? ParseKernelMemoryEvent(byte[] buffer, int offset, Providers.KernelEventHeader header)
    {
        var memEvent = _kernelDriver.ParseMemoryEvent(buffer, offset);
        if (memEvent == null) return null;

        var evt = memEvent.Value;
        return new ProcMonEvent
        {
            Timestamp = DateTime.UtcNow,
            ProcessId = (int)header.ProcessId,
            ThreadId = (int)header.ThreadId,
            ProcessName = evt.SourceProcessName ?? GetProcessDisplayName((int)header.ProcessId),
            Category = EventCategory.Memory,
            Operation = Providers.NexusKernelDriver.GetMemOpName(evt.Operation),
            Path = $"{evt.TargetProcessName ?? "?"} @ 0x{evt.Address:X} ({evt.Size} bytes)",
            Result = evt.Status == 0 ? "SUCCESS" : $"0x{evt.Status:X8}",
            Duration = TimeSpan.Zero,
            Details = new Dictionary<string, string>
            {
                ["TargetPID"] = evt.TargetProcessId.ToString(),
                ["TargetProcess"] = evt.TargetProcessName ?? "",
                ["Address"] = $"0x{evt.Address:X}",
                ["Size"] = evt.Size.ToString(),
                ["DataPreview"] = evt.DataPreview != null ? BitConverter.ToString(evt.DataPreview, 0, Math.Min(16, evt.DataPreview.Length)) : "",
                ["Source"] = "Kernel"
            }
        };
    }

    private static string GetValueTypeName(uint valueType) => valueType switch
    {
        0 => "REG_NONE",
        1 => "REG_SZ",
        2 => "REG_EXPAND_SZ",
        3 => "REG_BINARY",
        4 => "REG_DWORD",
        5 => "REG_DWORD_BIG_ENDIAN",
        6 => "REG_LINK",
        7 => "REG_MULTI_SZ",
        11 => "REG_QWORD",
        _ => $"Type_{valueType}"
    };

    private void EventList_RetrieveVirtualItem(object? sender, RetrieveVirtualItemEventArgs e)
    {
        lock (_eventsLock)
        {
            if (e.ItemIndex >= 0 && e.ItemIndex < _events.Count)
            {
                var evt = _events[e.ItemIndex];
                e.Item = CreateListViewItem(evt, e.ItemIndex);
            }
            else
            {
                e.Item = new ListViewItem();
            }
        }
    }

    private void EventList_DrawColumnHeader(object? sender, DrawListViewColumnHeaderEventArgs e)
    {
        using var brush = new SolidBrush(NexusTheme.BackgroundHeader);
        e.Graphics.FillRectangle(brush, e.Bounds);

        using var textBrush = new SolidBrush(NexusTheme.TextPrimary);
        var flags = TextFormatFlags.Left | TextFormatFlags.VerticalCenter;
        TextRenderer.DrawText(e.Graphics, e.Header?.Text, _eventList.Font, e.Bounds, NexusTheme.TextPrimary, flags);
    }

    private void EventList_DrawSubItem(object? sender, DrawListViewSubItemEventArgs e)
    {
        if (e.Item == null) return;

        // Background
        var backColor = e.Item.Selected ? NexusTheme.Selection : NexusTheme.BackgroundControl;
        using (var brush = new SolidBrush(backColor))
        {
            e.Graphics.FillRectangle(brush, e.Bounds);
        }

        // Text color based on category
        var foreColor = NexusTheme.TextPrimary;
        if (e.Item.Tag is ProcMonEvent evt && e.ColumnIndex == 3) // Category column (index shifted due to Process column)
        {
            foreColor = _categoryColors.GetValueOrDefault(evt.Category, NexusTheme.TextPrimary);
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

        var index = _eventList.SelectedIndices[0];
        lock (_eventsLock)
        {
            if (index >= 0 && index < _events.Count)
            {
                var evt = _events[index];
                _detailText.Text = FormatEventDetails(evt);
            }
        }
    }

    #endregion
    }
