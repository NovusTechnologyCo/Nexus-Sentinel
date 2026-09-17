// <file>
// <summary>
// Partial class for ApiMonPanel handling the capture list view: virtual ListView
// population from the event queue, owner-draw rendering with color coding, timer-based
// polling, and multi-process event merging.
// </summary>
// </file>

using Nexus.UI.Models;
using Nexus.UI.Styles;

namespace Nexus.UI.Panels;

public partial class ApiMonPanel
{
    /// <summary>
    /// Timer tick: polls the event queue and updates the ListView.
    /// </summary>
    private void UpdateTimer_Tick(object? sender, EventArgs e)
    {
        ProcessEventQueue();
    }

    /// <summary>
    /// Drains the concurrent queue and adds events to the display list.
    /// </summary>
    private void ProcessEventQueue()
    {
        var newEvents = new List<ApiCallEvent>();

        while (_eventQueue.TryDequeue(out var evt))
        {
            newEvents.Add(evt);
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

            _captureList.VirtualListSize = _events.Count;

            if (_autoScroll && _events.Count > 0)
            {
                _captureList.EnsureVisible(_events.Count - 1);
            }
        }

        _eventCountLabel.Text = $"Events: {_events.Count:N0}" +
            (_selectedApis.Count > 0 ? $" | Selected: {_selectedApis.Count}" : "");
    }

    /// <summary>
    /// Virtual mode: provides ListViewItems on demand.
    /// </summary>
    private void CaptureList_RetrieveVirtualItem(object? sender, RetrieveVirtualItemEventArgs e)
    {
        lock (_eventsLock)
        {
            if (e.ItemIndex >= 0 && e.ItemIndex < _events.Count)
            {
                var evt = _events[e.ItemIndex];
                e.Item = CreateCaptureListItem(evt);
            }
            else
            {
                e.Item = new ListViewItem();
            }
        }
    }

    private static ListViewItem CreateCaptureListItem(ApiCallEvent evt)
    {
        var item = new ListViewItem(evt.SequenceNumber.ToString());
        item.SubItems.Add(evt.Timestamp.ToString("HH:mm:ss.fff"));
        item.SubItems.Add(evt.ProcessDisplayName);  // Process column
        item.SubItems.Add(evt.ThreadId.ToString());
        item.SubItems.Add(evt.Module);
        item.SubItems.Add(evt.Function);
        item.SubItems.Add(evt.ParameterSummary);
        item.SubItems.Add(evt.ReturnValue);
        item.SubItems.Add(evt.Duration.TotalMilliseconds < 1
            ? $"{evt.Duration.TotalMicroseconds:F0}us"
            : $"{evt.Duration.TotalMilliseconds:F1}ms");
        item.Tag = evt;
        return item;
    }

    /// <summary>
    /// Owner-draw: column headers with dark theme.
    /// </summary>
    private void CaptureList_DrawColumnHeader(object? sender, DrawListViewColumnHeaderEventArgs e)
    {
        using var brush = new SolidBrush(NexusTheme.BackgroundHeader);
        e.Graphics.FillRectangle(brush, e.Bounds);

        var flags = TextFormatFlags.Left | TextFormatFlags.VerticalCenter;
        TextRenderer.DrawText(e.Graphics, e.Header?.Text, _captureList.Font, e.Bounds, NexusTheme.TextPrimary, flags);
    }

    /// <summary>
    /// Owner-draw: sub-items with per-module color coding.
    /// Column indices: 0=#, 1=Time, 2=Process, 3=TID, 4=Module, 5=Function, 6=Params, 7=Return, 8=Duration
    /// </summary>
    private void CaptureList_DrawSubItem(object? sender, DrawListViewSubItemEventArgs e)
    {
        if (e.Item == null) return;

        // Background
        var backColor = e.Item.Selected ? NexusTheme.Selection : NexusTheme.BackgroundControl;
        using (var brush = new SolidBrush(backColor))
        {
            e.Graphics.FillRectangle(brush, e.Bounds);
        }

        // Text color
        var foreColor = NexusTheme.TextPrimary;
        if (e.Item.Tag is ApiCallEvent evt)
        {
            if (e.ColumnIndex == 2) // Process column
            {
                foreColor = NexusTheme.AccentSecondary;
            }
            else if (e.ColumnIndex == 4 || e.ColumnIndex == 5) // Module or Function column
            {
                foreColor = GetModuleColor(evt.Module);
            }
            else if (e.ColumnIndex == 7) // Return column
            {
                foreColor = evt.Success ? NexusTheme.Success : NexusTheme.Error;
            }
        }

        var flags = TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis;
        TextRenderer.DrawText(e.Graphics, e.SubItem?.Text, _captureList.Font, e.Bounds, foreColor, flags);
    }

    /// <summary>
    /// When an event is selected, update the detail panel.
    /// </summary>
    private void CaptureList_SelectedIndexChanged(object? sender, EventArgs e)
    {
        if (_captureList.SelectedIndices.Count == 0)
        {
            ClearDetailPanel();
            return;
        }

        int selectedIndex = _captureList.SelectedIndices[0];
        ApiCallEvent? selectedEvent;

        lock (_eventsLock)
        {
            if (selectedIndex < 0 || selectedIndex >= _events.Count)
                return;
            selectedEvent = _events[selectedIndex];
        }

        ShowEventDetails(selectedEvent);
    }
}
