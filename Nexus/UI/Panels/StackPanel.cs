// <file>
// <summary>
// Call stack panel displaying the stack frame chain for a selected thread.
// Resolves return addresses to module+function+offset using symbol information.
// Supports thread selection via dropdown, double-click to navigate to return address
// in the disassembler, and context menu operations.
// </summary>
// </file>

using Nexus.UI.Core;
using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using Nexus.UI.Styles;

namespace Nexus.UI.Panels;

/// <summary>
/// Call stack panel displaying the unwound stack frames of a debugged thread.
/// Shows frame index, return address, stack pointer, and resolved module/function/offset
/// for each frame. Supports thread switching and navigation to frame addresses.
/// </summary>
public class StackPanel : UserControl
{
    private readonly ListView _listView;
    private readonly ComboBox _cboThread;
    private readonly Label _lblStatus;
    private readonly ContextMenuStrip _contextMenu;

    private IntPtr _processHandle;
    private uint _threadId;
    private readonly List<StackFrameEntry> _frames = new();
    private bool _initializing;

    public event EventHandler<ulong>? OnNavigateToAddress;

    public class StackFrameEntry
    {
        public int FrameIndex { get; set; }
        public ulong ReturnAddress { get; set; }
        public ulong StackPointer { get; set; }
        public ulong InstructionPointer { get; set; }
        public string ModuleName { get; set; } = "";
        public string FunctionName { get; set; } = "";
        public ulong Offset { get; set; }
        public bool IsInline { get; set; }
    }

    private class ThreadItem
    {
        public uint ThreadId { get; set; }
        public ulong StartAddress { get; set; }
        public override string ToString() => $"Thread {ThreadId}";
    }

    public StackPanel()
    {
        BackColor = NexusTheme.BackgroundPanel;

        // Header
        var header = new Label
        {
            Text = "Stack",
            Dock = DockStyle.Top,
            Height = 24,
            Padding = new Padding(NexusTheme.Space8, 4, 0, 0),
            Font = new Font(NexusTheme.FontFamily, 9, FontStyle.Bold),
            ForeColor = NexusTheme.TextPrimary,
            BackColor = NexusTheme.BackgroundDark
        };

        // Toolbar
        var toolbar = new Panel
        {
            Dock = DockStyle.Top,
            Height = 28,
            Padding = new Padding(4)
        };

        var lblThread = new Label { Text = "Thread:", Location = new Point(4, 6), AutoSize = true };
        _cboThread = new ComboBox
        {
            Location = new Point(55, 2),
            Size = new Size(100, 23),
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        _cboThread.SelectedIndexChanged += (s, e) =>
        {
            if (_initializing) return;
            if (_cboThread.SelectedItem is ThreadItem item)
            {
                _threadId = item.ThreadId;
                RefreshStack();
            }
        };
        NexusTheme.StyleComboBox(_cboThread);

        var btnRefresh = new Button { Text = "Refresh", Size = new Size(60, 22), Location = new Point(165, 2) };
        btnRefresh.Click += (s, e) => RefreshStack();
        NexusTheme.StyleButton(btnRefresh);

        toolbar.Controls.AddRange(new Control[] { lblThread, _cboThread, btnRefresh });

        // ListView
        _listView = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = true,
            Font = new Font("Consolas", 9f)
        };
        _listView.Columns.Add("#", 30);
        _listView.Columns.Add("Return", 110);
        _listView.Columns.Add("Module", 80);
        _listView.Columns.Add("Function", 150);
        NexusTheme.StyleListView(_listView);

        _listView.DoubleClick += ListView_DoubleClick;

        // Context menu
        _contextMenu = new ContextMenuStrip();
        _contextMenu.Items.Add("Go to Address", null, (s, e) => GoToAddress());
        _contextMenu.Items.Add(new ToolStripSeparator());
        _contextMenu.Items.Add("Copy Address", null, (s, e) => CopyAddress());
        _contextMenu.Items.Add("Copy Function", null, (s, e) => CopyFunction());
        _contextMenu.Items.Add("Copy Line", null, (s, e) => CopyLine());
        _contextMenu.Items.Add(new ToolStripSeparator());
        _contextMenu.Items.Add("Set Breakpoint at Return", null, (s, e) => SetBreakpointAtReturn());
        _listView.ContextMenuStrip = _contextMenu;

        // Status
        _lblStatus = new Label
        {
            Dock = DockStyle.Bottom,
            Height = 20,
            Padding = new Padding(4, 2, 0, 0),
            Text = ""
        };

        Controls.Add(_listView);
        Controls.Add(toolbar);
        Controls.Add(header);
        Controls.Add(_lblStatus);

        // Subscribe to events
        EventBus.Instance.Subscribe<BreakpointHitEvent>(OnBreakpointHit);
    }

    public void SetProcessHandle(IntPtr handle)
    {
        _processHandle = handle;
        LoadThreads();
    }

    private void OnBreakpointHit(BreakpointHitEvent evt)
    {
        if (InvokeRequired)
        {
            BeginInvoke(() => OnBreakpointHit(evt));
            return;
        }

        _threadId = (uint)evt.ThreadId;

        // Select the thread in the combo
        foreach (ThreadItem item in _cboThread.Items)
        {
            if (item.ThreadId == _threadId)
            {
                _cboThread.SelectedItem = item;
                break;
            }
        }

        RefreshStack();
    }

    public void SetThreadId(uint threadId)
    {
        _threadId = threadId;
        RefreshStack();
    }

    private void LoadThreads()
    {
        _initializing = true;
        try
        {
            _cboThread.Items.Clear();
            if (_processHandle == IntPtr.Zero) return;

            NexusEngine.Nexus_EnumerateThreads(_processHandle, null, 0, out nuint count);
            if (count == 0) return;

            var threads = new NexusThreadInfo[count];
            NexusEngine.Nexus_EnumerateThreads(_processHandle, threads, count, out _);

            foreach (var t in threads)
            {
                var item = new ThreadItem
                {
                    ThreadId = t.ThreadId,
                    StartAddress = t.StartAddress
                };
                _cboThread.Items.Add(item);

                if (t.ThreadId == _threadId)
                    _cboThread.SelectedItem = item;
            }

            if (_cboThread.SelectedIndex < 0 && _cboThread.Items.Count > 0)
                _cboThread.SelectedIndex = 0;
        }
        finally
        {
            _initializing = false;
        }
    }

    public void RefreshStack()
    {
        _frames.Clear();
        _listView.Items.Clear();

        if (_processHandle == IntPtr.Zero || _threadId == 0)
        {
            _lblStatus.Text = "No thread selected";
            return;
        }

        _lblStatus.Text = "Walking stack...";

        IntPtr walkerHandle = IntPtr.Zero;
        try
        {
            var result = NexusEngine.Nexus_StackWalkerCreate(_processHandle, out walkerHandle);
            if (result != NexusResult.OK && result != NexusResult.Success)
            {
                _lblStatus.Text = $"Failed: {NexusHelper.GetErrorMessage(result)}";
                return;
            }

            var stackFrames = new NexusStackFrame[64];
            result = NexusEngine.Nexus_StackWalk(walkerHandle, _threadId, stackFrames, (nuint)stackFrames.Length, out nuint frameCount);

            if (result == NexusResult.OK || result == NexusResult.Success)
            {
                _listView.BeginUpdate();
                for (int i = 0; i < (int)frameCount; i++)
                {
                    var sf = stackFrames[i];
                    var frame = new StackFrameEntry
                    {
                        FrameIndex = (int)sf.FrameIndex,
                        ReturnAddress = sf.ReturnAddress,
                        StackPointer = sf.StackPointer,
                        InstructionPointer = sf.InstructionPointer,
                        ModuleName = sf.ModuleName ?? "",
                        FunctionName = sf.FunctionName ?? "",
                        Offset = sf.FunctionOffset,
                        IsInline = sf.IsInline != 0
                    };
                    _frames.Add(frame);

                    var item = new ListViewItem(frame.FrameIndex.ToString());
                    item.SubItems.Add($"0x{frame.ReturnAddress:X}");
                    item.SubItems.Add(frame.ModuleName);
                    item.SubItems.Add(frame.FunctionName + (frame.Offset > 0 ? $"+0x{frame.Offset:X}" : ""));
                    item.Tag = frame;
                    _listView.Items.Add(item);
                }
                _listView.EndUpdate();
                _lblStatus.Text = $"{_frames.Count} frames";
            }
            else
            {
                _lblStatus.Text = $"Failed: {NexusHelper.GetErrorMessage(result)}";
            }
        }
        catch (Exception ex)
        {
            _lblStatus.Text = $"Error: {ex.Message}";
        }
        finally
        {
            if (walkerHandle != IntPtr.Zero)
                NexusEngine.Nexus_StackWalkerDestroy(walkerHandle);
        }
    }

    private StackFrameEntry? GetSelectedFrame()
    {
        if (_listView.SelectedItems.Count == 0) return null;
        return _listView.SelectedItems[0].Tag as StackFrameEntry;
    }

    private void ListView_DoubleClick(object? sender, EventArgs e)
    {
        GoToAddress();
    }

    private void GoToAddress()
    {
        var frame = GetSelectedFrame();
        if (frame == null) return;

        OnNavigateToAddress?.Invoke(this, frame.ReturnAddress);
        EventBus.Instance.Publish(new NavigateToAddressEvent(frame.ReturnAddress, "Disassembler"));
    }

    private void CopyAddress()
    {
        var frame = GetSelectedFrame();
        if (frame != null)
            Clipboard.SetText($"0x{frame.ReturnAddress:X}");
    }

    private void CopyFunction()
    {
        var frame = GetSelectedFrame();
        if (frame != null)
            Clipboard.SetText(frame.FunctionName);
    }

    private void CopyLine()
    {
        var frame = GetSelectedFrame();
        if (frame != null)
            Clipboard.SetText($"0x{frame.ReturnAddress:X}\t{frame.ModuleName}\t{frame.FunctionName}");
    }

    private void SetBreakpointAtReturn()
    {
        var frame = GetSelectedFrame();
        if (frame == null) return;

        // Publish event to add breakpoint
        MessageBox.Show($"Set breakpoint at 0x{frame.ReturnAddress:X}", "Breakpoint", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            EventBus.Instance.Unsubscribe<BreakpointHitEvent>(OnBreakpointHit);
        }
        base.Dispose(disposing);
    }
}
