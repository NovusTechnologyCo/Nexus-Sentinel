// <file>
// <summary>
// Call stack viewer form displaying thread call stack with resolved symbols.
// </summary>
// </file>
using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using Nexus.UI.Styles;


namespace Nexus.UI.Forms;

/// <summary>
/// Form for viewing the call stack of a thread.
/// Matches CE's stack trace functionality.
/// </summary>
public class StackViewForm : Form
{
    // Controls
    private ListView _lvStack = null!;
    private ContextMenuStrip _contextMenu = null!;
    private Panel _pnlTop = null!;
    private Label _lblThread = null!;
    private ComboBox _cboThread = null!;
    private Button _btnRefresh = null!;
    private Panel _pnlBottom = null!;
    private Button _btnClose = null!;
    private Label _lblStatus = null!;
    private CheckBox _chkShowSymbols = null!;
    private CheckBox _chkShowModules = null!;

    // State
    private IntPtr _processHandle;
    private uint _threadId;
    private List<StackFrameEntry> _frames = new();

    // Events
    public event EventHandler<ulong>? OnNavigateToAddress;

    public StackViewForm(IntPtr processHandle, uint threadId = 0)
    {
        _processHandle = processHandle;
        _threadId = threadId;
        InitializeComponent();
        NexusTheme.StyleForm(this);
        SetupEventHandlers();
        LoadThreads();
        if (_threadId != 0)
            RefreshStack();
    }

    private void InitializeComponent()
    {
        Text = "Stack View";
        Size = new Size(900, 500);
        StartPosition = FormStartPosition.CenterParent;

        // Top panel
        _pnlTop = new Panel
        {
            Dock = DockStyle.Top,
            Height = 45
        };

        _lblThread = new Label
        {
            Text = "Thread:",
            Location = new Point(NexusTheme.Space16, 15),
            AutoSize = true
        };

        _cboThread = new ComboBox
        {
            Location = new Point(NexusTheme.Space16 + 64, 12),
            Size = new Size(150, 23),
            DropDownStyle = ComboBoxStyle.DropDownList
        };

        _btnRefresh = new Button
        {
            Text = "Refresh",
            Location = new Point(NexusTheme.Space16 + 64 + 160, 8),
            Size = new Size(NexusTheme.ButtonWidth, NexusTheme.ButtonHeight)
        };

        _chkShowSymbols = new CheckBox
        {
            Text = "Show symbols",
            Location = new Point(345, 14),
            AutoSize = true,
            Checked = true
        };

        _chkShowModules = new CheckBox
        {
            Text = "Show modules",
            Location = new Point(505, 14),
            AutoSize = true,
            Checked = true
        };

        _pnlTop.Controls.Add(_lblThread);
        _pnlTop.Controls.Add(_cboThread);
        _pnlTop.Controls.Add(_btnRefresh);
        _pnlTop.Controls.Add(_chkShowSymbols);
        _pnlTop.Controls.Add(_chkShowModules);

        // ListView
        _lvStack = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = true
        };

        _lvStack.Columns.Add("#", -2);
        _lvStack.Columns.Add("Return Address", -2);
        _lvStack.Columns.Add("Stack Address", -2);
        _lvStack.Columns.Add("Module", -2);
        _lvStack.Columns.Add("Function", -2);
        _lvStack.Columns.Add("Offset", -2);
        _lvStack.Columns.Add("Parameters", -2);

        // Context menu
        _contextMenu = new ContextMenuStrip();
        _contextMenu.Items.Add("Go to address in disassembler", null, (s, e) => GoToAddress());
        _contextMenu.Items.Add("-");
        _contextMenu.Items.Add("Copy address", null, (s, e) => CopyAddress());
        _contextMenu.Items.Add("Copy function name", null, (s, e) => CopyFunction());
        _contextMenu.Items.Add("Copy full line", null, (s, e) => CopyLine());
        _contextMenu.Items.Add("-");
        _contextMenu.Items.Add("Set breakpoint at return", null, (s, e) => SetBreakpoint());
        _lvStack.ContextMenuStrip = _contextMenu;

        // Bottom panel
        _pnlBottom = new Panel
        {
            Dock = DockStyle.Bottom,
            Height = 45
        };

        _lblStatus = new Label
        {
            Text = "",
            Location = new Point(NexusTheme.Space16, 15),
            AutoSize = true
        };

        _btnClose = new Button
        {
            Text = "Close",
            Location = new Point(900 - NexusTheme.Space16 - NexusTheme.ButtonWidth - 15, 8),
            Size = new Size(NexusTheme.ButtonWidth, NexusTheme.ButtonHeight),
            DialogResult = DialogResult.Cancel
        };
        _btnClose.Click += (s, e) => Close();

        _pnlBottom.Controls.Add(_lblStatus);
        _pnlBottom.Controls.Add(_btnClose);

        Controls.Add(_lvStack);
        Controls.Add(_pnlTop);
        Controls.Add(_pnlBottom);
        CancelButton = _btnClose;
    }

    private void SetupEventHandlers()
    {
        _cboThread.SelectedIndexChanged += (s, e) =>
        {
            if (_cboThread.SelectedItem is ThreadItem item)
            {
                _threadId = item.ThreadId;
                RefreshStack();
            }
        };
        _btnRefresh.Click += (s, e) => RefreshStack();
        _chkShowSymbols.CheckedChanged += (s, e) => UpdateDisplay();
        _chkShowModules.CheckedChanged += (s, e) => UpdateDisplay();
        _lvStack.DoubleClick += (s, e) => GoToAddress();
    }

    private void LoadThreads()
    {
        _cboThread.Items.Clear();

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

    private void RefreshStack()
    {
        _frames.Clear();

        if (_threadId == 0)
        {
            _lblStatus.Text = "No thread selected";
            UpdateDisplay();
            return;
        }

        _lblStatus.Text = "Stack walking...";
        Application.DoEvents();

        // Create stack walker
        var result = NexusEngine.Nexus_StackWalkerCreate(_processHandle, out IntPtr walkerHandle);
        if (result != NexusResult.OK && result != NexusResult.Success)
        {
            _lblStatus.Text = $"Failed to create stack walker: {NexusHelper.GetErrorMessage(result)}";
            UpdateDisplay();
            return;
        }

        try
        {
            // Walk the stack
            var stackFrames = new NexusStackFrame[64]; // Max 64 frames
            result = NexusEngine.Nexus_StackWalk(walkerHandle, _threadId, stackFrames, (nuint)stackFrames.Length, out nuint frameCount);

            if (result == NexusResult.OK || result == NexusResult.Success)
            {
                for (int i = 0; i < (int)frameCount; i++)
                {
                    var sf = stackFrames[i];
                    _frames.Add(new StackFrameEntry
                    {
                        FrameIndex = (int)sf.FrameIndex,
                        ReturnAddress = sf.ReturnAddress,
                        StackPointer = sf.StackPointer,
                        InstructionPointer = sf.InstructionPointer,
                        ModuleName = sf.ModuleName ?? "",
                        FunctionName = sf.FunctionName ?? "",
                        Offset = sf.FunctionOffset,
                        IsInline = sf.IsInline != 0
                    });
                }
                _lblStatus.Text = $"{_frames.Count} frames";
            }
            else
            {
                _lblStatus.Text = $"Stack walk failed: {NexusHelper.GetErrorMessage(result)}";
            }
        }
        finally
        {
            NexusEngine.Nexus_StackWalkerDestroy(walkerHandle);
        }

        UpdateDisplay();
    }

    private void UpdateDisplay()
    {
        _lvStack.BeginUpdate();
        _lvStack.Items.Clear();

        foreach (var frame in _frames)
        {
            var item = new ListViewItem(frame.FrameIndex.ToString());
            item.SubItems.Add($"0x{frame.ReturnAddress:X}");
            item.SubItems.Add($"0x{frame.StackPointer:X}");
            item.SubItems.Add(_chkShowModules.Checked ? frame.ModuleName : "");
            item.SubItems.Add(_chkShowSymbols.Checked ? frame.FunctionName : "");
            item.SubItems.Add(frame.Offset > 0 ? $"+0x{frame.Offset:X}" : "");
            item.SubItems.Add(""); // Parameters placeholder
            item.Tag = frame;
            _lvStack.Items.Add(item);
        }

        _lvStack.EndUpdate();
    }

    private StackFrameEntry? GetSelectedFrame()
    {
        if (_lvStack.SelectedItems.Count == 0) return null;
        return _lvStack.SelectedItems[0].Tag as StackFrameEntry;
    }

    private void GoToAddress()
    {
        var frame = GetSelectedFrame();
        if (frame != null)
            OnNavigateToAddress?.Invoke(this, frame.ReturnAddress);
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
            Clipboard.SetText($"{frame.ModuleName}!{frame.FunctionName}+0x{frame.Offset:X}");
    }

    private void CopyLine()
    {
        if (_lvStack.SelectedItems.Count == 0) return;
        var item = _lvStack.SelectedItems[0];
        var text = string.Join("\t", Enumerable.Range(0, item.SubItems.Count)
            .Select(i => item.SubItems[i].Text));
        Clipboard.SetText(text);
    }

    private void SetBreakpoint()
    {
        var frame = GetSelectedFrame();
        if (frame == null) return;
        MessageBox.Show($"Set breakpoint at 0x{frame.ReturnAddress:X}", "Info");
    }

    private class ThreadItem
    {
        public uint ThreadId { get; set; }
        public ulong StartAddress { get; set; }

        public override string ToString() => $"Thread {ThreadId} (0x{StartAddress:X})";
    }
}

/// <summary>
/// Holds information about a stack frame.
/// </summary>
public class StackFrameEntry
{
    public int FrameIndex { get; set; }
    public ulong ReturnAddress { get; set; }
    public ulong StackPointer { get; set; }
    public ulong InstructionPointer { get; set; }
    public string ModuleName { get; set; } = "";
    public string FunctionName { get; set; } = "";
    public uint Offset { get; set; }
    public bool IsInline { get; set; }
}

/// <summary>
/// Form for viewing raw stack memory.
/// </summary>
public class StackMemoryForm : Form
{
    private RichTextBox _txtStack = null!;
    private Panel _pnlTop = null!;
    private TextBox _txtStackPointer = null!;
    private NumericUpDown _nudSize = null!;
    private Button _btnRefresh = null!;
    private Button _btnClose = null!;

    private IntPtr _processHandle;
    private ulong _stackPointer;

    public StackMemoryForm(IntPtr processHandle, ulong stackPointer)
    {
        _processHandle = processHandle;
        _stackPointer = stackPointer;
        InitializeComponent();
        NexusTheme.StyleForm(this);
        RefreshStack();
    }

    private void InitializeComponent()
    {
        Text = "Stack Memory";
        Size = new Size(700, 500);
        StartPosition = FormStartPosition.CenterParent;

        _pnlTop = new Panel { Dock = DockStyle.Top, Height = 45 };

        var lblSp = new Label { Text = "RSP:", Location = new Point(10, 15), AutoSize = true };
        _txtStackPointer = new TextBox
        {
            Location = new Point(50, 12),
            Size = new Size(150, 23),
            Text = $"0x{_stackPointer:X}"
        };

        var lblSize = new Label { Text = "Size:", Location = new Point(220, 15), AutoSize = true };
        _nudSize = new NumericUpDown
        {
            Location = new Point(260, 12),
            Size = new Size(80, 23),
            Minimum = 64,
            Maximum = 8192,
            Value = 512,
            Increment = 64
        };

        _btnRefresh = new Button
        {
            Text = "Refresh",
            Location = new Point(360, 11),
            Width = 80
        };
        _btnRefresh.Click += (s, e) => RefreshStack();

        _pnlTop.Controls.Add(lblSp);
        _pnlTop.Controls.Add(_txtStackPointer);
        _pnlTop.Controls.Add(lblSize);
        _pnlTop.Controls.Add(_nudSize);
        _pnlTop.Controls.Add(_btnRefresh);

        _txtStack = new RichTextBox
        {
            Dock = DockStyle.Fill,
            Font = new Font("Consolas", 10),
            ReadOnly = true,
            WordWrap = false
        };

        _btnClose = new Button
        {
            Text = "Close",
            Dock = DockStyle.Bottom,
            Height = 30,
            DialogResult = DialogResult.Cancel
        };

        Controls.Add(_txtStack);
        Controls.Add(_pnlTop);
        Controls.Add(_btnClose);
        CancelButton = _btnClose;
    }

    private void RefreshStack()
    {
        if (!ulong.TryParse(_txtStackPointer.Text.Replace("0x", ""),
            System.Globalization.NumberStyles.HexNumber, null, out _stackPointer))
        {
            MessageBox.Show("Invalid stack pointer", "Error");
            return;
        }

        var size = (int)_nudSize.Value;
        var buffer = new byte[size];

        var result = NexusEngine.Nexus_ReadProcessMemory(
            _processHandle, _stackPointer, buffer, (nuint)size, out var bytesRead);

        if (result != NexusResult.Success && result != NexusResult.OK)
        {
            _txtStack.Text = $"Failed to read stack: {result}";
            return;
        }

        var sb = new System.Text.StringBuilder();
        sb.AppendLine("Address          | Value            | ASCII");
        sb.AppendLine(new string('-', 60));

        for (int i = 0; i < (int)bytesRead; i += 8)
        {
            var addr = _stackPointer + (ulong)i;
            ulong value = 0;
            for (int j = 0; j < 8 && i + j < (int)bytesRead; j++)
                value |= (ulong)buffer[i + j] << (j * 8);

            var ascii = "";
            for (int j = 0; j < 8 && i + j < (int)bytesRead; j++)
            {
                var b = buffer[i + j];
                ascii += (b >= 32 && b < 127) ? (char)b : '.';
            }

            sb.AppendLine($"0x{addr:X16} | 0x{value:X16} | {ascii}");
        }

        _txtStack.Text = sb.ToString();
    }
}
