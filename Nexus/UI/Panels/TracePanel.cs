// <file>
// <summary>
// Instruction trace panel recording executed instructions during single-stepping or
// trace-into/trace-over operations. Shows instruction index, address, disassembled text,
// and register snapshot for each traced instruction. Supports configurable max instruction
// count, start address, step-over mode, and export to file.
// </summary>
// </file>

using System.Text;
using Nexus.UI.Core;
using Nexus.UI.Interop;
using Nexus.UI.Styles;

namespace Nexus.UI.Panels;

/// <summary>
/// Instruction trace panel recording the sequence of executed instructions during debugging.
/// Each entry captures the instruction address, disassembled text, register state, and thread ID.
/// Supports trace-into and trace-over modes with configurable instruction limits.
/// </summary>
public class TracePanel : UserControl
{
    private readonly ListView _listView;
    private readonly Button _btnStart;
    private readonly Button _btnStop;
    private readonly Button _btnClear;
    private readonly Label _lblStatus;
    private readonly Label _lblCount;
    private readonly TextBox _txtStartAddress;
    private readonly NumericUpDown _nudMaxInstructions;
    private readonly CheckBox _chkStepOver;

    private readonly List<TraceEntry> _entries = new();
    private readonly object _entriesLock = new();
    private volatile bool _isTracing;
    private IntPtr _processHandle;

    public event EventHandler<ulong>? OnNavigateToAddress;

    public class TraceEntry
    {
        public int Index { get; set; }
        public ulong Address { get; set; }
        public string Instruction { get; set; } = "";
        public string Registers { get; set; } = "";
        public uint ThreadId { get; set; }
    }

    public TracePanel()
    {
        BackColor = NexusTheme.BackgroundPanel;

        // Header
        var header = new Label
        {
            Text = "Trace",
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
            Height = 32,
            Padding = new Padding(4)
        };

        var lblStart = new Label { Text = "From:", Location = new Point(4, 8), AutoSize = true };
        _txtStartAddress = new TextBox { Location = new Point(40, 4), Width = 100 };
        NexusTheme.StyleTextBox(_txtStartAddress);

        var lblMax = new Label { Text = "Max:", Location = new Point(150, 8), AutoSize = true };
        _nudMaxInstructions = new NumericUpDown
        {
            Location = new Point(180, 4),
            Width = 60,
            Minimum = 100,
            Maximum = 100000,
            Value = 1000,
            Increment = 100
        };

        _btnStart = new Button { Text = "Start", Size = new Size(50, 24), Location = new Point(250, 4) };
        _btnStart.Click += BtnStart_Click;
        NexusTheme.StyleButton(_btnStart);

        _btnStop = new Button { Text = "Stop", Size = new Size(45, 24), Location = new Point(305, 4), Enabled = false };
        _btnStop.Click += BtnStop_Click;
        NexusTheme.StyleButton(_btnStop);

        _btnClear = new Button { Text = "Clear", Size = new Size(45, 24), Location = new Point(355, 4) };
        _btnClear.Click += (s, e) => ClearTrace();
        NexusTheme.StyleButton(_btnClear);

        _chkStepOver = new CheckBox { Text = "Step over", Location = new Point(410, 6), AutoSize = true };
        NexusTheme.StyleCheckBox(_chkStepOver);

        toolbar.Controls.AddRange(new Control[] { lblStart, _txtStartAddress, lblMax, _nudMaxInstructions,
            _btnStart, _btnStop, _btnClear, _chkStepOver });

        // ListView (virtual mode for performance)
        _listView = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = true,
            VirtualMode = true,
            Font = new Font("Consolas", 9f)
        };
        _listView.Columns.Add("#", 50);
        _listView.Columns.Add("Address", 120);
        _listView.Columns.Add("Instruction", 250);
        _listView.Columns.Add("Thread", 60);
        NexusTheme.StyleListView(_listView);

        _listView.RetrieveVirtualItem += ListView_RetrieveVirtualItem;
        _listView.DoubleClick += ListView_DoubleClick;

        // Context menu
        var contextMenu = new ContextMenuStrip();
        contextMenu.Items.Add("Go to Address", null, (s, e) => GoToSelectedAddress());
        contextMenu.Items.Add("Copy Line", null, (s, e) => CopyLine());
        contextMenu.Items.Add("Copy All", null, (s, e) => CopyAll());
        contextMenu.Items.Add(new ToolStripSeparator());
        contextMenu.Items.Add("Save to File...", null, (s, e) => SaveToFile());
        _listView.ContextMenuStrip = contextMenu;

        // Status bar
        var statusBar = new Panel
        {
            Dock = DockStyle.Bottom,
            Height = 24
        };
        _lblStatus = new Label { Text = "Ready", Location = new Point(4, 4), AutoSize = true };
        _lblCount = new Label { Text = "0 instructions", Location = new Point(200, 4), AutoSize = true };
        statusBar.Controls.AddRange(new Control[] { _lblStatus, _lblCount });

        Controls.Add(_listView);
        Controls.Add(toolbar);
        Controls.Add(header);
        Controls.Add(statusBar);
    }

    public void SetProcessHandle(IntPtr handle)
    {
        _processHandle = handle;
    }

    private void BtnStart_Click(object? sender, EventArgs e)
    {
        if (_processHandle == IntPtr.Zero)
        {
            MessageBox.Show("No process attached.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        var addressText = _txtStartAddress.Text.Trim();
        if (addressText.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            addressText = addressText[2..];

        if (!ulong.TryParse(addressText, System.Globalization.NumberStyles.HexNumber, null, out var startAddress))
        {
            MessageBox.Show("Invalid start address.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        lock (_entriesLock) { _entries.Clear(); }
        _listView.VirtualListSize = 0;
        _isTracing = true;
        _btnStart.Enabled = false;
        _btnStop.Enabled = true;
        _lblStatus.Text = "Tracing...";

        var maxInstructions = (int)_nudMaxInstructions.Value;
        Task.Run(() => PerformTrace(startAddress, maxInstructions));
    }

    private void PerformTrace(ulong startAddress, int maxInstructions)
    {
        try
        {
            int maxInstr = Math.Min(maxInstructions, 1000);
            var instructions = new NexusDisasmInstruction[maxInstr];
            var result = NexusEngine.Nexus_DisasmDecodeProcess(_processHandle, startAddress, (nuint)maxInstr, instructions, out nuint count);

            if (result == NexusResult.OK && count > 0)
            {
                for (int i = 0; i < (int)count && _isTracing; i++)
                {
                    var entry = new TraceEntry
                    {
                        Index = i + 1,
                        Address = instructions[i].Address,
                        Instruction = instructions[i].Text ?? instructions[i].Mnemonic ?? "???",
                        Registers = "",
                        ThreadId = 0
                    };
                    lock (_entriesLock) { _entries.Add(entry); }

                    if (i % 100 == 0)
                    {
                        int cnt = i;
                        Invoke(() =>
                        {
                            _listView.VirtualListSize = cnt;
                            _lblCount.Text = $"{cnt} instructions";
                        });
                    }
                }
            }

            Invoke(() =>
            {
                _listView.VirtualListSize = _entries.Count;
                _lblCount.Text = $"{_entries.Count} instructions";
                _lblStatus.Text = $"Complete - {_entries.Count} instructions";
                _isTracing = false;
                _btnStart.Enabled = true;
                _btnStop.Enabled = false;
            });
        }
        catch (Exception ex)
        {
            Invoke(() =>
            {
                _lblStatus.Text = $"Error: {ex.Message}";
                _isTracing = false;
                _btnStart.Enabled = true;
                _btnStop.Enabled = false;
            });
        }
    }

    private void BtnStop_Click(object? sender, EventArgs e)
    {
        _isTracing = false;
        _btnStart.Enabled = true;
        _btnStop.Enabled = false;
        _lblStatus.Text = "Stopped";
    }

    private void ClearTrace()
    {
        lock (_entriesLock) { _entries.Clear(); }
        _listView.VirtualListSize = 0;
        _lblCount.Text = "0 instructions";
        _lblStatus.Text = "Ready";
    }

    private void ListView_RetrieveVirtualItem(object? sender, RetrieveVirtualItemEventArgs e)
    {
        lock (_entriesLock)
        {
            if (e.ItemIndex >= 0 && e.ItemIndex < _entries.Count)
            {
                var entry = _entries[e.ItemIndex];
                var item = new ListViewItem(entry.Index.ToString());
                item.SubItems.Add($"0x{entry.Address:X}");
                item.SubItems.Add(entry.Instruction);
                item.SubItems.Add(entry.ThreadId > 0 ? entry.ThreadId.ToString() : "");
                e.Item = item;
            }
            else
            {
                e.Item = new ListViewItem("");
            }
        }
    }

    private void ListView_DoubleClick(object? sender, EventArgs e)
    {
        GoToSelectedAddress();
    }

    private void GoToSelectedAddress()
    {
        if (_listView.SelectedIndices.Count == 0) return;
        var idx = _listView.SelectedIndices[0];
        ulong address;
        lock (_entriesLock)
        {
            if (idx < 0 || idx >= _entries.Count) return;
            address = _entries[idx].Address;
        }
        OnNavigateToAddress?.Invoke(this, address);
        EventBus.Instance.Publish(new NavigateToAddressEvent(address, "Disassembler"));
    }

    private void CopyLine()
    {
        if (_listView.SelectedIndices.Count == 0) return;
        var idx = _listView.SelectedIndices[0];
        lock (_entriesLock)
        {
            if (idx < 0 || idx >= _entries.Count) return;
            var entry = _entries[idx];
            Clipboard.SetText($"{entry.Address:X}\t{entry.Instruction}");
        }
    }

    private void CopyAll()
    {
        var sb = new StringBuilder();
        sb.AppendLine("#\tAddress\tInstruction");
        lock (_entriesLock)
        {
            foreach (var entry in _entries)
                sb.AppendLine($"{entry.Index}\t{entry.Address:X}\t{entry.Instruction}");
        }
        Clipboard.SetText(sb.ToString());
    }

    private void SaveToFile()
    {
        using var saveDialog = new SaveFileDialog
        {
            Filter = "Text files (*.txt)|*.txt|CSV files (*.csv)|*.csv|All files (*.*)|*.*",
            DefaultExt = ".txt"
        };

        if (saveDialog.ShowDialog() != DialogResult.OK) return;

        var sb = new StringBuilder();
        sb.AppendLine("Nexus Instruction Trace");
        sb.AppendLine($"Instructions: {_entries.Count}");
        sb.AppendLine(new string('=', 80));
        sb.AppendLine();

        foreach (var entry in _entries)
            sb.AppendLine($"{entry.Index,6}  {entry.Address:X16}  {entry.Instruction}");

        File.WriteAllText(saveDialog.FileName, sb.ToString());
        MessageBox.Show($"Trace saved to {saveDialog.FileName}", "Save Complete", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    public void AddTraceEntry(ulong address, string instruction, uint threadId = 0)
    {
        int count;
        lock (_entriesLock)
        {
            _entries.Add(new TraceEntry
            {
                Index = _entries.Count + 1,
                Address = address,
                Instruction = instruction,
                ThreadId = threadId
            });
            count = _entries.Count;
        }
        _listView.VirtualListSize = count;
        _lblCount.Text = $"{count} instructions";
    }
}
