// <file>
// <summary>
// Value history dialog tracking memory value changes over time.
// </summary>
// </file>
using Nexus.UI.Core;
using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using Nexus.UI.Styles;


namespace Nexus.UI.Forms;

/// <summary>
/// Form for tracking and displaying value changes at an address.
/// Shows a history of values with timestamps.
/// </summary>
public partial class ValueHistoryForm : Form
{
    private ListView _lvHistory = null!;
    private TextBox _txtAddress = null!;
    private ComboBox _cbValueType = null!;
    private NumericUpDown _nudInterval = null!;
    private Button _btnStart = null!;
    private Button _btnStop = null!;
    private Button _btnClear = null!;
    private Button _btnExport = null!;
    private CheckBox _cbRecordChangesOnly = null!;
    private Label _lblStatus = null!;
    private Button _btnClose = null!;
    private System.Windows.Forms.Timer _timer = null!;

    private ulong _address;
    private readonly List<(DateTime Time, string Value)> _history = [];

#pragma warning disable CS0414 // Field is assigned but never used (reserved for timer control)
    private bool _isRecording;
#pragma warning restore CS0414

    public ValueHistoryForm()
    {
        InitializeComponent();
        NexusTheme.StyleForm(this);
    }

    public ValueHistoryForm(ulong address) : this()
    {
        _address = address;
        _txtAddress.Text = address.ToString("X");
    }

    private void InitializeComponent()
    {
        Text = "Value History";
        Size = new Size(600, 460);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        StartPosition = FormStartPosition.CenterParent;
        MaximizeBox = false;
        MinimizeBox = false;

        // Configuration
        var lblAddress = new Label
        {
            Text = "Address:",
            Location = new Point(15, 18),
            AutoSize = true
        };
        Controls.Add(lblAddress);

        _txtAddress = new TextBox
        {
            Location = new Point(95, 15),
            Width = 120,
            Font = new Font("Consolas", 9F)
        };
        Controls.Add(_txtAddress);

        var lblType = new Label
        {
            Text = "Type:",
            Location = new Point(225, 18),
            AutoSize = true
        };
        Controls.Add(lblType);

        _cbValueType = new ComboBox
        {
            Location = new Point(280, 15),
            Size = new Size(90, 23),
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        _cbValueType.Items.AddRange(["Byte", "2 Bytes", "4 Bytes", "8 Bytes", "Float", "Double"]);
        _cbValueType.SelectedIndex = 2;
        Controls.Add(_cbValueType);

        var lblInterval = new Label
        {
            Text = "Interval (ms):",
            Location = new Point(380, 18),
            AutoSize = true
        };
        Controls.Add(lblInterval);

        _nudInterval = new NumericUpDown
        {
            Location = new Point(500, 15),
            Width = 70,
            Minimum = 10,
            Maximum = 10000,
            Value = 100
        };
        Controls.Add(_nudInterval);

        // Buttons
        _btnStart = new Button
        {
            Text = "Start",
            Location = new Point(15, 50),
            Size = new Size(70, 32)
        };
        _btnStart.Click += BtnStart_Click;
        Controls.Add(_btnStart);

        _btnStop = new Button
        {
            Text = "Stop",
            Location = new Point(95, 50),
            Size = new Size(70, 32),
            Enabled = false
        };
        _btnStop.Click += BtnStop_Click;
        Controls.Add(_btnStop);

        _cbRecordChangesOnly = new CheckBox
        {
            Text = "Record changes only",
            Location = new Point(180, 55),
            AutoSize = true,
            Checked = true
        };
        Controls.Add(_cbRecordChangesOnly);

        // History list
        _lvHistory = new ListView
        {
            Location = new Point(15, 90),
            Size = new Size(555, 265),
            View = View.Details,
            FullRowSelect = true,
            GridLines = true
        };
        _lvHistory.Columns.Add("#", -2);
        _lvHistory.Columns.Add("Time", -2);
        _lvHistory.Columns.Add("Value (Dec)", -2);
        _lvHistory.Columns.Add("Value (Hex)", -2);
        _lvHistory.Columns.Add("Delta", -2);
        Controls.Add(_lvHistory);

        // Bottom controls
        _btnClear = new Button
        {
            Text = "Clear",
            Location = new Point(15, 365),
            Size = new Size(70, 32)
        };
        _btnClear.Click += BtnClear_Click;
        Controls.Add(_btnClear);

        _btnExport = new Button
        {
            Text = "Export...",
            Location = new Point(95, 365),
            Size = new Size(80, 32)
        };
        _btnExport.Click += BtnExport_Click;
        Controls.Add(_btnExport);

        _lblStatus = new Label
        {
            Text = "Ready",
            Location = new Point(190, 372),
            AutoSize = true
        };
        Controls.Add(_lblStatus);

        _btnClose = new Button
        {
            Text = "Close",
            Location = new Point(500, 365),
            Size = new Size(70, 32),
            DialogResult = DialogResult.Cancel
        };
        _btnClose.Click += (s, e) => Close();
        Controls.Add(_btnClose);

        // Timer
        _timer = new System.Windows.Forms.Timer
        {
            Interval = 100
        };
        _timer.Tick += Timer_Tick;

        CancelButton = _btnClose;
    }

    private string? _lastValue;

    private void BtnStart_Click(object? sender, EventArgs e)
    {
        if (!TryParseAddress(_txtAddress.Text, out _address))
        {
            MessageBox.Show("Invalid address", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        _timer.Interval = (int)_nudInterval.Value;
        _timer.Start();
        _isRecording = true;
        _btnStart.Enabled = false;
        _btnStop.Enabled = true;
        _lblStatus.Text = "Recording...";
    }

    private void BtnStop_Click(object? sender, EventArgs e)
    {
        _timer.Stop();
        _isRecording = false;
        _btnStart.Enabled = true;
        _btnStop.Enabled = false;
        _lblStatus.Text = $"Stopped - {_history.Count} entries";
    }

    private void Timer_Tick(object? sender, EventArgs e)
    {
        if (!ProcessContext.Current.IsAttached)
        {
            _lblStatus.Text = "No process attached";
            return;
        }

        var value = ReadMemoryValue();
        if (value == null)
        {
            _lblStatus.Text = "Failed to read memory";
            return;
        }

        if (!_cbRecordChangesOnly.Checked || value != _lastValue)
        {
            AddEntry(value);
            _lastValue = value;
        }
    }

    private string? ReadMemoryValue()
    {
        var size = _cbValueType.SelectedIndex switch
        {
            0 => 1,  // Byte
            1 => 2,  // 2 Bytes
            2 => 4,  // 4 Bytes
            3 => 8,  // 8 Bytes
            4 => 4,  // Float
            5 => 8,  // Double
            _ => 4
        };

        var buffer = new byte[size];
        var result = NexusEngine.Nexus_ReadProcessMemory(
            ProcessContext.Current.NativeProcessHandle,
            _address,
            buffer,
            (nuint)size,
            out var bytesRead);

        if (result != NexusResult.OK || bytesRead == 0)
            return null;

        return _cbValueType.SelectedIndex switch
        {
            0 => buffer[0].ToString(),
            1 => BitConverter.ToInt16(buffer, 0).ToString(),
            2 => BitConverter.ToInt32(buffer, 0).ToString(),
            3 => BitConverter.ToInt64(buffer, 0).ToString(),
            4 => BitConverter.ToSingle(buffer, 0).ToString("G"),
            5 => BitConverter.ToDouble(buffer, 0).ToString("G"),
            _ => BitConverter.ToInt32(buffer, 0).ToString()
        };
    }

    private void AddEntry(string value)
    {
        var time = DateTime.Now;
        _history.Add((time, value));

        var lvi = new ListViewItem(_history.Count.ToString());
        lvi.SubItems.Add(time.ToString("HH:mm:ss.fff"));
        lvi.SubItems.Add(value);

        if (long.TryParse(value, out var numValue))
        {
            lvi.SubItems.Add($"0x{numValue:X}");

            // Calculate delta from previous
            if (_history.Count > 1 && long.TryParse(_history[^2].Value, out var prevValue))
            {
                var delta = numValue - prevValue;
                lvi.SubItems.Add(delta >= 0 ? $"+{delta}" : delta.ToString());

                if (delta > 0)
                    lvi.ForeColor = Color.Green;
                else if (delta < 0)
                    lvi.ForeColor = Color.Red;
            }
            else
            {
                lvi.SubItems.Add("-");
            }
        }
        else
        {
            lvi.SubItems.Add("-");
            lvi.SubItems.Add("-");
        }

        _lvHistory.Items.Add(lvi);
        _lvHistory.EnsureVisible(_lvHistory.Items.Count - 1);
        _lblStatus.Text = $"Recording... ({_history.Count} entries)";
    }

    private void BtnClear_Click(object? sender, EventArgs e)
    {
        _history.Clear();
        _lvHistory.Items.Clear();
        _lastValue = null;
        _lblStatus.Text = "Cleared";
    }

    private void BtnExport_Click(object? sender, EventArgs e)
    {
        using var sfd = new SaveFileDialog
        {
            Filter = "CSV files (*.csv)|*.csv|Text files (*.txt)|*.txt",
            DefaultExt = "csv"
        };

        if (sfd.ShowDialog() == DialogResult.OK)
        {
            try
            {
                using var writer = new StreamWriter(sfd.FileName);
                writer.WriteLine("Index,Time,Value");
                for (int i = 0; i < _history.Count; i++)
                {
                    var (time, value) = _history[i];
                    writer.WriteLine($"{i + 1},{time:HH:mm:ss.fff},{value}");
                }
                MessageBox.Show("History exported", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Export failed: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        _timer.Stop();
        _timer.Dispose();
        base.OnFormClosing(e);
    }

    private static bool TryParseAddress(string text, out ulong address)
    {
        text = text.Trim();
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            text = text[2..];
        return ulong.TryParse(text, System.Globalization.NumberStyles.HexNumber, null, out address);
    }
}
