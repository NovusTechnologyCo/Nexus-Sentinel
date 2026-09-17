// <file>
// <summary>
// Speedhack control dialog for manipulating target process time scale.
// </summary>
// </file>
using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using Nexus.UI.Styles;


namespace Nexus.UI.Forms;

/// <summary>
/// Form for controlling speedhack (game speed manipulation).
/// </summary>
public class SpeedhackForm : Form
{
    // Controls
    private GroupBox _grpSpeed = null!;
    private TrackBar _trkSpeed = null!;
    private NumericUpDown _nudSpeed = null!;
    private Label _lblSpeedValue = null!;
    private Button _btnEnable = null!;
    private Button _btnDisable = null!;
    private Button _btnApply = null!;
    private CheckBox _chkHotkey = null!;
#pragma warning disable CS0414 // Assigned for hotkey label
    private Label _lblHotkey = null!;
#pragma warning restore CS0414
    private TextBox _txtHotkey = null!;
    private GroupBox _grpPresets = null!;
    private Button _btn025x = null!;
    private Button _btn05x = null!;
    private Button _btn1x = null!;
    private Button _btn2x = null!;
    private Button _btn5x = null!;
    private Button _btn10x = null!;
    private GroupBox _grpStatus = null!;
    private Label _lblStatus = null!;
    private Label _lblCurrentSpeed = null!;
    private Button _btnClose = null!;

    // State
    private readonly IntPtr _processHandle;
    private IntPtr _speedhackHandle;
    private bool _isEnabled;
    private double _currentSpeed = 1.0;

    public SpeedhackForm(IntPtr processHandle)
    {
        _processHandle = processHandle;
        InitializeComponent();
        NexusTheme.StyleForm(this);
        UpdateStatus();
    }

    private void InitializeComponent()
    {
        Text = "Speedhack";
        Size = new Size(400, 400);
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;

        const int margin = NexusTheme.Space16;
        const int contentWidth = 400 - margin * 2 - 15;  // Account for form border

        // Speed control group
        _grpSpeed = new GroupBox
        {
            Text = "Speed Control",
            Location = new Point(margin, margin),
            Size = new Size(contentWidth, 100)
        };

        var lblSpeed = new Label
        {
            Text = "Speed:",
            Location = new Point(15, 25),
            AutoSize = true
        };

        _trkSpeed = new TrackBar
        {
            Location = new Point(60, 20),
            Size = new Size(200, 45),
            Minimum = 1,
            Maximum = 200,
            Value = 100,
            TickFrequency = 25,
            LargeChange = 25,
            SmallChange = 5
        };
        _trkSpeed.ValueChanged += TrkSpeed_ValueChanged;

        _nudSpeed = new NumericUpDown
        {
            Location = new Point(270, 25),
            Size = new Size(80, 23),
            Minimum = 0.01m,
            Maximum = 100.00m,
            Value = 1.00m,
            DecimalPlaces = 2,
            Increment = 0.1m
        };
        _nudSpeed.ValueChanged += NudSpeed_ValueChanged;

        _lblSpeedValue = new Label
        {
            Text = "1.00x",
            Location = new Point(15, 72),
            Size = new Size(100, 25),
            Font = new Font(Font.FontFamily, 12, FontStyle.Bold)
        };

        _btnApply = new Button
        {
            Text = "Apply",
            Location = new Point(270, 60),
            Size = new Size(80, 32)
        };
        _btnApply.Click += BtnApply_Click;

        _grpSpeed.Controls.Add(lblSpeed);
        _grpSpeed.Controls.Add(_trkSpeed);
        _grpSpeed.Controls.Add(_nudSpeed);
        _grpSpeed.Controls.Add(_btnApply);
        _grpSpeed.Controls.Add(_lblSpeedValue);
        _lblSpeedValue.BringToFront();

        // Preset buttons group
        _grpPresets = new GroupBox
        {
            Text = "Presets",
            Location = new Point(margin, 120),
            Size = new Size(contentWidth, 60)
        };

        _btn025x = CreatePresetButton("0.25x", 15, 0.25f);
        _btn05x = CreatePresetButton("0.5x", 70, 0.5f);
        _btn1x = CreatePresetButton("1x", 125, 1.0f);
        _btn2x = CreatePresetButton("2x", 180, 2.0f);
        _btn5x = CreatePresetButton("5x", 235, 5.0f);
        _btn10x = CreatePresetButton("10x", 290, 10.0f);

        _grpPresets.Controls.Add(_btn025x);
        _grpPresets.Controls.Add(_btn05x);
        _grpPresets.Controls.Add(_btn1x);
        _grpPresets.Controls.Add(_btn2x);
        _grpPresets.Controls.Add(_btn5x);
        _grpPresets.Controls.Add(_btn10x);

        // Status group
        _grpStatus = new GroupBox
        {
            Text = "Status",
            Location = new Point(margin, 190),
            Size = new Size(contentWidth, 70)
        };

        _lblStatus = new Label
        {
            Text = "Status: Disabled",
            Location = new Point(15, 25),
            AutoSize = true
        };

        _lblCurrentSpeed = new Label
        {
            Text = "Current Speed: 1.00x (Normal)",
            Location = new Point(15, 45),
            AutoSize = true
        };

        _grpStatus.Controls.Add(_lblStatus);
        _grpStatus.Controls.Add(_lblCurrentSpeed);

        // Enable/Disable buttons
        _btnEnable = new Button
        {
            Text = "Enable",
            Location = new Point(margin, 270),
            Size = new Size(100, NexusTheme.ButtonHeight)
        };
        _btnEnable.Click += BtnEnable_Click;

        _btnDisable = new Button
        {
            Text = "Disable",
            Location = new Point(margin + 100 + NexusTheme.ButtonGap, 270),
            Size = new Size(100, NexusTheme.ButtonHeight),
            Enabled = false
        };
        _btnDisable.Click += BtnDisable_Click;

        // Hotkey
        _chkHotkey = new CheckBox
        {
            Text = "Hotkey:",
            Location = new Point(margin, 310),
            AutoSize = true
        };

        _txtHotkey = new TextBox
        {
            Location = new Point(margin + 105, 308),
            Size = new Size(100, 23),
            Text = "None",
            ReadOnly = true
        };
        _txtHotkey.KeyDown += TxtHotkey_KeyDown;

        // Close button
        _btnClose = new Button
        {
            Text = "Close",
            Location = new Point(margin + contentWidth - 95, 305),
            Size = new Size(95, NexusTheme.ButtonHeight),
            DialogResult = DialogResult.Cancel
        };
        _btnClose.Click += (s, e) => Close();

        Controls.Add(_grpSpeed);
        Controls.Add(_grpPresets);
        Controls.Add(_grpStatus);
        Controls.Add(_btnEnable);
        Controls.Add(_btnDisable);
        Controls.Add(_chkHotkey);
        Controls.Add(_txtHotkey);
        Controls.Add(_btnClose);
        CancelButton = _btnClose;
    }

    private Button CreatePresetButton(string text, int x, float speed)
    {
        var btn = new Button
        {
            Text = text,
            Location = new Point(x, 20),
            Size = new Size(50, 32)
        };
        btn.Click += (s, e) => SetSpeed(speed);
        return btn;
    }

    private void TrkSpeed_ValueChanged(object? sender, EventArgs e)
    {
        // Convert trackbar value (1-200) to speed (0.01-10.0)
        float speed;
        if (_trkSpeed.Value <= 100)
        {
            // 1-100 maps to 0.01-1.0
            speed = _trkSpeed.Value / 100.0f;
        }
        else
        {
            // 101-200 maps to 1.0-10.0
            speed = 1.0f + ((_trkSpeed.Value - 100) / 100.0f * 9.0f);
        }

        _nudSpeed.Value = (decimal)speed;
        _lblSpeedValue.Text = $"{speed:F2}x";
    }

    private void NudSpeed_ValueChanged(object? sender, EventArgs e)
    {
        float speed = (float)_nudSpeed.Value;

        // Update trackbar
        int trackValue;
        if (speed <= 1.0f)
        {
            trackValue = (int)(speed * 100);
        }
        else
        {
            trackValue = 100 + (int)((speed - 1.0f) / 9.0f * 100);
        }
        trackValue = Math.Clamp(trackValue, 1, 200);

        _trkSpeed.ValueChanged -= TrkSpeed_ValueChanged;
        _trkSpeed.Value = trackValue;
        _trkSpeed.ValueChanged += TrkSpeed_ValueChanged;

        _lblSpeedValue.Text = $"{speed:F2}x";
    }

    private void SetSpeed(double speed)
    {
        _nudSpeed.Value = (decimal)speed;
        if (_isEnabled)
        {
            ApplySpeedhack(speed);
        }
    }

    private void BtnApply_Click(object? sender, EventArgs e)
    {
        if (_isEnabled)
        {
            ApplySpeedhack((float)_nudSpeed.Value);
        }
        else
        {
            MessageBox.Show("Enable speedhack first before applying speed changes.",
                "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
    }

    private void BtnEnable_Click(object? sender, EventArgs e)
    {
        if (_processHandle == IntPtr.Zero)
        {
            MessageBox.Show("No process attached.", "Error",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        // Create speedhack handle if not already created
        if (_speedhackHandle == IntPtr.Zero)
        {
            var createResult = NexusEngine.Nexus_SpeedhackCreate(_processHandle, 0, out _speedhackHandle);
            if (createResult != NexusResult.OK && createResult != NexusResult.Success)
            {
                MessageBox.Show($"Failed to initialize speedhack: {NexusHelper.GetErrorMessage(createResult)}",
                    "Speedhack Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
        }

        double speed = (double)_nudSpeed.Value;

        // Set speed
        var speedResult = NexusEngine.Nexus_SpeedhackSetSpeed(_speedhackHandle, speed);
        if (speedResult != NexusResult.OK && speedResult != NexusResult.Success)
        {
            MessageBox.Show($"Failed to set speed: {NexusHelper.GetErrorMessage(speedResult)}",
                "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        // Enable
        var enableResult = NexusEngine.Nexus_SpeedhackSetEnabled(_speedhackHandle, 1);
        if (enableResult == NexusResult.OK || enableResult == NexusResult.Success)
        {
            _isEnabled = true;
            _currentSpeed = speed;
            _btnEnable.Enabled = false;
            _btnDisable.Enabled = true;
            UpdateStatus();
        }
        else
        {
            MessageBox.Show($"Failed to enable speedhack: {NexusHelper.GetErrorMessage(enableResult)}",
                "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void BtnDisable_Click(object? sender, EventArgs e)
    {
        if (_speedhackHandle == IntPtr.Zero)
        {
            _isEnabled = false;
            _btnEnable.Enabled = true;
            _btnDisable.Enabled = false;
            UpdateStatus();
            return;
        }

        var result = NexusEngine.Nexus_SpeedhackSetEnabled(_speedhackHandle, 0);

        if (result == NexusResult.OK || result == NexusResult.Success)
        {
            _isEnabled = false;
            _currentSpeed = 1.0;
            _btnEnable.Enabled = true;
            _btnDisable.Enabled = false;
            UpdateStatus();
        }
        else
        {
            MessageBox.Show($"Failed to disable speedhack: {NexusHelper.GetErrorMessage(result)}",
                "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void ApplySpeedhack(double speed)
    {
        if (_speedhackHandle == IntPtr.Zero)
        {
            MessageBox.Show("Speedhack not initialized. Enable it first.",
                "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        var result = NexusEngine.Nexus_SpeedhackSetSpeed(_speedhackHandle, speed);

        if (result == NexusResult.OK || result == NexusResult.Success)
        {
            _currentSpeed = speed;
            UpdateStatus();
        }
        else
        {
            MessageBox.Show($"Failed to apply speed: {NexusHelper.GetErrorMessage(result)}",
                "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void UpdateStatus()
    {
        _lblStatus.Text = _isEnabled ? "Status: Enabled" : "Status: Disabled";
        _lblStatus.ForeColor = _isEnabled ? Color.Green : Color.Red;

        string speedDesc = _currentSpeed switch
        {
            < 0.5 => "Very Slow",
            < 1.0 => "Slow",
            1.0 => "Normal",
            < 2.0 => "Fast",
            < 5.0 => "Very Fast",
            _ => "Ultra Fast"
        };
        _lblCurrentSpeed.Text = $"Current Speed: {_currentSpeed:F2}x ({speedDesc})";
    }

    private void TxtHotkey_KeyDown(object? sender, KeyEventArgs e)
    {
        e.Handled = true;
        e.SuppressKeyPress = true;

        if (e.KeyCode == Keys.Escape)
        {
            _txtHotkey.Text = "None";
            _chkHotkey.Checked = false;
            return;
        }

        var parts = new List<string>();
        if (e.Control) parts.Add("Ctrl");
        if (e.Alt) parts.Add("Alt");
        if (e.Shift) parts.Add("Shift");

        if (e.KeyCode != Keys.ControlKey && e.KeyCode != Keys.Menu && e.KeyCode != Keys.ShiftKey)
        {
            parts.Add(e.KeyCode.ToString());
        }

        if (parts.Count > 0)
        {
            _txtHotkey.Text = string.Join("+", parts);
        }
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        // Destroy speedhack handle when closing
        if (_speedhackHandle != IntPtr.Zero)
        {
            NexusEngine.Nexus_SpeedhackDestroy(_speedhackHandle);
            _speedhackHandle = IntPtr.Zero;
        }
        base.OnFormClosing(e);
    }
}

/// <summary>
/// Form for controlling game freeze/pause.
/// </summary>
public class FreezeForm : Form
{
    private Button _btnPause = null!;
    private Button _btnResume = null!;
    private Label _lblStatus = null!;
    private ListView _lvThreads = null!;
    private CheckBox _chkSelectAll = null!;
    private Button _btnRefresh = null!;
    private Button _btnClose = null!;

    private readonly IntPtr _processHandle;
    private bool _isPaused;
    private readonly List<uint> _selectedThreads = [];

    public FreezeForm(IntPtr processHandle)
    {
        _processHandle = processHandle;
        InitializeComponent();
        NexusTheme.StyleForm(this);
        RefreshThreads();
    }

    private void InitializeComponent()
    {
        Text = "Process Freeze";
        Size = new Size(450, 400);
        StartPosition = FormStartPosition.CenterParent;

        var pnlTop = new Panel
        {
            Dock = DockStyle.Top,
            Height = 80
        };

        _lblStatus = new Label
        {
            Text = "Status: Running",
            Location = new Point(10, 10),
            AutoSize = true,
            Font = new Font(Font.FontFamily, 10, FontStyle.Bold),
            ForeColor = Color.Green
        };

        _btnPause = new Button
        {
            Text = "Pause",
            Location = new Point(10, 40),
            Size = new Size(80, 32)
        };
        _btnPause.Click += BtnPause_Click;

        _btnResume = new Button
        {
            Text = "Resume",
            Location = new Point(100, 40),
            Size = new Size(90, 32),
            Enabled = false
        };
        _btnResume.Click += BtnResume_Click;

        _btnRefresh = new Button
        {
            Text = "Refresh",
            Location = new Point(330, 40),
            Size = new Size(80, 30)
        };
        _btnRefresh.Click += (s, e) => RefreshThreads();

        pnlTop.Controls.Add(_lblStatus);
        pnlTop.Controls.Add(_btnPause);
        pnlTop.Controls.Add(_btnResume);
        pnlTop.Controls.Add(_btnRefresh);

        // Thread list
        _lvThreads = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            CheckBoxes = true,
            GridLines = true
        };
        _lvThreads.Columns.Add("Thread ID", -2);
        _lvThreads.Columns.Add("State", -2);
        _lvThreads.Columns.Add("Priority", -2);
        _lvThreads.Columns.Add("Start Address", -2);

        _chkSelectAll = new CheckBox
        {
            Text = "Select All Threads",
            Dock = DockStyle.Bottom,
            Height = 25
        };
        _chkSelectAll.CheckedChanged += ChkSelectAll_CheckedChanged;

        var pnlBottom = new Panel
        {
            Dock = DockStyle.Bottom,
            Height = 45
        };

        _btnClose = new Button
        {
            Text = "Close",
            Location = new Point(340, 10),
            Size = new Size(80, 32),
            DialogResult = DialogResult.Cancel
        };

        pnlBottom.Controls.Add(_btnClose);

        Controls.Add(_lvThreads);
        Controls.Add(_chkSelectAll);
        Controls.Add(pnlTop);
        Controls.Add(pnlBottom);
        CancelButton = _btnClose;
    }

    private void RefreshThreads()
    {
        _lvThreads.Items.Clear();

        var result = NexusEngine.Nexus_EnumerateThreads(_processHandle, null, 0, out var count);
        if (count == 0) return;

        var threads = new NexusThreadInfo[count];
        result = NexusEngine.Nexus_EnumerateThreads(_processHandle, threads, count, out _);

        foreach (var t in threads)
        {
            var item = new ListViewItem(t.ThreadId.ToString());
            item.SubItems.Add(((NexusThreadState)t.State).ToString());
            item.SubItems.Add((t.BasePriority + t.DeltaPriority).ToString());
            item.SubItems.Add($"0x{t.StartAddress:X}");
            item.Tag = t.ThreadId;
            item.Checked = _chkSelectAll.Checked;
            _lvThreads.Items.Add(item);
        }
    }

    private void ChkSelectAll_CheckedChanged(object? sender, EventArgs e)
    {
        foreach (ListViewItem item in _lvThreads.Items)
        {
            item.Checked = _chkSelectAll.Checked;
        }
    }

    private void BtnPause_Click(object? sender, EventArgs e)
    {
        _selectedThreads.Clear();

        foreach (ListViewItem item in _lvThreads.CheckedItems)
        {
            if (item.Tag is uint threadId)
            {
                var result = NexusEngine.Nexus_SuspendThread(threadId);
                if (result == NexusResult.OK || result == NexusResult.Success)
                {
                    _selectedThreads.Add(threadId);
                }
            }
        }

        if (_selectedThreads.Count > 0)
        {
            _isPaused = true;
            _btnPause.Enabled = false;
            _btnResume.Enabled = true;
            _lblStatus.Text = $"Status: Paused ({_selectedThreads.Count} threads)";
            _lblStatus.ForeColor = Color.Red;
        }

        RefreshThreads();
    }

    private void BtnResume_Click(object? sender, EventArgs e)
    {
        foreach (var threadId in _selectedThreads)
        {
            NexusEngine.Nexus_ResumeThread(threadId);
        }

        _selectedThreads.Clear();
        _isPaused = false;
        _btnPause.Enabled = true;
        _btnResume.Enabled = false;
        _lblStatus.Text = "Status: Running";
        _lblStatus.ForeColor = Color.Green;

        RefreshThreads();
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        // Resume all threads when closing
        if (_isPaused && _selectedThreads.Count > 0)
        {
            var result = MessageBox.Show(
                "Some threads are still paused. Resume them before closing?",
                "Confirm",
                MessageBoxButtons.YesNoCancel,
                MessageBoxIcon.Question);

            if (result == DialogResult.Yes)
            {
                BtnResume_Click(null, EventArgs.Empty);
            }
            else if (result == DialogResult.Cancel)
            {
                e.Cancel = true;
                return;
            }
        }

        base.OnFormClosing(e);
    }
}
