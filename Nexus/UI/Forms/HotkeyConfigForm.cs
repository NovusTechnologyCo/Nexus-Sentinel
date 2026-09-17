// <file>
// <summary>
// Hotkey configuration dialog for global keyboard shortcuts.
// </summary>
// </file>
#pragma warning disable CS0169 // Field is never used

using System.Runtime.InteropServices;
using Nexus.UI.Helpers;
using Nexus.UI.Styles;


namespace Nexus.UI.Forms;

public class HotkeyItem
{
    public int Id { get; set; }
    public Keys[] KeyCombo { get; set; } = [];
    public string Description { get; set; } = "";
    public HotkeyAction Action { get; set; }
    public object? Tag { get; set; } // Memory record or generic handler
    public int DelayBetweenActivate { get; set; } = 100; // ms
    public DateTime LastActivated { get; set; }
}

public enum HotkeyAction
{
    Toggle,
    ToggleEntry,
    Enable,
    Disable,
    FreezeEntry,
    IncreaseValue,
    DecreaseValue,
    SetValue,
    PauseProcess,
    SpeedHack,
    Custom
}

public partial class HotkeyConfigForm : Form
{
    private readonly List<HotkeyItem> _hotkeys = [];
    private HotkeyItem? _editingHotkey;
    private readonly List<Keys> _currentKeyCombo = [];
    private bool _isRecording;

    public IReadOnlyList<HotkeyItem> Hotkeys => _hotkeys.AsReadOnly();

    public HotkeyConfigForm()
    {
        InitializeComponent();
        NexusTheme.StyleForm(this);
        LoadDefaultHotkeys();
    }

    private void InitializeComponent()
    {
        Text = "Hotkey Configuration";
        Size = new Size(600, 500);
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.Sizable;
        MinimumSize = new Size(400, 300);

        // Hotkey list
        lvHotkeys = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = true,
            MultiSelect = false
        };
        lvHotkeys.Columns.Add("Keys", -2);
        lvHotkeys.Columns.Add("Action", -2);
        lvHotkeys.Columns.Add("Description", -2);
        lvHotkeys.SelectedIndexChanged += LvHotkeys_SelectedIndexChanged;
        lvHotkeys.DoubleClick += BtnEdit_Click;

        // Context menu
        var ctxMenu = new ContextMenuStrip();
        ctxMenu.Items.Add("Edit hotkey...", null, BtnEdit_Click);
        ctxMenu.Items.Add("Remove hotkey", null, BtnRemove_Click);
        ctxMenu.Items.Add(new ToolStripSeparator());
        ctxMenu.Items.Add("Add new hotkey...", null, BtnAdd_Click);
        lvHotkeys.ContextMenuStrip = ctxMenu;

        // Bottom panel
        var pnlBottom = new Panel
        {
            Dock = DockStyle.Bottom,
            Height = 45
        };

        btnAdd = new Button
        {
            Text = "Add",
            Location = new Point(10, 10),
            Size = new Size(75, 32)
        };
        btnAdd.Click += BtnAdd_Click;

        btnEdit = new Button
        {
            Text = "Edit",
            Location = new Point(95, 10),
            Size = new Size(80, 32),
            Enabled = false
        };
        btnEdit.Click += BtnEdit_Click;

        btnRemove = new Button
        {
            Text = "Remove",
            Location = new Point(180, 10),
            Size = new Size(85, 32),
            Enabled = false
        };
        btnRemove.Click += BtnRemove_Click;

        btnOk = new Button
        {
            Text = "OK",
            DialogResult = DialogResult.OK,
            Location = new Point(420, 10),
            Size = new Size(75, 32)
        };
        btnOk.Click += (s, e) => Close();

        btnCancel = new Button
        {
            Text = "Cancel",
            DialogResult = DialogResult.Cancel,
            Location = new Point(505, 10),
            Size = new Size(75, 32)
        };
        btnCancel.Click += (s, e) => Close();

        pnlBottom.Controls.AddRange([btnAdd, btnEdit, btnRemove, btnOk, btnCancel]);

        // Settings panel
        var gbSettings = new GroupBox
        {
            Text = "Hotkey Settings",
            Dock = DockStyle.Top,
            Height = 80
        };

        var lblPoll = new Label
        {
            Text = "Poll interval (ms):",
            Location = new Point(10, 25),
            AutoSize = true
        };

        nudPollInterval = new NumericUpDown
        {
            Location = new Point(160, 22),
            Width = 70,
            Minimum = 10,
            Maximum = 1000,
            Value = 100
        };

        var lblIdle = new Label
        {
            Text = "Idle time (ms):",
            Location = new Point(250, 25),
            AutoSize = true
        };

        nudIdleTime = new NumericUpDown
        {
            Location = new Point(380, 22),
            Width = 70,
            Minimum = 10,
            Maximum = 1000,
            Value = 100
        };

        cbSuspendHotkeys = new CheckBox
        {
            Text = "Suspend hotkeys when Nexus is in foreground",
            Location = new Point(10, 50),
            AutoSize = true
        };

        gbSettings.Controls.AddRange([lblPoll, nudPollInterval, lblIdle, nudIdleTime, cbSuspendHotkeys]);

        AcceptButton = btnOk;
        CancelButton = btnCancel;

        Controls.Add(lvHotkeys);
        Controls.Add(gbSettings);
        Controls.Add(pnlBottom);

        Resize += (s, e) => RepositionButtons();
        Load += (s, e) => RepositionButtons();
    }

    private void RepositionButtons()
    {
        btnOk.Location = new Point(ClientSize.Width - 170, 10);
        btnCancel.Location = new Point(ClientSize.Width - 85, 10);
    }

    private void LoadDefaultHotkeys()
    {
        // Add some common default hotkeys
        _hotkeys.Add(new HotkeyItem
        {
            Id = 1,
            KeyCombo = [Keys.Control, Keys.Alt, Keys.P],
            Action = HotkeyAction.PauseProcess,
            Description = "Pause/Resume target process"
        });

        _hotkeys.Add(new HotkeyItem
        {
            Id = 2,
            KeyCombo = [Keys.Control, Keys.Alt, Keys.Add],
            Action = HotkeyAction.SpeedHack,
            Description = "Increase speed"
        });

        _hotkeys.Add(new HotkeyItem
        {
            Id = 3,
            KeyCombo = [Keys.Control, Keys.Alt, Keys.Subtract],
            Action = HotkeyAction.SpeedHack,
            Description = "Decrease speed"
        });

        RefreshList();
    }

    private void RefreshList()
    {
        lvHotkeys.BeginUpdate();
        lvHotkeys.Items.Clear();

        foreach (var hotkey in _hotkeys)
        {
            var item = new ListViewItem(FormatKeyCombo(hotkey.KeyCombo));
            item.SubItems.Add(hotkey.Action.ToString());
            item.SubItems.Add(hotkey.Description);
            item.Tag = hotkey;
            lvHotkeys.Items.Add(item);
        }

        lvHotkeys.EndUpdate();
    }

    private static string FormatKeyCombo(Keys[] keys)
    {
        if (keys.Length == 0) return "(none)";

        var parts = new List<string>();
        foreach (var key in keys)
        {
            parts.Add(key switch
            {
                Keys.ControlKey or Keys.Control or Keys.LControlKey or Keys.RControlKey => "Ctrl",
                Keys.ShiftKey or Keys.Shift or Keys.LShiftKey or Keys.RShiftKey => "Shift",
                Keys.Menu or Keys.Alt or Keys.LMenu or Keys.RMenu => "Alt",
                _ => key.ToString()
            });
        }
        return string.Join(" + ", parts);
    }

    private void LvHotkeys_SelectedIndexChanged(object? sender, EventArgs e)
    {
        bool hasSelection = lvHotkeys.SelectedItems.Count > 0;
        btnEdit.Enabled = hasSelection;
        btnRemove.Enabled = hasSelection;
    }

    private void BtnAdd_Click(object? sender, EventArgs e)
    {
        var newHotkey = new HotkeyItem
        {
            Id = _hotkeys.Count > 0 ? _hotkeys.Max(h => h.Id) + 1 : 1,
            KeyCombo = [],
            Action = HotkeyAction.Custom,
            Description = "New hotkey"
        };

        if (ShowHotkeyEditor(newHotkey))
        {
            _hotkeys.Add(newHotkey);
            RefreshList();
        }
    }

    private void BtnEdit_Click(object? sender, EventArgs e)
    {
        if (lvHotkeys.SelectedItems.Count == 0) return;

        var hotkey = lvHotkeys.SelectedItems[0].Tag as HotkeyItem;
        if (hotkey != null && ShowHotkeyEditor(hotkey))
        {
            RefreshList();
        }
    }

    private void BtnRemove_Click(object? sender, EventArgs e)
    {
        if (lvHotkeys.SelectedItems.Count == 0) return;

        var hotkey = lvHotkeys.SelectedItems[0].Tag as HotkeyItem;
        if (hotkey != null)
        {
            if (MessageBox.Show($"Remove hotkey '{FormatKeyCombo(hotkey.KeyCombo)}'?",
                "Remove Hotkey", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
            {
                _hotkeys.Remove(hotkey);
                RefreshList();
            }
        }
    }

    private bool ShowHotkeyEditor(HotkeyItem hotkey)
    {
        using var editorForm = new Form
        {
            Text = "Edit Hotkey",
            Size = new Size(450, 275),
            FormBorderStyle = FormBorderStyle.FixedDialog,
            StartPosition = FormStartPosition.CenterParent,
            MaximizeBox = false,
            MinimizeBox = false
        };

        var lblKeys = new Label
        {
            Text = "Keys:",
            Location = new Point(15, 20),
            AutoSize = true
        };

        var txtKeys = new TextBox
        {
            Location = new Point(125, 17),
            Width = 200,
            Text = FormatKeyCombo(hotkey.KeyCombo),
            ReadOnly = true,
            BackColor = Color.White
        };

        _currentKeyCombo.Clear();
        _currentKeyCombo.AddRange(hotkey.KeyCombo);
        _isRecording = false;

        var btnRecord = new Button
        {
            Text = "Record",
            Location = new Point(335, 15),
            Size = new Size(80, 32)
        };

        btnRecord.Click += (s, e) =>
        {
            if (!_isRecording)
            {
                _isRecording = true;
                _currentKeyCombo.Clear();
                txtKeys.Text = "(Press keys...)";
                btnRecord.Text = "Stop";
                txtKeys.Focus();
            }
            else
            {
                _isRecording = false;
                txtKeys.Text = FormatKeyCombo(_currentKeyCombo.ToArray());
                btnRecord.Text = "Record";
            }
        };

        txtKeys.KeyDown += (s, e) =>
        {
            if (_isRecording)
            {
                e.Handled = true;
                e.SuppressKeyPress = true;

                if (!_currentKeyCombo.Contains(e.KeyCode))
                {
                    _currentKeyCombo.Add(e.KeyCode);
                    txtKeys.Text = FormatKeyCombo(_currentKeyCombo.ToArray());
                }
            }
        };

        var lblAction = new Label
        {
            Text = "Action:",
            Location = new Point(15, 55),
            AutoSize = true
        };

        var cmbAction = new ComboBox
        {
            Location = new Point(125, 52),
            Width = 200,
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        cmbAction.Items.AddRange(Enum.GetNames(typeof(HotkeyAction)));
        cmbAction.SelectedItem = hotkey.Action.ToString();

        var lblDesc = new Label
        {
            Text = "Description:",
            Location = new Point(15, 90),
            AutoSize = true
        };

        var txtDesc = new TextBox
        {
            Location = new Point(125, 87),
            Width = 270,
            Text = hotkey.Description
        };

        var lblDelay = new Label
        {
            Text = "Delay (ms):",
            Location = new Point(15, 125),
            AutoSize = true
        };

        var nudDelay = new NumericUpDown
        {
            Location = new Point(125, 122),
            Size = new Size(80, 32),
            Minimum = 0,
            Maximum = 10000,
            Value = hotkey.DelayBetweenActivate
        };

        var btnOk = new Button
        {
            Text = "OK",
            DialogResult = DialogResult.OK,
            Location = new Point(235, 170),
            Size = new Size(75, 32)
        };

        var btnCancelEdit = new Button
        {
            Text = "Cancel",
            DialogResult = DialogResult.Cancel,
            Location = new Point(320, 170),
            Size = new Size(75, 32)
        };

        editorForm.Controls.AddRange([
            lblKeys, txtKeys, btnRecord,
            lblAction, cmbAction,
            lblDesc, txtDesc,
            lblDelay, nudDelay,
            btnOk, btnCancelEdit
        ]);

        editorForm.AcceptButton = btnOk;
        editorForm.CancelButton = btnCancelEdit;

        if (editorForm.ShowDialog(this) == DialogResult.OK)
        {
            hotkey.KeyCombo = _currentKeyCombo.ToArray();
            hotkey.Action = Enum.TryParse<HotkeyAction>(cmbAction.SelectedItem?.ToString(), out var action)
                ? action : HotkeyAction.Custom;
            hotkey.Description = txtDesc.Text;
            hotkey.DelayBetweenActivate = (int)nudDelay.Value;
            return true;
        }

        return false;
    }

    /// <summary>
    /// Registers all hotkeys with the system.
    /// </summary>
    public void RegisterAllHotkeys(IntPtr windowHandle)
    {
        foreach (var hotkey in _hotkeys)
        {
            RegisterHotkey(windowHandle, hotkey);
        }
    }

    /// <summary>
    /// Unregisters all hotkeys from the system.
    /// </summary>
    public void UnregisterAllHotkeys(IntPtr windowHandle)
    {
        foreach (var hotkey in _hotkeys)
        {
            UnregisterHotkey(windowHandle, hotkey.Id);
        }
    }

    private static void RegisterHotkey(IntPtr hWnd, HotkeyItem hotkey)
    {
        if (hotkey.KeyCombo.Length == 0) return;

        uint modifiers = 0;
        uint vk = 0;

        foreach (var key in hotkey.KeyCombo)
        {
            switch (key)
            {
                case Keys.Control:
                case Keys.ControlKey:
                case Keys.LControlKey:
                case Keys.RControlKey:
                    modifiers |= 0x0002; // MOD_CONTROL
                    break;
                case Keys.Alt:
                case Keys.Menu:
                case Keys.LMenu:
                case Keys.RMenu:
                    modifiers |= 0x0001; // MOD_ALT
                    break;
                case Keys.Shift:
                case Keys.ShiftKey:
                case Keys.LShiftKey:
                case Keys.RShiftKey:
                    modifiers |= 0x0004; // MOD_SHIFT
                    break;
                case Keys.LWin:
                case Keys.RWin:
                    modifiers |= 0x0008; // MOD_WIN
                    break;
                default:
                    vk = (uint)key;
                    break;
            }
        }

        if (vk != 0)
        {
            NativeMethods.RegisterHotKey(hWnd, hotkey.Id, modifiers, vk);
        }
    }

    private static void UnregisterHotkey(IntPtr hWnd, int id)
    {
        NativeMethods.UnregisterHotKey(hWnd, id);
    }

    /// <summary>
    /// Shows a simple hotkey picker dialog and returns the selected hotkey.
    /// </summary>
    /// <param name="owner">Parent window</param>
    /// <param name="currentKey">Current hotkey value (optional)</param>
    /// <param name="currentAction">Current action (optional)</param>
    /// <param name="hotkey">The selected hotkey if successful</param>
    /// <param name="action">The selected action if successful</param>
    /// <param name="actionValue">The action value (for Set/Increase/Decrease) if successful</param>
    /// <returns>True if user clicked OK, false if cancelled</returns>
    public static bool ShowHotkeyPicker(
        IWin32Window? owner,
        Keys currentKey,
        HotkeyAction currentAction,
        out Keys hotkey,
        out HotkeyAction action,
        out string actionValue)
    {
        hotkey = Keys.None;
        action = HotkeyAction.Toggle;
        actionValue = "";

        using var form = new Form
        {
            Text = "Set Hotkey",
            Size = new Size(400, 300),
            FormBorderStyle = FormBorderStyle.FixedDialog,
            StartPosition = FormStartPosition.CenterParent,
            MaximizeBox = false,
            MinimizeBox = false,
            KeyPreview = true
        };

        Keys capturedKey = currentKey;
        bool isCapturing = false;

        // Instructions
        var lblInstructions = new Label
        {
            Text = "Click the box below and press your hotkey combination:",
            Location = new Point(15, 15),
            AutoSize = true
        };

        // Hotkey textbox
        var txtHotkey = new TextBox
        {
            Location = new Point(15, 40),
            Size = new Size(260, 23),
            ReadOnly = true,
            Text = currentKey == Keys.None ? "(None)" : FormatSingleKey(currentKey),
            TextAlign = HorizontalAlignment.Center,
            BackColor = Color.White
        };

        var btnClear = new Button
        {
            Text = "Clear",
            Location = new Point(285, 38),
            Size = new Size(80, 27)
        };
        btnClear.Click += (s, e) =>
        {
            capturedKey = Keys.None;
            txtHotkey.Text = "(None)";
        };

        // Action group
        var gbAction = new GroupBox
        {
            Text = "Action",
            Location = new Point(15, 75),
            Size = new Size(350, 130)
        };

        var rbToggle = new RadioButton { Text = "Toggle activation", Location = new Point(15, 25), AutoSize = true, Checked = currentAction == HotkeyAction.Toggle };
        var rbEnable = new RadioButton { Text = "Enable only", Location = new Point(15, 50), AutoSize = true, Checked = currentAction == HotkeyAction.Enable };
        var rbDisable = new RadioButton { Text = "Disable only", Location = new Point(15, 75), AutoSize = true, Checked = currentAction == HotkeyAction.Disable };
        var rbSetValue = new RadioButton { Text = "Set value to:", Location = new Point(175, 25), AutoSize = true, Checked = currentAction == HotkeyAction.SetValue };
        var rbIncrease = new RadioButton { Text = "Increase by:", Location = new Point(175, 50), AutoSize = true, Checked = currentAction == HotkeyAction.IncreaseValue };
        var rbDecrease = new RadioButton { Text = "Decrease by:", Location = new Point(175, 75), AutoSize = true, Checked = currentAction == HotkeyAction.DecreaseValue };

        var txtValue = new TextBox
        {
            Location = new Point(175, 100),
            Size = new Size(100, 23),
            Text = "1",
            Enabled = currentAction == HotkeyAction.SetValue || currentAction == HotkeyAction.IncreaseValue || currentAction == HotkeyAction.DecreaseValue
        };

        void UpdateValueEnabled()
        {
            txtValue.Enabled = rbSetValue.Checked || rbIncrease.Checked || rbDecrease.Checked;
        }

        rbToggle.CheckedChanged += (s, e) => UpdateValueEnabled();
        rbEnable.CheckedChanged += (s, e) => UpdateValueEnabled();
        rbDisable.CheckedChanged += (s, e) => UpdateValueEnabled();
        rbSetValue.CheckedChanged += (s, e) => UpdateValueEnabled();
        rbIncrease.CheckedChanged += (s, e) => UpdateValueEnabled();
        rbDecrease.CheckedChanged += (s, e) => UpdateValueEnabled();

        gbAction.Controls.AddRange([rbToggle, rbEnable, rbDisable, rbSetValue, rbIncrease, rbDecrease, txtValue]);

        // Buttons
        var btnOk = new Button
        {
            Text = "OK",
            DialogResult = DialogResult.OK,
            Location = new Point(200, 220),
            Size = new Size(80, 32)
        };

        var btnCancel = new Button
        {
            Text = "Cancel",
            DialogResult = DialogResult.Cancel,
            Location = new Point(290, 220),
            Size = new Size(80, 32)
        };

        form.Controls.AddRange([lblInstructions, txtHotkey, btnClear, gbAction, btnOk, btnCancel]);
        form.AcceptButton = btnOk;
        form.CancelButton = btnCancel;

        // Capture key when textbox is focused
        txtHotkey.Enter += (s, e) =>
        {
            isCapturing = true;
            txtHotkey.BackColor = Color.LightYellow;
        };

        txtHotkey.Leave += (s, e) =>
        {
            isCapturing = false;
            txtHotkey.BackColor = Color.White;
        };

        form.KeyDown += (s, e) =>
        {
            if (!isCapturing) return;

            // Ignore modifier-only keys
            if (e.KeyCode == Keys.ControlKey || e.KeyCode == Keys.ShiftKey ||
                e.KeyCode == Keys.Menu || e.KeyCode == Keys.LWin || e.KeyCode == Keys.RWin)
                return;

            capturedKey = e.KeyCode;
            if (e.Control) capturedKey |= Keys.Control;
            if (e.Shift) capturedKey |= Keys.Shift;
            if (e.Alt) capturedKey |= Keys.Alt;

            txtHotkey.Text = FormatSingleKey(capturedKey);
            e.Handled = true;
            e.SuppressKeyPress = true;
        };

        if (form.ShowDialog(owner) == DialogResult.OK)
        {
            hotkey = capturedKey;

            if (rbToggle.Checked) action = HotkeyAction.Toggle;
            else if (rbEnable.Checked) action = HotkeyAction.Enable;
            else if (rbDisable.Checked) action = HotkeyAction.Disable;
            else if (rbSetValue.Checked) { action = HotkeyAction.SetValue; actionValue = txtValue.Text; }
            else if (rbIncrease.Checked) { action = HotkeyAction.IncreaseValue; actionValue = txtValue.Text; }
            else if (rbDecrease.Checked) { action = HotkeyAction.DecreaseValue; actionValue = txtValue.Text; }

            return true;
        }

        return false;
    }

    /// <summary>
    /// Shows a simple hotkey picker dialog (simpler overload).
    /// </summary>
    public static bool ShowHotkeyPicker(IWin32Window? owner, out Keys hotkey, out HotkeyAction action)
    {
        return ShowHotkeyPicker(owner, Keys.None, HotkeyAction.Toggle, out hotkey, out action, out _);
    }

    /// <summary>
    /// Formats a single Keys value (with modifiers) to a display string.
    /// </summary>
    private static string FormatSingleKey(Keys key)
    {
        if (key == Keys.None) return "(None)";

        var parts = new List<string>();

        if ((key & Keys.Control) != 0) parts.Add("Ctrl");
        if ((key & Keys.Alt) != 0) parts.Add("Alt");
        if ((key & Keys.Shift) != 0) parts.Add("Shift");

        var baseKey = key & Keys.KeyCode;
        if (baseKey != Keys.None)
        {
            parts.Add(baseKey switch
            {
                Keys.D0 => "0", Keys.D1 => "1", Keys.D2 => "2", Keys.D3 => "3", Keys.D4 => "4",
                Keys.D5 => "5", Keys.D6 => "6", Keys.D7 => "7", Keys.D8 => "8", Keys.D9 => "9",
                Keys.Space => "Space", Keys.Return => "Enter", Keys.Escape => "Esc",
                Keys.Back => "Backspace", Keys.Tab => "Tab",
                _ => baseKey.ToString()
            });
        }

        return string.Join(" + ", parts);
    }

    private static class NativeMethods
    {
        [DllImport("user32.dll")]
        public static extern bool RegisterHotKey(IntPtr hWnd, int id, uint fsModifiers, uint vk);

        [DllImport("user32.dll")]
        public static extern bool UnregisterHotKey(IntPtr hWnd, int id);
    }

    // Controls
    private ListView lvHotkeys = null!;
    private Button btnAdd = null!;
    private Button btnEdit = null!;
    private Button btnRemove = null!;
    private Button btnOk = null!;
    private Button btnCancel = null!;
    private NumericUpDown nudPollInterval = null!;
    private NumericUpDown nudIdleTime = null!;
    private CheckBox cbSuspendHotkeys = null!;
}
