// <file>
// <summary>
// Scan settings dialog for configuring memory scan parameters.
// </summary>
// </file>
using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using Nexus.UI.Styles;

namespace Nexus.UI.Forms;

/// <summary>
/// Dialog for configuring scan type, value type, and scan options.
/// Matches CE's scan settings panel behavior.
/// </summary>
public class ScanSettingsForm : Form
{
    // Scan type
    private GroupBox _grpScanType = null!;
    private ComboBox _cboScanType = null!;

    // Value type
    private GroupBox _grpValueType = null!;
    private ComboBox _cboValueType = null!;
    private CheckBox _chkHex = null!;

    // String options (shown when string type selected)
    private GroupBox _grpStringOptions = null!;
    private RadioButton _rbUnicode = null!;
    private RadioButton _rbAnsi = null!;
    private CheckBox _chkCaseSensitive = null!;

    // Scan options
    private GroupBox _grpScanOptions = null!;
    private CheckBox _chkWritable = null!;
    private CheckBox _chkExecutable = null!;
    private CheckBox _chkCopyOnWrite = null!;
    private CheckBox _chkFastScan = null!;
    private Label _lblAlignment = null!;
    private NumericUpDown _nudAlignment = null!;

    // Memory range
    private GroupBox _grpMemoryRange = null!;
    private TextBox _txtStartAddress = null!;
    private TextBox _txtEndAddress = null!;
    private CheckBox _chkAllRegions = null!;

    // Buttons
    private Button _btnOK = null!;
    private Button _btnCancel = null!;

    // Result properties
    public NexusScanType ScanType { get; private set; } = NexusScanType.Exact;
    public NexusValueType ValueType { get; private set; } = NexusValueType.FourBytes;
    public bool IsHex { get; private set; }
    public bool IsUnicode { get; private set; } = true;
    public bool CaseSensitive { get; private set; }
    public bool WritableOnly { get; private set; } = true;
    public bool ExecutableOnly { get; private set; }
    public bool CopyOnWriteOnly { get; private set; }
    public bool FastScan { get; private set; } = true;
    public int Alignment { get; private set; } = 4;
    public ulong StartAddress { get; private set; }
    public ulong EndAddress { get; private set; } = 0x7FFFFFFFFFFF;
    public bool ScanAllRegions { get; private set; } = true;

    public ScanSettingsForm()
    {
        InitializeComponent();
        NexusTheme.StyleForm(this);
        SetupEventHandlers();
        LoadDefaults();
    }

    private void InitializeComponent()
    {
        Text = "Scan Settings";
        Size = new Size(500, 450);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        StartPosition = FormStartPosition.CenterParent;

        // Scan Type and Value Type on same row
        var lblScanType = new Label
        {
            Text = "Scan Type",
            Location = new Point(NexusTheme.DialogPadding, NexusTheme.DialogPadding),
            AutoSize = true
        };

        _cboScanType = new ComboBox
        {
            DropDownStyle = ComboBoxStyle.DropDownList,
            Location = new Point(NexusTheme.DialogPadding, NexusTheme.DialogPadding + 20),
            Size = new Size(200, NexusTheme.ComboBoxHeight)
        };
        NexusTheme.StyleComboBox(_cboScanType);
        _cboScanType.Items.AddRange(new object[] {
            "Exact Value",
            "Bigger than...",
            "Smaller than...",
            "Value between...",
            "Unknown initial value",
            "Increased value",
            "Increased value by...",
            "Decreased value",
            "Decreased value by...",
            "Changed value",
            "Unchanged value"
        });

        var lblValueType = new Label
        {
            Text = "Value Type",
            Location = new Point(230, NexusTheme.DialogPadding),
            AutoSize = true
        };

        _cboValueType = new ComboBox
        {
            DropDownStyle = ComboBoxStyle.DropDownList,
            Location = new Point(230, NexusTheme.DialogPadding + 20),
            Size = new Size(150, NexusTheme.ComboBoxHeight)
        };
        NexusTheme.StyleComboBox(_cboValueType);
        _cboValueType.Items.AddRange(new object[] {
            "Binary",
            "Byte",
            "2 Bytes",
            "4 Bytes",
            "8 Bytes",
            "Float",
            "Double",
            "String",
            "Array of byte",
            "All"
        });

        _chkHex = new CheckBox
        {
            Text = "Hex",
            Location = new Point(400, NexusTheme.DialogPadding + 22),
            AutoSize = true
        };
        NexusTheme.StyleCheckBox(_chkHex);

        // String Options group (initially hidden)
        _grpStringOptions = new GroupBox
        {
            Text = "String Options",
            Location = new Point(NexusTheme.DialogPadding, NexusTheme.DialogPadding + 20 + NexusTheme.ComboBoxHeight + NexusTheme.Space8),
            Size = new Size(460, 60),
            Visible = false
        };

        _rbUnicode = new RadioButton
        {
            Text = "Unicode",
            Location = new Point(15, 22),
            AutoSize = true,
            Checked = true
        };

        _rbAnsi = new RadioButton
        {
            Text = "ANSI",
            Location = new Point(100, 22),
            AutoSize = true
        };

        _chkCaseSensitive = new CheckBox
        {
            Text = "Case sensitive",
            Location = new Point(180, 22),
            AutoSize = true
        };

        _grpStringOptions.Controls.Add(_rbUnicode);
        _grpStringOptions.Controls.Add(_rbAnsi);
        _grpStringOptions.Controls.Add(_chkCaseSensitive);

        // Scan Options group
        _grpScanOptions = new GroupBox
        {
            Text = "Scan Options",
            Location = new Point(NexusTheme.DialogPadding, NexusTheme.DialogPadding + 20 + NexusTheme.ComboBoxHeight + NexusTheme.Space8),
            Size = new Size(460, 100)
        };

        _chkWritable = new CheckBox
        {
            Text = "Writable",
            Location = new Point(15, 30),
            AutoSize = true,
            Checked = true
        };

        _chkExecutable = new CheckBox
        {
            Text = "Executable",
            Location = new Point(140, 30),
            AutoSize = true
        };

        _chkCopyOnWrite = new CheckBox
        {
            Text = "Copy-on-write",
            Location = new Point(280, 30),
            AutoSize = true
        };

        _chkFastScan = new CheckBox
        {
            Text = "Fast scan",
            Location = new Point(15, 60),
            AutoSize = true,
            Checked = true
        };

        _lblAlignment = new Label
        {
            Text = "Alignment:",
            Location = new Point(140, 62),
            AutoSize = true
        };

        _nudAlignment = new NumericUpDown
        {
            Location = new Point(240, 59),
            Size = new Size(60, 23),
            Minimum = 1,
            Maximum = 16,
            Value = 4
        };

        _grpScanOptions.Controls.Add(_chkWritable);
        _grpScanOptions.Controls.Add(_chkExecutable);
        _grpScanOptions.Controls.Add(_chkCopyOnWrite);
        _grpScanOptions.Controls.Add(_chkFastScan);
        _grpScanOptions.Controls.Add(_lblAlignment);
        _grpScanOptions.Controls.Add(_nudAlignment);

        // Memory Range group
        _grpMemoryRange = new GroupBox
        {
            Text = "Memory Scan Range",
            Location = new Point(NexusTheme.DialogPadding, 185),
            Size = new Size(460, 110)
        };

        _chkAllRegions = new CheckBox
        {
            Text = "Scan all memory regions",
            Location = new Point(15, 30),
            AutoSize = true,
            Checked = true
        };

        var lblStart = new Label
        {
            Text = "Start:",
            Location = new Point(15, 68),
            AutoSize = true
        };

        _txtStartAddress = new TextBox
        {
            Location = new Point(60, 65),
            Size = new Size(170, NexusTheme.TextBoxHeight),
            Text = "0",
            TextAlign = HorizontalAlignment.Right,
            Enabled = false
        };
        NexusTheme.StyleTextBox(_txtStartAddress);

        var lblEnd = new Label
        {
            Text = "End:",
            Location = new Point(240, 68),
            AutoSize = true
        };

        _txtEndAddress = new TextBox
        {
            Location = new Point(280, 65),
            Size = new Size(160, NexusTheme.TextBoxHeight),
            Text = "7FFFFFFFFFFF",
            TextAlign = HorizontalAlignment.Right,
            Enabled = false
        };
        NexusTheme.StyleTextBox(_txtEndAddress);

        _grpMemoryRange.Controls.Add(_chkAllRegions);
        _grpMemoryRange.Controls.Add(lblStart);
        _grpMemoryRange.Controls.Add(_txtStartAddress);
        _grpMemoryRange.Controls.Add(lblEnd);
        _grpMemoryRange.Controls.Add(_txtEndAddress);

        // Buttons
        int buttonY = 360;
        _btnOK = new Button
        {
            Text = "OK",
            Location = new Point(290, buttonY),
            Size = new Size(NexusTheme.ButtonWidth, NexusTheme.ButtonHeight),
            DialogResult = DialogResult.OK
        };
        NexusTheme.StylePrimaryButton(_btnOK);

        _btnCancel = new Button
        {
            Text = "Cancel",
            Location = new Point(290 + NexusTheme.ButtonWidth + NexusTheme.ButtonGap, buttonY),
            Size = new Size(NexusTheme.ButtonWidth, NexusTheme.ButtonHeight),
            DialogResult = DialogResult.Cancel
        };
        NexusTheme.StyleButton(_btnCancel);

        // Create dummy groupboxes for fields not in groups
        _grpScanType = new GroupBox { Visible = false };
        _grpValueType = new GroupBox { Visible = false };

        Controls.Add(lblScanType);
        Controls.Add(_cboScanType);
        Controls.Add(lblValueType);
        Controls.Add(_cboValueType);
        Controls.Add(_chkHex);
        Controls.Add(_grpStringOptions);
        Controls.Add(_grpScanOptions);
        Controls.Add(_grpMemoryRange);
        Controls.Add(_btnOK);
        Controls.Add(_btnCancel);

        AcceptButton = _btnOK;
        CancelButton = _btnCancel;
    }

    private void SetupEventHandlers()
    {
        _cboValueType.SelectedIndexChanged += (s, e) => UpdateStringOptionsVisibility();
        _chkAllRegions.CheckedChanged += (s, e) =>
        {
            _txtStartAddress.Enabled = !_chkAllRegions.Checked;
            _txtEndAddress.Enabled = !_chkAllRegions.Checked;
        };
        _chkFastScan.CheckedChanged += (s, e) =>
        {
            _lblAlignment.Enabled = _chkFastScan.Checked;
            _nudAlignment.Enabled = _chkFastScan.Checked;
        };

        _btnOK.Click += (s, e) =>
        {
            ApplySettings();
            DialogResult = DialogResult.OK;
            Close();
        };

        _btnCancel.Click += (s, e) =>
        {
            DialogResult = DialogResult.Cancel;
            Close();
        };
    }

    private void LoadDefaults()
    {
        _cboScanType.SelectedIndex = 0; // Exact Value
        _cboValueType.SelectedIndex = 3; // 4 Bytes
    }

    private void UpdateStringOptionsVisibility()
    {
        var isString = _cboValueType.SelectedIndex == 7; // String
        _grpStringOptions.Visible = isString;

        // Adjust positions when string options shown
        if (isString)
        {
            _grpScanOptions.Location = new Point(NexusTheme.DialogPadding, 140);
            _grpMemoryRange.Location = new Point(NexusTheme.DialogPadding, 255);
            int buttonY = 430;
            _btnOK.Location = new Point(290, buttonY);
            _btnCancel.Location = new Point(290 + NexusTheme.ButtonWidth + NexusTheme.ButtonGap, buttonY);
            Size = new Size(500, 520);
        }
        else
        {
            _grpScanOptions.Location = new Point(NexusTheme.DialogPadding, NexusTheme.DialogPadding + 20 + NexusTheme.ComboBoxHeight + NexusTheme.Space8);
            _grpMemoryRange.Location = new Point(NexusTheme.DialogPadding, 185);
            int buttonY = 360;
            _btnOK.Location = new Point(290, buttonY);
            _btnCancel.Location = new Point(290 + NexusTheme.ButtonWidth + NexusTheme.ButtonGap, buttonY);
            Size = new Size(500, 450);
        }
    }

    private void ApplySettings()
    {
        // Map scan type
        ScanType = _cboScanType.SelectedIndex switch
        {
            0 => NexusScanType.Exact,
            1 => NexusScanType.BiggerThan,
            2 => NexusScanType.SmallerThan,
            3 => NexusScanType.Between,
            4 => NexusScanType.UnknownInitial,
            5 => NexusScanType.Increased,
            6 => NexusScanType.IncreasedBy,
            7 => NexusScanType.Decreased,
            8 => NexusScanType.DecreasedBy,
            9 => NexusScanType.Changed,
            10 => NexusScanType.Unchanged,
            _ => NexusScanType.Exact
        };

        // Map value type
        ValueType = _cboValueType.SelectedIndex switch
        {
            0 => NexusValueType.Binary,
            1 => NexusValueType.Byte,
            2 => NexusValueType.TwoBytes,
            3 => NexusValueType.FourBytes,
            4 => NexusValueType.EightBytes,
            5 => NexusValueType.Float,
            6 => NexusValueType.Double,
            7 => NexusValueType.String,
            8 => NexusValueType.ArrayOfBytes,
            9 => NexusValueType.All,
            _ => NexusValueType.FourBytes
        };

        IsHex = _chkHex.Checked;
        IsUnicode = _rbUnicode.Checked;
        CaseSensitive = _chkCaseSensitive.Checked;

        WritableOnly = _chkWritable.Checked;
        ExecutableOnly = _chkExecutable.Checked;
        CopyOnWriteOnly = _chkCopyOnWrite.Checked;
        FastScan = _chkFastScan.Checked;
        Alignment = (int)_nudAlignment.Value;

        ScanAllRegions = _chkAllRegions.Checked;
        if (!ScanAllRegions)
        {
            if (ulong.TryParse(_txtStartAddress.Text, System.Globalization.NumberStyles.HexNumber, null, out var start))
                StartAddress = start;
            if (ulong.TryParse(_txtEndAddress.Text, System.Globalization.NumberStyles.HexNumber, null, out var end))
                EndAddress = end;
        }
    }

    /// <summary>
    /// Sets the form values from existing scan settings.
    /// </summary>
    public void LoadSettings(NexusScanType scanType, NexusValueType valueType, bool hex,
        bool unicode, bool caseSensitive, bool writable, bool executable,
        bool copyOnWrite, bool fastScan, int alignment)
    {
        _cboScanType.SelectedIndex = scanType switch
        {
            NexusScanType.Exact => 0,
            NexusScanType.BiggerThan => 1,
            NexusScanType.SmallerThan => 2,
            NexusScanType.Between => 3,
            NexusScanType.UnknownInitial => 4,
            NexusScanType.Increased => 5,
            NexusScanType.IncreasedBy => 6,
            NexusScanType.Decreased => 7,
            NexusScanType.DecreasedBy => 8,
            NexusScanType.Changed => 9,
            NexusScanType.Unchanged => 10,
            _ => 0
        };

        _cboValueType.SelectedIndex = valueType switch
        {
            NexusValueType.Binary => 0,
            NexusValueType.Byte => 1,
            NexusValueType.TwoBytes => 2,
            NexusValueType.FourBytes => 3,
            NexusValueType.EightBytes => 4,
            NexusValueType.Float => 5,
            NexusValueType.Double => 6,
            NexusValueType.String => 7,
            NexusValueType.ArrayOfBytes => 8,
            NexusValueType.All => 9,
            _ => 3
        };

        _chkHex.Checked = hex;
        _rbUnicode.Checked = unicode;
        _rbAnsi.Checked = !unicode;
        _chkCaseSensitive.Checked = caseSensitive;
        _chkWritable.Checked = writable;
        _chkExecutable.Checked = executable;
        _chkCopyOnWrite.Checked = copyOnWrite;
        _chkFastScan.Checked = fastScan;
        _nudAlignment.Value = alignment;
    }
}

/// <summary>
/// Quick value type selector popup matching CE's dropdown behavior.
/// </summary>
public class ValueTypeSelectorForm : Form
{
    private ListBox _lbTypes = null!;

    public NexusValueType SelectedType { get; private set; } = NexusValueType.FourBytes;

    public ValueTypeSelectorForm()
    {
        InitializeComponent();
        NexusTheme.StyleForm(this);
    }

    private void InitializeComponent()
    {
        Text = "Select Value Type";
        Size = new Size(200, 280);
        FormBorderStyle = FormBorderStyle.FixedToolWindow;
        StartPosition = FormStartPosition.CenterParent;
        ShowInTaskbar = false;

        _lbTypes = new ListBox
        {
            Dock = DockStyle.Fill,
            Font = new Font("Segoe UI", 9)
        };

        _lbTypes.Items.AddRange(new object[]
        {
            "Binary",
            "Byte",
            "2 Bytes",
            "4 Bytes",
            "8 Bytes",
            "Float",
            "Double",
            "String",
            "Array of byte",
            "All"
        });

        _lbTypes.SelectedIndex = 3; // 4 Bytes default

        _lbTypes.DoubleClick += (s, e) =>
        {
            ApplySelection();
            DialogResult = DialogResult.OK;
            Close();
        };

        _lbTypes.KeyDown += (s, e) =>
        {
            if (e.KeyCode == Keys.Enter)
            {
                ApplySelection();
                DialogResult = DialogResult.OK;
                Close();
            }
            else if (e.KeyCode == Keys.Escape)
            {
                DialogResult = DialogResult.Cancel;
                Close();
            }
        };

        Controls.Add(_lbTypes);
    }

    private void ApplySelection()
    {
        SelectedType = _lbTypes.SelectedIndex switch
        {
            0 => NexusValueType.Binary,
            1 => NexusValueType.Byte,
            2 => NexusValueType.TwoBytes,
            3 => NexusValueType.FourBytes,
            4 => NexusValueType.EightBytes,
            5 => NexusValueType.Float,
            6 => NexusValueType.Double,
            7 => NexusValueType.String,
            8 => NexusValueType.ArrayOfBytes,
            9 => NexusValueType.All,
            _ => NexusValueType.FourBytes
        };
    }

    public void SetSelectedType(NexusValueType type)
    {
        _lbTypes.SelectedIndex = type switch
        {
            NexusValueType.Binary => 0,
            NexusValueType.Byte => 1,
            NexusValueType.TwoBytes => 2,
            NexusValueType.FourBytes => 3,
            NexusValueType.EightBytes => 4,
            NexusValueType.Float => 5,
            NexusValueType.Double => 6,
            NexusValueType.String => 7,
            NexusValueType.ArrayOfBytes => 8,
            NexusValueType.All => 9,
            _ => 3
        };
    }
}
