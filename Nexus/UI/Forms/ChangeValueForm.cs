// <file>
// <summary>
// Value edit dialog for changing memory values at a specific address.
// </summary>
// </file>
using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using Nexus.UI.Styles;

namespace Nexus.UI.Forms;

/// <summary>
/// Form for changing the value of one or more addresses.
/// Matches CE's "Change value" dialog.
/// </summary>
public class ChangeValueForm : Form
{
    // Controls
    private Label _lblValue = null!;
    private TextBox _txtValue = null!;
    private CheckBox _chkHex = null!;
    private Button _btnOK = null!;
    private Button _btnCancel = null!;

    // Properties
    public string Value { get; private set; } = "";
    public bool IsHex { get; private set; }

    public ChangeValueForm(string currentValue = "", bool isHex = false)
    {
        InitializeComponent();
        NexusTheme.StyleForm(this);
        _txtValue.Text = currentValue;
        _chkHex.Checked = isHex;
    }

    private void InitializeComponent()
    {
        Text = "Change Value";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        StartPosition = FormStartPosition.CenterParent;

        const int margin = NexusTheme.Space16;
        const int labelWidth = 50;
        const int textboxWidth = 200;
        const int contentWidth = labelWidth + NexusTheme.Space8 + textboxWidth;

        _lblValue = new Label
        {
            Text = "Value:",
            Location = new Point(margin, margin + 6),
            AutoSize = true
        };

        _txtValue = new TextBox
        {
            Location = new Point(margin + labelWidth + NexusTheme.Space8, margin),
            Size = new Size(textboxWidth, NexusTheme.TextBoxHeight)
        };
        NexusTheme.StyleTextBox(_txtValue);

        // Row 2: Hex checkbox on left, OK/Cancel on right
        int buttonY = margin + NexusTheme.TextBoxHeight + NexusTheme.Space8;

        _chkHex = new CheckBox
        {
            Text = "Hex",
            Location = new Point(margin, buttonY + 5),
            AutoSize = true
        };
        NexusTheme.StyleCheckBox(_chkHex);

        int buttonX = margin + contentWidth - NexusTheme.ButtonWidth;

        _btnCancel = new Button
        {
            Text = "Cancel",
            Location = new Point(buttonX, buttonY),
            Size = new Size(NexusTheme.ButtonWidth, NexusTheme.ButtonHeight),
            DialogResult = DialogResult.Cancel
        };
        NexusTheme.StyleButton(_btnCancel);
        _btnCancel.Click += (s, e) => Close();

        buttonX -= NexusTheme.ButtonWidth + NexusTheme.ButtonGap;
        _btnOK = new Button
        {
            Text = "OK",
            Location = new Point(buttonX, buttonY),
            Size = new Size(NexusTheme.ButtonWidth, NexusTheme.ButtonHeight),
            DialogResult = DialogResult.OK
        };
        NexusTheme.StylePrimaryButton(_btnOK);
        _btnOK.Click += (s, e) =>
        {
            Value = _txtValue.Text;
            IsHex = _chkHex.Checked;
        };

        Controls.Add(_lblValue);
        Controls.Add(_txtValue);
        Controls.Add(_chkHex);
        Controls.Add(_btnOK);
        Controls.Add(_btnCancel);

        AcceptButton = _btnOK;
        CancelButton = _btnCancel;

        ClientSize = new Size(margin + contentWidth + margin, buttonY + NexusTheme.ButtonHeight + margin);
    }

    protected override void OnShown(EventArgs e)
    {
        base.OnShown(e);
        _txtValue.SelectAll();
        _txtValue.Focus();
    }
}

// ChangeDescriptionForm - DELETED (use InputBoxForm.Show instead)

/// <summary>
/// Form for changing the address of an entry.
/// </summary>
public class ChangeAddressForm : Form
{
    private Label _lblAddress = null!;
    private TextBox _txtAddress = null!;
    private CheckBox _chkPointer = null!;
    private GroupBox _grpPointer = null!;
    private Label _lblBaseAddress = null!;
    private TextBox _txtBaseAddress = null!;
    private ListView _lvOffsets = null!;
    private Button _btnAddOffset = null!;
    private Button _btnRemoveOffset = null!;
    private Button _btnOK = null!;
    private Button _btnCancel = null!;

    public string Address { get; private set; } = "";
    public bool IsPointer { get; private set; }
    public string BaseAddress { get; private set; } = "";
    public List<long> Offsets { get; private set; } = new();

    public ChangeAddressForm(string currentAddress = "", bool isPointer = false,
        string baseAddress = "", List<long>? offsets = null)
    {
        InitializeComponent();
        NexusTheme.StyleForm(this);
        _txtAddress.Text = currentAddress;
        _chkPointer.Checked = isPointer;

        if (isPointer)
        {
            _txtBaseAddress.Text = baseAddress;
            if (offsets != null)
            {
                foreach (var offset in offsets)
                {
                    _lvOffsets.Items.Add(new ListViewItem($"0x{offset:X}") { Tag = offset });
                }
            }
        }

        UpdatePointerUI();
    }

    private void InitializeComponent()
    {
        Text = "Change Address";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        StartPosition = FormStartPosition.CenterParent;

        const int margin = NexusTheme.Space16;
        const int labelWidth = 60;
        const int contentWidth = 360;
        const int gbMargin = 15;

        _lblAddress = new Label
        {
            Text = "Address:",
            Location = new Point(margin, margin + 6),
            AutoSize = true
        };

        _txtAddress = new TextBox
        {
            Location = new Point(margin + labelWidth + NexusTheme.Space8, margin),
            Size = new Size(200, NexusTheme.TextBoxHeight)
        };
        NexusTheme.StyleTextBox(_txtAddress);

        _chkPointer = new CheckBox
        {
            Text = "Pointer",
            Location = new Point(margin + labelWidth + NexusTheme.Space8 + 200 + NexusTheme.Space16, margin + 3),
            AutoSize = true
        };
        NexusTheme.StyleCheckBox(_chkPointer);
        _chkPointer.CheckedChanged += (s, e) => UpdatePointerUI();

        // Pointer group
        int groupY = margin + NexusTheme.TextBoxHeight + NexusTheme.Space8;
        _grpPointer = new GroupBox
        {
            Text = "Pointer",
            Location = new Point(margin, groupY),
            Size = new Size(contentWidth, 210),
            Visible = false
        };

        _lblBaseAddress = new Label
        {
            Text = "Base:",
            Location = new Point(gbMargin, 28),
            AutoSize = true
        };

        _txtBaseAddress = new TextBox
        {
            Location = new Point(gbMargin + 45, 25),
            Size = new Size(200, NexusTheme.TextBoxHeight)
        };
        NexusTheme.StyleTextBox(_txtBaseAddress);

        var lblOffsets = new Label
        {
            Text = "Offsets (hex):",
            Location = new Point(gbMargin, 58),
            AutoSize = true
        };

        _lvOffsets = new ListView
        {
            Location = new Point(gbMargin, 78),
            Size = new Size(contentWidth - gbMargin - NexusTheme.ButtonWidth - NexusTheme.Space8 - gbMargin, 115),
            View = View.List
        };

        int offsetBtnX = contentWidth - gbMargin - NexusTheme.ButtonWidth;
        _btnAddOffset = new Button
        {
            Text = "Add",
            Location = new Point(offsetBtnX, 78),
            Size = new Size(NexusTheme.ButtonWidth, NexusTheme.ButtonHeight)
        };
        NexusTheme.StyleButton(_btnAddOffset);
        _btnAddOffset.Click += (s, e) => AddOffset();

        _btnRemoveOffset = new Button
        {
            Text = "Remove",
            Location = new Point(offsetBtnX, 78 + NexusTheme.ButtonHeight + NexusTheme.Space8),
            Size = new Size(NexusTheme.ButtonWidth, NexusTheme.ButtonHeight)
        };
        NexusTheme.StyleButton(_btnRemoveOffset);
        _btnRemoveOffset.Click += (s, e) => RemoveOffset();

        _grpPointer.Controls.Add(_lblBaseAddress);
        _grpPointer.Controls.Add(_txtBaseAddress);
        _grpPointer.Controls.Add(lblOffsets);
        _grpPointer.Controls.Add(_lvOffsets);
        _grpPointer.Controls.Add(_btnAddOffset);
        _grpPointer.Controls.Add(_btnRemoveOffset);

        // Buttons - right-aligned
        int buttonY = groupY + 210 + NexusTheme.Space8;
        int buttonX = margin + contentWidth - NexusTheme.ButtonWidth;

        _btnCancel = new Button
        {
            Text = "Cancel",
            Location = new Point(buttonX, buttonY),
            Size = new Size(NexusTheme.ButtonWidth, NexusTheme.ButtonHeight),
            DialogResult = DialogResult.Cancel
        };
        NexusTheme.StyleButton(_btnCancel);
        _btnCancel.Click += (s, e) => Close();

        buttonX -= NexusTheme.ButtonWidth + NexusTheme.ButtonGap;
        _btnOK = new Button
        {
            Text = "OK",
            Location = new Point(buttonX, buttonY),
            Size = new Size(NexusTheme.ButtonWidth, NexusTheme.ButtonHeight),
            DialogResult = DialogResult.OK
        };
        NexusTheme.StylePrimaryButton(_btnOK);
        _btnOK.Click += (s, e) => ApplySettings();

        Controls.Add(_lblAddress);
        Controls.Add(_txtAddress);
        Controls.Add(_chkPointer);
        Controls.Add(_grpPointer);
        Controls.Add(_btnOK);
        Controls.Add(_btnCancel);

        AcceptButton = _btnOK;
        CancelButton = _btnCancel;

        // Start with non-pointer size
        ClientSize = new Size(margin + contentWidth + margin, margin + NexusTheme.TextBoxHeight + NexusTheme.Space16 + NexusTheme.ButtonHeight + margin);
    }

    private void UpdatePointerUI()
    {
        _grpPointer.Visible = _chkPointer.Checked;
        _txtAddress.Enabled = !_chkPointer.Checked;

        const int margin = NexusTheme.Space16;
        const int contentWidth = 360;
        int groupY = margin + NexusTheme.TextBoxHeight + NexusTheme.Space8;

        if (_chkPointer.Checked)
        {
            // Pointer mode - show group and buttons below
            int buttonY = groupY + 210 + NexusTheme.Space8;
            _btnOK.Location = new Point(margin + contentWidth - NexusTheme.ButtonWidth * 2 - NexusTheme.ButtonGap, buttonY);
            _btnCancel.Location = new Point(margin + contentWidth - NexusTheme.ButtonWidth, buttonY);
            ClientSize = new Size(margin + contentWidth + margin, buttonY + NexusTheme.ButtonHeight + margin);
        }
        else
        {
            // Simple mode - buttons right after address row
            int buttonY = margin + NexusTheme.TextBoxHeight + NexusTheme.Space16;
            _btnOK.Location = new Point(margin + contentWidth - NexusTheme.ButtonWidth * 2 - NexusTheme.ButtonGap, buttonY);
            _btnCancel.Location = new Point(margin + contentWidth - NexusTheme.ButtonWidth, buttonY);
            ClientSize = new Size(margin + contentWidth + margin, buttonY + NexusTheme.ButtonHeight + margin);
        }
    }

    private void AddOffset()
    {
        var input = Microsoft.VisualBasic.Interaction.InputBox("Enter offset (hex):", "Add Offset", "0");
        if (string.IsNullOrEmpty(input)) return;

        // Parse as hex
        if (input.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            input = input[2..];

        if (long.TryParse(input, System.Globalization.NumberStyles.HexNumber, null, out var offset))
        {
            _lvOffsets.Items.Add(new ListViewItem($"0x{offset:X}") { Tag = offset });
        }
        else
        {
            MessageBox.Show("Invalid hex value", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void RemoveOffset()
    {
        if (_lvOffsets.SelectedItems.Count > 0)
        {
            _lvOffsets.Items.Remove(_lvOffsets.SelectedItems[0]);
        }
    }

    private void ApplySettings()
    {
        IsPointer = _chkPointer.Checked;

        if (IsPointer)
        {
            BaseAddress = _txtBaseAddress.Text;
            Offsets.Clear();
            foreach (ListViewItem item in _lvOffsets.Items)
            {
                if (item.Tag is long offset)
                    Offsets.Add(offset);
            }

            // Build address representation
            Address = $"[{BaseAddress}";
            foreach (var offset in Offsets)
            {
                Address += offset >= 0 ? $"+{offset:X}" : $"-{-offset:X}";
            }
            Address += "]";
        }
        else
        {
            Address = _txtAddress.Text;
        }
    }
}

/// <summary>
/// Form for adding a new address entry manually.
/// Matches CE's "Add Address Manually" dialog.
/// </summary>
public class AddAddressForm : Form
{
    // Controls
    private Label _lblDescription = null!;
    private TextBox _txtDescription = null!;
    private Label _lblAddress = null!;
    private TextBox _txtAddress = null!;
    private Label _lblType = null!;
    private ComboBox _cboType = null!;
    private CheckBox _chkPointer = null!;
    private GroupBox _grpPointer = null!;
    private TextBox _txtBaseAddress = null!;
    private ListView _lvOffsets = null!;
    private Button _btnAddOffset = null!;
    private Button _btnRemoveOffset = null!;
    private Button _btnOK = null!;
    private Button _btnCancel = null!;

    // Result properties
    public string Description { get; private set; } = "";
    public string Address { get; private set; } = "";
    public NexusValueType ValueType { get; private set; } = NexusValueType.FourBytes;
    public bool IsPointer { get; private set; }
    public string BaseAddress { get; private set; } = "";
    public List<long> Offsets { get; private set; } = new();

    public AddAddressForm()
    {
        InitializeComponent();
        NexusTheme.StyleForm(this);
    }

    private void InitializeComponent()
    {
        Text = "Add Address Manually";
        Size = new Size(450, 410);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        StartPosition = FormStartPosition.CenterParent;

        _lblDescription = new Label
        {
            Text = "Description:",
            Location = new Point(12, 18),
            AutoSize = true
        };

        _txtDescription = new TextBox
        {
            Location = new Point(110, 15),
            Size = new Size(310, NexusTheme.TextBoxHeight)
        };
        NexusTheme.StyleTextBox(_txtDescription);

        _lblAddress = new Label
        {
            Text = "Address:",
            Location = new Point(12, 48),
            AutoSize = true
        };

        _txtAddress = new TextBox
        {
            Location = new Point(100, 45),
            Size = new Size(200, NexusTheme.TextBoxHeight)
        };
        NexusTheme.StyleTextBox(_txtAddress);

        _lblType = new Label
        {
            Text = "Type:",
            Location = new Point(12, 78),
            AutoSize = true
        };

        _cboType = new ComboBox
        {
            Location = new Point(100, 75),
            Size = new Size(150, NexusTheme.ComboBoxHeight),
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        NexusTheme.StyleComboBox(_cboType);
        _cboType.Items.AddRange(new object[]
        {
            "Binary",
            "Byte",
            "2 Bytes",
            "4 Bytes",
            "8 Bytes",
            "Float",
            "Double",
            "String",
            "Array of byte"
        });
        _cboType.SelectedIndex = 3; // 4 Bytes

        _chkPointer = new CheckBox
        {
            Text = "Pointer",
            Location = new Point(260, 77),
            AutoSize = true
        };
        NexusTheme.StyleCheckBox(_chkPointer);
        _chkPointer.CheckedChanged += (s, e) => UpdatePointerUI();

        // Pointer group
        _grpPointer = new GroupBox
        {
            Text = "Pointer Details",
            Location = new Point(12, 110),
            Size = new Size(410, 200),
            Visible = false
        };

        var lblBase = new Label
        {
            Text = "Base Address:",
            Location = new Point(10, 25),
            AutoSize = true
        };

        _txtBaseAddress = new TextBox
        {
            Location = new Point(100, 22),
            Size = new Size(200, NexusTheme.TextBoxHeight)
        };
        NexusTheme.StyleTextBox(_txtBaseAddress);

        var lblOffsets = new Label
        {
            Text = "Offsets:",
            Location = new Point(10, 55),
            AutoSize = true
        };

        _lvOffsets = new ListView
        {
            Location = new Point(10, 75),
            Size = new Size(300, 90),
            View = View.List
        };

        _btnAddOffset = new Button
        {
            Text = "Add",
            Location = new Point(320, 75),
            Size = new Size(NexusTheme.ButtonWidth, NexusTheme.ButtonHeight)
        };
        NexusTheme.StyleButton(_btnAddOffset);
        _btnAddOffset.Click += (s, e) => AddOffset();

        _btnRemoveOffset = new Button
        {
            Text = "Remove",
            Location = new Point(320, 75 + NexusTheme.ButtonHeight + NexusTheme.Space4),
            Size = new Size(NexusTheme.ButtonWidth, NexusTheme.ButtonHeight)
        };
        NexusTheme.StyleButton(_btnRemoveOffset);
        _btnRemoveOffset.Click += (s, e) =>
        {
            if (_lvOffsets.SelectedItems.Count > 0)
                _lvOffsets.Items.Remove(_lvOffsets.SelectedItems[0]);
        };

        _grpPointer.Controls.Add(lblBase);
        _grpPointer.Controls.Add(_txtBaseAddress);
        _grpPointer.Controls.Add(lblOffsets);
        _grpPointer.Controls.Add(_lvOffsets);
        _grpPointer.Controls.Add(_btnAddOffset);
        _grpPointer.Controls.Add(_btnRemoveOffset);

        // Buttons
        int buttonY = 320;
        _btnOK = new Button
        {
            Text = "OK",
            Location = new Point(250, buttonY),
            Size = new Size(NexusTheme.ButtonWidth, NexusTheme.ButtonHeight),
            DialogResult = DialogResult.OK
        };
        NexusTheme.StylePrimaryButton(_btnOK);
        _btnOK.Click += (s, e) => ApplySettings();

        _btnCancel = new Button
        {
            Text = "Cancel",
            Location = new Point(250 + NexusTheme.ButtonWidth + NexusTheme.ButtonGap, buttonY),
            Size = new Size(NexusTheme.ButtonWidth, NexusTheme.ButtonHeight),
            DialogResult = DialogResult.Cancel
        };
        NexusTheme.StyleButton(_btnCancel);
        _btnCancel.Click += (s, e) => Close();

        Controls.Add(_lblDescription);
        Controls.Add(_txtDescription);
        Controls.Add(_lblAddress);
        Controls.Add(_txtAddress);
        Controls.Add(_lblType);
        Controls.Add(_cboType);
        Controls.Add(_chkPointer);
        Controls.Add(_grpPointer);
        Controls.Add(_btnOK);
        Controls.Add(_btnCancel);

        AcceptButton = _btnOK;
        CancelButton = _btnCancel;
    }

    private void UpdatePointerUI()
    {
        _grpPointer.Visible = _chkPointer.Checked;
        _txtAddress.Enabled = !_chkPointer.Checked;
    }

    private void AddOffset()
    {
        var input = Microsoft.VisualBasic.Interaction.InputBox("Enter offset (hex):", "Add Offset", "0");
        if (string.IsNullOrEmpty(input)) return;

        if (input.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            input = input[2..];

        if (long.TryParse(input, System.Globalization.NumberStyles.HexNumber, null, out var offset))
        {
            _lvOffsets.Items.Add(new ListViewItem($"0x{offset:X}") { Tag = offset });
        }
    }

    private void ApplySettings()
    {
        Description = _txtDescription.Text;
        IsPointer = _chkPointer.Checked;

        ValueType = _cboType.SelectedIndex switch
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
            _ => NexusValueType.FourBytes
        };

        if (IsPointer)
        {
            BaseAddress = _txtBaseAddress.Text;
            Offsets.Clear();
            foreach (ListViewItem item in _lvOffsets.Items)
            {
                if (item.Tag is long offset)
                    Offsets.Add(offset);
            }
            // Build address string
            Address = $"[{BaseAddress}";
            foreach (var offset in Offsets)
            {
                Address += offset >= 0 ? $"+{offset:X}" : $"-{-offset:X}";
            }
            Address += "]";
        }
        else
        {
            Address = _txtAddress.Text;
        }
    }
}
