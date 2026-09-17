// <file>
// <summary>
// Cheat table editor for managing address lists with freeze and value type settings.
// </summary>
// </file>
using System.ComponentModel;
using Nexus.UI.Styles;


namespace Nexus.UI.Forms;

/// <summary>
/// Form for editing cheat table properties and metadata.
/// </summary>
public class TablePropertiesForm : Form
{
    // Controls
    private TabControl _tabControl = null!;
    private TabPage _tabGeneral = null!;
    private TabPage _tabScripts = null!;
    private TabPage _tabMetadata = null!;
    private TextBox _txtTitle = null!;
    private TextBox _txtAuthor = null!;
    private TextBox _txtVersion = null!;
    private TextBox _txtGameVersion = null!;
    private TextBox _txtDescription = null!;
    private TextBox _txtNotes = null!;
#pragma warning disable CS0414 // Assigned for future scripts panel
    private ListView _lvScripts = null!;
#pragma warning restore CS0414
    private RichTextBox _txtScript = null!;
    private Button _btnOK = null!;
    private Button _btnCancel = null!;

    // Data
    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public string TableTitle { get; set; } = "";
    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public string TableAuthor { get; set; } = "Spontaneous";
    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public string TableVersion { get; set; } = "1.0";
    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public string GameVersion { get; set; } = "";
    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public string Description { get; set; } = "";
    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public string Notes { get; set; } = "";
    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public string TableScript { get; set; } = "";

    public TablePropertiesForm()
    {
        InitializeComponent();
        NexusTheme.StyleForm(this);
        LoadData();
    }

    private void InitializeComponent()
    {
        Text = "Table Properties";
        Size = new Size(550, 450);
        StartPosition = FormStartPosition.CenterParent;

        _tabControl = new TabControl
        {
            Dock = DockStyle.Fill
        };

        // General tab
        _tabGeneral = new TabPage("General");
        CreateGeneralTab();
        _tabControl.TabPages.Add(_tabGeneral);

        // Scripts tab
        _tabScripts = new TabPage("C# Script");
        CreateScriptsTab();
        _tabControl.TabPages.Add(_tabScripts);

        // Metadata tab
        _tabMetadata = new TabPage("Notes");
        CreateMetadataTab();
        _tabControl.TabPages.Add(_tabMetadata);

        // Button panel
        var pnlButtons = new Panel
        {
            Dock = DockStyle.Bottom,
            Height = 45
        };

        _btnOK = new Button
        {
            Text = "OK",
            Location = new Point(355, 10),
            Size = new Size(80, 32),
            DialogResult = DialogResult.OK
        };
        _btnOK.Click += (s, e) => SaveData();

        _btnCancel = new Button
        {
            Text = "Cancel",
            Location = new Point(445, 10),
            Size = new Size(80, 32),
            DialogResult = DialogResult.Cancel
        };

        pnlButtons.Controls.Add(_btnOK);
        pnlButtons.Controls.Add(_btnCancel);

        Controls.Add(_tabControl);
        Controls.Add(pnlButtons);
        AcceptButton = _btnOK;
        CancelButton = _btnCancel;
    }

    private void CreateGeneralTab()
    {
        var lblTitle = new Label
        {
            Text = "Table Title:",
            Location = new Point(15, 20),
            AutoSize = true
        };
        _txtTitle = new TextBox
        {
            Location = new Point(120, 17),
            Size = new Size(380, 23)
        };

        var lblAuthor = new Label
        {
            Text = "Author:",
            Location = new Point(15, 50),
            AutoSize = true
        };
        _txtAuthor = new TextBox
        {
            Location = new Point(120, 47),
            Size = new Size(200, 23)
        };

        var lblVersion = new Label
        {
            Text = "Table Version:",
            Location = new Point(15, 80),
            AutoSize = true
        };
        _txtVersion = new TextBox
        {
            Location = new Point(135, 77),
            Size = new Size(100, 23)
        };

        var lblGameVer = new Label
        {
            Text = "Game Version:",
            Location = new Point(15, 110),
            AutoSize = true
        };
        _txtGameVersion = new TextBox
        {
            Location = new Point(140, 107),
            Size = new Size(200, 23)
        };

        var lblDesc = new Label
        {
            Text = "Description:",
            Location = new Point(15, 145),
            AutoSize = true
        };
        _txtDescription = new TextBox
        {
            Location = new Point(120, 142),
            Size = new Size(380, 180),
            Multiline = true,
            ScrollBars = ScrollBars.Vertical
        };

        _tabGeneral.Controls.Add(lblTitle);
        _tabGeneral.Controls.Add(_txtTitle);
        _tabGeneral.Controls.Add(lblAuthor);
        _tabGeneral.Controls.Add(_txtAuthor);
        _tabGeneral.Controls.Add(lblVersion);
        _tabGeneral.Controls.Add(_txtVersion);
        _tabGeneral.Controls.Add(lblGameVer);
        _tabGeneral.Controls.Add(_txtGameVersion);
        _tabGeneral.Controls.Add(lblDesc);
        _tabGeneral.Controls.Add(_txtDescription);
    }

    private void CreateScriptsTab()
    {
        var lblInfo = new Label
        {
            Text = "C# script that runs when the table is loaded:",
            Location = new Point(10, 10),
            AutoSize = true
        };

        _txtScript = new RichTextBox
        {
            Location = new Point(10, 35),
            Size = new Size(500, 300),
            Font = new Font("Consolas", 10),
            WordWrap = false
        };

        _tabScripts.Controls.Add(lblInfo);
        _tabScripts.Controls.Add(_txtScript);
    }

    private void CreateMetadataTab()
    {
        var lblNotes = new Label
        {
            Text = "Additional notes (not visible to users):",
            Location = new Point(10, 10),
            AutoSize = true
        };

        _txtNotes = new TextBox
        {
            Location = new Point(10, 35),
            Size = new Size(500, 300),
            Multiline = true,
            ScrollBars = ScrollBars.Both
        };

        _tabMetadata.Controls.Add(lblNotes);
        _tabMetadata.Controls.Add(_txtNotes);
    }

    private void LoadData()
    {
        _txtTitle.Text = TableTitle;
        _txtAuthor.Text = TableAuthor;
        _txtVersion.Text = TableVersion;
        _txtGameVersion.Text = GameVersion;
        _txtDescription.Text = Description;
        _txtNotes.Text = Notes;
        _txtScript.Text = TableScript;
    }

    private void SaveData()
    {
        TableTitle = _txtTitle.Text;
        TableAuthor = _txtAuthor.Text;
        TableVersion = _txtVersion.Text;
        GameVersion = _txtGameVersion.Text;
        Description = _txtDescription.Text;
        Notes = _txtNotes.Text;
        TableScript = _txtScript.Text;
    }
}

/// <summary>
/// Form for adding/editing a memory record in a cheat table.
/// </summary>
public class MemoryRecordForm : Form
{
    private TextBox _txtDescription = null!;
    private TextBox _txtAddress = null!;
    private ComboBox _cboValueType = null!;
#pragma warning disable CS0414 // Assigned for value display/edit
    private TextBox _txtValue = null!;
#pragma warning restore CS0414
    private CheckBox _chkPointer = null!;
    private Panel _pnlOffsets = null!;
    private DataGridView _dgvOffsets = null!;
    private Button _btnAddOffset = null!;
    private Button _btnRemoveOffset = null!;
    private CheckBox _chkActive = null!;
    private GroupBox _grpHotkey = null!;
    private TextBox _txtHotkey = null!;
    private ComboBox _cboHotkeyAction = null!;
    private TextBox _txtHotkeyValue = null!;
    private Button _btnOK = null!;
    private Button _btnCancel = null!;

    // Data
    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public string RecordDescription { get; set; } = "New Entry";
    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public string Address { get; set; } = "00000000";
    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public int ValueType { get; set; } = 3; // 4 bytes
    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public List<long> Offsets { get; set; } = [];
    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public bool IsPointer { get; set; }
    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public bool IsActive { get; set; }

    public MemoryRecordForm()
    {
        InitializeComponent();
        NexusTheme.StyleForm(this);
        LoadData();
    }

    private void InitializeComponent()
    {
        Text = "Memory Record";
        Size = new Size(450, 500);
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;

        var lblDesc = new Label
        {
            Text = "Description:",
            Location = new Point(15, 20),
            AutoSize = true
        };
        _txtDescription = new TextBox
        {
            Location = new Point(100, 17),
            Size = new Size(320, 23)
        };

        var lblAddr = new Label
        {
            Text = "Address:",
            Location = new Point(15, 50),
            AutoSize = true
        };
        _txtAddress = new TextBox
        {
            Location = new Point(100, 47),
            Size = new Size(150, 23)
        };

        var lblType = new Label
        {
            Text = "Type:",
            Location = new Point(15, 80),
            AutoSize = true
        };
        _cboValueType = new ComboBox
        {
            Location = new Point(100, 77),
            Size = new Size(150, 23),
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        _cboValueType.Items.AddRange(new object[]
        {
            "Byte",
            "2 Bytes",
            "4 Bytes",
            "8 Bytes",
            "Float",
            "Double",
            "String",
            "Array of Bytes"
        });
        _cboValueType.SelectedIndex = 2;

        _chkActive = new CheckBox
        {
            Text = "Active (frozen)",
            Location = new Point(270, 79),
            AutoSize = true
        };

        // Pointer section
        _chkPointer = new CheckBox
        {
            Text = "Pointer",
            Location = new Point(15, 110),
            AutoSize = true
        };
        _chkPointer.CheckedChanged += ChkPointer_CheckedChanged;

        _pnlOffsets = new Panel
        {
            Location = new Point(15, 135),
            Size = new Size(400, 150),
            Visible = false
        };

        var lblBase = new Label
        {
            Text = "Base address or module+offset (e.g., game.exe+1A2B3C):",
            Location = new Point(0, 0),
            AutoSize = true
        };

        _dgvOffsets = new DataGridView
        {
            Location = new Point(0, 25),
            Size = new Size(300, 90),
            AllowUserToAddRows = true,
            RowHeadersVisible = false,
            ColumnHeadersVisible = false
        };
        _dgvOffsets.Columns.Add("Offset", "Offset");
        _dgvOffsets.Columns[0].Width = 280;

        _btnAddOffset = new Button
        {
            Text = "Add",
            Location = new Point(310, 25),
            Width = 80
        };
        _btnAddOffset.Click += (s, e) => _dgvOffsets.Rows.Add("0");

        _btnRemoveOffset = new Button
        {
            Text = "Remove",
            Location = new Point(310, 60),
            Width = 80
        };
        _btnRemoveOffset.Click += (s, e) =>
        {
            if (_dgvOffsets.CurrentRow != null && !_dgvOffsets.CurrentRow.IsNewRow)
                _dgvOffsets.Rows.Remove(_dgvOffsets.CurrentRow);
        };

        _pnlOffsets.Controls.Add(lblBase);
        _pnlOffsets.Controls.Add(_dgvOffsets);
        _pnlOffsets.Controls.Add(_btnAddOffset);
        _pnlOffsets.Controls.Add(_btnRemoveOffset);

        // Hotkey section
        _grpHotkey = new GroupBox
        {
            Text = "Hotkey",
            Location = new Point(15, 295),
            Size = new Size(400, 100)
        };

        var lblHotkey = new Label
        {
            Text = "Key:",
            Location = new Point(15, 25),
            AutoSize = true
        };
        _txtHotkey = new TextBox
        {
            Location = new Point(60, 22),
            Size = new Size(120, 23),
            Text = "None",
            ReadOnly = true
        };
        _txtHotkey.KeyDown += TxtHotkey_KeyDown;

        var lblAction = new Label
        {
            Text = "Action:",
            Location = new Point(15, 55),
            AutoSize = true
        };
        _cboHotkeyAction = new ComboBox
        {
            Location = new Point(60, 52),
            Size = new Size(150, 23),
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        _cboHotkeyAction.Items.AddRange(new object[]
        {
            "Toggle Active",
            "Set to Value",
            "Increase by",
            "Decrease by"
        });
        _cboHotkeyAction.SelectedIndex = 0;

        var lblValue = new Label
        {
            Text = "Value:",
            Location = new Point(220, 55),
            AutoSize = true
        };
        _txtHotkeyValue = new TextBox
        {
            Location = new Point(265, 52),
            Size = new Size(120, 23)
        };

        _grpHotkey.Controls.Add(lblHotkey);
        _grpHotkey.Controls.Add(_txtHotkey);
        _grpHotkey.Controls.Add(lblAction);
        _grpHotkey.Controls.Add(_cboHotkeyAction);
        _grpHotkey.Controls.Add(lblValue);
        _grpHotkey.Controls.Add(_txtHotkeyValue);

        // Buttons
        _btnOK = new Button
        {
            Text = "OK",
            Location = new Point(255, 420),
            Size = new Size(80, 32),
            DialogResult = DialogResult.OK
        };
        _btnOK.Click += (s, e) => SaveData();

        _btnCancel = new Button
        {
            Text = "Cancel",
            Location = new Point(345, 420),
            Size = new Size(80, 32),
            DialogResult = DialogResult.Cancel
        };

        Controls.Add(lblDesc);
        Controls.Add(_txtDescription);
        Controls.Add(lblAddr);
        Controls.Add(_txtAddress);
        Controls.Add(lblType);
        Controls.Add(_cboValueType);
        Controls.Add(_chkActive);
        Controls.Add(_chkPointer);
        Controls.Add(_pnlOffsets);
        Controls.Add(_grpHotkey);
        Controls.Add(_btnOK);
        Controls.Add(_btnCancel);
        AcceptButton = _btnOK;
        CancelButton = _btnCancel;
    }

    private void ChkPointer_CheckedChanged(object? sender, EventArgs e)
    {
        _pnlOffsets.Visible = _chkPointer.Checked;

        // Adjust hotkey group position
        if (_chkPointer.Checked)
        {
            _grpHotkey.Location = new Point(15, 295);
        }
        else
        {
            _grpHotkey.Location = new Point(15, 145);
        }
    }

    private void TxtHotkey_KeyDown(object? sender, KeyEventArgs e)
    {
        e.Handled = true;
        e.SuppressKeyPress = true;

        if (e.KeyCode == Keys.Escape)
        {
            _txtHotkey.Text = "None";
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

    private void LoadData()
    {
        _txtDescription.Text = RecordDescription;
        _txtAddress.Text = Address;
        _cboValueType.SelectedIndex = ValueType;
        _chkPointer.Checked = IsPointer;
        _chkActive.Checked = IsActive;

        foreach (var offset in Offsets)
        {
            _dgvOffsets.Rows.Add($"0x{offset:X}");
        }
    }

    private void SaveData()
    {
        RecordDescription = _txtDescription.Text;
        Address = _txtAddress.Text;
        ValueType = _cboValueType.SelectedIndex;
        IsPointer = _chkPointer.Checked;
        IsActive = _chkActive.Checked;

        Offsets.Clear();
        foreach (DataGridViewRow row in _dgvOffsets.Rows)
        {
            if (row.IsNewRow) continue;
            var value = row.Cells[0].Value?.ToString() ?? "0";
            value = value.Replace("0x", "").Replace("0X", "");
            if (long.TryParse(value, System.Globalization.NumberStyles.HexNumber, null, out var offset))
            {
                Offsets.Add(offset);
            }
        }
    }
}
