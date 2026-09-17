// <file>
// <summary>
// Group editing and table import/export dialog forms for the cheat table system.
// </summary>
// </file>
using System.ComponentModel;
using Nexus.UI.Styles;


namespace Nexus.UI.Forms;

/// <summary>
/// Form for creating groups in a cheat table.
/// </summary>
public class GroupForm : Form
{
    private TextBox _txtName = null!;
    private TextBox _txtDescription = null!;
    private CheckBox _chkExpandedDefault = null!;
    private Button _btnOK = null!;
    private Button _btnCancel = null!;

    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public string GroupName { get; set; } = "New Group";
    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public string GroupDescription { get; set; } = "";
    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public bool ExpandedByDefault { get; set; } = true;

    public GroupForm()
    {
        InitializeComponent();
        NexusTheme.StyleForm(this);
        LoadData();
    }

    private void InitializeComponent()
    {
        Text = "Edit Group";
        Size = new Size(400, 200);
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;

        var lblName = new Label
        {
            Text = "Group Name:",
            Location = new Point(15, 20),
            AutoSize = true
        };
        _txtName = new TextBox
        {
            Location = new Point(110, 17),
            Size = new Size(250, 23)
        };

        var lblDesc = new Label
        {
            Text = "Description:",
            Location = new Point(15, 55),
            AutoSize = true
        };
        _txtDescription = new TextBox
        {
            Location = new Point(110, 52),
            Size = new Size(250, 50),
            Multiline = true
        };

        _chkExpandedDefault = new CheckBox
        {
            Text = "Expanded by default",
            Location = new Point(110, 110),
            AutoSize = true,
            Checked = true
        };

        _btnOK = new Button
        {
            Text = "OK",
            Location = new Point(200, 140),
            Size = new Size(80, 32),
            DialogResult = DialogResult.OK
        };
        _btnOK.Click += (s, e) => SaveData();

        _btnCancel = new Button
        {
            Text = "Cancel",
            Location = new Point(290, 140),
            Size = new Size(80, 32),
            DialogResult = DialogResult.Cancel
        };

        Controls.Add(lblName);
        Controls.Add(_txtName);
        Controls.Add(lblDesc);
        Controls.Add(_txtDescription);
        Controls.Add(_chkExpandedDefault);
        Controls.Add(_btnOK);
        Controls.Add(_btnCancel);
        AcceptButton = _btnOK;
        CancelButton = _btnCancel;
    }

    private void LoadData()
    {
        _txtName.Text = GroupName;
        _txtDescription.Text = GroupDescription;
        _chkExpandedDefault.Checked = ExpandedByDefault;
    }

    private void SaveData()
    {
        GroupName = _txtName.Text;
        GroupDescription = _txtDescription.Text;
        ExpandedByDefault = _chkExpandedDefault.Checked;
    }
}

/// <summary>
/// Form for importing/exporting cheat tables.
/// </summary>
public class TableImportExportForm : Form
{
    private RadioButton _rbImport = null!;
    private RadioButton _rbExport = null!;
    private ComboBox _cboFormat = null!;
    private TextBox _txtFilePath = null!;
    private Button _btnBrowse = null!;
    private CheckBox _chkIncludeScripts = null!;
    private CheckBox _chkIncludeGroups = null!;
    private CheckBox _chkIncludeRecords = null!;
    private Button _btnExecute = null!;
    private Button _btnCancel = null!;

    public bool IsImport => _rbImport.Checked;
    public string FilePath => _txtFilePath.Text;
    public string Format => _cboFormat.SelectedItem?.ToString() ?? "NST";

    public TableImportExportForm(bool isImport = true)
    {
        InitializeComponent();
        NexusTheme.StyleForm(this);
        if (isImport)
            _rbImport.Checked = true;
        else
            _rbExport.Checked = true;
    }

    private void InitializeComponent()
    {
        Text = "Import/Export Table";
        Size = new Size(500, 280);
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;

        var grpMode = new GroupBox
        {
            Text = "Mode",
            Location = new Point(15, 10),
            Size = new Size(450, 55)
        };

        _rbImport = new RadioButton
        {
            Text = "Import",
            Location = new Point(15, 22),
            AutoSize = true,
            Checked = true
        };

        _rbExport = new RadioButton
        {
            Text = "Export",
            Location = new Point(100, 22),
            AutoSize = true
        };

        grpMode.Controls.Add(_rbImport);
        grpMode.Controls.Add(_rbExport);

        var lblFormat = new Label
        {
            Text = "Format:",
            Location = new Point(15, 80),
            AutoSize = true
        };
        _cboFormat = new ComboBox
        {
            Location = new Point(80, 77),
            Size = new Size(150, 23),
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        _cboFormat.Items.AddRange(new object[]
        {
            "NST (Nexus Table)",
            "JSON",
            "XML"
        });
        _cboFormat.SelectedIndex = 0;

        var lblFile = new Label
        {
            Text = "File:",
            Location = new Point(15, 115),
            AutoSize = true
        };
        _txtFilePath = new TextBox
        {
            Location = new Point(80, 112),
            Size = new Size(300, 23)
        };
        _btnBrowse = new Button
        {
            Text = "...",
            Location = new Point(390, 111),
            Width = 40
        };
        _btnBrowse.Click += BtnBrowse_Click;

        _chkIncludeRecords = new CheckBox
        {
            Text = "Include memory records",
            Location = new Point(80, 145),
            AutoSize = true,
            Checked = true
        };

        _chkIncludeGroups = new CheckBox
        {
            Text = "Include groups",
            Location = new Point(80, 170),
            AutoSize = true,
            Checked = true
        };

        _chkIncludeScripts = new CheckBox
        {
            Text = "Include scripts",
            Location = new Point(80, 195),
            AutoSize = true,
            Checked = true
        };

        _btnExecute = new Button
        {
            Text = "Execute",
            Location = new Point(300, 220),
            Size = new Size(80, 32),
            DialogResult = DialogResult.OK
        };

        _btnCancel = new Button
        {
            Text = "Cancel",
            Location = new Point(390, 220),
            Size = new Size(80, 32),
            DialogResult = DialogResult.Cancel
        };

        Controls.Add(grpMode);
        Controls.Add(lblFormat);
        Controls.Add(_cboFormat);
        Controls.Add(lblFile);
        Controls.Add(_txtFilePath);
        Controls.Add(_btnBrowse);
        Controls.Add(_chkIncludeRecords);
        Controls.Add(_chkIncludeGroups);
        Controls.Add(_chkIncludeScripts);
        Controls.Add(_btnExecute);
        Controls.Add(_btnCancel);
        AcceptButton = _btnExecute;
        CancelButton = _btnCancel;
    }

    private void BtnBrowse_Click(object? sender, EventArgs e)
    {
        if (_rbImport.Checked)
        {
            using var ofd = new OpenFileDialog
            {
                Filter = "Nexus Tables (*.nst)|*.nst|JSON Files (*.json)|*.json|All Files (*.*)|*.*",
                Title = "Import Table"
            };

            if (ofd.ShowDialog() == DialogResult.OK)
            {
                _txtFilePath.Text = ofd.FileName;
            }
        }
        else
        {
            using var sfd = new SaveFileDialog
            {
                Filter = "Nexus Tables (*.nst)|*.nst|JSON Files (*.json)|*.json|All Files (*.*)|*.*",
                Title = "Export Table"
            };

            if (sfd.ShowDialog() == DialogResult.OK)
            {
                _txtFilePath.Text = sfd.FileName;
            }
        }
    }
}
