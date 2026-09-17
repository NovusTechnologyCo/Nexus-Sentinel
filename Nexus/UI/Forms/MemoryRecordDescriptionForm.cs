// <file>
// <summary>
// Memory record editor for changing saved address description and value type.
// </summary>
// </file>
using Nexus.UI.Helpers;
using Nexus.UI.Styles;


namespace Nexus.UI.Forms;

/// <summary>
/// Form to edit memory record description and display settings.
/// </summary>
public partial class MemoryRecordDescriptionForm : Form
{
    public string Description => txtDescription.Text;
    public bool ShowAsHex => chkShowHex.Checked;
    public bool ShowAsSigned => chkSigned.Checked;
    public string DisplayType => cmbDisplayType.Text;
    public Color TextColor { get; private set; } = Color.Black;

    public MemoryRecordDescriptionForm()
    {
        InitializeComponent();
        NexusTheme.StyleForm(this);
    }

    public MemoryRecordDescriptionForm(string description, bool showAsHex = false, bool signed = false) : this()
    {
        txtDescription.Text = description;
        chkShowHex.Checked = showAsHex;
        chkSigned.Checked = signed;
    }

    private void InitializeComponent()
    {
        Text = "Change description";
        Size = new Size(530, 250);
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;

        int y = 15;

        // Description
        var lblDescription = new Label
        {
            Text = "Description:",
            Location = new Point(15, y),
            AutoSize = true
        };

        y += 25;

        txtDescription = new TextBox
        {
            Location = new Point(15, y),
            Width = 485
        };

        y += 35;

        // Display options
        gbDisplay = new GroupBox
        {
            Text = "Display options",
            Location = new Point(15, y),
            Size = new Size(485, 100)
        };

        chkShowHex = new CheckBox
        {
            Text = "Show as hexadecimal",
            Location = new Point(15, 22),
            AutoSize = true
        };

        chkSigned = new CheckBox
        {
            Text = "Show as signed",
            Location = new Point(15, 50),
            AutoSize = true
        };

        var lblDisplayType = new Label
        {
            Text = "Display type:",
            Location = new Point(220, 22),
            AutoSize = true
        };

        cmbDisplayType = new ComboBox
        {
            Location = new Point(340, 19),
            Size = new Size(120, 32),
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        cmbDisplayType.Items.AddRange(["Default", "Byte", "2 Bytes", "4 Bytes", "8 Bytes", "Float", "Double"]);
        cmbDisplayType.SelectedIndex = 0;

        btnColor = new Button
        {
            Text = "Text Color...",
            Location = new Point(300, 60),
            Size = new Size(100, 32)
        };
        btnColor.Click += BtnColor_Click;

        pnlColorPreview = new Panel
        {
            Location = new Point(410, 65),
            Size = new Size(50, 23),
            BorderStyle = BorderStyle.FixedSingle,
            BackColor = Color.Black
        };

        gbDisplay.Controls.AddRange([chkShowHex, chkSigned, lblDisplayType, cmbDisplayType, btnColor, pnlColorPreview]);

        y += 110;

        // Buttons
        btnOk = new Button
        {
            Text = "OK",
            Size = new Size(80, 32),
            Location = new Point(330, y),
            DialogResult = DialogResult.OK
        };
        btnOk.Click += (s, e) => Close();

        btnCancel = new Button
        {
            Text = "Cancel",
            Size = new Size(80, 32),
            Location = new Point(420, y),
            DialogResult = DialogResult.Cancel
        };
        btnCancel.Click += (s, e) => Close();

        AcceptButton = btnOk;
        CancelButton = btnCancel;

        Controls.AddRange([lblDescription, txtDescription, gbDisplay, btnOk, btnCancel]);

        ClientSize = new Size(515, y + 40);
    }

    protected override void OnShown(EventArgs e)
    {
        base.OnShown(e);
        txtDescription.Focus();
        txtDescription.SelectAll();
    }

    private void BtnColor_Click(object? sender, EventArgs e)
    {
        using var colorDialog = new ColorDialog { Color = TextColor };
        if (colorDialog.ShowDialog(this) == DialogResult.OK)
        {
            TextColor = colorDialog.Color;
            pnlColorPreview.BackColor = TextColor;
        }
    }

    /// <summary>
    /// Shows the description editor dialog.
    /// </summary>
    public static MemoryRecordDescriptionForm? ShowEditor(IWin32Window? owner,
        string description, bool showAsHex = false, bool signed = false)
    {
        using var form = new MemoryRecordDescriptionForm(description, showAsHex, signed);
        if (form.ShowDialog(owner) == DialogResult.OK)
        {
            return form;
        }
        return null;
    }

    // Controls
    private TextBox txtDescription = null!;
    private GroupBox gbDisplay = null!;
    private CheckBox chkShowHex = null!;
    private CheckBox chkSigned = null!;
    private ComboBox cmbDisplayType = null!;
    private Button btnColor = null!;
    private Panel pnlColorPreview = null!;
    private Button btnOk = null!;
    private Button btnCancel = null!;
}
