// <file>
// <summary>
// Structure pointer rescan configuration for updating pointer field targets.
// </summary>
// </file>
using Nexus.UI.Helpers;
using Nexus.UI.Styles;


namespace Nexus.UI.Forms;

/// <summary>
/// Struct pointer scan type.
/// </summary>
public enum StructPointerScanType
{
    StringScan,
    PointerScan,
    ValueScan
}

/// <summary>
/// Form to configure structure pointer rescan options.
/// </summary>
public partial class StructPointerRescanForm : Form
{
    public StructPointerScanType ScanType => (StructPointerScanType)cmbType.SelectedIndex;
    public string RegexPattern => txtRegex.Text;
    public bool CaseSensitive => chkCaseSensitive.Checked;
    public bool MustBeStart => chkMustBeStart.Checked;
    public bool PointerInRange => chkPointerInRange.Checked;
    public ulong PointerRangeStart => ParseHex(txtPointerStart.Text);
    public ulong PointerRangeStop => ParseHex(txtPointerStop.Text);
    public bool MustBeSame => rbMustBeSame.Checked;
    public bool MustBeDifferent => rbMustBeDifferent.Checked;

    public StructPointerRescanForm()
    {
        InitializeComponent();
        NexusTheme.StyleForm(this);
    }

    private void InitializeComponent()
    {
        Text = "Rescan structure pointers";
        Size = new Size(350, 280);
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;

        int y = 15;

        // Scan type
        lblType = new Label
        {
            Text = "Scan type:",
            Location = new Point(10, y),
            AutoSize = true
        };

        cmbType = new ComboBox
        {
            Location = new Point(100, y - 3),
            Width = 150,
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        cmbType.Items.AddRange(["String scan", "Pointer scan", "Value scan"]);
        cmbType.SelectedIndex = 0;
        cmbType.SelectedIndexChanged += CmbType_SelectedIndexChanged;

        y += 30;

        // Regex pattern
        lblRegex = new Label
        {
            Text = "Pattern (regex):",
            Location = new Point(10, y),
            AutoSize = true
        };

        txtRegex = new TextBox
        {
            Location = new Point(10, y + 18),
            Width = 315
        };

        y += 50;

        // Case sensitive
        chkCaseSensitive = new CheckBox
        {
            Text = "Case sensitive",
            Location = new Point(10, y),
            AutoSize = true
        };

        chkMustBeStart = new CheckBox
        {
            Text = "Must be at start",
            Location = new Point(130, y),
            AutoSize = true
        };

        y += 30;

        // Pointer range
        chkPointerInRange = new CheckBox
        {
            Text = "Pointer must be in range:",
            Location = new Point(10, y),
            AutoSize = true
        };
        chkPointerInRange.CheckedChanged += ChkPointerInRange_CheckedChanged;

        y += 25;

        txtPointerStart = new TextBox
        {
            Location = new Point(30, y),
            Size = new Size(100, 23),
            Text = "00000000",
            CharacterCasing = CharacterCasing.Upper,
            Enabled = false
        };

        lblAnd = new Label
        {
            Text = "and",
            Location = new Point(135, y + 3),
            AutoSize = true,
            Enabled = false
        };

        txtPointerStop = new TextBox
        {
            Location = new Point(165, y),
            Size = new Size(100, 23),
            Text = "7FFFFFFF",
            CharacterCasing = CharacterCasing.Upper,
            Enabled = false
        };

        y += 35;

        // Value comparison
        gbComparison = new GroupBox
        {
            Text = "Value comparison",
            Location = new Point(10, y),
            Size = new Size(315, 95)
        };

        rbMustBeSame = new RadioButton
        {
            Text = "Must be same",
            Location = new Point(15, 22),
            AutoSize = true
        };

        rbMustBeDifferent = new RadioButton
        {
            Text = "Must be different",
            Location = new Point(15, 47),
            AutoSize = true
        };

        rbDontCare = new RadioButton
        {
            Text = "Don't care",
            Location = new Point(15, 72),
            AutoSize = true,
            Checked = true
        };

        gbComparison.Controls.AddRange([rbMustBeSame, rbMustBeDifferent, rbDontCare]);

        y += 105;

        // Buttons
        btnOk = new Button
        {
            Text = "OK",
            Size = new Size(80, 32),
            Location = new Point(150, y),
            DialogResult = DialogResult.OK
        };
        btnOk.Click += (s, e) => Close();

        btnCancel = new Button
        {
            Text = "Cancel",
            Size = new Size(80, 32),
            Location = new Point(240, y),
            DialogResult = DialogResult.Cancel
        };
        btnCancel.Click += (s, e) => Close();

        AcceptButton = btnOk;
        CancelButton = btnCancel;

        Controls.AddRange([
            lblType, cmbType,
            lblRegex, txtRegex,
            chkCaseSensitive, chkMustBeStart,
            chkPointerInRange, txtPointerStart, lblAnd, txtPointerStop,
            gbComparison,
            btnOk, btnCancel
        ]);

        ClientSize = new Size(335, y + 35);
    }

    private void CmbType_SelectedIndexChanged(object? sender, EventArgs e)
    {
        bool isStringScan = cmbType.SelectedIndex == 0;
        chkCaseSensitive.Enabled = isStringScan;
        chkMustBeStart.Enabled = isStringScan;
        txtRegex.Enabled = isStringScan;
    }

    private void ChkPointerInRange_CheckedChanged(object? sender, EventArgs e)
    {
        bool enabled = chkPointerInRange.Checked;
        txtPointerStart.Enabled = enabled;
        txtPointerStop.Enabled = enabled;
        lblAnd.Enabled = enabled;
    }

    private static ulong ParseHex(string text)
    {
        text = text.Trim();
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            text = text[2..];
        return ulong.TryParse(text, System.Globalization.NumberStyles.HexNumber, null, out var result) ? result : 0;
    }

    /// <summary>
    /// Result data from the struct pointer rescan dialog.
    /// </summary>
    public record RescanResult(
        StructPointerScanType ScanType, string RegexPattern, bool CaseSensitive,
        bool MustBeStart, bool PointerInRange, ulong PointerRangeStart,
        ulong PointerRangeStop, bool MustBeSame, bool MustBeDifferent);

    /// <summary>
    /// Shows the struct pointer rescan dialog.
    /// </summary>
    public static RescanResult? ShowRescan(IWin32Window? owner)
    {
        using var form = new StructPointerRescanForm();
        if (form.ShowDialog(owner) == DialogResult.OK)
        {
            return new RescanResult(
                form.ScanType, form.RegexPattern, form.CaseSensitive,
                form.MustBeStart, form.PointerInRange, form.PointerRangeStart,
                form.PointerRangeStop, form.MustBeSame, form.MustBeDifferent);
        }
        return null;
    }

    // Controls
    private Label lblType = null!;
    private ComboBox cmbType = null!;
    private Label lblRegex = null!;
    private TextBox txtRegex = null!;
    private CheckBox chkCaseSensitive = null!;
    private CheckBox chkMustBeStart = null!;
    private CheckBox chkPointerInRange = null!;
    private TextBox txtPointerStart = null!;
    private Label lblAnd = null!;
    private TextBox txtPointerStop = null!;
    private GroupBox gbComparison = null!;
    private RadioButton rbMustBeSame = null!;
    private RadioButton rbMustBeDifferent = null!;
    private RadioButton rbDontCare = null!;
    private Button btnOk = null!;
    private Button btnCancel = null!;
}
