// <file>
// <summary>
// Pointer scan merge settings for combining multiple result sets.
// </summary>
// </file>
using Nexus.UI.Helpers;
using Nexus.UI.Styles;


namespace Nexus.UI.Forms;

/// <summary>
/// Merge operation type.
/// </summary>
public enum PointerMergeOperation
{
    Intersect,      // Only keep pointers that exist in both
    Union,          // Keep all pointers from both
    Subtract        // Remove pointers that exist in second from first
}

/// <summary>
/// Form to configure pointer scan result merge settings.
/// </summary>
public partial class MergePointerScanResultSettingsForm : Form
{
    public PointerMergeOperation MergeOperation => rbIntersect.Checked ? PointerMergeOperation.Intersect :
                                                    rbUnion.Checked ? PointerMergeOperation.Union :
                                                    PointerMergeOperation.Subtract;
    public bool CompareOffsets => chkCompareOffsets.Checked;
    public bool AllowOffsetDifference => chkAllowDifference.Checked;
    public int MaxOffsetDifference => (int)nudMaxDifference.Value;
    public bool MatchModuleName => chkMatchModule.Checked;
    public string OutputFile => txtOutput.Text;

    public MergePointerScanResultSettingsForm()
    {
        InitializeComponent();
        NexusTheme.StyleForm(this);
    }

    private void InitializeComponent()
    {
        Text = "Merge Pointer Scan Results";
        Size = new Size(420, 350);
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;

        int y = 15;

        // Operation group
        gbOperation = new GroupBox
        {
            Text = "Merge operation",
            Location = new Point(10, y),
            Size = new Size(385, 100)
        };

        rbIntersect = new RadioButton
        {
            Text = "Intersect (keep only matching pointers)",
            Location = new Point(15, 22),
            AutoSize = true,
            Checked = true
        };

        rbUnion = new RadioButton
        {
            Text = "Union (combine all pointers)",
            Location = new Point(15, 47),
            AutoSize = true
        };

        rbSubtract = new RadioButton
        {
            Text = "Subtract (remove matching from first)",
            Location = new Point(15, 72),
            AutoSize = true
        };

        gbOperation.Controls.AddRange([rbIntersect, rbUnion, rbSubtract]);

        y += 110;

        // Comparison options
        gbComparison = new GroupBox
        {
            Text = "Comparison options",
            Location = new Point(10, y),
            Size = new Size(385, 105)
        };

        chkCompareOffsets = new CheckBox
        {
            Text = "Compare pointer offsets",
            Location = new Point(15, 25),
            AutoSize = true,
            Checked = true
        };

        chkAllowDifference = new CheckBox
        {
            Text = "Allow offset difference up to:",
            Location = new Point(15, 50),
            AutoSize = true
        };
        chkAllowDifference.CheckedChanged += ChkAllowDifference_CheckedChanged;

        nudMaxDifference = new NumericUpDown
        {
            Location = new Point(290, 48),
            Size = new Size(80, 23),
            Minimum = 0,
            Maximum = 0x10000,
            Value = 0,
            Enabled = false
        };

        chkMatchModule = new CheckBox
        {
            Text = "Match module name",
            Location = new Point(15, 75),
            AutoSize = true,
            Checked = true
        };

        gbComparison.Controls.AddRange([chkCompareOffsets, chkAllowDifference, nudMaxDifference, chkMatchModule]);

        y += 115;

        // Output file
        lblOutput = new Label
        {
            Text = "Output file:",
            Location = new Point(10, y),
            AutoSize = true
        };

        y += 20;

        txtOutput = new TextBox
        {
            Location = new Point(10, y),
            Width = 310
        };

        btnBrowse = new Button
        {
            Text = "...",
            Location = new Point(325, y - 4),
            Size = new Size(40, 32)
        };
        btnBrowse.Click += BtnBrowse_Click;

        y += 40;

        // Buttons
        btnMerge = new Button
        {
            Text = "Merge",
            Size = new Size(80, 32),
            Location = new Point(215, y),
            DialogResult = DialogResult.OK
        };
        btnMerge.Click += BtnMerge_Click;

        btnCancel = new Button
        {
            Text = "Cancel",
            Size = new Size(80, 32),
            Location = new Point(305, y),
            DialogResult = DialogResult.Cancel
        };
        btnCancel.Click += (s, e) => Close();

        AcceptButton = btnMerge;
        CancelButton = btnCancel;

        Controls.AddRange([gbOperation, gbComparison, lblOutput, txtOutput, btnBrowse, btnMerge, btnCancel]);

        ClientSize = new Size(400, y + 35);
    }

    private void ChkAllowDifference_CheckedChanged(object? sender, EventArgs e)
    {
        nudMaxDifference.Enabled = chkAllowDifference.Checked;
    }

    private void BtnBrowse_Click(object? sender, EventArgs e)
    {
        using var sfd = new SaveFileDialog
        {
            Title = "Save Merged Result",
            Filter = "Pointer Table (*.PTR)|*.PTR|All Files (*.*)|*.*",
            DefaultExt = "PTR"
        };

        if (sfd.ShowDialog(this) == DialogResult.OK)
        {
            txtOutput.Text = sfd.FileName;
        }
    }

    private void BtnMerge_Click(object? sender, EventArgs e)
    {
        if (string.IsNullOrWhiteSpace(txtOutput.Text))
        {
            MessageBox.Show("Please specify an output file.", "Error",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
            DialogResult = DialogResult.None;
        }
    }

    /// <summary>
    /// Result data from the merge settings dialog.
    /// </summary>
    public record MergeSettingsResult(
        PointerMergeOperation MergeOperation, bool CompareOffsets,
        bool AllowOffsetDifference, int MaxOffsetDifference,
        bool MatchModuleName, string OutputFile);

    /// <summary>
    /// Shows the merge settings dialog.
    /// </summary>
    public static MergeSettingsResult? ShowSettings(IWin32Window? owner)
    {
        using var form = new MergePointerScanResultSettingsForm();
        if (form.ShowDialog(owner) == DialogResult.OK)
        {
            return new MergeSettingsResult(
                form.MergeOperation, form.CompareOffsets,
                form.AllowOffsetDifference, form.MaxOffsetDifference,
                form.MatchModuleName, form.OutputFile);
        }
        return null;
    }

    // Controls
    private GroupBox gbOperation = null!;
    private RadioButton rbIntersect = null!;
    private RadioButton rbUnion = null!;
    private RadioButton rbSubtract = null!;
    private GroupBox gbComparison = null!;
    private CheckBox chkCompareOffsets = null!;
    private CheckBox chkAllowDifference = null!;
    private NumericUpDown nudMaxDifference = null!;
    private CheckBox chkMatchModule = null!;
    private Label lblOutput = null!;
    private TextBox txtOutput = null!;
    private Button btnBrowse = null!;
    private Button btnMerge = null!;
    private Button btnCancel = null!;
}
