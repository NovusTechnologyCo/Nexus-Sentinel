// <file>
// <summary>
// Pointer scanner configuration for scan depth, offset range, and threads.
// </summary>
// </file>
using Nexus.UI.Helpers;
using Nexus.UI.Styles;

namespace Nexus.UI.Forms;

/// <summary>
/// Form to configure pointer scanner settings.
/// </summary>
public partial class PointerScannerSettingsForm : Form
{
    public ulong StartAddress { get; private set; }
    public ulong StopAddress { get; private set; }
    public int MaxLevel { get; private set; } = 5;
    public int MaxOffset { get; private set; } = 4096;
    public bool OnlyPositiveOffsets { get; private set; } = true;
    public bool HeapOnly { get; private set; }
    public bool StackOnly { get; private set; }
    public bool MustStartWithBase { get; private set; } = true;
    public bool MustEndWithSpecificOffset { get; private set; }
    public int SpecificEndOffset { get; private set; }
    public bool UseCompression { get; private set; } = true;
    public int ThreadCount { get; private set; } = Environment.ProcessorCount;

    public PointerScannerSettingsForm()
    {
        InitializeComponent();
        NexusTheme.StyleForm(this);
    }

    private void InitializeComponent()
    {
        Text = "Pointer Scanner Settings";
        Size = new Size(525, 480);
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;

        int y = NexusTheme.DialogPadding;

        // Address range
        gbAddressRange = new GroupBox
        {
            Text = "Address range to scan",
            Location = new Point(NexusTheme.DialogPadding, y),
            Size = new Size(490, 80)
        };

        var lblStart = new Label { Text = "Start:", Location = new Point(15, 28), AutoSize = true };
        txtStart = new TextBox
        {
            Location = new Point(80, 25),
            Width = 150,
            Text = "00000000",
            CharacterCasing = CharacterCasing.Upper
        };
        NexusTheme.StyleTextBox(txtStart);

        var lblStop = new Label { Text = "Stop:", Location = new Point(15, 55), AutoSize = true };
        txtStop = new TextBox
        {
            Location = new Point(80, 52),
            Width = 150,
            Text = "7FFFFFFF",
            CharacterCasing = CharacterCasing.Upper
        };
        NexusTheme.StyleTextBox(txtStop);

        chkHeapOnly = new CheckBox
        {
            Text = "Heap only",
            Location = new Point(250, 28),
            AutoSize = true
        };
        NexusTheme.StyleCheckBox(chkHeapOnly);

        chkStackOnly = new CheckBox
        {
            Text = "Stack only",
            Location = new Point(250, 53),
            AutoSize = true
        };
        NexusTheme.StyleCheckBox(chkStackOnly);

        gbAddressRange.Controls.AddRange([lblStart, txtStart, lblStop, txtStop, chkHeapOnly, chkStackOnly]);

        y += 90;

        // Pointer path settings
        gbPointerPath = new GroupBox
        {
            Text = "Pointer path",
            Location = new Point(10, y),
            Size = new Size(490, 110)
        };

        var lblMaxLevel = new Label { Text = "Max level:", Location = new Point(NexusTheme.Space8 + 7, 25), AutoSize = true };
        nudMaxLevel = new NumericUpDown
        {
            Location = new Point(120, 22),
            Size = new Size(80, NexusTheme.ControlHeight),
            Minimum = 1,
            Maximum = 10,
            Value = 5
        };

        var lblMaxOffset = new Label { Text = "Max offset:", Location = new Point(NexusTheme.Space8 + 7, 55), AutoSize = true };
        nudMaxOffset = new NumericUpDown
        {
            Location = new Point(120, 52),
            Size = new Size(80, NexusTheme.ControlHeight),
            Minimum = 0,
            Maximum = 65536,
            Value = 4096
        };

        chkPositiveOnly = new CheckBox
        {
            Text = "Only positive offsets",
            Location = new Point(220, 25),
            AutoSize = true,
            Checked = true
        };
        NexusTheme.StyleCheckBox(chkPositiveOnly);

        chkMustStartWithBase = new CheckBox
        {
            Text = "Must start with base module",
            Location = new Point(220, 50),
            AutoSize = true,
            Checked = true
        };
        NexusTheme.StyleCheckBox(chkMustStartWithBase);

        chkMustEndWithOffset = new CheckBox
        {
            Text = "Must end with specific offset:",
            Location = new Point(15, 82),
            AutoSize = true
        };
        NexusTheme.StyleCheckBox(chkMustEndWithOffset);
        chkMustEndWithOffset.CheckedChanged += ChkMustEndWithOffset_CheckedChanged;

        nudEndOffset = new NumericUpDown
        {
            Location = new Point(290, 79),
            Size = new Size(90, NexusTheme.ControlHeight),
            Minimum = -65536,
            Maximum = 65536,
            Value = 0,
            Enabled = false
        };

        gbPointerPath.Controls.AddRange([lblMaxLevel, nudMaxLevel, lblMaxOffset, nudMaxOffset,
            chkPositiveOnly, chkMustStartWithBase, chkMustEndWithOffset, nudEndOffset]);

        y += 120;

        // Performance settings
        gbPerformance = new GroupBox
        {
            Text = "Performance",
            Location = new Point(NexusTheme.DialogPadding, y),
            Size = new Size(490, 80)
        };

        var lblThreads = new Label { Text = "Thread count:", Location = new Point(NexusTheme.Space8 + 7, 25), AutoSize = true };
        nudThreads = new NumericUpDown
        {
            Location = new Point(140, 22),
            Size = new Size(80, NexusTheme.ControlHeight),
            Minimum = 1,
            Maximum = 64,
            Value = Environment.ProcessorCount
        };

        chkCompression = new CheckBox
        {
            Text = "Use compression (saves disk space)",
            Location = new Point(15, 52),
            AutoSize = true,
            Checked = true
        };
        NexusTheme.StyleCheckBox(chkCompression);

        gbPerformance.Controls.AddRange([lblThreads, nudThreads, chkCompression]);

        y += 90;

        // File settings
        gbFile = new GroupBox
        {
            Text = "Output file",
            Location = new Point(NexusTheme.DialogPadding, y),
            Size = new Size(490, 60)
        };

        txtOutputFile = new TextBox
        {
            Location = new Point(NexusTheme.Space8 + 7, 25),
            Width = 375,
            Height = NexusTheme.TextBoxHeight
        };
        NexusTheme.StyleTextBox(txtOutputFile);

        btnBrowse = new Button
        {
            Text = "...",
            Location = new Point(395, 24),
            Size = new Size(NexusTheme.ButtonWidth, NexusTheme.ButtonHeight)
        };
        NexusTheme.StyleButton(btnBrowse);
        btnBrowse.Click += BtnBrowse_Click;

        gbFile.Controls.AddRange([txtOutputFile, btnBrowse]);

        y += 70;

        // Buttons
        btnOk = new Button
        {
            Text = "OK",
            Size = new Size(NexusTheme.ButtonWidth, NexusTheme.ButtonHeight),
            Location = new Point(300, y),
            DialogResult = DialogResult.OK
        };
        NexusTheme.StylePrimaryButton(btnOk);
        btnOk.Click += BtnOk_Click;

        btnCancel = new Button
        {
            Text = "Cancel",
            Size = new Size(NexusTheme.ButtonWidth, NexusTheme.ButtonHeight),
            Location = new Point(300 + NexusTheme.ButtonWidth + NexusTheme.ButtonGap, y),
            DialogResult = DialogResult.Cancel
        };
        NexusTheme.StyleButton(btnCancel);
        btnCancel.Click += BtnCancel_Click;

        AcceptButton = btnOk;
        CancelButton = btnCancel;

        Controls.AddRange([gbAddressRange, gbPointerPath, gbPerformance, gbFile, btnOk, btnCancel]);

        ClientSize = new Size(510, y + 45);
    }

    private void ChkMustEndWithOffset_CheckedChanged(object? sender, EventArgs e)
    {
        nudEndOffset.Enabled = chkMustEndWithOffset.Checked;
    }

    private void BtnBrowse_Click(object? sender, EventArgs e)
    {
        using var sfd = new SaveFileDialog
        {
            Title = "Save Pointer Scan Results",
            Filter = "Pointer Table (*.PTR)|*.PTR|All Files (*.*)|*.*",
            DefaultExt = "PTR"
        };

        if (sfd.ShowDialog(this) == DialogResult.OK)
        {
            txtOutputFile.Text = sfd.FileName;
        }
    }

    private void BtnOk_Click(object? sender, EventArgs e)
    {
        // Parse addresses
        if (!TryParseHex(txtStart.Text, out var start) || !TryParseHex(txtStop.Text, out var stop))
        {
            MessageBox.Show("Invalid address format.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        StartAddress = start;
        StopAddress = stop;
        MaxLevel = (int)nudMaxLevel.Value;
        MaxOffset = (int)nudMaxOffset.Value;
        OnlyPositiveOffsets = chkPositiveOnly.Checked;
        HeapOnly = chkHeapOnly.Checked;
        StackOnly = chkStackOnly.Checked;
        MustStartWithBase = chkMustStartWithBase.Checked;
        MustEndWithSpecificOffset = chkMustEndWithOffset.Checked;
        SpecificEndOffset = (int)nudEndOffset.Value;
        UseCompression = chkCompression.Checked;
        ThreadCount = (int)nudThreads.Value;

        DialogResult = DialogResult.OK;
        Close();
    }

    private void BtnCancel_Click(object? sender, EventArgs e)
    {
        DialogResult = DialogResult.Cancel;
        Close();
    }

    private static bool TryParseHex(string text, out ulong result)
    {
        text = text.Trim();
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            text = text[2..];
        return ulong.TryParse(text, System.Globalization.NumberStyles.HexNumber, null, out result);
    }

    /// <summary>
    /// Result data from the pointer scanner settings dialog.
    /// </summary>
    public record SettingsResult(
        ulong StartAddress, ulong StopAddress, int MaxLevel, int MaxOffset,
        bool OnlyPositiveOffsets, bool HeapOnly, bool StackOnly,
        bool MustStartWithBase, bool MustEndWithSpecificOffset, int SpecificEndOffset,
        bool UseCompression, int ThreadCount);

    /// <summary>
    /// Shows the pointer scanner settings dialog.
    /// </summary>
    public static SettingsResult? ShowSettings(IWin32Window? owner)
    {
        using var form = new PointerScannerSettingsForm();
        if (form.ShowDialog(owner) == DialogResult.OK)
        {
            return new SettingsResult(
                form.StartAddress, form.StopAddress, form.MaxLevel, form.MaxOffset,
                form.OnlyPositiveOffsets, form.HeapOnly, form.StackOnly,
                form.MustStartWithBase, form.MustEndWithSpecificOffset, form.SpecificEndOffset,
                form.UseCompression, form.ThreadCount);
        }
        return null;
    }

    // Controls
    private GroupBox gbAddressRange = null!;
    private TextBox txtStart = null!;
    private TextBox txtStop = null!;
    private CheckBox chkHeapOnly = null!;
    private CheckBox chkStackOnly = null!;
    private GroupBox gbPointerPath = null!;
    private NumericUpDown nudMaxLevel = null!;
    private NumericUpDown nudMaxOffset = null!;
    private CheckBox chkPositiveOnly = null!;
    private CheckBox chkMustStartWithBase = null!;
    private CheckBox chkMustEndWithOffset = null!;
    private NumericUpDown nudEndOffset = null!;
    private GroupBox gbPerformance = null!;
    private NumericUpDown nudThreads = null!;
    private CheckBox chkCompression = null!;
    private GroupBox gbFile = null!;
    private TextBox txtOutputFile = null!;
    private Button btnBrowse = null!;
    private Button btnOk = null!;
    private Button btnCancel = null!;
}
