// <file>
// <summary>
// Breakpoint condition editor for conditional breakpoints with expression evaluation.
// </summary>
// </file>
using Nexus.UI.Helpers;
using Nexus.UI.Styles;


namespace Nexus.UI.Forms;

/// <summary>
/// Breakpoint condition type.
/// </summary>
public enum BreakConditionType
{
    Always,
    RegisterEquals,
    RegisterNotEquals,
    RegisterGreater,
    RegisterLess,
    MemoryEquals,
    MemoryChanged,
    HitCount,
    Expression
}

/// <summary>
/// Form to configure conditional breakpoint settings.
/// </summary>
public partial class BreakpointConditionForm : Form
{
    public BreakConditionType ConditionType { get; private set; } = BreakConditionType.Always;
    public string Register { get; private set; } = "RAX";
    public ulong CompareValue { get; private set; }
    public ulong MemoryAddress { get; private set; }
    public int HitCount { get; private set; }
    public string Expression { get; private set; } = "";
    public bool LogOnly { get; private set; }
    public string LogExpression { get; private set; } = "";

    public BreakpointConditionForm()
    {
        InitializeComponent();
        ApplyStyles();
    }

    private void ApplyStyles()
    {
        NexusTheme.StyleForm(this);

        // Ensure GroupBox backgrounds are set first
        gbCondition.BackColor = NexusTheme.BackgroundDark;
        gbLogging.BackColor = NexusTheme.BackgroundDark;

        // Style all controls explicitly (disabled controls need special handling)
        // RadioButtons
        foreach (var rb in new[] { rbAlways, rbRegister, rbMemory, rbHitCount, rbExpression })
        {
            rb.BackColor = NexusTheme.BackgroundDark;
            rb.ForeColor = NexusTheme.TextPrimary;
        }

        // ComboBoxes - ensure display updates after styling
        foreach (var cmb in new[] { cmbRegister, cmbOperator, cmbMemOp })
        {
            cmb.BackColor = NexusTheme.BackgroundControl;
            cmb.ForeColor = NexusTheme.TextPrimary;
        }

        // NumericUpDown
        nudHitCount.BackColor = NexusTheme.BackgroundControl;
        nudHitCount.ForeColor = NexusTheme.TextPrimary;

        // TextBoxes - style each explicitly
        txtRegValue.BackColor = NexusTheme.BackgroundControl;
        txtRegValue.ForeColor = NexusTheme.TextPrimary;
        txtRegValue.BorderStyle = BorderStyle.FixedSingle;

        txtMemAddress.BackColor = NexusTheme.BackgroundControl;
        txtMemAddress.ForeColor = NexusTheme.TextPrimary;
        txtMemAddress.BorderStyle = BorderStyle.FixedSingle;

        txtExpression.BackColor = NexusTheme.BackgroundControl;
        txtExpression.ForeColor = NexusTheme.TextPrimary;
        txtExpression.BorderStyle = BorderStyle.FixedSingle;

        txtLogExpression.BackColor = NexusTheme.BackgroundControl;
        txtLogExpression.ForeColor = NexusTheme.TextPrimary;
        txtLogExpression.BorderStyle = BorderStyle.FixedSingle;

        // Checkbox
        chkLogOnly.BackColor = NexusTheme.BackgroundDark;
        chkLogOnly.ForeColor = NexusTheme.TextPrimary;

        // Style info label
        lblInfo.ForeColor = NexusTheme.TextSecondary;

        // Style buttons
        NexusTheme.StylePrimaryButton(btnOk);
        NexusTheme.StyleButton(btnCancel);
    }

    private void InitializeComponent()
    {
        Text = "Breakpoint Condition";
        Size = new Size(610, 400);
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;

        const int margin = NexusTheme.Space16;
        int y = margin;
        const int rowHeight = 40;  // Height between rows
        const int contentWidth = 493;  // 525 - margin * 2

        // Condition type
        gbCondition = new GroupBox
        {
            Text = "Condition",
            Location = new Point(margin, y),
            Size = new Size(contentWidth, 268)  // Height for 5 rows + expression textbox + 8px padding
        };

        int rowY = 30;  // Starting Y inside groupbox

        // Row 1: Break always
        rbAlways = new RadioButton
        {
            Text = "Break always",
            Location = new Point(15, rowY),
            AutoSize = true,
            Checked = true
        };
        rbAlways.CheckedChanged += Rb_CheckedChanged;

        rowY += rowHeight;

        // Row 2: Register condition
        rbRegister = new RadioButton
        {
            Text = "Register condition:",
            Location = new Point(15, rowY),
            AutoSize = true
        };
        rbRegister.CheckedChanged += Rb_CheckedChanged;

        cmbRegister = new ComboBox
        {
            Location = new Point(210, rowY - 3),
            Size = new Size(80, 25),
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        cmbRegister.Items.AddRange(["RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP",
            "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "RIP"]);
        cmbRegister.SelectedIndex = 0;

        cmbOperator = new ComboBox
        {
            Location = new Point(298, rowY - 3),
            Size = new Size(60, 25),
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        cmbOperator.Items.AddRange(["==", "!=", ">", "<", ">=", "<="]);
        cmbOperator.SelectedIndex = 0;

        txtRegValue = new TextBox
        {
            Location = new Point(366, rowY - 3),
            Size = new Size(112, 25),
            CharacterCasing = CharacterCasing.Upper
        };

        rowY += rowHeight;

        // Row 3: Memory at address
        rbMemory = new RadioButton
        {
            Text = "Memory at address:",
            Location = new Point(15, rowY),
            AutoSize = true
        };
        rbMemory.CheckedChanged += Rb_CheckedChanged;

        txtMemAddress = new TextBox
        {
            Location = new Point(210, rowY - 3),
            Size = new Size(165, 25),
            CharacterCasing = CharacterCasing.Upper
        };

        cmbMemOp = new ComboBox
        {
            Location = new Point(383, rowY - 3),
            Size = new Size(95, 25),
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        cmbMemOp.Items.AddRange(["equals", "changed"]);
        cmbMemOp.SelectedIndex = 0;

        rowY += rowHeight;

        // Row 4: Hit count
        rbHitCount = new RadioButton
        {
            Text = "Hit count reaches:",
            Location = new Point(15, rowY),
            AutoSize = true
        };
        rbHitCount.CheckedChanged += Rb_CheckedChanged;

        nudHitCount = new NumericUpDown
        {
            Location = new Point(210, rowY - 3),
            Size = new Size(90, 25),
            Minimum = 1,
            Maximum = 999999,
            Value = 1
        };

        rowY += rowHeight;

        // Row 5: C# expression
        rbExpression = new RadioButton
        {
            Text = "C# expression:",
            Location = new Point(15, rowY),
            AutoSize = true
        };
        rbExpression.CheckedChanged += Rb_CheckedChanged;

        rowY += 35;  // Gap before textbox

        txtExpression = new TextBox
        {
            Location = new Point(15, rowY),
            Size = new Size(contentWidth - 30, 25),  // 15px margin on each side
            Text = "// Return true to break"
        };

        gbCondition.Controls.AddRange([rbAlways, rbRegister, cmbRegister, cmbOperator, txtRegValue,
            rbMemory, txtMemAddress, cmbMemOp, rbHitCount, nudHitCount, rbExpression, txtExpression]);

        y += 278;  // Account for Condition groupbox

        // Logging options
        gbLogging = new GroupBox
        {
            Text = "Logging",
            Location = new Point(margin, y),
            Size = new Size(contentWidth, 93)
        };

        chkLogOnly = new CheckBox
        {
            Text = "Log without breaking",
            Location = new Point(15, 25),
            AutoSize = true
        };

        var lblLogExpr = new Label
        {
            Text = "Log expression:",
            Location = new Point(15, 53),
            AutoSize = true
        };

        txtLogExpression = new TextBox
        {
            Location = new Point(150, 50),
            Width = contentWidth - 150 - 15,  // 15px right margin
            Text = "$\"Hit at {RIP:X}\""
        };

        gbLogging.Controls.AddRange([chkLogOnly, lblLogExpr, txtLogExpression]);

        y += 103;

        // Info
        lblInfo = new Label
        {
            Text = "Conditions are evaluated using C#. Use register names (RAX, RBX, etc.) " +
                   "and ReadInt(address)/ReadFloat(address) for memory access.",
            Location = new Point(margin, y),
            Size = new Size(contentWidth, 80),
            ForeColor = Color.Gray,
            AutoSize = false
        };

        y += 85;

        // Buttons - right-aligned with margin
        int buttonX = margin + contentWidth - NexusTheme.ButtonWidth;
        btnCancel = new Button
        {
            Text = "Cancel",
            Size = new Size(NexusTheme.ButtonWidth, NexusTheme.ButtonHeight),
            Location = new Point(buttonX, y),
            DialogResult = DialogResult.Cancel
        };
        btnCancel.Click += (s, e) => Close();

        buttonX -= NexusTheme.ButtonWidth + NexusTheme.ButtonGap;
        btnOk = new Button
        {
            Text = "OK",
            Size = new Size(NexusTheme.ButtonWidth, NexusTheme.ButtonHeight),
            Location = new Point(buttonX, y),
            DialogResult = DialogResult.OK
        };
        btnOk.Click += BtnOk_Click;
        btnOk.Click += (s, e) => Close();

        AcceptButton = btnOk;
        CancelButton = btnCancel;

        Controls.AddRange([gbCondition, gbLogging, lblInfo, btnOk, btnCancel]);

        ClientSize = new Size(525, y + NexusTheme.ButtonHeight + margin);
    }

    private void Rb_CheckedChanged(object? sender, EventArgs e)
    {
        // All controls stay enabled for consistent dark theme appearance
        // Values are only used based on which radio button is selected
    }

    private void BtnOk_Click(object? sender, EventArgs e)
    {
        if (rbAlways.Checked)
        {
            ConditionType = BreakConditionType.Always;
        }
        else if (rbRegister.Checked)
        {
            Register = cmbRegister.Text;
            ConditionType = cmbOperator.SelectedIndex switch
            {
                0 => BreakConditionType.RegisterEquals,
                1 => BreakConditionType.RegisterNotEquals,
                2 => BreakConditionType.RegisterGreater,
                3 => BreakConditionType.RegisterLess,
                _ => BreakConditionType.RegisterEquals
            };

            if (!TryParseHex(txtRegValue.Text, out var val))
            {
                MessageBox.Show("Invalid register value.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                DialogResult = DialogResult.None;
                return;
            }
            CompareValue = val;
        }
        else if (rbMemory.Checked)
        {
            if (!TryParseHex(txtMemAddress.Text, out var addr))
            {
                MessageBox.Show("Invalid memory address.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                DialogResult = DialogResult.None;
                return;
            }
            MemoryAddress = addr;
            ConditionType = cmbMemOp.SelectedIndex == 0 ? BreakConditionType.MemoryEquals : BreakConditionType.MemoryChanged;
        }
        else if (rbHitCount.Checked)
        {
            ConditionType = BreakConditionType.HitCount;
            HitCount = (int)nudHitCount.Value;
        }
        else if (rbExpression.Checked)
        {
            ConditionType = BreakConditionType.Expression;
            Expression = txtExpression.Text;
        }

        LogOnly = chkLogOnly.Checked;
        LogExpression = txtLogExpression.Text;
    }

    private static bool TryParseHex(string text, out ulong result)
    {
        text = text.Trim();
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            text = text[2..];
        return ulong.TryParse(text, System.Globalization.NumberStyles.HexNumber, null, out result);
    }

    /// <summary>
    /// Result data from the breakpoint condition dialog.
    /// </summary>
    public record ConditionResult(
        BreakConditionType ConditionType, string Register, ulong CompareValue,
        ulong MemoryAddress, int HitCount, string Expression,
        bool LogOnly, string LogExpression);

    /// <summary>
    /// Shows the breakpoint condition dialog.
    /// </summary>
    public static ConditionResult? ShowCondition(IWin32Window? owner)
    {
        using var form = new BreakpointConditionForm();
        if (form.ShowDialog(owner) == DialogResult.OK)
        {
            return new ConditionResult(
                form.ConditionType, form.Register, form.CompareValue,
                form.MemoryAddress, form.HitCount, form.Expression,
                form.LogOnly, form.LogExpression);
        }
        return null;
    }

    // Controls
    private GroupBox gbCondition = null!;
    private RadioButton rbAlways = null!;
    private RadioButton rbRegister = null!;
    private ComboBox cmbRegister = null!;
    private ComboBox cmbOperator = null!;
    private TextBox txtRegValue = null!;
    private RadioButton rbMemory = null!;
    private TextBox txtMemAddress = null!;
    private ComboBox cmbMemOp = null!;
    private RadioButton rbHitCount = null!;
    private NumericUpDown nudHitCount = null!;
    private RadioButton rbExpression = null!;
    private TextBox txtExpression = null!;
    private GroupBox gbLogging = null!;
    private CheckBox chkLogOnly = null!;
    private TextBox txtLogExpression = null!;
    private Label lblInfo = null!;
    private Button btnOk = null!;
    private Button btnCancel = null!;
}
