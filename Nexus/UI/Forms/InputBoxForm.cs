// <file>
// <summary>
// Generic input dialog for prompting the user to enter a value.
// </summary>
// </file>
using Nexus.UI.Helpers;
using Nexus.UI.Styles;

namespace Nexus.UI.Forms;

public enum InputType
{
    Text,
    Integer,
    Hex,
    Float,
    Address
}

public partial class InputBoxForm : Form
{
    private InputType _inputType = InputType.Text;
    private string _result = "";

    public string Result => _result;

    /// <summary>
    /// Alias for Result property for backward compatibility.
    /// </summary>
    public string Value => _result;

    public InputBoxForm()
    {
        InitializeComponent();
        NexusTheme.StyleForm(this);
    }

    public InputBoxForm(string title, string prompt, string defaultValue = "",
        InputType inputType = InputType.Text) : this()
    {
        Text = title;
        lblPrompt.Text = prompt;
        txtInput.Text = defaultValue;
        _inputType = inputType;

        // Configure input based on type
        switch (inputType)
        {
            case InputType.Hex:
                lblPrefix.Text = "0x";
                lblPrefix.Visible = true;
                break;
            case InputType.Address:
                lblPrefix.Text = "0x";
                lblPrefix.Visible = true;
                txtInput.MaxLength = 16;
                break;
            case InputType.Integer:
            case InputType.Float:
                lblPrefix.Visible = false;
                break;
            default:
                lblPrefix.Visible = false;
                break;
        }
    }

    private void InitializeComponent()
    {
        Text = "Input";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        StartPosition = FormStartPosition.CenterParent;
        MaximizeBox = false;
        MinimizeBox = false;

        // Prompt label
        lblPrompt = new Label
        {
            Text = "Enter value:",
            Location = new Point(NexusTheme.DialogPadding, NexusTheme.DialogPadding),
            AutoSize = true,
            MaximumSize = new Size(360, 0)
        };

        // Input textbox - position below prompt
        int inputY = NexusTheme.DialogPadding + 20 + NexusTheme.Space8;
        txtInput = new TextBox
        {
            Location = new Point(NexusTheme.DialogPadding, inputY),
            Width = 280,
            Height = NexusTheme.TextBoxHeight,
            Font = new Font("Consolas", 10F)
        };
        NexusTheme.StyleTextBox(txtInput);
        txtInput.KeyDown += TxtInput_KeyDown;
        txtInput.TextChanged += TxtInput_TextChanged;

        // Prefix label (for hex values)
        lblPrefix = new Label
        {
            Text = "0x",
            Location = new Point(NexusTheme.DialogPadding, inputY + 4),
            AutoSize = true,
            Visible = false,
            Font = new Font("Consolas", 10F)
        };

        // Checkbox for hex display
        cbHex = new CheckBox
        {
            Text = "Hex",
            Location = new Point(305, inputY + 5),
            AutoSize = true,
            Visible = false // Can be shown for integer type
        };
        NexusTheme.StyleCheckBox(cbHex);
        cbHex.CheckedChanged += CbHex_CheckedChanged;

        // Button row - position below input with proper spacing
        int buttonY = inputY + NexusTheme.TextBoxHeight + NexusTheme.Space16;
        int formWidth = 350;
        int buttonAreaWidth = NexusTheme.ButtonWidth * 2 + NexusTheme.ButtonGap;
        int buttonX = formWidth - NexusTheme.DialogPadding - buttonAreaWidth;

        // OK button
        btnOk = new Button
        {
            Text = "OK",
            Location = new Point(buttonX, buttonY),
            Size = new Size(NexusTheme.ButtonWidth, NexusTheme.ButtonHeight),
            DialogResult = DialogResult.OK
        };
        NexusTheme.StylePrimaryButton(btnOk);
        btnOk.Click += BtnOk_Click;

        // Cancel button
        btnCancel = new Button
        {
            Text = "Cancel",
            Location = new Point(buttonX + NexusTheme.ButtonWidth + NexusTheme.ButtonGap, buttonY),
            Size = new Size(NexusTheme.ButtonWidth, NexusTheme.ButtonHeight),
            DialogResult = DialogResult.Cancel
        };
        NexusTheme.StyleButton(btnCancel);
        btnCancel.Click += (s, e) => Close();

        AcceptButton = btnOk;
        CancelButton = btnCancel;

        // Set form size based on content
        int formHeight = buttonY + NexusTheme.ButtonHeight + NexusTheme.DialogPadding;
        ClientSize = new Size(formWidth, formHeight);

        Controls.AddRange([lblPrompt, lblPrefix, txtInput, cbHex, btnOk, btnCancel]);

        Load += (s, e) =>
        {
            txtInput.Focus();
            txtInput.SelectAll();
        };
    }

    private void TxtInput_KeyDown(object? sender, KeyEventArgs e)
    {
        // Allow special keys
        if (e.KeyCode == Keys.Enter)
        {
            BtnOk_Click(sender, e);
            e.Handled = true;
        }
    }

    private void TxtInput_TextChanged(object? sender, EventArgs e)
    {
        // Update prefix position if visible
        if (lblPrefix.Visible)
        {
            txtInput.Location = new Point(lblPrefix.Right + 2, txtInput.Location.Y);
        }
    }

    private void CbHex_CheckedChanged(object? sender, EventArgs e)
    {
        lblPrefix.Visible = cbHex.Checked;
        txtInput.Location = cbHex.Checked
            ? new Point(lblPrefix.Right + 2, txtInput.Location.Y)
            : new Point(15, txtInput.Location.Y);
    }

    private void BtnOk_Click(object? sender, EventArgs e)
    {
        // Validate input based on type
        string input = txtInput.Text.Trim();

        try
        {
            switch (_inputType)
            {
                case InputType.Integer:
                    if (cbHex.Checked || input.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                    {
                        input = input.Replace("0x", "").Replace("0X", "");
                        long.Parse(input, System.Globalization.NumberStyles.HexNumber);
                    }
                    else
                    {
                        long.Parse(input);
                    }
                    break;

                case InputType.Hex:
                case InputType.Address:
                    input = input.Replace("0x", "").Replace("0X", "");
                    if (!string.IsNullOrEmpty(input))
                    {
                        ulong.Parse(input, System.Globalization.NumberStyles.HexNumber);
                    }
                    break;

                case InputType.Float:
                    double.Parse(input);
                    break;
            }

            _result = txtInput.Text.Trim();
            DialogResult = DialogResult.OK;
            Close();
        }
        catch (FormatException)
        {
            string expectedType = _inputType switch
            {
                InputType.Integer => "integer",
                InputType.Hex => "hexadecimal",
                InputType.Address => "hexadecimal address",
                InputType.Float => "decimal number",
                _ => "valid value"
            };

            MessageBox.Show($"Please enter a valid {expectedType}.", "Invalid Input",
                MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    /// <summary>
    /// Shows an input dialog and returns the entered value.
    /// </summary>
    public static bool Show(IWin32Window? owner, string title, string prompt,
        out string result, string defaultValue = "", InputType inputType = InputType.Text)
    {
        using var form = new InputBoxForm(title, prompt, defaultValue, inputType);

        if (form.ShowDialog(owner) == DialogResult.OK)
        {
            result = form.Result;
            return true;
        }

        result = "";
        return false;
    }

    /// <summary>
    /// Shows an input dialog for integer values.
    /// </summary>
    public static bool ShowInteger(IWin32Window? owner, string title, string prompt,
        out long result, long defaultValue = 0, bool allowHex = true)
    {
        using var form = new InputBoxForm(title, prompt, defaultValue.ToString(), InputType.Integer);
        if (allowHex)
        {
            form.cbHex.Visible = true;
        }

        if (form.ShowDialog(owner) == DialogResult.OK)
        {
            string input = form.Result.Replace("0x", "").Replace("0X", "");
            if (form.cbHex.Checked)
            {
                result = long.Parse(input, System.Globalization.NumberStyles.HexNumber);
            }
            else
            {
                result = long.Parse(input);
            }
            return true;
        }

        result = 0;
        return false;
    }

    /// <summary>
    /// Shows an input dialog for address values.
    /// </summary>
    public static bool ShowAddress(IWin32Window? owner, string title, string prompt,
        out ulong result, ulong defaultValue = 0)
    {
        string defaultStr = defaultValue != 0 ? $"{defaultValue:X}" : "";
        using var form = new InputBoxForm(title, prompt, defaultStr, InputType.Address);

        if (form.ShowDialog(owner) == DialogResult.OK)
        {
            string input = form.Result.Replace("0x", "").Replace("0X", "").Trim();
            result = ulong.Parse(input, System.Globalization.NumberStyles.HexNumber);
            return true;
        }

        result = 0;
        return false;
    }

    /// <summary>
    /// Shows an input dialog for float values.
    /// </summary>
    public static bool ShowFloat(IWin32Window? owner, string title, string prompt,
        out double result, double defaultValue = 0)
    {
        using var form = new InputBoxForm(title, prompt, defaultValue.ToString("G"), InputType.Float);

        if (form.ShowDialog(owner) == DialogResult.OK)
        {
            result = double.Parse(form.Result);
            return true;
        }

        result = 0;
        return false;
    }

    /// <summary>
    /// Shows an input dialog and returns the result directly (null if cancelled).
    /// This overload provides a simpler API for common use cases.
    /// </summary>
    public static string? Show(string title, string prompt, string defaultValue = "")
    {
        using var form = new InputBoxForm(title, prompt, defaultValue);
        if (form.ShowDialog() == DialogResult.OK)
        {
            return form.Result;
        }
        return null;
    }

    // Controls
    private Label lblPrompt = null!;
    private Label lblPrefix = null!;
    private TextBox txtInput = null!;
    private CheckBox cbHex = null!;
    private Button btnOk = null!;
    private Button btnCancel = null!;
}
