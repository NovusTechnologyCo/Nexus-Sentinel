// <file>
// <summary>
// Address navigation dialog for jumping to a specific address.
// </summary>
// </file>
using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using Nexus.UI.Styles;

namespace Nexus.UI.Forms;

/// <summary>
/// Form to enter an address to navigate to.
/// </summary>
public partial class GotoAddressForm : Form
{
    private readonly List<ulong> _history = [];
    private readonly IntPtr _processHandle;

    public ulong Address { get; private set; }

    public GotoAddressForm()
    {
        InitializeComponent();
        NexusTheme.StyleForm(this);
    }

    public GotoAddressForm(IntPtr processHandle, ulong currentAddress = 0) : this()
    {
        _processHandle = processHandle;
        if (currentAddress != 0)
        {
            cmbAddress.Text = $"{currentAddress:X}";
        }
    }

    private void InitializeComponent()
    {
        Text = "Go to Address";
        Size = new Size(455, 240);
        MinimumSize = new Size(455, 240);
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;

        // Address input
        var lblAddress = new Label
        {
            Text = "Enter address or expression:",
            Location = new Point(NexusTheme.DialogPadding, NexusTheme.DialogPadding),
            AutoSize = true
        };

        cmbAddress = new ComboBox
        {
            Location = new Point(NexusTheme.DialogPadding, NexusTheme.DialogPadding + 33),
            Width = 355,
            Height = NexusTheme.ComboBoxHeight,
            Font = new Font("Consolas", 10F)
        };
        NexusTheme.StyleComboBox(cmbAddress);

        // Examples
        lblExamples = new Label
        {
            Text = "Examples: 12345678, game.exe+1234, [RAX+10],\nReadInteger(address), [[ptr]+offset]",
            Location = new Point(NexusTheme.DialogPadding, NexusTheme.DialogPadding + 33 + NexusTheme.ComboBoxHeight + NexusTheme.Space8),
            Size = new Size(420, 50),
            AutoSize = false,
            ForeColor = Color.Gray
        };

        int buttonY = NexusTheme.DialogPadding + 33 + NexusTheme.ComboBoxHeight + NexusTheme.Space8 + 55;

        // Buttons
        btnOk = new Button
        {
            Text = "OK",
            Size = new Size(NexusTheme.ButtonWidth, NexusTheme.ButtonHeight),
            Location = new Point(200, buttonY),
            DialogResult = DialogResult.OK
        };
        NexusTheme.StylePrimaryButton(btnOk);
        btnOk.Click += BtnOk_Click;

        btnCancel = new Button
        {
            Text = "Cancel",
            Size = new Size(NexusTheme.ButtonWidth, NexusTheme.ButtonHeight),
            Location = new Point(200 + NexusTheme.ButtonWidth + NexusTheme.ButtonGap, buttonY),
            DialogResult = DialogResult.Cancel
        };
        NexusTheme.StyleButton(btnCancel);
        btnCancel.Click += (s, e) => Close();

        AcceptButton = btnOk;
        CancelButton = btnCancel;

        Controls.AddRange([lblAddress, cmbAddress, lblExamples, btnOk, btnCancel]);
    }

    protected override void OnShown(EventArgs e)
    {
        base.OnShown(e);

        // Load history into combo box
        foreach (var addr in _history)
        {
            cmbAddress.Items.Add($"{addr:X}");
        }

        cmbAddress.Focus();
        cmbAddress.SelectAll();
    }

    private void BtnOk_Click(object? sender, EventArgs e)
    {
        string input = cmbAddress.Text.Trim();
        if (string.IsNullOrEmpty(input))
        {
            MessageBox.Show("Please enter an address.", "Error",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
            DialogResult = DialogResult.None;
            return;
        }

        // Try to parse as simple hex address first
        if (TryParseAddress(input, out var address))
        {
            Address = address;

            // Add to history
            if (!_history.Contains(address))
            {
                _history.Insert(0, address);
                if (_history.Count > 20)
                    _history.RemoveAt(_history.Count - 1);
            }
            DialogResult = DialogResult.OK;
            Close();
            return;
        }

        // Try module+offset format (e.g., "game.exe+1234")
        if (input.Contains('+') && _processHandle != IntPtr.Zero)
        {
            var parts = input.Split('+', 2);
            string moduleName = parts[0].Trim();
            string offsetStr = parts[1].Trim();

            // Get module base address
            ulong? moduleBase = GetModuleBaseAddress(moduleName);
            if (moduleBase.HasValue)
            {
                // Parse offset
                if (TryParseAddress(offsetStr, out ulong offset))
                {
                    Address = moduleBase.Value + offset;
                    if (!_history.Contains(Address))
                    {
                        _history.Insert(0, Address);
                        if (_history.Count > 20) _history.RemoveAt(_history.Count - 1);
                    }
                    DialogResult = DialogResult.OK;
                    Close();
                    return;
                }
            }
            else
            {
                MessageBox.Show($"Module '{moduleName}' not found in process.",
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                DialogResult = DialogResult.None;
                return;
            }
        }

        // Try pointer dereference (e.g., "[address]" or "[address+offset]")
        if (input.StartsWith('[') && input.EndsWith(']') && _processHandle != IntPtr.Zero)
        {
            string inner = input[1..^1].Trim();
            ulong? innerAddr = EvaluateSimpleExpression(inner);
            if (innerAddr.HasValue)
            {
                // Read pointer value at that address
                var buffer = new byte[8];
                var result = NexusEngine.Nexus_ReadProcessMemory(
                    _processHandle, innerAddr.Value, buffer, 8, out nuint bytesRead);

                if ((result == NexusResult.OK || result == NexusResult.Success) && bytesRead >= 8)
                {
                    Address = BitConverter.ToUInt64(buffer, 0);
                    if (!_history.Contains(Address))
                    {
                        _history.Insert(0, Address);
                        if (_history.Count > 20) _history.RemoveAt(_history.Count - 1);
                    }
                    DialogResult = DialogResult.OK;
                    Close();
                    return;
                }
                else
                {
                    MessageBox.Show($"Failed to read pointer at 0x{innerAddr.Value:X}",
                        "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    DialogResult = DialogResult.None;
                    return;
                }
            }
        }

        MessageBox.Show("Could not parse address.", "Error",
            MessageBoxButtons.OK, MessageBoxIcon.Error);
        DialogResult = DialogResult.None;
    }

    private static bool TryParseAddress(string text, out ulong address)
    {
        text = text.Trim();

        // Remove 0x prefix if present
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            text = text[2..];

        // Remove $ prefix (Pascal hex notation)
        if (text.StartsWith('$'))
            text = text[1..];

        return ulong.TryParse(text, System.Globalization.NumberStyles.HexNumber, null, out address);
    }

    private ulong? GetModuleBaseAddress(string moduleName)
    {
        if (_processHandle == IntPtr.Zero) return null;

        // Enumerate modules
        NexusEngine.Nexus_EnumerateModules(_processHandle, null, 0, out nuint count);
        if (count == 0) return null;

        var modules = new NexusModuleInfo[count];
        NexusEngine.Nexus_EnumerateModules(_processHandle, modules, count, out _);

        // Find module by name (case insensitive)
        foreach (var mod in modules)
        {
            if (mod.Name.Equals(moduleName, StringComparison.OrdinalIgnoreCase) ||
                Path.GetFileName(mod.Path).Equals(moduleName, StringComparison.OrdinalIgnoreCase))
            {
                return mod.BaseAddress;
            }
        }

        // Try without extension
        string nameWithoutExt = Path.GetFileNameWithoutExtension(moduleName);
        foreach (var mod in modules)
        {
            if (Path.GetFileNameWithoutExtension(mod.Name).Equals(nameWithoutExt, StringComparison.OrdinalIgnoreCase))
            {
                return mod.BaseAddress;
            }
        }

        return null;
    }

    private ulong? EvaluateSimpleExpression(string expr)
    {
        expr = expr.Trim();

        // Try simple hex address
        if (TryParseAddress(expr, out ulong address))
            return address;

        // Try module+offset
        if (expr.Contains('+'))
        {
            var parts = expr.Split('+', 2);
            string left = parts[0].Trim();
            string right = parts[1].Trim();

            ulong? leftVal = null;

            // Left side could be a module or hex
            if (TryParseAddress(left, out ulong leftAddr))
                leftVal = leftAddr;
            else
                leftVal = GetModuleBaseAddress(left);

            if (leftVal.HasValue && TryParseAddress(right, out ulong rightAddr))
                return leftVal.Value + rightAddr;
        }

        // Try module-offset
        if (expr.Contains('-') && !expr.StartsWith('-'))
        {
            var parts = expr.Split('-', 2);
            string left = parts[0].Trim();
            string right = parts[1].Trim();

            ulong? leftVal = null;
            if (TryParseAddress(left, out ulong leftAddr))
                leftVal = leftAddr;
            else
                leftVal = GetModuleBaseAddress(left);

            if (leftVal.HasValue && TryParseAddress(right, out ulong rightAddr))
                return leftVal.Value - rightAddr;
        }

        // Try just a module name
        var moduleBase = GetModuleBaseAddress(expr);
        if (moduleBase.HasValue)
            return moduleBase;

        return null;
    }

    /// <summary>
    /// Shows the goto address dialog and returns the address if OK was clicked.
    /// </summary>
    public static ulong? ShowGoto(IWin32Window? owner, IntPtr processHandle = default, ulong currentAddress = 0)
    {
        using var form = new GotoAddressForm(processHandle, currentAddress);
        if (form.ShowDialog(owner) == DialogResult.OK)
        {
            return form.Address;
        }
        return null;
    }

    // Controls
    private ComboBox cmbAddress = null!;
    private Label lblExamples = null!;
    private Button btnOk = null!;
    private Button btnCancel = null!;
}
