// <file>
// <summary>
// Memory fill dialog for writing a repeated byte pattern across a memory range.
// </summary>
// </file>
using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using Nexus.UI.Styles;


namespace Nexus.UI.Forms;

public partial class FillMemoryForm : Form
{
    private readonly IntPtr _processHandle;
    private readonly ulong _viewerAddress;
    private byte _defaultFillValue = 0x90; // Default to NOP

    public FillMemoryForm()
    {
        InitializeComponent();
        NexusTheme.StyleForm(this);
    }

    public FillMemoryForm(IntPtr processHandle) : this()
    {
        _processHandle = processHandle;
    }

    public FillMemoryForm(IntPtr processHandle, ulong startAddress, ulong endAddress, byte defaultFillValue = 0x90) : this(processHandle)
    {
        txtFrom.Text = $"{startAddress:X}";
        txtTo.Text = $"{endAddress:X}";
        txtFillValue.Text = $"{defaultFillValue:X2}";
        _viewerAddress = startAddress;
        _defaultFillValue = defaultFillValue;
    }

    private void InitializeComponent()
    {
        Text = "Fill Memory";
        Size = new Size(430, 250);
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;

        const int margin = NexusTheme.Space16;
        int y = margin;

        // From address
        var lblFrom = new Label
        {
            Text = "From address:",
            Location = new Point(margin, y + 3),
            AutoSize = true
        };

        var lblFromPrefix = new Label
        {
            Text = "0x",
            Location = new Point(135, y + 3),
            AutoSize = true,
            Font = new Font("Consolas", 10F)
        };

        txtFrom = new TextBox
        {
            Location = new Point(170, y),
            Width = 220,
            Font = new Font("Consolas", 10F),
            MaxLength = 16
        };

        y += 35;

        // To address
        var lblTo = new Label
        {
            Text = "To address:",
            Location = new Point(margin, y + 3),
            AutoSize = true
        };

        var lblToPrefix = new Label
        {
            Text = "0x",
            Location = new Point(135, y + 3),
            AutoSize = true,
            Font = new Font("Consolas", 10F)
        };

        txtTo = new TextBox
        {
            Location = new Point(170, y),
            Width = 220,
            Font = new Font("Consolas", 10F),
            MaxLength = 16
        };

        y += 35;

        // Fill value
        var lblFill = new Label
        {
            Text = "Fill value (byte):",
            Location = new Point(margin, y + 3),
            AutoSize = true
        };

        var lblFillPrefix = new Label
        {
            Text = "0x",
            Location = new Point(150, y + 3),
            AutoSize = true,
            Font = new Font("Consolas", 10F)
        };

        txtFillValue = new TextBox
        {
            Location = new Point(190, y),
            Width = 60,
            Font = new Font("Consolas", 10F),
            MaxLength = 2,
            Text = "90"  // Default to NOP
        };

        y += 60;

        // Buttons - right aligned
        int buttonX = 430 - margin - NexusTheme.ButtonWidth - 15;  // Account for form border
        btnCancel = new Button
        {
            Text = "Close",
            DialogResult = DialogResult.Cancel,
            Location = new Point(buttonX, y),
            Size = new Size(NexusTheme.ButtonWidth, NexusTheme.ButtonHeight)
        };
        btnCancel.Click += (s, e) => Close();

        buttonX -= NexusTheme.ButtonWidth + NexusTheme.ButtonGap;
        btnFill = new Button
        {
            Text = "Fill",
            Location = new Point(buttonX, y),
            Size = new Size(NexusTheme.ButtonWidth, NexusTheme.ButtonHeight)
        };
        btnFill.Click += BtnFill_Click;

        AcceptButton = btnFill;
        CancelButton = btnCancel;

        Controls.AddRange([lblFrom, lblFromPrefix, txtFrom,
            lblTo, lblToPrefix, txtTo,
            lblFill, lblFillPrefix, txtFillValue,
            btnFill, btnCancel]);
    }

    private void BtnFill_Click(object? sender, EventArgs e)
    {
        try
        {
            // Parse from address
            if (!ulong.TryParse(txtFrom.Text.Trim(),
                System.Globalization.NumberStyles.HexNumber, null, out ulong startAddr))
            {
                MessageBox.Show("Please fill in a valid 'From' address.", "Invalid Input",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                txtFrom.Focus();
                return;
            }

            // Parse to address
            if (!ulong.TryParse(txtTo.Text.Trim(),
                System.Globalization.NumberStyles.HexNumber, null, out ulong endAddr))
            {
                MessageBox.Show("Please fill in a valid 'To' address.", "Invalid Input",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                txtTo.Focus();
                return;
            }

            // Parse fill value
            if (!byte.TryParse(txtFillValue.Text.Trim(),
                System.Globalization.NumberStyles.HexNumber, null, out byte fillValue))
            {
                MessageBox.Show("Please fill in a valid 'Fill' value (00-FF).", "Invalid Input",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                txtFillValue.Focus();
                return;
            }

            // Swap if needed
            if (endAddr < startAddr)
            {
                (startAddr, endAddr) = (endAddr, startAddr);
            }

            ulong count = endAddr - startAddr + 1;

            // Safety check for very large fills
            if (count > 100 * 1024 * 1024) // 100 MB
            {
                var result = MessageBox.Show(
                    $"You are about to fill {count:N0} bytes ({count / 1024.0 / 1024.0:F2} MB).\n\n" +
                    "This is a large region and may take a while.\n" +
                    "Are you sure you want to continue?",
                    "Large Fill Warning",
                    MessageBoxButtons.YesNo, MessageBoxIcon.Warning);

                if (result != DialogResult.Yes) return;
            }

            // Perform the fill
            if (!FillMemory(startAddr, count, fillValue))
            {
                if (!AdminHelper.IsRunningAsAdmin())
                {
                    // Offer to restart as admin (only carries PID, user will need to redo the operation)
                    AdminHelper.PromptAndRestartAsAdmin(
                        this,
                        "Failed to fill memory. The region may be protected.",
                        0);
                }
                else
                {
                    MessageBox.Show(
                        "Failed to fill memory. The region may be protected or the process is not accessible.",
                        "Fill Failed",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error);
                }
                return;
            }

            MessageBox.Show($"Successfully filled {count:N0} bytes with 0x{fillValue:X2}.",
                "Fill Complete", MessageBoxButtons.OK, MessageBoxIcon.Information);

            DialogResult = DialogResult.OK;
            Close();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error filling memory: {ex.Message}", "Error",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private bool FillMemory(ulong startAddress, ulong count, byte fillValue)
    {
        // Use engine API for fill memory with automatic protection handling
        return NexusEngine.FillMemory(_processHandle, startAddress, count, fillValue);
    }

    /// <summary>
    /// Shows the fill memory dialog.
    /// </summary>
    public static bool Show(IWin32Window? owner, IntPtr processHandle,
        ulong startAddress = 0, ulong endAddress = 0)
    {
        using var form = new FillMemoryForm(processHandle, startAddress, endAddress);
        return form.ShowDialog(owner) == DialogResult.OK;
    }

    // Controls
    private TextBox txtFrom = null!;
    private TextBox txtTo = null!;
    private TextBox txtFillValue = null!;
    private Button btnFill = null!;
    private Button btnCancel = null!;
}
