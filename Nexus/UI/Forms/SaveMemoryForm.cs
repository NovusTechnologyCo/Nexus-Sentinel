// <file>
// <summary>
// Save memory region dialog for dumping process memory to a binary file.
// </summary>
// </file>
using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using Nexus.UI.Styles;


namespace Nexus.UI.Forms;

/// <summary>
/// Dialog for saving a range of process memory to a binary file on disk.
/// </summary>
public partial class SaveMemoryForm : Form
{
    private readonly IntPtr _processHandle;
    private readonly List<MemoryRegion> _regions = [];

    public class MemoryRegion
    {
        public ulong From { get; set; }
        public ulong To { get; set; }
        public ulong Size => To - From;

        public override string ToString() => $"{From:X} - {To:X} ({Size:N0} bytes)";
    }

    public SaveMemoryForm(IntPtr processHandle, ulong initialFrom = 0, ulong initialTo = 0)
    {
        _processHandle = processHandle;
        InitializeComponent();
        NexusTheme.StyleForm(this);

        if (initialFrom > 0 || initialTo > 0)
        {
            txtFrom.Text = initialFrom.ToString("X");
            txtTo.Text = initialTo.ToString("X");
        }
    }

    private void BtnAdd_Click(object? sender, EventArgs e)
    {
        // Parse from address
        var fromText = txtFrom.Text.Trim();
        if (fromText.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            fromText = fromText[2..];
        if (!ulong.TryParse(fromText,
            System.Globalization.NumberStyles.HexNumber, null, out var from))
        {
            MessageBox.Show("Invalid 'From' address.", "Error",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
            txtFrom.Focus();
            return;
        }

        // Parse to address
        var toText = txtTo.Text.Trim();
        if (toText.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            toText = toText[2..];
        if (!ulong.TryParse(toText,
            System.Globalization.NumberStyles.HexNumber, null, out var to))
        {
            MessageBox.Show("Invalid 'To' address.", "Error",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
            txtTo.Focus();
            return;
        }

        if (to <= from)
        {
            MessageBox.Show("'To' address must be greater than 'From' address.", "Error",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        var region = new MemoryRegion { From = from, To = to };
        _regions.Add(region);
        lbRegions.Items.Add(region.ToString());

        // Clear inputs for next entry
        txtFrom.Text = "";
        txtTo.Text = "";
        txtFrom.Focus();
    }

    private void BtnSave_Click(object? sender, EventArgs e)
    {
        if (_regions.Count == 0)
        {
            MessageBox.Show("Please add at least one memory region.", "No Regions",
                MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        using var saveDialog = new SaveFileDialog
        {
            Filter = "Nexus Memory file (*.nmem)|*.nmem|Binary file (*.bin)|*.bin|All files (*.*)|*.*",
            DefaultExt = ".nmem",
            Title = "Save Memory Region"
        };

        if (saveDialog.ShowDialog(this) != DialogResult.OK)
            return;

        try
        {
            SaveMemoryToFile(saveDialog.FileName);
            MessageBox.Show("Memory saved successfully.", "Success",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            DialogResult = DialogResult.OK;
            Close();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Failed to save memory:\n{ex.Message}", "Error",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void SaveMemoryToFile(string filename)
    {
        using var fs = new FileStream(filename, FileMode.Create, FileAccess.Write);
        using var writer = new BinaryWriter(fs);

        bool includeHeader = !chkNoHeader.Checked;

        if (includeHeader)
        {
            // Write Nexus memory file header
            writer.Write("NMEM"u8); // Magic
            writer.Write((uint)1); // Version
            writer.Write((uint)_regions.Count); // Region count
        }

        foreach (var region in _regions)
        {
            var size = region.To - region.From;
            var buffer = new byte[Math.Min(size, 64 * 1024)]; // 64KB chunks

            if (includeHeader)
            {
                // Write region header
                writer.Write(region.From);
                writer.Write(region.To);
            }

            // Read and write memory
            var remaining = size;
            var currentAddress = region.From;

            while (remaining > 0)
            {
                var toRead = (nuint)Math.Min(remaining, (ulong)buffer.Length);

                unsafe
                {
                    fixed (byte* ptr = buffer)
                    {
                        var result = NexusEngine.Nexus_ReadMemory(
                            _processHandle, currentAddress, (IntPtr)ptr, toRead, out var bytesRead);

                        if (result != NexusResult.OK && result != NexusResult.Success)
                        {
                            throw new Exception($"Failed to read memory at {currentAddress:X}: {NexusHelper.GetErrorMessage(result)}");
                        }

                        writer.Write(buffer, 0, (int)bytesRead);
                        currentAddress += bytesRead;
                        remaining -= bytesRead;
                    }
                }
            }
        }
    }

    private void BtnCancel_Click(object? sender, EventArgs e)
    {
        DialogResult = DialogResult.Cancel;
        Close();
    }

    private void LbRegions_DoubleClick(object? sender, EventArgs e)
    {
        // Remove selected region
        if (lbRegions.SelectedIndex >= 0)
        {
            _regions.RemoveAt(lbRegions.SelectedIndex);
            lbRegions.Items.RemoveAt(lbRegions.SelectedIndex);
        }
    }

    private void CtxClearList_Click(object? sender, EventArgs e)
    {
        _regions.Clear();
        lbRegions.Items.Clear();
    }
}
