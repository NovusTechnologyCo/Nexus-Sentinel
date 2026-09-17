// <file>
// <summary>
// Load memory region dialog for reading a binary file into process memory.
// </summary>
// </file>
using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using Nexus.UI.Styles;


namespace Nexus.UI.Forms;

/// <summary>
/// Dialog for loading a binary file from disk into the target process memory at a specified address.
/// </summary>
public partial class LoadMemoryForm : Form
{
    private readonly IntPtr _processHandle;
    private readonly List<MemoryRegion> _regions = [];
    private string? _loadedFilePath;

    public class MemoryRegion
    {
        public ulong OriginalAddress { get; set; }
        public ulong TargetAddress { get; set; }
        public ulong Size { get; set; }
        public byte[] Data { get; set; } = [];

        public override string ToString() => $"{OriginalAddress:X} - {OriginalAddress + Size:X} ({Size:N0} bytes)";
    }

    public LoadMemoryForm(IntPtr processHandle)
    {
        _processHandle = processHandle;
        InitializeComponent();
        NexusTheme.StyleForm(this);
    }

    public bool LoadFile(string filename)
    {
        try
        {
            _loadedFilePath = filename;
            _regions.Clear();
            lbRegions.Items.Clear();

            using var fs = new FileStream(filename, FileMode.Open, FileAccess.Read);
            using var reader = new BinaryReader(fs);

            // Check for Nexus memory file header
            var magic = reader.ReadBytes(4);
            if (magic.Length == 4 && magic[0] == 'N' && magic[1] == 'M' && magic[2] == 'E' && magic[3] == 'M')
            {
                // Nexus format with header
                var version = reader.ReadUInt32();
                var regionCount = reader.ReadUInt32();

                for (uint i = 0; i < regionCount; i++)
                {
                    var from = reader.ReadUInt64();
                    var to = reader.ReadUInt64();
                    var size = to - from;
                    if (size > int.MaxValue)
                        throw new InvalidDataException($"Region {i} size ({size:N0} bytes) exceeds maximum supported size.");
                    var data = reader.ReadBytes((int)size);

                    var region = new MemoryRegion
                    {
                        OriginalAddress = from,
                        TargetAddress = from,
                        Size = size,
                        Data = data
                    };
                    _regions.Add(region);
                }
            }
            else
            {
                // Raw binary file - treat as single region starting at 0
                fs.Seek(0, SeekOrigin.Begin);
                var data = new byte[fs.Length];
                fs.ReadExactly(data, 0, data.Length);

                var region = new MemoryRegion
                {
                    OriginalAddress = 0,
                    TargetAddress = 0,
                    Size = (ulong)data.Length,
                    Data = data
                };
                _regions.Add(region);
            }

            // Populate listbox
            foreach (var region in _regions)
            {
                lbRegions.Items.Add(region.ToString());
            }

            if (_regions.Count > 0)
            {
                lbRegions.SelectedIndex = 0;
                UpdateAddressField();
            }

            return true;
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Failed to load file:\n{ex.Message}", "Error",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
            return false;
        }
    }

    private void LbRegions_SelectedIndexChanged(object? sender, EventArgs e)
    {
        UpdateAddressField();
    }

    private void UpdateAddressField()
    {
        if (lbRegions.SelectedIndex >= 0 && lbRegions.SelectedIndex < _regions.Count)
        {
            var region = _regions[lbRegions.SelectedIndex];
            txtAddress.Text = region.TargetAddress.ToString("X");
        }
    }

    private void BtnEdit_Click(object? sender, EventArgs e)
    {
        if (lbRegions.SelectedIndex < 0) return;

        // Parse new address
        var addrText = txtAddress.Text.Trim();
        if (addrText.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            addrText = addrText[2..];
        if (!ulong.TryParse(addrText,
            System.Globalization.NumberStyles.HexNumber, null, out var newAddress))
        {
            MessageBox.Show("Invalid address.", "Error",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        var region = _regions[lbRegions.SelectedIndex];
        region.TargetAddress = newAddress;

        // Update listbox display
        lbRegions.Items[lbRegions.SelectedIndex] =
            $"{region.OriginalAddress:X} -> {region.TargetAddress:X} ({region.Size:N0} bytes)";
    }

    private void BtnOK_Click(object? sender, EventArgs e)
    {
        if (_regions.Count == 0)
        {
            MessageBox.Show("No memory regions to load.", "Error",
                MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        // Apply any pending address change
        if (lbRegions.SelectedIndex >= 0)
        {
            BtnEdit_Click(sender, e);
        }

        try
        {
            WriteMemoryRegions();
            MessageBox.Show("Memory loaded successfully.", "Success",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            DialogResult = DialogResult.OK;
            Close();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Failed to write memory:\n{ex.Message}", "Error",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void WriteMemoryRegions()
    {
        if (_processHandle == IntPtr.Zero)
        {
            throw new InvalidOperationException("No process attached.");
        }

        foreach (var region in _regions)
        {
            unsafe
            {
                fixed (byte* ptr = region.Data)
                {
                    var result = NexusEngine.Nexus_WriteMemory(
                        _processHandle, region.TargetAddress, (IntPtr)ptr, (nuint)region.Data.Length, out var written);

                    if (result != NexusResult.OK && result != NexusResult.Success)
                    {
                        throw new Exception($"Failed to write at {region.TargetAddress:X}: {NexusHelper.GetErrorMessage(result)}");
                    }

                    if (written != (nuint)region.Data.Length)
                    {
                        throw new Exception($"Partial write at {region.TargetAddress:X}: wrote {written} of {region.Data.Length} bytes");
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

    public static DialogResult ShowLoadDialog(IntPtr processHandle, IWin32Window? owner = null)
    {
        using var openDialog = new OpenFileDialog
        {
            Filter = "Nexus Memory file (*.nmem)|*.nmem|Binary file (*.bin)|*.bin|All files (*.*)|*.*",
            Title = "Load Memory Region"
        };

        if (openDialog.ShowDialog(owner) != DialogResult.OK)
            return DialogResult.Cancel;

        using var form = new LoadMemoryForm(processHandle);
        if (!form.LoadFile(openDialog.FileName))
            return DialogResult.Cancel;

        return form.ShowDialog(owner);
    }
}
