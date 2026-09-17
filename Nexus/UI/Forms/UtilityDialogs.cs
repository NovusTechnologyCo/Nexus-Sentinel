// <file>
// <summary>
// Collection of small utility dialog forms: plugin approval and other prompts.
// </summary>
// </file>
using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using Nexus.UI.Styles;


namespace Nexus.UI.Forms;

/// <summary>
/// Dialog for navigating to a specific memory address.
/// </summary>
public class GoToAddressForm : Form
{
    private Label _lblAddress = null!;
    private TextBox _txtAddress = null!;
    private CheckBox _chkHex = null!;
    private Button _btnOK = null!;
    private Button _btnCancel = null!;
    private ComboBox _cboHistory = null!;

    private static readonly List<string> _addressHistory = [];

    public ulong Address { get; private set; }

    public GoToAddressForm(ulong currentAddress = 0)
    {
        InitializeComponent();
        NexusTheme.StyleForm(this);
        if (currentAddress != 0)
            _txtAddress.Text = currentAddress.ToString("X");
    }

    private void InitializeComponent()
    {
        Text = "Go To Address";
        Size = new Size(350, 150);
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;

        _lblAddress = new Label
        {
            Text = "Address:",
            Location = new Point(15, 20),
            AutoSize = true
        };

        _txtAddress = new TextBox
        {
            Location = new Point(80, 17),
            Size = new Size(150, 23),
            Font = new Font("Consolas", 10)
        };

        _chkHex = new CheckBox
        {
            Text = "Hex",
            Location = new Point(240, 19),
            AutoSize = true,
            Checked = true
        };

        _cboHistory = new ComboBox
        {
            Location = new Point(80, 50),
            Size = new Size(150, 23),
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        _cboHistory.Items.AddRange([.. _addressHistory]);
        _cboHistory.SelectedIndexChanged += (s, e) =>
        {
            if (_cboHistory.SelectedItem is string addr)
                _txtAddress.Text = addr;
        };

        var lblHistory = new Label
        {
            Text = "History:",
            Location = new Point(15, 53),
            AutoSize = true
        };

        _btnOK = new Button
        {
            Text = "OK",
            Location = new Point(160, 85),
            Size = new Size(80, 32),
            DialogResult = DialogResult.OK
        };
        _btnOK.Click += BtnOK_Click;

        _btnCancel = new Button
        {
            Text = "Cancel",
            Location = new Point(250, 85),
            Size = new Size(80, 32),
            DialogResult = DialogResult.Cancel
        };

        Controls.Add(_lblAddress);
        Controls.Add(_txtAddress);
        Controls.Add(_chkHex);
        Controls.Add(lblHistory);
        Controls.Add(_cboHistory);
        Controls.Add(_btnOK);
        Controls.Add(_btnCancel);
        AcceptButton = _btnOK;
        CancelButton = _btnCancel;
    }

    private void BtnOK_Click(object? sender, EventArgs e)
    {
        var text = _txtAddress.Text.Trim();
        if (string.IsNullOrEmpty(text))
        {
            MessageBox.Show("Please enter an address.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            DialogResult = DialogResult.None;
            return;
        }

        // Remove 0x prefix
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            text = text[2..];

        var style = _chkHex.Checked
            ? System.Globalization.NumberStyles.HexNumber
            : System.Globalization.NumberStyles.Integer;

        if (!ulong.TryParse(text, style, null, out var address))
        {
            MessageBox.Show("Invalid address format.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            DialogResult = DialogResult.None;
            return;
        }

        Address = address;

        // Add to history
        var historyEntry = address.ToString("X");
        if (!_addressHistory.Contains(historyEntry))
        {
            _addressHistory.Insert(0, historyEntry);
            if (_addressHistory.Count > 20)
                _addressHistory.RemoveAt(_addressHistory.Count - 1);
        }
    }
}

/// <summary>
/// Dialog for finding bytes/patterns in memory.
/// </summary>
public class FindMemoryForm : Form
{
    private TabControl _tabControl = null!;
    private TabPage _tabBytes = null!;
    private TabPage _tabString = null!;
    private TextBox _txtBytes = null!;
    private TextBox _txtString = null!;
    private CheckBox _chkCaseSensitive = null!;
    private CheckBox _chkUnicode = null!;
    private CheckBox _chkWildcards = null!;
    private RadioButton _rbDown = null!;
    private RadioButton _rbUp = null!;
    private Button _btnFind = null!;
    private Button _btnCancel = null!;

    public byte[]? SearchBytes { get; private set; }
    public string? SearchString { get; private set; }
    public bool CaseSensitive => _chkCaseSensitive.Checked;
    public bool Unicode => _chkUnicode.Checked;
    public bool SearchDown => _rbDown.Checked;
    public bool UseWildcards => _chkWildcards.Checked;

    public FindMemoryForm()
    {
        InitializeComponent();
        NexusTheme.StyleForm(this);
    }

    private void InitializeComponent()
    {
        Text = "Find in Memory";
        Size = new Size(400, 250);
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;

        _tabControl = new TabControl
        {
            Location = new Point(10, 10),
            Size = new Size(365, 130)
        };

        // Bytes tab
        _tabBytes = new TabPage("Bytes/AOB");
        var lblBytes = new Label
        {
            Text = "Byte pattern (e.g., 90 90 ?? FF):",
            Location = new Point(10, 15),
            AutoSize = true
        };
        _txtBytes = new TextBox
        {
            Location = new Point(10, 35),
            Size = new Size(330, 23),
            Font = new Font("Consolas", 10)
        };
        _chkWildcards = new CheckBox
        {
            Text = "Use wildcards (?? for any byte)",
            Location = new Point(10, 65),
            AutoSize = true,
            Checked = true
        };
        _tabBytes.Controls.Add(lblBytes);
        _tabBytes.Controls.Add(_txtBytes);
        _tabBytes.Controls.Add(_chkWildcards);
        _tabControl.TabPages.Add(_tabBytes);

        // String tab
        _tabString = new TabPage("String");
        var lblString = new Label
        {
            Text = "Search string:",
            Location = new Point(10, 15),
            AutoSize = true
        };
        _txtString = new TextBox
        {
            Location = new Point(10, 35),
            Size = new Size(330, 23)
        };
        _chkCaseSensitive = new CheckBox
        {
            Text = "Case sensitive",
            Location = new Point(10, 65),
            AutoSize = true
        };
        _chkUnicode = new CheckBox
        {
            Text = "Unicode (UTF-16)",
            Location = new Point(130, 65),
            AutoSize = true
        };
        _tabString.Controls.Add(lblString);
        _tabString.Controls.Add(_txtString);
        _tabString.Controls.Add(_chkCaseSensitive);
        _tabString.Controls.Add(_chkUnicode);
        _tabControl.TabPages.Add(_tabString);

        // Direction
        var grpDirection = new GroupBox
        {
            Text = "Direction",
            Location = new Point(10, 145),
            Size = new Size(150, 55)
        };
        _rbDown = new RadioButton
        {
            Text = "Down",
            Location = new Point(10, 22),
            AutoSize = true,
            Checked = true
        };
        _rbUp = new RadioButton
        {
            Text = "Up",
            Location = new Point(80, 22),
            AutoSize = true
        };
        grpDirection.Controls.Add(_rbDown);
        grpDirection.Controls.Add(_rbUp);

        // Buttons
        _btnFind = new Button
        {
            Text = "Find Next",
            Location = new Point(200, 165),
            Size = new Size(80, 32),
            DialogResult = DialogResult.OK
        };
        _btnFind.Click += BtnFind_Click;

        _btnCancel = new Button
        {
            Text = "Cancel",
            Location = new Point(295, 165),
            Size = new Size(80, 32),
            DialogResult = DialogResult.Cancel
        };

        Controls.Add(_tabControl);
        Controls.Add(grpDirection);
        Controls.Add(_btnFind);
        Controls.Add(_btnCancel);
        AcceptButton = _btnFind;
        CancelButton = _btnCancel;
    }

    private void BtnFind_Click(object? sender, EventArgs e)
    {
        if (_tabControl.SelectedTab == _tabBytes)
        {
            // Parse byte pattern
            var pattern = _txtBytes.Text.Trim();
            if (string.IsNullOrEmpty(pattern))
            {
                MessageBox.Show("Please enter a byte pattern.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                DialogResult = DialogResult.None;
                return;
            }

            try
            {
                var bytes = new List<byte>();
                var parts = pattern.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                foreach (var part in parts)
                {
                    if (part == "??" || part == "?")
                        bytes.Add(0); // Placeholder for wildcard
                    else
                        bytes.Add(Convert.ToByte(part, 16));
                }
                SearchBytes = [.. bytes];
            }
            catch
            {
                MessageBox.Show("Invalid byte pattern.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                DialogResult = DialogResult.None;
                return;
            }
        }
        else
        {
            // String search
            if (string.IsNullOrEmpty(_txtString.Text))
            {
                MessageBox.Show("Please enter a search string.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                DialogResult = DialogResult.None;
                return;
            }
            SearchString = _txtString.Text;
        }
    }
}

// Note: FillMemoryForm is now in separate file FillMemoryForm.cs

/// <summary>
/// Dialog for copying a memory region.
/// </summary>
public class CopyMemoryForm : Form
{
    private Label _lblSource = null!;
    private TextBox _txtSource = null!;
    private Label _lblDest = null!;
    private TextBox _txtDest = null!;
    private Label _lblSize = null!;
    private TextBox _txtSize = null!;
    private Button _btnCopy = null!;
    private Button _btnCancel = null!;

    private readonly IntPtr _processHandle;

    public CopyMemoryForm(IntPtr processHandle, ulong sourceAddress = 0)
    {
        _processHandle = processHandle;
        InitializeComponent();
        NexusTheme.StyleForm(this);
        if (sourceAddress != 0)
            _txtSource.Text = sourceAddress.ToString("X");
    }

    private void InitializeComponent()
    {
        Text = "Copy Memory";
        Size = new Size(350, 180);
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;

        _lblSource = new Label
        {
            Text = "Source Address:",
            Location = new Point(15, 20),
            AutoSize = true
        };

        _txtSource = new TextBox
        {
            Location = new Point(120, 17),
            Size = new Size(190, 23),
            Font = new Font("Consolas", 10)
        };

        _lblDest = new Label
        {
            Text = "Dest Address:",
            Location = new Point(15, 55),
            AutoSize = true
        };

        _txtDest = new TextBox
        {
            Location = new Point(120, 52),
            Size = new Size(190, 23),
            Font = new Font("Consolas", 10)
        };

        _lblSize = new Label
        {
            Text = "Size (bytes):",
            Location = new Point(15, 90),
            AutoSize = true
        };

        _txtSize = new TextBox
        {
            Location = new Point(120, 87),
            Size = new Size(100, 23)
        };

        _btnCopy = new Button
        {
            Text = "Copy",
            Location = new Point(140, 120),
            Width = 80
        };
        _btnCopy.Click += BtnCopy_Click;

        _btnCancel = new Button
        {
            Text = "Cancel",
            Location = new Point(230, 120),
            Size = new Size(80, 32),
            DialogResult = DialogResult.Cancel
        };

        Controls.Add(_lblSource);
        Controls.Add(_txtSource);
        Controls.Add(_lblDest);
        Controls.Add(_txtDest);
        Controls.Add(_lblSize);
        Controls.Add(_txtSize);
        Controls.Add(_btnCopy);
        Controls.Add(_btnCancel);
        CancelButton = _btnCancel;
    }

    private void BtnCopy_Click(object? sender, EventArgs e)
    {
        // Parse source address
        var srcText = _txtSource.Text.Trim();
        if (srcText.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            srcText = srcText[2..];
        if (!ulong.TryParse(srcText, System.Globalization.NumberStyles.HexNumber, null, out var srcAddr))
        {
            MessageBox.Show("Invalid source address.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        // Parse destination address
        var destText = _txtDest.Text.Trim();
        if (destText.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            destText = destText[2..];
        if (!ulong.TryParse(destText, System.Globalization.NumberStyles.HexNumber, null, out var destAddr))
        {
            MessageBox.Show("Invalid destination address.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        // Parse size
        if (!int.TryParse(_txtSize.Text, out var size) || size <= 0 || size > 0x10000000)
        {
            MessageBox.Show("Invalid size (max 256MB).", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        // Confirm
        var result = MessageBox.Show(
            $"Copy {size} bytes from 0x{srcAddr:X} to 0x{destAddr:X}?\n\nDestination will be overwritten!",
            "Confirm", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);

        if (result != DialogResult.Yes) return;

        // Read source
        var buffer = new byte[size];
        unsafe
        {
            fixed (byte* ptr = buffer)
            {
                var readResult = NexusEngine.Nexus_ReadMemory(
                    _processHandle, srcAddr, (IntPtr)ptr, (nuint)size, out var read);

                if (readResult != NexusResult.OK && readResult != NexusResult.Success)
                {
                    MessageBox.Show($"Read failed: {NexusHelper.GetErrorMessage(readResult)}",
                        "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                // Write to destination
                var writeResult = NexusEngine.Nexus_WriteMemory(
                    _processHandle, destAddr, (IntPtr)ptr, read, out var written);

                if (writeResult == NexusResult.OK || writeResult == NexusResult.Success)
                {
                    MessageBox.Show($"Copied {written} bytes.", "Success",
                        MessageBoxButtons.OK, MessageBoxIcon.Information);
                    DialogResult = DialogResult.OK;
                    Close();
                }
                else
                {
                    MessageBox.Show($"Write failed: {NexusHelper.GetErrorMessage(writeResult)}",
                        "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }
    }
}

/// <summary>
/// Dialog for dumping memory to a file.
/// </summary>
public class DumpMemoryForm : Form
{
    private Label _lblStart = null!;
    private TextBox _txtStart = null!;
    private Label _lblSize = null!;
    private TextBox _txtSize = null!;
    private Label _lblFile = null!;
    private TextBox _txtFile = null!;
    private Button _btnBrowse = null!;
    private Button _btnDump = null!;
    private Button _btnCancel = null!;
    private ProgressBar _progress = null!;

    private readonly IntPtr _processHandle;

    public DumpMemoryForm(IntPtr processHandle, ulong startAddress = 0, ulong size = 0)
    {
        _processHandle = processHandle;
        InitializeComponent();
        NexusTheme.StyleForm(this);
        if (startAddress != 0)
            _txtStart.Text = startAddress.ToString("X");
        if (size != 0)
            _txtSize.Text = size.ToString("X");
    }

    private void InitializeComponent()
    {
        Text = "Dump Memory";
        Size = new Size(450, 200);
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;

        _lblStart = new Label
        {
            Text = "Start Address:",
            Location = new Point(15, 20),
            AutoSize = true
        };

        _txtStart = new TextBox
        {
            Location = new Point(110, 17),
            Size = new Size(150, 23),
            Font = new Font("Consolas", 10)
        };

        _lblSize = new Label
        {
            Text = "Size (hex):",
            Location = new Point(270, 20),
            AutoSize = true
        };

        _txtSize = new TextBox
        {
            Location = new Point(340, 17),
            Size = new Size(80, 23),
            Font = new Font("Consolas", 10)
        };

        _lblFile = new Label
        {
            Text = "Output File:",
            Location = new Point(15, 55),
            AutoSize = true
        };

        _txtFile = new TextBox
        {
            Location = new Point(110, 52),
            Size = new Size(260, 23)
        };

        _btnBrowse = new Button
        {
            Text = "...",
            Location = new Point(380, 51),
            Width = 40
        };
        _btnBrowse.Click += (s, e) =>
        {
            using var dialog = new SaveFileDialog
            {
                Filter = "Binary files (*.bin)|*.bin|All files (*.*)|*.*",
                Title = "Save dump as"
            };
            if (dialog.ShowDialog() == DialogResult.OK)
                _txtFile.Text = dialog.FileName;
        };

        _progress = new ProgressBar
        {
            Location = new Point(15, 90),
            Size = new Size(405, 20),
            Visible = false
        };

        _btnDump = new Button
        {
            Text = "Dump",
            Location = new Point(250, 125),
            Width = 80
        };
        _btnDump.Click += BtnDump_Click;

        _btnCancel = new Button
        {
            Text = "Cancel",
            Location = new Point(340, 125),
            Size = new Size(80, 32),
            DialogResult = DialogResult.Cancel
        };

        Controls.Add(_lblStart);
        Controls.Add(_txtStart);
        Controls.Add(_lblSize);
        Controls.Add(_txtSize);
        Controls.Add(_lblFile);
        Controls.Add(_txtFile);
        Controls.Add(_btnBrowse);
        Controls.Add(_progress);
        Controls.Add(_btnDump);
        Controls.Add(_btnCancel);
        CancelButton = _btnCancel;
    }

    private async void BtnDump_Click(object? sender, EventArgs e)
    {
        // Parse start address
        var addrText = _txtStart.Text.Trim();
        if (addrText.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            addrText = addrText[2..];
        if (!ulong.TryParse(addrText, System.Globalization.NumberStyles.HexNumber, null, out var startAddr))
        {
            MessageBox.Show("Invalid start address.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        // Parse size
        var sizeText = _txtSize.Text.Trim();
        if (sizeText.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            sizeText = sizeText[2..];
        if (!ulong.TryParse(sizeText, System.Globalization.NumberStyles.HexNumber, null, out var size) || size == 0)
        {
            MessageBox.Show("Invalid size.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        // Check file path
        if (string.IsNullOrEmpty(_txtFile.Text))
        {
            MessageBox.Show("Please specify output file.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        _btnDump.Enabled = false;
        _progress.Visible = true;
        _progress.Value = 0;

        try
        {
            const int chunkSize = 0x10000; // 64KB chunks
            using var fs = File.Create(_txtFile.Text);

            ulong offset = 0;
            while (offset < size)
            {
                var toRead = (int)Math.Min(chunkSize, size - offset);
                var buffer = new byte[toRead];

                unsafe
                {
                    fixed (byte* ptr = buffer)
                    {
                        var result = NexusEngine.Nexus_ReadMemory(
                            _processHandle,
                            startAddr + offset,
                            (IntPtr)ptr,
                            (nuint)toRead,
                            out var read);

                        if (result != NexusResult.OK && result != NexusResult.Success)
                        {
                            // Fill unreadable with zeros
                            Array.Clear(buffer, 0, toRead);
                        }
                    }
                }

                await fs.WriteAsync(buffer.AsMemory(0, toRead));
                offset += (ulong)toRead;
                _progress.Value = (int)((offset * 100) / size);
            }

            MessageBox.Show($"Dumped {size:N0} bytes to {Path.GetFileName(_txtFile.Text)}",
                "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
            DialogResult = DialogResult.OK;
            Close();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Dump failed: {ex.Message}", "Error",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            _btnDump.Enabled = true;
            _progress.Visible = false;
        }
    }
}

// Note: InputBoxForm is now in separate file InputBoxForm.cs
