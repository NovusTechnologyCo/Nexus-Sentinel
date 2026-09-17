using System.Drawing.Drawing2D;
using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using Nexus.UI.Styles;

namespace Nexus.UI.Forms;

public partial class MemoryViewerForm
{
    #region Clipboard Operations

    private void MnuCopy_Click(object? sender, EventArgs e)
    {
        if (_processHandle == IntPtr.Zero) return;

        int length = Math.Max(1, _selectionLength);
        var bytes = new byte[length];

        unsafe
        {
            fixed (byte* ptr = bytes)
            {
                NexusEngine.Nexus_ReadMemory(
                    _processHandle,
                    _selectedAddress,
                    (IntPtr)ptr,
                    (nuint)length,
                    out _);
            }
        }

        string hexString = BitConverter.ToString(bytes).Replace("-", " ");
        Clipboard.SetText(hexString);
    }

    private void MnuPaste_Click(object? sender, EventArgs e)
    {
        if (_processHandle == IntPtr.Zero) return;

        try
        {
            string text = Clipboard.GetText().Replace(" ", "").Replace("-", "");
            var bytes = new byte[text.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(text.Substring(i * 2, 2), 16);
            }
            WriteValueAtSelection(bytes);
        }
        catch
        {
            MessageBox.Show("Invalid clipboard content", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void CopySelectedAddress()
    {
        // For hex view - copy single address
        if (_hexSelectedAddress != 0)
        {
            Clipboard.SetText($"{_hexSelectedAddress:X}");
        }
    }

    private void CopyDisasmAddress()
    {
        // Copy all addresses in the disasm selection
        if (_cachedDisasmCount == 0 || _disasmSelectedAddress == 0) return;

        var addresses = new List<string>();
        for (int i = 0; i < _cachedDisasmCount; i++)
        {
            var insn = _cachedDisasm[i];
            if (insn.Address >= _disasmSelectedAddress && insn.Address < _disasmSelectionEnd)
            {
                addresses.Add($"{insn.Address:X}");
            }
        }

        if (addresses.Count > 0)
        {
            Clipboard.SetText(string.Join(Environment.NewLine, addresses));
        }
    }

    private void CopyDisasmBytes()
    {
        // Copy bytes of all selected instructions
        if (_processHandle == IntPtr.Zero || _disasmSelectedAddress == 0) return;

        int length = (int)(_disasmSelectionEnd - _disasmSelectedAddress);
        if (length <= 0 || length > 0x1000) return; // Sanity check

        var bytes = new byte[length];
        unsafe
        {
            fixed (byte* ptr = bytes)
            {
                NexusEngine.Nexus_ReadMemory(_processHandle, _disasmSelectedAddress, (IntPtr)ptr, (nuint)length, out _);
            }
        }

        string hexString = BitConverter.ToString(bytes).Replace("-", " ");
        Clipboard.SetText(hexString);
    }

    private void CopyDisassembly()
    {
        // Copy all selected disassembly lines (address + instruction)
        if (_cachedDisasmCount == 0 || _disasmSelectedAddress == 0) return;

        var lines = new List<string>();
        for (int i = 0; i < _cachedDisasmCount; i++)
        {
            var insn = _cachedDisasm[i];
            if (insn.Address >= _disasmSelectedAddress && insn.Address < _disasmSelectionEnd)
            {
                string instrText;
                bool isUndefined = string.IsNullOrEmpty(insn.Mnemonic) ||
                                   insn.Mnemonic.Equals("db", StringComparison.OrdinalIgnoreCase) ||
                                   (!string.IsNullOrEmpty(insn.Text) && insn.Text.StartsWith("db ", StringComparison.OrdinalIgnoreCase));
                if (isUndefined)
                    instrText = "??";
                else if (!string.IsNullOrEmpty(insn.Text))
                    instrText = insn.Text;
                else
                    instrText = $"{insn.Mnemonic} {insn.Operands}".Trim();
                lines.Add($"{insn.Address:X16}  {instrText}");
            }
        }

        if (lines.Count > 0)
        {
            Clipboard.SetText(string.Join(Environment.NewLine, lines));
        }
    }

    #endregion

    #region Search

    private void MnuFindBytes_Click(object? sender, EventArgs e)
    {
        // Create simple search dialog
        using var dialog = new Form
        {
            Text = "Find Bytes",
            Size = new Size(450, 180),
            FormBorderStyle = FormBorderStyle.FixedDialog,
            StartPosition = FormStartPosition.CenterParent,
            MaximizeBox = false,
            MinimizeBox = false
        };

        var lblPattern = new Label { Text = "Byte pattern (hex, e.g. 90 90 ?? 48):", Location = new Point(15, 15), AutoSize = true };
        var txtPattern = new TextBox { Location = new Point(15, 38), Width = 400 };
        NexusTheme.StyleTextBox(txtPattern);
        var lblInfo = new Label { Text = "Use ?? or * for wildcards", Location = new Point(15, 65), AutoSize = true, ForeColor = Color.Gray };

        var btnSearch = new Button { Text = "Find Next", Location = new Point(240, 95), Size = new Size(85, 32), DialogResult = DialogResult.OK };
        var btnCancel = new Button { Text = "Cancel", Location = new Point(330, 95), Size = new Size(85, 32), DialogResult = DialogResult.Cancel };

        dialog.Controls.AddRange(new Control[] { lblPattern, txtPattern, lblInfo, btnSearch, btnCancel });
        dialog.AcceptButton = btnSearch;
        dialog.CancelButton = btnCancel;

        if (dialog.ShowDialog(this) != DialogResult.OK || string.IsNullOrWhiteSpace(txtPattern.Text))
            return;

        // Parse the pattern
        var patternStr = txtPattern.Text.Trim();
        var parts = patternStr.Split(new[] { ' ', ',' }, StringSplitOptions.RemoveEmptyEntries);
        var pattern = new List<byte?>();

        foreach (var part in parts)
        {
            if (part == "??" || part == "*" || part == "?")
            {
                pattern.Add(null); // Wildcard
            }
            else if (byte.TryParse(part, System.Globalization.NumberStyles.HexNumber, null, out byte b))
            {
                pattern.Add(b);
            }
            else
            {
                MessageBox.Show($"Invalid byte pattern: {part}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
        }

        if (pattern.Count == 0)
        {
            MessageBox.Show("Empty pattern", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        // Search for the pattern starting from current address
        SearchBytes(pattern.ToArray(), _selectedAddress + 1);
    }

    private void SearchBytes(byte?[] pattern, ulong startAddress)
    {
        const int chunkSize = 0x10000; // 64KB chunks
        var buffer = new byte[chunkSize];
        ulong searchAddr = startAddress;
        ulong maxAddress = searchAddr + 0x10000000; // Search up to 256MB forward

        // Show progress
        Cursor = Cursors.WaitCursor;

        try
        {
            while (searchAddr < maxAddress)
            {
                var result = NexusEngine.Nexus_ReadProcessMemory(_processHandle, searchAddr, buffer, (nuint)chunkSize, out nuint bytesRead);
                if ((result != NexusResult.OK && result != NexusResult.Success) || bytesRead == 0)
                {
                    // Skip unreadable regions
                    searchAddr += (ulong)chunkSize;
                    continue;
                }

                // Search in this chunk
                for (int i = 0; i <= (int)bytesRead - pattern.Length; i++)
                {
                    bool match = true;
                    for (int j = 0; j < pattern.Length; j++)
                    {
                        byte? p = pattern[j];
                        if (p.HasValue && buffer[i + j] != p.Value)
                        {
                            match = false;
                            break;
                        }
                    }

                    if (match)
                    {
                        ulong foundAddr = searchAddr + (ulong)i;
                        GoToAddress(foundAddr);
                        MessageBox.Show($"Found pattern at 0x{foundAddr:X}", "Search Result",
                            MessageBoxButtons.OK, MessageBoxIcon.Information);
                        return;
                    }
                }

                searchAddr += (ulong)bytesRead;
                Application.DoEvents();
            }

            MessageBox.Show("Pattern not found", "Search", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        finally
        {
            Cursor = Cursors.Default;
        }
    }

    #endregion

    #region NOP / Patch

    private void ReplaceWithNop()
    {
        if (_processHandle == IntPtr.Zero || _disasmSelectedAddress == 0) return;

        int length = (int)(_disasmSelectionEnd - _disasmSelectedAddress);
        if (length <= 0) return;

        // Confirm the operation
        var result = MessageBox.Show(
            $"Replace {length} bytes at 0x{_disasmSelectedAddress:X} with NOP (0x90)?\n\nYou can undo this with Ctrl+Z or right-click > Undo.",
            "Replace with NOP",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Question);

        if (result != DialogResult.Yes) return;

        // Save original bytes for undo
        SaveBytesForUndo(_disasmSelectedAddress, length, $"NOP {length} bytes at 0x{_disasmSelectedAddress:X}");

        // Fill with NOP
        var nopBuffer = new byte[length];
        Array.Fill(nopBuffer, (byte)0x90);

        NexusResult writeResult;
        unsafe
        {
            fixed (byte* ptr = nopBuffer)
            {
                writeResult = NexusEngine.Nexus_WriteMemory(
                    _processHandle,
                    _disasmSelectedAddress,
                    (IntPtr)ptr,
                    (nuint)length,
                    out _);
            }
        }

        if (writeResult != NexusResult.OK)
        {
            // Remove the undo entry since write failed
            if (_undoStack.Count > 0) _undoStack.Pop();
            MessageBox.Show($"Failed to write memory: {NexusHelper.GetErrorMessage(writeResult)}",
                "Write Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        RefreshDisasmMemory();
    }

    #endregion

    #region Dump File / Memory Dump

    private void MnuDump_Click(object? sender, EventArgs e)
    {
        using var dialog = new SaveFileDialog
        {
            Filter = "Binary files (*.bin)|*.bin|All files (*.*)|*.*",
            Title = "Dump memory to file"
        };

        if (dialog.ShowDialog() != DialogResult.OK) return;

        ulong length = (ulong)(_bytesPerRow * _rowCount);
        var bytes = new byte[length];

        unsafe
        {
            fixed (byte* ptr = bytes)
            {
                NexusEngine.Nexus_ReadMemory(
                    _processHandle,
                    _scrollAddress,
                    (IntPtr)ptr,
                    (nuint)length,
                    out nuint read);

                File.WriteAllBytes(dialog.FileName, bytes[..(int)read]);
            }
        }

        MessageBox.Show($"Dumped {length} bytes to {dialog.FileName}", "Dump Complete",
            MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private void OpenDump()
    {
        using var dialog = new OpenFileDialog
        {
            Filter = "Binary files (*.bin)|*.bin|All files (*.*)|*.*",
            Title = "Open memory dump"
        };

        if (dialog.ShowDialog() != DialogResult.OK) return;

        try
        {
            // Read the dump file
            _dumpFileData = File.ReadAllBytes(dialog.FileName);
            _dumpFileName = Path.GetFileName(dialog.FileName);

            // Ask for base address
            using var addrDialog = new Form
            {
                Text = "Dump Base Address",
                Size = new Size(300, 130),
                StartPosition = FormStartPosition.CenterParent,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                MaximizeBox = false,
                MinimizeBox = false
            };

            var lblAddr = new Label { Text = "Base Address:", Location = new Point(10, 15), AutoSize = true };
            var txtAddr = new TextBox { Location = new Point(100, 12), Width = 170, Text = "0" };
            NexusTheme.StyleTextBox(txtAddr);

            var btnOk = new Button { Text = "OK", Location = new Point(100, 50), Size = new Size(80, 28), DialogResult = DialogResult.OK };
            var btnCancel = new Button { Text = "Cancel", Location = new Point(190, 50), Size = new Size(80, 28), DialogResult = DialogResult.Cancel };

            addrDialog.Controls.AddRange([lblAddr, txtAddr, btnOk, btnCancel]);
            addrDialog.AcceptButton = btnOk;
            addrDialog.CancelButton = btnCancel;

            if (addrDialog.ShowDialog(this) != DialogResult.OK)
            {
                _dumpFileData = null;
                _dumpFileName = null;
                return;
            }

            // Parse base address
            string addrText = txtAddr.Text.Trim();
            if (addrText.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                addrText = addrText[2..];
            if (!ulong.TryParse(addrText, System.Globalization.NumberStyles.HexNumber, null, out _dumpFileBaseAddress))
                _dumpFileBaseAddress = 0;

            // Navigate to the base address
            GoToAddress(_dumpFileBaseAddress);
            UpdateTitle();

            MessageBox.Show($"Loaded {_dumpFileData.Length:N0} bytes from {_dumpFileName}\nBase address: 0x{_dumpFileBaseAddress:X}",
                "Dump Loaded", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (Exception ex)
        {
            _dumpFileData = null;
            _dumpFileName = null;
            MessageBox.Show($"Failed to load dump: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void CloseDump()
    {
        _dumpFileData = null;
        _dumpFileName = null;
        _dumpFileBaseAddress = 0;
        UpdateTitle();
        RefreshMemory();
    }

    #endregion
}
