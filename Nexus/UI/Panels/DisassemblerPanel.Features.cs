// <file>
// <summary>
// Partial class for DisassemblerPanel containing additional features migrated from
// MemoryViewerForm: find bytes dialog, cross-reference scanning, code cave scanning,
// data dissection, copy/export operations, and hook detection.
// </summary>
// </file>

using Nexus.UI.Core;
using Nexus.UI.Forms;
using Nexus.UI.Interop;
using Nexus.UI.Styles;

namespace Nexus.UI.Panels;

public partial class DisassemblerPanel
{
    #region New Features (Migrated from MemoryViewerForm)

    private void ShowFindBytesDialog()
    {
        if (_processHandle == IntPtr.Zero)
        {
            MessageBox.Show("No process attached", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        using var dialog = new Form
        {
            Text = "Find Bytes",
            Size = new Size(450, 180),
            FormBorderStyle = FormBorderStyle.FixedDialog,
            StartPosition = FormStartPosition.CenterParent,
            MaximizeBox = false,
            MinimizeBox = false,
            BackColor = NexusTheme.BackgroundPanel
        };

        var lblPattern = new Label { Text = "Byte pattern (hex, e.g. 90 90 ?? 48):", Location = new Point(15, 15), AutoSize = true, ForeColor = NexusTheme.TextPrimary };
        var txtPattern = new TextBox { Location = new Point(15, 38), Width = 400 };
        NexusTheme.StyleTextBox(txtPattern);
        var lblInfo = new Label { Text = "Use ?? or * for wildcards", Location = new Point(15, 65), AutoSize = true, ForeColor = NexusTheme.TextSecondary };

        var btnSearch = new Button { Text = "Find Next", Location = new Point(240, 95), Size = new Size(85, 32), DialogResult = DialogResult.OK };
        var btnCancel = new Button { Text = "Cancel", Location = new Point(330, 95), Size = new Size(85, 32), DialogResult = DialogResult.Cancel };
        NexusTheme.StylePrimaryButton(btnSearch);
        NexusTheme.StyleButton(btnCancel);

        dialog.Controls.AddRange([lblPattern, txtPattern, lblInfo, btnSearch, btnCancel]);
        dialog.AcceptButton = btnSearch;
        dialog.CancelButton = btnCancel;

        if (dialog.ShowDialog(this) != DialogResult.OK || string.IsNullOrWhiteSpace(txtPattern.Text))
            return;

        // Parse the pattern
        var patternStr = txtPattern.Text.Trim();
        var parts = patternStr.Split([' ', ','], StringSplitOptions.RemoveEmptyEntries);
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
        SearchBytes([.. pattern], _disasmSelectedAddress + 1);
    }

    private void SearchBytes(byte?[] pattern, ulong startAddress)
    {
        Cursor = Cursors.WaitCursor;
        UpdateLocalStatus("Searching...");

        try
        {
            // Build pattern string for engine API (e.g., "DE AD ?? EF")
            var sb = new System.Text.StringBuilder();
            for (int i = 0; i < pattern.Length; i++)
            {
                if (i > 0) sb.Append(' ');
                sb.Append(pattern[i].HasValue ? pattern[i]!.Value.ToString("X2") : "??");
            }

            // Use engine pattern scan API
            var results = NexusEngine.PatternScan(_processHandle, sb.ToString(), startAddress, 0, 1);

            if (results.Length > 0)
            {
                ulong foundAddr = results[0];
                GoToAddress(foundAddr);
                UpdateLocalStatus($"Found pattern at 0x{foundAddr:X}");
                MessageBox.Show($"Found pattern at 0x{foundAddr:X}", "Search Result",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
                UpdateLocalStatus("Pattern not found");
                MessageBox.Show("Pattern not found", "Search", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }
        finally
        {
            Cursor = Cursors.Default;
        }
    }

    private void ShowDumpMemoryDialog()
    {
        if (_processHandle == IntPtr.Zero)
        {
            MessageBox.Show("No process attached", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        using var sizeDialog = new Form
        {
            Text = "Dump Memory",
            Size = new Size(350, 180),
            StartPosition = FormStartPosition.CenterParent,
            FormBorderStyle = FormBorderStyle.FixedDialog,
            MaximizeBox = false,
            MinimizeBox = false,
            BackColor = NexusTheme.BackgroundPanel
        };

        var lblAddress = new Label { Text = "Start Address:", Location = new Point(10, 15), AutoSize = true, ForeColor = NexusTheme.TextPrimary };
        var txtAddr = new TextBox { Location = new Point(110, 12), Width = 200, Text = $"{_disasmSelectedAddress:X}" };
        NexusTheme.StyleTextBox(txtAddr);

        var lblSize = new Label { Text = "Size (bytes):", Location = new Point(10, 45), AutoSize = true, ForeColor = NexusTheme.TextPrimary };
        var txtSize = new TextBox { Location = new Point(110, 42), Width = 200, Text = "4096" };
        NexusTheme.StyleTextBox(txtSize);

        var btnOk = new Button { Text = "OK", Location = new Point(145, 90), Size = new Size(80, 28), DialogResult = DialogResult.OK };
        var btnCancel = new Button { Text = "Cancel", Location = new Point(235, 90), Size = new Size(80, 28), DialogResult = DialogResult.Cancel };
        NexusTheme.StylePrimaryButton(btnOk);
        NexusTheme.StyleButton(btnCancel);

        sizeDialog.Controls.AddRange([lblAddress, txtAddr, lblSize, txtSize, btnOk, btnCancel]);
        sizeDialog.AcceptButton = btnOk;
        sizeDialog.CancelButton = btnCancel;

        if (sizeDialog.ShowDialog(this) != DialogResult.OK) return;

        if (!ulong.TryParse(txtAddr.Text.Replace("0x", "").Replace("0X", ""), System.Globalization.NumberStyles.HexNumber, null, out ulong dumpAddr))
        {
            MessageBox.Show("Invalid address", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        if (!ulong.TryParse(txtSize.Text, out ulong dumpSize) || dumpSize == 0)
        {
            MessageBox.Show("Invalid size", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        using var saveDialog = new SaveFileDialog
        {
            Filter = "Binary files (*.bin)|*.bin|All files (*.*)|*.*",
            Title = "Dump memory to file"
        };

        if (saveDialog.ShowDialog() != DialogResult.OK) return;

        var bytes = new byte[dumpSize];
        unsafe
        {
            fixed (byte* ptr = bytes)
            {
                NexusEngine.Nexus_ReadMemory(_processHandle, dumpAddr, (IntPtr)ptr, (nuint)dumpSize, out nuint read);
                File.WriteAllBytes(saveDialog.FileName, bytes[..(int)read]);
            }
        }

        MessageBox.Show($"Dumped {dumpSize} bytes to {saveDialog.FileName}", "Dump Complete",
            MessageBoxButtons.OK, MessageBoxIcon.Information);
        UpdateLocalStatus($"Dumped {dumpSize} bytes to file");
    }

    private void ShowAllocateMemoryDialog()
    {
        if (_processHandle == IntPtr.Zero)
        {
            MessageBox.Show("No process attached", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        using var dialog = new Form
        {
            Text = "Allocate Memory",
            Size = new Size(350, 210),
            StartPosition = FormStartPosition.CenterParent,
            FormBorderStyle = FormBorderStyle.FixedDialog,
            MaximizeBox = false,
            MinimizeBox = false,
            BackColor = NexusTheme.BackgroundPanel
        };

        var lblSize = new Label { Text = "Size (bytes):", Location = new Point(10, 15), AutoSize = true, ForeColor = NexusTheme.TextPrimary };
        var txtSize = new TextBox { Location = new Point(110, 12), Width = 200, Text = "4096" };
        NexusTheme.StyleTextBox(txtSize);

        var lblProt = new Label { Text = "Protection:", Location = new Point(10, 45), AutoSize = true, ForeColor = NexusTheme.TextPrimary };
        var cboProt = new ComboBox { Location = new Point(110, 42), Width = 200, DropDownStyle = ComboBoxStyle.DropDownList };
        cboProt.Items.AddRange([
            "PAGE_EXECUTE_READWRITE (0x40)",
            "PAGE_EXECUTE_READ (0x20)",
            "PAGE_READWRITE (0x04)",
            "PAGE_READONLY (0x02)"
        ]);
        cboProt.SelectedIndex = 0;
        NexusTheme.StyleComboBox(cboProt);

        var lblResult = new Label { Text = "Allocated at:", Location = new Point(10, 80), AutoSize = true, ForeColor = NexusTheme.TextPrimary };
        var txtResult = new TextBox { Location = new Point(110, 77), Width = 200, ReadOnly = true };
        NexusTheme.StyleTextBox(txtResult);

        var btnAllocate = new Button { Text = "Allocate", Location = new Point(110, 115), Size = new Size(90, 28) };
        var btnGoTo = new Button { Text = "Go To", Location = new Point(210, 115), Size = new Size(70, 28), Enabled = false };
        var btnClose = new Button { Text = "Close", Location = new Point(110, 150), Size = new Size(170, 28), DialogResult = DialogResult.Cancel };
        NexusTheme.StylePrimaryButton(btnAllocate);
        NexusTheme.StyleButton(btnGoTo);
        NexusTheme.StyleButton(btnClose);

        ulong allocatedAddress = 0;

        btnAllocate.Click += (s, e) =>
        {
            if (!ulong.TryParse(txtSize.Text, out ulong size) || size == 0)
            {
                MessageBox.Show("Invalid size", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            uint protect = cboProt.SelectedIndex switch
            {
                0 => 0x40, // PAGE_EXECUTE_READWRITE
                1 => 0x20, // PAGE_EXECUTE_READ
                2 => 0x04, // PAGE_READWRITE
                3 => 0x02, // PAGE_READONLY
                _ => 0x04
            };

            var result = NexusEngine.Nexus_AllocateMemory(_processHandle, (nuint)size, protect, out ulong addr);
            if (result == NexusResult.OK && addr != 0)
            {
                allocatedAddress = addr;
                txtResult.Text = $"0x{addr:X}";
                btnGoTo.Enabled = true;
                UpdateLocalStatus($"Allocated {size} bytes at 0x{addr:X}");
            }
            else
            {
                MessageBox.Show($"Allocation failed: {result}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        };

        btnGoTo.Click += (s, e) =>
        {
            if (allocatedAddress != 0)
            {
                GoToAddress(allocatedAddress);
                dialog.Close();
            }
        };

        dialog.Controls.AddRange([lblSize, txtSize, lblProt, cboProt, lblResult, txtResult, btnAllocate, btnGoTo, btnClose]);
        dialog.CancelButton = btnClose;
        dialog.ShowDialog(this);
    }

    private void ShowProtectionDialog()
    {
        if (_processHandle == IntPtr.Zero)
        {
            MessageBox.Show("No process attached", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        ulong selectedAddr = _disasmSelectedAddress;

        using var dialog = new Form
        {
            Text = "Change Memory Protection",
            Size = new Size(350, 210),
            StartPosition = FormStartPosition.CenterParent,
            FormBorderStyle = FormBorderStyle.FixedDialog,
            MaximizeBox = false,
            MinimizeBox = false,
            BackColor = NexusTheme.BackgroundPanel
        };

        var lblAddress = new Label { Text = "Address:", Location = new Point(10, 15), AutoSize = true, ForeColor = NexusTheme.TextPrimary };
        var txtAddr = new TextBox { Location = new Point(110, 12), Width = 200, Text = $"{selectedAddr:X}" };
        NexusTheme.StyleTextBox(txtAddr);

        var lblSize = new Label { Text = "Size:", Location = new Point(10, 45), AutoSize = true, ForeColor = NexusTheme.TextPrimary };
        var txtSize = new TextBox { Location = new Point(110, 42), Width = 200, Text = "4096" };
        NexusTheme.StyleTextBox(txtSize);

        var lblProt = new Label { Text = "Protection:", Location = new Point(10, 75), AutoSize = true, ForeColor = NexusTheme.TextPrimary };
        var cboProt = new ComboBox { Location = new Point(110, 72), Width = 200, DropDownStyle = ComboBoxStyle.DropDownList };
        cboProt.Items.AddRange([
            "PAGE_EXECUTE_READWRITE (0x40)",
            "PAGE_EXECUTE_READ (0x20)",
            "PAGE_READWRITE (0x04)",
            "PAGE_READONLY (0x02)"
        ]);
        cboProt.SelectedIndex = 0;
        NexusTheme.StyleComboBox(cboProt);

        var btnOk = new Button { Text = "OK", Location = new Point(145, 115), Size = new Size(80, 32), DialogResult = DialogResult.OK };
        var btnCancel = new Button { Text = "Cancel", Location = new Point(235, 115), Size = new Size(80, 32), DialogResult = DialogResult.Cancel };
        NexusTheme.StylePrimaryButton(btnOk);
        NexusTheme.StyleButton(btnCancel);

        dialog.Controls.AddRange([lblAddress, txtAddr, lblSize, txtSize, lblProt, cboProt, btnOk, btnCancel]);
        dialog.AcceptButton = btnOk;
        dialog.CancelButton = btnCancel;

        if (dialog.ShowDialog(this) == DialogResult.OK)
        {
            if (!ulong.TryParse(txtAddr.Text.Replace("0x", "").Replace("0X", ""), System.Globalization.NumberStyles.HexNumber, null, out ulong addr))
            {
                MessageBox.Show("Invalid address", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            if (!ulong.TryParse(txtSize.Text, out ulong size))
            {
                MessageBox.Show("Invalid size", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            uint newProtect = cboProt.SelectedIndex switch
            {
                0 => 0x40, // PAGE_EXECUTE_READWRITE
                1 => 0x20, // PAGE_EXECUTE_READ
                2 => 0x04, // PAGE_READWRITE
                3 => 0x02, // PAGE_READONLY
                _ => 0x04
            };

            var result = NexusEngine.Nexus_ProtectMemory(_processHandle, addr, (nuint)size, newProtect, out uint oldProtect);

            if (result == NexusResult.OK)
            {
                MessageBox.Show($"Protection changed from 0x{oldProtect:X} to 0x{newProtect:X}",
                    "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
                UpdateLocalStatus($"Protection changed at 0x{addr:X}");
                RefreshViews();
            }
            else
            {
                MessageBox.Show($"Protection change failed: {result}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }

    private void ShowSymbolInfo()
    {
        if (_processHandle == IntPtr.Zero)
        {
            MessageBox.Show("No process attached", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        ulong selectedAddr = _disasmSelectedAddress;

        // Create symbol handler
        uint options = NexusEngine.NEXUS_SYM_UNDNAME | NexusEngine.NEXUS_SYM_DEFERRED_LOADS;
        var result = NexusEngine.Nexus_SymbolCreate(_processHandle, options, out IntPtr symbolHandle);
        if (result != NexusResult.OK)
        {
            MessageBox.Show($"Failed to create symbol handler: {result}", "Symbol Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        try
        {
            result = NexusEngine.Nexus_SymbolFromAddress(symbolHandle, selectedAddr, out var info, out var displacement);
            if (result == NexusResult.OK)
            {
                string dispStr = displacement != 0 ? $"+0x{displacement:X}" : "";
                MessageBox.Show(
                    $"Address: 0x{selectedAddr:X16}\n" +
                    $"Symbol: {info.Name}{dispStr}\n" +
                    $"Module: {info.ModuleName}",
                    "Symbol Info",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
                UpdateLocalStatus($"Symbol: {info.Name}{dispStr}");
            }
            else
            {
                MessageBox.Show("No symbol found at this address", "Symbol Info",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }
        finally
        {
            NexusEngine.Nexus_SymbolDestroy(symbolHandle);
        }
    }

    private void ShowCFGForCurrentAddress()
    {
        ulong selectedAddr = _disasmSelectedAddress;
        if (selectedAddr == 0)
        {
            UpdateLocalStatus("No address selected");
            return;
        }

        // Publish navigate event to switch to CFG panel and analyze
        PublishEvent(new NavigateToAddressEvent(selectedAddr, "CFG"));
    }

    private void OpenInDissectData(bool _)
    {
        if (_processHandle == IntPtr.Zero)
        {
            MessageBox.Show("No process attached", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        ulong selectedAddr = _disasmSelectedAddress;
        if (selectedAddr == 0)
        {
            UpdateLocalStatus("No address selected");
            return;
        }

        var form = new DissectDataForm(_processHandle, selectedAddr, _is64Bit);
        form.Show(this);
    }

    #endregion
}
