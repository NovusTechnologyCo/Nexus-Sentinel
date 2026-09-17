// <file>
// <summary>
// Partial class for DisassemblerPanel containing inline assembly and byte editing:
// assemble dialog, NOP fill, undo/redo operations, and direct byte patching.
// </summary>
// </file>

using Nexus.UI.Forms;
using Nexus.UI.Interop;
using Nexus.UI.Styles;

namespace Nexus.UI.Panels;

public partial class DisassemblerPanel
{
    #region Assembly & Editing

    private void ShowAssembleDialog(ulong? address = null, string? currentInstruction = null)
    {
        ulong targetAddress = address ?? _disasmSelectedAddress;
        string instruction = currentInstruction ?? "";

        using var dialog = new Form
        {
            Text = "Single-line assembler",
            Size = new Size(620, 180),
            StartPosition = FormStartPosition.CenterParent,
            FormBorderStyle = FormBorderStyle.FixedDialog,
            MaximizeBox = false,
            MinimizeBox = false,
            BackColor = NexusTheme.BackgroundPanel
        };

        var label = new Label
        {
            Text = $"Enter instruction (address=0x{targetAddress:X}):",
            Location = new Point(12, 15),
            AutoSize = true,
            ForeColor = NexusTheme.TextPrimary
        };

        var textBox = new TextBox
        {
            Location = new Point(12, 45),
            Size = new Size(580, 23),
            Text = instruction,
            Font = NexusTheme.FontMono
        };
        NexusTheme.StyleTextBox(textBox);

        var btnOk = new Button { Text = "OK", Location = new Point(420, 90), Size = new Size(80, 30), DialogResult = DialogResult.OK };
        var btnCancel = new Button { Text = "Cancel", Location = new Point(510, 90), Size = new Size(80, 30), DialogResult = DialogResult.Cancel };
        NexusTheme.StylePrimaryButton(btnOk);
        NexusTheme.StyleButton(btnCancel);

        dialog.Controls.AddRange([label, textBox, btnOk, btnCancel]);
        dialog.AcceptButton = btnOk;
        dialog.CancelButton = btnCancel;

        if (dialog.ShowDialog(this) == DialogResult.OK && !string.IsNullOrWhiteSpace(textBox.Text))
        {
            AssembleAndWrite(targetAddress, textBox.Text.Trim());
        }
    }

    private void ShowAutoAssembleDialog()
    {
        if (_processHandle == IntPtr.Zero)
        {
            MessageBox.Show("No process attached", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        var form = new AutoInjectForm(_processHandle);
        form.Show(this);
    }

    private void AssembleAndWrite(ulong address, string instruction)
    {
        if (_processHandle == IntPtr.Zero) return;

        var result = NexusEngine.Nexus_Assemble(instruction, address, _is64Bit, out var bytes, out var length, out var error);

        if (result != NexusResult.OK || length == 0)
        {
            string errorMsg = !string.IsNullOrEmpty(error) ? error : "Assembly failed";
            MessageBox.Show(errorMsg, "Assembler Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        if (!SaveBytesForUndo(address, (int)length, $"Assemble: {instruction}"))
            return;

        unsafe
        {
            fixed (byte* ptr = bytes)
            {
                var writeResult = NexusEngine.Nexus_WriteMemory(_processHandle, address, (IntPtr)ptr, length, out _);
                if (writeResult != NexusResult.OK)
                {
                    if (_undoStack.Count > 0) _undoStack.Pop();
                    MessageBox.Show($"Failed to write memory", "Write Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
            }
        }

        RefreshDisasmView();
        UpdateLocalStatus($"Assembled and wrote {length} bytes at 0x{address:X}");
    }

    private void ReplaceWithNop()
    {
        if (_processHandle == IntPtr.Zero || _disasmSelectedAddress == 0) return;

        if (_disasmSelectionEnd <= _disasmSelectedAddress) return;
        ulong rawLength = _disasmSelectionEnd - _disasmSelectedAddress;
        if (rawLength > 4096)
        {
            MessageBox.Show($"Selection too large ({rawLength} bytes). Maximum is 4096.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }
        int length = (int)rawLength;

        var result = MessageBox.Show(
            $"Replace {length} bytes at 0x{_disasmSelectedAddress:X} with NOP (0x90)?",
            "Replace with NOP",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Question);

        if (result != DialogResult.Yes) return;

        if (!SaveBytesForUndo(_disasmSelectedAddress, length, $"NOP {length} bytes"))
            return;

        var nopBuffer = new byte[length];
        Array.Fill(nopBuffer, (byte)0x90);

        unsafe
        {
            fixed (byte* ptr = nopBuffer)
            {
                var writeResult = NexusEngine.Nexus_WriteMemory(_processHandle, _disasmSelectedAddress, (IntPtr)ptr, (nuint)length, out _);
                if (writeResult != NexusResult.OK)
                {
                    if (_undoStack.Count > 0) _undoStack.Pop();
                    MessageBox.Show("Failed to write memory", "Write Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
            }
        }

        RefreshDisasmView();
        UpdateLocalStatus($"Replaced {length} bytes with NOP at 0x{_disasmSelectedAddress:X}");
    }

    private bool SaveBytesForUndo(ulong address, int length, string description)
    {
        if (_processHandle == IntPtr.Zero || length <= 0) return false;

        var originalBytes = new byte[length];
        unsafe
        {
            fixed (byte* ptr = originalBytes)
            {
                var readResult = NexusEngine.Nexus_ReadMemory(_processHandle, address, (IntPtr)ptr, (nuint)length, out _);
                if (readResult != NexusResult.OK)
                {
                    MessageBox.Show("Failed to read original bytes for undo", "Warning", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return false;
                }
            }
        }

        _undoStack.Push(new UndoEntry(address, originalBytes, description));
        return true;
    }

    private void UndoLastChange()
    {
        if (_processHandle == IntPtr.Zero || _undoStack.Count == 0)
        {
            UpdateLocalStatus("Nothing to undo");
            return;
        }

        var entry = _undoStack.Pop();

        unsafe
        {
            fixed (byte* ptr = entry.OriginalBytes)
            {
                var writeResult = NexusEngine.Nexus_WriteMemory(_processHandle, entry.Address, (IntPtr)ptr, (nuint)entry.OriginalBytes.Length, out _);
                if (writeResult != NexusResult.OK)
                {
                    _undoStack.Push(entry);
                    MessageBox.Show("Failed to undo", "Undo Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
            }
        }

        RefreshViews();
        UpdateLocalStatus($"Undone: {entry.Description}");
    }

    private void ShowEditValueDialog()
    {
        if (_processHandle == IntPtr.Zero) return;

        ulong address = _disasmSelectedAddress;
        int size = GetDisplayTypeSize();

        var bytes = new byte[size];
        unsafe
        {
            fixed (byte* ptr = bytes)
            {
                NexusEngine.Nexus_ReadMemory(_processHandle, address, (IntPtr)ptr, (nuint)size, out _);
            }
        }

        string currentValue = _displayTypeCombo.SelectedIndex switch
        {
            0 => bytes[0].ToString(),
            1 => BitConverter.ToInt16(bytes, 0).ToString(),
            2 => BitConverter.ToInt32(bytes, 0).ToString(),
            3 => BitConverter.ToInt64(bytes, 0).ToString(),
            4 => BitConverter.ToSingle(bytes, 0).ToString("G"),
            5 => BitConverter.ToDouble(bytes, 0).ToString("G"),
            _ => bytes[0].ToString()
        };

        using var dialog = new ChangeValueForm(currentValue, false);
        dialog.Text = $"Edit value at 0x{address:X}";
        if (dialog.ShowDialog(this) == DialogResult.OK)
        {
            WriteValueFromDialog(address, dialog.Value, _displayTypeCombo.SelectedIndex);
        }
    }

    private void WriteValueFromDialog(ulong address, string valueText, int typeIndex)
    {
        byte[]? bytes = null;
        try
        {
            bytes = typeIndex switch
            {
                0 => [byte.Parse(valueText)],
                1 => BitConverter.GetBytes(short.Parse(valueText)),
                2 => BitConverter.GetBytes(int.Parse(valueText)),
                3 => BitConverter.GetBytes(long.Parse(valueText)),
                4 => BitConverter.GetBytes(float.Parse(valueText)),
                5 => BitConverter.GetBytes(double.Parse(valueText)),
                _ => [byte.Parse(valueText)]
            };
        }
        catch
        {
            MessageBox.Show("Invalid value", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        if (bytes != null)
        {
            unsafe
            {
                fixed (byte* ptr = bytes)
                {
                    NexusEngine.Nexus_WriteMemory(_processHandle, address, (IntPtr)ptr, (nuint)bytes.Length, out _);
                }
            }
            RefreshViews();
        }
    }

    private int GetDisplayTypeSize()
    {
        return _displayTypeCombo.SelectedIndex switch
        {
            0 => 1,
            1 => 2,
            2 => 4,
            3 => 8,
            4 => 4,
            5 => 8,
            _ => 1
        };
    }

    private void ShowFillMemoryDialog()
    {
        if (_processHandle == IntPtr.Zero) return;

        using var dialog = new FillMemoryForm(_processHandle, _disasmSelectedAddress, _disasmSelectedAddress + 0x100);
        dialog.ShowDialog(this);
        RefreshViews();
    }

    #endregion
}
