using System.Drawing.Drawing2D;
using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using Nexus.UI.Styles;

namespace Nexus.UI.Forms;

public partial class MemoryViewerForm
{
    #region Disassembly View

    private void PnlDisasm_Paint(object? sender, PaintEventArgs e)
    {
        var g = e.Graphics;
        g.Clear(_backgroundColor);

        if (_processHandle == IntPtr.Zero)
        {
            g.DrawString("No process selected", _disasmFont, Brushes.Gray, 10, 10);
            _cachedDisasmCount = 0;
            return;
        }

        int lineHeight = (int)_disasmFont.GetHeight(g) + 2;
        _disasmLineHeight = lineHeight;
        int y = 2;

        // If memory read failed, show ?? for all lines
        if (!_disasmReadSuccess)
        {
            _cachedDisasmCount = 0;
            for (int row = 0; row < 32 && y < pnlDisasm.Height; row++)
            {
                ulong addr = _baseAddress + (ulong)row;
                g.DrawString($"{addr:X16}  ??", _disasmFont, Brushes.Black, 2, y);
                y += lineHeight;
            }
            return;
        }

        // Disassemble directly from process memory using the correct API
        if (_cachedDisasm.Length < 64)
            _cachedDisasm = new NexusDisasmInstruction[64];

        var result = NexusEngine.Nexus_DisasmDecodeProcess(
            _processHandle,
            _baseAddress,
            (nuint)_cachedDisasm.Length,
            _cachedDisasm,
            out nuint count);

        // Track where we are in memory for fallback raw bytes
        ulong currentAddr = _baseAddress;
        int bufferOffset = 0;

        // If disassembly succeeded, show decoded instructions
        if ((result == NexusResult.OK || result == NexusResult.Success) && count > 0)
        {
            _cachedDisasmCount = (int)count;

            for (int i = 0; i < _cachedDisasmCount && y < pnlDisasm.Height; i++)
            {
                var insn = _cachedDisasm[i];
                // Use the Text field which contains the full formatted instruction
                // Show "??" for undefined bytes (db XX) instead of the raw byte
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

                // Check for breakpoint
                bool hasBreakpoint = _breakpoints.ContainsKey(insn.Address);

                // Draw breakpoint marker (red circle on left margin)
                if (hasBreakpoint)
                {
                    int markerSize = lineHeight - 4;
                    int markerY = y + 1;
                    using var markerBrush = new SolidBrush(_breakpointMarkerColor);
                    g.FillEllipse(markerBrush, 2, markerY, markerSize, markerSize);
                }

                // Offset text if showing breakpoint margin
                int textX = hasBreakpoint ? 18 : 2;
                string line = $"{insn.Address:X16}  {instrText}";

                // Highlight if instruction falls within selection range (disasm uses its own selection)
                bool isSelected = insn.Address >= _disasmSelectedAddress &&
                                  insn.Address < _disasmSelectionEnd;
                if (isSelected)
                {
                    g.FillRectangle(new SolidBrush(_selectionBackColor), hasBreakpoint ? 16 : 0, y - 1, pnlDisasm.Width, lineHeight);
                    g.DrawString(line, _disasmFont, new SolidBrush(_selectionForeColor), textX, y);
                }
                else if (hasBreakpoint)
                {
                    // Light red background for breakpoint lines
                    g.FillRectangle(new SolidBrush(_breakpointBackColor), 16, y - 1, pnlDisasm.Width, lineHeight);
                    g.DrawString(line, _disasmFont, Brushes.Black, textX, y);
                }
                else
                {
                    // Color code based on instruction type
                    Brush brush = insn.IsCall != 0 ? Brushes.Blue :
                                  insn.IsBranch != 0 ? Brushes.Green :
                                  insn.IsReturn != 0 ? Brushes.DarkRed :
                                  Brushes.Black;
                    g.DrawString(line, _disasmFont, brush, textX, y);
                }

                y += lineHeight;
                currentAddr = insn.Address + insn.Length;
                bufferOffset = (int)(currentAddr - _baseAddress);
            }
        }
        else
        {
            _cachedDisasmCount = 0;
        }

        // If disassembly stopped early or failed, continue with raw bytes
        if (y < pnlDisasm.Height && bufferOffset < _disasmMemoryBuffer.Length)
        {
            while (y < pnlDisasm.Height && bufferOffset < _disasmMemoryBuffer.Length)
            {
                ulong addr = _baseAddress + (ulong)bufferOffset;
                byte b = _disasmMemoryBuffer[bufferOffset];

                string line = $"{addr:X16}  db {b:X2}";

                // Highlight if selected (disasm uses its own selection range)
                bool isSelected = addr >= _disasmSelectedAddress && addr < _disasmSelectionEnd;
                if (isSelected)
                {
                    g.FillRectangle(new SolidBrush(_selectionBackColor), 0, y - 1, pnlDisasm.Width, lineHeight);
                    g.DrawString(line, _disasmFont, new SolidBrush(_selectionForeColor), 2, y);
                }
                else
                {
                    // Gray for raw bytes (indicates disassembly failed here)
                    g.DrawString(line, _disasmFont, Brushes.Gray, 2, y);
                }

                y += lineHeight;
                bufferOffset++;
            }
        }
    }

    private void PnlDisasm_MouseWheel(object? sender, MouseEventArgs e)
    {
        // Scroll by instruction count, not byte count
        int linesToScroll = e.Delta > 0 ? -3 : 3; // Scroll 3 instructions at a time

        ScrollDisasmByInstructions(linesToScroll);
    }

    private void DisasmScrollBar_Scroll(object? sender, ScrollEventArgs e)
    {
        int delta = e.NewValue - (disasmScrollBar.Maximum / 2);
        if (delta == 0) return;

        ScrollDisasmByInstructions(delta);

        // Reset scrollbar to center for continuous scrolling
        disasmScrollBar.Value = disasmScrollBar.Maximum / 2;
    }

    /// <summary>
    /// Scrolls the disassembly view by a number of instructions.
    /// Uses cached disassembly for scrolling down, re-disassembles for scrolling up.
    /// </summary>
    private void ScrollDisasmByInstructions(int instructionCount)
    {
        if (instructionCount == 0) return;

        long scrollDelta;

        if (instructionCount > 0 && _cachedDisasmCount > 0)
        {
            // Scrolling down - use cached instruction boundaries
            int skipCount = Math.Min(instructionCount, _cachedDisasmCount - 1);
            if (skipCount > 0 && skipCount < _cachedDisasmCount)
            {
                // Move to the address of the Nth instruction
                scrollDelta = (long)(_cachedDisasm[skipCount].Address - _baseAddress);
            }
            else
            {
                // Fallback: estimate based on average instruction size
                scrollDelta = instructionCount * 4;
            }
        }
        else if (instructionCount < 0)
        {
            // Scrolling up - need to find instruction boundaries before current address
            // Use a heuristic: back up and re-disassemble to find boundaries
            int backupBytes = Math.Abs(instructionCount) * 8; // Generous estimate
            ulong scanStart = _baseAddress > (ulong)backupBytes ? _baseAddress - (ulong)backupBytes : 0;

            // Disassemble from the backup point to find instruction that ends at or near _baseAddress
            var tempDisasm = new NexusDisasmInstruction[64];
            var result = NexusEngine.Nexus_DisasmDecodeProcess(
                _processHandle, scanStart, 64, tempDisasm, out nuint count);

            if (result == NexusResult.OK && count > 0)
            {
                // Find instruction boundaries leading up to current address
                int targetIdx = -1;
                for (int i = 0; i < (int)count; i++)
                {
                    if (tempDisasm[i].Address >= _baseAddress)
                    {
                        // Found where we are, back up by requested instruction count
                        targetIdx = Math.Max(0, i + instructionCount);
                        break;
                    }
                }

                if (targetIdx >= 0 && targetIdx < (int)count)
                {
                    scrollDelta = (long)tempDisasm[targetIdx].Address - (long)_baseAddress;
                }
                else
                {
                    // Fallback
                    scrollDelta = instructionCount * 4;
                }
            }
            else
            {
                // Disassembly failed, use byte-based fallback
                scrollDelta = instructionCount * 4;
            }
        }
        else
        {
            // No cached disasm, use fallback
            scrollDelta = instructionCount * 4;
        }

        // Apply the scroll (disasm only - independent from hex view)
        long newBaseAddress = (long)_baseAddress + scrollDelta;
        if (newBaseAddress < 0) newBaseAddress = 0;
        _baseAddress = (ulong)newBaseAddress;

        // Update scrollbar position
        disasmScrollBar.Value = disasmScrollBar.Maximum / 2;

        // Only refresh disasm view
        RefreshDisasmMemory();
    }

    private void PnlDisasm_MouseDown(object? sender, MouseEventArgs e)
    {
        if (_cachedDisasmCount == 0 || _disasmLineHeight == 0) return;

        // Calculate which instruction was clicked
        int row = (e.Y - 2) / _disasmLineHeight;

        if (row >= 0 && row < _cachedDisasmCount)
        {
            ulong clickedAddress = _cachedDisasm[row].Address;
            _lastActiveViewIsHex = false;

            if ((Control.ModifierKeys & Keys.Shift) != 0 && _disasmSelectionAnchor != 0)
            {
                // Shift+click: extend selection from anchor to clicked address
                if (clickedAddress >= _disasmSelectionAnchor)
                {
                    _disasmSelectedAddress = _disasmSelectionAnchor;
                    _disasmSelectionEnd = clickedAddress + _cachedDisasm[row].Length;
                }
                else
                {
                    _disasmSelectedAddress = clickedAddress;
                    // Find the end of the anchor instruction
                    for (int i = 0; i < _cachedDisasmCount; i++)
                    {
                        if (_cachedDisasm[i].Address == _disasmSelectionAnchor)
                        {
                            _disasmSelectionEnd = _cachedDisasm[i].Address + _cachedDisasm[i].Length;
                            break;
                        }
                    }
                }
            }
            else
            {
                // Normal click: set new selection and anchor
                _disasmSelectedAddress = clickedAddress;
                _disasmSelectionEnd = clickedAddress + _cachedDisasm[row].Length;
                _disasmSelectionAnchor = clickedAddress;
            }

            _disasmSelectionLength = (int)(_disasmSelectionEnd - _disasmSelectedAddress);

            // Update status bar
            if (_disasmSelectionEnd > _disasmSelectedAddress + 16)
            {
                lblSelectedAddress.Text = $"Selected: 0x{_disasmSelectedAddress:X} - 0x{_disasmSelectionEnd:X}";
            }
            else
            {
                lblSelectedAddress.Text = $"Selected: 0x{_disasmSelectedAddress:X}";
            }

            // Only refresh disasm view (independent selection)
            pnlDisasm.Invalidate();
        }

        pnlDisasm.Focus();
    }

    private void PnlDisasm_MouseDoubleClick(object? sender, MouseEventArgs e)
    {
        if (_cachedDisasmCount == 0 || _disasmLineHeight == 0) return;

        // Calculate which instruction was double-clicked
        int row = (e.Y - 2) / _disasmLineHeight;

        if (row >= 0 && row < _cachedDisasmCount)
        {
            var insn = _cachedDisasm[row];
            ShowSingleLineAssembler(insn.Address, insn.Text ?? $"{insn.Mnemonic} {insn.Operands}".Trim());
        }
    }

    private void PnlDisasm_KeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Control && e.KeyCode == Keys.Z)
        {
            UndoLastChange();
            e.Handled = true;
        }
    }

    private void ShowSingleLineAssembler(ulong address, string currentInstruction)
    {
        using var dialog = new Form
        {
            Text = "Single-line assembler",
            Size = new Size(620, 220),
            StartPosition = FormStartPosition.CenterParent,
            FormBorderStyle = FormBorderStyle.FixedDialog,
            MaximizeBox = false,
            MinimizeBox = false
        };

        var label = new Label
        {
            Text = $"Type your assembler code here: (address={address:X})",
            Location = new Point(12, 15),
            AutoSize = true
        };

        var textBox = new TextBox
        {
            Location = new Point(12, 45),
            Size = new Size(580, 23),
            Text = currentInstruction,
            Font = new Font("Consolas", 10f)
        };
        NexusTheme.StyleTextBox(textBox);

        var btnOk = new Button
        {
            Text = "OK",
            Location = new Point(420, 100),
            Size = new Size(80, 30),
            DialogResult = DialogResult.OK
        };

        var btnCancel = new Button
        {
            Text = "Cancel",
            Location = new Point(510, 100),
            Size = new Size(80, 30),
            DialogResult = DialogResult.Cancel
        };

        dialog.Controls.AddRange([label, textBox, btnOk, btnCancel]);
        dialog.AcceptButton = btnOk;
        dialog.CancelButton = btnCancel;

        if (dialog.ShowDialog(this) == DialogResult.OK && !string.IsNullOrWhiteSpace(textBox.Text))
        {
            AssembleAndWrite(address, textBox.Text.Trim());
        }
    }

    private void AssembleAndWrite(ulong address, string instruction)
    {
        if (_processHandle == IntPtr.Zero) return;

        // Determine if target process is 64-bit
        bool is64Bit = true;
        if (_processHandle != IntPtr.Zero)
        {
            var result = NexusEngine.Nexus_GetProcessInfo(_processHandle, out var info);
            if (result == NexusResult.OK)
            {
                is64Bit = info.Is32Bit == 0; // Is64Bit = !Is32Bit
            }
        }

        // Use the engine's assembler
        var asmResult = NexusEngine.Nexus_Assemble(
            instruction,
            address,
            is64Bit,
            out var bytes,
            out var length,
            out var error);

        if (asmResult != NexusResult.OK || length == 0)
        {
            string errorMsg = !string.IsNullOrEmpty(error) ? error : "Assembly failed";
            MessageBox.Show(errorMsg, "Assembler Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        // Save original bytes for undo
        SaveBytesForUndo(address, (int)length, $"Assemble: {instruction}");

        // Write the assembled bytes to memory
        NexusResult writeResult;
        unsafe
        {
            fixed (byte* ptr = bytes)
            {
                writeResult = NexusEngine.Nexus_WriteMemory(
                    _processHandle,
                    address,
                    (IntPtr)ptr,
                    length,
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

        // Refresh disasm view to show the change
        RefreshDisasmMemory();
    }

    private void SaveBytesForUndo(ulong address, int length, string description)
    {
        if (_processHandle == IntPtr.Zero || length <= 0) return;

        var originalBytes = new byte[length];
        unsafe
        {
            fixed (byte* ptr = originalBytes)
            {
                NexusEngine.Nexus_ReadMemory(_processHandle, address, (IntPtr)ptr, (nuint)length, out _);
            }
        }

        _undoStack.Push(new UndoEntry(address, originalBytes, description));
    }

    private void UndoLastChange()
    {
        if (_processHandle == IntPtr.Zero || _undoStack.Count == 0)
        {
            MessageBox.Show("Nothing to undo.", "Undo", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var entry = _undoStack.Pop();

        // Write original bytes back
        NexusResult writeResult;
        unsafe
        {
            fixed (byte* ptr = entry.OriginalBytes)
            {
                writeResult = NexusEngine.Nexus_WriteMemory(
                    _processHandle,
                    entry.Address,
                    (IntPtr)ptr,
                    (nuint)entry.OriginalBytes.Length,
                    out _);
            }
        }

        if (writeResult != NexusResult.OK)
        {
            // Put it back on the stack since undo failed
            _undoStack.Push(entry);
            MessageBox.Show($"Failed to undo: {NexusHelper.GetErrorMessage(writeResult)}",
                "Undo Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        // Refresh views
        RefreshDisasmMemory();
        RefreshHexMemory();
    }

    #endregion
}
