// <file>
// <summary>
// Partial class for DisassemblerPanel handling all custom painting/rendering.
// Renders the disassembly view with syntax-highlighted instructions, breakpoint
// markers, selection highlighting, address labels, and instruction byte columns.
// </summary>
// </file>

using Nexus.UI.Interop;

namespace Nexus.UI.Panels;

public partial class DisassemblerPanel
{
    #region Disasm View Rendering

    private void DisasmPanel_Paint(object? sender, PaintEventArgs e)
    {
        var g = e.Graphics;
        g.Clear(_viewBackColor);

        if (_processHandle == IntPtr.Zero)
        {
            g.DrawString("Attach to a process to begin disassembly", _disasmFont, Brushes.Gray, 10, 10);
            _cachedDisasmCount = 0;
            return;
        }

        int lineHeight = (int)_disasmFont.GetHeight(g) + 2;
        _disasmLineHeight = lineHeight;
        int y = 2;

        // Column widths for x64dbg-style layout
        int charWidth = (int)g.MeasureString("0", _disasmFont).Width - 3;
        int addressWidth = charWidth * 17;   // 16 hex chars + space
        int bytesWidth = charWidth * 26;     // Room for "XX XX XX XX XX XX XX XX " (8 bytes typical)

        using var addressBrush = new SolidBrush(_addressColor);
        using var bytesBrush = new SolidBrush(_bytesColor);
        using var selectionBackBrush = new SolidBrush(_selectionBackColor);
        using var selectionForeBrush = new SolidBrush(_selectionForeColor);
        using var breakpointBackBrush = new SolidBrush(_breakpointBackColor);
        using var hexBrush = new SolidBrush(_hexColor);

        if (!_disasmReadSuccess)
        {
            _cachedDisasmCount = 0;
            for (int row = 0; row < 32 && y < _disasmPanel.Height; row++)
            {
                ulong addr = _disasmAddress + (ulong)row;
                g.DrawString($"{addr:X16}", _disasmFont, Brushes.Gray, 2, y);
                g.DrawString("??", _disasmFont, Brushes.Gray, 2 + addressWidth, y);
                y += lineHeight;
            }
            return;
        }

        // Disassemble from process memory
        if (_cachedDisasm.Length < 64)
            _cachedDisasm = new NexusDisasmInstruction[64];

        var result = NexusEngine.Nexus_DisasmDecodeProcess(_processHandle, _disasmAddress, 64, _cachedDisasm, out nuint count);

        ulong currentAddr = _disasmAddress;
        int bufferOffset = 0;

        if ((result == NexusResult.OK || result == NexusResult.Success) && count > 0)
        {
            _cachedDisasmCount = (int)count;

            for (int i = 0; i < _cachedDisasmCount && y < _disasmPanel.Height; i++)
            {
                var insn = _cachedDisasm[i];

                // Determine instruction text
                string instrText;
                bool isUndefined = string.IsNullOrEmpty(insn.Mnemonic) ||
                                   insn.Mnemonic.Equals("db", StringComparison.OrdinalIgnoreCase) ||
                                   (!string.IsNullOrEmpty(insn.Text) && insn.Text.StartsWith("db ", StringComparison.OrdinalIgnoreCase));

                if (isUndefined)
                    instrText = "??";
                else if (!string.IsNullOrEmpty(insn.Text))
                    instrText = insn.Text;
                else
                    instrText = insn.Mnemonic;

                // Format instruction bytes (x64dbg style)
                string bytesStr = FormatInstructionBytes(insn.Bytes, insn.Length);

                // Check for breakpoint
                bool hasBreakpoint = _breakpoints.ContainsKey(insn.Address);

                // Draw breakpoint marker
                if (hasBreakpoint)
                {
                    int markerSize = lineHeight - 4;
                    using var markerBrush = new SolidBrush(_breakpointMarkerColor);
                    g.FillEllipse(markerBrush, 2, y + 1, markerSize, markerSize);
                }

                int textX = hasBreakpoint ? 18 : 2;

                // Highlight selection
                bool isSelected = insn.Address >= _disasmSelectedAddress && insn.Address < _disasmSelectionEnd;

                if (isSelected)
                {
                    g.FillRectangle(selectionBackBrush, hasBreakpoint ? 16 : 0, y - 1, _disasmPanel.Width, lineHeight);
                    g.DrawString($"{insn.Address:X16}", _disasmFont, selectionForeBrush, textX, y);
                    g.DrawString(bytesStr, _disasmFont, selectionForeBrush, textX + addressWidth, y);
                    g.DrawString(instrText, _disasmFont, selectionForeBrush, textX + addressWidth + bytesWidth, y);
                }
                else if (hasBreakpoint)
                {
                    g.FillRectangle(breakpointBackBrush, 16, y - 1, _disasmPanel.Width, lineHeight);
                    g.DrawString($"{insn.Address:X16}", _disasmFont, addressBrush, textX, y);
                    g.DrawString(bytesStr, _disasmFont, bytesBrush, textX + addressWidth, y);
                    g.DrawString(instrText, _disasmFont, hexBrush, textX + addressWidth + bytesWidth, y);
                }
                else
                {
                    // Color code by instruction type
                    Color textColor = insn.IsCall != 0 ? _callColor :
                                      insn.IsBranch != 0 ? _jumpColor :
                                      insn.IsReturn != 0 ? _retColor :
                                      _hexColor;
                    g.DrawString($"{insn.Address:X16}", _disasmFont, addressBrush, textX, y);
                    g.DrawString(bytesStr, _disasmFont, bytesBrush, textX + addressWidth, y);
                    using var textBrush = new SolidBrush(textColor);
                    g.DrawString(instrText, _disasmFont, textBrush, textX + addressWidth + bytesWidth, y);
                }

                y += lineHeight;
                currentAddr = insn.Address + insn.Length;
                bufferOffset = (int)(currentAddr - _disasmAddress);
            }
        }
        else
        {
            _cachedDisasmCount = 0;
        }

        // Continue with raw bytes if disasm stopped early
        while (y < _disasmPanel.Height && bufferOffset < _disasmBuffer.Length)
        {
            ulong addr = _disasmAddress + (ulong)bufferOffset;
            byte b = _disasmBuffer[bufferOffset];

            bool isSelected = addr >= _disasmSelectedAddress && addr < _disasmSelectionEnd;
            if (isSelected)
            {
                g.FillRectangle(selectionBackBrush, 0, y - 1, _disasmPanel.Width, lineHeight);
                g.DrawString($"{addr:X16}", _disasmFont, selectionForeBrush, 2, y);
                g.DrawString($"{b:X2}", _disasmFont, selectionForeBrush, 2 + addressWidth, y);
                g.DrawString($"db {b:X2}", _disasmFont, selectionForeBrush, 2 + addressWidth + bytesWidth, y);
            }
            else
            {
                g.DrawString($"{addr:X16}", _disasmFont, Brushes.Gray, 2, y);
                g.DrawString($"{b:X2}", _disasmFont, Brushes.Gray, 2 + addressWidth, y);
                g.DrawString($"db {b:X2}", _disasmFont, Brushes.Gray, 2 + addressWidth + bytesWidth, y);
            }

            y += lineHeight;
            bufferOffset++;
        }
    }

    /// <summary>
    /// Formats instruction bytes as space-separated hex (x64dbg style).
    /// </summary>
    private static string FormatInstructionBytes(byte[]? bytes, byte length)
    {
        if (bytes == null || length == 0)
            return "";

        var sb = new System.Text.StringBuilder(length * 3);
        int len = Math.Min(length, bytes.Length);
        for (int i = 0; i < len; i++)
        {
            if (i > 0) sb.Append(' ');
            sb.Append(bytes[i].ToString("X2"));
        }
        return sb.ToString();
    }

    #endregion
}
