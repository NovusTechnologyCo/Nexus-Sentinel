using System.Drawing.Drawing2D;
using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using Nexus.UI.Styles;

namespace Nexus.UI.Forms;

public partial class MemoryViewerForm
{
    #region Memory Operations

    /// <summary>
    /// Refreshes both hex and disasm views (used on initial load or GoTo).
    /// </summary>
    private void RefreshMemory()
    {
        // Only refresh visible panels
        if (!splitContainer.Panel1Collapsed)
            RefreshDisasmMemory();
        if (!splitContainer.Panel2Collapsed)
            RefreshHexMemory();
    }

    /// <summary>
    /// Refreshes only the hex view memory buffer (independent scroll).
    /// </summary>
    private void RefreshHexMemory()
    {
        int totalBytes = _bytesPerRow * _rowCount;
        if (_memoryBuffer.Length < totalBytes)
            _memoryBuffer = new byte[totalBytes];

        // Check if in dump mode
        if (_dumpFileData != null)
        {
            // Read from dump file
            _hexReadSuccess = ReadFromDumpFile(_scrollAddress, _memoryBuffer, totalBytes);
            UpdateHexHeader();
            pnlHexView.Invalidate();
            pnlHexView.Update();
            return;
        }

        if (_processHandle == IntPtr.Zero)
        {
            _hexReadSuccess = false;
            pnlHexView.Invalidate();
            pnlHexView.Update();
            return;
        }

        NexusResult result;
        nuint bytesRead;
        unsafe
        {
            fixed (byte* ptr = _memoryBuffer)
            {
                result = NexusEngine.Nexus_ReadMemory(
                    _processHandle,
                    _scrollAddress,
                    (IntPtr)ptr,
                    (nuint)totalBytes,
                    out bytesRead);
            }
        }

        // Track if read was successful
        _hexReadSuccess = (result == NexusResult.OK || result == NexusResult.Success) && bytesRead > 0;

        // Update hex header with region info (like CE)
        UpdateHexHeader();

        pnlHexView.Invalidate();
        pnlHexView.Update();
    }

    /// <summary>
    /// Updates the hex view header with region info like CE shows.
    /// </summary>
    private void UpdateHexHeader()
    {
        // Handle dump mode
        if (_dumpFileData != null)
        {
            long offset = _scrollAddress >= _dumpFileBaseAddress
                ? (long)(_scrollAddress - _dumpFileBaseAddress)
                : -1;
            lblHexHeader.Text = offset >= 0 && offset < _dumpFileData.Length
                ? $"[Dump File: {_dumpFileName}]  Base=0x{_dumpFileBaseAddress:X}  Size={_dumpFileData.Length:N0}  Offset={offset:X}"
                : $"[Dump File: {_dumpFileName}]  Base=0x{_dumpFileBaseAddress:X}  Size={_dumpFileData.Length:N0}  (out of range)";
            return;
        }

        if (_processHandle == IntPtr.Zero)
        {
            lblHexHeader.Text = "";
            return;
        }

        string regionInfo = "";
        string moduleName = "";

        // Query the memory region at the current address directly (like CE does)
        var result = NexusEngine.Nexus_QueryMemory(_processHandle, _scrollAddress, out var region);
        if (result == NexusResult.OK)
        {
            string protect = GetProtectionString(region.Protection);
            // Match CE format: Protect + AllocationBase + Base + Size (RegionSize)
            regionInfo = $"Protect:{protect}  AllocationBase={region.AllocationBase:X}  Base={region.BaseAddress:X}  Size={region.Size:X}";
        }

        // Try to find module name
        var modules = new NexusModuleInfo[256];
        result = NexusEngine.Nexus_EnumerateModules(_processHandle, modules, 256, out var moduleCount);
        if (result == NexusResult.OK && moduleCount > 0)
        {
            for (int i = 0; i < (int)moduleCount; i++)
            {
                if (_scrollAddress >= modules[i].BaseAddress &&
                    _scrollAddress < modules[i].BaseAddress + modules[i].Size)
                {
                    moduleName = $"  Module={modules[i].Name}";
                    break;
                }
            }
        }

        // Show region info in the label (byte offsets are drawn in paint for alignment)
        lblHexHeader.Text = string.IsNullOrEmpty(regionInfo) ? "" : regionInfo + moduleName;
    }

    private static string GetProtectionString(uint protect)
    {
        // Match CE format exactly - build string by checking each flag
        var parts = new List<string>();

        // Base protection flags (mutually exclusive in practice)
        if ((protect & 0x01) != 0) parts.Add("No Access");
        if ((protect & 0x02) != 0) parts.Add("Read Only");
        if ((protect & 0x04) != 0) parts.Add("Read/Write");
        if ((protect & 0x08) != 0) parts.Add("Write Copy");
        if ((protect & 0x10) != 0) parts.Add("Execute");
        if ((protect & 0x20) != 0) parts.Add("Execute/Read Only");
        if ((protect & 0x40) != 0) parts.Add("Execute/Read/Write");
        if ((protect & 0x80) != 0) parts.Add("Execute/Write Copy");

        // Modifier flags
        if ((protect & 0x100) != 0) parts.Add("Guarded");
        if ((protect & 0x200) != 0) parts.Add("Not Cached");
        if ((protect & 0x400) != 0) parts.Add("Write Combine");

        return parts.Count > 0 ? string.Join(" ", parts) : $"0x{protect:X}";
    }

    /// <summary>
    /// Refreshes only the disasm view memory buffer (independent scroll).
    /// </summary>
    private void RefreshDisasmMemory()
    {
        // Read memory for disasm fallback (when disassembly fails)
        if (_disasmMemoryBuffer.Length < 512)
            _disasmMemoryBuffer = new byte[512];

        // Check if in dump mode
        if (_dumpFileData != null)
        {
            _disasmReadSuccess = ReadFromDumpFile(_baseAddress, _disasmMemoryBuffer, _disasmMemoryBuffer.Length);
            pnlDisasm.Invalidate();
            pnlDisasm.Update();
            return;
        }

        if (_processHandle == IntPtr.Zero)
        {
            _disasmReadSuccess = false;
            pnlDisasm.Invalidate();
            pnlDisasm.Update();
            return;
        }

        NexusResult result;
        nuint bytesRead;
        unsafe
        {
            fixed (byte* ptr = _disasmMemoryBuffer)
            {
                result = NexusEngine.Nexus_ReadMemory(
                    _processHandle,
                    _baseAddress,
                    (IntPtr)ptr,
                    (nuint)_disasmMemoryBuffer.Length,
                    out bytesRead);
            }
        }

        // Track if read was successful
        _disasmReadSuccess = (result == NexusResult.OK || result == NexusResult.Success) && bytesRead > 0;

        pnlDisasm.Invalidate();
        pnlDisasm.Update();
    }

    /// <summary>
    /// Reads data from the loaded dump file.
    /// </summary>
    private bool ReadFromDumpFile(ulong address, byte[] buffer, int count)
    {
        if (_dumpFileData == null) return false;

        // Calculate offset into dump file
        if (address < _dumpFileBaseAddress) return false;

        long offset = (long)(address - _dumpFileBaseAddress);
        if (offset >= _dumpFileData.Length) return false;

        // Calculate how many bytes we can actually read
        int available = (int)Math.Min(count, _dumpFileData.Length - offset);
        if (available <= 0) return false;

        // Copy data from dump file to buffer
        Array.Copy(_dumpFileData, offset, buffer, 0, available);

        // Zero out any remaining bytes
        if (available < count)
            Array.Clear(buffer, available, count - available);

        return true;
    }

    #endregion

    #region Hex View Rendering

    private void PnlHexView_Paint(object? sender, PaintEventArgs e)
    {
        var g = e.Graphics;
        g.Clear(_backgroundColor);

        if (_processHandle == IntPtr.Zero)
        {
            g.DrawString("No process selected", _hexFont, Brushes.Gray, 10, 10);
            return;
        }

        int lineHeight = (int)_hexFont.GetHeight(g) + 2;
        int charWidth = (int)g.MeasureString("0", _hexFont).Width;
        int addressWidth = charWidth * 17; // "0000000000000000 "
        int hexWidth = charWidth * 3; // "00 "
        int asciiStart = addressWidth + (_bytesPerRow * hexWidth) + charWidth;

        // Draw header row with byte offsets (dynamic based on current address)
        int headerY = 2;
        g.DrawString("address", _hexFont, Brushes.Gray, 2, headerY);
        int hx = addressWidth;
        int startOffset = (int)(_scrollAddress & 0xFF); // Low byte of address
        for (int col = 0; col < _bytesPerRow; col++)
        {
            int offset = (startOffset + col) & 0xFF;
            g.DrawString($"{offset:X2}", _hexFont, Brushes.Gray, hx, headerY);
            hx += hexWidth;
            if (col == 7) hx += charWidth;
        }

        // Draw data rows (starting after header)
        int dataStartY = lineHeight + 4;

        using var addrBrush = new SolidBrush(_addressColor);
        using var selBackBrush = new SolidBrush(_selectionBackColor);
        using var selForeBrush = new SolidBrush(_selectionForeColor);
        using var hexColorBrush = new SolidBrush(_hexColor);
        using var asciiBrush = new SolidBrush(_asciiColor);

        for (int row = 0; row < _rowCount; row++)
        {
            int y = row * lineHeight + dataStartY;
            ulong rowAddress = _scrollAddress + (ulong)(row * _bytesPerRow);

            // Draw address
            string addressStr = $"{rowAddress:X16}";
            g.DrawString(addressStr, _hexFont, addrBrush, 2, y);

            // Draw hex bytes
            int x = addressWidth;
            for (int col = 0; col < _bytesPerRow; col++)
            {
                int bufferIndex = row * _bytesPerRow + col;
                if (bufferIndex >= _memoryBuffer.Length) break;

                ulong byteAddress = rowAddress + (ulong)col;

                // Check if selected (hex view uses its own selection)
                bool isSelected = byteAddress >= _hexSelectedAddress &&
                                  byteAddress < _hexSelectedAddress + (ulong)Math.Max(1, _hexSelectionLength);

                // Show "??" if read failed, otherwise show the byte value
                string byteStr = _hexReadSuccess ? $"{_memoryBuffer[bufferIndex]:X2}" : "??";

                if (isSelected)
                {
                    var rect = new RectangleF(x - 1, y - 1, hexWidth, lineHeight);
                    g.FillRectangle(selBackBrush, rect);
                    g.DrawString(byteStr, _hexFont, selForeBrush, x, y);
                }
                else
                {
                    g.DrawString(byteStr, _hexFont, hexColorBrush, x, y);
                }

                x += hexWidth;

                // Add extra space after 8 bytes
                if (col == 7) x += charWidth;
            }

            // Draw ASCII representation
            x = asciiStart;
            for (int col = 0; col < _bytesPerRow; col++)
            {
                int bufferIndex = row * _bytesPerRow + col;
                if (bufferIndex >= _memoryBuffer.Length) break;

                // Show "?" if read failed, otherwise show the character
                char c;
                if (_hexReadSuccess)
                {
                    byte b = _memoryBuffer[bufferIndex];
                    c = (b >= 32 && b < 127) ? (char)b : '.';
                }
                else
                {
                    c = '?';
                }

                ulong byteAddress = rowAddress + (ulong)col;
                bool isSelected = byteAddress >= _hexSelectedAddress &&
                                  byteAddress < _hexSelectedAddress + (ulong)Math.Max(1, _hexSelectionLength);

                if (isSelected)
                {
                    var rect = new RectangleF(x - 1, y - 1, charWidth, lineHeight);
                    g.FillRectangle(selBackBrush, rect);
                    g.DrawString(c.ToString(), _hexFont, selForeBrush, x, y);
                }
                else
                {
                    g.DrawString(c.ToString(), _hexFont, asciiBrush, x, y);
                }

                x += charWidth - 3;
            }
        }
    }

    private void PnlHexView_MouseWheel(object? sender, MouseEventArgs e)
    {
        int linesToScroll = e.Delta / 120 * -3;
        long scrollDelta = linesToScroll * _bytesPerRow;

        long newScrollAddress = (long)_scrollAddress + scrollDelta;
        if (newScrollAddress < 0) newScrollAddress = 0;
        _scrollAddress = (ulong)newScrollAddress;

        // Update scrollbar position (center it since we have infinite scroll)
        hexScrollBar.Value = hexScrollBar.Maximum / 2;

        // Only refresh hex view (independent from disasm)
        RefreshHexMemory();
    }

    private void HexScrollBar_Scroll(object? sender, ScrollEventArgs e)
    {
        int delta = e.NewValue - (hexScrollBar.Maximum / 2);
        if (delta == 0) return;

        long scrollDelta = delta * _bytesPerRow;

        long newScrollAddress = (long)_scrollAddress + scrollDelta;
        if (newScrollAddress < 0) newScrollAddress = 0;
        _scrollAddress = (ulong)newScrollAddress;

        // Reset scrollbar to center for continuous scrolling
        hexScrollBar.Value = hexScrollBar.Maximum / 2;

        // Only refresh hex view (independent from disasm)
        RefreshHexMemory();
    }

    private void PnlHexView_MouseDown(object? sender, MouseEventArgs e)
    {
        // Calculate which byte was clicked
        int lineHeight = (int)_hexFont.GetHeight(CreateGraphics()) + 2;
        using var g = CreateGraphics();
        int charWidth = (int)g.MeasureString("0", _hexFont).Width;
        int addressWidth = charWidth * 17;
        int hexWidth = charWidth * 3;

        // Account for header row offset
        int dataStartY = lineHeight + 4;
        int row = (e.Y - dataStartY) / lineHeight;
        int col = -1;

        // Ignore clicks on header row
        if (row < 0) return;

        // Check if click is in hex area
        int hexX = e.X - addressWidth;
        if (hexX >= 0)
        {
            // Account for extra space after 8 bytes
            if (hexX >= hexWidth * 8 + charWidth)
                hexX -= charWidth;

            col = hexX / hexWidth;
            if (col >= 0 && col < _bytesPerRow)
            {
                _hexSelectedAddress = _scrollAddress + (ulong)(row * _bytesPerRow + col);
                _hexSelectionLength = 1;
                _lastActiveViewIsHex = true;

                // Update status bar
                lblSelectedAddress.Text = $"Selected: 0x{_hexSelectedAddress:X}";

                // Only refresh hex view (independent selection)
                pnlHexView.Invalidate();
            }
        }

        pnlHexView.Focus();
    }

    private void PnlHexView_KeyDown(object? sender, KeyEventArgs e)
    {
        switch (e.KeyCode)
        {
            case Keys.Up:
                if (_hexSelectedAddress >= (ulong)_bytesPerRow)
                    _hexSelectedAddress -= (ulong)_bytesPerRow;
                EnsureHexVisible();
                UpdateHexSelectionDisplay();
                e.Handled = true;
                break;

            case Keys.Down:
                _hexSelectedAddress += (ulong)_bytesPerRow;
                EnsureHexVisible();
                UpdateHexSelectionDisplay();
                e.Handled = true;
                break;

            case Keys.Left:
                if (_hexSelectedAddress > 0)
                    _hexSelectedAddress--;
                EnsureHexVisible();
                UpdateHexSelectionDisplay();
                e.Handled = true;
                break;

            case Keys.Right:
                _hexSelectedAddress++;
                EnsureHexVisible();
                UpdateHexSelectionDisplay();
                e.Handled = true;
                break;

            case Keys.PageUp:
                ulong pageSize = (ulong)(_bytesPerRow * _rowCount);
                if (_scrollAddress >= pageSize)
                {
                    _scrollAddress -= pageSize;
                    if (_hexSelectedAddress >= pageSize)
                        _hexSelectedAddress -= pageSize;
                }
                else
                {
                    _scrollAddress = 0;
                    _hexSelectedAddress = 0;
                }
                RefreshHexMemory();
                e.Handled = true;
                break;

            case Keys.PageDown:
                _scrollAddress += (ulong)(_bytesPerRow * _rowCount);
                _hexSelectedAddress += (ulong)(_bytesPerRow * _rowCount);
                RefreshHexMemory();
                e.Handled = true;
                break;

            case Keys.G when e.Control:
                ShowGoToDialog();
                e.Handled = true;
                break;
        }
    }

    private void UpdateHexSelectionDisplay()
    {
        lblSelectedAddress.Text = $"Selected: 0x{_hexSelectedAddress:X}";
        pnlHexView.Invalidate();
    }

    private void PnlHexView_MouseDoubleClick(object? sender, MouseEventArgs e)
    {
        // Calculate which byte was double-clicked (same logic as MouseDown)
        int lineHeight = (int)_hexFont.GetHeight(CreateGraphics()) + 2;
        using var g = CreateGraphics();
        int charWidth = (int)g.MeasureString("0", _hexFont).Width;
        int addressWidth = charWidth * 17;
        int hexWidth = charWidth * 3;

        int dataStartY = lineHeight + 4;
        int row = (e.Y - dataStartY) / lineHeight;

        if (row < 0) return;

        int hexX = e.X - addressWidth;
        if (hexX >= 0)
        {
            if (hexX >= hexWidth * 8 + charWidth)
                hexX -= charWidth;

            int col = hexX / hexWidth;
            if (col >= 0 && col < _bytesPerRow)
            {
                ulong address = _scrollAddress + (ulong)(row * _bytesPerRow + col);
                ShowChangeOffsetDialog(address);
            }
        }
    }

    private void ShowChangeOffsetDialog(ulong address)
    {
        if (_processHandle == IntPtr.Zero) return;

        using var dialog = new Form
        {
            Text = $"Change offset {address:X}",
            Size = new Size(350, 220),
            StartPosition = FormStartPosition.CenterParent,
            FormBorderStyle = FormBorderStyle.FixedDialog,
            MaximizeBox = false,
            MinimizeBox = false
        };

        // Read current value
        byte currentByte = 0;
        unsafe
        {
            NexusEngine.Nexus_ReadMemory(_processHandle, address, (IntPtr)(&currentByte), 1, out _);
        }

        var textBox = new TextBox
        {
            Location = new Point(12, 20),
            Size = new Size(310, 23),
            Text = currentByte.ToString(),
            Font = new Font("Consolas", 10f)
        };
        NexusTheme.StyleTextBox(textBox);

        var cboType = new ComboBox
        {
            Location = new Point(12, 60),
            Size = new Size(120, 23),
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        cboType.Items.AddRange(["1 Byte", "2 Bytes", "4 Bytes", "8 Bytes", "Float", "Double"]);
        cboType.SelectedIndex = 0;
        NexusTheme.StyleComboBox(cboType);

        var chkHex = new CheckBox
        {
            Text = "Hexadecimal",
            Location = new Point(145, 62),
            AutoSize = true
        };
        NexusTheme.StyleCheckBox(chkHex);

        // Update textbox when hex checkbox or type changes
        chkHex.CheckedChanged += (s, e) => UpdateValueDisplay(textBox, cboType, chkHex, address);
        cboType.SelectedIndexChanged += (s, e) => UpdateValueDisplay(textBox, cboType, chkHex, address);

        var btnOk = new Button
        {
            Text = "OK",
            Location = new Point(150, 130),
            Size = new Size(80, 30),
            DialogResult = DialogResult.OK
        };

        var btnCancel = new Button
        {
            Text = "Cancel",
            Location = new Point(240, 130),
            Size = new Size(80, 30),
            DialogResult = DialogResult.Cancel
        };

        dialog.Controls.AddRange([textBox, cboType, chkHex, btnOk, btnCancel]);
        dialog.AcceptButton = btnOk;
        dialog.CancelButton = btnCancel;

        if (dialog.ShowDialog(this) == DialogResult.OK)
        {
            WriteValueFromDialog(address, textBox.Text, cboType.SelectedIndex, chkHex.Checked);
        }
    }

    private void UpdateValueDisplay(TextBox textBox, ComboBox cboType, CheckBox chkHex, ulong address)
    {
        if (_processHandle == IntPtr.Zero) return;

        int size = cboType.SelectedIndex switch
        {
            0 => 1, 1 => 2, 2 => 4, 3 => 8, 4 => 4, 5 => 8, _ => 1
        };

        var buffer = new byte[8];
        unsafe
        {
            fixed (byte* ptr = buffer)
            {
                NexusEngine.Nexus_ReadMemory(_processHandle, address, (IntPtr)ptr, (nuint)size, out _);
            }
        }

        string value = (cboType.SelectedIndex, chkHex.Checked) switch
        {
            (0, false) => buffer[0].ToString(),
            (0, true) => buffer[0].ToString("X2"),
            (1, false) => BitConverter.ToInt16(buffer, 0).ToString(),
            (1, true) => BitConverter.ToUInt16(buffer, 0).ToString("X4"),
            (2, false) => BitConverter.ToInt32(buffer, 0).ToString(),
            (2, true) => BitConverter.ToUInt32(buffer, 0).ToString("X8"),
            (3, false) => BitConverter.ToInt64(buffer, 0).ToString(),
            (3, true) => BitConverter.ToUInt64(buffer, 0).ToString("X16"),
            (4, _) => BitConverter.ToSingle(buffer, 0).ToString("G"),
            (5, _) => BitConverter.ToDouble(buffer, 0).ToString("G"),
            _ => buffer[0].ToString()
        };

        textBox.Text = value;
    }

    private void WriteValueFromDialog(ulong address, string valueText, int typeIndex, bool isHex)
    {
        if (_processHandle == IntPtr.Zero) return;

        byte[]? bytes = null;
        try
        {
            var style = isHex ? System.Globalization.NumberStyles.HexNumber : System.Globalization.NumberStyles.Any;

            bytes = typeIndex switch
            {
                0 => [isHex ? byte.Parse(valueText, style) : byte.Parse(valueText)],
                1 => BitConverter.GetBytes(isHex ? short.Parse(valueText, style) : short.Parse(valueText)),
                2 => BitConverter.GetBytes(isHex ? int.Parse(valueText, style) : int.Parse(valueText)),
                3 => BitConverter.GetBytes(isHex ? long.Parse(valueText, style) : long.Parse(valueText)),
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
            RefreshHexMemory();
        }
    }

    private void EnsureHexVisible()
    {
        ulong viewStart = _scrollAddress;
        ulong viewEnd = _scrollAddress + (ulong)(_bytesPerRow * _rowCount);

        if (_hexSelectedAddress < viewStart)
        {
            _scrollAddress = _hexSelectedAddress - (_hexSelectedAddress % (ulong)_bytesPerRow);
            RefreshHexMemory();
        }
        else if (_hexSelectedAddress >= viewEnd)
        {
            _scrollAddress = _hexSelectedAddress - (ulong)(_bytesPerRow * (_rowCount - 1));
            _scrollAddress -= _scrollAddress % (ulong)_bytesPerRow;
            RefreshHexMemory();
        }
    }

    #endregion
}
