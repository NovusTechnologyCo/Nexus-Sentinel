using Nexus.UI.Core;
using Nexus.UI.Interop;
using Nexus.UI.Styles;

namespace Nexus.UI.Panels;

public partial class StructuresPanel
{
    #region Event Handlers

    protected override void OnProcessAttached(object? sender, ProcessAttachedEventArgs e)
    {
        base.OnProcessAttached(sender, e);
        _refreshTimer.Start();
        UpdateStatus($"Attached to PID {e.ProcessId}");
        RefreshValues();
    }

    protected override void OnProcessDetached(object? sender, ProcessDetachedEventArgs e)
    {
        base.OnProcessDetached(sender, e);
        _refreshTimer.Stop();
        UpdateStatus("No process attached");
        ClearValues();
    }

    private void AddressTextBox_KeyDown(object? sender, KeyEventArgs e)
    {
        if (e.KeyCode == Keys.Enter)
        {
            // Go to address and add it to saved list
            GotoBtn_Click(sender, e);
            AddAddressBtn_Click(sender, e);
            e.Handled = true;
            e.SuppressKeyPress = true;
        }
    }

    private void AddressCombo_SelectedIndexChanged(object? sender, EventArgs e)
    {
        if (_addressCombo.SelectedIndex >= 0 && _addressCombo.SelectedIndex < _savedAddresses.Count)
        {
            // Copy selected address to textbox
            _addressTextBox.Text = _savedAddresses[_addressCombo.SelectedIndex];
            GotoBtn_Click(sender, e);
        }
    }

    private void AddAddressBtn_Click(object? sender, EventArgs e)
    {
        var text = _addressTextBox.Text.Trim();
        if (string.IsNullOrEmpty(text)) return;

        // Normalize to hex format
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            text = text[2..];
        text = text.ToUpperInvariant();

        if (ulong.TryParse(text, System.Globalization.NumberStyles.HexNumber, null, out var address))
        {
            var formatted = $"{address:X}";
            if (!_savedAddresses.Contains(formatted))
            {
                _savedAddresses.Add(formatted);
                _addressCombo.Items.Add(formatted);
                _addressCombo.SelectedIndex = _savedAddresses.Count - 1;
                UpdateStatus($"Added address 0x{formatted} to list");
            }
        }
    }

    private void RemoveAddressBtn_Click(object? sender, EventArgs e)
    {
        if (_addressCombo.SelectedIndex >= 0)
        {
            var removed = _savedAddresses[_addressCombo.SelectedIndex];
            _savedAddresses.RemoveAt(_addressCombo.SelectedIndex);
            _addressCombo.Items.RemoveAt(_addressCombo.SelectedIndex);
            UpdateStatus($"Removed address 0x{removed} from list");
        }
    }

    private void GotoBtn_Click(object? sender, EventArgs e)
    {
        var text = _addressTextBox.Text.Trim();
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            text = text[2..];

        if (ulong.TryParse(text, System.Globalization.NumberStyles.HexNumber, null, out var address))
        {
            _baseAddress = address;
            _addressTextBox.Text = $"{address:X}";
            RefreshValues();
            UpdateStatus($"Base address: 0x{address:X}");
        }
        else
        {
            UpdateStatus("Invalid address format", true);
        }
    }

    private void AnalyzeBtn_Click(object? sender, EventArgs e)
    {
        if (!Context.IsAttached)
        {
            UpdateStatus("No process attached", true);
            return;
        }

        if (_baseAddress == 0)
        {
            UpdateStatus("Enter a base address first", true);
            return;
        }

        AutoDissectStructure();
    }

    private void AutoDissectStructure()
    {
        var handle = Context.NativeProcessHandle;
        if (handle == IntPtr.Zero) return;

        // Use engine's advanced auto-guess API for better heuristics
        var result = NexusEngine.Nexus_StructureCreate("AutoGuess", out var structHandle);
        if (result != NexusResult.OK)
        {
            UpdateStatus($"Failed to create structure: {result}", true);
            return;
        }

        try
        {
            // Use engine's auto-guess with advanced heuristics (256 bytes)
            result = NexusEngine.Nexus_StructureAutoGuess(structHandle, handle, _baseAddress, 256);
            if (result != NexusResult.OK)
            {
                UpdateStatus($"Auto-guess failed: {result}", true);
                return;
            }

            // Create a new class and load the guessed structure
            var cls = _selectedClass ?? CreateNewClass("AutoClass");
            cls.Fields.Clear();

            // Get element count
            result = NexusEngine.Nexus_StructureGetElementCount(structHandle, out var count);
            if (result != NexusResult.OK || count == 0)
            {
                UpdateStatus("Auto-guess returned no elements", true);
                return;
            }

            // Read all elements
            for (uint i = 0; i < count; i++)
            {
                result = NexusEngine.Nexus_StructureGetElementByIndex(structHandle, i, out var element);
                if (result != NexusResult.OK) continue;

                cls.Fields.Add(new StructureField
                {
                    Offset = (int)element.Offset,
                    Type = NexusElementTypeToFieldType((NexusElementType)element.ElementType),
                    Name = string.IsNullOrEmpty(element.Name) ? $"field_{element.Offset:X}" : element.Name,
                    ElementId = i
                });
            }

            // Update UI
            if (_selectedClass == null)
            {
                _classes.Add(cls);
                _classCombo.Items.Add(cls.Name);
                _classCombo.SelectedIndex = _classes.Count - 1;
            }

            UpdateClassTree();
            RefreshFieldsGrid();
            RefreshValues();
            UpdateStatus($"Auto-dissected {cls.Fields.Count} fields using engine heuristics");
        }
        finally
        {
            NexusEngine.Nexus_StructureDestroy(structHandle);
        }
    }

    private StructureClass CreateNewClass(string baseName)
    {
        int index = 1;
        string name = baseName;
        while (_classes.Any(c => c.Name == name))
        {
            name = $"{baseName}{index++}";
        }
        return new StructureClass { Name = name };
    }

    private void ClassCombo_SelectedIndexChanged(object? sender, EventArgs e)
    {
        if (_classCombo.SelectedIndex >= 0 && _classCombo.SelectedIndex < _classes.Count)
        {
            _selectedClass = _classes[_classCombo.SelectedIndex];
            RefreshFieldsGrid();
            RefreshValues();
        }
    }

    private void ClassTree_AfterSelect(object? sender, TreeViewEventArgs e)
    {
        if (e.Node?.Tag is StructureClass cls)
        {
            _selectedClass = cls;
            _classCombo.SelectedIndex = _classes.IndexOf(cls);
            RefreshFieldsGrid();
            RefreshValues();
        }
    }

    private void RefreshTimer_Tick(object? sender, EventArgs e)
    {
        if (Context.IsAttached)
        {
            RefreshValues();
        }
    }

    private void HexPreview_Paint(object? sender, PaintEventArgs e)
    {
        var g = e.Graphics;
        g.Clear(NexusTheme.BackgroundControl);

        if (_previewBuffer == null || _previewBuffer.Length == 0)
            return;

        using var font = new Font("Consolas", 9f);
        using var addrBrush = new SolidBrush(NexusTheme.Accent);
        using var hexBrush = new SolidBrush(NexusTheme.TextPrimary);
        using var asciiBrush = new SolidBrush(Color.FromArgb(206, 145, 120));

        // Measure character width for proper spacing (same approach as DisassemblerPanel)
        int lineHeight = (int)font.GetHeight(g) + 2;
        int charWidth = (int)g.MeasureString("0", font).Width;
        int bytesPerRow = 16;
        int addressWidth = charWidth * 17;  // 16 hex chars + space
        int hexWidth = charWidth * 3;       // 2 hex chars + space
        int asciiStart = addressWidth + (bytesPerRow * hexWidth) + charWidth;

        // Draw header row - byte offsets based on base address alignment
        int headerY = 2;
        int startOffset = (int)(_baseAddress & 0xF);  // Low nibble of address
        g.DrawString("address", font, Brushes.Gray, 2, headerY);
        int hx = addressWidth;
        for (int col = 0; col < bytesPerRow; col++)
        {
            int byteOffset = (startOffset + col) & 0xF;  // Wrap at 16
            g.DrawString($"{byteOffset:X2}", font, Brushes.Gray, hx, headerY);
            hx += hexWidth;
            if (col == 7) hx += charWidth;  // Extra gap in middle
        }

        // Draw data rows
        int dataStartY = lineHeight + 4;
        int maxRows = Math.Min(_previewBuffer.Length / bytesPerRow, 8);

        for (int row = 0; row < maxRows; row++)
        {
            int y = row * lineHeight + dataStartY;
            ulong rowAddress = _baseAddress + (ulong)(row * bytesPerRow);

            // Address column
            g.DrawString($"{rowAddress:X16}", font, addrBrush, 2, y);

            // Hex bytes
            int x = addressWidth;
            for (int col = 0; col < bytesPerRow; col++)
            {
                int bufferIndex = row * bytesPerRow + col;
                if (bufferIndex >= _previewBuffer.Length) break;

                g.DrawString($"{_previewBuffer[bufferIndex]:X2}", font, hexBrush, x, y);
                x += hexWidth;
                if (col == 7) x += charWidth;  // Extra gap in middle
            }

            // ASCII column
            x = asciiStart;
            for (int col = 0; col < bytesPerRow; col++)
            {
                int bufferIndex = row * bytesPerRow + col;
                if (bufferIndex >= _previewBuffer.Length) break;

                byte b = _previewBuffer[bufferIndex];
                char c = (b >= 32 && b < 127) ? (char)b : '.';
                g.DrawString(c.ToString(), font, asciiBrush, x, y);
                x += charWidth - 3;
            }
        }
    }

    private void SearchTextBox_TextChanged(object? sender, EventArgs e)
    {
        var searchText = _searchTextBox.Text.Trim().ToLowerInvariant();

        if (string.IsNullOrEmpty(searchText))
        {
            // Show all rows
            foreach (DataGridViewRow row in _fieldsGrid.Rows)
                row.Visible = true;
            return;
        }

        // Filter rows by name match
        foreach (DataGridViewRow row in _fieldsGrid.Rows)
        {
            var field = row.Tag as StructureField;
            if (field != null)
            {
                var matches = field.Name.ToLowerInvariant().Contains(searchText) ||
                              field.Type.ToString().ToLowerInvariant().Contains(searchText) ||
                              (field.Comment?.ToLowerInvariant().Contains(searchText) ?? false);
                row.Visible = matches;
            }
        }
    }

    #region Grid Editing

    private void FieldsGrid_CurrentCellDirtyStateChanged(object? sender, EventArgs e)
    {
        // Commit ComboBox changes immediately so CellValueChanged fires
        if (_fieldsGrid.IsCurrentCellDirty && _fieldsGrid.CurrentCell?.OwningColumn?.Name == "Type")
        {
            _fieldsGrid.CommitEdit(DataGridViewDataErrorContexts.Commit);
        }
    }

    private void FieldsGrid_CellValueChanged(object? sender, DataGridViewCellEventArgs e)
    {
        if (e.RowIndex < 0 || _selectedClass == null) return;

        var row = _fieldsGrid.Rows[e.RowIndex];
        var field = row.Tag as StructureField;
        if (field == null) return;

        var columnName = _fieldsGrid.Columns[e.ColumnIndex].Name;

        switch (columnName)
        {
            case "Type":
                var typeValue = row.Cells["Type"].Value?.ToString();
                if (!string.IsNullOrEmpty(typeValue) && Enum.TryParse<FieldType>(typeValue, out var newType))
                {
                    field.Type = newType;
                    UpdateClassTree();
                    RefreshValues();
                }
                break;

            case "Name":
                var nameValue = row.Cells["Name"].Value?.ToString();
                if (!string.IsNullOrEmpty(nameValue))
                {
                    field.Name = nameValue;
                    UpdateClassTree();
                }
                break;

            case "Comment":
                field.Comment = row.Cells["Comment"].Value?.ToString();
                break;

            case "Value":
                // Write-back: write new value to memory
                if (Context.IsAttached && _baseAddress != 0)
                {
                    var newValue = row.Cells["Value"].Value?.ToString();
                    if (!string.IsNullOrEmpty(newValue))
                    {
                        WriteFieldValue(field, newValue);
                    }
                }
                break;
        }
    }

    #endregion

    #endregion
}
