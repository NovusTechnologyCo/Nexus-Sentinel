using Nexus.UI.Core;
using Nexus.UI.Interop;
using Nexus.UI.Styles;

namespace Nexus.UI.Panels;

public partial class StructuresPanel
{
    #region Structure Operations

    private void FillStructureGaps()
    {
        if (_selectedClass == null)
        {
            UpdateStatus("No class selected", true);
            return;
        }

        if (!Context.IsAttached || _baseAddress == 0)
        {
            UpdateStatus("Attach to process and set base address first", true);
            return;
        }

        // Create engine structure from our class
        var result = NexusEngine.Nexus_StructureCreate(_selectedClass.Name, out var structHandle);
        if (result != NexusResult.OK)
        {
            UpdateStatus($"Failed to create structure: {result}", true);
            return;
        }

        try
        {
            // Add all existing elements
            foreach (var field in _selectedClass.Fields)
            {
                var elemType = FieldTypeToNexusElementType(field.Type);
                var size = GetFieldSize(field.Type);
                NexusEngine.Nexus_StructureAddElement(structHandle, field.Offset, elemType, field.Name, size, out _);
            }

            // Fill gaps using engine
            result = NexusEngine.Nexus_StructureFillGaps(structHandle, Context.NativeProcessHandle, _baseAddress);
            if (result != NexusResult.OK)
            {
                UpdateStatus($"Fill gaps failed: {result}", true);
                return;
            }

            // Reload structure from engine
            _selectedClass.Fields.Clear();
            result = NexusEngine.Nexus_StructureGetElementCount(structHandle, out var count);
            if (result == NexusResult.OK)
            {
                for (uint i = 0; i < count; i++)
                {
                    result = NexusEngine.Nexus_StructureGetElementByIndex(structHandle, i, out var element);
                    if (result != NexusResult.OK) continue;

                    _selectedClass.Fields.Add(new StructureField
                    {
                        Offset = (int)element.Offset,
                        Type = NexusElementTypeToFieldType((NexusElementType)element.ElementType),
                        Name = string.IsNullOrEmpty(element.Name) ? $"field_{element.Offset:X}" : element.Name,
                        ElementId = i
                    });
                }
            }

            UpdateClassTree();
            RefreshFieldsGrid();
            RefreshValues();
            UpdateStatus($"Filled gaps - now {_selectedClass.Fields.Count} fields");
        }
        finally
        {
            NexusEngine.Nexus_StructureDestroy(structHandle);
        }
    }

    private void SortElementsByOffset()
    {
        if (_selectedClass == null)
        {
            UpdateStatus("No class selected", true);
            return;
        }

        // Sort locally
        _selectedClass.Fields.Sort((a, b) => a.Offset.CompareTo(b.Offset));

        UpdateClassTree();
        RefreshFieldsGrid();
        UpdateStatus("Sorted elements by offset");
    }

    private void CloneSelectedClass()
    {
        if (_selectedClass == null)
        {
            UpdateStatus("No class selected", true);
            return;
        }

        // Create a deep copy
        var newName = $"{_selectedClass.Name}_Copy";
        int index = 1;
        while (_classes.Any(c => c.Name == newName))
        {
            newName = $"{_selectedClass.Name}_Copy{index++}";
        }

        var clone = new StructureClass { Name = newName };
        foreach (var field in _selectedClass.Fields)
        {
            clone.Fields.Add(new StructureField
            {
                Offset = field.Offset,
                Type = field.Type,
                Name = field.Name,
                Comment = field.Comment,
                NestedStructName = field.NestedStructName,
                ArrayCount = field.ArrayCount
            });
        }

        _classes.Add(clone);
        UpdateClassTree();
        UpdateClassCombo();
        _classCombo.SelectedIndex = _classes.Count - 1;
        UpdateStatus($"Cloned class as '{newName}'");
    }

    private void AddPadding()
    {
        if (_selectedClass == null) return;

        using var dialog = new Form
        {
            Text = "Add Padding",
            Size = new Size(280, 150),
            FormBorderStyle = FormBorderStyle.FixedDialog,
            StartPosition = FormStartPosition.CenterParent,
            MaximizeBox = false,
            MinimizeBox = false,
            BackColor = NexusTheme.BackgroundDark
        };

        var lblSize = new Label { Text = "Size (bytes):", Location = new Point(12, 20), AutoSize = true, ForeColor = NexusTheme.TextPrimary };
        var txtSize = new TextBox { Text = "4", Location = new Point(100, 17), Size = new Size(150, 23) };
        NexusTheme.StyleTextBox(txtSize);

        var btnOk = new Button { Text = "OK", DialogResult = DialogResult.OK, Location = new Point(94, 65), Size = new Size(75, 28) };
        var btnCancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, Location = new Point(175, 65), Size = new Size(75, 28) };
        NexusTheme.StylePrimaryButton(btnOk);
        NexusTheme.StyleButton(btnCancel);

        dialog.Controls.AddRange([lblSize, txtSize, btnOk, btnCancel]);
        dialog.AcceptButton = btnOk;
        dialog.CancelButton = btnCancel;

        if (dialog.ShowDialog(this) == DialogResult.OK && int.TryParse(txtSize.Text, out var size) && size > 0)
        {
            int nextOffset = 0;
            if (_selectedClass.Fields.Count > 0)
            {
                var lastField = _selectedClass.Fields[^1];
                nextOffset = lastField.Offset + GetFieldSize(lastField.Type);
            }

            var field = new StructureField
            {
                Offset = nextOffset,
                Type = FieldType.Padding,
                Name = $"padding_{nextOffset:X}",
                ArrayCount = size
            };

            _selectedClass.Fields.Add(field);
            RefreshFieldsGrid();
            UpdateClassTree();
        }
    }

    private void ChangeFieldToStruct()
    {
        if (_fieldsGrid.SelectedRows.Count == 0 || _selectedClass == null) return;

        var selectedRow = _fieldsGrid.SelectedRows[0];
        var field = selectedRow.Tag as StructureField;
        if (field == null) return;

        // Show dialog to select which struct to use
        using var dialog = new Form
        {
            Text = "Select Structure",
            Size = new Size(300, 150),
            FormBorderStyle = FormBorderStyle.FixedDialog,
            StartPosition = FormStartPosition.CenterParent,
            MaximizeBox = false,
            MinimizeBox = false,
            BackColor = NexusTheme.BackgroundDark
        };

        var lblStruct = new Label { Text = "Structure:", Location = new Point(12, 20), AutoSize = true, ForeColor = NexusTheme.TextPrimary };
        var cmbStruct = new ComboBox { Location = new Point(80, 17), Size = new Size(190, 23), DropDownStyle = ComboBoxStyle.DropDownList };
        NexusTheme.StyleComboBox(cmbStruct);

        // Add available structures (excluding current one)
        foreach (var cls in _classes.Where(c => c != _selectedClass))
        {
            cmbStruct.Items.Add(cls.Name);
        }
        if (cmbStruct.Items.Count > 0) cmbStruct.SelectedIndex = 0;

        var btnOk = new Button { Text = "OK", DialogResult = DialogResult.OK, Location = new Point(114, 65), Size = new Size(75, 28) };
        var btnCancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, Location = new Point(195, 65), Size = new Size(75, 28) };
        NexusTheme.StylePrimaryButton(btnOk);
        NexusTheme.StyleButton(btnCancel);

        dialog.Controls.AddRange([lblStruct, cmbStruct, btnOk, btnCancel]);
        dialog.AcceptButton = btnOk;
        dialog.CancelButton = btnCancel;

        if (dialog.ShowDialog(this) == DialogResult.OK && cmbStruct.SelectedItem != null)
        {
            field.Type = FieldType.Struct;
            field.NestedStructName = cmbStruct.SelectedItem.ToString();
            RefreshFieldsGrid();
            UpdateClassTree();
            RefreshValues();
        }
    }

    private void ExpandNestedStruct()
    {
        if (_fieldsGrid.SelectedRows.Count == 0 || _selectedClass == null) return;

        var selectedRow = _fieldsGrid.SelectedRows[0];
        var field = selectedRow.Tag as StructureField;
        if (field == null || field.Type != FieldType.Struct || string.IsNullOrEmpty(field.NestedStructName))
        {
            UpdateStatus("Select a Struct type field to expand", true);
            return;
        }

        // Find the nested structure
        var nestedStruct = _classes.FirstOrDefault(c => c.Name == field.NestedStructName);
        if (nestedStruct == null)
        {
            UpdateStatus($"Structure '{field.NestedStructName}' not found", true);
            return;
        }

        // Toggle expansion
        field.IsExpanded = !field.IsExpanded;

        // If expanding, insert nested fields after this one
        if (field.IsExpanded)
        {
            var fieldIndex = _selectedClass.Fields.IndexOf(field);
            int insertIndex = fieldIndex + 1;

            foreach (var nestedField in nestedStruct.Fields)
            {
                var expandedField = new StructureField
                {
                    Offset = field.Offset + nestedField.Offset,
                    Type = nestedField.Type,
                    Name = $"{field.Name}.{nestedField.Name}",
                    Comment = $"[from {field.NestedStructName}]",
                    NestedStructName = nestedField.NestedStructName
                };
                _selectedClass.Fields.Insert(insertIndex++, expandedField);
            }
            UpdateStatus($"Expanded {nestedStruct.Fields.Count} fields from {field.NestedStructName}");
        }
        else
        {
            // Remove expanded fields
            var prefix = $"{field.Name}.";
            _selectedClass.Fields.RemoveAll(f => f.Name.StartsWith(prefix));
            UpdateStatus($"Collapsed {field.NestedStructName}");
        }

        RefreshFieldsGrid();
        UpdateClassTree();
        RefreshValues();
    }

    private void CopySelectedField()
    {
        if (_fieldsGrid.SelectedRows.Count == 0) return;
        var selectedRow = _fieldsGrid.SelectedRows[0];
        var field = selectedRow.Tag as StructureField;
        if (field == null) return;

        // Deep copy the field
        _copiedField = new StructureField
        {
            Offset = field.Offset,
            Type = field.Type,
            Name = field.Name,
            Comment = field.Comment,
            ArrayCount = field.ArrayCount,
            ArrayBaseType = field.ArrayBaseType,
            BitOffset = field.BitOffset,
            BitSize = field.BitSize,
            EnumName = field.EnumName,
            EnumValues = field.EnumValues != null ? new Dictionary<long, string>(field.EnumValues) : null,
            NestedStructName = field.NestedStructName,
            PointerOffsets = field.PointerOffsets != null ? new List<long>(field.PointerOffsets) : null
        };
        UpdateStatus($"Copied field '{field.Name}'");
    }

    private void PasteField()
    {
        if (_selectedClass == null || _copiedField == null)
        {
            UpdateStatus("Nothing to paste", true);
            return;
        }

        // Calculate offset for new field
        int nextOffset = 0;
        if (_selectedClass.Fields.Count > 0)
        {
            var lastField = _selectedClass.Fields[^1];
            nextOffset = lastField.Offset + GetFieldSize(lastField.Type, lastField.ArrayCount, lastField.ArrayBaseType);
        }

        var newField = new StructureField
        {
            Offset = nextOffset,
            Type = _copiedField.Type,
            Name = $"{_copiedField.Name}_copy",
            Comment = _copiedField.Comment,
            ArrayCount = _copiedField.ArrayCount,
            ArrayBaseType = _copiedField.ArrayBaseType,
            BitOffset = _copiedField.BitOffset,
            BitSize = _copiedField.BitSize,
            EnumName = _copiedField.EnumName,
            EnumValues = _copiedField.EnumValues != null ? new Dictionary<long, string>(_copiedField.EnumValues) : null,
            NestedStructName = _copiedField.NestedStructName,
            PointerOffsets = _copiedField.PointerOffsets != null ? new List<long>(_copiedField.PointerOffsets) : null
        };

        _selectedClass.Fields.Add(newField);
        RefreshFieldsGrid();
        UpdateClassTree();
        UpdateStatus($"Pasted field as '{newField.Name}'");
    }

    private void ChangeFieldToArray()
    {
        if (_fieldsGrid.SelectedRows.Count == 0 || _selectedClass == null) return;
        var field = _fieldsGrid.SelectedRows[0].Tag as StructureField;
        if (field == null) return;

        using var dialog = new Form
        {
            Text = "Configure Array",
            Size = new Size(300, 180),
            FormBorderStyle = FormBorderStyle.FixedDialog,
            StartPosition = FormStartPosition.CenterParent,
            MaximizeBox = false,
            MinimizeBox = false,
            BackColor = NexusTheme.BackgroundDark
        };

        var lblType = new Label { Text = "Element Type:", Location = new Point(12, 20), AutoSize = true, ForeColor = NexusTheme.TextPrimary };
        var cmbType = new ComboBox { Location = new Point(100, 17), Size = new Size(170, 23), DropDownStyle = ComboBoxStyle.DropDownList };
        cmbType.Items.AddRange(["Int8", "UInt8", "Int16", "UInt16", "Int32", "UInt32", "Int64", "UInt64", "Float", "Double", "Pointer"]);
        cmbType.SelectedIndex = 1; // UInt8 default
        NexusTheme.StyleComboBox(cmbType);

        var lblCount = new Label { Text = "Count:", Location = new Point(12, 55), AutoSize = true, ForeColor = NexusTheme.TextPrimary };
        var txtCount = new TextBox { Text = "16", Location = new Point(100, 52), Size = new Size(170, 23) };
        NexusTheme.StyleTextBox(txtCount);

        var btnOk = new Button { Text = "OK", DialogResult = DialogResult.OK, Location = new Point(114, 95), Size = new Size(75, 28) };
        var btnCancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, Location = new Point(195, 95), Size = new Size(75, 28) };
        NexusTheme.StylePrimaryButton(btnOk);
        NexusTheme.StyleButton(btnCancel);

        dialog.Controls.AddRange([lblType, cmbType, lblCount, txtCount, btnOk, btnCancel]);
        dialog.AcceptButton = btnOk;
        dialog.CancelButton = btnCancel;

        if (dialog.ShowDialog(this) == DialogResult.OK && int.TryParse(txtCount.Text, out var count) && count > 0)
        {
            field.Type = FieldType.Array;
            field.ArrayCount = count;
            if (Enum.TryParse<FieldType>(cmbType.SelectedItem?.ToString(), out var baseType))
                field.ArrayBaseType = baseType;
            RefreshFieldsGrid();
            UpdateClassTree();
            RefreshValues();
        }
    }

    private void ChangeFieldToBitfield()
    {
        if (_fieldsGrid.SelectedRows.Count == 0 || _selectedClass == null) return;
        var field = _fieldsGrid.SelectedRows[0].Tag as StructureField;
        if (field == null) return;

        using var dialog = new Form
        {
            Text = "Configure Bitfield",
            Size = new Size(300, 180),
            FormBorderStyle = FormBorderStyle.FixedDialog,
            StartPosition = FormStartPosition.CenterParent,
            MaximizeBox = false,
            MinimizeBox = false,
            BackColor = NexusTheme.BackgroundDark
        };

        var lblOffset = new Label { Text = "Bit Offset:", Location = new Point(12, 20), AutoSize = true, ForeColor = NexusTheme.TextPrimary };
        var txtOffset = new TextBox { Text = "0", Location = new Point(100, 17), Size = new Size(170, 23) };
        NexusTheme.StyleTextBox(txtOffset);

        var lblSize = new Label { Text = "Bit Size:", Location = new Point(12, 55), AutoSize = true, ForeColor = NexusTheme.TextPrimary };
        var txtSize = new TextBox { Text = "1", Location = new Point(100, 52), Size = new Size(170, 23) };
        NexusTheme.StyleTextBox(txtSize);

        var btnOk = new Button { Text = "OK", DialogResult = DialogResult.OK, Location = new Point(114, 95), Size = new Size(75, 28) };
        var btnCancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, Location = new Point(195, 95), Size = new Size(75, 28) };
        NexusTheme.StylePrimaryButton(btnOk);
        NexusTheme.StyleButton(btnCancel);

        dialog.Controls.AddRange([lblOffset, txtOffset, lblSize, txtSize, btnOk, btnCancel]);
        dialog.AcceptButton = btnOk;
        dialog.CancelButton = btnCancel;

        if (dialog.ShowDialog(this) == DialogResult.OK &&
            int.TryParse(txtOffset.Text, out var bitOffset) && bitOffset >= 0 && bitOffset < 32 &&
            int.TryParse(txtSize.Text, out var bitSize) && bitSize > 0 && bitSize <= 32)
        {
            field.Type = FieldType.Bitfield;
            field.BitOffset = bitOffset;
            field.BitSize = bitSize;
            RefreshFieldsGrid();
            UpdateClassTree();
            RefreshValues();
        }
    }

    private void ChangeFieldToEnum()
    {
        if (_fieldsGrid.SelectedRows.Count == 0 || _selectedClass == null) return;
        var field = _fieldsGrid.SelectedRows[0].Tag as StructureField;
        if (field == null) return;

        using var dialog = new Form
        {
            Text = "Configure Enum",
            Size = new Size(400, 350),
            FormBorderStyle = FormBorderStyle.FixedDialog,
            StartPosition = FormStartPosition.CenterParent,
            MaximizeBox = false,
            MinimizeBox = false,
            BackColor = NexusTheme.BackgroundDark
        };

        var lblName = new Label { Text = "Enum Name:", Location = new Point(12, 20), AutoSize = true, ForeColor = NexusTheme.TextPrimary };
        var txtName = new TextBox { Text = field.EnumName ?? $"{field.Name}Enum", Location = new Point(100, 17), Size = new Size(270, 23) };
        NexusTheme.StyleTextBox(txtName);

        var lblValues = new Label { Text = "Values (one per line: value=name):", Location = new Point(12, 55), AutoSize = true, ForeColor = NexusTheme.TextPrimary };
        var txtValues = new TextBox
        {
            Location = new Point(12, 80),
            Size = new Size(358, 180),
            Multiline = true,
            ScrollBars = ScrollBars.Vertical,
            Font = new Font("Consolas", 9f)
        };
        NexusTheme.StyleTextBox(txtValues);

        // Pre-fill with existing values
        if (field.EnumValues != null)
        {
            txtValues.Text = string.Join(Environment.NewLine, field.EnumValues.Select(kv => $"{kv.Key}={kv.Value}"));
        }
        else
        {
            txtValues.Text = "0=None\r\n1=Value1\r\n2=Value2";
        }

        var btnOk = new Button { Text = "OK", DialogResult = DialogResult.OK, Location = new Point(214, 270), Size = new Size(75, 28) };
        var btnCancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, Location = new Point(295, 270), Size = new Size(75, 28) };
        NexusTheme.StylePrimaryButton(btnOk);
        NexusTheme.StyleButton(btnCancel);

        dialog.Controls.AddRange([lblName, txtName, lblValues, txtValues, btnOk, btnCancel]);
        dialog.AcceptButton = btnOk;
        dialog.CancelButton = btnCancel;

        if (dialog.ShowDialog(this) == DialogResult.OK)
        {
            field.Type = FieldType.Enum;
            field.EnumName = txtName.Text.Trim();
            field.EnumValues = [];

            foreach (var line in txtValues.Text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
            {
                var parts = line.Split('=', 2);
                if (parts.Length == 2 && long.TryParse(parts[0].Trim(), out var value))
                {
                    field.EnumValues[value] = parts[1].Trim();
                }
            }

            // Store in global definitions
            if (!string.IsNullOrEmpty(field.EnumName))
                _enumDefinitions[field.EnumName] = field.EnumValues;

            RefreshFieldsGrid();
            UpdateClassTree();
            RefreshValues();
        }
    }

    private void SetPointerChain()
    {
        if (_fieldsGrid.SelectedRows.Count == 0 || _selectedClass == null) return;
        var field = _fieldsGrid.SelectedRows[0].Tag as StructureField;
        if (field == null || field.Type != FieldType.Pointer)
        {
            UpdateStatus("Select a Pointer field to set chain", true);
            return;
        }

        using var dialog = new Form
        {
            Text = "Set Pointer Chain",
            Size = new Size(350, 180),
            FormBorderStyle = FormBorderStyle.FixedDialog,
            StartPosition = FormStartPosition.CenterParent,
            MaximizeBox = false,
            MinimizeBox = false,
            BackColor = NexusTheme.BackgroundDark
        };

        var lblHelp = new Label
        {
            Text = "Enter offsets separated by commas (e.g., 0x10, 0x8, 0x0):",
            Location = new Point(12, 20),
            Size = new Size(320, 20),
            ForeColor = NexusTheme.TextPrimary
        };

        var txtOffsets = new TextBox
        {
            Location = new Point(12, 45),
            Size = new Size(310, 23),
            Font = new Font("Consolas", 9f),
            Text = field.PointerOffsets != null ? string.Join(", ", field.PointerOffsets.Select(o => $"0x{o:X}")) : ""
        };
        NexusTheme.StyleTextBox(txtOffsets);

        var lblExample = new Label
        {
            Text = "Base -> [+0x10] -> [+0x8] -> [+0x0] = Final value",
            Location = new Point(12, 75),
            Size = new Size(320, 20),
            ForeColor = NexusTheme.TextSecondary,
            Font = new Font("Segoe UI", 8f)
        };

        var btnOk = new Button { Text = "OK", DialogResult = DialogResult.OK, Location = new Point(166, 105), Size = new Size(75, 28) };
        var btnCancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, Location = new Point(247, 105), Size = new Size(75, 28) };
        var btnClear = new Button { Text = "Clear", Location = new Point(12, 105), Size = new Size(75, 28) };
        NexusTheme.StylePrimaryButton(btnOk);
        NexusTheme.StyleButton(btnCancel);
        NexusTheme.StyleButton(btnClear);
        btnClear.Click += (s, e) => { txtOffsets.Clear(); };

        dialog.Controls.AddRange([lblHelp, txtOffsets, lblExample, btnOk, btnCancel, btnClear]);
        dialog.AcceptButton = btnOk;
        dialog.CancelButton = btnCancel;

        if (dialog.ShowDialog(this) == DialogResult.OK)
        {
            var text = txtOffsets.Text.Trim();
            if (string.IsNullOrEmpty(text))
            {
                field.PointerOffsets = null;
            }
            else
            {
                field.PointerOffsets = [];
                foreach (var part in text.Split(',', StringSplitOptions.RemoveEmptyEntries))
                {
                    var trimmed = part.Trim();
                    if (trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                        trimmed = trimmed[2..];

                    if (long.TryParse(trimmed, System.Globalization.NumberStyles.HexNumber, null, out var offset))
                        field.PointerOffsets.Add(offset);
                }
            }
            RefreshValues();
            UpdateStatus(field.PointerOffsets?.Count > 0 ? $"Set {field.PointerOffsets.Count}-level pointer chain" : "Cleared pointer chain");
        }
    }

    private void ValidateFieldAlignment()
    {
        if (_selectedClass == null)
        {
            UpdateStatus("No class selected", true);
            return;
        }

        var issues = new List<string>();

        foreach (var field in _selectedClass.Fields)
        {
            var size = GetFieldSize(field.Type, field.ArrayCount, field.ArrayBaseType);
            var alignment = size switch
            {
                1 => 1,
                2 => 2,
                <= 4 => 4,
                _ => 8
            };

            if (field.Offset % alignment != 0)
            {
                issues.Add($"{field.Name} at 0x{field.Offset:X}: {size}-byte type should be {alignment}-byte aligned");
            }
        }

        if (issues.Count == 0)
        {
            MessageBox.Show("All fields are properly aligned.", "Alignment Validation",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        else
        {
            MessageBox.Show($"Found {issues.Count} alignment issues:\n\n" + string.Join("\n", issues.Take(10)) +
                (issues.Count > 10 ? $"\n...and {issues.Count - 10} more" : ""),
                "Alignment Validation", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    #endregion
}
