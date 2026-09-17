using Nexus.UI.Core;
using Nexus.UI.Interop;
using Nexus.UI.Styles;

namespace Nexus.UI.Panels;

public partial class StructuresPanel
{
    #region Class Management

    private void AddNewClass(string? name = null)
    {
        name ??= $"Class{_classes.Count + 1}";
        var cls = new StructureClass { Name = name };

        // Add some default fields
        cls.Fields.Add(new StructureField { Offset = 0, Type = FieldType.UInt64, Name = "field_0" });
        cls.Fields.Add(new StructureField { Offset = 8, Type = FieldType.UInt64, Name = "field_8" });
        cls.Fields.Add(new StructureField { Offset = 16, Type = FieldType.UInt64, Name = "field_10" });
        cls.Fields.Add(new StructureField { Offset = 24, Type = FieldType.UInt64, Name = "field_18" });

        _classes.Add(cls);
        UpdateClassTree();
        UpdateClassCombo();

        _classCombo.SelectedIndex = _classes.Count - 1;
    }

    private void RenameSelectedClass()
    {
        if (_selectedClass == null) return;

        using var dialog = new Form
        {
            Text = "Rename Class",
            Size = new Size(300, 120),
            FormBorderStyle = FormBorderStyle.FixedDialog,
            StartPosition = FormStartPosition.CenterParent,
            MaximizeBox = false,
            MinimizeBox = false,
            BackColor = NexusTheme.BackgroundDark
        };

        var textBox = new TextBox
        {
            Text = _selectedClass.Name,
            Location = new Point(12, 20),
            Size = new Size(260, 23)
        };
        NexusTheme.StyleTextBox(textBox);

        var btnOk = new Button { Text = "OK", DialogResult = DialogResult.OK, Location = new Point(116, 55), Size = new Size(75, 28) };
        var btnCancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, Location = new Point(197, 55), Size = new Size(75, 28) };
        NexusTheme.StylePrimaryButton(btnOk);
        NexusTheme.StyleButton(btnCancel);

        dialog.Controls.AddRange([textBox, btnOk, btnCancel]);
        dialog.AcceptButton = btnOk;
        dialog.CancelButton = btnCancel;

        if (dialog.ShowDialog(this) == DialogResult.OK && !string.IsNullOrWhiteSpace(textBox.Text))
        {
            _selectedClass.Name = textBox.Text.Trim();
            UpdateClassTree();
            UpdateClassCombo();
        }
    }

    private void DeleteSelectedClass()
    {
        if (_selectedClass == null || _classes.Count <= 1) return;

        var result = MessageBox.Show(
            $"Delete class '{_selectedClass.Name}'?",
            "Confirm Delete",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Question);

        if (result == DialogResult.Yes)
        {
            _classes.Remove(_selectedClass);
            _selectedClass = _classes.FirstOrDefault();
            UpdateClassTree();
            UpdateClassCombo();
            if (_classes.Count > 0)
                _classCombo.SelectedIndex = 0;
        }
    }

    private void UpdateClassTree()
    {
        _classTree.Nodes.Clear();
        foreach (var cls in _classes)
        {
            var node = new TreeNode(cls.Name) { Tag = cls };
            foreach (var field in cls.Fields)
            {
                node.Nodes.Add(new TreeNode($"+0x{field.Offset:X} {field.Name} ({field.Type})") { Tag = field });
            }
            _classTree.Nodes.Add(node);
        }
        _classTree.ExpandAll();
    }

    private void UpdateClassCombo()
    {
        _classCombo.Items.Clear();
        foreach (var cls in _classes)
        {
            _classCombo.Items.Add(cls.Name);
        }
    }

    #endregion

    #region Field Management

    private void RefreshFieldsGrid()
    {
        _fieldsGrid.Rows.Clear();
        if (_selectedClass == null) return;

        foreach (var field in _selectedClass.Fields)
        {
            var rowIndex = _fieldsGrid.Rows.Add();
            var row = _fieldsGrid.Rows[rowIndex];
            row.Tag = field;
            row.Cells["Offset"].Value = $"0x{field.Offset:X}";
            row.Cells["Type"].Value = field.Type.ToString();
            row.Cells["Name"].Value = field.Name;
            row.Cells["Value"].Value = field.CachedValue;
            row.Cells["Comment"].Value = field.Comment;
        }
    }

    private void AddField()
    {
        if (_selectedClass == null) return;

        int nextOffset = 0;
        if (_selectedClass.Fields.Count > 0)
        {
            var lastField = _selectedClass.Fields[^1];
            nextOffset = lastField.Offset + GetFieldSize(lastField.Type);
        }

        var field = new StructureField
        {
            Offset = nextOffset,
            Type = FieldType.UInt64,
            Name = $"field_{nextOffset:X}"
        };

        _selectedClass.Fields.Add(field);
        RefreshFieldsGrid();
        UpdateClassTree();
    }

    private void InsertFieldAbove()
    {
        if (_selectedClass == null || _fieldsGrid.SelectedRows.Count == 0) return;

        var selectedRow = _fieldsGrid.SelectedRows[0];
        var selectedField = selectedRow.Tag as StructureField;
        if (selectedField == null) return;

        var index = _selectedClass.Fields.IndexOf(selectedField);
        var field = new StructureField
        {
            Offset = selectedField.Offset,
            Type = FieldType.UInt64,
            Name = $"field_{selectedField.Offset:X}"
        };

        _selectedClass.Fields.Insert(index, field);

        // Shift subsequent fields
        for (int i = index + 1; i < _selectedClass.Fields.Count; i++)
        {
            _selectedClass.Fields[i].Offset += GetFieldSize(field.Type);
        }

        RefreshFieldsGrid();
        UpdateClassTree();
    }

    private void DeleteSelectedField()
    {
        if (_selectedClass == null || _fieldsGrid.SelectedRows.Count == 0) return;

        var selectedRow = _fieldsGrid.SelectedRows[0];
        var selectedField = selectedRow.Tag as StructureField;
        if (selectedField == null) return;

        _selectedClass.Fields.Remove(selectedField);
        RefreshFieldsGrid();
        UpdateClassTree();
    }

    private void ChangeFieldType(string typeName)
    {
        if (_fieldsGrid.SelectedRows.Count == 0) return;

        var selectedRow = _fieldsGrid.SelectedRows[0];
        var field = selectedRow.Tag as StructureField;
        if (field == null) return;

        if (Enum.TryParse<FieldType>(typeName, out var type))
        {
            field.Type = type;
            RefreshFieldsGrid();
            RefreshValues();
            UpdateClassTree();
        }
    }

    private void FollowPointer()
    {
        if (_fieldsGrid.SelectedRows.Count == 0) return;

        var selectedRow = _fieldsGrid.SelectedRows[0];
        var field = selectedRow.Tag as StructureField;
        if (field == null || field.Type != FieldType.Pointer) return;

        if (ulong.TryParse(field.CachedValue?.Replace("0x", ""), System.Globalization.NumberStyles.HexNumber, null, out var ptr) && ptr != 0)
        {
            _baseAddress = ptr;
            _addressTextBox.Text = $"{ptr:X}";
            RefreshValues();
        }
    }

    private static int GetFieldSize(FieldType type, int customSize = 0, FieldType arrayBaseType = FieldType.UInt8) => type switch
    {
        FieldType.Int8 or FieldType.UInt8 or FieldType.Bool => 1,
        FieldType.Int16 or FieldType.UInt16 => 2,
        FieldType.Int32 or FieldType.UInt32 or FieldType.Float or FieldType.Timestamp => 4,
        FieldType.Int64 or FieldType.UInt64 or FieldType.Double or FieldType.Pointer => 8,
        FieldType.String or FieldType.WString => 64,
        FieldType.Bytes => 16,
        FieldType.Struct => customSize > 0 ? customSize : 8,  // Default to pointer size for nested struct
        FieldType.Padding => customSize > 0 ? customSize : 1,  // Padding uses custom size
        FieldType.Array => customSize * GetFieldSize(arrayBaseType),  // Array size = count * element size
        FieldType.Bitfield => (customSize + 7) / 8,  // Bitfield size in bytes (round up)
        FieldType.Enum => 4,  // Default to 4-byte enum
        FieldType.GUID => 16,  // GUID is always 16 bytes
        FieldType.Union => customSize > 0 ? customSize : 8,  // Union uses largest member size
        _ => 8
    };

    #endregion
}
