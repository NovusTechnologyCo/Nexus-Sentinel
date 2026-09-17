using Nexus.UI.Core;
using Nexus.UI.Interop;
using Nexus.UI.Styles;

namespace Nexus.UI.Panels;

public partial class StructuresPanel
{
    #region Save/Load Operations

    private void SaveStructure()
    {
        if (_selectedClass == null)
        {
            UpdateStatus("No class selected to save", true);
            return;
        }

        using var dialog = new SaveFileDialog
        {
            Title = "Save Structure",
            Filter = "Nexus Structure (*.nxs)|*.nxs|All files (*.*)|*.*",
            DefaultExt = "nxs",
            FileName = _selectedClass.Name
        };

        if (dialog.ShowDialog() != DialogResult.OK) return;

        try
        {
            // Create engine structure from our class
            var result = NexusEngine.Nexus_StructureCreate(_selectedClass.Name, out var structHandle);
            if (result != NexusResult.OK)
            {
                UpdateStatus($"Failed to create structure: {result}", true);
                return;
            }

            try
            {
                // Add all elements
                foreach (var field in _selectedClass.Fields)
                {
                    var elemType = FieldTypeToNexusElementType(field.Type);
                    var size = GetFieldSize(field.Type);
                    NexusEngine.Nexus_StructureAddElement(structHandle, field.Offset, elemType, field.Name, size, out _);
                }

                // Save to file
                result = NexusEngine.Nexus_StructureSave(structHandle, dialog.FileName);
                if (result != NexusResult.OK)
                {
                    UpdateStatus($"Failed to save structure: {result}", true);
                    return;
                }

                UpdateStatus($"Saved structure to {Path.GetFileName(dialog.FileName)}");
            }
            finally
            {
                NexusEngine.Nexus_StructureDestroy(structHandle);
            }
        }
        catch (Exception ex)
        {
            UpdateStatus($"Save failed: {ex.Message}", true);
        }
    }

    private void LoadStructure()
    {
        using var dialog = new OpenFileDialog
        {
            Title = "Load Structure",
            Filter = "Nexus Structure (*.nxs)|*.nxs|All files (*.*)|*.*",
            DefaultExt = "nxs"
        };

        if (dialog.ShowDialog() != DialogResult.OK) return;

        try
        {
            var result = NexusEngine.Nexus_StructureLoad(dialog.FileName, out var structHandle);
            if (result != NexusResult.OK)
            {
                UpdateStatus($"Failed to load structure: {result}", true);
                return;
            }

            try
            {
                LoadStructureFromHandle(structHandle, Path.GetFileNameWithoutExtension(dialog.FileName));
                UpdateStatus($"Loaded structure from {Path.GetFileName(dialog.FileName)}");
            }
            finally
            {
                NexusEngine.Nexus_StructureDestroy(structHandle);
            }
        }
        catch (Exception ex)
        {
            UpdateStatus($"Load failed: {ex.Message}", true);
        }
    }

    private void ImportCEStructure()
    {
        using var dialog = new OpenFileDialog
        {
            Title = "Import Cheat Engine Structure",
            Filter = "CE Structure (*.CSX)|*.CSX|All files (*.*)|*.*",
            DefaultExt = "CSX"
        };

        if (dialog.ShowDialog() != DialogResult.OK) return;

        try
        {
            var result = NexusEngine.Nexus_StructureImportCE(dialog.FileName, out var structHandle);
            if (result != NexusResult.OK)
            {
                UpdateStatus($"Failed to import CE structure: {result}", true);
                return;
            }

            try
            {
                LoadStructureFromHandle(structHandle, Path.GetFileNameWithoutExtension(dialog.FileName));
                UpdateStatus($"Imported CE structure from {Path.GetFileName(dialog.FileName)}");
            }
            finally
            {
                NexusEngine.Nexus_StructureDestroy(structHandle);
            }
        }
        catch (Exception ex)
        {
            UpdateStatus($"Import failed: {ex.Message}", true);
        }
    }

    private void ExportCEStructure()
    {
        if (_selectedClass == null)
        {
            UpdateStatus("No class selected to export", true);
            return;
        }

        using var dialog = new SaveFileDialog
        {
            Title = "Export Cheat Engine Structure",
            Filter = "CE Structure (*.CSX)|*.CSX|All files (*.*)|*.*",
            DefaultExt = "CSX",
            FileName = _selectedClass.Name
        };

        if (dialog.ShowDialog() != DialogResult.OK) return;

        try
        {
            // Create engine structure from our class
            var result = NexusEngine.Nexus_StructureCreate(_selectedClass.Name, out var structHandle);
            if (result != NexusResult.OK)
            {
                UpdateStatus($"Failed to create structure: {result}", true);
                return;
            }

            try
            {
                // Add all elements
                foreach (var field in _selectedClass.Fields)
                {
                    var elemType = FieldTypeToNexusElementType(field.Type);
                    var size = GetFieldSize(field.Type);
                    NexusEngine.Nexus_StructureAddElement(structHandle, field.Offset, elemType, field.Name, size, out _);
                }

                // Export to CE format
                result = NexusEngine.Nexus_StructureExportCE(structHandle, dialog.FileName);
                if (result != NexusResult.OK)
                {
                    UpdateStatus($"Failed to export CE structure: {result}", true);
                    return;
                }

                UpdateStatus($"Exported CE structure to {Path.GetFileName(dialog.FileName)}");
            }
            finally
            {
                NexusEngine.Nexus_StructureDestroy(structHandle);
            }
        }
        catch (Exception ex)
        {
            UpdateStatus($"Export failed: {ex.Message}", true);
        }
    }

    private void LoadStructureFromHandle(IntPtr structHandle, string defaultName)
    {
        // Get structure info
        var result = NexusEngine.Nexus_StructureGetInfo(structHandle, out var info);
        if (result != NexusResult.OK)
        {
            UpdateStatus($"Failed to get structure info: {result}", true);
            return;
        }

        // Create new class
        var cls = new StructureClass
        {
            Name = string.IsNullOrEmpty(info.Name) ? defaultName : info.Name
        };

        // Get element count
        result = NexusEngine.Nexus_StructureGetElementCount(structHandle, out var count);
        if (result != NexusResult.OK)
        {
            UpdateStatus($"Failed to get element count: {result}", true);
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
                Name = string.IsNullOrEmpty(element.Name) ? $"field_{element.Offset:X}" : element.Name
            });
        }

        // Add to our list
        _classes.Add(cls);
        UpdateClassTree();
        UpdateClassCombo();
        _classCombo.SelectedIndex = _classes.Count - 1;
    }

    private static NexusElementType FieldTypeToNexusElementType(FieldType type) => type switch
    {
        FieldType.Int8 or FieldType.UInt8 or FieldType.Bool => NexusElementType.Byte,
        FieldType.Int16 or FieldType.UInt16 => NexusElementType.Word,
        FieldType.Int32 or FieldType.UInt32 => NexusElementType.DWord,
        FieldType.Int64 or FieldType.UInt64 => NexusElementType.QWord,
        FieldType.Float => NexusElementType.Float,
        FieldType.Double => NexusElementType.Double,
        FieldType.String => NexusElementType.String,
        FieldType.WString => NexusElementType.WString,
        FieldType.Pointer => NexusElementType.Pointer,
        FieldType.Bytes => NexusElementType.ByteArray,
        FieldType.Struct => NexusElementType.Struct,
        FieldType.Padding => NexusElementType.Padding,
        _ => NexusElementType.QWord
    };

    private static FieldType NexusElementTypeToFieldType(NexusElementType type) => type switch
    {
        NexusElementType.Byte => FieldType.UInt8,
        NexusElementType.Word => FieldType.UInt16,
        NexusElementType.DWord => FieldType.UInt32,
        NexusElementType.QWord => FieldType.UInt64,
        NexusElementType.Float => FieldType.Float,
        NexusElementType.Double => FieldType.Double,
        NexusElementType.String => FieldType.String,
        NexusElementType.WString => FieldType.WString,
        NexusElementType.Pointer => FieldType.Pointer,
        NexusElementType.ByteArray => FieldType.Bytes,
        NexusElementType.Struct => FieldType.Struct,
        NexusElementType.Padding => FieldType.Padding,
        _ => FieldType.UInt64
    };

    #endregion

    #region Structure Library

    private static string LibraryPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "NexusSentinel", "structure_library.json");

    private void SaveToLibrary()
    {
        if (_selectedClass == null)
        {
            UpdateStatus("No class selected to save", true);
            return;
        }

        try
        {
            // Ensure directory exists
            var dir = Path.GetDirectoryName(LibraryPath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                Directory.CreateDirectory(dir);

            // Load existing library
            var library = LoadLibraryData();

            // Add or update the structure
            var entry = SerializeStructureClass(_selectedClass);
            library[_selectedClass.Name] = entry;

            // Save back
            var json = System.Text.Json.JsonSerializer.Serialize(library, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(LibraryPath, json);

            UpdateStatus($"Saved '{_selectedClass.Name}' to library ({library.Count} structures total)");
        }
        catch (Exception ex)
        {
            UpdateStatus($"Failed to save to library: {ex.Message}", true);
        }
    }

    private void LoadFromLibrary()
    {
        try
        {
            var library = LoadLibraryData();
            if (library.Count == 0)
            {
                UpdateStatus("Library is empty", true);
                return;
            }

            // Show selection dialog
            using var dialog = new Form
            {
                Text = "Load from Library",
                Size = new Size(400, 350),
                FormBorderStyle = FormBorderStyle.FixedDialog,
                StartPosition = FormStartPosition.CenterParent,
                MaximizeBox = false,
                MinimizeBox = false,
                BackColor = NexusTheme.BackgroundDark
            };

            var listBox = new ListBox
            {
                Location = new Point(12, 12),
                Size = new Size(360, 240),
                Font = new Font("Consolas", 9f)
            };
            listBox.Items.AddRange(library.Keys.OrderBy(k => k).ToArray());
            if (listBox.Items.Count > 0) listBox.SelectedIndex = 0;

            var btnOk = new Button { Text = "Load", DialogResult = DialogResult.OK, Location = new Point(216, 265), Size = new Size(75, 28) };
            var btnCancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, Location = new Point(297, 265), Size = new Size(75, 28) };
            NexusTheme.StylePrimaryButton(btnOk);
            NexusTheme.StyleButton(btnCancel);

            dialog.Controls.AddRange([listBox, btnOk, btnCancel]);
            dialog.AcceptButton = btnOk;
            dialog.CancelButton = btnCancel;

            if (dialog.ShowDialog(this) == DialogResult.OK && listBox.SelectedItem != null)
            {
                var name = listBox.SelectedItem.ToString()!;
                if (library.TryGetValue(name, out var entry))
                {
                    var cls = DeserializeStructureClass(name, entry);
                    _classes.Add(cls);
                    UpdateClassTree();
                    UpdateClassCombo();
                    _classCombo.SelectedIndex = _classes.Count - 1;
                    UpdateStatus($"Loaded '{name}' from library");
                }
            }
        }
        catch (Exception ex)
        {
            UpdateStatus($"Failed to load from library: {ex.Message}", true);
        }
    }

    private void ManageLibrary()
    {
        try
        {
            var library = LoadLibraryData();

            using var dialog = new Form
            {
                Text = "Manage Structure Library",
                Size = new Size(500, 400),
                FormBorderStyle = FormBorderStyle.FixedDialog,
                StartPosition = FormStartPosition.CenterParent,
                MaximizeBox = false,
                MinimizeBox = false,
                BackColor = NexusTheme.BackgroundDark
            };

            var listBox = new ListBox
            {
                Location = new Point(12, 12),
                Size = new Size(360, 300),
                Font = new Font("Consolas", 9f),
                SelectionMode = SelectionMode.MultiExtended
            };
            listBox.Items.AddRange(library.Keys.OrderBy(k => k).ToArray());

            var btnDelete = new Button { Text = "Delete Selected", Location = new Point(380, 12), Size = new Size(95, 28) };
            NexusTheme.StyleButton(btnDelete);
            btnDelete.Click += (s, e) =>
            {
                var selected = listBox.SelectedItems.Cast<string>().ToList();
                foreach (var name in selected)
                {
                    library.Remove(name);
                    listBox.Items.Remove(name);
                }
            };

            var btnExport = new Button { Text = "Export All", Location = new Point(380, 48), Size = new Size(95, 28) };
            NexusTheme.StyleButton(btnExport);
            btnExport.Click += (s, e) =>
            {
                using var saveDialog = new SaveFileDialog
                {
                    Title = "Export Library",
                    Filter = "JSON files (*.json)|*.json",
                    FileName = "structure_library_export.json"
                };
                if (saveDialog.ShowDialog() == DialogResult.OK)
                {
                    var json = System.Text.Json.JsonSerializer.Serialize(library, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
                    File.WriteAllText(saveDialog.FileName, json);
                    MessageBox.Show($"Exported {library.Count} structures.", "Export Complete", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            };

            var btnImport = new Button { Text = "Import", Location = new Point(380, 84), Size = new Size(95, 28) };
            NexusTheme.StyleButton(btnImport);
            btnImport.Click += (s, e) =>
            {
                using var openDialog = new OpenFileDialog
                {
                    Title = "Import Library",
                    Filter = "JSON files (*.json)|*.json"
                };
                if (openDialog.ShowDialog() == DialogResult.OK)
                {
                    var json = File.ReadAllText(openDialog.FileName);
                    var imported = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, System.Text.Json.JsonElement>>(json);
                    if (imported != null)
                    {
                        int count = 0;
                        foreach (var kv in imported)
                        {
                            if (!library.ContainsKey(kv.Key))
                            {
                                library[kv.Key] = kv.Value;
                                listBox.Items.Add(kv.Key);
                                count++;
                            }
                        }
                        MessageBox.Show($"Imported {count} new structures.", "Import Complete", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                }
            };

            var lblCount = new Label
            {
                Text = $"{library.Count} structures in library",
                Location = new Point(12, 320),
                AutoSize = true,
                ForeColor = NexusTheme.TextSecondary
            };

            var btnSave = new Button { Text = "Save && Close", DialogResult = DialogResult.OK, Location = new Point(380, 320), Size = new Size(95, 28) };
            NexusTheme.StylePrimaryButton(btnSave);

            dialog.Controls.AddRange([listBox, btnDelete, btnExport, btnImport, lblCount, btnSave]);
            dialog.AcceptButton = btnSave;

            if (dialog.ShowDialog(this) == DialogResult.OK)
            {
                // Save updated library
                var dir = Path.GetDirectoryName(LibraryPath);
                if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                    Directory.CreateDirectory(dir);

                var json = System.Text.Json.JsonSerializer.Serialize(library, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(LibraryPath, json);
                UpdateStatus($"Library saved with {library.Count} structures");
            }
        }
        catch (Exception ex)
        {
            UpdateStatus($"Failed to manage library: {ex.Message}", true);
        }
    }

    private Dictionary<string, System.Text.Json.JsonElement> LoadLibraryData()
    {
        if (!File.Exists(LibraryPath))
            return [];

        var json = File.ReadAllText(LibraryPath);
        return System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, System.Text.Json.JsonElement>>(json) ?? [];
    }

    private static System.Text.Json.JsonElement SerializeStructureClass(StructureClass cls)
    {
        var fields = cls.Fields.Select(f => new
        {
            f.Offset,
            Type = f.Type.ToString(),
            f.Name,
            f.Comment,
            f.ArrayCount,
            ArrayBaseType = f.ArrayBaseType.ToString(),
            f.BitOffset,
            f.BitSize,
            f.EnumName,
            f.EnumValues,
            f.NestedStructName,
            f.PointerOffsets
        }).ToList();

        var json = System.Text.Json.JsonSerializer.Serialize(new { Name = cls.Name, Fields = fields });
        return System.Text.Json.JsonSerializer.Deserialize<System.Text.Json.JsonElement>(json);
    }

    private static StructureClass DeserializeStructureClass(string name, System.Text.Json.JsonElement element)
    {
        var cls = new StructureClass { Name = name };

        if (element.TryGetProperty("Fields", out var fieldsElement) && fieldsElement.ValueKind == System.Text.Json.JsonValueKind.Array)
        {
            foreach (var fieldElement in fieldsElement.EnumerateArray())
            {
                var field = new StructureField();

                if (fieldElement.TryGetProperty("Offset", out var offset))
                    field.Offset = offset.GetInt32();
                if (fieldElement.TryGetProperty("Type", out var type) && Enum.TryParse<FieldType>(type.GetString(), out var ft))
                    field.Type = ft;
                if (fieldElement.TryGetProperty("Name", out var fname))
                    field.Name = fname.GetString() ?? "field";
                if (fieldElement.TryGetProperty("Comment", out var comment))
                    field.Comment = comment.GetString();
                if (fieldElement.TryGetProperty("ArrayCount", out var arrayCount))
                    field.ArrayCount = arrayCount.GetInt32();
                if (fieldElement.TryGetProperty("ArrayBaseType", out var abt) && Enum.TryParse<FieldType>(abt.GetString(), out var abtType))
                    field.ArrayBaseType = abtType;
                if (fieldElement.TryGetProperty("BitOffset", out var bitOffset))
                    field.BitOffset = bitOffset.GetInt32();
                if (fieldElement.TryGetProperty("BitSize", out var bitSize))
                    field.BitSize = bitSize.GetInt32();
                if (fieldElement.TryGetProperty("EnumName", out var enumName))
                    field.EnumName = enumName.GetString();
                if (fieldElement.TryGetProperty("NestedStructName", out var nestedStruct))
                    field.NestedStructName = nestedStruct.GetString();

                if (fieldElement.TryGetProperty("EnumValues", out var enumValues) && enumValues.ValueKind == System.Text.Json.JsonValueKind.Object)
                {
                    field.EnumValues = [];
                    foreach (var prop in enumValues.EnumerateObject())
                    {
                        if (long.TryParse(prop.Name, out var key))
                            field.EnumValues[key] = prop.Value.GetString() ?? "";
                    }
                }

                if (fieldElement.TryGetProperty("PointerOffsets", out var ptrOffsets) && ptrOffsets.ValueKind == System.Text.Json.JsonValueKind.Array)
                {
                    field.PointerOffsets = [];
                    foreach (var po in ptrOffsets.EnumerateArray())
                        field.PointerOffsets.Add(po.GetInt64());
                }

                cls.Fields.Add(field);
            }
        }

        return cls;
    }

    #endregion

    #region Code Generation

    private void GenerateCStruct()
    {
        if (_selectedClass == null) return;

        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"typedef struct _{_selectedClass.Name} {{");

        foreach (var field in _selectedClass.Fields)
        {
            var cType = GetCType(field.Type, field);
            if (field.Type == FieldType.Padding)
                sb.AppendLine($"    {cType}; // 0x{field.Offset:X} - padding");
            else
                sb.AppendLine($"    {cType} {field.Name}; // 0x{field.Offset:X}");
        }

        sb.AppendLine($"}} {_selectedClass.Name};");

        Clipboard.SetText(sb.ToString());
        UpdateStatus("C struct copied to clipboard");
    }

    private void GenerateCSharpClass()
    {
        if (_selectedClass == null) return;

        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"[StructLayout(LayoutKind.Explicit)]");
        sb.AppendLine($"public unsafe struct {_selectedClass.Name}");
        sb.AppendLine("{");

        foreach (var field in _selectedClass.Fields)
        {
            var csType = GetCSharpType(field.Type, field);
            if (field.Type == FieldType.Padding)
                sb.AppendLine($"    [FieldOffset(0x{field.Offset:X})] public {csType}; // padding");
            else
                sb.AppendLine($"    [FieldOffset(0x{field.Offset:X})] public {csType} {field.Name};");
        }

        sb.AppendLine("}");

        Clipboard.SetText(sb.ToString());
        UpdateStatus("C# class copied to clipboard");
    }

    private static string GetCType(FieldType type, StructureField? field = null) => type switch
    {
        FieldType.Int8 => "int8_t",
        FieldType.UInt8 => "uint8_t",
        FieldType.Int16 => "int16_t",
        FieldType.UInt16 => "uint16_t",
        FieldType.Int32 => "int32_t",
        FieldType.UInt32 => "uint32_t",
        FieldType.Int64 => "int64_t",
        FieldType.UInt64 => "uint64_t",
        FieldType.Float => "float",
        FieldType.Double => "double",
        FieldType.Bool => "bool",
        FieldType.Pointer => "void*",
        FieldType.String => "char*",
        FieldType.WString => "wchar_t*",
        FieldType.Bytes => "uint8_t[16]",
        FieldType.Struct => field?.NestedStructName ?? "void*",
        FieldType.Padding => $"uint8_t[{field?.ArrayCount ?? 1}]",
        FieldType.Array => $"{GetCType(field?.ArrayBaseType ?? FieldType.UInt8)}[{field?.ArrayCount ?? 1}]",
        FieldType.Bitfield => $"uint32_t /* bits {field?.BitOffset}-{(field?.BitOffset ?? 0) + (field?.BitSize ?? 1) - 1} */",
        FieldType.Enum => field?.EnumName ?? "int32_t",
        FieldType.GUID => "GUID",
        FieldType.Timestamp => "time_t",
        FieldType.Union => "union { /* members */ }",
        _ => "void*"
    };

    private static string GetCSharpType(FieldType type, StructureField? field = null) => type switch
    {
        FieldType.Int8 => "sbyte",
        FieldType.UInt8 => "byte",
        FieldType.Int16 => "short",
        FieldType.UInt16 => "ushort",
        FieldType.Int32 => "int",
        FieldType.UInt32 => "uint",
        FieldType.Int64 => "long",
        FieldType.UInt64 => "ulong",
        FieldType.Float => "float",
        FieldType.Double => "double",
        FieldType.Bool => "bool",
        FieldType.Pointer => "IntPtr",
        FieldType.String => "IntPtr",
        FieldType.WString => "IntPtr",
        FieldType.Struct => field?.NestedStructName ?? "IntPtr",
        FieldType.Padding => $"fixed byte _padding_{field?.Offset:X}[{field?.ArrayCount ?? 1}]",
        FieldType.Array => $"fixed {GetCSharpType(field?.ArrayBaseType ?? FieldType.UInt8)} {field?.Name}[{field?.ArrayCount ?? 1}]",
        FieldType.Bitfield => "uint",
        FieldType.Enum => field?.EnumName ?? "int",
        FieldType.GUID => "Guid",
        FieldType.Timestamp => "uint",
        FieldType.Union => "/* union */",
        _ => "IntPtr"
    };

    #endregion
}
