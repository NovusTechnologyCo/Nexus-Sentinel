using Nexus.UI.Core;
using Nexus.UI.Interop;
using Nexus.UI.Styles;

namespace Nexus.UI.Panels;

public partial class StructuresPanel
{
    #region Advanced Analysis

    private void ShowStructureDiff()
    {
        if (_classes.Count < 2)
        {
            UpdateStatus("Need at least 2 structures to compare", true);
            return;
        }

        using var dialog = new Form
        {
            Text = "Compare Structures",
            Size = new Size(800, 600),
            FormBorderStyle = FormBorderStyle.Sizable,
            StartPosition = FormStartPosition.CenterParent,
            BackColor = NexusTheme.BackgroundDark
        };

        var lblStruct1 = new Label { Text = "Structure 1:", Location = new Point(12, 15), AutoSize = true, ForeColor = NexusTheme.TextPrimary };
        var cmbStruct1 = new ComboBox { Location = new Point(90, 12), Size = new Size(200, 23), DropDownStyle = ComboBoxStyle.DropDownList };
        cmbStruct1.Items.AddRange(_classes.Select(c => c.Name).ToArray());
        cmbStruct1.SelectedIndex = 0;
        NexusTheme.StyleComboBox(cmbStruct1);

        var lblStruct2 = new Label { Text = "Structure 2:", Location = new Point(310, 15), AutoSize = true, ForeColor = NexusTheme.TextPrimary };
        var cmbStruct2 = new ComboBox { Location = new Point(390, 12), Size = new Size(200, 23), DropDownStyle = ComboBoxStyle.DropDownList };
        cmbStruct2.Items.AddRange(_classes.Select(c => c.Name).ToArray());
        cmbStruct2.SelectedIndex = Math.Min(1, _classes.Count - 1);
        NexusTheme.StyleComboBox(cmbStruct2);

        var btnCompare = new Button { Text = "Compare", Location = new Point(610, 10), Size = new Size(80, 28) };
        NexusTheme.StylePrimaryButton(btnCompare);

        var diffGrid = new DataGridView
        {
            Location = new Point(12, 50),
            Size = new Size(760, 480),
            Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right,
            AllowUserToAddRows = false,
            AllowUserToDeleteRows = false,
            ReadOnly = true,
            RowHeadersVisible = false,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect,
            Font = new Font("Consolas", 9f)
        };
        NexusTheme.StyleDataGridView(diffGrid);
        diffGrid.Columns.AddRange([
            new DataGridViewTextBoxColumn { Name = "Status", HeaderText = "Status", Width = 80 },
            new DataGridViewTextBoxColumn { Name = "Offset", HeaderText = "Offset", Width = 70 },
            new DataGridViewTextBoxColumn { Name = "Name1", HeaderText = "Name (1)", Width = 150 },
            new DataGridViewTextBoxColumn { Name = "Type1", HeaderText = "Type (1)", Width = 100 },
            new DataGridViewTextBoxColumn { Name = "Name2", HeaderText = "Name (2)", Width = 150 },
            new DataGridViewTextBoxColumn { Name = "Type2", HeaderText = "Type (2)", Width = 100 }
        ]);

        btnCompare.Click += (s, e) =>
        {
            diffGrid.Rows.Clear();
            var struct1 = _classes.FirstOrDefault(c => c.Name == cmbStruct1.SelectedItem?.ToString());
            var struct2 = _classes.FirstOrDefault(c => c.Name == cmbStruct2.SelectedItem?.ToString());
            if (struct1 == null || struct2 == null) return;

            var allOffsets = struct1.Fields.Select(f => f.Offset)
                .Concat(struct2.Fields.Select(f => f.Offset))
                .Distinct().OrderBy(o => o).ToList();

            foreach (var offset in allOffsets)
            {
                var field1 = struct1.Fields.FirstOrDefault(f => f.Offset == offset);
                var field2 = struct2.Fields.FirstOrDefault(f => f.Offset == offset);

                string status;
                Color rowColor;

                if (field1 == null)
                {
                    status = "Added";
                    rowColor = Color.FromArgb(40, 80, 40);
                }
                else if (field2 == null)
                {
                    status = "Removed";
                    rowColor = Color.FromArgb(80, 40, 40);
                }
                else if (field1.Type != field2.Type || field1.Name != field2.Name)
                {
                    status = "Modified";
                    rowColor = Color.FromArgb(80, 80, 40);
                }
                else
                {
                    status = "Same";
                    rowColor = NexusTheme.BackgroundControl;
                }

                var rowIdx = diffGrid.Rows.Add(
                    status,
                    $"0x{offset:X}",
                    field1?.Name ?? "-",
                    field1?.Type.ToString() ?? "-",
                    field2?.Name ?? "-",
                    field2?.Type.ToString() ?? "-"
                );
                diffGrid.Rows[rowIdx].DefaultCellStyle.BackColor = rowColor;
            }
        };

        var btnClose = new Button { Text = "Close", Location = new Point(700, 540), Size = new Size(75, 28), Anchor = AnchorStyles.Bottom | AnchorStyles.Right };
        NexusTheme.StyleButton(btnClose);
        btnClose.Click += (s, e) => dialog.Close();

        dialog.Controls.AddRange([lblStruct1, cmbStruct1, lblStruct2, cmbStruct2, btnCompare, diffGrid, btnClose]);
        btnCompare.PerformClick(); // Initial comparison
        dialog.ShowDialog(this);
    }

    private void ShowByteMapView()
    {
        if (_selectedClass == null || _selectedClass.Fields.Count == 0)
        {
            UpdateStatus("No structure selected", true);
            return;
        }

        using var dialog = new Form
        {
            Text = $"Byte Map - {_selectedClass.Name}",
            Size = new Size(900, 500),
            FormBorderStyle = FormBorderStyle.Sizable,
            StartPosition = FormStartPosition.CenterParent,
            BackColor = NexusTheme.BackgroundDark
        };

        var byteMapPanel = new Panel
        {
            Location = new Point(12, 12),
            Size = new Size(860, 400),
            Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right,
            AutoScroll = true,
            BackColor = NexusTheme.BackgroundControl
        };

        // Calculate structure size
        int structSize = 0;
        foreach (var field in _selectedClass.Fields)
        {
            var fieldEnd = field.Offset + GetFieldSize(field.Type, field.ArrayCount, field.ArrayBaseType);
            if (fieldEnd > structSize) structSize = fieldEnd;
        }

        var byteMapCanvas = new Panel
        {
            Location = new Point(0, 0),
            Size = new Size(Math.Max(860, (structSize / 16 + 1) * 50 + 100), Math.Max(400, 20 * 18 + 50)),
            BackColor = NexusTheme.BackgroundControl
        };

        byteMapCanvas.Paint += (s, e) =>
        {
            var g = e.Graphics;
            g.Clear(NexusTheme.BackgroundControl);

            using var font = new Font("Consolas", 8f);
            using var headerBrush = new SolidBrush(NexusTheme.TextSecondary);
            using var textBrush = new SolidBrush(NexusTheme.TextPrimary);

            int cellWidth = 45;
            int cellHeight = 18;
            int headerWidth = 70;
            int bytesPerRow = 16;

            // Draw header row (0-F)
            for (int i = 0; i < bytesPerRow; i++)
            {
                g.DrawString($"+{i:X}", font, headerBrush, headerWidth + i * cellWidth + 12, 2);
            }

            // Draw rows
            int numRows = (structSize + bytesPerRow - 1) / bytesPerRow;
            var fieldColors = new Dictionary<string, Color>();
            var colorPalette = new[] {
                Color.FromArgb(60, 100, 140), Color.FromArgb(100, 60, 100), Color.FromArgb(60, 100, 60),
                Color.FromArgb(140, 100, 60), Color.FromArgb(100, 100, 60), Color.FromArgb(60, 60, 100),
                Color.FromArgb(100, 80, 80), Color.FromArgb(80, 100, 100)
            };
            int colorIdx = 0;

            // Assign colors to fields
            foreach (var field in _selectedClass.Fields)
            {
                if (!fieldColors.ContainsKey(field.Name))
                {
                    fieldColors[field.Name] = colorPalette[colorIdx % colorPalette.Length];
                    colorIdx++;
                }
            }

            for (int row = 0; row < numRows; row++)
            {
                int y = 20 + row * cellHeight;
                int rowOffset = row * bytesPerRow;

                // Row header
                g.DrawString($"0x{rowOffset:X3}", font, headerBrush, 5, y);

                for (int col = 0; col < bytesPerRow; col++)
                {
                    int offset = rowOffset + col;
                    int x = headerWidth + col * cellWidth;

                    // Find field at this offset
                    var field = _selectedClass.Fields.FirstOrDefault(f =>
                        offset >= f.Offset &&
                        offset < f.Offset + GetFieldSize(f.Type, f.ArrayCount, f.ArrayBaseType));

                    if (field != null)
                    {
                        var color = fieldColors[field.Name];
                        using var brush = new SolidBrush(color);
                        g.FillRectangle(brush, x, y, cellWidth - 2, cellHeight - 2);

                        // Show field name on first byte
                        if (offset == field.Offset)
                        {
                            var shortName = field.Name.Length > 5 ? field.Name[..5] : field.Name;
                            g.DrawString(shortName, font, textBrush, x + 2, y + 1);
                        }
                    }
                    else
                    {
                        // Padding/gap
                        using var gapBrush = new SolidBrush(Color.FromArgb(40, 40, 40));
                        g.FillRectangle(gapBrush, x, y, cellWidth - 2, cellHeight - 2);
                        g.DrawString("--", font, headerBrush, x + 12, y + 1);
                    }
                }
            }

            // Draw legend
            int legendY = 20 + numRows * cellHeight + 10;
            int legendX = 10;
            g.DrawString("Legend:", font, headerBrush, legendX, legendY);
            legendX += 50;

            foreach (var kv in fieldColors.Take(8))
            {
                using var brush = new SolidBrush(kv.Value);
                g.FillRectangle(brush, legendX, legendY, 12, 12);
                g.DrawString(kv.Key, font, textBrush, legendX + 15, legendY);
                legendX += 100;
                if (legendX > 750) { legendX = 60; legendY += 16; }
            }
        };

        byteMapPanel.Controls.Add(byteMapCanvas);

        var lblInfo = new Label
        {
            Text = $"Structure size: {structSize} bytes ({_selectedClass.Fields.Count} fields)",
            Location = new Point(12, 420),
            AutoSize = true,
            Anchor = AnchorStyles.Bottom | AnchorStyles.Left,
            ForeColor = NexusTheme.TextSecondary
        };

        var btnClose = new Button { Text = "Close", Location = new Point(800, 420), Size = new Size(75, 28), Anchor = AnchorStyles.Bottom | AnchorStyles.Right };
        NexusTheme.StyleButton(btnClose);
        btnClose.Click += (s, e) => dialog.Close();

        dialog.Controls.AddRange([byteMapPanel, lblInfo, btnClose]);
        dialog.ShowDialog(this);
    }

    private void DetectVTable()
    {
        if (!Context.IsAttached || _baseAddress == 0)
        {
            UpdateStatus("Attach to process and set base address first", true);
            return;
        }

        var handle = Context.NativeProcessHandle;
        if (handle == IntPtr.Zero) return;

        // Read first 8 bytes as potential VTable pointer
        var vtablePtr = NexusEngine.ReadBytes(handle, _baseAddress, 8);
        if (vtablePtr.Length < 8)
        {
            UpdateStatus("Failed to read VTable pointer", true);
            return;
        }

        var vtableAddr = BitConverter.ToUInt64(vtablePtr, 0);
        if (vtableAddr < 0x10000 || vtableAddr > 0x7FFFFFFFFFFF)
        {
            UpdateStatus("No valid VTable pointer found at offset 0", true);
            return;
        }

        // Read VTable entries (up to 50 function pointers)
        const int maxEntries = 50;
        var vtableData = NexusEngine.ReadBytes(handle, vtableAddr, maxEntries * 8);
        if (vtableData.Length < 8)
        {
            UpdateStatus("Failed to read VTable", true);
            return;
        }

        // Find valid function pointers
        var virtualFunctions = new List<(int Index, ulong Address)>();
        for (int i = 0; i < vtableData.Length / 8; i++)
        {
            var funcAddr = BitConverter.ToUInt64(vtableData, i * 8);

            // Check if it looks like a valid code pointer
            if (funcAddr > 0x10000 && funcAddr < 0x7FFFFFFFFFFF)
            {
                // Try to read first byte to verify it's code
                var firstByte = NexusEngine.ReadBytes(handle, funcAddr, 1);
                if (firstByte.Length > 0)
                {
                    virtualFunctions.Add((i, funcAddr));
                }
                else
                {
                    break; // End of VTable
                }
            }
            else
            {
                break; // End of VTable
            }
        }

        if (virtualFunctions.Count == 0)
        {
            UpdateStatus("No virtual functions detected", true);
            return;
        }

        // Show VTable dialog
        using var dialog = new Form
        {
            Text = $"VTable at 0x{vtableAddr:X}",
            Size = new Size(600, 450),
            FormBorderStyle = FormBorderStyle.Sizable,
            StartPosition = FormStartPosition.CenterParent,
            BackColor = NexusTheme.BackgroundDark
        };

        var vtableGrid = new DataGridView
        {
            Location = new Point(12, 12),
            Size = new Size(560, 350),
            Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right,
            AllowUserToAddRows = false,
            AllowUserToDeleteRows = false,
            ReadOnly = true,
            RowHeadersVisible = false,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect,
            Font = new Font("Consolas", 9f)
        };
        NexusTheme.StyleDataGridView(vtableGrid);
        vtableGrid.Columns.AddRange([
            new DataGridViewTextBoxColumn { Name = "Index", HeaderText = "Index", Width = 60 },
            new DataGridViewTextBoxColumn { Name = "Address", HeaderText = "Address", Width = 150 },
            new DataGridViewTextBoxColumn { Name = "Name", HeaderText = "Name", Width = 200 },
            new DataGridViewTextBoxColumn { Name = "Bytes", HeaderText = "First Bytes", Width = 140 }
        ]);

        foreach (var (index, addr) in virtualFunctions)
        {
            var firstBytes = NexusEngine.ReadBytes(handle, addr, 6);
            var bytesStr = BitConverter.ToString(firstBytes).Replace("-", " ");
            vtableGrid.Rows.Add(index, $"0x{addr:X}", $"vfunc_{index}", bytesStr);
        }

        var btnAddToStruct = new Button { Text = "Add VTable to Structure", Location = new Point(12, 375), Size = new Size(150, 28), Anchor = AnchorStyles.Bottom | AnchorStyles.Left };
        NexusTheme.StylePrimaryButton(btnAddToStruct);
        btnAddToStruct.Click += (s, e) =>
        {
            if (_selectedClass == null) return;

            // Check if VTable field already exists
            if (!_selectedClass.Fields.Any(f => f.Offset == 0 && f.Name == "vtable"))
            {
                // Insert VTable pointer at offset 0
                _selectedClass.Fields.Insert(0, new StructureField
                {
                    Offset = 0,
                    Type = FieldType.Pointer,
                    Name = "vtable",
                    Comment = $"VTable @ 0x{vtableAddr:X} ({virtualFunctions.Count} functions)"
                });

                // Shift other fields if needed
                foreach (var field in _selectedClass.Fields.Skip(1).Where(f => f.Offset < 8))
                {
                    field.Offset = 8;
                }

                RefreshFieldsGrid();
                UpdateClassTree();
            }
            UpdateStatus($"VTable with {virtualFunctions.Count} functions added to structure");
        };

        var btnClose = new Button { Text = "Close", Location = new Point(497, 375), Size = new Size(75, 28), Anchor = AnchorStyles.Bottom | AnchorStyles.Right };
        NexusTheme.StyleButton(btnClose);
        btnClose.Click += (s, e) => dialog.Close();

        dialog.Controls.AddRange([vtableGrid, btnAddToStruct, btnClose]);
        dialog.ShowDialog(this);
    }

    private void ParseRTTI()
    {
        if (!Context.IsAttached || _baseAddress == 0)
        {
            UpdateStatus("Attach to process and set base address first", true);
            return;
        }

        var handle = Context.NativeProcessHandle;
        if (handle == IntPtr.Zero) return;

        // MSVC x64 RTTI: vtable[-1] = RTTICompleteObjectLocator
        var vtablePtr = NexusEngine.ReadBytes(handle, _baseAddress, 8);
        if (vtablePtr.Length < 8)
        {
            UpdateStatus("Failed to read VTable pointer", true);
            return;
        }

        var vtableAddr = BitConverter.ToUInt64(vtablePtr, 0);
        if (vtableAddr < 0x10000)
        {
            UpdateStatus("Invalid VTable pointer", true);
            return;
        }

        // Read RTTI pointer at vtable[-1]
        var rttiPtrBytes = NexusEngine.ReadBytes(handle, vtableAddr - 8, 8);
        if (rttiPtrBytes.Length < 8)
        {
            UpdateStatus("Failed to read RTTI pointer", true);
            return;
        }

        var rttiAddr = BitConverter.ToUInt64(rttiPtrBytes, 0);
        if (rttiAddr < 0x10000 || rttiAddr > 0x7FFFFFFFFFFF)
        {
            UpdateStatus("No RTTI information found (non-MSVC or stripped)", true);
            return;
        }

        // Read RTTICompleteObjectLocator
        var colData = NexusEngine.ReadBytes(handle, rttiAddr, 24);
        if (colData.Length < 24)
        {
            UpdateStatus("Failed to read RTTI data", true);
            return;
        }

        // Parse COL structure (MSVC x64)
        var signature = BitConverter.ToUInt32(colData, 0);
        var offset = BitConverter.ToUInt32(colData, 4);
        var cdOffset = BitConverter.ToUInt32(colData, 8);
        var typeDescRva = BitConverter.ToUInt32(colData, 12);
        var classHierarchyRva = BitConverter.ToUInt32(colData, 16);
        var selfRva = BitConverter.ToUInt32(colData, 20);

        // Validate signature (1 for x64)
        if (signature != 1)
        {
            UpdateStatus($"RTTI signature mismatch: {signature} (expected 1 for x64)", true);
            return;
        }

        // Calculate module base from self pointer
        var moduleBase = rttiAddr - selfRva;

        // Read TypeDescriptor
        var typeDescAddr = moduleBase + typeDescRva;
        var typeDescData = NexusEngine.ReadBytes(handle, typeDescAddr, 32);
        if (typeDescData.Length < 32)
        {
            UpdateStatus("Failed to read type descriptor", true);
            return;
        }

        // Read decorated name (starts at offset 16 in TypeDescriptor)
        var nameBytes = NexusEngine.ReadBytes(handle, typeDescAddr + 16, 256);
        var nameEnd = Array.IndexOf(nameBytes, (byte)0);
        if (nameEnd < 0) nameEnd = nameBytes.Length;
        var decoratedName = System.Text.Encoding.ASCII.GetString(nameBytes, 0, nameEnd);

        // Demangle the name (basic demangling)
        var className = decoratedName;
        if (className.StartsWith(".?AV"))
        {
            className = className[4..];
            var atIdx = className.IndexOf("@@");
            if (atIdx > 0) className = className[..atIdx];
        }

        // Show results
        var msg = $"RTTI Information:\n\n" +
                  $"Class Name: {className}\n" +
                  $"Decorated: {decoratedName}\n" +
                  $"Module Base: 0x{moduleBase:X}\n" +
                  $"VTable: 0x{vtableAddr:X}\n" +
                  $"Type Descriptor: 0x{typeDescAddr:X}\n" +
                  $"Offset in class: {offset}";

        var result = MessageBox.Show(msg + "\n\nRename current structure to detected class name?",
            "RTTI Information", MessageBoxButtons.YesNo, MessageBoxIcon.Information);

        if (result == DialogResult.Yes && _selectedClass != null)
        {
            _selectedClass.Name = className;
            UpdateClassTree();
            UpdateClassCombo();
            UpdateStatus($"Structure renamed to '{className}'");
        }
    }

    private void ImportFromPDB()
    {
        using var dialog = new OpenFileDialog
        {
            Title = "Import Types from PDB",
            Filter = "PDB files (*.pdb)|*.pdb|All files (*.*)|*.*"
        };

        if (dialog.ShowDialog() != DialogResult.OK) return;

        // PDB parsing requires specialized libraries (Microsoft.DiaSymReader or similar)
        // For now, show a message about the feature
        MessageBox.Show(
            "PDB import requires Microsoft Debug Interface Access (DIA) SDK.\n\n" +
            "To use this feature:\n" +
            "1. Install Visual Studio or Windows SDK\n" +
            "2. Use dia2dump.exe to extract types:\n" +
            "   dia2dump -t yourfile.pdb > types.txt\n" +
            "3. Import the types.txt manually\n\n" +
            "Full PDB integration is planned for a future release.",
            "PDB Import", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private void ScanForStrings()
    {
        if (!Context.IsAttached || _baseAddress == 0)
        {
            UpdateStatus("Attach to process and set base address first", true);
            return;
        }

        var handle = Context.NativeProcessHandle;
        var buffer = NexusEngine.ReadBytes(handle, _baseAddress, 512);
        if (buffer.Length == 0)
        {
            UpdateStatus("Failed to read memory", true);
            return;
        }

        var foundStrings = new List<(int Offset, string Value, bool IsUnicode)>();

        // Scan for ASCII strings
        for (int i = 0; i < buffer.Length - 4; i++)
        {
            if (buffer[i] >= 0x20 && buffer[i] < 0x7F)
            {
                int len = 0;
                while (i + len < buffer.Length && buffer[i + len] >= 0x20 && buffer[i + len] < 0x7F)
                    len++;

                if (len >= 4)
                {
                    var str = System.Text.Encoding.ASCII.GetString(buffer, i, len);
                    foundStrings.Add((i, str, false));
                    i += len;
                }
            }
        }

        // Scan for Unicode strings
        for (int i = 0; i < buffer.Length - 8; i += 2)
        {
            if (buffer[i] >= 0x20 && buffer[i] < 0x7F && buffer[i + 1] == 0)
            {
                int len = 0;
                while (i + len * 2 + 1 < buffer.Length &&
                       buffer[i + len * 2] >= 0x20 && buffer[i + len * 2] < 0x7F &&
                       buffer[i + len * 2 + 1] == 0)
                    len++;

                if (len >= 4)
                {
                    var str = System.Text.Encoding.Unicode.GetString(buffer, i, len * 2);
                    if (!foundStrings.Any(s => s.Offset == i))
                        foundStrings.Add((i, str, true));
                    i += len * 2;
                }
            }
        }

        if (foundStrings.Count == 0)
        {
            UpdateStatus("No strings found in first 512 bytes", true);
            return;
        }

        // Show results
        var result = MessageBox.Show(
            $"Found {foundStrings.Count} potential strings:\n\n" +
            string.Join("\n", foundStrings.Take(10).Select(s => $"0x{s.Offset:X}: \"{(s.Value.Length > 30 ? s.Value[..30] + "..." : s.Value)}\" ({(s.IsUnicode ? "Unicode" : "ASCII")})")),
            "String Scan Results", MessageBoxButtons.OKCancel, MessageBoxIcon.Information);

        if (result == DialogResult.OK && _selectedClass != null)
        {
            foreach (var (offset, value, isUnicode) in foundStrings)
            {
                if (!_selectedClass.Fields.Any(f => f.Offset == offset))
                {
                    _selectedClass.Fields.Add(new StructureField
                    {
                        Offset = offset,
                        Type = isUnicode ? FieldType.WString : FieldType.String,
                        Name = $"str_{offset:X}",
                        Comment = value.Length > 20 ? value[..20] + "..." : value
                    });
                }
            }
            SortElementsByOffset();
            RefreshFieldsGrid();
            UpdateStatus($"Added {foundStrings.Count} string fields");
        }
    }

    private void ScanForPointers()
    {
        if (!Context.IsAttached || _baseAddress == 0)
        {
            UpdateStatus("Attach to process and set base address first", true);
            return;
        }

        var handle = Context.NativeProcessHandle;
        var buffer = NexusEngine.ReadBytes(handle, _baseAddress, 256);
        if (buffer.Length < 8)
        {
            UpdateStatus("Failed to read memory", true);
            return;
        }

        var foundPointers = new List<(int Offset, ulong Value)>();

        // Scan for valid pointers (8-byte aligned)
        for (int i = 0; i <= buffer.Length - 8; i += 8)
        {
            var ptr = BitConverter.ToUInt64(buffer, i);

            // Check if it looks like a valid user-mode pointer
            if (ptr > 0x10000 && ptr < 0x7FFFFFFFFFFF && (ptr & 0x7) == 0)
            {
                // Try to validate by reading from the address
                var testRead = NexusEngine.ReadBytes(handle, ptr, 1);
                if (testRead.Length > 0)
                {
                    foundPointers.Add((i, ptr));
                }
            }
        }

        if (foundPointers.Count == 0)
        {
            UpdateStatus("No valid pointers found in first 256 bytes", true);
            return;
        }

        var result = MessageBox.Show(
            $"Found {foundPointers.Count} potential pointers:\n\n" +
            string.Join("\n", foundPointers.Take(15).Select(p => $"0x{p.Offset:X}: 0x{p.Value:X}")),
            "Pointer Scan Results", MessageBoxButtons.OKCancel, MessageBoxIcon.Information);

        if (result == DialogResult.OK && _selectedClass != null)
        {
            foreach (var (offset, value) in foundPointers)
            {
                if (!_selectedClass.Fields.Any(f => f.Offset == offset))
                {
                    _selectedClass.Fields.Add(new StructureField
                    {
                        Offset = offset,
                        Type = FieldType.Pointer,
                        Name = $"ptr_{offset:X}",
                        Comment = $"-> 0x{value:X}"
                    });
                }
            }
            SortElementsByOffset();
            RefreshFieldsGrid();
            UpdateStatus($"Added {foundPointers.Count} pointer fields");
        }
    }

    #endregion
}
