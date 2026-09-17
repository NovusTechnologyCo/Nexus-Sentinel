// <file>
// <summary>
// Data structure dissector for analyzing memory structures at a given address.
// </summary>
// </file>
using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using System.Text;
using Nexus.UI.Styles;


namespace Nexus.UI.Forms;

public partial class DissectDataForm : Form
{
    private readonly IntPtr _processHandle;
    private ulong _baseAddress;
    private readonly bool _is64Bit;
    private readonly List<StructureField> _fields = [];

    public class StructureField
    {
        public uint Offset { get; set; }
        public string Name { get; set; } = "";
        public FieldType Type { get; set; }
        public int ArraySize { get; set; } = 1;
        public string Value { get; set; } = "";
        public string Comment { get; set; } = "";
    }

    public enum FieldType
    {
        Byte,
        Int16,
        Int32,
        Int64,
        UInt16,
        UInt32,
        UInt64,
        Float,
        Double,
        Pointer,
        String,
        WideString,
        ByteArray,
        Custom
    }

    public DissectDataForm(IntPtr processHandle, ulong baseAddress, bool is64Bit = true)
    {
        _processHandle = processHandle;
        _baseAddress = baseAddress;
        _is64Bit = is64Bit;

        InitializeComponent();
        NexusTheme.StyleForm(this);

        // Set column widths after styling
        lvFields.Columns[0].Width = 80;   // Offset
        lvFields.Columns[1].Width = 140;  // Name
        lvFields.Columns[2].Width = 100;  // Type
        lvFields.Columns[3].Width = 200;  // Value
        lvFields.Columns[4].Width = 250;  // Comment

        txtAddress.Text = baseAddress.ToString("X");
        RefreshStructure();
    }

    private void InitializeComponent()
    {
        Text = "Dissect Data Structure";
        Size = new Size(805, 605);
        StartPosition = FormStartPosition.CenterScreen;
        Padding = new Padding(NexusTheme.Space16, NexusTheme.Space8, NexusTheme.Space16, NexusTheme.Space8);

        // Top panel
        var pnlTop = new Panel
        {
            Dock = DockStyle.Top,
            Height = NexusTheme.ControlHeight + NexusTheme.Space16
        };

        var lblAddress = new Label
        {
            Text = "Base Address:",
            Location = new Point(0, 10),
            AutoSize = true
        };

        txtAddress = new TextBox
        {
            Location = new Point(125, 6),
            Width = 150
        };

        var btnGo = new Button
        {
            Text = "Go",
            Location = new Point(285, 4),
            Size = new Size(60, NexusTheme.ControlHeight)
        };
        btnGo.Click += BtnGo_Click;

        var btnAutoAnalyze = new Button
        {
            Text = "Auto",
            Location = new Point(355, 4),
            Size = new Size(80, NexusTheme.ControlHeight)
        };
        btnAutoAnalyze.Click += BtnAutoAnalyze_Click;

        pnlTop.Controls.Add(lblAddress);
        pnlTop.Controls.Add(txtAddress);
        pnlTop.Controls.Add(btnGo);
        pnlTop.Controls.Add(btnAutoAnalyze);

        // ListView
        lvFields = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = true,
            Font = new Font("Consolas", 9F)
        };

        lvFields.Columns.Add("Offset", 70);
        lvFields.Columns.Add("Name", 150);
        lvFields.Columns.Add("Type", 100);
        lvFields.Columns.Add("Value", 200);
        lvFields.Columns.Add("Comment", 250);

        // Context menu
        var ctxMenu = new ContextMenuStrip();
        ctxAddField = new ToolStripMenuItem("Add field...");
        ctxAddField.Click += CtxAddField_Click;

        ctxEditField = new ToolStripMenuItem("Edit field...");
        ctxEditField.Click += CtxEditField_Click;

        ctxRemoveField = new ToolStripMenuItem("Remove field");
        ctxRemoveField.Click += CtxRemoveField_Click;

        var ctxSep1 = new ToolStripSeparator();

        ctxGuessType = new ToolStripMenuItem("Guess type at offset");
        ctxGuessType.Click += CtxGuessType_Click;

        ctxFollowPointer = new ToolStripMenuItem("Follow pointer");
        ctxFollowPointer.Click += CtxFollowPointer_Click;

        var ctxSep2 = new ToolStripSeparator();

        ctxCopyValue = new ToolStripMenuItem("Copy value");
        ctxCopyValue.Click += CtxCopyValue_Click;

        ctxCopyStruct = new ToolStripMenuItem("Copy structure definition");
        ctxCopyStruct.Click += CtxCopyStruct_Click;

        ctxMenu.Items.AddRange([
            ctxAddField, ctxEditField, ctxRemoveField, ctxSep1,
            ctxGuessType, ctxFollowPointer, ctxSep2,
            ctxCopyValue, ctxCopyStruct
        ]);
        lvFields.ContextMenuStrip = ctxMenu;
        lvFields.DoubleClick += LvFields_DoubleClick;

        // Bottom panel
        var pnlBottom = new Panel
        {
            Dock = DockStyle.Bottom,
            Height = NexusTheme.ControlHeight + NexusTheme.Space16
        };

        btnRefresh = new Button
        {
            Text = "Refresh",
            Location = new Point(0, NexusTheme.Space8),
            Size = new Size(80, NexusTheme.ControlHeight)
        };
        btnRefresh.Click += BtnRefresh_Click;

        btnSave = new Button
        {
            Text = "Save",
            Location = new Point(90, NexusTheme.Space8),
            Size = new Size(80, NexusTheme.ControlHeight)
        };
        btnSave.Click += BtnSave_Click;

        btnLoad = new Button
        {
            Text = "Load",
            Location = new Point(180, NexusTheme.Space8),
            Size = new Size(80, NexusTheme.ControlHeight)
        };
        btnLoad.Click += BtnLoad_Click;

        btnClose = new Button
        {
            Text = "Close",
            Anchor = AnchorStyles.Top | AnchorStyles.Right,
            Size = new Size(80, NexusTheme.ControlHeight),
            DialogResult = DialogResult.Cancel
        };
        btnClose.Click += (s, e) => Close();

        pnlBottom.Controls.Add(btnRefresh);
        pnlBottom.Controls.Add(btnSave);
        pnlBottom.Controls.Add(btnLoad);
        pnlBottom.Controls.Add(btnClose);

        // Position close button after adding to panel (needs panel width)
        pnlBottom.Layout += (s, e) => btnClose.Location = new Point(pnlBottom.ClientSize.Width - btnClose.Width, NexusTheme.Space8);

        Controls.Add(lvFields);
        Controls.Add(pnlTop);
        Controls.Add(pnlBottom);
        CancelButton = btnClose;
    }

    private void BtnGo_Click(object? sender, EventArgs e)
    {
        if (!ulong.TryParse(txtAddress.Text, System.Globalization.NumberStyles.HexNumber, null, out ulong addr))
        {
            MessageBox.Show("Invalid address format.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }
        _baseAddress = addr;
        RefreshStructure();
    }

    private void BtnRefresh_Click(object? sender, EventArgs e)
    {
        RefreshStructure();
    }

    private void RefreshStructure()
    {
        // Read values for all fields
        foreach (var field in _fields)
        {
            field.Value = ReadFieldValue(field);
        }
        UpdateListView();
    }

    private string ReadFieldValue(StructureField field)
    {
        ulong address = _baseAddress + field.Offset;
        int size = GetFieldSize(field.Type) * field.ArraySize;
        byte[] buffer = new byte[size];

        var result = NexusEngine.Nexus_ReadProcessMemory(_processHandle, address, buffer, (nuint)size, out nuint bytesRead);
        if (result != NexusResult.OK || bytesRead == 0)
            return "<read error>";

        return FormatFieldValue(buffer, field);
    }

    private static int GetFieldSize(FieldType type)
    {
        return type switch
        {
            FieldType.Byte => 1,
            FieldType.Int16 or FieldType.UInt16 => 2,
            FieldType.Int32 or FieldType.UInt32 or FieldType.Float => 4,
            FieldType.Int64 or FieldType.UInt64 or FieldType.Double or FieldType.Pointer => 8,
            FieldType.String or FieldType.WideString or FieldType.ByteArray => 64, // Default read size
            _ => 4
        };
    }

    private string FormatFieldValue(byte[] data, StructureField field)
    {
        try
        {
            return field.Type switch
            {
                FieldType.Byte => data[0].ToString(),
                FieldType.Int16 => BitConverter.ToInt16(data, 0).ToString(),
                FieldType.UInt16 => BitConverter.ToUInt16(data, 0).ToString(),
                FieldType.Int32 => BitConverter.ToInt32(data, 0).ToString(),
                FieldType.UInt32 => BitConverter.ToUInt32(data, 0).ToString(),
                FieldType.Int64 => BitConverter.ToInt64(data, 0).ToString(),
                FieldType.UInt64 => BitConverter.ToUInt64(data, 0).ToString(),
                FieldType.Float => BitConverter.ToSingle(data, 0).ToString("G6"),
                FieldType.Double => BitConverter.ToDouble(data, 0).ToString("G6"),
                FieldType.Pointer => $"0x{(_is64Bit ? BitConverter.ToUInt64(data, 0) : BitConverter.ToUInt32(data, 0)):X}",
                FieldType.String => Encoding.ASCII.GetString(data).TrimEnd('\0').Split('\0')[0],
                FieldType.WideString => Encoding.Unicode.GetString(data).TrimEnd('\0').Split('\0')[0],
                FieldType.ByteArray => BitConverter.ToString(data.Take(Math.Min(16, data.Length)).ToArray()),
                _ => BitConverter.ToString(data.Take(8).ToArray())
            };
        }
        catch
        {
            return "<format error>";
        }
    }

    private void UpdateListView()
    {
        lvFields.BeginUpdate();
        lvFields.Items.Clear();

        foreach (var field in _fields.OrderBy(f => f.Offset))
        {
            var item = new ListViewItem($"+{field.Offset:X}");
            item.SubItems.Add(field.Name);
            item.SubItems.Add(field.Type.ToString());
            item.SubItems.Add(field.Value);
            item.SubItems.Add(field.Comment);
            item.Tag = field;
            lvFields.Items.Add(item);
        }

        lvFields.EndUpdate();
    }

    private void BtnAutoAnalyze_Click(object? sender, EventArgs e)
    {
        // Auto-analyze the structure by reading memory and guessing types
        _fields.Clear();

        int structSize = 256; // Analyze first 256 bytes
        byte[] buffer = new byte[structSize];
        var result = NexusEngine.Nexus_ReadProcessMemory(_processHandle, _baseAddress, buffer, (nuint)structSize, out nuint bytesRead);

        if (result != NexusResult.OK)
        {
            MessageBox.Show("Failed to read memory.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        // Simple heuristic analysis
        for (uint offset = 0; offset < bytesRead; offset += 8)
        {
            if (offset + 8 > bytesRead) break;

            ulong value = BitConverter.ToUInt64(buffer, (int)offset);

            // Try to guess what this might be
            var field = new StructureField
            {
                Offset = offset,
                Name = $"field_{offset:X2}"
            };

            // Check if it looks like a pointer (high bits set for kernel/user space)
            if (_is64Bit && value > 0x10000 && value < 0x00007FFF_FFFFFFFF)
            {
                field.Type = FieldType.Pointer;
                field.Comment = "Possible pointer";
            }
            else if (value == 0)
            {
                field.Type = FieldType.UInt64;
                field.Comment = "Zero/null";
            }
            else if (value <= 0xFFFFFFFF)
            {
                // Could be 32-bit value or two 32-bit values
                uint low = (uint)(value & 0xFFFFFFFF);
                float asFloat = BitConverter.ToSingle(buffer, (int)offset);

                if (asFloat > 0.0001f && asFloat < 100000f && !float.IsNaN(asFloat) && !float.IsInfinity(asFloat))
                {
                    field.Type = FieldType.Float;
                    field.Comment = "Possible float";
                    offset -= 4; // Back up since we only consumed 4 bytes
                }
                else if (low < 10000000)
                {
                    field.Type = FieldType.Int32;
                    field.Comment = "Possible integer";
                    offset -= 4;
                }
                else
                {
                    field.Type = FieldType.UInt64;
                }
            }
            else
            {
                field.Type = FieldType.UInt64;
            }

            _fields.Add(field);
        }

        RefreshStructure();
    }

    private void CtxAddField_Click(object? sender, EventArgs e)
    {
        using var dialog = new FieldEditForm(null, _fields.Count > 0 ? _fields.Max(f => f.Offset) + 8 : 0);
        if (dialog.ShowDialog(this) != DialogResult.OK) return;

        _fields.Add(dialog.Field);
        RefreshStructure();
    }

    private void CtxEditField_Click(object? sender, EventArgs e)
    {
        if (lvFields.SelectedItems.Count == 0) return;
        var field = lvFields.SelectedItems[0].Tag as StructureField;
        if (field == null) return;

        using var dialog = new FieldEditForm(field, field.Offset);
        if (dialog.ShowDialog(this) != DialogResult.OK) return;

        RefreshStructure();
    }

    private void CtxRemoveField_Click(object? sender, EventArgs e)
    {
        if (lvFields.SelectedItems.Count == 0) return;
        var field = lvFields.SelectedItems[0].Tag as StructureField;
        if (field == null) return;

        _fields.Remove(field);
        RefreshStructure();
    }

    private void CtxGuessType_Click(object? sender, EventArgs e)
    {
        if (lvFields.SelectedItems.Count == 0) return;
        var field = lvFields.SelectedItems[0].Tag as StructureField;
        if (field == null) return;

        // Read the bytes and try different interpretations
        ulong address = _baseAddress + field.Offset;
        byte[] buffer = new byte[8];
        var result = NexusEngine.Nexus_ReadProcessMemory(_processHandle, address, buffer, 8, out _);
        if (result != NexusResult.OK) return;

        var sb = new StringBuilder();
        sb.AppendLine($"Value at offset +{field.Offset:X}:");
        sb.AppendLine();
        sb.AppendLine($"As Byte:     {buffer[0]}");
        sb.AppendLine($"As Int16:    {BitConverter.ToInt16(buffer, 0)}");
        sb.AppendLine($"As UInt16:   {BitConverter.ToUInt16(buffer, 0)}");
        sb.AppendLine($"As Int32:    {BitConverter.ToInt32(buffer, 0)}");
        sb.AppendLine($"As UInt32:   {BitConverter.ToUInt32(buffer, 0)}");
        sb.AppendLine($"As Int64:    {BitConverter.ToInt64(buffer, 0)}");
        sb.AppendLine($"As Float:    {BitConverter.ToSingle(buffer, 0):G6}");
        sb.AppendLine($"As Double:   {BitConverter.ToDouble(buffer, 0):G6}");
        sb.AppendLine($"As Pointer:  0x{BitConverter.ToUInt64(buffer, 0):X}");
        sb.AppendLine($"As Bytes:    {BitConverter.ToString(buffer)}");

        MessageBox.Show(sb.ToString(), "Type Analysis", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private void CtxFollowPointer_Click(object? sender, EventArgs e)
    {
        if (lvFields.SelectedItems.Count == 0) return;
        var field = lvFields.SelectedItems[0].Tag as StructureField;
        if (field == null || field.Type != FieldType.Pointer) return;

        ulong address = _baseAddress + field.Offset;
        byte[] buffer = new byte[8];
        var result = NexusEngine.Nexus_ReadProcessMemory(_processHandle, address, buffer, (nuint)(_is64Bit ? 8 : 4), out _);
        if (result != NexusResult.OK) return;

        ulong targetAddress = _is64Bit ? BitConverter.ToUInt64(buffer, 0) : BitConverter.ToUInt32(buffer, 0);
        if (targetAddress == 0)
        {
            MessageBox.Show("Pointer is null.", "Follow Pointer", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        // Open new dissector at target address
        var dissector = new DissectDataForm(_processHandle, targetAddress, _is64Bit);
        dissector.Show();
    }

    private void CtxCopyValue_Click(object? sender, EventArgs e)
    {
        if (lvFields.SelectedItems.Count == 0) return;
        var field = lvFields.SelectedItems[0].Tag as StructureField;
        if (field != null)
            Clipboard.SetText(field.Value);
    }

    private void CtxCopyStruct_Click(object? sender, EventArgs e)
    {
        var sb = new StringBuilder();
        sb.AppendLine("struct UnknownStruct {");
        foreach (var field in _fields.OrderBy(f => f.Offset))
        {
            string typeName = field.Type switch
            {
                FieldType.Byte => "uint8_t",
                FieldType.Int16 => "int16_t",
                FieldType.UInt16 => "uint16_t",
                FieldType.Int32 => "int32_t",
                FieldType.UInt32 => "uint32_t",
                FieldType.Int64 => "int64_t",
                FieldType.UInt64 => "uint64_t",
                FieldType.Float => "float",
                FieldType.Double => "double",
                FieldType.Pointer => "void*",
                FieldType.String => "char*",
                _ => "unknown"
            };
            sb.AppendLine($"    {typeName} {field.Name}; // +0x{field.Offset:X} = {field.Value}");
        }
        sb.AppendLine("};");

        Clipboard.SetText(sb.ToString());
        MessageBox.Show("Structure definition copied to clipboard.", "Copy Structure", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private void LvFields_DoubleClick(object? sender, EventArgs e)
    {
        CtxEditField_Click(sender, e);
    }

    private void BtnSave_Click(object? sender, EventArgs e)
    {
        using var saveDialog = new SaveFileDialog
        {
            Filter = "Structure files (*.nst)|*.nst|All files (*.*)|*.*",
            DefaultExt = ".nst"
        };

        if (saveDialog.ShowDialog() != DialogResult.OK) return;

        var sb = new StringBuilder();
        sb.AppendLine($"# Nexus Structure Definition");
        sb.AppendLine($"# Base: {_baseAddress:X}");
        sb.AppendLine();

        foreach (var field in _fields.OrderBy(f => f.Offset))
        {
            sb.AppendLine($"{field.Offset:X},{field.Name},{field.Type},{field.ArraySize},{field.Comment}");
        }

        File.WriteAllText(saveDialog.FileName, sb.ToString());
    }

    private void BtnLoad_Click(object? sender, EventArgs e)
    {
        using var openDialog = new OpenFileDialog
        {
            Filter = "Structure files (*.nst)|*.nst|All files (*.*)|*.*"
        };

        if (openDialog.ShowDialog() != DialogResult.OK) return;

        _fields.Clear();
        foreach (var line in File.ReadAllLines(openDialog.FileName))
        {
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#")) continue;

            var parts = line.Split(',');
            if (parts.Length < 3) continue;

            if (!uint.TryParse(parts[0], System.Globalization.NumberStyles.HexNumber, null, out uint offset)) continue;
            if (!Enum.TryParse<FieldType>(parts[2], out var type)) continue;

            _fields.Add(new StructureField
            {
                Offset = offset,
                Name = parts[1],
                Type = type,
                ArraySize = parts.Length > 3 && int.TryParse(parts[3], out int size) ? size : 1,
                Comment = parts.Length > 4 ? parts[4] : ""
            });
        }

        RefreshStructure();
    }

    // Form controls
    private TextBox txtAddress = null!;
    private ListView lvFields = null!;
    private Button btnRefresh = null!;
    private Button btnSave = null!;
    private Button btnLoad = null!;
    private Button btnClose = null!;
    private ToolStripMenuItem ctxAddField = null!;
    private ToolStripMenuItem ctxEditField = null!;
    private ToolStripMenuItem ctxRemoveField = null!;
    private ToolStripMenuItem ctxGuessType = null!;
    private ToolStripMenuItem ctxFollowPointer = null!;
    private ToolStripMenuItem ctxCopyValue = null!;
    private ToolStripMenuItem ctxCopyStruct = null!;
}

/// <summary>
/// Dialog for editing a structure field.
/// </summary>
public class FieldEditForm : Form
{
    public DissectDataForm.StructureField Field { get; private set; }

    private TextBox txtOffset = null!;
    private TextBox txtName = null!;
    private ComboBox cboType = null!;
    private NumericUpDown nudArraySize = null!;
    private TextBox txtComment = null!;

    public FieldEditForm(DissectDataForm.StructureField? existing, uint defaultOffset)
    {
        Field = existing ?? new DissectDataForm.StructureField { Offset = defaultOffset };
        InitializeComponent();
    }

    private void InitializeComponent()
    {
        Text = Field.Name == "" ? "Add Field" : "Edit Field";
        Size = new Size(400, 250);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        StartPosition = FormStartPosition.CenterParent;

        var lblOffset = new Label { Text = "Offset:", Location = new Point(15, 20), AutoSize = true };
        txtOffset = new TextBox { Location = new Point(100, 17), Width = 100, Text = Field.Offset.ToString("X") };

        var lblName = new Label { Text = "Name:", Location = new Point(15, 50), AutoSize = true };
        txtName = new TextBox { Location = new Point(100, 47), Width = 200, Text = Field.Name };

        var lblType = new Label { Text = "Type:", Location = new Point(15, 80), AutoSize = true };
        cboType = new ComboBox { Location = new Point(100, 77), Width = 120, DropDownStyle = ComboBoxStyle.DropDownList };
        foreach (var type in Enum.GetValues<DissectDataForm.FieldType>())
            cboType.Items.Add(type);
        cboType.SelectedItem = Field.Type;

        var lblArray = new Label { Text = "Array Size:", Location = new Point(15, 110), AutoSize = true };
        nudArraySize = new NumericUpDown { Location = new Point(100, 107), Width = 80, Minimum = 1, Maximum = 1000, Value = Field.ArraySize };

        var lblComment = new Label { Text = "Comment:", Location = new Point(15, 140), AutoSize = true };
        txtComment = new TextBox { Location = new Point(100, 137), Width = 250, Text = Field.Comment };

        var btnOK = new Button { Text = "OK", Location = new Point(200, 175), Size = new Size(80, 32), DialogResult = DialogResult.OK };
        btnOK.Click += BtnOK_Click;

        var btnCancel = new Button { Text = "Cancel", Location = new Point(290, 175), Size = new Size(80, 32), DialogResult = DialogResult.Cancel };

        Controls.AddRange([lblOffset, txtOffset, lblName, txtName, lblType, cboType, lblArray, nudArraySize, lblComment, txtComment, btnOK, btnCancel]);
        AcceptButton = btnOK;
        CancelButton = btnCancel;
    }

    private void BtnOK_Click(object? sender, EventArgs e)
    {
        if (!uint.TryParse(txtOffset.Text, System.Globalization.NumberStyles.HexNumber, null, out uint offset))
        {
            MessageBox.Show("Invalid offset format.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            DialogResult = DialogResult.None;
            return;
        }

        Field.Offset = offset;
        Field.Name = txtName.Text;
        Field.Type = (DissectDataForm.FieldType)cboType.SelectedItem!;
        Field.ArraySize = (int)nudArraySize.Value;
        Field.Comment = txtComment.Text;
        DialogResult = DialogResult.OK;
        Close();
    }
}
