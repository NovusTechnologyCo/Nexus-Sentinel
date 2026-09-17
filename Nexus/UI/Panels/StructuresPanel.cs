// <file>
// <summary>
// ReClass.NET-style structure editor panel for reverse engineering memory layouts.
// Allows users to define named structure classes with typed fields, view live memory
// values at a given base address, auto-analyze pointer chains, copy/paste fields,
// define custom enums, and export structure definitions as C/C++ headers.
// </summary>
// </file>

using Nexus.UI.Core;
using Nexus.UI.Interop;
using Nexus.UI.Styles;

namespace Nexus.UI.Panels;

/// <summary>
/// Structure editor panel providing ReClass.NET-style memory structure analysis.
/// <para>
/// Users can create named structure classes, add typed fields (int, float, pointer, string,
/// array, bitfield, enum, etc.), and bind them to a base address in the attached process.
/// The panel reads live memory and displays current values beside each field. Pointer fields
/// can be expanded to follow chains. Structures can be imported/exported as C headers.
/// </para>
/// </summary>
public partial class StructuresPanel : ShellPanel
{
    #region Fields

    // Structure data
    private readonly List<StructureClass> _classes = [];
    private StructureClass? _selectedClass;
    private ulong _baseAddress;

    // UI Controls
    private readonly TreeView _classTree;
    private readonly DataGridView _fieldsGrid;
    private readonly Panel _hexPreview;
    private readonly ComboBox _addressCombo;
    private readonly TextBox _addressTextBox;
    private readonly Button _addAddressBtn;
    private readonly Button _removeAddressBtn;
    private readonly Button _gotoBtn;
    private readonly Button _analyzeBtn;
    private readonly ComboBox _classCombo;
    private readonly Label _statusLabel;
    private readonly SplitContainer _mainSplit;
    private readonly System.Windows.Forms.Timer _refreshTimer;
    private readonly List<string> _savedAddresses = [];
    private readonly TextBox _searchTextBox;

    // Context menus
    private readonly ContextMenuStrip _classContextMenu;
    private readonly ContextMenuStrip _fieldContextMenu;

    // Fonts
    private readonly Font _monoFont = new("Consolas", 9f);

    // Memory buffer for preview
    private byte[] _previewBuffer = new byte[256];

    // Clipboard for copy/paste
    private StructureField? _copiedField;

    // Enum definitions (shared across all structures)
    private readonly Dictionary<string, Dictionary<long, string>> _enumDefinitions = [];

    #endregion

    #region Constructor

    public StructuresPanel()
    {
        Text = "Structures";
        BackColor = NexusTheme.BackgroundPanel;
        Padding = new Padding(0);

        // Create toolbar
        var toolbar = new FlowLayoutPanel
        {
            Dock = DockStyle.Top,
            Height = NexusTheme.ControlHeight + NexusTheme.Space8 + NexusTheme.Space4,  // 32 + 8 + 4 = 44
            BackColor = NexusTheme.BackgroundHeader,
            Padding = new Padding(NexusTheme.Space4, NexusTheme.Space4, NexusTheme.Space4, NexusTheme.Space4),
            WrapContents = false  // Prevent wrapping
        };

        var addrLabel = new Label
        {
            Text = "Address:",
            AutoSize = true,
            ForeColor = NexusTheme.TextPrimary,
            Margin = new Padding(0, 6, 4, 0)
        };

        // Dropdown for saved addresses
        _addressCombo = new ComboBox
        {
            Width = 180,
            Font = NexusTheme.FontMono,
            DropDownStyle = ComboBoxStyle.DropDownList  // Non-editable dropdown for saved addresses
        };
        _addressCombo.SelectedIndexChanged += AddressCombo_SelectedIndexChanged;
        NexusTheme.StyleComboBox(_addressCombo);
        _addressCombo.Margin = new Padding(0, 0, NexusTheme.Space8, 0);  // Set after styling

        // Text box for entering/editing address
        _addressTextBox = new TextBox
        {
            Width = 160,
            Font = NexusTheme.FontMono,
            Text = "0"
        };
        _addressTextBox.KeyDown += AddressTextBox_KeyDown;
        NexusTheme.StyleTextBox(_addressTextBox);
        _addressTextBox.Margin = new Padding(0, 0, NexusTheme.Space4, 0);  // Set after styling

        _addAddressBtn = new Button { Text = "+" };
        NexusTheme.StyleButtonSmall(_addAddressBtn);
        _addAddressBtn.Margin = new Padding(0, 0, NexusTheme.Space4, 0);
        _addAddressBtn.Click += AddAddressBtn_Click;
        new ToolTip().SetToolTip(_addAddressBtn, "Add address to saved list");

        _removeAddressBtn = new Button { Text = "-" };
        NexusTheme.StyleButtonSmall(_removeAddressBtn);
        _removeAddressBtn.Margin = new Padding(0, 0, NexusTheme.Space4, 0);
        _removeAddressBtn.Click += RemoveAddressBtn_Click;
        new ToolTip().SetToolTip(_removeAddressBtn, "Remove address from saved list");

        _gotoBtn = new Button { Text = "Go" };
        NexusTheme.StylePrimaryButton(_gotoBtn);
        _gotoBtn.Click += GotoBtn_Click;

        var separator1 = new Label { Text = "|", AutoSize = true, ForeColor = NexusTheme.TextSecondary, Margin = new Padding(8, 6, 8, 0) };

        _analyzeBtn = new Button { Text = "Analyze" };
        NexusTheme.StylePrimaryButton(_analyzeBtn);
        _analyzeBtn.Width = 100; // Ensure full text is visible with bold font
        _analyzeBtn.Click += AnalyzeBtn_Click;
        new ToolTip().SetToolTip(_analyzeBtn, "Auto-dissect structure at current address");

        var separator2 = new Label { Text = "|", AutoSize = true, ForeColor = NexusTheme.TextSecondary, Margin = new Padding(8, 6, 8, 0) };

        var classLabel = new Label
        {
            Text = "Class:",
            AutoSize = true,
            ForeColor = NexusTheme.TextPrimary,
            Margin = new Padding(0, 6, 4, 0)
        };

        _classCombo = new ComboBox
        {
            DropDownStyle = ComboBoxStyle.DropDownList,
            Width = 150
        };
        _classCombo.SelectedIndexChanged += ClassCombo_SelectedIndexChanged;
        NexusTheme.StyleComboBox(_classCombo);
        _classCombo.Margin = new Padding(0, 0, NexusTheme.Space4, 0);  // Set after styling

        var btnAddClass = new Button { Text = "+" };
        NexusTheme.StyleButtonSmall(btnAddClass);
        btnAddClass.Click += (s, e) => AddNewClass();
        new ToolTip().SetToolTip(btnAddClass, "Add new class");

        var separator3 = new Label { Text = "|", AutoSize = true, ForeColor = NexusTheme.TextSecondary, Margin = new Padding(8, 6, 8, 0) };

        var searchLabel = new Label { Text = "Search:", AutoSize = true, ForeColor = NexusTheme.TextPrimary, Margin = new Padding(0, 6, 4, 0) };
        _searchTextBox = new TextBox { Width = 120, Font = NexusTheme.FontMono };
        _searchTextBox.TextChanged += SearchTextBox_TextChanged;
        _searchTextBox.KeyDown += (s, e) => { if (e.KeyCode == Keys.Escape) { _searchTextBox.Clear(); e.Handled = true; } };
        NexusTheme.StyleTextBox(_searchTextBox);
        new ToolTip().SetToolTip(_searchTextBox, "Search fields by name (Escape to clear)");

        toolbar.Controls.AddRange([addrLabel, _addressCombo, _addressTextBox, _addAddressBtn, _removeAddressBtn, _gotoBtn, separator1, _analyzeBtn, separator2, classLabel, _classCombo, btnAddClass, separator3, searchLabel, _searchTextBox]);

        // Create main split container
        _mainSplit = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Orientation = Orientation.Vertical,
            BackColor = NexusTheme.BackgroundPanel,
            Panel1MinSize = 50,
            Panel2MinSize = 100
        };

        // Left panel - Class tree
        _classTree = new TreeView
        {
            Dock = DockStyle.Fill,
            BackColor = NexusTheme.BackgroundControl,
            ForeColor = NexusTheme.TextPrimary,
            BorderStyle = BorderStyle.None,
            Font = _monoFont,
            ShowLines = true,
            ShowPlusMinus = true,
            ShowRootLines = true
        };
        _classTree.AfterSelect += ClassTree_AfterSelect;
        _mainSplit.Panel1.Controls.Add(_classTree);

        // Right panel - split between fields grid and hex preview
        var rightSplit = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Orientation = Orientation.Horizontal,
            Panel1MinSize = 50,
            Panel2MinSize = 50
        };

        // Fields grid
        _fieldsGrid = new DataGridView
        {
            Dock = DockStyle.Fill,
            BackgroundColor = NexusTheme.BackgroundControl,
            ForeColor = NexusTheme.TextPrimary,
            BorderStyle = BorderStyle.None,
            AllowUserToAddRows = false,
            AllowUserToDeleteRows = false,
            RowHeadersVisible = false,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect,
            AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
            Font = _monoFont
        };
        NexusTheme.StyleDataGridView(_fieldsGrid);
        SetupFieldsGrid();
        _fieldsGrid.CellValueChanged += FieldsGrid_CellValueChanged;
        _fieldsGrid.CurrentCellDirtyStateChanged += FieldsGrid_CurrentCellDirtyStateChanged;
        rightSplit.Panel1.Controls.Add(_fieldsGrid);

        // Hex preview panel (double-buffered to prevent flicker)
        _hexPreview = new DoubleBufferedPanel
        {
            Dock = DockStyle.Fill,
            BackColor = NexusTheme.BackgroundControl
        };
        _hexPreview.Paint += HexPreview_Paint;
        rightSplit.Panel2.Controls.Add(_hexPreview);

        _mainSplit.Panel2.Controls.Add(rightSplit);

        // Status label
        _statusLabel = new Label
        {
            Dock = DockStyle.Bottom,
            Height = 24,
            BackColor = NexusTheme.BackgroundHeader,
            ForeColor = NexusTheme.TextSecondary,
            TextAlign = ContentAlignment.MiddleLeft,
            Padding = new Padding(4, 0, 0, 0)
        };

        // Context menus
        _classContextMenu = CreateClassContextMenu();
        _fieldContextMenu = CreateFieldContextMenu();
        _classTree.ContextMenuStrip = _classContextMenu;
        _fieldsGrid.ContextMenuStrip = _fieldContextMenu;

        // Refresh timer
        _refreshTimer = new System.Windows.Forms.Timer { Interval = 500 };
        _refreshTimer.Tick += RefreshTimer_Tick;

        // Add controls
        Controls.Add(_mainSplit);
        Controls.Add(_statusLabel);
        Controls.Add(toolbar);

        // Note: ShellPanel base class already subscribes to ProcessAttached/ProcessDetached

        // Create default class
        AddNewClass("NewClass");

        // Set splitter distance once after first resize
        bool splitterSet = false;
        _mainSplit.SizeChanged += (s, e) =>
        {
            if (!splitterSet && _mainSplit.Width > 400)
            {
                splitterSet = true;
                try
                {
                    _mainSplit.SplitterDistance = 400;  // Align with end of class tree content
                }
                catch { /* ignore */ }
            }
        };
    }

    #endregion

    #region Setup

    private void SetupFieldsGrid()
    {
        _fieldsGrid.Columns.Clear();
        _fieldsGrid.Columns.AddRange([
            new DataGridViewTextBoxColumn { Name = "Offset", HeaderText = "Offset", Width = 70, ReadOnly = true },
            new DataGridViewComboBoxColumn
            {
                Name = "Type",
                HeaderText = "Type",
                Width = 90,
                Items = { "Int8", "UInt8", "Int16", "UInt16", "Int32", "UInt32", "Int64", "UInt64",
                          "Float", "Double", "Bool", "Pointer", "String", "WString", "Bytes",
                          "Struct", "Padding", "Array", "Bitfield", "Enum", "GUID", "Timestamp", "Union" }
            },
            new DataGridViewTextBoxColumn { Name = "Name", HeaderText = "Name", Width = 120 },
            new DataGridViewTextBoxColumn { Name = "Value", HeaderText = "Value", Width = 180 },  // Editable for write-back
            new DataGridViewTextBoxColumn { Name = "Comment", HeaderText = "Comment", Width = 120 }
        ]);
    }

    private ContextMenuStrip CreateClassContextMenu()
    {
        var menu = new ContextMenuStrip();
        menu.Items.AddRange([
            new ToolStripMenuItem("Add Class", null, (s, e) => AddNewClass()),
            new ToolStripMenuItem("Rename Class", null, (s, e) => RenameSelectedClass()),
            new ToolStripMenuItem("Clone Class", null, (s, e) => CloneSelectedClass()),
            new ToolStripMenuItem("Delete Class", null, (s, e) => DeleteSelectedClass()),
            new ToolStripSeparator(),
            new ToolStripMenuItem("Fill Gaps", null, (s, e) => FillStructureGaps()),
            new ToolStripMenuItem("Sort by Offset", null, (s, e) => SortElementsByOffset()),
            new ToolStripSeparator(),
            new ToolStripMenuItem("Generate C Struct", null, (s, e) => GenerateCStruct()),
            new ToolStripMenuItem("Generate C# Class", null, (s, e) => GenerateCSharpClass())
        ]);
        return menu;
    }

    private ContextMenuStrip CreateFieldContextMenu()
    {
        var menu = new ContextMenuStrip();
        menu.Items.AddRange([
            new ToolStripMenuItem("Add Field", null, (s, e) => AddField()),
            new ToolStripMenuItem("Insert Field Above", null, (s, e) => InsertFieldAbove()),
            new ToolStripMenuItem("Add Padding", null, (s, e) => AddPadding()),
            new ToolStripMenuItem("Delete Field", null, (s, e) => DeleteSelectedField()),
            new ToolStripSeparator(),
            new ToolStripMenuItem("Copy Field", null, (s, e) => CopySelectedField()) { ShortcutKeys = Keys.Control | Keys.C },
            new ToolStripMenuItem("Paste Field", null, (s, e) => PasteField()) { ShortcutKeys = Keys.Control | Keys.V },
            new ToolStripSeparator(),
            new ToolStripMenuItem("Change Type", null)
            {
                DropDownItems =
                {
                    new ToolStripMenuItem("Int8", null, (s, e) => ChangeFieldType("Int8")),
                    new ToolStripMenuItem("UInt8", null, (s, e) => ChangeFieldType("UInt8")),
                    new ToolStripMenuItem("Int16", null, (s, e) => ChangeFieldType("Int16")),
                    new ToolStripMenuItem("UInt16", null, (s, e) => ChangeFieldType("UInt16")),
                    new ToolStripMenuItem("Int32", null, (s, e) => ChangeFieldType("Int32")),
                    new ToolStripMenuItem("UInt32", null, (s, e) => ChangeFieldType("UInt32")),
                    new ToolStripMenuItem("Int64", null, (s, e) => ChangeFieldType("Int64")),
                    new ToolStripMenuItem("UInt64", null, (s, e) => ChangeFieldType("UInt64")),
                    new ToolStripMenuItem("Float", null, (s, e) => ChangeFieldType("Float")),
                    new ToolStripMenuItem("Double", null, (s, e) => ChangeFieldType("Double")),
                    new ToolStripMenuItem("Pointer", null, (s, e) => ChangeFieldType("Pointer")),
                    new ToolStripMenuItem("String", null, (s, e) => ChangeFieldType("String")),
                    new ToolStripSeparator(),
                    new ToolStripMenuItem("Array...", null, (s, e) => ChangeFieldToArray()),
                    new ToolStripMenuItem("Bitfield...", null, (s, e) => ChangeFieldToBitfield()),
                    new ToolStripMenuItem("Enum...", null, (s, e) => ChangeFieldToEnum()),
                    new ToolStripMenuItem("Struct...", null, (s, e) => ChangeFieldToStruct()),
                    new ToolStripSeparator(),
                    new ToolStripMenuItem("GUID", null, (s, e) => ChangeFieldType("GUID")),
                    new ToolStripMenuItem("Timestamp", null, (s, e) => ChangeFieldType("Timestamp")),
                    new ToolStripMenuItem("Padding", null, (s, e) => ChangeFieldType("Padding")),
                }
            },
            new ToolStripSeparator(),
            new ToolStripMenuItem("Follow Pointer", null, (s, e) => FollowPointer()),
            new ToolStripMenuItem("Set Pointer Chain...", null, (s, e) => SetPointerChain()),
            new ToolStripMenuItem("Expand Struct", null, (s, e) => ExpandNestedStruct()),
            new ToolStripSeparator(),
            new ToolStripMenuItem("Validate Alignment", null, (s, e) => ValidateFieldAlignment()),
            new ToolStripMenuItem("Rescan Pointers...", null, (s, e) => ShowRescanPointers())
        ]);
        return menu;
    }

    private void ShowRescanPointers()
    {
        using var form = new Forms.StructPointerRescanForm();
        if (form.ShowDialog() == DialogResult.OK)
        {
            // Apply rescan with form settings
            if (_selectedClass == null)
            {
                MessageBox.Show("No class selected.", "Rescan Pointers",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var pointerFields = _selectedClass.Fields
                .Where(f => f.Type == FieldType.Pointer || f.Type == FieldType.UInt64)
                .ToList();

            if (pointerFields.Count == 0)
            {
                MessageBox.Show("No pointer fields found in the selected class.", "Rescan Pointers",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            int validCount = 0;
            foreach (var field in pointerFields)
            {
                ulong fieldAddr = _baseAddress + (ulong)field.Offset;

                // Read pointer value from memory
                byte[] buffer = new byte[8];
                unsafe
                {
                    fixed (byte* ptr = buffer)
                    {
                        var result = NexusEngine.Nexus_ReadMemory(
                            ProcessContext.Current.NativeProcessHandle,
                            fieldAddr, (IntPtr)ptr, 8, out _);
                        if (result != NexusResult.Success)
                            continue;
                    }
                }

                ulong pointerValue = BitConverter.ToUInt64(buffer, 0);

                // Apply pointer range filter
                if (form.PointerInRange)
                {
                    if (pointerValue < form.PointerRangeStart || pointerValue > form.PointerRangeStop)
                        continue;
                }

                validCount++;
            }

            MessageBox.Show($"Rescan complete.\n" +
                $"Found {validCount} of {pointerFields.Count} pointer fields matching criteria.",
                "Rescan Pointers", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
    }

    #endregion

    #region Panel Overrides

    public override string PanelId => "Structures";
    public override string PanelDisplayName => "Structures";

    public override ToolStripMenuItem[]? GetPanelMenus()
    {
        var fileMenu = new ToolStripMenuItem("&File");
        fileMenu.DropDownItems.AddRange([
            new ToolStripMenuItem("&Save structure...", null, (s, e) => SaveStructure()) { ShortcutKeys = Keys.Control | Keys.S },
            new ToolStripMenuItem("&Load structure...", null, (s, e) => LoadStructure()) { ShortcutKeys = Keys.Control | Keys.O },
            new ToolStripSeparator(),
            new ToolStripMenuItem("&Import CE structure...", null, (s, e) => ImportCEStructure()),
            new ToolStripMenuItem("&Export CE structure...", null, (s, e) => ExportCEStructure()),
            new ToolStripSeparator(),
            new ToolStripMenuItem("Save to &Library...", null, (s, e) => SaveToLibrary()),
            new ToolStripMenuItem("Load from Li&brary...", null, (s, e) => LoadFromLibrary()),
            new ToolStripMenuItem("&Manage Library...", null, (s, e) => ManageLibrary())
        ]);

        var classMenu = new ToolStripMenuItem("&Class");
        classMenu.DropDownItems.AddRange([
            new ToolStripMenuItem("&New class", null, (s, e) => AddNewClass()) { ShortcutKeys = Keys.Control | Keys.N },
            new ToolStripMenuItem("&Rename class", null, (s, e) => RenameSelectedClass()) { ShortcutKeys = Keys.F2 },
            new ToolStripMenuItem("&Clone class", null, (s, e) => CloneSelectedClass()),
            new ToolStripMenuItem("&Delete class", null, (s, e) => DeleteSelectedClass()) { ShortcutKeys = Keys.Delete },
            new ToolStripSeparator(),
            new ToolStripMenuItem("&Fill gaps", null, (s, e) => FillStructureGaps()),
            new ToolStripMenuItem("&Sort by offset", null, (s, e) => SortElementsByOffset()),
            new ToolStripSeparator(),
            new ToolStripMenuItem("Generate &C struct", null, (s, e) => GenerateCStruct()),
            new ToolStripMenuItem("Generate C# &class", null, (s, e) => GenerateCSharpClass())
        ]);

        var fieldMenu = new ToolStripMenuItem("&Field");
        fieldMenu.DropDownItems.AddRange([
            new ToolStripMenuItem("&Add field", null, (s, e) => AddField()) { ShortcutKeys = Keys.Insert },
            new ToolStripMenuItem("&Insert above", null, (s, e) => InsertFieldAbove()),
            new ToolStripMenuItem("&Delete field", null, (s, e) => DeleteSelectedField()),
            new ToolStripSeparator(),
            new ToolStripMenuItem("&Follow pointer", null, (s, e) => FollowPointer()),
            new ToolStripSeparator(),
            new ToolStripMenuItem("Set type: Int32", null, (s, e) => ChangeFieldType("Int32")),
            new ToolStripMenuItem("Set type: UInt32", null, (s, e) => ChangeFieldType("UInt32")),
            new ToolStripMenuItem("Set type: Pointer", null, (s, e) => ChangeFieldType("Pointer")),
            new ToolStripMenuItem("Set type: Float", null, (s, e) => ChangeFieldType("Float"))
        ]);

        var analysisMenu = new ToolStripMenuItem("&Analysis");
        analysisMenu.DropDownItems.AddRange([
            new ToolStripMenuItem("&Compare structures...", null, (s, e) => ShowStructureDiff()),
            new ToolStripMenuItem("&Visual byte-map...", null, (s, e) => ShowByteMapView()),
            new ToolStripSeparator(),
            new ToolStripMenuItem("Detect &VTable...", null, (s, e) => DetectVTable()),
            new ToolStripMenuItem("Parse &RTTI...", null, (s, e) => ParseRTTI()),
            new ToolStripSeparator(),
            new ToolStripMenuItem("Import from &PDB...", null, (s, e) => ImportFromPDB()),
            new ToolStripMenuItem("&Scan for strings...", null, (s, e) => ScanForStrings()),
            new ToolStripMenuItem("Scan for &pointers...", null, (s, e) => ScanForPointers())
        ]);

        return [fileMenu, classMenu, fieldMenu, analysisMenu];
    }

    #endregion

    // Event handlers, rendering, editing, IO, and analysis methods are in partial class files:
    // - StructuresPanel.Events.cs
    // - StructuresPanel.Editing.cs
    // - StructuresPanel.IO.cs
    // - StructuresPanel.Rendering.cs

    #region Helpers

    private void UpdateStatus(string message, bool isError = false)
    {
        _statusLabel.Text = message;
        _statusLabel.ForeColor = isError ? NexusTheme.Error : NexusTheme.TextSecondary;
    }

    #endregion
}

#region Data Models

/// <summary>
/// Represents a structure class definition.
/// </summary>
public class StructureClass
{
    public string Name { get; set; } = "NewClass";
    public List<StructureField> Fields { get; } = [];
}

/// <summary>
/// Represents a field within a structure.
/// </summary>
public class StructureField
{
    public int Offset { get; set; }
    public FieldType Type { get; set; } = FieldType.UInt64;
    public string Name { get; set; } = "field";
    public string? Comment { get; set; }
    public string? CachedValue { get; set; }
    public uint ElementId { get; set; }  // Engine element ID for typed reads
    public string? NestedStructName { get; set; }  // For Struct type - name of nested structure
    public int ArrayCount { get; set; } = 1;  // For array/padding support
    public bool IsExpanded { get; set; }  // For nested struct expansion in UI

    // Array support
    public FieldType ArrayBaseType { get; set; } = FieldType.UInt8;  // Base type for Array

    // Bitfield support
    public int BitOffset { get; set; }  // Bit offset within the byte (0-7)
    public int BitSize { get; set; } = 1;  // Number of bits (1-32)

    // Enum support
    public Dictionary<long, string>? EnumValues { get; set; }  // Value -> Name mapping
    public string? EnumName { get; set; }  // Name of the enum type

    // Union support
    public List<StructureField>? UnionMembers { get; set; }  // Overlapping fields in union

    // Pointer chain support
    public List<long>? PointerOffsets { get; set; }  // For multi-level pointer chains
    public ulong? ResolvedAddress { get; set; }  // Cached resolved address for pointer chains
}

/// <summary>
/// Field data types.
/// </summary>
public enum FieldType
{
    Int8,
    UInt8,
    Int16,
    UInt16,
    Int32,
    UInt32,
    Int64,
    UInt64,
    Float,
    Double,
    Bool,
    Pointer,
    String,
    WString,
    Bytes,
    Struct,    // Nested structure
    Padding,   // Gap/padding bytes
    Array,     // Dynamic array of base type
    Bitfield,  // Bit field within integer
    Enum,      // Enumerated value
    GUID,      // 16-byte GUID
    Timestamp, // Unix timestamp (displayed as datetime)
    Union      // Union of overlapping fields
}

#endregion
