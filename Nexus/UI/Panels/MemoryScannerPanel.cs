// <file>
// <summary>
// Memory scanner panel providing Cheat Engine-style value scanning capabilities.
// This is the primary tool for locating values in process memory. Supports first scan,
// next scan (narrowing), undo scan, multiple value types (byte through string/array),
// multiple scan modes (exact, greater/less, changed/unchanged, unknown initial value),
// hex input, memory region filtering, and a saved address table with freeze/description.
//
// Split into partial classes for maintainability:
//   - MemoryScannerPanel.cs              - Core UI setup, fields, event handlers
//   - MemoryScannerPanel.ScanOperations.cs - Scan logic and value parsing
//   - MemoryScannerPanel.SavedAddresses.cs - Saved address list management
//   - MemoryScannerPanel.ContextMenus.cs   - Context menu construction
//   - MemoryScannerPanel.MenuActions.cs    - Menu action handlers
// </summary>
// </file>

using Nexus.UI.Core;
using Nexus.UI.Interop;
using Nexus.UI.Styles;

namespace Nexus.UI.Panels;

/// <summary>
/// Memory scanner panel for finding and tracking values in process memory.
/// <para>
/// Provides a two-pane layout: the left pane shows scan results (found addresses with
/// current values), and the right pane shows scan controls and memory region options.
/// Below the scan results is the saved address table where users can bookmark addresses,
/// add descriptions, freeze values, and change value types.
/// </para>
/// <para>
/// Scan workflow: First Scan searches the entire address space (or configured range),
/// then Next Scan narrows results based on how values changed. Undo reverts to the
/// previous scan state. Results can be added to the saved address table for monitoring.
/// </para>
/// </summary>
public partial class MemoryScannerPanel : ShellPanel
{
    // UI Controls - Found List
    private readonly ListView _foundList;
    private readonly Label _foundLabel;
    private readonly Button _addToListBtn;
    private readonly Button _clearBtn;
    private readonly ContextMenuStrip _foundListContextMenu;

    // UI Controls - Saved Addresses Table
    private readonly ListView _savedList;
    private readonly Label _savedLabel;
    private readonly List<SavedAddress> _savedAddresses = [];
    private readonly ContextMenuStrip _savedListContextMenu;

    // UI Controls - Scan Options
    private readonly TextBox _scanValue;
    private readonly TextBox _scanValue2;
    private readonly Label _andLabel;
    private readonly CheckBox _hexCheckBox;
    private readonly Button _scanBtn;
    private readonly ComboBox _scanTypeCombo;
    private readonly ComboBox _valueTypeCombo;
    private readonly Button _firstScanBtn;
    private readonly Button _nextScanBtn;
    private readonly Button _undoBtn;

    // UI Controls - Memory Options
    private readonly GroupBox _memoryOptionsGroup;
    private readonly TextBox _startAddress;
    private readonly TextBox _stopAddress;
    private readonly CheckBox _writableCheck;
    private readonly CheckBox _executableCheck;
    private readonly CheckBox _fastScanCheck;

    // Scan state
    private bool _isFirstScan = true;
    private readonly List<FoundItem> _foundItems = [];
    private IntPtr _scanHandle;
    private nuint _resultCount;
    private int _scanValueType;
    private readonly Dictionary<ulong, NexusScanValue> _originalValues = new();

    public MemoryScannerPanel()
    {
        Text = "Memory Scanner";
        BackColor = NexusTheme.BackgroundPanel;
        Padding = new Padding(0); // No outer padding - sub-panels have their own

        // Main split container
        var mainSplit = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Orientation = Orientation.Vertical,
            BackColor = NexusTheme.BackgroundPanel
        };

        // ==========================================
        // LEFT PANEL - Found Results
        // ==========================================
        var leftPanel = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = NexusTheme.BackgroundPanel,
            Padding = NexusTheme.PanelPadding
        };

        _foundLabel = new Label
        {
            Text = "Found: 0",
            Dock = DockStyle.Top,
            Height = NexusTheme.ControlHeight,
            ForeColor = NexusTheme.TextPrimary,
            Font = NexusTheme.FontBody,
            TextAlign = ContentAlignment.MiddleLeft
        };

        _foundList = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            VirtualMode = true,
            HideSelection = false,
            Font = NexusTheme.FontMono
        };
        _foundList.Columns.Add("Address");
        _foundList.Columns.Add("Value", 90);
        _foundList.Columns.Add("Previous", 110);
        _foundList.Columns.Add("Original", 110);
        _foundList.RetrieveVirtualItem += FoundList_RetrieveVirtualItem;
        _foundList.Resize += (s, e) => ResizeAddressColumn();
        _foundList.DoubleClick += FoundList_DoubleClick;
        NexusTheme.StyleListView(_foundList);

        // Found List context menu
        _foundListContextMenu = CreateFoundListContextMenu();
        _foundList.ContextMenuStrip = _foundListContextMenu;

        // Combine label and buttons in same row at top
        var headerPanel = new Panel
        {
            Dock = DockStyle.Top,
            Height = NexusTheme.ControlHeight + NexusTheme.Space4,  // Add gap below
            BackColor = NexusTheme.BackgroundPanel,
            Padding = new Padding(0, 0, 0, NexusTheme.Space4)  // Bottom padding for gap
        };

        // Label on the left
        _foundLabel.Dock = DockStyle.Left;
        _foundLabel.AutoSize = true;

        // Buttons on the right in a flow panel
        var buttonPanel = new FlowLayoutPanel
        {
            Dock = DockStyle.Right,
            Width = NexusTheme.ButtonWidthWide + NexusTheme.ButtonWidth + NexusTheme.Space8,
            FlowDirection = FlowDirection.LeftToRight,  // Left to right so Add to List comes first
            BackColor = NexusTheme.BackgroundPanel
        };

        _addToListBtn = new Button { Text = "Add to List" };
        _clearBtn = new Button { Text = "Clear" };
        NexusTheme.StyleButtonWide(_addToListBtn);
        NexusTheme.StyleButton(_clearBtn);
        _clearBtn.Margin = new Padding(NexusTheme.Space4, 0, 0, 0);
        _addToListBtn.Click += AddToList_Click;
        _clearBtn.Click += Clear_Click;
        buttonPanel.Controls.AddRange([_addToListBtn, _clearBtn]);

        headerPanel.Controls.Add(_foundLabel);
        headerPanel.Controls.Add(buttonPanel);

        leftPanel.Controls.Add(_foundList);
        leftPanel.Controls.Add(headerPanel);

        // ==========================================
        // RIGHT PANEL - Scan Options + Saved Addresses
        // ==========================================
        var rightSplit = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Orientation = Orientation.Horizontal,
            BackColor = NexusTheme.BackgroundPanel
        };

        // Top: Scan Options
        var rightPanel = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = NexusTheme.BackgroundPanel,
            Padding = NexusTheme.PanelPadding
        };

        // Bottom: Saved Addresses
        var savedPanel = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = NexusTheme.BackgroundPanel,
            Padding = NexusTheme.PanelPadding
        };

        _savedLabel = new Label
        {
            Text = "Saved Addresses",
            Dock = DockStyle.Top,
            Height = NexusTheme.ControlHeight,
            ForeColor = NexusTheme.TextPrimary,
            Font = NexusTheme.FontBody,
            TextAlign = ContentAlignment.MiddleLeft
        };

        _savedList = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            HideSelection = false,
            LabelEdit = true,
            Font = NexusTheme.FontMono,
            CheckBoxes = true
        };
        _savedList.Columns.Add("Description", 150);  // Gets remaining space
        _savedList.Columns.Add("Address", 140);
        _savedList.Columns.Add("Type", 100);
        _savedList.Columns.Add("Value", 80);
        _savedList.Resize += (s, e) => AutoSizeSavedListColumns();
        _savedList.DoubleClick += SavedList_DoubleClick;
        _savedList.KeyDown += SavedList_KeyDown;
        _savedList.ItemChecked += SavedList_ItemChecked;
        NexusTheme.StyleListView(_savedList);

        // Saved Addresses context menu
        _savedListContextMenu = CreateSavedListContextMenu();
        _savedList.ContextMenuStrip = _savedListContextMenu;

        savedPanel.Controls.Add(_savedList);
        savedPanel.Controls.Add(_savedLabel);

        // Scan buttons row
        var scanBtnPanel = new FlowLayoutPanel
        {
            Dock = DockStyle.Top,
            Height = NexusTheme.ControlHeight + NexusTheme.Space16,
            FlowDirection = FlowDirection.LeftToRight,
            BackColor = NexusTheme.BackgroundPanel
        };

        _firstScanBtn = new Button { Text = "New" };
        _nextScanBtn = new Button { Text = "Next", Enabled = false };
        _undoBtn = new Button { Text = "Undo", Enabled = false };
        NexusTheme.StylePrimaryButton(_firstScanBtn);
        NexusTheme.StyleButton(_nextScanBtn);
        NexusTheme.StyleButton(_undoBtn);
        _firstScanBtn.Margin = new Padding(0, 0, NexusTheme.Space4, 0);
        _nextScanBtn.Margin = new Padding(0, 0, NexusTheme.Space4, 0);
        _firstScanBtn.Click += NewScan_Click;
        _nextScanBtn.Click += NextScan_Click;
        _undoBtn.Click += Undo_Click;
        scanBtnPanel.Controls.AddRange([_firstScanBtn, _nextScanBtn, _undoBtn]);

        // Value input row
        var valuePanel = new FlowLayoutPanel
        {
            Dock = DockStyle.Top,
            Height = NexusTheme.ControlHeight + NexusTheme.Space8,
            FlowDirection = FlowDirection.LeftToRight,
            BackColor = NexusTheme.BackgroundPanel
        };

        var valueLabel = CreateLabel("Value:", LabelWidth);
        valueLabel.Height = NexusTheme.ControlHeight;
        _scanValue = new TextBox { Width = 180, Text = "0" };
        NexusTheme.StyleTextBox(_scanValue);
        _scanValue.KeyDown += ScanValue_KeyDown;

        _andLabel = new Label
        {
            Text = "and",
            AutoSize = true,
            Height = NexusTheme.ControlHeight,
            ForeColor = NexusTheme.TextSecondary,
            TextAlign = ContentAlignment.MiddleLeft,
            Visible = false,
            Margin = new Padding(NexusTheme.Space4, 0, NexusTheme.Space4, 0)
        };
        _scanValue2 = new TextBox { Width = 100, Visible = false };
        NexusTheme.StyleTextBox(_scanValue2);
        _scanValue2.KeyDown += ScanValue_KeyDown;

        _hexCheckBox = new CheckBox
        {
            Text = "Hex",
            AutoSize = true,
            ForeColor = NexusTheme.TextPrimary,
            Margin = new Padding(NexusTheme.Space8, 8, 0, 0)
        };

        _scanBtn = new Button { Text = "First Scan", Width = NexusTheme.ButtonWidthWide };
        NexusTheme.StylePrimaryButton(_scanBtn);
        _scanBtn.Margin = new Padding(NexusTheme.Space8, 0, 0, 0);
        _scanBtn.Click += ScanBtn_Click;

        _scanValue.Margin = new Padding(0, 0, NexusTheme.Space4, 0);
        valuePanel.Controls.AddRange([valueLabel, _scanValue, _andLabel, _scanValue2, _hexCheckBox, _scanBtn]);

        // Scan type row
        var scanTypePanel = new FlowLayoutPanel
        {
            Dock = DockStyle.Top,
            Height = NexusTheme.ControlHeight + NexusTheme.Space8,
            FlowDirection = FlowDirection.LeftToRight,
            BackColor = NexusTheme.BackgroundPanel
        };

        var scanTypeLabel = CreateLabel("Scan Type:", LabelWidth);
        scanTypeLabel.Height = NexusTheme.ControlHeight;
        _scanTypeCombo = new ComboBox
        {
            DropDownStyle = ComboBoxStyle.DropDownList,
            Width = 180
        };
        _scanTypeCombo.Items.AddRange([
            "Exact Value",
            "Bigger than...",
            "Smaller than...",
            "Value between...",
            "Unknown initial value",
            "Increased value",
            "Decreased value",
            "Changed value",
            "Unchanged value",
            "Increased by...",
            "Decreased by..."
        ]);
        _scanTypeCombo.SelectedIndex = 0;
        _scanTypeCombo.SelectedIndexChanged += ScanType_Changed;
        NexusTheme.StyleComboBox(_scanTypeCombo);

        scanTypePanel.Controls.AddRange([scanTypeLabel, _scanTypeCombo]);

        // Value type row
        var valueTypePanel = new FlowLayoutPanel
        {
            Dock = DockStyle.Top,
            Height = NexusTheme.ControlHeight + NexusTheme.Space8,
            FlowDirection = FlowDirection.LeftToRight,
            BackColor = NexusTheme.BackgroundPanel
        };

        var valueTypeLabel = CreateLabel("Type:", LabelWidth);
        valueTypeLabel.Height = NexusTheme.ControlHeight;
        _valueTypeCombo = new ComboBox
        {
            DropDownStyle = ComboBoxStyle.DropDownList,
            Width = 180
        };
        _valueTypeCombo.Items.AddRange([
            "Byte",
            "2 Bytes",
            "4 Bytes",
            "8 Bytes",
            "Float",
            "Double",
            "String",
            "Array of Bytes",
            "All"
        ]);
        _valueTypeCombo.SelectedIndex = 2; // Default to 4 Bytes
        NexusTheme.StyleComboBox(_valueTypeCombo);

        valueTypePanel.Controls.AddRange([valueTypeLabel, _valueTypeCombo]);

        // Memory options group
        _memoryOptionsGroup = new GroupBox
        {
            Text = "Memory Options",
            Dock = DockStyle.Top,
            Height = 110,
            ForeColor = NexusTheme.TextPrimary,
            Padding = new Padding(NexusTheme.Space4),
            Margin = new Padding(0, NexusTheme.Space8, 0, 0)
        };

        // Row 1: Start address
        var startRow = new FlowLayoutPanel
        {
            Dock = DockStyle.Top,
            Height = 26,
            FlowDirection = FlowDirection.LeftToRight
        };
        var startLabel = new Label { Text = "Start:", Width = 38, TextAlign = ContentAlignment.MiddleLeft, ForeColor = NexusTheme.TextPrimary, AutoSize = true };
        _startAddress = new TextBox { Text = "0", Width = 120 };
        NexusTheme.StyleTextBox(_startAddress);
        startRow.Controls.AddRange([startLabel, _startAddress]);

        // Row 2: Stop address
        var stopRow = new FlowLayoutPanel
        {
            Dock = DockStyle.Top,
            Height = 26,
            FlowDirection = FlowDirection.LeftToRight
        };
        var stopLabel = new Label { Text = "Stop:", Width = 38, TextAlign = ContentAlignment.MiddleLeft, ForeColor = NexusTheme.TextPrimary, AutoSize = true };
        _stopAddress = new TextBox { Text = "7FFFFFFFFFFF", Width = 120 };
        NexusTheme.StyleTextBox(_stopAddress);
        stopRow.Controls.AddRange([stopLabel, _stopAddress]);

        // Row 3: Checkboxes
        var checkRow = new FlowLayoutPanel
        {
            Dock = DockStyle.Top,
            Height = 26,
            FlowDirection = FlowDirection.LeftToRight
        };
        _writableCheck = new CheckBox { Text = "Writable", Checked = true, AutoSize = true, ForeColor = NexusTheme.TextPrimary };
        _executableCheck = new CheckBox { Text = "Executable", AutoSize = true, ForeColor = NexusTheme.TextPrimary, Margin = new Padding(8, 0, 0, 0) };
        _fastScanCheck = new CheckBox { Text = "Fast Scan", Checked = true, AutoSize = true, ForeColor = NexusTheme.TextPrimary, Margin = new Padding(8, 0, 0, 0) };
        checkRow.Controls.AddRange([_writableCheck, _executableCheck, _fastScanCheck]);

        // Add rows to group (bottom to top due to Dock.Top)
        _memoryOptionsGroup.Controls.Add(checkRow);
        _memoryOptionsGroup.Controls.Add(stopRow);
        _memoryOptionsGroup.Controls.Add(startRow);

        // Add controls to right panel (bottom to top due to Dock.Top)
        rightPanel.Controls.Add(_memoryOptionsGroup);
        rightPanel.Controls.Add(valueTypePanel);
        rightPanel.Controls.Add(scanTypePanel);
        rightPanel.Controls.Add(valuePanel);
        rightPanel.Controls.Add(scanBtnPanel);

        // Wire up right split: scan options on top, saved addresses on bottom
        rightSplit.Panel1.Controls.Add(rightPanel);
        rightSplit.Panel2.Controls.Add(savedPanel);

        // Add panels to main split container
        mainSplit.Panel1.Controls.Add(leftPanel);
        mainSplit.Panel2.Controls.Add(rightSplit);

        Controls.Add(mainSplit);

        // Set splitter distances after control is sized
        Load += (s, e) =>
        {
            // Give Found List slightly more width (55% of available space)
            if (mainSplit.Width > 400)
                mainSplit.SplitterDistance = (int)(mainSplit.Width * 0.55);
            // Scan options: buttons(34) + value(34) + scan(34) + type(34) + memOptions(130 with checkboxes) = ~300
            // Set to minimum needed for scan options including checkboxes
            if (rightSplit.Height > 350)
                rightSplit.SplitterDistance = 310;
        };

        // Subscribe to AddToWatchListEvent to receive addresses from other panels
        EventBus.Instance.Subscribe<AddToWatchListEvent>(OnAddToWatchList);

        UpdateButtonStates();
    }

    private void OnAddToWatchList(AddToWatchListEvent evt)
    {
        // Convert value type string to int (NexusScanValueType cast)
        var valueType = (int)(evt.ValueType.ToLowerInvariant() switch
        {
            "byte" => NexusScanValueType.Byte,
            "int16" or "short" => NexusScanValueType.Int16,
            "int32" or "int" => NexusScanValueType.Int32,
            "int64" or "long" => NexusScanValueType.Int64,
            "float" => NexusScanValueType.Float,
            "double" => NexusScanValueType.Double,
            "pointer" => NexusScanValueType.Int64,
            _ => NexusScanValueType.Int32
        });

        var saved = new SavedAddress
        {
            Address = evt.Address,
            Description = evt.Description ?? $"Address_{evt.Address:X}",
            ValueType = valueType,
            IsFrozen = false
        };

        _savedAddresses.Add(saved);

        // Invoke on UI thread if needed
        if (InvokeRequired)
            Invoke(() => AddSavedAddressToList(saved));
        else
            AddSavedAddressToList(saved);

        PublishStatus($"Added address {evt.Address:X} to list", StatusType.Success);
    }

    public override string PanelId => "MemoryScanner";
    public override string PanelDisplayName => "Memory Scanner";

    public override ToolStripMenuItem[]? GetPanelMenus()
    {
        var scanMenu = new ToolStripMenuItem("&Scan");
        scanMenu.DropDownItems.AddRange([
            new ToolStripMenuItem("&First Scan", null, (s, e) => DoFirstScan()) { ShortcutKeys = Keys.F5 },
            new ToolStripMenuItem("&Next Scan", null, (s, e) => DoNextScan()) { ShortcutKeys = Keys.F6 },
            new ToolStripMenuItem("&Undo Scan", null, (s, e) => UndoScan()) { ShortcutKeys = Keys.Control | Keys.Z },
            new ToolStripSeparator(),
            new ToolStripMenuItem("&New Scan", null, (s, e) => ResetScan()),
            new ToolStripSeparator(),
            new ToolStripMenuItem("Add &selected to list", null, (s, e) => AddSelectedToList()),
            new ToolStripMenuItem("&Clear results", null, (s, e) => ClearFoundList())
        ]);

        var addressMenu = new ToolStripMenuItem("&Address");
        addressMenu.DropDownItems.AddRange([
            new ToolStripMenuItem("&Add address manually...", null, (s, e) => AddAddressManually()),
            new ToolStripMenuItem("&Change value...", null, (s, e) => ChangeSelectedValue()),
            new ToolStripMenuItem("&Toggle freeze", null, (s, e) => ToggleFreezeSelected()),
            new ToolStripSeparator(),
            new ToolStripMenuItem("&Browse in disassembler", null, (s, e) => BrowseInDisassembler()),
            new ToolStripMenuItem("Find what &accesses", null, (s, e) => FindWhatAccessesSelected()),
            new ToolStripMenuItem("Find what &writes", null, (s, e) => FindWhatWritesSelected()),
            new ToolStripSeparator(),
            new ToolStripMenuItem("&Delete selected", null, (s, e) => DeleteSelectedSaved()) { ShortcutKeys = Keys.Delete }
        ]);

        return [scanMenu, addressMenu];
    }

    private static Label CreateLabel(string text, int width = 0) => new()
    {
        Text = text,
        AutoSize = width == 0,
        Width = width > 0 ? width : 0,
        ForeColor = NexusTheme.TextPrimary,
        TextAlign = ContentAlignment.MiddleLeft
    };

    // Standard label width for aligned forms
    private const int LabelWidth = 80;

    #region Event Handlers

    protected override void OnProcessAttached(object? sender, ProcessAttachedEventArgs e)
    {
        if (InvokeRequired)
        {
            Invoke(() => OnProcessAttached(sender, e));
            return;
        }

        // Destroy old scan handle if exists
        if (_scanHandle != IntPtr.Zero)
        {
            NexusEngine.Nexus_AdvScanDestroy(_scanHandle);
            _scanHandle = IntPtr.Zero;
        }

        // Create new scan handle for this process
        var result = NexusEngine.Nexus_AdvScanCreate(e.ProcessHandle, out _scanHandle);
        if (result != NexusResult.OK)
        {
            PublishStatus($"Failed to create scanner: {NexusHelper.GetErrorMessage(result)}", StatusType.Error);
        }

        ResetScan();
        UpdateButtonStates();
    }

    protected override void OnProcessDetached(object? sender, ProcessDetachedEventArgs e)
    {
        if (InvokeRequired)
        {
            Invoke(() => OnProcessDetached(sender, e));
            return;
        }

        // Destroy scan handle
        if (_scanHandle != IntPtr.Zero)
        {
            NexusEngine.Nexus_AdvScanDestroy(_scanHandle);
            _scanHandle = IntPtr.Zero;
        }

        ResetScan();
        UpdateButtonStates();
    }

    private void ScanValue_KeyDown(object? sender, KeyEventArgs e)
    {
        if (e.KeyCode == Keys.Enter)
        {
            e.Handled = true;
            e.SuppressKeyPress = true;
            DoScan();
        }
    }

    private void ScanBtn_Click(object? sender, EventArgs e)
    {
        DoScan();
    }

    private void DoScan()
    {
        if (_isFirstScan)
            FirstScan_Click(null, EventArgs.Empty);
        else
            NextScan_Click(null, EventArgs.Empty);
    }

    private void ScanType_Changed(object? sender, EventArgs e)
    {
        var needsSecondValue = _scanTypeCombo.SelectedIndex == 3;
        _andLabel.Visible = needsSecondValue;
        _scanValue2.Visible = needsSecondValue;

        var needsValue = _scanTypeCombo.SelectedIndex < 4 ||
                         _scanTypeCombo.SelectedIndex >= 9;
        _scanValue.Enabled = needsValue;
    }

    private void FoundList_RetrieveVirtualItem(object? sender, RetrieveVirtualItemEventArgs e)
    {
        if (_scanHandle == IntPtr.Zero)
        {
            e.Item = new ListViewItem(["", "", "", ""]);
            return;
        }

        // Fetch this result from native engine
        var results = new NexusScanResultEntry[1];
        var fetchResult = NexusEngine.Nexus_AdvScanGetResults(
            _scanHandle,
            (ulong)e.ItemIndex,
            results,
            1,
            out var actualCount);

        if (fetchResult != NexusResult.OK || actualCount == 0)
        {
            e.Item = new ListViewItem(["???", "", "", ""]);
            return;
        }

        var entry = results[0];
        var lvi = new ListViewItem(entry.Address.ToString("X"));
        lvi.SubItems.Add(FormatValue(entry.CurrentValue, _scanValueType));
        lvi.SubItems.Add(FormatValue(entry.PreviousValue, _scanValueType));

        // Get original value (stored on first scan)
        var originalStr = _originalValues.TryGetValue(entry.Address, out var originalVal)
            ? FormatValue(originalVal, _scanValueType)
            : FormatValue(entry.PreviousValue, _scanValueType); // Fallback to previous
        lvi.SubItems.Add(originalStr);

        e.Item = lvi;
    }

    private static string FormatValue(NexusScanValue val, int valueType)
    {
        return valueType switch
        {
            0 => val.ByteVal.ToString(),
            1 => val.Int16Val.ToString(),
            2 => val.Int32Val.ToString(),
            3 => val.Int64Val.ToString(),
            4 => val.FloatVal.ToString("G"),
            5 => val.DoubleVal.ToString("G"),
            _ => val.Int32Val.ToString()
        };
    }

    private void FoundList_DoubleClick(object? sender, EventArgs e)
    {
        AddSelectedToList();
    }

    #endregion

    #region UI Helper Methods

    private void UpdateButtonStates()
    {
        var hasProcess = ProcessContext.Current.IsAttached;
        _firstScanBtn.Enabled = hasProcess;
        _nextScanBtn.Enabled = hasProcess && !_isFirstScan;
        _undoBtn.Enabled = hasProcess && !_isFirstScan;
        _scanBtn.Enabled = hasProcess;

        // "New" button always says "New", inline "Scan" button changes based on state
        _scanBtn.Text = _isFirstScan ? "First Scan" : "Next Scan";
    }

    private void PublishStatus(string message, StatusType type)
    {
        EventBus.Instance.Publish(new StatusUpdateEvent(message, type));
    }

    private void ResizeAddressColumn()
    {
        // Address column gets remaining space after other columns
        var otherColumnsWidth = 0;
        for (int i = 1; i < _foundList.Columns.Count; i++)
            otherColumnsWidth += _foundList.Columns[i].Width;

        var addressWidth = _foundList.ClientSize.Width - otherColumnsWidth - 4;
        if (addressWidth > 50)
            _foundList.Columns[0].Width = addressWidth;
    }

    #endregion

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            EventBus.Instance.Unsubscribe<AddToWatchListEvent>(OnAddToWatchList);
            if (_scanHandle != IntPtr.Zero)
            {
                NexusEngine.Nexus_AdvScanDestroy(_scanHandle);
                _scanHandle = IntPtr.Zero;
            }
        }
        base.Dispose(disposing);
    }
}
