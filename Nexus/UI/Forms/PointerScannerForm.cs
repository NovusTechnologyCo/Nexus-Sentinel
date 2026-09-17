// <file>
// <summary>
// Pointer scanner for finding multi-level pointer chains to a target address.
// </summary>
// </file>
using System.Runtime.InteropServices;
using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using Nexus.UI.Styles;

namespace Nexus.UI.Forms;

public partial class PointerScannerForm : Form
{
    // Main components
    private MenuStrip _mainMenu = null!;
    private ToolStripMenuItem _fileMenu = null!;
    private ToolStripMenuItem _pointerScannerMenu = null!;

    // Results list
    private ListView _lvResults = null!;

    // Info TreeView
    private TreeView _tvInfo = null!;

    // Progress panel
    private Panel _pnlProgress = null!;
    private ProgressBar _progressBar = null!;
    private Label _lblProgress = null!;

    // Control panel
    private Panel _pnlControl = null!;
    private Button _btnStopScan = null!;
    private Button _btnStopRescanLoop = null!;

    // Data panel
#pragma warning disable CS0414 // Assigned for results data panel
    private Panel _pnlData = null!;
#pragma warning restore CS0414
    private SplitContainer _splitContainer = null!;

    // Type selector
    private ComboBox _cbType = null!;

    // Context menus
    private ContextMenuStrip _pmResults = null!;
    private ContextMenuStrip _pmInfo = null!;

    // Timers
    private System.Windows.Forms.Timer _updateTimer = null!;

    // State
    private IntPtr _processHandle;
    private IntPtr _scanHandle;
    private bool _isScanning;
    private List<NexusPointerPath> _engineResults = new();
    private DateTime _scanStartTime;

    // Sorting state
    private int _sortColumn = 0;
    private bool _sortAscending = true;

    // Display options
    private bool _showSigned;
    private bool _showHexadecimal = true;

    // Process bitness
    private bool _is64Bit = true;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool IsWow64Process(IntPtr hProcess, out bool isWow64);

    public PointerScannerForm(IntPtr processHandle)
    {
        _processHandle = processHandle;
        DetectProcessBitness();
        InitializeComponent();
        NexusTheme.StyleForm(this);
        SetupEventHandlers();
    }

    private void DetectProcessBitness()
    {
        // On 64-bit Windows, check if target is WoW64 (32-bit process on 64-bit OS)
        if (Environment.Is64BitOperatingSystem)
        {
            if (IsWow64Process(_processHandle, out bool isWow64))
            {
                _is64Bit = !isWow64;  // WoW64 means 32-bit process
            }
        }
        else
        {
            _is64Bit = false;  // 32-bit OS = 32-bit process
        }
    }

    private void InitializeComponent()
    {
        Text = "Pointer Scanner";
        ClientSize = new Size(1300, 900);
        MinimumSize = new Size(1000, 700);
        StartPosition = FormStartPosition.CenterParent;

        // Main menu
        _mainMenu = new MenuStrip();

        // File menu
        _fileMenu = new ToolStripMenuItem("File");
        _fileMenu.DropDownItems.Add("New scan", null, (s, e) => NewScan());
        _fileMenu.DropDownItems.Add("-");
        _fileMenu.DropDownItems.Add("Open...", null, (s, e) => OpenResults());
        _fileMenu.DropDownItems.Add("Save...", null, (s, e) => SaveResults());
        _fileMenu.DropDownItems.Add("-");
        _fileMenu.DropDownItems.Add("Merge pointer files...", null, (s, e) => MergePointerFiles());

        // Pointer scanner menu
        _pointerScannerMenu = new ToolStripMenuItem("Pointer scanner");
        _pointerScannerMenu.DropDownItems.Add("Scan for pointers", null, (s, e) => StartPointerScan());
        _pointerScannerMenu.DropDownItems.Add("-");
        _pointerScannerMenu.DropDownItems.Add("Rescan memory", null, (s, e) => RescanMemory());
        _pointerScannerMenu.DropDownItems.Add("-");
        _pointerScannerMenu.DropDownItems.Add("Resume scan...", null, (s, e) => ResumeScan());
        _pointerScannerMenu.DropDownItems.Add("-");
        _pointerScannerMenu.DropDownItems.Add("Sort results...", null, (s, e) => ShowSortPointerList());
        _pointerScannerMenu.DropDownItems.Add("Advanced settings...", null, (s, e) => ShowAdvancedSettings());
        _pointerScannerMenu.DropDownItems.Add("-");
        _pointerScannerMenu.DropDownItems.Add("Set work folder...", null, (s, e) => SetWorkFolder());

        _mainMenu.Items.Add(_fileMenu);
        _mainMenu.Items.Add(_pointerScannerMenu);

        // Create main split container
        _splitContainer = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Orientation = Orientation.Vertical
        };

        // Adjust splitter after form is shown
        Shown += (s, e) =>
        {
            try
            {
                int rightPanelWidth = 275;
                int newDistance = _splitContainer.Width - rightPanelWidth;
                if (newDistance > 0 && newDistance < _splitContainer.Width)
                    _splitContainer.SplitterDistance = newDistance;
            }
            catch { }
        };

        // Left panel - Results
        var leftPanel = new Panel { Dock = DockStyle.Fill };

        // Type combo
        var typePanel = new Panel { Dock = DockStyle.Top, Height = 40 };
        var typeLabel = new Label { Text = "Type:", Location = new Point(5, 7), AutoSize = true };
        _cbType = new ComboBox
        {
            Location = new Point(60, 4),
            Width = 150,
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        _cbType.Items.AddRange(new object[] { "Byte", "2 Bytes", "4 Bytes", "8 Bytes", "Float", "Double", "All" });
        _cbType.SelectedIndex = 2; // 4 Bytes default
        typePanel.Controls.AddRange(new Control[] { typeLabel, _cbType });

        // Results ListView
        _lvResults = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            VirtualMode = true,
            VirtualListSize = 0
        };
        _lvResults.Columns.Add("Base Address", -2);
        _lvResults.Columns.Add("Offsets", -2);
        _lvResults.Columns.Add("Points to", -2);
        _lvResults.Columns.Add("Value", -2);

        // Results context menu
        _pmResults = new ContextMenuStrip();
        _pmResults.Items.Add("Add to address list", null, (s, e) => AddSelectedToAddressList());
        _pmResults.Items.Add("-");
        _pmResults.Items.Add("Resync modulelist", null, (s, e) => ResyncModuleList());
        _pmResults.Items.Add("-");
        _pmResults.Items.Add("Show as signed", null, (s, e) => ToggleSigned());
        _pmResults.Items.Add("Show as hexadecimal", null, (s, e) => ToggleHexadecimal());
        _lvResults.ContextMenuStrip = _pmResults;

        leftPanel.Controls.Add(_lvResults);
        leftPanel.Controls.Add(typePanel);

        // Right panel - Info tree
        _tvInfo = new TreeView
        {
            Dock = DockStyle.Fill,
            ShowLines = true,
            ShowPlusMinus = true
        };

        // Info context menu
        _pmInfo = new ContextMenuStrip();
        _tvInfo.ContextMenuStrip = _pmInfo;

        // Create right panel container
        var rightPanel = new Panel { Dock = DockStyle.Fill };
        rightPanel.Controls.Add(_tvInfo);

        _splitContainer.Panel1.Controls.Add(leftPanel);
        _splitContainer.Panel2.Controls.Add(rightPanel);

        // Progress panel at bottom
        _pnlProgress = new Panel
        {
            Dock = DockStyle.Bottom,
            Height = 50
        };

        _lblProgress = new Label
        {
            Text = "Ready",
            Location = new Point(5, 25),
            AutoSize = true
        };

        _progressBar = new ProgressBar
        {
            Location = new Point(250, 25),
            Width = 400,
            Height = 20
        };

        _pnlProgress.Controls.AddRange(new Control[] { _lblProgress, _progressBar });

        // Control panel
        _pnlControl = new Panel
        {
            Dock = DockStyle.Bottom,
            Height = 60
        };

        _btnStopScan = new Button
        {
            Text = "Stop scan",
            Location = new Point(5, 8),
            Size = new Size(100, 44),
            Enabled = false
        };

        _btnStopRescanLoop = new Button
        {
            Text = "Stop rescan loop",
            Location = new Point(115, 8),
            Size = new Size(120, 44),
            Enabled = false,
            Visible = false
        };

        _pnlControl.Controls.AddRange(new Control[] { _btnStopScan, _btnStopRescanLoop });

        // Update timer
        _updateTimer = new System.Windows.Forms.Timer
        {
            Interval = 1000,
            Enabled = true
        };

        // Add controls
        Controls.Add(_splitContainer);
        Controls.Add(_pnlControl);
        Controls.Add(_pnlProgress);
        Controls.Add(_mainMenu);
        MainMenuStrip = _mainMenu;

        // Initialize info tree
        InitializeInfoTree();
    }

    private void InitializeInfoTree()
    {
        _tvInfo.Nodes.Clear();

        var statsNode = _tvInfo.Nodes.Add("Statistics");
        statsNode.Nodes.Add("Total time: 00:00:00");
        statsNode.Nodes.Add("Paths evaluated: 0");
        statsNode.Nodes.Add("Paths per second: 0");
        statsNode.Nodes.Add("Results found: 0");
        statsNode.Nodes.Add("Queue size: 0");
        statsNode.Expand();

        var workersNode = _tvInfo.Nodes.Add("Local workers");
        workersNode.Nodes.Add("Thread 1: Idle");
    }

    private void SetupEventHandlers()
    {
        _lvResults.RetrieveVirtualItem += LvResults_RetrieveVirtualItem;
        _lvResults.DoubleClick += LvResults_DoubleClick;
        _lvResults.ColumnClick += LvResults_ColumnClick;

        _btnStopScan.Click += (s, e) => StopScan();
        _btnStopRescanLoop.Click += (s, e) => StopRescanLoop();

        _cbType.SelectedIndexChanged += (s, e) => RefreshResults();

        _updateTimer.Tick += UpdateTimer_Tick;

        FormClosing += PointerScannerForm_FormClosing;
    }

    private void PointerScannerForm_FormClosing(object? sender, FormClosingEventArgs e)
    {
        if (_isScanning)
        {
            var result = MessageBox.Show(
                "A scan is still in progress. Stop the scan and close?",
                "Pointer Scanner",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question);

            if (result == DialogResult.No)
            {
                e.Cancel = true;
                return;
            }

            StopScan();
        }

        _updateTimer.Stop();
        _updateTimer.Dispose();

        // Clean up scan handle
        if (_scanHandle != IntPtr.Zero)
        {
            NexusEngine.Nexus_PointerScanDestroy(_scanHandle);
            _scanHandle = IntPtr.Zero;
        }
    }
}

/// <summary>
/// Pointer scan settings dialog.
/// </summary>
public class PointerScanSettingsForm : Form
{
    private TextBox _txtAddress = null!;
    private NumericUpDown _nudMaxLevel = null!;
    private NumericUpDown _nudMaxOffset = null!;
    private CheckBox _cbOnlyBaseAddress = null!;
    private CheckBox _cbHeapOnly = null!;
    private CheckBox _cbStackOnly = null!;
    private CheckBox _cbMustEndWithOffset = null!;
    private TextBox _txtEndOffset = null!;
    private CheckBox _cbNegativeOffsets = null!;
    private NumericUpDown _nudMaxResults = null!;
    private Button _btnOK = null!;
    private Button _btnCancel = null!;

    public ulong TargetAddress => ulong.TryParse(_txtAddress.Text.Replace("0x", ""),
        System.Globalization.NumberStyles.HexNumber, null, out var addr) ? addr : 0;
    public int MaxLevel => (int)_nudMaxLevel.Value;
    public int MaxOffset => (int)_nudMaxOffset.Value;
    public bool OnlyBaseAddress => _cbOnlyBaseAddress.Checked;
    public bool HeapOnly => _cbHeapOnly.Checked;
    public bool StackOnly => _cbStackOnly.Checked;
    public bool MustEndWithOffset => _cbMustEndWithOffset.Checked;
    public bool AllowNegativeOffsets => _cbNegativeOffsets.Checked;
    public int MaxResults => (int)_nudMaxResults.Value;

    public PointerScanSettingsForm()
    {
        InitializeComponent();
        NexusTheme.StyleForm(this);
    }

    private void InitializeComponent()
    {
        Text = "Pointer scan settings";
        Size = new Size(450, 400);
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;

        var y = 15;

        // Address
        var lblAddress = new Label { Text = "Address to find:", Location = new Point(15, y), AutoSize = true };
        _txtAddress = new TextBox { Location = new Point(150, y - 3), Width = 200 };
        NexusTheme.StyleTextBox(_txtAddress);
        y += 30;

        // Max level
        var lblMaxLevel = new Label { Text = "Max level:", Location = new Point(15, y), AutoSize = true };
        _nudMaxLevel = new NumericUpDown
        {
            Location = new Point(150, y - 3),
            Size = new Size(80, 32),
            Minimum = 1,
            Maximum = 10,
            Value = 5
        };
        y += 30;

        // Max offset
        var lblMaxOffset = new Label { Text = "Max offset:", Location = new Point(15, y), AutoSize = true };
        _nudMaxOffset = new NumericUpDown
        {
            Location = new Point(150, y - 3),
            Size = new Size(80, 32),
            Minimum = 0,
            Maximum = 0x10000,
            Value = 4095,  // 0xFFF - matches CE default
            Hexadecimal = true
        };
        y += 30;

        // Options group
        var gbOptions = new GroupBox
        {
            Text = "Options",
            Location = new Point(15, y),
            Size = new Size(400, 150)
        };

        var oy = 20;
        _cbOnlyBaseAddress = new CheckBox
        {
            Text = "Only find static/base addresses",
            Location = new Point(10, oy),
            AutoSize = true
        };
        oy += 25;

        _cbHeapOnly = new CheckBox
        {
            Text = "Heap only",
            Location = new Point(10, oy),
            AutoSize = true
        };
        oy += 25;

        _cbStackOnly = new CheckBox
        {
            Text = "Stack only",
            Location = new Point(10, oy),
            AutoSize = true
        };
        oy += 25;

        _cbMustEndWithOffset = new CheckBox
        {
            Text = "Must end with specific offset:",
            Location = new Point(10, oy),
            AutoSize = true
        };
        _txtEndOffset = new TextBox
        {
            Location = new Point(275, oy - 3),
            Size = new Size(50, 32),
            Text = "0"
        };
        oy += 25;

        _cbNegativeOffsets = new CheckBox
        {
            Text = "Allow negative offsets",
            Location = new Point(10, oy),
            AutoSize = true,
            Checked = false  // Off by default like CE
        };

        gbOptions.Controls.AddRange(new Control[]
        {
            _cbOnlyBaseAddress, _cbHeapOnly, _cbStackOnly,
            _cbMustEndWithOffset, _txtEndOffset, _cbNegativeOffsets
        });
        y += 160;

        // Max results
        var lblMaxResults = new Label { Text = "Max results:", Location = new Point(15, y), AutoSize = true };
        _nudMaxResults = new NumericUpDown
        {
            Location = new Point(150, y - 3),
            Size = new Size(80, 32),
            Minimum = 1,
            Maximum = 100000000,
            Value = 10000000
        };
        y += 40;

        // Buttons
        _btnOK = new Button
        {
            Text = "OK",
            Location = new Point(200, y),
            Size = new Size(80, 32),
            DialogResult = DialogResult.OK
        };

        _btnCancel = new Button
        {
            Text = "Cancel",
            Location = new Point(290, y),
            Size = new Size(80, 32),
            DialogResult = DialogResult.Cancel
        };

        Controls.AddRange(new Control[]
        {
            lblAddress, _txtAddress,
            lblMaxLevel, _nudMaxLevel,
            lblMaxOffset, _nudMaxOffset,
            gbOptions,
            lblMaxResults, _nudMaxResults,
            _btnOK, _btnCancel
        });

        AcceptButton = _btnOK;
        CancelButton = _btnCancel;
    }
}

/// <summary>
/// Pointer rescan dialog.
/// </summary>
public class PointerRescanForm : Form
{
    private TextBox _txtAddress = null!;
    private CheckBox _cbForValue = null!;
    private ComboBox _cbValueType = null!;
    private TextBox _txtValue = null!;
    private CheckBox _cbFilterRange = null!;
    private TextBox _txtRangeStart = null!;
    private TextBox _txtRangeEnd = null!;
    private Button _btnOK = null!;
    private Button _btnCancel = null!;

    public ulong TargetAddress => ulong.TryParse(_txtAddress.Text.Replace("0x", ""),
        System.Globalization.NumberStyles.HexNumber, null, out var addr) ? addr : 0;
    public bool ForValue => _cbForValue.Checked;
    public int ValueType => _cbValueType.SelectedIndex;
    public string ValueText => _txtValue.Text;
    public bool FilterRange => _cbFilterRange.Checked;

    public PointerRescanForm()
    {
        InitializeComponent();
        NexusTheme.StyleForm(this);
    }

    private void InitializeComponent()
    {
        Text = "Rescan memory";
        Size = new Size(400, 300);
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;

        var y = 15;

        // Address
        var lblAddress = new Label { Text = "New address:", Location = new Point(15, y), AutoSize = true };
        _txtAddress = new TextBox { Location = new Point(120, y - 3), Width = 200 };
        NexusTheme.StyleTextBox(_txtAddress);
        y += 35;

        // For value
        _cbForValue = new CheckBox
        {
            Text = "Pointer must point to value:",
            Location = new Point(15, y),
            AutoSize = true
        };
        NexusTheme.StyleCheckBox(_cbForValue);
        y += 25;

        // Value type
        var lblType = new Label { Text = "Type:", Location = new Point(35, y), AutoSize = true };
        _cbValueType = new ComboBox
        {
            Location = new Point(80, y - 3),
            Size = new Size(80, 32),
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        _cbValueType.Items.AddRange(new object[] { "4 Bytes", "Float", "Double" });
        _cbValueType.SelectedIndex = 0;
        NexusTheme.StyleComboBox(_cbValueType);

        var lblValue = new Label { Text = "Value:", Location = new Point(190, y), AutoSize = true };
        _txtValue = new TextBox { Location = new Point(240, y - 3), Width = 100 };
        NexusTheme.StyleTextBox(_txtValue);
        y += 35;

        // Filter range
        _cbFilterRange = new CheckBox
        {
            Text = "Base address must be in range:",
            Location = new Point(15, y),
            AutoSize = true
        };
        NexusTheme.StyleCheckBox(_cbFilterRange);
        y += 25;

        var lblFrom = new Label { Text = "From:", Location = new Point(35, y), AutoSize = true };
        _txtRangeStart = new TextBox { Location = new Point(80, y - 3), Width = 120 };
        NexusTheme.StyleTextBox(_txtRangeStart);
        var lblTo = new Label { Text = "To:", Location = new Point(210, y), AutoSize = true };
        _txtRangeEnd = new TextBox { Location = new Point(240, y - 3), Width = 120 };
        NexusTheme.StyleTextBox(_txtRangeEnd);
        y += 50;

        // Buttons
        _btnOK = new Button
        {
            Text = "OK",
            Location = new Point(180, y),
            Size = new Size(80, 32),
            DialogResult = DialogResult.OK
        };

        _btnCancel = new Button
        {
            Text = "Cancel",
            Location = new Point(270, y),
            Size = new Size(80, 32),
            DialogResult = DialogResult.Cancel
        };

        Controls.AddRange(new Control[]
        {
            lblAddress, _txtAddress,
            _cbForValue,
            lblType, _cbValueType, lblValue, _txtValue,
            _cbFilterRange,
            lblFrom, _txtRangeStart, lblTo, _txtRangeEnd,
            _btnOK, _btnCancel
        });

        AcceptButton = _btnOK;
        CancelButton = _btnCancel;

        _cbForValue.CheckedChanged += (s, e) =>
        {
            _cbValueType.Enabled = _cbForValue.Checked;
            _txtValue.Enabled = _cbForValue.Checked;
        };

        _cbFilterRange.CheckedChanged += (s, e) =>
        {
            _txtRangeStart.Enabled = _cbFilterRange.Checked;
            _txtRangeEnd.Enabled = _cbFilterRange.Checked;
        };

        // Initial state
        _cbValueType.Enabled = false;
        _txtValue.Enabled = false;
        _txtRangeStart.Enabled = false;
        _txtRangeEnd.Enabled = false;
    }
}
