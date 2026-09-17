// <file>
// <summary>
// Standalone debugger dialog with breakpoint management, exception config, and tracing.
// </summary>
// </file>
using System.Text;
using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using Nexus.UI.Styles;

namespace Nexus.UI.Forms;

/// <summary>
/// Consolidated form for debugging operations including breakpoints, exceptions, and tracing.
/// </summary>
public partial class DebuggerForm : Form
{
    #region Fields

    private readonly IntPtr _processHandle;
    private readonly IntPtr _debuggerHandle;
    private int _selectedTab;

    // Tab bar
    private Panel _tabBar = null!;
    private Button[] _tabButtons = null!;

    // Content panels
    private Panel _pnlBreakpoints = null!;
    private Panel _pnlExceptions = null!;
    private Panel _pnlTracer = null!;

    // Breakpoints tab controls
    private ListView _lvBreakpoints = null!;
    private ContextMenuStrip _ctxBreakpoints = null!;
    private System.Windows.Forms.Timer _bpUpdateTimer = null!;
    private List<BreakpointInfo> _breakpoints = new();
    private bool _showShadowBreakpoints;

    // Exceptions tab controls
    private ListView _lvExceptions = null!;
    private ContextMenuStrip _ctxExceptions = null!;
    private List<ExceptionEntry> _exceptions = new();

    // Tracer tab controls
    private ListView _lvTrace = null!;
    private TextBox _txtStartAddress = null!;
    private TextBox _txtEndAddress = null!;
    private NumericUpDown _nudMaxInstructions = null!;
    private Button _btnStartTrace = null!;
    private Button _btnStopTrace = null!;
    private CheckBox _chkStepOver = null!;
    private CheckBox _chkIncludeRegisters = null!;
    private Label _lblTraceStatus = null!;
    private Label _lblTraceCount = null!;
    private volatile bool _isTracing;
    private Font? _traceFont;
    private readonly List<TraceEntry> _traceEntries = new();
    private readonly object _traceEntriesLock = new();

    // Bottom panel
    private Panel _pnlBottom = null!;
    private Button _btnRefresh = null!;
    private Button _btnClose = null!;
    private Panel _pnlTabOptions = null!;

    // Events
    public event EventHandler<ulong>? OnNavigateToAddress;

    #endregion

    #region Nested Types

    public class TraceEntry
    {
        public int Index { get; set; }
        public ulong Address { get; set; }
        public string Instruction { get; set; } = "";
        public string Registers { get; set; } = "";
        public uint ThreadId { get; set; }
    }

    #endregion

    #region Constructor

    public DebuggerForm(IntPtr processHandle, IntPtr debuggerHandle, int initialTab = 0)
    {
        _processHandle = processHandle;
        _debuggerHandle = debuggerHandle;
        _selectedTab = initialTab;

        InitializeComponent();
        NexusTheme.StyleForm(this);
        SetupEventHandlers();

        SwitchToTab(_selectedTab);
        RefreshCurrentTab();
    }

    public void SwitchToTab(int tabIndex)
    {
        _selectedTab = tabIndex;
        NexusTheme.UpdateTabSelection(_tabButtons, tabIndex);

        _pnlBreakpoints.Visible = tabIndex == 0;
        _pnlExceptions.Visible = tabIndex == 1;
        _pnlTracer.Visible = tabIndex == 2;

        UpdateTabOptions();
    }

    #endregion

    #region Initialization

    private void InitializeComponent()
    {
        Text = "Debugger";
        Size = new Size(1000, 650);
        StartPosition = FormStartPosition.CenterParent;
        MinimumSize = new Size(800, 500);

        // Tab bar
        (_tabBar, _tabButtons) = NexusTheme.CreateTabBar(
            ["Breakpoints", "Exceptions", "Tracer"],
            tabIndex => SwitchToTab(tabIndex));
        _tabBar.Dock = DockStyle.Top;

        // Tab options panel (for tab-specific controls)
        _pnlTabOptions = new Panel
        {
            Dock = DockStyle.Top,
            Height = 45,
            Padding = new Padding(NexusTheme.Space8)
        };

        // Bottom panel
        _pnlBottom = new Panel
        {
            Dock = DockStyle.Bottom,
            Height = 50,
            Padding = new Padding(NexusTheme.Space16, NexusTheme.Space8, NexusTheme.Space16, NexusTheme.Space8)
        };

        _btnRefresh = new Button
        {
            Text = "Refresh",
            Size = new Size(90, NexusTheme.ControlHeight),
            Anchor = AnchorStyles.Bottom | AnchorStyles.Left
        };
        _btnRefresh.Click += (s, e) => RefreshCurrentTab();
        NexusTheme.StyleButton(_btnRefresh);

        _btnClose = new Button
        {
            Text = "Close",
            Size = new Size(90, NexusTheme.ControlHeight),
            Anchor = AnchorStyles.Bottom | AnchorStyles.Right,
            DialogResult = DialogResult.Cancel
        };
        NexusTheme.StyleButton(_btnClose);

        _pnlBottom.Controls.Add(_btnRefresh);
        _pnlBottom.Controls.Add(_btnClose);
        _pnlBottom.Layout += (s, e) =>
        {
            _btnRefresh.Location = new Point(NexusTheme.Space8, (_pnlBottom.Height - _btnRefresh.Height) / 2);
            _btnClose.Location = new Point(_pnlBottom.Width - _btnClose.Width - NexusTheme.Space8, (_pnlBottom.Height - _btnClose.Height) / 2);
        };

        // Create tab panels
        CreateBreakpointsPanel();
        CreateExceptionsPanel();
        CreateTracerPanel();

        Controls.Add(_pnlBreakpoints);
        Controls.Add(_pnlExceptions);
        Controls.Add(_pnlTracer);
        Controls.Add(_pnlTabOptions);
        Controls.Add(_pnlBottom);
        Controls.Add(_tabBar);

        CancelButton = _btnClose;
    }

    private void CreateBreakpointsPanel()
    {
        _pnlBreakpoints = new Panel { Dock = DockStyle.Fill, Visible = false };

        // Button panel at top
        var buttonPanel = new Panel { Dock = DockStyle.Top, Height = 45 };

        var btnAdd = new Button { Text = "Add...", Size = new Size(80, NexusTheme.ControlHeight), Location = new Point(NexusTheme.Space8, 8) };
        btnAdd.Click += BtnAddBreakpoint_Click;
        NexusTheme.StyleButton(btnAdd);

        var btnRemove = new Button { Text = "Remove", Size = new Size(80, NexusTheme.ControlHeight), Location = new Point(96, 8) };
        btnRemove.Click += (s, e) => DeleteSelectedBreakpoint();
        NexusTheme.StyleButton(btnRemove);

        var btnRemoveAll = new Button { Text = "Remove All", Size = new Size(90, NexusTheme.ControlHeight), Location = new Point(184, 8) };
        btnRemoveAll.Click += BtnRemoveAllBreakpoints_Click;
        NexusTheme.StyleButton(btnRemoveAll);

        var btnEnableAll = new Button { Text = "Enable All", Size = new Size(90, NexusTheme.ControlHeight), Location = new Point(282, 8) };
        btnEnableAll.Click += BtnEnableAllBreakpoints_Click;
        NexusTheme.StyleButton(btnEnableAll);

        var btnDisableAll = new Button { Text = "Disable All", Size = new Size(90, NexusTheme.ControlHeight), Location = new Point(380, 8) };
        btnDisableAll.Click += BtnDisableAllBreakpoints_Click;
        NexusTheme.StyleButton(btnDisableAll);

        buttonPanel.Controls.AddRange(new Control[] { btnAdd, btnRemove, btnRemoveAll, btnEnableAll, btnDisableAll });

        // ListView
        _lvBreakpoints = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = true
        };
        _lvBreakpoints.Columns.Add("Address", 150);
        _lvBreakpoints.Columns.Add("Type", 120);
        _lvBreakpoints.Columns.Add("Size", 50);
        _lvBreakpoints.Columns.Add("Hits", 50);
        _lvBreakpoints.Columns.Add("Condition", 120);
        _lvBreakpoints.Columns.Add("Enabled", 60);
        _lvBreakpoints.Columns.Add("Description", 200);
        NexusTheme.StyleListView(_lvBreakpoints);

        // Context menu
        _ctxBreakpoints = new ContextMenuStrip();
        _ctxBreakpoints.Items.Add("Delete breakpoint", null, (s, e) => DeleteSelectedBreakpoint());
        _ctxBreakpoints.Items.Add("Set condition...", null, (s, e) => SetBreakpointCondition());
        _ctxBreakpoints.Items.Add(new ToolStripSeparator());
        _ctxBreakpoints.Items.Add("Toggle enabled", null, (s, e) => ToggleBreakpoint());
        _ctxBreakpoints.Items.Add(new ToolStripSeparator());
        var miShowShadow = new ToolStripMenuItem("Show shadow breakpoints") { CheckOnClick = true };
        miShowShadow.Click += (s, e) => { _showShadowBreakpoints = miShowShadow.Checked; RefreshBreakpoints(); };
        _ctxBreakpoints.Items.Add(miShowShadow);
        _ctxBreakpoints.Items.Add("Refresh", null, (s, e) => RefreshBreakpoints());
        _lvBreakpoints.ContextMenuStrip = _ctxBreakpoints;

        _lvBreakpoints.DoubleClick += (s, e) =>
        {
            if (_lvBreakpoints.SelectedItems.Count > 0 && _lvBreakpoints.SelectedItems[0].Tag is BreakpointInfo bp)
                OnNavigateToAddress?.Invoke(this, bp.Address);
        };

        _pnlBreakpoints.Controls.Add(_lvBreakpoints);
        _pnlBreakpoints.Controls.Add(buttonPanel);

        // Update timer
        _bpUpdateTimer = new System.Windows.Forms.Timer { Interval = 5000 };
        _bpUpdateTimer.Tick += (s, e) => { if (_selectedTab == 0) RefreshBreakpoints(); };
    }

    private void CreateExceptionsPanel()
    {
        _pnlExceptions = new Panel { Dock = DockStyle.Fill, Visible = false };

        // Description
        var lblDesc = new Label
        {
            Text = "Configure which exceptions to ignore when debugging. Checked exceptions will be ignored.",
            Dock = DockStyle.Top,
            Height = 35,
            Padding = new Padding(NexusTheme.Space8)
        };

        // Button panel at top
        var buttonPanel = new Panel { Dock = DockStyle.Top, Height = 45 };

        var btnAdd = new Button { Text = "Add...", Size = new Size(80, NexusTheme.ControlHeight), Location = new Point(NexusTheme.Space8, 8) };
        btnAdd.Click += BtnAddException_Click;
        NexusTheme.StyleButton(btnAdd);

        var btnIgnoreAll = new Button { Text = "Ignore All", Size = new Size(90, NexusTheme.ControlHeight), Location = new Point(96, 8) };
        btnIgnoreAll.Click += (s, e) => { foreach (var ex in _exceptions) ex.Ignore = true; RefreshExceptions(); };
        NexusTheme.StyleButton(btnIgnoreAll);

        var btnIgnoreNone = new Button { Text = "Ignore None", Size = new Size(100, NexusTheme.ControlHeight), Location = new Point(194, 8) };
        btnIgnoreNone.Click += (s, e) => { foreach (var ex in _exceptions) ex.Ignore = false; RefreshExceptions(); };
        NexusTheme.StyleButton(btnIgnoreNone);

        buttonPanel.Controls.AddRange(new Control[] { btnAdd, btnIgnoreAll, btnIgnoreNone });

        // ListView
        _lvExceptions = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            CheckBoxes = true
        };
        _lvExceptions.Columns.Add("Code", 120);
        _lvExceptions.Columns.Add("Name", 350);
        _lvExceptions.Columns.Add("Pass to App", 80);
        NexusTheme.StyleListView(_lvExceptions);
        _lvExceptions.ItemCheck += LvExceptions_ItemCheck;

        // Context menu
        _ctxExceptions = new ContextMenuStrip();
        _ctxExceptions.Items.Add("Toggle pass to application", null, (s, e) =>
        {
            if (_lvExceptions.SelectedItems.Count > 0 && _lvExceptions.SelectedItems[0].Tag is ExceptionEntry entry)
            {
                entry.PassToApplication = !entry.PassToApplication;
                RefreshExceptions();
            }
        });
        _ctxExceptions.Items.Add(new ToolStripSeparator());
        _ctxExceptions.Items.Add("Remove", null, (s, e) =>
        {
            if (_lvExceptions.SelectedItems.Count > 0 && _lvExceptions.SelectedItems[0].Tag is ExceptionEntry entry)
            {
                _exceptions.Remove(entry);
                RefreshExceptions();
            }
        });
        _lvExceptions.ContextMenuStrip = _ctxExceptions;

        _pnlExceptions.Controls.Add(_lvExceptions);
        _pnlExceptions.Controls.Add(buttonPanel);
        _pnlExceptions.Controls.Add(lblDesc);

        LoadDefaultExceptions();
    }

    private void CreateTracerPanel()
    {
        _pnlTracer = new Panel { Dock = DockStyle.Fill, Visible = false };

        // Top controls panel
        var pnlTop = new Panel { Dock = DockStyle.Top, Height = 80 };

        var lblStart = new Label { Text = "Start address:", Location = new Point(NexusTheme.Space8, 15), AutoSize = true };
        _txtStartAddress = new TextBox { Location = new Point(110, 12), Width = 140 };
        NexusTheme.StyleTextBox(_txtStartAddress);

        var lblEnd = new Label { Text = "End address:", Location = new Point(260, 15), AutoSize = true };
        _txtEndAddress = new TextBox { Location = new Point(360, 12), Width = 140 };
        NexusTheme.StyleTextBox(_txtEndAddress);

        var lblMax = new Label { Text = "Max instructions:", Location = new Point(510, 15), AutoSize = true };
        _nudMaxInstructions = new NumericUpDown
        {
            Location = new Point(630, 12),
            Size = new Size(100, 23),
            Minimum = 100,
            Maximum = 1000000,
            Value = 10000,
            Increment = 1000
        };

        _btnStartTrace = new Button { Text = "Start Trace", Location = new Point(NexusTheme.Space8, 45), Size = new Size(100, NexusTheme.ControlHeight) };
        _btnStartTrace.Click += BtnStartTrace_Click;
        NexusTheme.StyleButton(_btnStartTrace);

        _btnStopTrace = new Button { Text = "Stop", Location = new Point(116, 45), Size = new Size(70, NexusTheme.ControlHeight), Enabled = false };
        _btnStopTrace.Click += BtnStopTrace_Click;
        NexusTheme.StyleButton(_btnStopTrace);

        var btnClear = new Button { Text = "Clear", Location = new Point(194, 45), Size = new Size(70, NexusTheme.ControlHeight) };
        btnClear.Click += (s, e) => { lock (_traceEntriesLock) { _traceEntries.Clear(); } _lvTrace.VirtualListSize = 0; _lblTraceCount.Text = "0 instructions"; _lblTraceStatus.Text = "Ready"; };
        NexusTheme.StyleButton(btnClear);

        _chkStepOver = new CheckBox { Text = "Step over calls", Location = new Point(280, 50), AutoSize = true };
        NexusTheme.StyleCheckBox(_chkStepOver);

        _chkIncludeRegisters = new CheckBox { Text = "Include registers", Location = new Point(420, 50), AutoSize = true, Checked = true };
        NexusTheme.StyleCheckBox(_chkIncludeRegisters);

        pnlTop.Controls.AddRange(new Control[] { lblStart, _txtStartAddress, lblEnd, _txtEndAddress, lblMax, _nudMaxInstructions,
            _btnStartTrace, _btnStopTrace, btnClear, _chkStepOver, _chkIncludeRegisters });

        // ListView for trace results
        _lvTrace = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = true,
            Font = _traceFont = new Font("Consolas", 9F),
            VirtualMode = true
        };
        _lvTrace.Columns.Add("#", 60);
        _lvTrace.Columns.Add("Address", 140);
        _lvTrace.Columns.Add("Instruction", 300);
        _lvTrace.Columns.Add("Registers", 250);
        _lvTrace.Columns.Add("Thread", 70);
        NexusTheme.StyleListView(_lvTrace);
        _lvTrace.RetrieveVirtualItem += LvTrace_RetrieveVirtualItem;
        _lvTrace.DoubleClick += (s, e) =>
        {
            if (_lvTrace.SelectedIndices.Count > 0 && _lvTrace.SelectedIndices[0] < _traceEntries.Count)
                OnNavigateToAddress?.Invoke(this, _traceEntries[_lvTrace.SelectedIndices[0]].Address);
        };

        // Context menu for trace
        var ctxTrace = new ContextMenuStrip();
        ctxTrace.Items.Add("Go to address", null, (s, e) =>
        {
            if (_lvTrace.SelectedIndices.Count > 0 && _lvTrace.SelectedIndices[0] < _traceEntries.Count)
                OnNavigateToAddress?.Invoke(this, _traceEntries[_lvTrace.SelectedIndices[0]].Address);
        });
        ctxTrace.Items.Add("Copy line", null, (s, e) =>
        {
            if (_lvTrace.SelectedIndices.Count > 0 && _lvTrace.SelectedIndices[0] < _traceEntries.Count)
            {
                var entry = _traceEntries[_lvTrace.SelectedIndices[0]];
                Clipboard.SetText($"{entry.Address:X}\t{entry.Instruction}\t{entry.Registers}");
            }
        });
        ctxTrace.Items.Add("Copy all", null, (s, e) =>
        {
            var sb = new StringBuilder();
            sb.AppendLine("#\tAddress\tInstruction\tRegisters\tThread");
            foreach (var entry in _traceEntries)
                sb.AppendLine($"{entry.Index}\t{entry.Address:X}\t{entry.Instruction}\t{entry.Registers}\t{entry.ThreadId}");
            Clipboard.SetText(sb.ToString());
        });
        ctxTrace.Items.Add(new ToolStripSeparator());
        ctxTrace.Items.Add("Save trace to file...", null, SaveTraceToFile);
        _lvTrace.ContextMenuStrip = ctxTrace;

        // Status panel
        var pnlStatus = new Panel { Dock = DockStyle.Bottom, Height = 30 };
        _lblTraceStatus = new Label { Text = "Ready", Location = new Point(NexusTheme.Space8, 8), AutoSize = true };
        _lblTraceCount = new Label { Text = "0 instructions", Location = new Point(750, 8), AutoSize = true, Anchor = AnchorStyles.Right };
        pnlStatus.Controls.Add(_lblTraceStatus);
        pnlStatus.Controls.Add(_lblTraceCount);

        _pnlTracer.Controls.Add(_lvTrace);
        _pnlTracer.Controls.Add(pnlTop);
        _pnlTracer.Controls.Add(pnlStatus);
    }

    private void SetupEventHandlers()
    {
        FormClosed += (s, e) =>
        {
            _bpUpdateTimer.Stop();
            _bpUpdateTimer.Dispose();
            _isTracing = false;
            _traceFont?.Dispose();
            _traceFont = null;
        };
    }

    private void UpdateTabOptions()
    {
        _pnlTabOptions.Controls.Clear();
        // Tab-specific options could be added here if needed
    }

    #endregion

}

/// <summary>
/// Represents information about a breakpoint.
/// </summary>
public class BreakpointInfo
{
    public ulong Id { get; set; }
    public ulong Address { get; set; }
    public NexusBreakpointType Type { get; set; }
    public int Size { get; set; }
    public string? Condition { get; set; }
    public bool IsEasyCondition { get; set; }
    public int HitCount { get; set; }
    public bool Enabled { get; set; } = true;
    public bool IsShadow { get; set; }
    public string? Description { get; set; }
}

/// <summary>
/// Represents an exception type that can be ignored.
/// </summary>
public class ExceptionEntry
{
    public uint ExceptionCode { get; set; }
    public string Name { get; set; } = "";
    public bool Ignore { get; set; }
    public bool PassToApplication { get; set; } = true;
}
