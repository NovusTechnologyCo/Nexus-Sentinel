// <file>
// <summary>
// API Monitor panel providing rohitab-style API call interception and display.
// Injects NexusApiHook.dll into target processes, captures Win32/NT API calls in
// real time, and displays them with parameters, return values, timestamps, and
// call stacks. Features a tree-based API selector (organized by DLL and category),
// multi-process monitoring with child process following, profile save/load for
// API selections, and CSV/JSON export.
//
// Split into partial classes:
//   - ApiMonPanel.cs            - Core fields, constructor, layout
//   - ApiMonPanel.CaptureView.cs - Capture list population and rendering
//   - ApiMonPanel.DetailView.cs  - Parameter/stack detail display
//   - ApiMonPanel.FilterTree.cs  - API selection tree and search
//   - ApiMonPanel.MenuActions.cs - Toolbar and context menu handlers
// </summary>
// </file>

using System.Collections.Concurrent;
using Nexus.UI.Core;
using Nexus.UI.Forms;
using Nexus.UI.Models;
using Nexus.UI.Services;
using Nexus.UI.Styles;

namespace Nexus.UI.Panels;

/// <summary>
/// API Monitor panel for intercepting and analyzing Win32/NT API calls in target processes.
/// <para>
/// The left pane contains a tree view of available APIs organized by DLL and category,
/// loaded from API Monitor XML definition files. Users check the APIs they want to monitor.
/// The main pane shows a scrollable list of captured calls with timing, thread ID, API name,
/// parameters, and return value. A detail panel below shows full parameter data, hex dumps,
/// and call stack for the selected event.
/// </para>
/// <para>
/// Supports monitoring multiple processes simultaneously via separate
/// <see cref="ApiMonitorService"/> instances, with automatic child process detection.
/// </para>
/// </summary>
public partial class ApiMonPanel : ShellPanel
{
    #region Fields

    // Event data
    private readonly ConcurrentQueue<ApiCallEvent> _eventQueue = new();
    private readonly List<ApiCallEvent> _events = [];
    private readonly object _eventsLock = new();
    private int _maxEvents = 1000000;

    // API definitions
    private List<ApiModuleGroup> _moduleGroups = [];
    private readonly HashSet<string> _selectedApis = new(StringComparer.OrdinalIgnoreCase);

    // Filters
    private bool _autoScroll = true;
    private bool _isCapturing;
    private string _treeSearchText = "";

    // Multi-process service management
    private readonly Dictionary<int, ApiMonitorService> _monitorServices = [];
    private readonly Dictionary<int, IntPtr> _openedHandles = []; // handles we opened (need to close)
    private List<ApiDefinition>? _resolvedApis; // cached for reuse across processes

    // UI Controls - Toolbar
    private readonly Button _btnStartStop;
    private readonly Button _btnClear;
    private readonly Button _btnSave;
    private readonly Button _btnWatchlist;
    private readonly CheckBox _chkAutoScroll;
    private readonly Label _eventCountLabel;

    // UI Controls - Tree
    private readonly TreeView _apiTree;
    private readonly TextBox _treeSearchBox;
    private readonly Button _btnSelectAll;
    private readonly Button _btnSelectNone;
    private readonly Button _btnSaveProfile;
    private readonly Button _btnLoadProfile;

    // UI Controls - Capture ListView
    private readonly ListView _captureList;

    // UI Controls - Detail panel
    private readonly TabControl _detailTabs;
    private readonly ListView _parameterList;
    private readonly TextBox _hexDumpBox;
    private readonly ListView _callStackList;

    // UI Controls - Status
    private readonly Label _statusLabel;

    // Timer
    private readonly System.Windows.Forms.Timer _updateTimer;

    // Module color palette for owner-draw
    private static readonly Dictionary<string, Color> _moduleColors = new(StringComparer.OrdinalIgnoreCase)
    {
        { "kernel32.dll", Color.FromArgb(156, 220, 254) },
        { "ntdll.dll", Color.FromArgb(220, 220, 170) },
        { "advapi32.dll", Color.FromArgb(214, 157, 133) },
        { "ws2_32.dll", Color.FromArgb(78, 201, 176) },
        { "wininet.dll", Color.FromArgb(184, 215, 163) },
        { "user32.dll", Color.FromArgb(197, 134, 192) },
        { "gdi32.dll", Color.FromArgb(255, 165, 0) },
        { "ole32.dll", Color.FromArgb(255, 105, 180) },
        { "crypt32.dll", Color.FromArgb(100, 200, 255) },
    };

    private static readonly Color DefaultModuleColor = Color.FromArgb(204, 204, 204);

    #endregion

    #region Constructor

    public ApiMonPanel()
    {
        Text = "API Monitor";
        BackColor = NexusTheme.BackgroundPanel;
        Padding = new Padding(0);

        // === Toolbar ===
        var toolbar = new FlowLayoutPanel
        {
            Dock = DockStyle.Top,
            Height = 44,
            BackColor = NexusTheme.BackgroundHeader,
            Padding = new Padding(4),
            WrapContents = false
        };

        _btnStartStop = new Button { Text = "Start" };
        NexusTheme.StylePrimaryButton(_btnStartStop);
        _btnStartStop.Click += BtnStartStop_Click;

        _btnClear = new Button { Text = "Clear" };
        NexusTheme.StyleButton(_btnClear);
        _btnClear.Click += BtnClear_Click;

        _btnSave = new Button { Text = "Save" };
        NexusTheme.StyleButton(_btnSave);
        _btnSave.Click += BtnSave_Click;
        new ToolTip().SetToolTip(_btnSave, "Save captured events to JSON or CSV");

        _btnWatchlist = new Button { Text = "Watchlist..." };
        NexusTheme.StyleButton(_btnWatchlist);
        _btnWatchlist.Click += (s, e) =>
        {
            using var form = new ProcessWatchlistForm();
            form.ShowDialog(this);
        };
        new ToolTip().SetToolTip(_btnWatchlist,
            "Manage the API Monitor process watchlist (separate from debugger Auto Attach). " +
            "Add EAAntiCheat.GameService.exe here for the kernel-APC inject path.");

        _chkAutoScroll = new CheckBox
        {
            Text = "Auto-scroll",
            AutoSize = true,
            ForeColor = NexusTheme.TextPrimary,
            Checked = true,
            Margin = new Padding(16, 4, 0, 0)
        };
        _chkAutoScroll.CheckedChanged += (s, e) => _autoScroll = _chkAutoScroll.Checked;

        _eventCountLabel = new Label
        {
            Text = "Events: 0",
            AutoSize = true,
            ForeColor = NexusTheme.TextSecondary,
            Margin = new Padding(16, 6, 0, 0)
        };

        toolbar.Controls.AddRange([_btnStartStop, _btnClear, _btnSave, _btnWatchlist, _chkAutoScroll, _eventCountLabel]);

        // === Main split: Tree (left) | Results+Detail (right) ===
        var mainSplit = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Orientation = Orientation.Vertical,
            Panel1MinSize = 25,
            Panel2MinSize = 25,
            BackColor = NexusTheme.BackgroundPanel
        };
        // Defer SplitterDistance until the control has a real width
        mainSplit.Layout += (s, ev) =>
        {
            if (mainSplit.Width > 400 && mainSplit.SplitterDistance < 200)
                mainSplit.SplitterDistance = Math.Min(280, mainSplit.Width - 100);
        };

        // === Left panel: API Filter Tree ===
        var treePanel = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = NexusTheme.BackgroundControl,
        };

        _treeSearchBox = new TextBox
        {
            Dock = DockStyle.Top,
            Height = 28,
            PlaceholderText = "Search APIs...",
        };
        NexusTheme.StyleTextBox(_treeSearchBox);
        _treeSearchBox.TextChanged += TreeSearchBox_TextChanged;

        var treeButtonPanel = new FlowLayoutPanel
        {
            Dock = DockStyle.Top,
            Height = 30,
            BackColor = NexusTheme.BackgroundHeader,
            Padding = new Padding(2),
            WrapContents = false
        };

        _btnSelectAll = new Button { Text = "All", Width = 40, Height = 24 };
        NexusTheme.StyleButton(_btnSelectAll);
        _btnSelectAll.Click += BtnSelectAll_Click;

        _btnSelectNone = new Button { Text = "None", Width = 46, Height = 24 };
        NexusTheme.StyleButton(_btnSelectNone);
        _btnSelectNone.Click += BtnSelectNone_Click;

        _btnSaveProfile = new Button { Text = "Save", Width = 44, Height = 24 };
        NexusTheme.StyleButton(_btnSaveProfile);
        _btnSaveProfile.Click += BtnSaveProfile_Click;
        new ToolTip().SetToolTip(_btnSaveProfile, "Save current API selection as a profile");

        _btnLoadProfile = new Button { Text = "Load", Width = 44, Height = 24 };
        NexusTheme.StyleButton(_btnLoadProfile);
        _btnLoadProfile.Click += BtnLoadProfile_Click;
        new ToolTip().SetToolTip(_btnLoadProfile, "Load a saved API selection profile");

        treeButtonPanel.Controls.AddRange([_btnSelectAll, _btnSelectNone, _btnSaveProfile, _btnLoadProfile]);

        _apiTree = new TreeView
        {
            Dock = DockStyle.Fill,
            CheckBoxes = true,
            BackColor = NexusTheme.BackgroundControl,
            ForeColor = NexusTheme.TextPrimary,
            BorderStyle = BorderStyle.None,
            Font = new Font("Segoe UI", 9f),
            ShowLines = true,
            ShowPlusMinus = true,
            ShowRootLines = true,
            HideSelection = false,
            PathSeparator = "/"
        };
        NexusTheme.StyleTreeView(_apiTree);
        _apiTree.AfterCheck += ApiTree_AfterCheck;

        // Order matters: Dock.Fill first, then Top in reverse order
        treePanel.Controls.Add(_apiTree);
        treePanel.Controls.Add(treeButtonPanel);
        treePanel.Controls.Add(_treeSearchBox);

        mainSplit.Panel1.Controls.Add(treePanel);

        // === Right panel: Results (top) + Detail (bottom) ===
        var resultDetailSplit = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Orientation = Orientation.Horizontal,
            Panel1MinSize = 25,
            Panel2MinSize = 25,
            BackColor = NexusTheme.BackgroundPanel
        };
        resultDetailSplit.Layout += (s, ev) =>
        {
            if (resultDetailSplit.Height > 300 && resultDetailSplit.SplitterDistance < 150)
                resultDetailSplit.SplitterDistance = (int)(resultDetailSplit.Height * 0.65);
        };

        // Capture ListView (virtual + owner-draw)
        _captureList = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = false,
            VirtualMode = true,
            BackColor = NexusTheme.BackgroundControl,
            ForeColor = NexusTheme.TextPrimary,
            BorderStyle = BorderStyle.None,
            Font = new Font("Consolas", 9f),
            OwnerDraw = true
        };

        _captureList.Columns.AddRange([
            new ColumnHeader { Text = "#", Width = 50 },
            new ColumnHeader { Text = "Time", Width = 85 },
            new ColumnHeader { Text = "Process", Width = 120 },
            new ColumnHeader { Text = "TID", Width = 55 },
            new ColumnHeader { Text = "Module", Width = 100 },
            new ColumnHeader { Text = "Function", Width = 150 },
            new ColumnHeader { Text = "Parameters", Width = 300 },
            new ColumnHeader { Text = "Return", Width = 90 },
            new ColumnHeader { Text = "Duration", Width = 70 }
        ]);

        _captureList.RetrieveVirtualItem += CaptureList_RetrieveVirtualItem;
        _captureList.DrawColumnHeader += CaptureList_DrawColumnHeader;
        _captureList.DrawSubItem += CaptureList_DrawSubItem;
        _captureList.SelectedIndexChanged += CaptureList_SelectedIndexChanged;

        resultDetailSplit.Panel1.Controls.Add(_captureList);

        // Detail TabControl
        _detailTabs = new TabControl
        {
            Dock = DockStyle.Fill,
            Font = new Font("Segoe UI", 9f),
        };
        NexusTheme.StyleTabControl(_detailTabs);

        // Parameters tab
        var paramTab = new TabPage("Parameters");
        paramTab.BackColor = NexusTheme.BackgroundControl;
        _parameterList = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = false,
            BackColor = NexusTheme.BackgroundControl,
            ForeColor = NexusTheme.TextPrimary,
            BorderStyle = BorderStyle.None,
            Font = new Font("Consolas", 9f)
        };
        _parameterList.Columns.AddRange([
            new ColumnHeader { Text = "Direction", Width = 60 },
            new ColumnHeader { Text = "Name", Width = 140 },
            new ColumnHeader { Text = "Type", Width = 160 },
            new ColumnHeader { Text = "Value", Width = 400 }
        ]);
        NexusTheme.StyleListView(_parameterList);
        paramTab.Controls.Add(_parameterList);

        // Hex Buffer tab
        var hexTab = new TabPage("Hex Buffer");
        hexTab.BackColor = NexusTheme.BackgroundControl;
        _hexDumpBox = new TextBox
        {
            Dock = DockStyle.Fill,
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Both,
            Font = new Font("Consolas", 9f),
            BackColor = NexusTheme.BackgroundControl,
            ForeColor = NexusTheme.TextPrimary,
            BorderStyle = BorderStyle.None,
            WordWrap = false
        };
        hexTab.Controls.Add(_hexDumpBox);

        // Call Stack tab
        var stackTab = new TabPage("Call Stack");
        stackTab.BackColor = NexusTheme.BackgroundControl;
        _callStackList = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = false,
            BackColor = NexusTheme.BackgroundControl,
            ForeColor = NexusTheme.TextPrimary,
            BorderStyle = BorderStyle.None,
            Font = new Font("Consolas", 9f)
        };
        _callStackList.Columns.AddRange([
            new ColumnHeader { Text = "#", Width = 40 },
            new ColumnHeader { Text = "Address", Width = 140 },
            new ColumnHeader { Text = "Module", Width = 140 },
            new ColumnHeader { Text = "Function", Width = 300 }
        ]);
        NexusTheme.StyleListView(_callStackList);
        stackTab.Controls.Add(_callStackList);

        _detailTabs.TabPages.AddRange([paramTab, hexTab, stackTab]);
        resultDetailSplit.Panel2.Controls.Add(_detailTabs);

        mainSplit.Panel2.Controls.Add(resultDetailSplit);

        // === Status bar ===
        _statusLabel = new Label
        {
            Dock = DockStyle.Bottom,
            Height = 24,
            BackColor = NexusTheme.BackgroundHeader,
            ForeColor = NexusTheme.TextSecondary,
            TextAlign = ContentAlignment.MiddleLeft,
            Padding = new Padding(4, 0, 0, 0),
            Text = "Loading API definitions..."
        };

        // === Update timer ===
        _updateTimer = new System.Windows.Forms.Timer { Interval = 100 };
        _updateTimer.Tick += UpdateTimer_Tick;

        // === Add controls (Fill first, then edges) ===
        Controls.Add(mainSplit);
        Controls.Add(_statusLabel);
        Controls.Add(toolbar);

        // Load definitions on a background thread
        _ = Task.Run(() =>
        {
            try
            {
                var apiDir = ApiDefinitionLoader.FindApiDirectory();
                if (apiDir == null)
                {
                    BeginInvoke(() => _statusLabel.Text =
                        "API definition XMLs not found - ensure 'reference material/api-monitor-apis/' exists in the repo root");
                    return;
                }

                _moduleGroups = ApiDefinitionLoader.LoadAll(apiDir);

                if (_moduleGroups.Count == 0)
                {
                    BeginInvoke(() => _statusLabel.Text = $"No API definitions parsed from {apiDir}");
                    return;
                }

                BeginInvoke(PopulateTree);
            }
            catch (Exception ex)
            {
                BeginInvoke(() => _statusLabel.Text = $"Failed to load API definitions: {ex.Message}");
            }
        });
    }

    #endregion

    #region Panel Overrides

    public override string PanelId => "ApiMon";
    public override string PanelDisplayName => "API Monitor";

    public override ToolStripMenuItem[]? GetPanelMenus()
    {
        var captureMenu = new ToolStripMenuItem("&Capture");
        captureMenu.DropDownItems.AddRange([
            new ToolStripMenuItem("&Start/Stop", null, (s, e) => ToggleCapture()) { ShortcutKeys = Keys.Control | Keys.E },
            new ToolStripMenuItem("&Clear events", null, (s, e) => ClearEvents()) { ShortcutKeys = Keys.Control | Keys.X },
            new ToolStripSeparator(),
            new ToolStripMenuItem("&Auto scroll", null, (s, e) => ToggleAutoScroll()) { Checked = _autoScroll, CheckOnClick = true },
            new ToolStripSeparator(),
            new ToolStripMenuItem("&Save to JSON...", null, (s, e) => SaveEventsToJson()) { ShortcutKeys = Keys.Control | Keys.S },
            new ToolStripMenuItem("Save to &CSV...", null, (s, e) => SaveEventsToCsv()),
        ]);

        var profileMenu = new ToolStripMenuItem("&Profile");
        profileMenu.DropDownItems.AddRange([
            new ToolStripMenuItem("&Select All APIs", null, (s, e) => SelectAllApis()),
            new ToolStripMenuItem("&Deselect All APIs", null, (s, e) => DeselectAllApis()),
            new ToolStripSeparator(),
            new ToolStripMenuItem("&Save Profile...", null, (s, e) => SaveProfile()),
            new ToolStripMenuItem("&Load Profile...", null, (s, e) => LoadProfile()),
        ]);

        return [captureMenu, profileMenu];
    }

    protected override void OnProcessAttached(object? sender, ProcessAttachedEventArgs e)
    {
        base.OnProcessAttached(sender, e);
        _statusLabel.Text = $"Process attached: {e.ProcessName} (PID: {e.ProcessId}) - Select APIs and click Start";
    }

    protected override void OnProcessDetached(object? sender, ProcessDetachedEventArgs e)
    {
        base.OnProcessDetached(sender, e);

        // Don't stop if watchlist still has active processes
        if (_isCapturing && _monitorServices.Count > 1)
        {
            // Stop only the detached PID's service using the PID from event args
            // (Context.ProcessId is already cleared to 0 by the time this fires)
            if (e.ProcessId > 0)
                StopServiceForPid(e.ProcessId);
            _statusLabel.Text = "Process detached - watchlist monitoring continues";
            return;
        }

        if (_isCapturing)
            StopCapture();
        _statusLabel.Text = "Process detached";
    }

    protected override void OnHandleDestroyed(EventArgs e)
    {
        _updateTimer.Stop();
        foreach (var svc in _monitorServices.Values)
        {
            svc.StopMonitoring();
            svc.Dispose();
        }
        _monitorServices.Clear();
        // Close handles we opened
        foreach (var handle in _openedHandles.Values)
        {
            if (handle != IntPtr.Zero)
                Interop.NexusEngine.Nexus_CloseProcess(handle);
        }
        _openedHandles.Clear();
        base.OnHandleDestroyed(e);
    }

    #endregion

    #region Helpers

    private static Color GetModuleColor(string moduleName)
    {
        return _moduleColors.TryGetValue(moduleName, out var color) ? color : DefaultModuleColor;
    }

    #endregion
}
