// <file>
// <summary>
// Process monitoring panel combining ETW (Event Tracing for Windows) system-level tracing
// with API hook-based call tracing. Captures file I/O, registry access, network activity,
// process/thread creation, and API calls in real time. Supports multi-process monitoring
// with child process following, category-based color-coded event display, text filtering,
// auto-scroll, detail panel for individual events, and CSV/JSON export.
// </summary>
// </file>

using System.Collections.Concurrent;
using Nexus.UI.Core;
using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using Nexus.UI.Services;
using Nexus.UI.Styles;

namespace Nexus.UI.Panels;

/// <summary>
/// Process monitoring panel providing Sysinternals Process Monitor-style event capture.
/// <para>
/// Combines two data sources:
/// <list type="bullet">
///   <item>ETW tracing for system-wide file, registry, network, process, and thread events</item>
///   <item>API hook injection (via NexusApiHook.dll) for detailed user-mode API call tracing</item>
/// </list>
/// Events are displayed in a scrollable list with category-based color coding, text filtering,
/// and a detail pane showing full event properties. Supports monitoring multiple PIDs
/// simultaneously with automatic child process following.
/// </para>
/// </summary>
public partial class ProcMonPanel : ShellPanel
{
    #region Fields

    // Event data
    private readonly ConcurrentQueue<ProcMonEvent> _eventQueue = new();
    private readonly List<ProcMonEvent> _events = [];
    private readonly object _eventsLock = new();
    private int _maxEvents = 100000; // Increased from 10K to 100K

    // Multi-process monitoring
    private readonly HashSet<int> _monitoredPids = [];
    private readonly Dictionary<int, string> _pidNames = [];
    private readonly Dictionary<int, int> _parentChildMap = []; // child -> parent
    private bool _followChildProcesses = true;

    // Filters
    private bool _showFileEvents = true;
    private bool _showRegistryEvents = true;
    private bool _showNetworkEvents = true;
    private bool _showProcessEvents = true;
    private bool _showThreadEvents = true;
    private bool _showApiCalls = true;
    private string _filterText = "";
    private bool _autoScroll = true;
    private bool _autoStartOnAttach = true;
    private bool _isCapturing;

    // ETW tracing
    private IntPtr _etwHandle;
    private readonly NexusEtwEvent[] _etwEventBuffer = new NexusEtwEvent[100];

    // UI Controls
    private readonly ListView _eventList;
    private readonly TextBox _filterBox;
    private readonly CheckBox _chkFile;
    private readonly CheckBox _chkRegistry;
    private readonly CheckBox _chkNetwork;
    private readonly CheckBox _chkProcess;
    private readonly CheckBox _chkThread;
    private readonly CheckBox _chkApi;
    private readonly CheckBox _chkAutoScroll;
    private readonly CheckBox _chkAutoStart;
    private readonly CheckBox _chkFollowChildren;
    private readonly Button _btnStartStop;
    private readonly Button _btnClear;
    private readonly Button _btnSave;
    private readonly Button _btnAddProcess;
    private readonly Button _btnRemoveProcess;
    private readonly ComboBox _cmbMonitoredPids;
    private readonly Label _statusLabel;
    private readonly Panel _detailPanel;
    private readonly TextBox _detailText;
    private readonly System.Windows.Forms.Timer _updateTimer;

    // Colors for event types
    private readonly Dictionary<EventCategory, Color> _categoryColors = new()
    {
        { EventCategory.File, Color.FromArgb(156, 220, 254) },
        { EventCategory.Registry, Color.FromArgb(220, 220, 170) },
        { EventCategory.Network, Color.FromArgb(78, 201, 176) },
        { EventCategory.Process, Color.FromArgb(214, 157, 133) },
        { EventCategory.Thread, Color.FromArgb(184, 215, 163) },
        { EventCategory.ApiCall, Color.FromArgb(197, 134, 192) },
        { EventCategory.Memory, Color.FromArgb(255, 165, 0) },    // Orange for memory ops
        { EventCategory.Handle, Color.FromArgb(255, 105, 180) }   // Pink for handle ops
    };

    // Kernel driver for kernel-level monitoring
    private readonly Providers.NexusKernelDriver _kernelDriver = Providers.NexusKernelDriver.Instance;
    private bool _useKernelMonitoring;
    private bool _showMemoryEvents = true;
    private bool _showHandleEvents = true;

    // Driver watchlist integration
    private readonly HashSet<string> _watchedDriverNames = new(StringComparer.OrdinalIgnoreCase);

    #endregion

    #region Constructor

    public ProcMonPanel()
    {
        Text = "ProcMon";
        BackColor = NexusTheme.BackgroundPanel;
        Padding = new Padding(0);

        // Create toolbar
        var toolbar = new FlowLayoutPanel
        {
            Dock = DockStyle.Top,
            Height = 100,
            BackColor = NexusTheme.BackgroundHeader,
            Padding = new Padding(4),
            WrapContents = true
        };

        // Row 1: Start/Stop, Clear, Filter
        _btnStartStop = new Button { Text = "Start" };
        NexusTheme.StylePrimaryButton(_btnStartStop);
        _btnStartStop.Click += BtnStartStop_Click;

        _btnClear = new Button { Text = "Clear" };
        NexusTheme.StyleButton(_btnClear);
        _btnClear.Click += BtnClear_Click;

        _btnSave = new Button { Text = "Save" };
        NexusTheme.StyleButton(_btnSave);
        _btnSave.Click += BtnSave_Click;
        new ToolTip().SetToolTip(_btnSave, "Save event log to file (JSON or CSV)");

        var filterLabel = new Label
        {
            Text = "Filter:",
            AutoSize = true,
            ForeColor = NexusTheme.TextPrimary,
            Margin = new Padding(16, 6, 4, 0)
        };

        _filterBox = new TextBox { Width = 200 };
        NexusTheme.StyleTextBox(_filterBox);
        _filterBox.TextChanged += FilterBox_TextChanged;

        _chkAutoScroll = new CheckBox
        {
            Text = "Auto-scroll",
            AutoSize = true,
            ForeColor = NexusTheme.TextPrimary,
            Checked = true,
            Margin = new Padding(16, 4, 0, 0)
        };
        _chkAutoScroll.CheckedChanged += (s, e) => _autoScroll = _chkAutoScroll.Checked;

        _chkAutoStart = new CheckBox
        {
            Text = "Auto-start",
            AutoSize = true,
            ForeColor = NexusTheme.TextPrimary,
            Checked = true,
            Margin = new Padding(8, 4, 0, 0)
        };
        _chkAutoStart.CheckedChanged += (s, e) => _autoStartOnAttach = _chkAutoStart.Checked;
        new ToolTip().SetToolTip(_chkAutoStart, "Automatically start capturing when attaching to a process");

        // Row 2: Multi-process monitoring controls
        var processLabel = new Label
        {
            Text = "Monitored:",
            AutoSize = true,
            ForeColor = NexusTheme.TextPrimary,
            Margin = new Padding(0, 6, 4, 0)
        };

        _cmbMonitoredPids = new ComboBox
        {
            Width = 180,
            DropDownStyle = ComboBoxStyle.DropDownList,
            BackColor = NexusTheme.BackgroundControl,
            ForeColor = NexusTheme.TextPrimary
        };

        _btnAddProcess = new Button { Text = "+", Width = 30 };
        NexusTheme.StyleButton(_btnAddProcess);
        _btnAddProcess.Click += BtnAddProcess_Click;
        new ToolTip().SetToolTip(_btnAddProcess, "Add process to monitor");

        _btnRemoveProcess = new Button { Text = "-", Width = 30 };
        NexusTheme.StyleButton(_btnRemoveProcess);
        _btnRemoveProcess.Click += BtnRemoveProcess_Click;
        new ToolTip().SetToolTip(_btnRemoveProcess, "Remove selected process from monitoring");

        _chkFollowChildren = new CheckBox
        {
            Text = "Follow child processes",
            AutoSize = true,
            ForeColor = NexusTheme.TextPrimary,
            Checked = true,
            Margin = new Padding(16, 4, 0, 0)
        };
        _chkFollowChildren.CheckedChanged += (s, e) => _followChildProcesses = _chkFollowChildren.Checked;
        new ToolTip().SetToolTip(_chkFollowChildren, "Automatically monitor processes spawned by monitored processes");

        // Row 3: Event type filters
        _chkFile = CreateFilterCheckbox("File", true, (s, e) => { _showFileEvents = _chkFile!.Checked; ApplyFilter(); });
        _chkRegistry = CreateFilterCheckbox("Registry", true, (s, e) => { _showRegistryEvents = _chkRegistry!.Checked; ApplyFilter(); });
        _chkNetwork = CreateFilterCheckbox("Network", true, (s, e) => { _showNetworkEvents = _chkNetwork!.Checked; ApplyFilter(); });
        _chkProcess = CreateFilterCheckbox("Process", true, (s, e) => { _showProcessEvents = _chkProcess!.Checked; ApplyFilter(); });
        _chkThread = CreateFilterCheckbox("Thread", true, (s, e) => { _showThreadEvents = _chkThread!.Checked; ApplyFilter(); });
        _chkApi = CreateFilterCheckbox("API Calls", true, (s, e) => { _showApiCalls = _chkApi!.Checked; ApplyFilter(); });

        toolbar.Controls.AddRange([
            _btnStartStop, _btnClear, _btnSave, filterLabel, _filterBox, _chkAutoScroll, _chkAutoStart,
            processLabel, _cmbMonitoredPids, _btnAddProcess, _btnRemoveProcess, _chkFollowChildren,
            _chkFile, _chkRegistry, _chkNetwork, _chkProcess, _chkThread, _chkApi
        ]);

        // Main split container
        var mainSplit = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Orientation = Orientation.Horizontal,
            SplitterDistance = 400,
            Panel2MinSize = 100,
            BackColor = NexusTheme.BackgroundPanel
        };

        // Event list
        _eventList = new ListView
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

        _eventList.Columns.AddRange([
            new ColumnHeader { Text = "#", Width = 60 },
            new ColumnHeader { Text = "Time", Width = 100 },
            new ColumnHeader { Text = "Process", Width = 140 },
            new ColumnHeader { Text = "Category", Width = 80 },
            new ColumnHeader { Text = "Operation", Width = 120 },
            new ColumnHeader { Text = "Path/Details", Width = 350 },
            new ColumnHeader { Text = "Result", Width = 80 },
            new ColumnHeader { Text = "Duration", Width = 80 }
        ]);

        _eventList.RetrieveVirtualItem += EventList_RetrieveVirtualItem;
        _eventList.DrawColumnHeader += EventList_DrawColumnHeader;
        _eventList.DrawSubItem += EventList_DrawSubItem;
        _eventList.SelectedIndexChanged += EventList_SelectedIndexChanged;

        mainSplit.Panel1.Controls.Add(_eventList);

        // Detail panel
        _detailPanel = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = NexusTheme.BackgroundControl,
            Padding = new Padding(4)
        };

        var detailLabel = new Label
        {
            Text = "Event Details",
            Dock = DockStyle.Top,
            Height = 20,
            ForeColor = NexusTheme.TextSecondary,
            Font = new Font(NexusTheme.FontFamily, 9f, FontStyle.Bold)
        };

        _detailText = new TextBox
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

        _detailPanel.Controls.Add(_detailText);
        _detailPanel.Controls.Add(detailLabel);
        mainSplit.Panel2.Controls.Add(_detailPanel);

        // Status label
        _statusLabel = new Label
        {
            Dock = DockStyle.Bottom,
            Height = 24,
            BackColor = NexusTheme.BackgroundHeader,
            ForeColor = NexusTheme.TextSecondary,
            TextAlign = ContentAlignment.MiddleLeft,
            Padding = new Padding(4, 0, 0, 0),
            Text = "Ready - Click 'Start' to begin monitoring"
        };

        // Update timer
        _updateTimer = new System.Windows.Forms.Timer { Interval = 100 };
        _updateTimer.Tick += UpdateTimer_Tick;

        // Add controls
        Controls.Add(mainSplit);
        Controls.Add(_statusLabel);
        Controls.Add(toolbar);

        // Note: ShellPanel base class already subscribes to ProcessAttached/ProcessDetached
    }

    private CheckBox CreateFilterCheckbox(string text, bool isChecked, EventHandler handler)
    {
        var chk = new CheckBox
        {
            Text = text,
            AutoSize = true,
            ForeColor = NexusTheme.TextPrimary,
            Checked = isChecked,
            Margin = new Padding(8, 4, 0, 0)
        };
        chk.CheckedChanged += handler;
        return chk;
    }

    #endregion

    #region Panel Overrides

    public override string PanelId => "ProcMon";
    public override string PanelDisplayName => "Process Monitor";

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
            new ToolStripMenuItem("Save to &Text...", null, (s, e) => SaveEventsToText())
        ]);

        var filterMenu = new ToolStripMenuItem("&Filter");
        filterMenu.DropDownItems.AddRange([
            new ToolStripMenuItem("Show &File events", null, (s, e) => { _showFileEvents = !_showFileEvents; ApplyFilter(); }) { Checked = _showFileEvents, CheckOnClick = true },
            new ToolStripMenuItem("Show &Registry events", null, (s, e) => { _showRegistryEvents = !_showRegistryEvents; ApplyFilter(); }) { Checked = _showRegistryEvents, CheckOnClick = true },
            new ToolStripMenuItem("Show &Network events", null, (s, e) => { _showNetworkEvents = !_showNetworkEvents; ApplyFilter(); }) { Checked = _showNetworkEvents, CheckOnClick = true },
            new ToolStripMenuItem("Show &Process events", null, (s, e) => { _showProcessEvents = !_showProcessEvents; ApplyFilter(); }) { Checked = _showProcessEvents, CheckOnClick = true },
            new ToolStripMenuItem("Show &Thread events", null, (s, e) => { _showThreadEvents = !_showThreadEvents; ApplyFilter(); }) { Checked = _showThreadEvents, CheckOnClick = true },
            new ToolStripMenuItem("Show &API calls", null, (s, e) => { _showApiCalls = !_showApiCalls; ApplyFilter(); }) { Checked = _showApiCalls, CheckOnClick = true },
            new ToolStripSeparator(),
            new ToolStripMenuItem("&Reset filters", null, (s, e) => ResetFilters())
        ]);

        return [captureMenu, filterMenu];
    }

    private void ToggleCapture()
    {
        if (_isCapturing) StopCapture(); else StartCapture();
    }

    private void ClearEvents()
    {
        BtnClear_Click(null, EventArgs.Empty);
    }

    private void ToggleAutoScroll()
    {
        _autoScroll = !_autoScroll;
    }

    private void ResetFilters()
    {
        _showFileEvents = true;
        _showRegistryEvents = true;
        _showNetworkEvents = true;
        _showProcessEvents = true;
        _showThreadEvents = true;
        _showApiCalls = true;
        _filterText = "";
        _filterBox.Text = "";
        ApplyFilter();
    }

    #endregion

    // Event Handlers -> ProcMonPanel.Events.cs
    // Capture Control -> ProcMonPanel.Capture.cs
    // Event Processing + Helpers + Multi-Process + Watchlist -> ProcMonPanel.Processing.cs
    }

#region Data Models

/// <summary>
/// Event categories for ProcMon.
/// </summary>
public enum EventCategory
{
    File,
    Registry,
    Network,
    Process,
    Thread,
    ApiCall,
    Memory,     // Cross-process memory operations
    Handle,     // Handle/object operations
    Syscall     // Security-sensitive syscalls (SecureBoot, CI, Debugger)
}

/// <summary>
/// Represents a captured process monitoring event.
/// </summary>
public class ProcMonEvent
{
    private static int _sequenceCounter;

    public int SequenceNumber { get; } = Interlocked.Increment(ref _sequenceCounter);
    public DateTime Timestamp { get; set; }
    public EventCategory Category { get; set; }
    public string Operation { get; set; } = "";
    public string Path { get; set; } = "";
    public string Result { get; set; } = "";
    public TimeSpan Duration { get; set; }
    public int ProcessId { get; set; }
    public int ThreadId { get; set; }
    public string ProcessName { get; set; } = "";
    public Dictionary<string, string> Details { get; set; } = [];
    public string? StackTrace { get; set; }
}

/// <summary>
/// Represents a monitored process in the ComboBox.
/// </summary>
public class MonitoredProcessItem
{
    public int ProcessId { get; }
    public string ProcessName { get; }
    public bool IsChild { get; set; }
    public int ParentPid { get; set; }

    public MonitoredProcessItem(int pid, string name)
    {
        ProcessId = pid;
        ProcessName = name;
    }

    public override string ToString()
    {
        var prefix = IsChild ? "  └─ " : "";
        return $"{prefix}{ProcessName} (PID: {ProcessId})";
    }
}

#endregion

#region Dialogs

/// <summary>
/// Dialog for selecting a process to add to monitoring.
/// </summary>
public class AddProcessDialog : Form
{
    private readonly ListView _processList;
    private readonly TextBox _filterBox;

    public int SelectedProcessId { get; private set; }
    public string SelectedProcessName { get; private set; } = "";

    public AddProcessDialog()
    {
        Text = "Add Process to Monitor";
        Size = new Size(500, 400);
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        BackColor = NexusTheme.BackgroundPanel;

        var filterLabel = new Label
        {
            Text = "Filter:",
            Location = new Point(12, 15),
            AutoSize = true,
            ForeColor = NexusTheme.TextPrimary
        };

        _filterBox = new TextBox
        {
            Location = new Point(60, 12),
            Width = 200,
            BackColor = NexusTheme.BackgroundControl,
            ForeColor = NexusTheme.TextPrimary
        };
        _filterBox.TextChanged += (s, e) => RefreshProcessList();

        _processList = new ListView
        {
            Location = new Point(12, 44),
            Size = new Size(460, 270),
            View = View.Details,
            FullRowSelect = true,
            GridLines = false,
            BackColor = NexusTheme.BackgroundControl,
            ForeColor = NexusTheme.TextPrimary,
            BorderStyle = BorderStyle.FixedSingle
        };
        _processList.Columns.AddRange([
            new ColumnHeader { Text = "PID", Width = 60 },
            new ColumnHeader { Text = "Name", Width = 200 },
            new ColumnHeader { Text = "Title", Width = 180 }
        ]);
        _processList.DoubleClick += (s, e) => SelectProcess();

        var btnOk = new Button
        {
            Text = "Add",
            DialogResult = DialogResult.OK,
            Location = new Point(316, 325),
            Width = 75
        };
        NexusTheme.StylePrimaryButton(btnOk);
        btnOk.Click += (s, e) => SelectProcess();

        var btnCancel = new Button
        {
            Text = "Cancel",
            DialogResult = DialogResult.Cancel,
            Location = new Point(397, 325),
            Width = 75
        };
        NexusTheme.StyleButton(btnCancel);

        Controls.AddRange([filterLabel, _filterBox, _processList, btnOk, btnCancel]);

        AcceptButton = btnOk;
        CancelButton = btnCancel;

        RefreshProcessList();
    }

    private void RefreshProcessList()
    {
        _processList.Items.Clear();
        var filter = _filterBox.Text.ToLowerInvariant();

        try
        {
            foreach (var proc in System.Diagnostics.Process.GetProcesses().OrderBy(p => p.ProcessName))
            {
                try
                {
                    var name = proc.ProcessName;
                    var title = "";
                    try { title = proc.MainWindowTitle; } catch { }

                    if (!string.IsNullOrEmpty(filter))
                    {
                        if (!name.Contains(filter, StringComparison.OrdinalIgnoreCase) &&
                            !proc.Id.ToString().Contains(filter) &&
                            !title.Contains(filter, StringComparison.OrdinalIgnoreCase))
                            continue;
                    }

                    var item = new ListViewItem([proc.Id.ToString(), name, title])
                    {
                        Tag = proc.Id
                    };
                    _processList.Items.Add(item);
                }
                catch
                {
                    // Skip processes we can't access
                }
            }
        }
        catch
        {
            // Handle enumeration errors
        }
    }

    private void SelectProcess()
    {
        if (_processList.SelectedItems.Count == 0) return;

        var item = _processList.SelectedItems[0];
        SelectedProcessId = (int)item.Tag!;
        SelectedProcessName = item.SubItems[1].Text;
        DialogResult = DialogResult.OK;
    }
}

#endregion
