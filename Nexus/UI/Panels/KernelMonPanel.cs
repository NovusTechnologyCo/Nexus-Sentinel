// <file>
// <summary>
// Kernel-level event monitoring panel powered by NexusKernel.sys driver callbacks.
// Captures registry reads, process creation/termination, handle operations, image loads,
// memory access events, file operations, and syscall traces. Integrates with the
// ProcessWatchlist service for automatic detection and filtering of target processes
// and kernel drivers. Provides CSV export, text filtering, and per-category toggles.
// </summary>
// </file>

using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using Nexus.UI.Core;
using Nexus.UI.Forms;
using Nexus.UI.Models;
using Nexus.UI.Providers;
using Nexus.UI.Services;
using Nexus.UI.Styles;

namespace Nexus.UI.Panels;

/// <summary>
/// Kernel monitor panel for real-time kernel callback event capture and analysis.
/// <para>
/// Communicates with NexusKernel.sys via IOCTL to receive kernel-level events including
/// registry access, process lifecycle, handle operations, image loads, memory operations,
/// file I/O, and syscall traces. Integrates with <see cref="ProcessWatchlist"/> for
/// auto-detection of watched processes and drivers.
/// </para>
/// <para>
/// Typical workflow:
/// <list type="number">
///   <item>Configure watchlist entries (e.g., eaanticheat.sys, gamelauncher.exe)</item>
///   <item>Click Start to load the kernel driver and begin capturing all events</item>
///   <item>Launch the target application; watchlist detects processes as they appear</item>
///   <item>Toggle "Watchlist Only" to filter the display to watched PIDs</item>
///   <item>Export captured events to CSV for offline analysis</item>
/// </list>
/// </para>
/// <remarks>
/// The kernel driver must be loaded via SC (Service Control Manager) if API Monitor
/// integration is also needed, since the mapper approach cannot create the device
/// object required for IOCTL communication.
/// </remarks>
/// </summary>
public partial class KernelMonPanel : ShellPanel
{
    #region Fields

    // Service
    private readonly KernelMonitorService _service = new();
    private bool _isMonitoring;

    // Event data
    private readonly ConcurrentQueue<KernelMonEvent> _pendingQueue = new();
    private readonly List<KernelMonEvent> _events = [];
    private readonly object _eventsLock = new();
    private int _maxEvents = 200000;

    // Filter state
    private bool _showRegistry = true;
    private bool _showProcess = true;
    private bool _showHandle = true;
    private bool _showImageLoad = true;
    private bool _showMemory;
    private bool _showFile;
    private bool _showSyscall = true;
    private string _filterText = "";
    private bool _autoScroll = true;
    private bool _watchlistOnly;

    // Watchlist integration
    private readonly HashSet<uint> _watchlistPids = [];
    private readonly HashSet<string> _watchlistDriverNames = new(StringComparer.OrdinalIgnoreCase);

    // UI Controls
    private readonly ListView _eventList;
    private readonly TextBox _filterBox;
    private readonly TextBox _pidBox;
    private readonly CheckBox _chkRegistry;
    private readonly CheckBox _chkProcess;
    private readonly CheckBox _chkHandle;
    private readonly CheckBox _chkImageLoad;
    private readonly CheckBox _chkMemory;
    private readonly CheckBox _chkFile;
    private readonly CheckBox _chkSyscall;
    private readonly CheckBox _chkAutoScroll;
    private readonly CheckBox _chkWatchlistOnly;
    private readonly CheckBox _chkAutoStart;
    private readonly Button _btnConnect;
    private readonly Button _btnStartStop;
    private readonly Button _btnClear;
    private readonly Button _btnExport;
    private readonly Button _btnWatchlist;
    private readonly Label _statusLabel;
    private readonly Panel _detailPanel;
    private readonly TextBox _detailText;
    private readonly System.Windows.Forms.Timer _updateTimer;

    // Filtered view
    private readonly List<int> _filteredIndices = [];
    private bool _filterDirty = true;
    private uint _filterPid; // manual PID filter (from textbox, 0=all)

    // PID -> process name cache
    private readonly ConcurrentDictionary<uint, string> _processNames = new();

    // Colors for event types
    private static readonly Dictionary<KernelMonEventType, Color> EventColors = new()
    {
        { KernelMonEventType.Registry, Color.FromArgb(220, 220, 170) },     // beige
        { KernelMonEventType.Process, Color.FromArgb(214, 157, 133) },      // salmon
        { KernelMonEventType.Handle, Color.FromArgb(78, 201, 176) },        // teal
        { KernelMonEventType.ImageLoad, Color.FromArgb(184, 215, 163) },    // light green
        { KernelMonEventType.Memory, Color.FromArgb(255, 165, 0) },         // orange
        { KernelMonEventType.File, Color.FromArgb(156, 220, 254) },         // light blue
        { KernelMonEventType.Syscall, Color.FromArgb(197, 134, 192) },      // purple
    };

    #endregion

    #region Constructor

    public KernelMonPanel()
    {
        Text = "Kernel Monitor";
        BackColor = NexusTheme.BackgroundPanel;
        Padding = new Padding(0);

        // Toolbar
        var toolbar = new FlowLayoutPanel
        {
            Dock = DockStyle.Top,
            Height = 70,
            BackColor = NexusTheme.BackgroundHeader,
            Padding = new Padding(4),
            WrapContents = true
        };

        // Row 1: Connect, Start/Stop, Watchlist, Clear, Export, PID filter, Search
        _btnConnect = new Button { Text = "Connect \u25BC", Width = 110 };
        NexusTheme.StyleButton(_btnConnect);
        _btnConnect.Click += BtnConnect_Click;

        _btnStartStop = new Button { Text = "Start" };
        NexusTheme.StylePrimaryButton(_btnStartStop);
        _btnStartStop.Click += BtnStartStop_Click;
        new ToolTip().SetToolTip(_btnStartStop, "Start monitoring. Auto-connects via SC if not connected.\nCaptures ALL events; use filters to narrow display.");

        _btnWatchlist = new Button { Text = "Watchlist..." };
        NexusTheme.StyleButton(_btnWatchlist);
        _btnWatchlist.Click += (s, e) =>
        {
            using var form = new ProcessWatchlistForm();
            form.ShowDialog(this);
        };
        new ToolTip().SetToolTip(_btnWatchlist, "Configure which processes/drivers to watch for.\nKernel Mon will highlight events from these targets.");

        _btnClear = new Button { Text = "Clear" };
        NexusTheme.StyleButton(_btnClear);
        _btnClear.Click += BtnClear_Click;

        _btnExport = new Button { Text = "Export CSV" };
        NexusTheme.StyleButton(_btnExport);
        _btnExport.Click += BtnExport_Click;

        var pidLabel = new Label
        {
            Text = "PID:",
            AutoSize = true,
            ForeColor = NexusTheme.TextPrimary,
            Margin = new Padding(12, 6, 2, 0)
        };

        _pidBox = new TextBox { Width = 65, PlaceholderText = "0=all" };
        NexusTheme.StyleTextBox(_pidBox);
        _pidBox.KeyDown += (s, e) =>
        {
            if (e.KeyCode == Keys.Enter)
            {
                e.SuppressKeyPress = true;
                ApplyPidFilter();
            }
        };

        var filterLabel = new Label
        {
            Text = "Search:",
            AutoSize = true,
            ForeColor = NexusTheme.TextPrimary,
            Margin = new Padding(12, 6, 2, 0)
        };

        _filterBox = new TextBox { Width = 160 };
        NexusTheme.StyleTextBox(_filterBox);
        _filterBox.TextChanged += (s, e) => { _filterText = _filterBox.Text; _filterDirty = true; };

        _chkAutoScroll = new CheckBox
        {
            Text = "Auto-scroll",
            AutoSize = true,
            ForeColor = NexusTheme.TextPrimary,
            Checked = true,
            Margin = new Padding(12, 4, 0, 0)
        };
        _chkAutoScroll.CheckedChanged += (s, e) => _autoScroll = _chkAutoScroll.Checked;

        _chkWatchlistOnly = new CheckBox
        {
            Text = "Watchlist Only",
            AutoSize = true,
            ForeColor = NexusTheme.Accent,
            Checked = false,
            Margin = new Padding(8, 4, 0, 0)
        };
        _chkWatchlistOnly.CheckedChanged += (s, e) => { _watchlistOnly = _chkWatchlistOnly.Checked; _filterDirty = true; };
        new ToolTip().SetToolTip(_chkWatchlistOnly, "Only show events from processes/drivers in the watchlist");

        _chkAutoStart = new CheckBox
        {
            Text = "Auto-start",
            AutoSize = true,
            ForeColor = NexusTheme.TextPrimary,
            Checked = false,
            Margin = new Padding(8, 4, 0, 0)
        };
        new ToolTip().SetToolTip(_chkAutoStart, "Auto-connect + start monitoring when this tab becomes visible.\nEnsures events are captured before target processes launch.");

        // Row 2: Event type filter checkboxes
        _chkRegistry = CreateFilterCheckbox("Registry", true, (s, e) => { _showRegistry = _chkRegistry!.Checked; _filterDirty = true; });
        _chkProcess = CreateFilterCheckbox("Process", true, (s, e) => { _showProcess = _chkProcess!.Checked; _filterDirty = true; });
        _chkHandle = CreateFilterCheckbox("Handle", true, (s, e) => { _showHandle = _chkHandle!.Checked; _filterDirty = true; });
        _chkImageLoad = CreateFilterCheckbox("ImageLoad", true, (s, e) => { _showImageLoad = _chkImageLoad!.Checked; _filterDirty = true; });
        _chkMemory = CreateFilterCheckbox("Memory", false, (s, e) => { _showMemory = _chkMemory!.Checked; _filterDirty = true; });
        _chkFile = CreateFilterCheckbox("File", false, (s, e) => { _showFile = _chkFile!.Checked; _filterDirty = true; });
        _chkSyscall = CreateFilterCheckbox("Syscall", true, (s, e) => { _showSyscall = _chkSyscall!.Checked; _filterDirty = true; });

        toolbar.Controls.AddRange([
            _btnConnect, _btnStartStop, _btnWatchlist, _btnClear, _btnExport,
            pidLabel, _pidBox, filterLabel, _filterBox, _chkAutoScroll, _chkAutoStart, _chkWatchlistOnly,
            _chkRegistry, _chkProcess, _chkHandle, _chkImageLoad, _chkMemory, _chkFile, _chkSyscall
        ]);

        // Main split: event list (top) / detail (bottom)
        var mainSplit = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Orientation = Orientation.Horizontal,
            SplitterDistance = 400,
            Panel2MinSize = 80,
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
            new ColumnHeader { Text = "PID", Width = 60 },
            new ColumnHeader { Text = "Process", Width = 120 },
            new ColumnHeader { Text = "Type", Width = 80 },
            new ColumnHeader { Text = "Operation", Width = 120 },
            new ColumnHeader { Text = "Path / Details", Width = 400 },
            new ColumnHeader { Text = "Result", Width = 80 }
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
            Text = "Ready. Click Start to begin monitoring, or configure Watchlist first."
        };

        // Update timer (UI refresh from background events)
        _updateTimer = new System.Windows.Forms.Timer { Interval = 50 };
        _updateTimer.Tick += UpdateTimer_Tick;
        _updateTimer.Start();

        // Layout
        Controls.Add(mainSplit);
        Controls.Add(_statusLabel);
        Controls.Add(toolbar);

        // Subscribe to service events
        _service.OnRegistryEvent += OnRegistryEvent;
        _service.OnProcessEvent += OnProcessEvent;
        _service.OnHandleEvent += OnHandleEvent;
        _service.OnImageLoadEvent += OnImageLoadEvent;
        _service.OnMemoryEvent += OnMemoryEvent;
        _service.OnFileEvent += OnFileEvent;
        _service.OnSyscallEvent += OnSyscallEvent;
        _service.OnError += msg => EnqueueStatus($"Error: {msg}");
        _service.OnDisconnected += () => BeginInvokeIfNeeded(() =>
        {
            _btnConnect.Text = "Connect \u25BC";
            _statusLabel.Text = "Disconnected";
        });
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

    public override string PanelId => "KernelMon";
    public override string PanelDisplayName => "Kernel Monitor";

    public override ToolStripMenuItem[]? GetPanelMenus()
    {
        var captureMenu = new ToolStripMenuItem("&Capture");

        var connectSub = new ToolStripMenuItem("&Connect");
        connectSub.DropDownItems.Add("SC (Service) - Recommended", null, (s, e) => ConnectViaSc());
        connectSub.DropDownItems.Add("Mapper (Bootkit)", null, (s, e) => ConnectViaMapper());

        captureMenu.DropDownItems.AddRange([
            connectSub,
            new ToolStripMenuItem("&Disconnect", null, (s, e) => { if (_service.IsConnected) _service.Disconnect(); }),
            new ToolStripSeparator(),
            new ToolStripMenuItem("&Start/Stop Monitoring", null, (s, e) => ToggleMonitoring()) { ShortcutKeys = Keys.Control | Keys.E },
            new ToolStripMenuItem("&Watchlist...", null, (s, e) => { using var f = new ProcessWatchlistForm(); f.ShowDialog(this); }),
            new ToolStripSeparator(),
            new ToolStripMenuItem("&Clear Events", null, (s, e) => ClearEvents()) { ShortcutKeys = Keys.Control | Keys.X },
            new ToolStripMenuItem("&Export to CSV...", null, (s, e) => ExportToCsv()) { ShortcutKeys = Keys.Control | Keys.S }
        ]);

        return [captureMenu];
    }

    protected override void OnHandleDestroyed(EventArgs e)
    {
        ProcessWatchlist.Instance.WatchlistChanged -= OnWatchlistEntriesChanged;
        StopMonitoring();
        _updateTimer.Stop();
        _service.Dispose();
        base.OnHandleDestroyed(e);
    }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        // Subscribe to watchlist changes so we can auto-start when entries are added
        ProcessWatchlist.Instance.WatchlistChanged += OnWatchlistEntriesChanged;
    }

    protected override void OnVisibleChanged(EventArgs e)
    {
        base.OnVisibleChanged(e);
        if (Visible && _chkAutoStart.Checked && !_isMonitoring)
        {
            TryAutoStart();
        }
    }

    /// <summary>
    /// When watchlist entries change and auto-start is on, begin monitoring.
    /// </summary>
    private void OnWatchlistEntriesChanged(object? sender, EventArgs e)
    {
        if (!IsHandleCreated || IsDisposed) return;
        if (InvokeRequired) { BeginInvoke(() => OnWatchlistEntriesChanged(sender, e)); return; }

        if (_chkAutoStart.Checked && !_isMonitoring && ProcessWatchlist.Instance.Entries.Count > 0)
        {
            TryAutoStart();
        }
    }

    /// <summary>
    /// Auto-connect via SC and start monitoring if conditions are met.
    /// Called when the panel becomes visible or when watchlist entries are added.
    /// </summary>
    private void TryAutoStart()
    {
        var watchlist = ProcessWatchlist.Instance;
        if (watchlist.Entries.Count == 0)
        {
            _statusLabel.Text = "Auto-start: No watchlist entries. Configure watchlist first.";
            return;
        }

        if (_isMonitoring) return;

        // Auto-connect via SC if not connected
        if (!_service.IsConnected)
        {
            string driverPath = FindDriverPath();
            if (string.IsNullOrEmpty(driverPath))
            {
                _statusLabel.Text = "Auto-start: NexusKernel.sys not found. Build it first.";
                return;
            }

            _statusLabel.Text = "Auto-start: Loading NexusKernel.sys via SC...";
            Application.DoEvents();

            string? error = _service.ConnectViaSc(driverPath);
            if (error != null)
            {
                string shortError;
                if (error.Contains("577")) shortError = "DSE enabled - driver must be signed, or enable test signing";
                else if (error.Contains("1275")) shortError = "Driver blocked (HVCI?) - check Event Viewer";
                else if (error.Contains("STOPPED")) shortError = "DriverEntry failed - check Event Viewer > System";
                else if (error.Contains("not created")) shortError = "Device not created - try: sc stop/delete NexusKernel, then retry";
                else shortError = "SC load failed - click Start for details";

                _statusLabel.Text = $"Auto-start failed: {shortError}";
                return;
            }

            _btnConnect.Text = "Disconnect";
        }

        // Start monitoring
        StartMonitoring();
    }

    #endregion

    // Event Handlers (from KernelMonitorService - background thread) -> KernelMonPanel.*.cs

    // UI Event Handlers -> KernelMonPanel.*.cs

    #region Watchlist Integration

    private void OnWatchlistProcessDiscovered(object? sender, WatchlistProcessEventArgs e)
    {
        if (!IsHandleCreated || IsDisposed) return;
        if (InvokeRequired) { BeginInvoke(() => OnWatchlistProcessDiscovered(sender, e)); return; }

        _watchlistPids.Add((uint)e.ProcessId);
        _processNames[(uint)e.ProcessId] = e.ProcessName;
        _filterDirty = true;

        _statusLabel.Text = $"Watchlist: Detected {e.ProcessName} (PID {e.ProcessId}) | {_watchlistPids.Count} watched PIDs | {_events.Count:N0} events";
    }

    private void OnWatchlistProcessExited(object? sender, WatchlistProcessEventArgs e)
    {
        if (!IsHandleCreated || IsDisposed) return;
        if (InvokeRequired) { BeginInvoke(() => OnWatchlistProcessExited(sender, e)); return; }

        // DON'T remove the PID from _watchlistPids - keep it so "Watchlist Only"
        // filter still shows historical events from this process after it exits.
        // PIDs are cleared on StopMonitoring() or ClearEvents().

        _statusLabel.Text = $"Watchlist: {e.ProcessName} (PID {e.ProcessId}) exited | {_watchlistPids.Count} watched PIDs | Events preserved";
    }

    private void OnWatchlistDriverLoaded(object? sender, WatchlistDriverEventArgs e)
    {
        if (!IsHandleCreated || IsDisposed) return;
        if (InvokeRequired) { BeginInvoke(() => OnWatchlistDriverLoaded(sender, e)); return; }

        _watchlistDriverNames.Add(e.Entry.Name);
        _watchlistPids.Add(4); // System PID for driver events
        _filterDirty = true;

        _statusLabel.Text = $"Watchlist: Driver {e.Entry.Name} loaded at 0x{e.Entry.DriverBase:X}";
    }

    private void OnWatchlistDriverUnloaded(object? sender, WatchlistDriverEventArgs e)
    {
        if (!IsHandleCreated || IsDisposed) return;
        if (InvokeRequired) { BeginInvoke(() => OnWatchlistDriverUnloaded(sender, e)); return; }

        // DON'T remove driver name or System PID - keep historical events visible.
        _statusLabel.Text = $"Watchlist: Driver {e.Entry.Name} unloaded | Events preserved";
    }

    #endregion

    // Timer / UI Update -> KernelMonPanel.*.cs

    // ListView Drawing -> KernelMonPanel.*.cs

    // Helpers -> KernelMonPanel.*.cs
}

#region Data Model

public enum KernelMonEventType
{
    Registry,
    Process,
    Handle,
    ImageLoad,
    Memory,
    File,
    Syscall
}

public class KernelMonEvent
{
    public int SequenceNumber { get; set; }
    public DateTime Timestamp { get; set; }
    public KernelMonEventType Type { get; set; }
    public uint ProcessId { get; set; }
    public uint ThreadId { get; set; }
    public string ProcessName { get; set; } = "";
    public string Operation { get; set; } = "";
    public string Path { get; set; } = "";
    public string Result { get; set; } = "";
    public string Details { get; set; } = "";
}

#endregion
