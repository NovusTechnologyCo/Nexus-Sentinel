// <file>
// <summary>
// Main application shell window for Nexus Sentinel.
// Hosts the tab-based module navigation system, toolbar, menu bar, status bar,
// and coordinates process attachment, provider switching, plugin loading, and
// auto-attach functionality. This is the top-level form created at startup.
// </summary>
// </file>

using System.Runtime.InteropServices;
using System.Text;
using Nexus.UI.Core;
using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using Nexus.UI.Panels;
using Nexus.UI.Plugins;
using Nexus.UI.Providers;
using Nexus.UI.Services;
using Nexus.UI.Styles;

namespace Nexus.UI.Forms;

/// <summary>
/// Main application shell window providing the top-level UI container for Nexus Sentinel.
/// <para>
/// ShellForm manages the overall application layout including:
/// <list type="bullet">
///   <item>Tab bar for switching between module panels (Scanner, Debugger, Structures, ProcMon, API Monitor, Kernel Monitor)</item>
///   <item>Context toolbar with quick-access buttons for common operations</item>
///   <item>Menu bar with File, View, Debug, Tools, Plugins, Provider, Settings, and Help menus</item>
///   <item>Status bar showing attached process info, current provider, and elevation status</item>
///   <item>Process attachment and detachment lifecycle</item>
///   <item>Provider switching between User Mode, Kernel Mode, and Hypervisor access levels</item>
///   <item>Auto-attach by process name or window title</item>
///   <item>Plugin system initialization and management</item>
/// </list>
/// </para>
/// </summary>
public partial class ShellForm : Form
{
    private ToolStrip _toolbar = null!;
    private ToolStrip _tabBar = null!;
    private Panel _contentPanel = null!;
    private readonly ToolStripStatusLabel _statusLabel;
    private readonly ToolStripStatusLabel _processLabel;
    private readonly ToolStripStatusLabel _providerLabel;
    private readonly ToolStripStatusLabel _elevationLabel;
    private ToolStripMenuItem _pluginsMenu = null!;

    // Toolbar buttons that need state updates
    private ToolStripButton _attachBtn = null!;
    private ToolStripButton _detachBtn = null!;
    private ToolStripButton _memoryViewerBtn = null!;
    private ToolStripButton _processInspectorBtn = null!;
    private ToolStripButton _pointerScanBtn = null!;
    private ToolStripButton _structuresBtn = null!;
    private ToolStripButton _scriptsBtn = null!;

    // Menu items that need state updates
    private ToolStripMenuItem _menuOpenProcess = null!;
    private ToolStripMenuItem _menuDetach = null!;
    private ToolStripMenuItem _menuCloseProcess = null!;
    private ToolStripMenuItem _menuMemoryViewer = null!;
    private ToolStripMenuItem _menuProcessInspector = null!;
    private ToolStripMenuItem _menuMemoryMap = null!;
    private ToolStripMenuItem _menuAttachDebugger = null!;
    private ToolStripMenuItem _menuDebugger = null!;
    private ToolStripMenuItem _menuPointerScanner = null!;
    private ToolStripMenuItem _menuStructureDissector = null!;
    private ToolStripMenuItem _menuCodeCaveScanner = null!;
    private ToolStripMenuItem _menuScriptEditor = null!;
    private ToolStripMenuItem _menuSpeedhack = null!;

    // Tab bar buttons
    private ToolStripButton _tabScanner = null!;
    private ToolStripButton _tabDebugger = null!;
    private ToolStripButton _tabStructures = null!;
    private ToolStripButton _tabProcMon = null!;
    private ToolStripButton _tabApiMon = null!;
    private ToolStripButton _tabKernelMon = null!;

    // Panel instances
    private MemoryScannerPanel? _scannerPanel;
    private DebuggerLayoutPanel? _debuggerLayoutPanel;
    private StructuresPanel? _structuresPanel;
    private ProcMonPanel? _procMonPanel;
    private ApiMonPanel? _apiMonPanel;
    private KernelMonPanel? _kernelMonPanel;

    // Legacy process handle for forms that need it
    private IntPtr _processHandle;
    private uint _attachedPid;

    // Auto-attach pause state (set when user manually detaches)
    private bool _autoAttachPaused;
    private ToolStripMenuItem _menuResumeAutoAttach = null!;

    // Panel menu tracking
    private ToolStripMenuItem[]? _currentPanelMenus;
    private int _panelMenuInsertIndex; // Index where panel menus are inserted (before Help)

    // Plugin system
    private PluginLoader? _pluginLoader;
    private PluginHost? _pluginHost;

    // Cached fonts for tab switching (avoid GDI leak from creating new Font on every switch)
    private Font? _tabFontNormal;
    private Font? _tabFontBold;

    // Provider selection
    private ToolStripMenuItem _menuProviderUserMode = null!;
    private ToolStripMenuItem _menuProviderKernel = null!;
    private ToolStripMenuItem _menuProviderHypervisor = null!;
    private ToolStripDropDownButton _providerDropdown = null!;
    private ProviderPrivilege _currentProviderLevel = ProviderPrivilege.UserMode;

    // P/Invoke for window enumeration (used by auto-attach by window title)
    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

    [DllImport("user32.dll")]
    private static extern int GetWindowTextLength(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);

    public ShellForm()
    {
        InitializeComponent();

        // Create status bar
        var statusStrip = new StatusStrip
        {
            BackColor = NexusTheme.BackgroundDark,
            ForeColor = NexusTheme.TextPrimary,
            SizingGrip = false
        };
        _statusLabel = new ToolStripStatusLabel
        {
            Spring = true,
            TextAlign = ContentAlignment.MiddleLeft,
            ForeColor = NexusTheme.TextSecondary
        };
        _processLabel = new ToolStripStatusLabel
        {
            BorderSides = ToolStripStatusLabelBorderSides.Left,
            ForeColor = NexusTheme.TextPrimary
        };
        _providerLabel = new ToolStripStatusLabel
        {
            BorderSides = ToolStripStatusLabelBorderSides.Left,
            ForeColor = NexusTheme.Accent
        };
        _elevationLabel = new ToolStripStatusLabel
        {
            BorderSides = ToolStripStatusLabelBorderSides.Left,
            Text = ElevationHelper.IsElevated ? "Administrator" : "User",
            ForeColor = ElevationHelper.IsElevated ? NexusTheme.Success : NexusTheme.TextSecondary,
            ToolTipText = ElevationHelper.IsElevated
                ? "Running with administrator privileges"
                : "Running as standard user - some features may be limited"
        };
        _elevationLabel.Click += ElevationLabel_Click;
        statusStrip.Items.AddRange([_statusLabel, _processLabel, _providerLabel, _elevationLabel]);

        // Create toolbar
        _toolbar = CreateToolbar();

        // Create tab bar (second toolbar for module switching)
        _tabBar = CreateTabBar();

        // Create content panel for module panels
        _contentPanel = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = NexusTheme.BackgroundPanel,
            Padding = new Padding(NexusTheme.Space8)
        };

        // Clear all controls and add in correct order
        // WinForms dock rules:
        // - Controls are docked in reverse z-order (last added docks last)
        // - Dock.Fill should be added FIRST so it fills remaining space after others dock
        // - Dock.Top: added in reverse visual order (topmost added last)

        var menuStrip = MainMenuStrip!;
        Controls.Clear();

        // Add order: Fill first, then edges
        // Visual order: Menu -> TabBar -> Toolbar (context) -> Content -> StatusBar
        Controls.Add(_contentPanel); // Fill - FIRST (will fill remaining space)
        Controls.Add(statusStrip);   // Bottom
        Controls.Add(_toolbar);      // Top - context toolbar (below tab bar)
        Controls.Add(_tabBar);       // Top - tab bar (below menu)
        Controls.Add(menuStrip);     // Top - topmost
        MainMenuStrip = menuStrip;

        // Subscribe to events
        ProcessContext.Current.ProcessAttached += OnProcessAttached;
        ProcessContext.Current.ProcessDetached += OnProcessDetached;
        ProcessContext.Current.ProviderChanged += OnProviderChanged;
        EventBus.Instance.Subscribe<StatusUpdateEvent>(OnStatusUpdate);
        EventBus.Instance.Subscribe<NavigateToAddressEvent>(OnNavigateToAddress);

        // Apply theme
        NexusTheme.ApplyTo(this);

        // Initialize UI
        UpdateTitle();
        UpdateProcessStatus();
        UpdateProviderStatus();
        UpdateToolbarState();

        // Create module panels and show default
        CreateModulePanels();
        SwitchToModule(0); // Show scanner by default

        UpdateStatus("Ready - Use File > Open Process to attach to a process", StatusType.Info);

        // Initialize auto-attach (subscribes to settings changes)
        InitializeAutoAttach();

        // Initialize plugin system
        InitializePluginSystem();

        // Restore process watchlist from settings
        ProcessWatchlist.Instance.RestoreFromSettings();
    }

    // Auto-Attach -> ShellForm.*.cs

    private ToolStrip CreateToolbar()
    {
        var toolbar = new ToolStrip
        {
            Dock = DockStyle.Top,
            GripStyle = ToolStripGripStyle.Hidden,
            Padding = new Padding(NexusTheme.Space4, NexusTheme.Space4, NexusTheme.Space4, NexusTheme.Space4),
            AutoSize = false,
            Height = NexusTheme.ControlHeight + NexusTheme.Space16
        };
        NexusTheme.StyleToolStrip(toolbar);

        // Process section
        _attachBtn = CreateToolbarButton("Attach Process", "📎", (s, e) => OpenProcess());
        _detachBtn = CreateToolbarButton("Detach", "⏏", (s, e) => CloseProcess());
        toolbar.Items.Add(_attachBtn);
        toolbar.Items.Add(_detachBtn);
        toolbar.Items.Add(new ToolStripSeparator());

        // View section
        _memoryViewerBtn = CreateToolbarButton("Memory Viewer", "🔍", (s, e) => ShowMemoryViewer());
        _processInspectorBtn = CreateToolbarButton("Process Inspector", "📋", (s, e) => ShowProcessInspector());
        toolbar.Items.Add(_memoryViewerBtn);
        toolbar.Items.Add(_processInspectorBtn);
        toolbar.Items.Add(new ToolStripSeparator());

        // Tools section
        _pointerScanBtn = CreateToolbarButton("Pointer Scan", "🎯", (s, e) => ShowPointerScanner());
        _structuresBtn = CreateToolbarButton("Structures", "🏗", (s, e) => ShowStructureDissector());
        _scriptsBtn = CreateToolbarButton("Scripts", "📜", (s, e) => ShowScriptEditor());
        toolbar.Items.Add(_pointerScanBtn);
        toolbar.Items.Add(_structuresBtn);
        toolbar.Items.Add(_scriptsBtn);
        toolbar.Items.Add(new ToolStripSeparator());

        // Provider selection dropdown
        _providerDropdown = new ToolStripDropDownButton
        {
            Text = "⚙ User Mode",
            DisplayStyle = ToolStripItemDisplayStyle.Text,
            ForeColor = NexusTheme.Accent,
            Padding = new Padding(NexusTheme.Space8, NexusTheme.Space4, NexusTheme.Space8, NexusTheme.Space4),
            ToolTipText = "Select memory/debug provider"
        };
        _providerDropdown.DropDownItems.Add("User Mode", null, (s, e) => SetProvider(ProviderPrivilege.UserMode));
        _providerDropdown.DropDownItems.Add("Kernel Mode", null, (s, e) => SetProvider(ProviderPrivilege.Kernel));
        _providerDropdown.DropDownItems.Add("Hypervisor", null, (s, e) => SetProvider(ProviderPrivilege.Hypervisor));
        toolbar.Items.Add(_providerDropdown);

        return toolbar;
    }

    private static ToolStripButton CreateToolbarButton(string text, string emoji, EventHandler onClick)
    {
        var btn = new ToolStripButton
        {
            Text = $"{emoji} {text}",
            DisplayStyle = ToolStripItemDisplayStyle.Text,
            ForeColor = NexusTheme.TextPrimary,
            Padding = new Padding(NexusTheme.Space8, NexusTheme.Space4, NexusTheme.Space8, NexusTheme.Space4),
            Margin = new Padding(0, 0, NexusTheme.Space4, 0)
        };
        btn.Click += onClick;
        return btn;
    }

    private void UpdateToolbarState()
    {
        var hasProcess = _processHandle != IntPtr.Zero;
        const string disabledTooltip = "Attach a process first";
        const string alreadyAttachedTooltip = "Already attached to a process";

        // Attach button - disabled when already attached
        _attachBtn.Enabled = !hasProcess;
        _attachBtn.ToolTipText = hasProcess ? alreadyAttachedTooltip : "Attach to a process";
        _menuOpenProcess.Enabled = !hasProcess;
        _menuOpenProcess.ToolTipText = hasProcess ? alreadyAttachedTooltip : "";

        // Update toolbar buttons that require a process
        _detachBtn.Enabled = hasProcess;
        _memoryViewerBtn.Enabled = hasProcess;
        _processInspectorBtn.Enabled = hasProcess;
        _pointerScanBtn.Enabled = hasProcess;
        _structuresBtn.Enabled = hasProcess;
        _scriptsBtn.Enabled = hasProcess;

        // Update toolbar button tooltips
        _detachBtn.ToolTipText = hasProcess ? "Detach from process" : disabledTooltip;
        _memoryViewerBtn.ToolTipText = hasProcess ? "Open Memory Viewer" : disabledTooltip;
        _processInspectorBtn.ToolTipText = hasProcess ? "Open Process Inspector" : disabledTooltip;
        _pointerScanBtn.ToolTipText = hasProcess ? "Pointer Scanner" : disabledTooltip;
        _structuresBtn.ToolTipText = hasProcess ? "Structure Dissector" : disabledTooltip;
        _scriptsBtn.ToolTipText = hasProcess ? "Script Editor" : disabledTooltip;

        // Update menu items that require a process
        var menuItems = new ToolStripMenuItem[]
        {
            _menuCloseProcess, _menuDetach,
            _menuMemoryViewer, _menuProcessInspector, _menuMemoryMap,
            _menuAttachDebugger, _menuDebugger,
            _menuPointerScanner, _menuStructureDissector, _menuCodeCaveScanner,
            _menuScriptEditor, _menuSpeedhack
        };

        foreach (var item in menuItems)
        {
            item.Enabled = hasProcess;
            item.ToolTipText = hasProcess ? "" : disabledTooltip;
        }
    }

    private ToolStrip CreateTabBar()
    {
        var tabBar = new ToolStrip
        {
            Dock = DockStyle.Top,
            GripStyle = ToolStripGripStyle.Hidden,
            Padding = new Padding(NexusTheme.Space4, 0, NexusTheme.Space4, 0),
            AutoSize = false,
            Height = NexusTheme.ControlHeight,
            BackColor = NexusTheme.BackgroundDark
        };
        NexusTheme.StyleToolStrip(tabBar);

        _tabScanner = CreateTabButton("Memory Scanner", 0);
        _tabDebugger = CreateTabButton("Debugger", 1);
        _tabStructures = CreateTabButton("Structures", 2);
        _tabProcMon = CreateTabButton("ProcMon", 3);
        _tabApiMon = CreateTabButton("API Monitor", 4);
        _tabKernelMon = CreateTabButton("Kernel Mon", 5);

        tabBar.Items.Add(_tabScanner);
        tabBar.Items.Add(_tabDebugger);
        tabBar.Items.Add(_tabStructures);
        tabBar.Items.Add(_tabProcMon);
        tabBar.Items.Add(_tabApiMon);
        tabBar.Items.Add(_tabKernelMon);

        return tabBar;
    }

    private ToolStripButton CreateTabButton(string text, int index)
    {
        var btn = new ToolStripButton
        {
            Text = text,
            DisplayStyle = ToolStripItemDisplayStyle.Text,
            ForeColor = NexusTheme.TextSecondary,
            Padding = new Padding(NexusTheme.Space16, NexusTheme.Space4, NexusTheme.Space16, NexusTheme.Space4),
            Margin = new Padding(0, 0, NexusTheme.Space4, 0)
        };
        btn.Click += (s, e) => SwitchToModule(index);
        return btn;
    }

    /// <summary>
    /// Switches the visible module panel to the specified tab index.
    /// Updates tab bar styling, shows/hides panels, and refreshes panel-specific menus.
    /// </summary>
    /// <param name="index">Tab index: 0=Scanner, 1=Debugger, 2=Structures, 3=ProcMon, 4=API Monitor, 5=Kernel Monitor.</param>
    private void SwitchToModule(int index)
    {
        // Update tab button states
        _tabScanner.ForeColor = index == 0 ? NexusTheme.Accent : NexusTheme.TextSecondary;
        _tabDebugger.ForeColor = index == 1 ? NexusTheme.Accent : NexusTheme.TextSecondary;
        _tabStructures.ForeColor = index == 2 ? NexusTheme.Accent : NexusTheme.TextSecondary;
        _tabProcMon.ForeColor = index == 3 ? NexusTheme.Accent : NexusTheme.TextSecondary;
        _tabApiMon.ForeColor = index == 4 ? NexusTheme.Accent : NexusTheme.TextSecondary;
        _tabKernelMon.ForeColor = index == 5 ? NexusTheme.Accent : NexusTheme.TextSecondary;

        _tabFontNormal ??= new Font(_tabBar.Font.FontFamily, _tabBar.Font.Size, FontStyle.Regular);
        _tabFontBold ??= new Font(_tabBar.Font.FontFamily, _tabBar.Font.Size, FontStyle.Bold);

        _tabScanner.Font = index == 0 ? _tabFontBold : _tabFontNormal;
        _tabDebugger.Font = index == 1 ? _tabFontBold : _tabFontNormal;
        _tabStructures.Font = index == 2 ? _tabFontBold : _tabFontNormal;
        _tabProcMon.Font = index == 3 ? _tabFontBold : _tabFontNormal;
        _tabApiMon.Font = index == 4 ? _tabFontBold : _tabFontNormal;
        _tabKernelMon.Font = index == 5 ? _tabFontBold : _tabFontNormal;

        // Show/hide panels and bring visible one to front
        ShellPanel? activePanel = null;
        if (_scannerPanel != null)
        {
            _scannerPanel.Visible = index == 0;
            if (index == 0) { _scannerPanel.BringToFront(); activePanel = _scannerPanel; }
        }
        if (_debuggerLayoutPanel != null)
        {
            _debuggerLayoutPanel.Visible = index == 1;
            if (index == 1) { _debuggerLayoutPanel.BringToFront(); activePanel = _debuggerLayoutPanel; }
        }
        if (_structuresPanel != null)
        {
            _structuresPanel.Visible = index == 2;
            if (index == 2) { _structuresPanel.BringToFront(); activePanel = _structuresPanel; }
        }
        if (_procMonPanel != null)
        {
            _procMonPanel.Visible = index == 3;
            if (index == 3) { _procMonPanel.BringToFront(); activePanel = _procMonPanel; }
        }
        if (_apiMonPanel != null)
        {
            _apiMonPanel.Visible = index == 4;
            if (index == 4) { _apiMonPanel.BringToFront(); activePanel = _apiMonPanel; }
        }
        if (_kernelMonPanel != null)
        {
            _kernelMonPanel.Visible = index == 5;
            if (index == 5) { _kernelMonPanel.BringToFront(); activePanel = _kernelMonPanel; }
        }

        // Update panel-specific menus
        UpdatePanelMenus(activePanel);
    }

    private void UpdatePanelMenus(ShellPanel? activePanel)
    {
        if (MainMenuStrip == null) return;

        // Remove current panel menus
        if (_currentPanelMenus != null)
        {
            foreach (var menu in _currentPanelMenus)
            {
                MainMenuStrip.Items.Remove(menu);
            }
            _currentPanelMenus = null;
        }

        // Get new panel menus
        var newMenus = activePanel?.GetPanelMenus();
        if (newMenus == null || newMenus.Length == 0) return;

        // Insert new panel menus before Help (which is the last item)
        // Panel menus go after Settings, before Help
        int insertIndex = _panelMenuInsertIndex;
        foreach (var menu in newMenus)
        {
            // Menus inherit styling from the MenuStrip
            MainMenuStrip.Items.Insert(insertIndex++, menu);
        }

        _currentPanelMenus = newMenus;
    }

    private void CreateModulePanels()
    {
        // Create all panels and add to content panel
        _scannerPanel = new MemoryScannerPanel { Dock = DockStyle.Fill };
        _debuggerLayoutPanel = new DebuggerLayoutPanel { Dock = DockStyle.Fill, Visible = false };
        _structuresPanel = new StructuresPanel { Dock = DockStyle.Fill, Visible = false };
        _procMonPanel = new ProcMonPanel { Dock = DockStyle.Fill, Visible = false };
        _apiMonPanel = new ApiMonPanel { Dock = DockStyle.Fill, Visible = false };
        _kernelMonPanel = new KernelMonPanel { Dock = DockStyle.Fill, Visible = false };

        _contentPanel.Controls.Add(_scannerPanel);
        _contentPanel.Controls.Add(_debuggerLayoutPanel);
        _contentPanel.Controls.Add(_structuresPanel);
        _contentPanel.Controls.Add(_procMonPanel);
        _contentPanel.Controls.Add(_apiMonPanel);
        _contentPanel.Controls.Add(_kernelMonPanel);
    }

    private void InitializeComponent()
    {
        SuspendLayout();

        // Form settings
        AutoScaleDimensions = new SizeF(7F, 15F);
        AutoScaleMode = AutoScaleMode.Font;
        ClientSize = new Size(1200, 800);
        MinimumSize = new Size(800, 600);
        StartPosition = FormStartPosition.CenterScreen;
        Text = "Nexus Sentinel";
        BackColor = NexusTheme.BackgroundDark;

        // Apply application icon from theme
        if (NexusTheme.AppIcon != null)
        {
            Icon = NexusTheme.AppIcon;
        }

        // Create menu strip
        var menuStrip = new MenuStrip();
        NexusTheme.StyleMenuStrip(menuStrip);

        // File menu
        var fileMenu = new ToolStripMenuItem("&File");
        _menuOpenProcess = new ToolStripMenuItem("&Attach Process...", null, (s, e) => OpenProcess());
        fileMenu.DropDownItems.Add(_menuOpenProcess);
        fileMenu.DropDownItems.Add("&Auto Attach...", null, (s, e) => ShowAutoAttach());
        _menuResumeAutoAttach = new ToolStripMenuItem("&Resume Auto Attach", null, (s, e) => ResumeAutoAttach());
        _menuResumeAutoAttach.Enabled = false; // Only enabled when paused
        fileMenu.DropDownItems.Add(_menuResumeAutoAttach);
        fileMenu.DropDownItems.Add("&Launch and Attach...", null, (s, e) => LaunchAndAttach());
        fileMenu.DropDownItems.Add(new ToolStripSeparator());
        _menuCloseProcess = new ToolStripMenuItem("&Detach Process", null, (s, e) => CloseProcess());
        fileMenu.DropDownItems.Add(_menuCloseProcess);
        fileMenu.DropDownItems.Add(new ToolStripSeparator());
        fileMenu.DropDownItems.Add("&Save Memory Region...", null, (s, e) => ShowSaveMemory());
        fileMenu.DropDownItems.Add("&Load Memory Region...", null, (s, e) => ShowLoadMemory());
        fileMenu.DropDownItems.Add(new ToolStripSeparator());
        fileMenu.DropDownItems.Add("E&xit", null, (s, e) => Close());
        menuStrip.Items.Add(fileMenu);

        // View menu
        var viewMenu = new ToolStripMenuItem("&View");
        viewMenu.DropDownItems.Add("&Memory Scanner", null, (s, e) => SwitchToModule(0));
        viewMenu.DropDownItems.Add("&Debugger", null, (s, e) => SwitchToModule(1));
        viewMenu.DropDownItems.Add("S&tructures", null, (s, e) => SwitchToModule(2));
        viewMenu.DropDownItems.Add("&ProcMon", null, (s, e) => SwitchToModule(3));
        viewMenu.DropDownItems.Add("&API Monitor", null, (s, e) => SwitchToModule(4));
        viewMenu.DropDownItems.Add("&Kernel Monitor", null, (s, e) => SwitchToModule(5));
        viewMenu.DropDownItems.Add(new ToolStripSeparator());
        _menuMemoryViewer = new ToolStripMenuItem("Memory &Viewer", null, (s, e) => ShowMemoryViewer());
        _menuProcessInspector = new ToolStripMenuItem("&Process Inspector...", null, (s, e) => ShowProcessInspector());
        viewMenu.DropDownItems.Add(_menuMemoryViewer);
        viewMenu.DropDownItems.Add(_menuProcessInspector);
        viewMenu.DropDownItems.Add(new ToolStripSeparator());
        _menuMemoryMap = new ToolStripMenuItem("Memory &Map", null, (s, e) => ShowMemoryMap());
        viewMenu.DropDownItems.Add(_menuMemoryMap);
        viewMenu.DropDownItems.Add("Enumerate &DLLs and Symbols", null, (s, e) => ShowEnumerateDLLs());
        viewMenu.DropDownItems.Add(new ToolStripSeparator());
        viewMenu.DropDownItems.Add("Stac&k View...", null, (s, e) => ShowStackView());
        viewMenu.DropDownItems.Add(new ToolStripSeparator());
        viewMenu.DropDownItems.Add("Scan &History...", null, (s, e) => ShowScanHistory());
        viewMenu.DropDownItems.Add("&Value History...", null, (s, e) => ShowValueHistory());
        menuStrip.Items.Add(viewMenu);

        // Debug menu
        var debugMenu = new ToolStripMenuItem("&Debug");
        _menuAttachDebugger = new ToolStripMenuItem("&Attach Debugger", null, (s, e) => AttachDebugger());
        debugMenu.DropDownItems.Add(_menuAttachDebugger);
        _menuDetach = new ToolStripMenuItem("&Detach Debugger", null, (s, e) => DetachDebugger());
        debugMenu.DropDownItems.Add(_menuDetach);
        debugMenu.DropDownItems.Add(new ToolStripSeparator());
        _menuDebugger = new ToolStripMenuItem("&Debugger...", null, (s, e) => ShowDebugger());
        debugMenu.DropDownItems.Add(_menuDebugger);
        debugMenu.DropDownItems.Add("Break &Thread...", null, (s, e) => ShowBreakThread());
        debugMenu.DropDownItems.Add(new ToolStripSeparator());
        debugMenu.DropDownItems.Add("&Continue", null, (s, e) => DebugContinue());
        debugMenu.DropDownItems.Add("Step &Into", null, (s, e) => DebugStepInto());
        debugMenu.DropDownItems.Add("Step &Over", null, (s, e) => DebugStepOver());
        debugMenu.DropDownItems.Add("Step O&ut", null, (s, e) => DebugStepOut());
        debugMenu.DropDownItems.Add("&Pause", null, (s, e) => DebugPause());
        menuStrip.Items.Add(debugMenu);

        // Tools menu
        var toolsMenu = new ToolStripMenuItem("&Tools");
        _menuPointerScanner = new ToolStripMenuItem("&Pointer Scanner...", null, (s, e) => ShowPointerScanner());
        _menuStructureDissector = new ToolStripMenuItem("&Structure Dissector...", null, (s, e) => ShowStructureDissector());
        _menuCodeCaveScanner = new ToolStripMenuItem("&Code Cave Scanner...", null, (s, e) => ShowCodeCaveScanner());
        toolsMenu.DropDownItems.Add(_menuPointerScanner);
        toolsMenu.DropDownItems.Add(_menuStructureDissector);
        toolsMenu.DropDownItems.Add(_menuCodeCaveScanner);
        toolsMenu.DropDownItems.Add(new ToolStripSeparator());
        _menuScriptEditor = new ToolStripMenuItem("&Script Editor...", null, (s, e) => ShowScriptEditor());
        toolsMenu.DropDownItems.Add(_menuScriptEditor);
        toolsMenu.DropDownItems.Add(new ToolStripSeparator());
        _menuSpeedhack = new ToolStripMenuItem("Speedhac&k...", null, (s, e) => ShowSpeedhack());
        toolsMenu.DropDownItems.Add(_menuSpeedhack);
        toolsMenu.DropDownItems.Add("Code &Injection...", null, (s, e) => ShowCodeInjection());
        toolsMenu.DropDownItems.Add(".&NET Info...", null, (s, e) => ShowDotNetInfo());
        toolsMenu.DropDownItems.Add("Find &Static Addresses...", null, (s, e) => ShowFindStatics());
        toolsMenu.DropDownItems.Add("Window &Spy...", null, (s, e) => ShowWindowSpy());
        toolsMenu.DropDownItems.Add(new ToolStripSeparator());
        toolsMenu.DropDownItems.Add("Process &Watchlist...", null, (s, e) => ShowProcessWatchlist());
        toolsMenu.DropDownItems.Add("&Bootkit Control...", null, (s, e) => ShowBootkitControl());
        toolsMenu.DropDownItems.Add("Map &Driver...", null, (s, e) => ShowMapDriver());
        toolsMenu.DropDownItems.Add(new ToolStripSeparator());
        toolsMenu.DropDownItems.Add("Form &Reviewer...", null, (s, e) => new FormReviewerForm().Show());
        menuStrip.Items.Add(toolsMenu);

        // Plugins menu
        _pluginsMenu = new ToolStripMenuItem("&Plugins");
        _pluginsMenu.DropDownItems.Add("&Manage Plugins...", null, (s, e) => ShowPluginManager());
        _pluginsMenu.DropDownItems.Add(new ToolStripSeparator());
        menuStrip.Items.Add(_pluginsMenu);

        // Provider menu
        var providerMenu = new ToolStripMenuItem("Pro&vider");
        _menuProviderUserMode = new ToolStripMenuItem("&User Mode", null, (s, e) => SetProvider(ProviderPrivilege.UserMode))
        {
            Checked = true,
            ToolTipText = "Standard user-mode memory access via Windows API"
        };
        _menuProviderKernel = new ToolStripMenuItem("&Kernel Mode", null, (s, e) => SetProvider(ProviderPrivilege.Kernel))
        {
            ToolTipText = "Kernel-level access via NexusKernel.sys driver"
        };
        _menuProviderHypervisor = new ToolStripMenuItem("&Hypervisor", null, (s, e) => SetProvider(ProviderPrivilege.Hypervisor))
        {
            ToolTipText = "Ring -1 access via SentinelHV hypervisor"
        };
        providerMenu.DropDownItems.AddRange([_menuProviderUserMode, _menuProviderKernel, _menuProviderHypervisor]);
        providerMenu.DropDownItems.Add(new ToolStripSeparator());
        providerMenu.DropDownItems.Add("&Refresh Availability", null, (s, e) => RefreshProviderAvailability());
        providerMenu.DropDownItems.Add("&Load Kernel Driver...", null, (s, e) => LoadKernelDriver());
        providerMenu.DropDownOpening += (s, e) => RefreshProviderAvailability();
        menuStrip.Items.Add(providerMenu);

        // Settings menu
        var settingsMenu = new ToolStripMenuItem("&Settings");
        settingsMenu.DropDownItems.Add("&Preferences...", null, (s, e) => ShowSettings());
        settingsMenu.DropDownItems.Add("&Scan Settings...", null, (s, e) => ShowScanSettings());
        settingsMenu.DropDownItems.Add("&Hotkeys...", null, (s, e) => ShowHotkeys());
        menuStrip.Items.Add(settingsMenu);

        // Remember insert index for panel-specific menus (after Settings, before Help)
        _panelMenuInsertIndex = menuStrip.Items.Count;

        // Help menu
        var helpMenu = new ToolStripMenuItem("&Help");
        helpMenu.DropDownItems.Add("&Documentation", null, (s, e) => ShowDocumentation());
        helpMenu.DropDownItems.Add("&About Nexus Sentinel", null, (s, e) => ShowAbout());
        menuStrip.Items.Add(helpMenu);

        MainMenuStrip = menuStrip;
        Controls.Add(menuStrip);

        // Toolbar created in constructor to ensure proper dock order
        ResumeLayout(false);
        PerformLayout();
    }

    // Process Management -> ShellForm.*.cs

    // View Operations -> ShellForm.*.cs

    // Debug Operations -> ShellForm.*.cs

    // Tools -> ShellForm.*.cs

    // Provider Switching -> ShellForm.*.cs

    // Auto Attach and Launch -> ShellForm.*.cs

    // Settings and Help -> ShellForm.*.cs

    // Status Updates -> ShellForm.*.cs

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            // Unsubscribe event handlers to prevent leaks (Issue 18)
            ProcessContext.Current.ProcessAttached -= OnProcessAttached;
            ProcessContext.Current.ProcessDetached -= OnProcessDetached;
            ProcessContext.Current.ProviderChanged -= OnProviderChanged;
            NexusSettings.SettingsChanged -= OnSettingsChanged_AutoAttach;

            EventBus.Instance.Unsubscribe<StatusUpdateEvent>(OnStatusUpdate);
            EventBus.Instance.Unsubscribe<NavigateToAddressEvent>(OnNavigateToAddress);

            // Dispose cached fonts (Issue 19)
            _tabFontNormal?.Dispose();
            _tabFontBold?.Dispose();
        }
        base.Dispose(disposing);
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        ProcessWatchlist.Instance.SaveToSettings();
        ProcessWatchlist.Instance.Dispose();
        CloseProcess();
        _pluginLoader?.Dispose();
        ProcessContext.Current.Dispose();
        NexusKernelDriver.Shutdown();
        EventBus.Instance.Clear();
        base.OnFormClosing(e);
    }

    // Plugin System -> ShellForm.*.cs
}
