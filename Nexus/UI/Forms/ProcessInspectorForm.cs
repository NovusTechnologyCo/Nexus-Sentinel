// <file>
// <summary>
// Consolidated process inspector with tabs for threads, modules, handles, and memory.
// </summary>
// </file>
using System.Runtime.InteropServices;
using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using Nexus.UI.Providers;
using Nexus.UI.Styles;
using static Nexus.UI.UIHelpers;

namespace Nexus.UI.Forms;

/// <summary>
/// Consolidated form for inspecting all aspects of a target process.
/// </summary>
public partial class ProcessInspectorForm : Form
{
    #region Fields

    private readonly IntPtr _processHandle;
    private readonly uint _processId;
    private int _selectedTab;

    // Tab bar
    private Panel _tabBar = null!;
    private Button[] _tabButtons = null!;

    // Content panels (one per tab)
    private Panel _pnlInfo = null!;
    private Panel _pnlThreads = null!;
    private Panel _pnlModules = null!;
    private Panel _pnlHandles = null!;
    private Panel _pnlMemory = null!;
    private Panel _pnlHeaps = null!;

    // Info tab controls
    private TextBox _txtInfo = null!;
    private Button _btnCopy = null!;

    // Threads tab controls
    private ListView _lvThreads = null!;
    private ContextMenuStrip _ctxThreads = null!;
    private System.Windows.Forms.Timer _threadRefreshTimer = null!;
    private List<ThreadInfo> _threads = new();

    // Modules tab controls
    private ListView _lvModules = null!;
    private ContextMenuStrip _ctxModules = null!;
    private TextBox _txtModuleFilter = null!;
    private CheckBox _chkShowSystemModules = null!;
    private Label _lblModuleCount = null!;
    private List<ModuleEntry> _allModules = new();

    // Handles tab controls
    private ListView _lvHandles = null!;
    private ContextMenuStrip _ctxHandles = null!;
    private TextBox _txtHandleFilter = null!;
    private ComboBox _cboHandleType = null!;
    private Label _lblHandleCount = null!;
    private List<HandleEntry> _allHandles = new();

    // Memory tab controls
    private ListView _lvMemory = null!;
    private ContextMenuStrip _ctxMemory = null!;
    private CheckBox _chkShowFreeRegions = null!;
    private Label _lblMemoryTotal = null!;
    private List<MemoryRegion> _memoryRegions = new();

    // Heaps tab controls
    private SplitContainer _heapsSplit = null!;
    private ListView _lvHeaps = null!;
    private ListView _lvHeapBlocks = null!;
    private ContextMenuStrip _ctxHeaps = null!;
    private ContextMenuStrip _ctxHeapBlocks = null!;
    private CheckBox _chkShowFreeBlocks = null!;
    private Label _lblHeapStatus = null!;
    private List<HeapInfo> _heaps = new();

    // Bottom panel
    private Panel _pnlBottom = null!;
    private Button _btnRefresh = null!;
    private Button _btnClose = null!;
    private Panel _pnlTabOptions = null!;

    // Events
    public event EventHandler<ulong>? OnNavigateToAddress;

    #endregion

    #region Constructor

    public ProcessInspectorForm(IntPtr processHandle, uint processId, int initialTab = 0)
    {
        _processHandle = processHandle;
        _processId = processId;
        _selectedTab = initialTab;

        InitializeComponent();
        NexusTheme.StyleForm(this);
        SetupEventHandlers();

        // Load initial tab
        SwitchTab(initialTab);
    }

    #endregion

    #region Initialization

    private void InitializeComponent()
    {
        Text = $"Process Inspector - PID: {_processId}";
        Size = new Size(950, 650);
        StartPosition = FormStartPosition.CenterParent;
        MinimumSize = new Size(800, 500);

        // Tab bar
        (_tabBar, _tabButtons) = NexusTheme.CreateTabBar(
            ["Info", "Threads", "Modules", "Handles", "Memory", "Heaps"],
            SwitchTab
        );

        // Content panel
        var pnlContent = new Panel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(NexusTheme.Space8)
        };

        // Initialize all tab panels
        InitializeInfoTab();
        InitializeThreadsTab();
        InitializeModulesTab();
        InitializeHandlesTab();
        InitializeMemoryTab();
        InitializeHeapsTab();

        // Add all panels to content
        pnlContent.Controls.Add(_pnlInfo);
        pnlContent.Controls.Add(_pnlThreads);
        pnlContent.Controls.Add(_pnlModules);
        pnlContent.Controls.Add(_pnlHandles);
        pnlContent.Controls.Add(_pnlMemory);
        pnlContent.Controls.Add(_pnlHeaps);

        // Bottom panel with refresh/close and tab-specific options
        InitializeBottomPanel();

        Controls.Add(pnlContent);
        Controls.Add(_pnlBottom);
        Controls.Add(_tabBar);

        CancelButton = _btnClose;
    }

    private void InitializeInfoTab()
    {
        _pnlInfo = new Panel { Dock = DockStyle.Fill, Visible = false };

        _txtInfo = new TextBox
        {
            Dock = DockStyle.Fill,
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Both,
            Font = new Font("Consolas", 9F),
            WordWrap = false
        };
        NexusTheme.StyleTextBox(_txtInfo);

        _pnlInfo.Controls.Add(_txtInfo);
    }

    private void InitializeThreadsTab()
    {
        _pnlThreads = new Panel { Dock = DockStyle.Fill, Visible = false };

        _lvThreads = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = true
        };
        _lvThreads.Columns.Add("Thread ID", 80);
        _lvThreads.Columns.Add("Start Address", 130);
        _lvThreads.Columns.Add("Priority", 60);
        _lvThreads.Columns.Add("State", 80);
        _lvThreads.Columns.Add("Base Priority", 85);
        _lvThreads.Columns.Add("Wait Reason", 90);
        NexusTheme.StyleListView(_lvThreads);

        _ctxThreads = new ContextMenuStrip();
        _ctxThreads.Items.Add("Suspend thread", null, (s, e) => SuspendThread());
        _ctxThreads.Items.Add("Resume thread", null, (s, e) => ResumeThread());
        _ctxThreads.Items.Add("-");
        _ctxThreads.Items.Add("Set priority...", null, (s, e) => SetThreadPriority());
        _ctxThreads.Items.Add("-");
        _ctxThreads.Items.Add("View thread context", null, (s, e) => ViewThreadContext());
        _ctxThreads.Items.Add("View thread stack", null, (s, e) => ViewThreadStack());
        _ctxThreads.Items.Add("-");
        _ctxThreads.Items.Add("Go to start address", null, (s, e) => GoToThreadStartAddress());
        _ctxThreads.Items.Add("-");
        _ctxThreads.Items.Add("Terminate thread", null, (s, e) => TerminateSelectedThread());
        _lvThreads.ContextMenuStrip = _ctxThreads;

        _threadRefreshTimer = new System.Windows.Forms.Timer { Interval = 2000 };

        _pnlThreads.Controls.Add(_lvThreads);
    }

    private void InitializeModulesTab()
    {
        _pnlModules = new Panel { Dock = DockStyle.Fill, Visible = false };

        _lvModules = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = true
        };
        _lvModules.Columns.Add("Address", 130);
        _lvModules.Columns.Add("Size", 80);
        _lvModules.Columns.Add("Module Name", 200);
        _lvModules.Columns.Add("Path", 400);
        NexusTheme.StyleListView(_lvModules);

        _ctxModules = new ContextMenuStrip();
        _ctxModules.Items.Add("Browse this memory region", null, (s, e) => BrowseModule());
        _ctxModules.Items.Add("Disassemble at entry point", null, (s, e) => DisassembleModuleEntry());
        _ctxModules.Items.Add("-");
        _ctxModules.Items.Add("Dump module to file...", null, (s, e) => DumpModule());
        _ctxModules.Items.Add("-");
        _ctxModules.Items.Add("Copy address", null, (s, e) => CopyModuleAddress());
        _ctxModules.Items.Add("Copy module name", null, (s, e) => CopyModuleName());
        _ctxModules.Items.Add("Copy full path", null, (s, e) => CopyModulePath());
        _ctxModules.Items.Add("-");
        _ctxModules.Items.Add("View exports...", null, (s, e) => ViewModuleExports());
        _ctxModules.Items.Add("View imports...", null, (s, e) => ViewModuleImports());
        _lvModules.ContextMenuStrip = _ctxModules;

        _pnlModules.Controls.Add(_lvModules);
    }

    private void InitializeHandlesTab()
    {
        _pnlHandles = new Panel { Dock = DockStyle.Fill, Visible = false };

        _lvHandles = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = true
        };
        _lvHandles.Columns.Add("Handle", 80);
        _lvHandles.Columns.Add("Type", 120);
        _lvHandles.Columns.Add("Access", 100);
        _lvHandles.Columns.Add("Name/Object", 400);
        NexusTheme.StyleListView(_lvHandles);

        _ctxHandles = new ContextMenuStrip();
        _ctxHandles.Items.Add("Close handle", null, (s, e) => CloseSelectedHandle());
        _ctxHandles.Items.Add("-");
        _ctxHandles.Items.Add("Copy handle value", null, (s, e) => CopyHandleValue());
        _ctxHandles.Items.Add("Copy name", null, (s, e) => CopyHandleName());
        _lvHandles.ContextMenuStrip = _ctxHandles;

        _pnlHandles.Controls.Add(_lvHandles);
    }

    private void InitializeMemoryTab()
    {
        _pnlMemory = new Panel { Dock = DockStyle.Fill, Visible = false };

        _lvMemory = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = true
        };
        _lvMemory.Columns.Add("Address", 130);
        _lvMemory.Columns.Add("Size", 100);
        _lvMemory.Columns.Add("Protection", 80);
        _lvMemory.Columns.Add("State", 70);
        _lvMemory.Columns.Add("Type", 70);
        _lvMemory.Columns.Add("Module/Mapped File", 300);
        NexusTheme.StyleListView(_lvMemory);

        _ctxMemory = new ContextMenuStrip();
        _ctxMemory.Items.Add("Browse this memory region", null, (s, e) => BrowseMemoryRegion());
        _ctxMemory.Items.Add("Dump memory to file...", null, (s, e) => DumpMemoryRegion());
        _ctxMemory.Items.Add("-");
        _ctxMemory.Items.Add("Set access protection...", null, (s, e) => SetMemoryProtection());
        _ctxMemory.Items.Add("-");
        _ctxMemory.Items.Add("Copy address", null, (s, e) => CopyMemoryAddress());
        _ctxMemory.Items.Add("Copy row", null, (s, e) => CopyMemoryRow());
        _lvMemory.ContextMenuStrip = _ctxMemory;

        _pnlMemory.Controls.Add(_lvMemory);
    }

    private void InitializeHeapsTab()
    {
        _pnlHeaps = new Panel { Dock = DockStyle.Fill, Visible = false };

        _heapsSplit = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Orientation = Orientation.Vertical
        };

        // Left: Heap list
        var pnlHeapsHeader = new Panel { Dock = DockStyle.Top, Height = 28 };
        pnlHeapsHeader.Controls.Add(new Label { Text = "Heaps:", Dock = DockStyle.Fill, Padding = new Padding(2, 5, 0, 0) });

        _lvHeaps = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = true
        };
        _lvHeaps.Columns.Add("Base Address", 120);
        _lvHeaps.Columns.Add("Size", 70);
        _lvHeaps.Columns.Add("Blocks", 60);
        _lvHeaps.Columns.Add("Flags", 70);
        NexusTheme.StyleListView(_lvHeaps);

        _ctxHeaps = new ContextMenuStrip();
        _ctxHeaps.Items.Add("Browse memory at base", null, (s, e) => BrowseHeapBase());
        _ctxHeaps.Items.Add("Copy base address", null, (s, e) => CopyHeapBase());
        _lvHeaps.ContextMenuStrip = _ctxHeaps;

        _heapsSplit.Panel1.Controls.Add(_lvHeaps);
        _heapsSplit.Panel1.Controls.Add(pnlHeapsHeader);

        // Right: Block list
        var pnlBlocksHeader = new Panel { Dock = DockStyle.Top, Height = 28 };
        pnlBlocksHeader.Controls.Add(new Label { Text = "Heap Blocks:", Dock = DockStyle.Fill, Padding = new Padding(2, 5, 0, 0) });

        _lvHeapBlocks = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = true,
            Font = new Font("Consolas", 9F)
        };
        _lvHeapBlocks.Columns.Add("Address", 120);
        _lvHeapBlocks.Columns.Add("Size", 80);
        _lvHeapBlocks.Columns.Add("Status", 60);
        _lvHeapBlocks.Columns.Add("Flags", 80);
        NexusTheme.StyleListView(_lvHeapBlocks);

        _ctxHeapBlocks = new ContextMenuStrip();
        _ctxHeapBlocks.Items.Add("Browse memory at address", null, (s, e) => BrowseHeapBlock());
        _ctxHeapBlocks.Items.Add("Copy address", null, (s, e) => CopyHeapBlockAddress());
        _lvHeapBlocks.ContextMenuStrip = _ctxHeapBlocks;

        _heapsSplit.Panel2.Controls.Add(_lvHeapBlocks);
        _heapsSplit.Panel2.Controls.Add(pnlBlocksHeader);

        _pnlHeaps.Controls.Add(_heapsSplit);

        // Set splitter position on load
        Load += (s, e) => _heapsSplit.SplitterDistance = _heapsSplit.Width / 2;
    }

    private void InitializeBottomPanel()
    {
        _pnlBottom = new Panel
        {
            Dock = DockStyle.Bottom,
            Height = 50
        };

        _btnRefresh = new Button
        {
            Text = "Refresh",
            Location = new Point(NexusTheme.Space16, 10),
            Size = new Size(NexusTheme.ButtonWidth, NexusTheme.ButtonHeight)
        };
        NexusTheme.StyleButton(_btnRefresh);

        _btnClose = new Button
        {
            Text = "Close",
            Location = new Point(NexusTheme.Space16 + NexusTheme.ButtonWidth + NexusTheme.ButtonGap, 10),
            Size = new Size(NexusTheme.ButtonWidth, NexusTheme.ButtonHeight),
            DialogResult = DialogResult.Cancel
        };
        NexusTheme.StyleButton(_btnClose);

        // Tab options panel (holds tab-specific controls)
        _pnlTabOptions = new Panel
        {
            Location = new Point(220, 0),
            Size = new Size(700, 50)
        };

        // Info tab option: Copy button
        _btnCopy = new Button
        {
            Text = "Copy All",
            Location = new Point(0, 10),
            Size = new Size(80, NexusTheme.ButtonHeight),
            Visible = false
        };
        NexusTheme.StyleButton(_btnCopy);

        // Modules tab options
        var lblModFilter = new Label { Text = "Filter:", Location = new Point(0, 15), AutoSize = true, Visible = false, Name = "lblModFilter" };
        _txtModuleFilter = new TextBox { Location = new Point(45, 12), Size = new Size(120, 23), Visible = false };
        NexusTheme.StyleTextBox(_txtModuleFilter);
        _chkShowSystemModules = new CheckBox { Text = "Show system modules", Location = new Point(175, 14), AutoSize = true, Checked = true, Visible = false };
        NexusTheme.StyleCheckBox(_chkShowSystemModules);
        _lblModuleCount = new Label { Text = "0 modules", Location = new Point(350, 15), AutoSize = true, Visible = false };

        // Handles tab options
        var lblHndFilter = new Label { Text = "Filter:", Location = new Point(0, 15), AutoSize = true, Visible = false, Name = "lblHndFilter" };
        _txtHandleFilter = new TextBox { Location = new Point(45, 12), Size = new Size(100, 23), Visible = false };
        NexusTheme.StyleTextBox(_txtHandleFilter);
        var lblHndType = new Label { Text = "Type:", Location = new Point(155, 15), AutoSize = true, Visible = false, Name = "lblHndType" };
        _cboHandleType = new ComboBox { Location = new Point(195, 12), Size = new Size(100, 23), DropDownStyle = ComboBoxStyle.DropDownList, Visible = false };
        _cboHandleType.Items.AddRange(new object[] { "(All)", "File", "Section", "Event", "Mutant", "Key", "Process", "Thread", "Directory" });
        _cboHandleType.SelectedIndex = 0;
        _lblHandleCount = new Label { Text = "0 handles", Location = new Point(310, 15), AutoSize = true, Visible = false };

        // Memory tab options
        _chkShowFreeRegions = new CheckBox { Text = "Show free regions", Location = new Point(0, 14), AutoSize = true, Visible = false };
        NexusTheme.StyleCheckBox(_chkShowFreeRegions);
        _lblMemoryTotal = new Label { Text = "Total: 0 bytes", Location = new Point(160, 15), AutoSize = true, Visible = false };

        // Heaps tab options
        _chkShowFreeBlocks = new CheckBox { Text = "Show free blocks", Location = new Point(0, 14), AutoSize = true, Visible = false };
        NexusTheme.StyleCheckBox(_chkShowFreeBlocks);
        _lblHeapStatus = new Label { Text = "", Location = new Point(140, 15), AutoSize = true, Visible = false };

        _pnlTabOptions.Controls.AddRange(new Control[] {
            _btnCopy,
            lblModFilter, _txtModuleFilter, _chkShowSystemModules, _lblModuleCount,
            lblHndFilter, _txtHandleFilter, lblHndType, _cboHandleType, _lblHandleCount,
            _chkShowFreeRegions, _lblMemoryTotal,
            _chkShowFreeBlocks, _lblHeapStatus
        });

        _pnlBottom.Controls.Add(_btnRefresh);
        _pnlBottom.Controls.Add(_btnClose);
        _pnlBottom.Controls.Add(_pnlTabOptions);
    }

    private void SetupEventHandlers()
    {
        _btnRefresh.Click += (s, e) => RefreshCurrentTab();
        _btnClose.Click += (s, e) => Close();
        _btnCopy.Click += (s, e) => CopyInfoText();

        // Threads
        _lvThreads.DoubleClick += (s, e) => ViewThreadContext();
        _threadRefreshTimer.Tick += (s, e) => { if (_selectedTab == 1) RefreshThreads(); };

        // Modules
        _txtModuleFilter.TextChanged += (s, e) => ApplyModuleFilter();
        _chkShowSystemModules.CheckedChanged += (s, e) => ApplyModuleFilter();
        _lvModules.DoubleClick += (s, e) => BrowseModule();
        _lvModules.ColumnClick += (s, e) => SortListView(_lvModules, e.Column);

        // Handles
        _txtHandleFilter.TextChanged += (s, e) => ApplyHandleFilter();
        _cboHandleType.SelectedIndexChanged += (s, e) => ApplyHandleFilter();
        _lvHandles.ColumnClick += (s, e) => SortListView(_lvHandles, e.Column);

        // Memory
        _chkShowFreeRegions.CheckedChanged += (s, e) => RefreshMemoryRegions();
        _lvMemory.DoubleClick += (s, e) => BrowseMemoryRegion();
        _lvMemory.ColumnClick += (s, e) => SortListView(_lvMemory, e.Column);

        // Heaps
        _lvHeaps.SelectedIndexChanged += (s, e) => UpdateHeapBlockList();
        _chkShowFreeBlocks.CheckedChanged += (s, e) => UpdateHeapBlockList();

        FormClosed += (s, e) => { _threadRefreshTimer.Stop(); _threadRefreshTimer.Dispose(); };
    }

    #endregion

    #region Tab Switching

    private void SwitchTab(int tabIndex)
    {
        _selectedTab = tabIndex;
        NexusTheme.UpdateTabSelection(_tabButtons, tabIndex);

        // Hide all panels
        _pnlInfo.Visible = false;
        _pnlThreads.Visible = false;
        _pnlModules.Visible = false;
        _pnlHandles.Visible = false;
        _pnlMemory.Visible = false;
        _pnlHeaps.Visible = false;

        // Hide all tab options
        foreach (Control c in _pnlTabOptions.Controls)
            c.Visible = false;

        // Stop thread timer when not on threads tab
        _threadRefreshTimer.Stop();

        // Show selected panel and its options
        switch (tabIndex)
        {
            case 0: // Info
                _pnlInfo.Visible = true;
                _pnlInfo.BringToFront();
                _btnCopy.Visible = true;
                if (_txtInfo.TextLength == 0) RefreshInfo();
                break;

            case 1: // Threads
                _pnlThreads.Visible = true;
                _pnlThreads.BringToFront();
                _threadRefreshTimer.Start();
                if (_lvThreads.Items.Count == 0) RefreshThreads();
                break;

            case 2: // Modules
                _pnlModules.Visible = true;
                _pnlModules.BringToFront();
                ShowModuleOptions();
                if (_lvModules.Items.Count == 0) RefreshModules();
                break;

            case 3: // Handles
                _pnlHandles.Visible = true;
                _pnlHandles.BringToFront();
                ShowHandleOptions();
                if (_lvHandles.Items.Count == 0) RefreshHandles();
                break;

            case 4: // Memory
                _pnlMemory.Visible = true;
                _pnlMemory.BringToFront();
                _chkShowFreeRegions.Visible = true;
                _lblMemoryTotal.Visible = true;
                if (_lvMemory.Items.Count == 0) RefreshMemoryRegions();
                break;

            case 5: // Heaps
                _pnlHeaps.Visible = true;
                _pnlHeaps.BringToFront();
                _chkShowFreeBlocks.Visible = true;
                _lblHeapStatus.Visible = true;
                if (_lvHeaps.Items.Count == 0) RefreshHeaps();
                break;
        }
    }

    private void ShowModuleOptions()
    {
        foreach (Control c in _pnlTabOptions.Controls)
        {
            if (c.Name == "lblModFilter" || c == _txtModuleFilter ||
                c == _chkShowSystemModules || c == _lblModuleCount)
                c.Visible = true;
        }
    }

    private void ShowHandleOptions()
    {
        foreach (Control c in _pnlTabOptions.Controls)
        {
            if (c.Name == "lblHndFilter" || c == _txtHandleFilter ||
                c.Name == "lblHndType" || c == _cboHandleType || c == _lblHandleCount)
                c.Visible = true;
        }
    }

    private void RefreshCurrentTab()
    {
        switch (_selectedTab)
        {
            case 0: RefreshInfo(); break;
            case 1: RefreshThreads(); break;
            case 2: RefreshModules(); break;
            case 3: RefreshHandles(); break;
            case 4: RefreshMemoryRegions(); break;
            case 5: RefreshHeaps(); break;
        }
    }

    #endregion

    #region Info Tab

    private void RefreshInfo()
    {
        _txtInfo.Clear();

        // Basic process info
        var result = NexusEngine.Nexus_GetProcessInfo(_processHandle, out var info);
        if (result == NexusResult.OK)
        {
            AddInfoLine("Process ID", _processId.ToString());
            AddInfoLine("Process Name", new string(info.Name).TrimEnd('\0'));
            AddInfoLine("Process Path", new string(info.Path).TrimEnd('\0'));
            AddInfoLine("Architecture", info.Is32Bit != 0 ? "32-bit (WOW64)" : "64-bit");
            AddInfoLine("Parent PID", info.ParentPid.ToString());
        }
        else
        {
            AddInfoLine("Process ID", _processId.ToString());
            AddInfoLine("Status", "Unable to retrieve process information");
        }

        AddInfoSeparator();
        LoadInfoModules();
        AddInfoSeparator();
        LoadInfoMemory();
        AddInfoSeparator();
        LoadInfoThreads();
    }

    private void LoadInfoModules()
    {
        AddInfoHeader("Modules");
        NexusEngine.Nexus_EnumerateModules(_processHandle, null, 0, out nuint count);
        if (count == 0) { AddInfoLine("Modules", "None found"); return; }

        var modules = new NexusModuleInfo[count];
        if (NexusEngine.Nexus_EnumerateModules(_processHandle, modules, count, out _) != NexusResult.OK)
        { AddInfoLine("Modules", "Failed to enumerate"); return; }

        AddInfoLine("Module Count", count.ToString());
        _txtInfo.AppendText(Environment.NewLine);
        foreach (var mod in modules)
        {
            var name = new string(mod.Name).TrimEnd('\0');
            _txtInfo.AppendText($"  {mod.BaseAddress:X16}  {mod.Size,10:N0}  {name}{Environment.NewLine}");
        }
    }

    private void LoadInfoMemory()
    {
        AddInfoHeader("Memory Regions");
        NexusEngine.Nexus_EnumerateMemoryRegions(_processHandle, null, 0, out nuint count);
        if (count == 0) { AddInfoLine("Regions", "None found"); return; }

        var regions = new NexusMemoryRegion[count];
        if (NexusEngine.Nexus_EnumerateMemoryRegions(_processHandle, regions, count, out _) != NexusResult.OK)
        { AddInfoLine("Regions", "Failed to enumerate"); return; }

        ulong totalCommitted = 0, totalReserved = 0, totalExecutable = 0, totalWritable = 0;
        int committedCount = 0, reservedCount = 0;

        foreach (var region in regions)
        {
            if ((region.State & 0x1000) != 0)
            {
                totalCommitted += region.Size; committedCount++;
                if ((region.Protection & 0xF0) != 0) totalExecutable += region.Size;
                if ((region.Protection & 0x04) != 0 || (region.Protection & 0x08) != 0 ||
                    (region.Protection & 0x40) != 0 || (region.Protection & 0x80) != 0)
                    totalWritable += region.Size;
            }
            else if ((region.State & 0x2000) != 0) { totalReserved += region.Size; reservedCount++; }
        }

        AddInfoLine("Total Regions", count.ToString());
        AddInfoLine("Committed", $"{committedCount} ({FormatSize(totalCommitted)})");
        AddInfoLine("Reserved", $"{reservedCount} ({FormatSize(totalReserved)})");
        AddInfoLine("Executable", FormatSize(totalExecutable));
        AddInfoLine("Writable", FormatSize(totalWritable));
    }

    private void LoadInfoThreads()
    {
        AddInfoHeader("Threads");
        NexusEngine.Nexus_EnumerateThreads(_processHandle, null, 0, out nuint count);
        if (count == 0) { AddInfoLine("Threads", "None found"); return; }

        var threads = new NexusThreadInfo[count];
        if (NexusEngine.Nexus_EnumerateThreads(_processHandle, threads, count, out _) != NexusResult.OK)
        { AddInfoLine("Threads", "Failed to enumerate"); return; }

        AddInfoLine("Thread Count", count.ToString());
        _txtInfo.AppendText(Environment.NewLine);
        foreach (var t in threads)
        {
            var state = t.State switch { 1 => "Running", 2 => "Suspended", 4 => "Waiting", 8 => "Terminated", _ => "Unknown" };
            _txtInfo.AppendText($"  TID {t.ThreadId,-8}  Priority: {t.BasePriority,-3}  State: {state}{Environment.NewLine}");
        }
    }

    private void AddInfoLine(string label, string value) => _txtInfo.AppendText($"{label,-20}: {value}{Environment.NewLine}");
    private void AddInfoHeader(string text) => _txtInfo.AppendText($"{Environment.NewLine}=== {text} ==={Environment.NewLine}");
    private void AddInfoSeparator() => _txtInfo.AppendText(new string('-', 60) + Environment.NewLine);
    private void CopyInfoText() { if (!string.IsNullOrEmpty(_txtInfo.Text)) Clipboard.SetText(_txtInfo.Text); }

    #endregion

    // Threads Tab + Modules Tab -> ProcessInspectorForm.Threads.cs
    // Handles Tab + Heaps Tab  -> ProcessInspectorForm.Handles.cs
    // Memory Tab               -> ProcessInspectorForm.Memory.cs

    #region Utilities

    private static string FormatSize(ulong bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
        if (bytes < 1024 * 1024 * 1024) return $"{bytes / (1024.0 * 1024):F1} MB";
        return $"{bytes / (1024.0 * 1024 * 1024):F2} GB";
    }

    private void SortListView(ListView lv, int column)
    {
        lv.ListViewItemSorter = new ListViewColumnSorter(column);
        lv.Sort();
    }

    private class ListViewColumnSorter : System.Collections.IComparer
    {
        private readonly int _col;
        public ListViewColumnSorter(int col) => _col = col;
        public int Compare(object? x, object? y)
        {
            if (x is not ListViewItem ix || y is not ListViewItem iy) return 0;
            var tx = ix.SubItems[_col].Text; var ty = iy.SubItems[_col].Text;
            if (tx.StartsWith("0x") && ty.StartsWith("0x"))
            {
                try { return Convert.ToUInt64(tx[2..], 16).CompareTo(Convert.ToUInt64(ty[2..], 16)); } catch { }
            }
            return string.Compare(tx, ty, StringComparison.OrdinalIgnoreCase);
        }
    }

    #endregion

    #region P/Invoke

    private const int SystemHandleInformation = 16;
    private const int STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xC0000004);
    private const uint PROCESS_DUP_HANDLE = 0x0040;
    private const uint DUPLICATE_CLOSE_SOURCE = 0x00000001;
    private const uint TH32CS_SNAPHEAPLIST = 0x00000001;
    private static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);
    private const uint LF32_FREE = 0x00000002;

    [DllImport("ntdll.dll")] private static extern int NtQuerySystemInformation(int SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength, out int ReturnLength);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool DuplicateHandle(IntPtr hSourceProcessHandle, IntPtr hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle, uint dwDesiredAccess, bool bInheritHandle, uint dwOptions);
    [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr hObject);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool Heap32ListFirst(IntPtr hSnapshot, ref HEAPLIST32 lphl);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool Heap32ListNext(IntPtr hSnapshot, ref HEAPLIST32 lphl);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool Heap32First(ref HEAPENTRY32 lphe, uint th32ProcessID, UIntPtr th32HeapID);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool Heap32Next(ref HEAPENTRY32 lphe);

    [StructLayout(LayoutKind.Sequential)] private struct SYSTEM_HANDLE_ENTRY { public int OwnerPid; public byte ObjectType; public byte HandleFlags; public ushort HandleValue; public IntPtr ObjectPointer; public uint GrantedAccess; }
    [StructLayout(LayoutKind.Sequential)] private struct HEAPLIST32 { public uint dwSize; public uint th32ProcessID; public UIntPtr th32HeapID; public uint dwFlags; }
    [StructLayout(LayoutKind.Sequential)] private struct HEAPENTRY32 { public uint dwSize; public IntPtr hHandle; public UIntPtr dwAddress; public UIntPtr dwBlockSize; public uint dwFlags; public uint dwLockCount; public uint dwResvd; public uint th32ProcessID; public UIntPtr th32HeapID; }

    #endregion

    #region Nested Types

    public class ModuleEntry
    {
        public ulong BaseAddress { get; set; }
        public ulong Size { get; set; }
        public string Name { get; set; } = "";
        public string Path { get; set; } = "";
        public bool IsSystemModule { get; set; }
    }

    public class HandleEntry
    {
        public IntPtr Handle { get; set; }
        public string TypeName { get; set; } = "";
        public string Name { get; set; } = "";
        public uint GrantedAccess { get; set; }
        public byte ObjectType { get; set; }
    }

    public class MemoryRegion
    {
        public ulong BaseAddress { get; set; }
        public ulong Size { get; set; }
        public uint Protection { get; set; }
        public uint State { get; set; }
        public uint Type { get; set; }
    }

    public class HeapInfo
    {
        public ulong BaseAddress { get; set; }
        public ulong Size { get; set; }
        public uint Flags { get; set; }
        public int BlockCount { get; set; }
        public List<HeapBlock> Blocks { get; set; } = new();
    }

    public class HeapBlock
    {
        public ulong Address { get; set; }
        public ulong Size { get; set; }
        public uint Flags { get; set; }
        public bool IsFree { get; set; }
    }

    #endregion
}
