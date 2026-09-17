// <file>
// <summary>
// Process selection dialog with process list and auto-attach configuration tab.
// </summary>
// </file>
using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using Nexus.UI.Styles;
using System.Runtime.InteropServices;
using System.Text;

namespace Nexus.UI.Forms;

public partial class ProcessWindow : Form
{
    public uint SelectedPid { get; private set; }
    public bool AttachDebuggerRequested { get; private set; }

    private NexusProcessInfo[] _processes = [];
    private string _filter = "";
    private bool _showInvisibleWindows = false;
    private bool _ownProcessesOnly = false;
    private bool _showPidAsDecimal = false;
    private bool _isLoadingAutoAttach = false;

    // Window enumeration data
    private readonly List<WindowInfo> _windows = [];
    private readonly List<WindowInfo> _applications = [];

    // P/Invoke for window enumeration
    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

    [DllImport("user32.dll")]
    private static extern int GetWindowTextLength(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    [DllImport("user32.dll")]
    private static extern IntPtr GetWindow(IntPtr hWnd, uint uCmd);

    [DllImport("user32.dll")]
    private static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

    private const uint GW_OWNER = 4;

    private class WindowInfo
    {
        public IntPtr Handle { get; set; }
        public string Title { get; set; } = "";
        public string ClassName { get; set; } = "";
        public uint ProcessId { get; set; }
        public bool IsVisible { get; set; }
    }

    public ProcessWindow()
    {
        InitializeComponent();
        NexusTheme.StyleForm(this);
        RefreshProcessList();
        RefreshWindowList();
        RefreshApplicationList();
        RefreshAutoAttachList();
        Load += (s, e) => SwitchTab(2);  // Start on Windows tab after form loads
        refreshTimer.Start();
    }

    /// <summary>
    /// Switches to the Auto Attach tab (index 3)
    /// </summary>
    public void SwitchToAutoAttachTab()
    {
        Load -= LoadHandler;
        Load += LoadHandler;
        void LoadHandler(object? s, EventArgs e) => SwitchTab(3);
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        refreshTimer.Stop();
        base.OnFormClosing(e);
    }
}

partial class ProcessWindow
{
    private System.ComponentModel.IContainer? components = null;

    protected override void Dispose(bool disposing)
    {
        if (disposing && (components != null))
        {
            components.Dispose();
        }
        base.Dispose(disposing);
    }

    private void InitializeComponent()
    {
        this.components = new System.ComponentModel.Container();

        // Main controls
        this.menuStrip = new MenuStrip();
        this.fileMenu = new ToolStripMenuItem();
        this.miCreateProcess = new ToolStripMenuItem();
        this.miOpenFile = new ToolStripMenuItem();

        // Tab bar (shell-style using ToolStrip)
        (this._tabBar, this._tabButtons) = NexusTheme.CreateTabBar(
            ["Applications", "Processes", "Windows", "Auto Attach"],
            SwitchTab
        );

        // Content panel to hold the ListViews
        this.pnlContent = new Panel();

        this.lvProcesses = new ListView();
        this.colPid = new ColumnHeader();
        this.colName = new ColumnHeader();
        this.colArch = new ColumnHeader();

        this.lvWindows = new ListView();
        this.colWinHandle = new ColumnHeader();
        this.colWinPid = new ColumnHeader();
        this.colWinTitle = new ColumnHeader();
        this.colWinClass = new ColumnHeader();

        this.lvApplications = new ListView();
        this.colAppTitle = new ColumnHeader();
        this.colAppPid = new ColumnHeader();

        this.txtFilter = new TextBox();
        this.lblFilter = new Label();
        this.lblCount = new Label();

        this.pnlButtons = new Panel();
        this.btnOK = new Button();
        this.btnCancel = new Button();
        this.btnAttachDebugger = new Button();
        this.btnNetwork = new Button();
        this.btnRefresh = new Button();
        this.btnAddToAutoAttach = new Button();

        // Auto Attach tab controls
        this.pnlAutoAttach = new Panel();
        this.lvAutoAttach = new ListView();
        this.colAutoAttachName = new ColumnHeader();
        this.colAutoAttachType = new ColumnHeader();
        this.colAutoAttachEnabled = new ColumnHeader();
        this.txtAutoAttachName = new TextBox();
        this.btnAutoAttachBrowse = new Button();
        this.btnAutoAttachAdd = new Button();
        this.btnAutoAttachRemove = new Button();
        this.lblCheckInterval = new Label();
        this.nudCheckInterval = new NumericUpDown();

        this.ctxProcessList = new ContextMenuStrip(this.components);
        this.miInputPidManually = new ToolStripMenuItem();
        this.miFilter = new ToolStripMenuItem();
        this.miRefresh = new ToolStripMenuItem();
        this.toolStripSeparator1 = new ToolStripSeparator();
        this.miShowInvisible = new ToolStripMenuItem();
        this.miOwnProcessesOnly = new ToolStripMenuItem();
        this.miConvertPidToDecimal = new ToolStripMenuItem();

        this.refreshTimer = new System.Windows.Forms.Timer(this.components);

        this.menuStrip.SuspendLayout();
        this.pnlButtons.SuspendLayout();
        this.ctxProcessList.SuspendLayout();
        this.SuspendLayout();

        //
        // menuStrip
        //
        this.menuStrip.Items.Add(this.fileMenu);
        this.menuStrip.Location = new Point(0, 0);
        this.menuStrip.Size = new Size(500, 24);

        //
        // fileMenu
        //
        this.fileMenu.DropDownItems.AddRange(new ToolStripItem[] {
            this.miCreateProcess, this.miOpenFile
        });
        this.fileMenu.Text = "&File";

        this.miCreateProcess.Text = "Create Process...";
        this.miCreateProcess.Click += new EventHandler(this.MiCreateProcess_Click);

        this.miOpenFile.Text = "Open File...";
        this.miOpenFile.Click += new EventHandler(this.MiOpenFile_Click);

        //
        // _tabBar - shell-style tab bar (created via NexusTheme.CreateTabBar)
        //
        this._tabBar.Dock = DockStyle.Top;

        //
        // pnlContent - holds the ListViews
        //
        this.pnlContent.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
        this.pnlContent.Location = new Point(12, 24 + NexusTheme.ToolbarHeight); // menuStrip height + tab bar height
        this.pnlContent.Size = new Size(756, 330);
        this.pnlContent.BackColor = NexusTheme.BackgroundPanel;

        //
        // lvWindows - in content panel, initially hidden
        //
        this.lvWindows.Columns.AddRange(new ColumnHeader[] {
            this.colWinPid, this.colWinHandle, this.colWinTitle, this.colWinClass
        });
        this.lvWindows.ContextMenuStrip = this.ctxProcessList;
        this.lvWindows.Dock = DockStyle.Fill;
        this.lvWindows.FullRowSelect = true;
        this.lvWindows.MultiSelect = false;
        this.lvWindows.Name = "lvWindows";
        this.lvWindows.View = View.Details;
        this.lvWindows.Visible = false;
        this.lvWindows.DoubleClick += new EventHandler(this.LvProcesses_DoubleClick);
        NexusTheme.StyleListView(this.lvWindows);

        this.colWinHandle.Text = "Handle";
        this.colWinHandle.Width = 110;

        this.colWinPid.Text = "PID";
        this.colWinPid.Width = 100;

        this.colWinTitle.Text = "Window Title";
        this.colWinTitle.Width = 500;

        this.colWinClass.Text = "Class";
        this.colWinClass.Width = 220;

        //
        // lvApplications - in content panel, initially visible
        //
        this.lvApplications.Columns.AddRange(new ColumnHeader[] {
            this.colAppPid, this.colAppTitle
        });
        this.lvApplications.ContextMenuStrip = this.ctxProcessList;
        this.lvApplications.Dock = DockStyle.Fill;
        this.lvApplications.FullRowSelect = true;
        this.lvApplications.MultiSelect = false;
        this.lvApplications.Name = "lvApplications";
        this.lvApplications.View = View.Details;
        this.lvApplications.Visible = true;
        this.lvApplications.DoubleClick += new EventHandler(this.LvProcesses_DoubleClick);
        NexusTheme.StyleListView(this.lvApplications);

        this.colAppTitle.Text = "Application";
        this.colAppTitle.Width = 830;

        this.colAppPid.Text = "PID";
        this.colAppPid.Width = 100;

        //
        // lvProcesses - in content panel, initially hidden
        //
        this.lvProcesses.Columns.AddRange(new ColumnHeader[] {
            this.colPid, this.colName, this.colArch
        });
        this.lvProcesses.ContextMenuStrip = this.ctxProcessList;
        this.lvProcesses.Dock = DockStyle.Fill;
        this.lvProcesses.FullRowSelect = true;
        this.lvProcesses.MultiSelect = false;
        this.lvProcesses.Name = "lvProcesses";
        this.lvProcesses.View = View.Details;
        this.lvProcesses.Visible = false;
        this.lvProcesses.DoubleClick += new EventHandler(this.LvProcesses_DoubleClick);
        this.lvProcesses.KeyPress += new KeyPressEventHandler(this.LvProcesses_KeyPress);
        NexusTheme.StyleListView(this.lvProcesses);

        this.colPid.Text = "PID";
        this.colPid.Width = 100;

        this.colName.Text = "Process Name";
        this.colName.Width = 750;

        this.colArch.Text = "Arch";
        this.colArch.Width = 60;

        // Add ListViews to content panel
        this.pnlContent.Controls.Add(this.lvApplications);
        this.pnlContent.Controls.Add(this.lvProcesses);
        this.pnlContent.Controls.Add(this.lvWindows);
        this.pnlContent.Controls.Add(this.pnlAutoAttach);

        //
        // pnlAutoAttach - Auto Attach tab content
        //
        this.pnlAutoAttach.Dock = DockStyle.Fill;
        this.pnlAutoAttach.Visible = false;
        this.pnlAutoAttach.BackColor = NexusTheme.BackgroundPanel;

        // Row 1: Add entry controls
        int aaMargin = 12;
        int aaY = aaMargin;

        this.txtAutoAttachName.Location = new Point(aaMargin, aaY);
        this.txtAutoAttachName.Size = new Size(400, NexusTheme.TextBoxHeight);
        this.txtAutoAttachName.PlaceholderText = "Process name (e.g., notepad.exe)";
        NexusTheme.StyleTextBox(this.txtAutoAttachName);

        this.btnAutoAttachBrowse.Location = new Point(aaMargin + 406, aaY);
        this.btnAutoAttachBrowse.Size = new Size(32, NexusTheme.ButtonHeight);
        this.btnAutoAttachBrowse.Text = "...";
        this.btnAutoAttachBrowse.Click += new EventHandler(this.BtnAutoAttachBrowse_Click);
        NexusTheme.StyleButton(this.btnAutoAttachBrowse);

        this.btnAutoAttachAdd.Location = new Point(aaMargin + 444, aaY);
        this.btnAutoAttachAdd.Size = new Size(60, NexusTheme.ButtonHeight);
        this.btnAutoAttachAdd.Text = "Add";
        this.btnAutoAttachAdd.Click += new EventHandler(this.BtnAutoAttachAdd_Click);
        NexusTheme.StylePrimaryButton(this.btnAutoAttachAdd);

        // Row 2: ListView
        aaY += NexusTheme.ButtonHeight + NexusTheme.Space8;
        this.lvAutoAttach.Location = new Point(aaMargin, aaY);
        this.lvAutoAttach.Size = new Size(732, 200);
        this.lvAutoAttach.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
        this.lvAutoAttach.View = View.Details;
        this.lvAutoAttach.FullRowSelect = true;
        this.lvAutoAttach.CheckBoxes = true;
        this.lvAutoAttach.GridLines = true;
        this.lvAutoAttach.Columns.AddRange(new ColumnHeader[] {
            this.colAutoAttachName, this.colAutoAttachType, this.colAutoAttachEnabled
        });
        this.lvAutoAttach.ItemChecked += new ItemCheckedEventHandler(this.LvAutoAttach_ItemChecked);
        NexusTheme.StyleListView(this.lvAutoAttach);

        this.colAutoAttachName.Text = "Process/Window";
        this.colAutoAttachName.Width = 500;
        this.colAutoAttachType.Text = "Type";
        this.colAutoAttachType.Width = 80;
        this.colAutoAttachEnabled.Text = "Enabled";
        this.colAutoAttachEnabled.Width = 60;

        // Row 3: Remove button and check interval
        aaY += 200 + NexusTheme.Space8;
        this.btnAutoAttachRemove.Location = new Point(aaMargin, aaY);
        this.btnAutoAttachRemove.Anchor = AnchorStyles.Bottom | AnchorStyles.Left;
        this.btnAutoAttachRemove.Size = new Size(120, NexusTheme.ButtonHeight);
        this.btnAutoAttachRemove.Text = "Remove Selected";
        this.btnAutoAttachRemove.Click += new EventHandler(this.BtnAutoAttachRemove_Click);
        NexusTheme.StyleButton(this.btnAutoAttachRemove);

        this.lblCheckInterval.Location = new Point(aaMargin + 300, aaY + 5);
        this.lblCheckInterval.Anchor = AnchorStyles.Bottom | AnchorStyles.Left;
        this.lblCheckInterval.AutoSize = true;
        this.lblCheckInterval.Text = "Check interval (ms):";
        this.lblCheckInterval.ForeColor = NexusTheme.TextPrimary;

        this.nudCheckInterval.Location = new Point(aaMargin + 430, aaY);
        this.nudCheckInterval.Anchor = AnchorStyles.Bottom | AnchorStyles.Left;
        this.nudCheckInterval.Size = new Size(90, NexusTheme.TextBoxHeight);
        this.nudCheckInterval.Minimum = 100;
        this.nudCheckInterval.Maximum = 60000;
        this.nudCheckInterval.Value = NexusSettings.Instance.AutoAttachCheckInterval;
        this.nudCheckInterval.Increment = 100;
        this.nudCheckInterval.ValueChanged += new EventHandler(this.NudCheckInterval_ValueChanged);
        this.nudCheckInterval.BackColor = NexusTheme.BackgroundControl;
        this.nudCheckInterval.ForeColor = NexusTheme.TextPrimary;

        this.pnlAutoAttach.Controls.Add(this.txtAutoAttachName);
        this.pnlAutoAttach.Controls.Add(this.btnAutoAttachBrowse);
        this.pnlAutoAttach.Controls.Add(this.btnAutoAttachAdd);
        this.pnlAutoAttach.Controls.Add(this.lvAutoAttach);
        this.pnlAutoAttach.Controls.Add(this.btnAutoAttachRemove);
        this.pnlAutoAttach.Controls.Add(this.lblCheckInterval);
        this.pnlAutoAttach.Controls.Add(this.nudCheckInterval);

        //
        // Filter controls
        //
        this.lblFilter.Anchor = AnchorStyles.Bottom | AnchorStyles.Left;
        this.lblFilter.AutoSize = true;
        this.lblFilter.Location = new Point(12, 407);
        this.lblFilter.Text = "Filter:";

        this.txtFilter.Anchor = AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
        this.txtFilter.Location = new Point(55, 404);
        this.txtFilter.Size = new Size(400, 23);
        this.txtFilter.TabIndex = 1;
        this.txtFilter.TextChanged += new EventHandler(this.TxtFilter_TextChanged);

        this.lblCount.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
        this.lblCount.AutoSize = true;
        this.lblCount.Location = new Point(550, 407);
        this.lblCount.Text = "0 processes";

        //
        // pnlButtons - use FlowLayoutPanel for consistent spacing
        //
        this.pnlButtons.Anchor = AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
        this.pnlButtons.Controls.Add(this.btnNetwork);
        this.pnlButtons.Controls.Add(this.btnOK);
        this.pnlButtons.Controls.Add(this.btnCancel);
        this.pnlButtons.Controls.Add(this.btnRefresh);
        this.pnlButtons.Controls.Add(this.btnAddToAutoAttach);
        this.pnlButtons.Controls.Add(this.btnAttachDebugger);
        this.pnlButtons.Location = new Point(12, 435);
        this.pnlButtons.Size = new Size(756, 50);

        // Network button on far left
        this.btnNetwork.Location = new Point(0, 10);
        this.btnNetwork.Size = new Size(100, NexusTheme.ButtonHeight);
        this.btnNetwork.Text = "Network";
        this.btnNetwork.Click += new EventHandler(this.BtnNetwork_Click);
        NexusTheme.StyleButton(this.btnNetwork);

        // Main action buttons - tighter spacing to fit all
        int centerStart = 115;
        int btnWidth = 75;  // Smaller buttons
        int btnGap = 6;

        this.btnOK.Location = new Point(centerStart, 10);
        this.btnOK.Size = new Size(btnWidth, NexusTheme.ButtonHeight);
        this.btnOK.Text = "Open";
        this.btnOK.Click += new EventHandler(this.BtnOK_Click);
        NexusTheme.StylePrimaryButton(this.btnOK);

        this.btnCancel.Location = new Point(centerStart + btnWidth + btnGap, 10);
        this.btnCancel.Size = new Size(btnWidth, NexusTheme.ButtonHeight);
        this.btnCancel.Text = "Cancel";
        this.btnCancel.DialogResult = DialogResult.Cancel;
        this.btnCancel.Click += new EventHandler(this.BtnCancel_Click);
        NexusTheme.StyleButton(this.btnCancel);

        this.btnRefresh.Location = new Point(centerStart + (btnWidth + btnGap) * 2, 10);
        this.btnRefresh.Size = new Size(btnWidth, NexusTheme.ButtonHeight);
        this.btnRefresh.Text = "Refresh";
        this.btnRefresh.Click += new EventHandler(this.BtnRefresh_Click);
        NexusTheme.StyleButton(this.btnRefresh);

        // Add to Auto-Attach button (visible on tabs 0-2)
        this.btnAddToAutoAttach.Location = new Point(centerStart + (btnWidth + btnGap) * 3, 10);
        this.btnAddToAutoAttach.Size = new Size(110, NexusTheme.ButtonHeight);
        this.btnAddToAutoAttach.Text = "+ Auto-Attach";
        this.btnAddToAutoAttach.Click += new EventHandler(this.BtnAddToAutoAttach_Click);
        NexusTheme.StyleButton(this.btnAddToAutoAttach);

        // Attach Debugger button on right
        this.btnAttachDebugger.Text = "Attach Debugger";
        this.btnAttachDebugger.Click += new EventHandler(this.BtnAttachDebugger_Click);
        NexusTheme.StylePrimaryButton(this.btnAttachDebugger);
        this.btnAttachDebugger.Anchor = AnchorStyles.Top | AnchorStyles.Right;
        this.btnAttachDebugger.Location = new Point(756 - 120, 10);
        this.btnAttachDebugger.Size = new Size(120, NexusTheme.ButtonHeight);

        //
        // ctxProcessList
        //
        this.ctxProcessList.Items.AddRange(new ToolStripItem[] {
            this.miInputPidManually,
            this.miFilter,
            this.miRefresh,
            this.toolStripSeparator1,
            this.miShowInvisible,
            this.miOwnProcessesOnly,
            this.miConvertPidToDecimal
        });

        this.miInputPidManually.Text = "Input PID manually";
        this.miInputPidManually.ShortcutKeys = Keys.Control | Keys.P;
        this.miInputPidManually.Click += new EventHandler(this.MiInputPidManually_Click);

        this.miFilter.Text = "Filter";
        this.miFilter.ShortcutKeys = Keys.Control | Keys.F;

        this.miRefresh.Text = "Refresh";
        this.miRefresh.ShortcutKeys = Keys.F5;
        this.miRefresh.Click += new EventHandler(this.BtnRefresh_Click);

        this.miShowInvisible.Text = "Show invisible windows";
        this.miShowInvisible.CheckOnClick = true;
        this.miShowInvisible.Click += new EventHandler(this.MiShowInvisible_Click);

        this.miOwnProcessesOnly.Text = "Only show processes of the current user";
        this.miOwnProcessesOnly.CheckOnClick = true;
        this.miOwnProcessesOnly.Click += new EventHandler(this.MiOwnProcessesOnly_Click);

        this.miConvertPidToDecimal.Text = "Convert PID to decimal";
        this.miConvertPidToDecimal.CheckOnClick = true;
        this.miConvertPidToDecimal.Click += new EventHandler(this.MiConvertPidToDecimal_Click);

        //
        // refreshTimer
        //
        this.refreshTimer.Interval = 2000;
        this.refreshTimer.Tick += new EventHandler(this.RefreshTimer_Tick);

        //
        // ProcessWindow
        //
        this.AcceptButton = this.btnOK;
        this.CancelButton = this.btnCancel;
        this.AutoScaleDimensions = new SizeF(7F, 15F);
        this.AutoScaleMode = AutoScaleMode.Font;
        this.ClientSize = new Size(780, 490);
        this.BackColor = NexusTheme.BackgroundDark;
        this.Controls.Add(this.menuStrip);
        this.Controls.Add(this._tabBar);
        this.Controls.Add(this.pnlContent);
        this.Controls.Add(this.lblFilter);
        this.Controls.Add(this.txtFilter);
        this.Controls.Add(this.lblCount);
        this.Controls.Add(this.pnlButtons);
        this.MainMenuStrip = this.menuStrip;
        this.MaximizeBox = false;
        this.MinimizeBox = false;
        this.MinimumSize = new Size(400, 400);
        this.Name = "ProcessWindow";
        this.ShowIcon = false;
        this.ShowInTaskbar = false;
        this.StartPosition = FormStartPosition.CenterParent;
        this.Text = "Process List";

        this.menuStrip.ResumeLayout(false);
        this.menuStrip.PerformLayout();
        this.pnlButtons.ResumeLayout(false);
        this.ctxProcessList.ResumeLayout(false);
        this.ResumeLayout(false);
        this.PerformLayout();
    }

    // Menu
    private MenuStrip menuStrip = null!;
    private ToolStripMenuItem fileMenu = null!;
    private ToolStripMenuItem miCreateProcess = null!;
    private ToolStripMenuItem miOpenFile = null!;

    // Tab bar (shell-style Panel with Buttons)
    private Panel _tabBar = null!;
    private Button[] _tabButtons = null!;
    private Panel pnlContent = null!;
    private int _selectedTab = 0;

    // Process list
    private ListView lvProcesses = null!;
    private ColumnHeader colPid = null!;
    private ColumnHeader colName = null!;
    private ColumnHeader colArch = null!;

    // Windows list
    private ListView lvWindows = null!;
    private ColumnHeader colWinHandle = null!;
    private ColumnHeader colWinPid = null!;
    private ColumnHeader colWinTitle = null!;
    private ColumnHeader colWinClass = null!;

    // Applications list
    private ListView lvApplications = null!;
    private ColumnHeader colAppTitle = null!;
    private ColumnHeader colAppPid = null!;

    // Filter
    private TextBox txtFilter = null!;
    private Label lblFilter = null!;
    private Label lblCount = null!;

    // Buttons
    private Panel pnlButtons = null!;
    private Button btnOK = null!;
    private Button btnCancel = null!;
    private Button btnRefresh = null!;
    private Button btnAddToAutoAttach = null!;
    private Button btnAttachDebugger = null!;
    private Button btnNetwork = null!;

    // Auto Attach tab
    private Panel pnlAutoAttach = null!;
    private ListView lvAutoAttach = null!;
    private ColumnHeader colAutoAttachName = null!;
    private ColumnHeader colAutoAttachType = null!;
    private ColumnHeader colAutoAttachEnabled = null!;
    private TextBox txtAutoAttachName = null!;
    private Button btnAutoAttachBrowse = null!;
    private Button btnAutoAttachAdd = null!;
    private Button btnAutoAttachRemove = null!;
    private Label lblCheckInterval = null!;
    private NumericUpDown nudCheckInterval = null!;

    // Context menu
    private ContextMenuStrip ctxProcessList = null!;
    private ToolStripMenuItem miInputPidManually = null!;
    private ToolStripMenuItem miFilter = null!;
    private ToolStripMenuItem miRefresh = null!;
    private ToolStripSeparator toolStripSeparator1 = null!;
    private ToolStripMenuItem miShowInvisible = null!;
    private ToolStripMenuItem miOwnProcessesOnly = null!;
    private ToolStripMenuItem miConvertPidToDecimal = null!;

    // Timer
    private System.Windows.Forms.Timer refreshTimer = null!;
}
