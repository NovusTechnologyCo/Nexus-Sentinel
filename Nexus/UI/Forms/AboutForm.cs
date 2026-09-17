// <file>
// <summary>
// About dialog for Nexus Sentinel displaying application version, engine version,
// system information (OS, CPU, RAM, .NET runtime), and project credits.
// Contains three tabs: About, System Info, and Credits.
// </summary>
// </file>

using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using Nexus.UI.Styles;


namespace Nexus.UI.Forms;

/// <summary>
/// About dialog showing application identity, version information, system diagnostics,
/// and project credits. Displayed as a fixed-size modal dialog with three tabs.
/// </summary>
public class AboutForm : Form
{
    // Controls
    private PictureBox _picLogo = null!;
    private Label _lblTitle = null!;
    private Label _lblVersion = null!;
    private Label _lblEngineVersion = null!;
    private Label _lblCopyright = null!;

    // Tab bar (shell-style Panel with Buttons)
    private Panel _tabBar = null!;
    private Button[] _tabButtons = null!;
    private Panel _pnlContent = null!;
    private int _selectedTab = 0;

    // Content panels
    private Panel _pnlAbout = null!;
    private Panel _pnlSystem = null!;
    private Panel _pnlCredits = null!;
    private ListView _lvSystemInfo = null!;

    public AboutForm()
    {
        InitializeComponent();
        NexusTheme.StyleForm(this);

        // Override with lighter background after StyleForm sets BackgroundDark
        BackColor = NexusTheme.BackgroundDark;  // Form background darkest
        _tabBar.BackColor = NexusTheme.BackgroundElevated;
        _pnlContent.BackColor = NexusTheme.BackgroundElevated;
        _pnlAbout.BackColor = NexusTheme.BackgroundElevated;
        _pnlSystem.BackColor = NexusTheme.BackgroundElevated;
        _pnlCredits.BackColor = NexusTheme.BackgroundElevated;

        LoadSystemInfo();
        Load += (s, e) => SwitchTab(0);  // Apply tab selection after form loads
    }

    private void InitializeComponent()
    {
        Text = "About Nexus Sentinel";
        const int margin = Styles.NexusTheme.Space16;
        const int contentWidth = 528;  // 560 - (margin * 2)
        // Layout: headerHeight (112) + ToolbarHeight (36) + contentPanel (460) + margin (16) = 624
        ClientSize = new Size(560, 624);
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        BackColor = Styles.NexusTheme.BackgroundElevated;

        // Logo from embedded resources
        _picLogo = new PictureBox
        {
            Location = new Point(margin, margin),
            Size = new Size(80, 80),
            SizeMode = PictureBoxSizeMode.Zoom,
            BackColor = Color.Transparent
        };

        // Load logo from embedded resource
        try
        {
            var assembly = System.Reflection.Assembly.GetExecutingAssembly();
            using var stream = assembly.GetManifestResourceStream("Nexus.UI.Resources.logo.png");
            if (stream != null)
            {
                // Load as Bitmap to preserve transparency
                _picLogo.Image = new Bitmap(stream);
            }
        }
        catch
        {
            // Fallback if logo not found
            _picLogo.BackColor = Color.FromArgb(30, 30, 30);
        }

        // Title - positioned to the right of logo
        const int textX = margin + 80 + margin;  // logo left + logo width + gap
        _lblTitle = new Label
        {
            Text = "Nexus Sentinel",
            Location = new Point(textX, margin - 6),  // Align with top of logo visually
            AutoSize = true,
            Font = new Font(Font.FontFamily, 16, FontStyle.Bold)
        };

        // Version
        _lblVersion = new Label
        {
            Text = $"Version: 1.0.0",
            Location = new Point(textX, margin + 34),
            AutoSize = true
        };

        // Engine version
        _lblEngineVersion = new Label
        {
            Text = $"Engine: {NexusHelper.GetVersionString()}",
            Location = new Point(textX, margin + 54),
            AutoSize = true
        };

        // Copyright
        _lblCopyright = new Label
        {
            Text = "Copyright (c) 2025-2026 Nexus Sentinel Contributors",
            Location = new Point(textX, margin + 74),
            AutoSize = true
        };

        // Tab bar (shell-style using ToolStrip)
        const int headerHeight = margin + 80 + margin;  // logo top + logo height + gap
        (_tabBar, _tabButtons) = Styles.NexusTheme.CreateTabBar(
            ["About", "System Info", "Credits"],
            SwitchTab
        );
        _tabBar.Dock = DockStyle.None;  // Don't dock - use explicit position
        _tabBar.Location = new Point(margin, headerHeight);
        _tabBar.Size = new Size(contentWidth, Styles.NexusTheme.ToolbarHeight);

        // Make tab buttons fill the width evenly with 8px padding on sides, 4px gap between
        int padding = 8;
        int gap = 4;
        int totalGaps = (_tabButtons.Length - 1) * gap;  // Gaps between buttons
        int tabBarWidth = contentWidth - (padding * 2) - totalGaps;  // Account for padding and gaps
        int buttonWidth = tabBarWidth / _tabButtons.Length;
        int buttonHeight = Styles.NexusTheme.ToolbarHeight - padding;  // Top padding only
        for (int i = 0; i < _tabButtons.Length; i++)
        {
            _tabButtons[i].Location = new Point(padding + (i * (buttonWidth + gap)), padding);
            _tabButtons[i].Size = new Size(buttonWidth, buttonHeight);
        }

        // Content panel
        _pnlContent = new Panel
        {
            Location = new Point(margin, headerHeight + Styles.NexusTheme.ToolbarHeight),
            Size = new Size(contentWidth, 460),
            BackColor = Styles.NexusTheme.BackgroundElevated
        };

        // About panel
        _pnlAbout = new Panel { Dock = DockStyle.Fill, BackColor = Styles.NexusTheme.BackgroundElevated };
        var lblAbout = new Label
        {
            Text = "Nexus Sentinel - Advanced System Introspection Framework\n\n" +
                   "A unified platform for memory analysis, debugging,\n" +
                   "reverse engineering, and system monitoring.",
            Location = new Point(10, 10),
            Size = new Size(500, 75),
            AutoSize = false,
            ForeColor = Styles.NexusTheme.TextPrimary
        };

        var lblWebsite = new Label
        {
            Text = "Website: ",
            Location = new Point(10, 90),
            AutoSize = true,
            ForeColor = Styles.NexusTheme.TextPrimary
        };

        var linkWebsite = new LinkLabel
        {
            Text = "https://nexus-sentinel.org",
            Location = new Point(90, 90),
            AutoSize = true,
            LinkColor = Styles.NexusTheme.Accent,
            ActiveLinkColor = Styles.NexusTheme.AccentLight,
            VisitedLinkColor = Styles.NexusTheme.Accent
        };
        linkWebsite.LinkClicked += (s, e) =>
        {
            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "https://nexus-sentinel.org",
                    UseShellExecute = true
                });
            }
            catch { }
        };

        var lblLicense = new Label
        {
            Text = "License: AGPL-3.0 (Open Source)\n\n" +
                   "Features:\n" +
                   "  - Memory scanning with pointer resolution\n" +
                   "  - Debugging with breakpoints and stepping\n" +
                   "  - x86/x64 disassembly and code analysis\n" +
                   "  - Structure dissection (ReClass-style)\n" +
                   "  - Process and API monitoring\n" +
                   "  - C# scripting via Roslyn\n" +
                   "  - Plugin system with signature verification",
            Location = new Point(10, 115),
            Size = new Size(500, 320),
            AutoSize = false,
            ForeColor = Styles.NexusTheme.TextPrimary
        };

        _pnlAbout.Controls.Add(lblAbout);
        _pnlAbout.Controls.Add(lblWebsite);
        _pnlAbout.Controls.Add(linkWebsite);
        _pnlAbout.Controls.Add(lblLicense);

        // System panel
        _pnlSystem = new Panel { Dock = DockStyle.Fill, BackColor = Styles.NexusTheme.BackgroundElevated, Visible = false };
        _lvSystemInfo = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = true
        };
        _lvSystemInfo.Columns.Add("Property", 180);
        _lvSystemInfo.Columns.Add("Value", 300);
        Styles.NexusTheme.StyleListView(_lvSystemInfo);
        _pnlSystem.Controls.Add(_lvSystemInfo);

        // Credits panel - use ListView to match System Info border exactly
        _pnlCredits = new Panel { Dock = DockStyle.Fill, BackColor = Styles.NexusTheme.BackgroundElevated, Visible = false };
        var lvCredits = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            HeaderStyle = ColumnHeaderStyle.None,
            FullRowSelect = true,
            GridLines = false,
            Scrollable = true
        };
        lvCredits.Columns.Add("Credits", -2);  // -2 = auto-size to fill
        Styles.NexusTheme.StyleListView(lvCredits);

        // Add credits as list items
        string[] creditLines = {
            "Nexus Sentinel",
            "==============",
            "",
            "Lead Developer: Spontaneous",
            "",
            "Built with:",
            "  - .NET 10 (Microsoft)",
            "  - Roslyn Compiler (Microsoft)",
            "  - Zydis Disassembler (Florian Bernd, Joel Hoener)",
            "  - DbgHelp (Microsoft)",
            "",
            "Inspired by:",
            "  - Cheat Engine",
            "  - ReClass.NET",
            "  - x64dbg",
            "  - HyperDbg",
            "  - Process Monitor",
            "",
            "Special Thanks:",
            "  - The reverse engineering community",
            "  - All contributors",
        };
        foreach (var line in creditLines)
            lvCredits.Items.Add(line);

        _pnlCredits.Controls.Add(lvCredits);

        _pnlContent.Controls.Add(_pnlAbout);
        _pnlContent.Controls.Add(_pnlSystem);
        _pnlContent.Controls.Add(_pnlCredits);

        Controls.Add(_picLogo);
        Controls.Add(_lblTitle);
        Controls.Add(_lblVersion);
        Controls.Add(_lblEngineVersion);
        Controls.Add(_lblCopyright);
        Controls.Add(_tabBar);
        Controls.Add(_pnlContent);
    }

    private void SwitchTab(int tabIndex)
    {
        _selectedTab = tabIndex;

        // Update button appearance using standard helper
        Styles.NexusTheme.UpdateTabSelection(_tabButtons, tabIndex);

        // Show/hide panels
        _pnlAbout.Visible = tabIndex == 0;
        _pnlSystem.Visible = tabIndex == 1;
        _pnlCredits.Visible = tabIndex == 2;

        if (tabIndex == 0) _pnlAbout.BringToFront();
        else if (tabIndex == 1) _pnlSystem.BringToFront();
        else if (tabIndex == 2) _pnlCredits.BringToFront();
    }

    private void LoadSystemInfo()
    {
        _lvSystemInfo.Items.Clear();

        // OS info - get friendly name and full version
        string osName = GetWindowsVersionName();
        string osVersion = GetFullWindowsVersion();
        AddSystemItem("Operating System", osName);
        AddSystemItem("OS Version", osVersion);
        AddSystemItem("64-bit OS", Environment.Is64BitOperatingSystem ? "Yes" : "No");
        AddSystemItem("64-bit Process", Environment.Is64BitProcess ? "Yes" : "No");

        // .NET info
        AddSystemItem(".NET Version", Environment.Version.ToString());
        AddSystemItem("CLR Version", Environment.Version.ToString());

        // System info
        AddSystemItem("Machine Name", Environment.MachineName);
        AddSystemItem("User Name", Environment.UserName);
        AddSystemItem("Processor Count", Environment.ProcessorCount.ToString());
        AddSystemItem("System Directory", Environment.SystemDirectory);

        // Memory info
        var process = System.Diagnostics.Process.GetCurrentProcess();
        AddSystemItem("Working Set", $"{process.WorkingSet64 / 1024 / 1024} MB");
        AddSystemItem("Private Memory", $"{process.PrivateMemorySize64 / 1024 / 1024} MB");

        // Engine info
        AddSystemItem("Engine Loaded", "Yes"); // Assume loaded if we got here
        AddSystemItem("Engine Version", NexusHelper.GetVersionString());
    }

    private void AddSystemItem(string property, string value)
    {
        var item = new ListViewItem(property);
        item.SubItems.Add(value);
        _lvSystemInfo.Items.Add(item);
    }

    private static string GetWindowsVersionName()
    {
        // Windows 11 starts at build 22000
        var version = Environment.OSVersion.Version;
        if (version.Major == 10 && version.Build >= 22000)
            return "Windows 11";
        else if (version.Major == 10)
            return "Windows 10";
        else if (version.Major == 6 && version.Minor == 3)
            return "Windows 8.1";
        else if (version.Major == 6 && version.Minor == 2)
            return "Windows 8";
        else if (version.Major == 6 && version.Minor == 1)
            return "Windows 7";
        else
            return $"Windows {version.Major}.{version.Minor}";
    }

    private static string GetFullWindowsVersion()
    {
        try
        {
            // Read from registry to get full version including UBR (Update Build Revision)
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            if (key != null)
            {
                var major = key.GetValue("CurrentMajorVersionNumber");
                var minor = key.GetValue("CurrentMinorVersionNumber");
                var build = key.GetValue("CurrentBuildNumber") ?? key.GetValue("CurrentBuild");
                var ubr = key.GetValue("UBR");

                if (major != null && build != null)
                {
                    string version = $"{major}.{minor ?? 0}.{build}";
                    if (ubr != null)
                        version += $".{ubr}";
                    return version;
                }
            }
        }
        catch
        {
            // Fall back to Environment.OSVersion if registry fails
        }

        return Environment.OSVersion.Version.ToString();
    }

}

/// <summary>
/// Form for displaying diagnostic/debug information.
/// </summary>
public class DiagnosticsForm : Form
{
    private ListView _lvDiagnostics = null!;
    private Button _btnRefresh = null!;
    private Button _btnCopy = null!;
    private Button _btnClose = null!;

    private readonly IntPtr _processHandle;

    public DiagnosticsForm(IntPtr processHandle)
    {
        _processHandle = processHandle;
        InitializeComponent();
        NexusTheme.StyleForm(this);
        RefreshDiagnostics();
    }

    private void InitializeComponent()
    {
        Text = "Diagnostics";
        Size = new Size(600, 400);
        StartPosition = FormStartPosition.CenterParent;

        _lvDiagnostics = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = true
        };
        _lvDiagnostics.Columns.Add("Category", -2);
        _lvDiagnostics.Columns.Add("Property", -2);
        _lvDiagnostics.Columns.Add("Value", -2);

        var pnlBottom = new Panel
        {
            Dock = DockStyle.Bottom,
            Height = 45
        };

        _btnRefresh = new Button
        {
            Text = "Refresh",
            Location = new Point(10, 10),
            Size = new Size(80, 32)
        };
        _btnRefresh.Click += (s, e) => RefreshDiagnostics();

        _btnCopy = new Button
        {
            Text = "Copy",
            Location = new Point(100, 10),
            Size = new Size(80, 32)
        };
        _btnCopy.Click += BtnCopy_Click;

        _btnClose = new Button
        {
            Text = "Close",
            Location = new Point(490, 10),
            Size = new Size(80, 32),
            DialogResult = DialogResult.Cancel
        };
        _btnClose.Click += (s, e) => Close();

        pnlBottom.Controls.Add(_btnRefresh);
        pnlBottom.Controls.Add(_btnCopy);
        pnlBottom.Controls.Add(_btnClose);

        Controls.Add(_lvDiagnostics);
        Controls.Add(pnlBottom);
        CancelButton = _btnClose;
    }

    private void RefreshDiagnostics()
    {
        _lvDiagnostics.BeginUpdate();
        _lvDiagnostics.Items.Clear();

        // Engine diagnostics
        AddItem("Engine", "Loaded", "Yes"); // Assume loaded if we got here
        AddItem("Engine", "Version", NexusHelper.GetVersionString());

        if (_processHandle != IntPtr.Zero)
        {
            // Process info
            var result = NexusEngine.Nexus_GetProcessInfo(_processHandle, out var info);
            if (result == NexusResult.OK)
            {
                AddItem("Process", "Name", info.Name);
                AddItem("Process", "PID", info.Pid.ToString());
                AddItem("Process", "Is 64-bit", info.Is32Bit == 0 ? "Yes" : "No");
            }

            // Module count
            result = NexusEngine.Nexus_EnumerateModules(_processHandle, null, 0, out var moduleCount);
            AddItem("Process", "Module Count", moduleCount.ToString());

            // Thread count
            result = NexusEngine.Nexus_EnumerateThreads(_processHandle, null, 0, out var threadCount);
            AddItem("Process", "Thread Count", threadCount.ToString());
        }

        // Memory diagnostics
        var process = System.Diagnostics.Process.GetCurrentProcess();
        AddItem("Memory", "Working Set", $"{process.WorkingSet64 / 1024 / 1024} MB");
        AddItem("Memory", "Private Memory", $"{process.PrivateMemorySize64 / 1024 / 1024} MB");
        AddItem("Memory", "Virtual Memory", $"{process.VirtualMemorySize64 / 1024 / 1024} MB");
        AddItem("Memory", "GC Total Memory", $"{GC.GetTotalMemory(false) / 1024 / 1024} MB");

        // Thread diagnostics
        AddItem("Threads", "UI Thread Count", process.Threads.Count.ToString());

        _lvDiagnostics.EndUpdate();
    }

    private void AddItem(string category, string property, string value)
    {
        var item = new ListViewItem(category);
        item.SubItems.Add(property);
        item.SubItems.Add(value);
        _lvDiagnostics.Items.Add(item);
    }

    private void BtnCopy_Click(object? sender, EventArgs e)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("Nexus Diagnostics");
        sb.AppendLine("=================");

        foreach (ListViewItem item in _lvDiagnostics.Items)
        {
            sb.AppendLine($"[{item.Text}] {item.SubItems[1].Text}: {item.SubItems[2].Text}");
        }

        Clipboard.SetText(sb.ToString());
        MessageBox.Show("Diagnostics copied to clipboard.", "Info",
            MessageBoxButtons.OK, MessageBoxIcon.Information);
    }
}

/// <summary>
/// Form for viewing/editing application settings.
/// </summary>
public class OptionsForm : Form
{
    private TreeView _tvCategories = null!;
    private Panel _pnlOptions = null!;
    private Button _btnOK = null!;
    private Button _btnCancel = null!;
    private Button _btnApply = null!;

    // Settings panels
    private Panel _pnlGeneral = null!;
    private Panel _pnlScan = null!;
    private Panel _pnlDebugger = null!;
    private Panel _pnlHotkeys = null!;

    public OptionsForm()
    {
        InitializeComponent();
        NexusTheme.StyleForm(this);
        CreateSettingsPanels();
        SelectCategory("General");
    }

    private void InitializeComponent()
    {
        Text = "Options";
        Size = new Size(700, 500);
        StartPosition = FormStartPosition.CenterParent;

        // Category tree
        _tvCategories = new TreeView
        {
            Dock = DockStyle.Left,
            Width = 180
        };
        _tvCategories.Nodes.Add("General", "General");
        _tvCategories.Nodes.Add("Scan", "Scan Settings");
        _tvCategories.Nodes.Add("Debugger", "Debugger");
        _tvCategories.Nodes.Add("Hotkeys", "Hotkeys");
        _tvCategories.Nodes.Add("Updates", "Updates");
        _tvCategories.Nodes.Add("Plugins", "Plugins");
        _tvCategories.AfterSelect += TvCategories_AfterSelect;

        // Options panel
        _pnlOptions = new Panel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(10)
        };

        // Button panel
        var pnlButtons = new Panel
        {
            Dock = DockStyle.Bottom,
            Height = 45
        };

        _btnOK = new Button
        {
            Text = "OK",
            Location = new Point(475, 10),
            Size = new Size(80, 32),
            DialogResult = DialogResult.OK
        };
        _btnOK.Click += (s, e) => ApplySettings();

        _btnCancel = new Button
        {
            Text = "Cancel",
            Location = new Point(565, 10),
            Size = new Size(80, 32),
            DialogResult = DialogResult.Cancel
        };

        _btnApply = new Button
        {
            Text = "Apply",
            Location = new Point(385, 10),
            Size = new Size(80, 32)
        };
        _btnApply.Click += (s, e) => ApplySettings();

        pnlButtons.Controls.Add(_btnApply);
        pnlButtons.Controls.Add(_btnOK);
        pnlButtons.Controls.Add(_btnCancel);

        Controls.Add(_pnlOptions);
        Controls.Add(_tvCategories);
        Controls.Add(pnlButtons);
        AcceptButton = _btnOK;
        CancelButton = _btnCancel;
    }

    private void CreateSettingsPanels()
    {
        // General settings
        _pnlGeneral = new Panel { Dock = DockStyle.Fill, Visible = false };
        var chkRememberProcess = new CheckBox
        {
            Text = "Remember last attached process",
            Location = new Point(10, 10),
            AutoSize = true,
            Checked = true
        };
        var chkAutoAttach = new CheckBox
        {
            Text = "Auto-attach on startup",
            Location = new Point(10, 35),
            AutoSize = true
        };
        var chkMinimizeToTray = new CheckBox
        {
            Text = "Minimize to system tray",
            Location = new Point(10, 60),
            AutoSize = true
        };
        var chkShowSplash = new CheckBox
        {
            Text = "Show splash screen on startup",
            Location = new Point(10, 85),
            AutoSize = true,
            Checked = true
        };
        _pnlGeneral.Controls.Add(chkRememberProcess);
        _pnlGeneral.Controls.Add(chkAutoAttach);
        _pnlGeneral.Controls.Add(chkMinimizeToTray);
        _pnlGeneral.Controls.Add(chkShowSplash);
        _pnlOptions.Controls.Add(_pnlGeneral);

        // Scan settings
        _pnlScan = new Panel { Dock = DockStyle.Fill, Visible = false };
        var lblScanThreads = new Label
        {
            Text = "Scan thread count:",
            Location = new Point(10, 15),
            AutoSize = true
        };
        var nudScanThreads = new NumericUpDown
        {
            Location = new Point(175, 12),
            Width = 60,
            Minimum = 1,
            Maximum = 64,
            Value = Environment.ProcessorCount
        };
        var chkScanWritable = new CheckBox
        {
            Text = "Only scan writable memory",
            Location = new Point(10, 45),
            AutoSize = true,
            Checked = true
        };
        var chkScanExecutable = new CheckBox
        {
            Text = "Skip executable memory",
            Location = new Point(10, 70),
            AutoSize = true
        };
        var chkFastScan = new CheckBox
        {
            Text = "Fast scan (alignment optimization)",
            Location = new Point(10, 95),
            AutoSize = true,
            Checked = true
        };
        _pnlScan.Controls.Add(lblScanThreads);
        _pnlScan.Controls.Add(nudScanThreads);
        _pnlScan.Controls.Add(chkScanWritable);
        _pnlScan.Controls.Add(chkScanExecutable);
        _pnlScan.Controls.Add(chkFastScan);
        _pnlOptions.Controls.Add(_pnlScan);

        // Debugger settings
        _pnlDebugger = new Panel { Dock = DockStyle.Fill, Visible = false };
        var chkBreakOnAttach = new CheckBox
        {
            Text = "Break on attach",
            Location = new Point(10, 10),
            AutoSize = true
        };
        var chkBreakOnException = new CheckBox
        {
            Text = "Break on exceptions",
            Location = new Point(10, 35),
            AutoSize = true,
            Checked = true
        };
        var chkLogExceptions = new CheckBox
        {
            Text = "Log all exceptions",
            Location = new Point(10, 60),
            AutoSize = true
        };
        var chkUseHardwareBP = new CheckBox
        {
            Text = "Prefer hardware breakpoints",
            Location = new Point(10, 85),
            AutoSize = true,
            Checked = true
        };
        _pnlDebugger.Controls.Add(chkBreakOnAttach);
        _pnlDebugger.Controls.Add(chkBreakOnException);
        _pnlDebugger.Controls.Add(chkLogExceptions);
        _pnlDebugger.Controls.Add(chkUseHardwareBP);
        _pnlOptions.Controls.Add(_pnlDebugger);

        // Hotkeys settings
        _pnlHotkeys = new Panel { Dock = DockStyle.Fill, Visible = false };
        var lblHotkeysInfo = new Label
        {
            Text = "Configure global hotkeys for common operations.\n\n" +
                   "Click on a hotkey field and press the desired key combination.",
            Location = new Point(10, 10),
            Size = new Size(400, 50)
        };
        var btnEditHotkeys = new Button
        {
            Text = "Configure Hotkeys...",
            Location = new Point(10, 70),
            Size = new Size(140, 32)
        };
        btnEditHotkeys.Click += (s, e) =>
        {
            using var form = new HotkeyConfigForm();
            form.ShowDialog(this);
        };
        _pnlHotkeys.Controls.Add(lblHotkeysInfo);
        _pnlHotkeys.Controls.Add(btnEditHotkeys);
        _pnlOptions.Controls.Add(_pnlHotkeys);
    }

    private void TvCategories_AfterSelect(object? sender, TreeViewEventArgs e)
    {
        if (e.Node != null)
            SelectCategory(e.Node.Name);
    }

    private void SelectCategory(string category)
    {
        // Hide all panels
        _pnlGeneral.Visible = false;
        _pnlScan.Visible = false;
        _pnlDebugger.Visible = false;
        _pnlHotkeys.Visible = false;

        // Show selected panel
        switch (category)
        {
            case "General":
                _pnlGeneral.Visible = true;
                break;
            case "Scan":
                _pnlScan.Visible = true;
                break;
            case "Debugger":
                _pnlDebugger.Visible = true;
                break;
            case "Hotkeys":
                _pnlHotkeys.Visible = true;
                break;
        }
    }

    private void ApplySettings()
    {
        var settings = NexusSettings.Instance;

        // Read settings from General panel controls
        foreach (Control ctrl in _pnlGeneral.Controls)
        {
            if (ctrl is CheckBox chk)
            {
                // Map checkbox text to settings property
                // Note: These settings are placeholders for future implementation
            }
        }

        // Read settings from Scan panel controls
        foreach (Control ctrl in _pnlScan.Controls)
        {
            if (ctrl is CheckBox chk)
            {
                if (chk.Text.Contains("Only scan writable"))
                    settings.ScanMemImage = chk.Checked;
                else if (chk.Text.Contains("Fast scan"))
                    settings.SimpleFloatComparison = chk.Checked;
            }
            else if (ctrl is NumericUpDown nud && nud.Tag?.ToString() == "threads")
            {
                settings.ScanThreadCount = (int)nud.Value;
            }
        }

        // Read settings from Debugger panel controls
        foreach (Control ctrl in _pnlDebugger.Controls)
        {
            if (ctrl is CheckBox chk)
            {
                if (chk.Text.Contains("Break on attach"))
                    settings.BreakOnAttach = chk.Checked;
                else if (chk.Text.Contains("Break on exceptions"))
                    settings.HandleUnhandledBreakpoints = chk.Checked;
            }
        }

        // Save settings to disk
        settings.Save();

        MessageBox.Show("Settings saved.", "Info",
            MessageBoxButtons.OK, MessageBoxIcon.Information);
    }
}
