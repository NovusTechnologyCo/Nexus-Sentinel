// <file>
// <summary>
// Plugin manager dialog for viewing and managing plugin trust settings.
// </summary>
// </file>
using Nexus.UI.Helpers;
using Nexus.UI.Plugins;
using Nexus.UI.Styles;


namespace Nexus.UI.Forms;

/// <summary>
/// Form for managing plugins - viewing status, approving, blocking, etc.
/// </summary>
public class PluginManagerForm : Form
{
    private ListView _listView = null!;
    private Panel _detailsPanel = null!;
    private Label _lblName = null!;
    private Label _lblVersion = null!;
    private Label _lblAuthor = null!;
    private Label _lblDescription = null!;
    private Label _lblSignature = null!;
    private Label _lblTrust = null!;
    private Label _lblHash = null!;
    private Button _btnApprove = null!;
    private Button _btnBlock = null!;
    private Button _btnRevoke = null!;
    private Button _btnRefresh = null!;
    private Button _btnOpenFolder = null!;
    private Button _btnClose = null!;

    private readonly PluginLoader _loader;

    public PluginManagerForm(PluginLoader loader)
    {
        _loader = loader;
        InitializeComponent();
        NexusTheme.StyleForm(this);
        LoadPluginList();
    }

    private void InitializeComponent()
    {
        Text = "Plugin Manager";
        Size = new Size(800, 550);
        StartPosition = FormStartPosition.CenterParent;
        MinimumSize = new Size(600, 400);

        // Main split - list on left, details on right
        var splitContainer = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Orientation = Orientation.Vertical,
            SplitterDistance = 450,
            FixedPanel = FixedPanel.Panel2
        };

        // Plugin list
        _listView = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = true,
            MultiSelect = false
        };
        _listView.Columns.Add("Plugin", 180);
        _listView.Columns.Add("Version", 70);
        _listView.Columns.Add("Signature", 150);
        _listView.Columns.Add("Status", 100);
        _listView.SelectedIndexChanged += ListView_SelectedIndexChanged;
        _listView.DoubleClick += ListView_DoubleClick;

        splitContainer.Panel1.Controls.Add(_listView);

        // Details panel
        _detailsPanel = new Panel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(10)
        };

        var detailsLayout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 10,
            AutoSize = false
        };

        _lblName = new Label { AutoSize = true, Font = new Font(Font.FontFamily, 12, FontStyle.Bold) };
        _lblVersion = new Label { AutoSize = true };
        _lblAuthor = new Label { AutoSize = true };
        _lblDescription = new Label { AutoSize = true, MaximumSize = new Size(280, 60) };
        _lblSignature = new Label { AutoSize = true };
        _lblTrust = new Label { AutoSize = true };
        _lblHash = new Label { AutoSize = true, Font = new Font("Consolas", 8), MaximumSize = new Size(280, 40) };

        detailsLayout.Controls.Add(_lblName);
        detailsLayout.Controls.Add(_lblVersion);
        detailsLayout.Controls.Add(_lblAuthor);
        detailsLayout.Controls.Add(new Label { Height = 10 }); // Spacer
        detailsLayout.Controls.Add(_lblDescription);
        detailsLayout.Controls.Add(new Label { Height = 10 }); // Spacer
        detailsLayout.Controls.Add(_lblSignature);
        detailsLayout.Controls.Add(_lblTrust);
        detailsLayout.Controls.Add(new Label { Height = 10 }); // Spacer
        detailsLayout.Controls.Add(_lblHash);

        _detailsPanel.Controls.Add(detailsLayout);
        splitContainer.Panel2.Controls.Add(_detailsPanel);

        // Button panel
        var buttonPanel = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom,
            FlowDirection = FlowDirection.RightToLeft,
            Height = 45,
            Padding = new Padding(5)
        };

        _btnClose = new Button { Text = "Close", Width = 80, Height = 30 };
        _btnClose.Click += (s, e) => Close();

        _btnOpenFolder = new Button { Text = "Open Folder", Width = 100, Height = 30 };
        _btnOpenFolder.Click += BtnOpenFolder_Click;

        _btnRefresh = new Button { Text = "Refresh", Width = 80, Height = 30 };
        _btnRefresh.Click += BtnRefresh_Click;

        _btnRevoke = new Button { Text = "Revoke", Width = 80, Height = 30 };
        _btnRevoke.Click += BtnRevoke_Click;

        _btnBlock = new Button { Text = "Block", Width = 80, Height = 30 };
        _btnBlock.Click += BtnBlock_Click;

        _btnApprove = new Button { Text = "Approve", Width = 80, Height = 30 };
        _btnApprove.Click += BtnApprove_Click;

        buttonPanel.Controls.Add(_btnClose);
        buttonPanel.Controls.Add(_btnOpenFolder);
        buttonPanel.Controls.Add(_btnRefresh);
        buttonPanel.Controls.Add(_btnRevoke);
        buttonPanel.Controls.Add(_btnBlock);
        buttonPanel.Controls.Add(_btnApprove);

        Controls.Add(splitContainer);
        Controls.Add(buttonPanel);

        UpdateButtonStates();
    }

    private void LoadPluginList()
    {
        _listView.Items.Clear();

        foreach (var plugin in _loader.Plugins)
        {
            var item = new ListViewItem(plugin.Name ?? plugin.FileName);
            item.SubItems.Add(plugin.Version ?? "-");
            item.SubItems.Add(plugin.SignatureStatusDisplay);
            item.SubItems.Add(GetStatusText(plugin));
            item.Tag = plugin;

            // Color coding
            item.ForeColor = plugin.TrustStatus switch
            {
                PluginTrustStatus.Trusted => Color.Green,
                PluginTrustStatus.UserApproved => Color.DarkCyan,
                PluginTrustStatus.RequiresApproval => Color.Orange,
                PluginTrustStatus.Blocked => Color.Red,
                _ => ForeColor
            };

            if (plugin.SignatureStatus == PluginSignatureStatus.Invalid)
            {
                item.ForeColor = Color.Red;
                item.Font = new Font(item.Font, FontStyle.Strikeout);
            }

            _listView.Items.Add(item);
        }
    }

    private string GetStatusText(PluginInfo plugin)
    {
        if (plugin.IsLoaded)
            return "Loaded";
        if (!string.IsNullOrEmpty(plugin.LoadError))
            return "Error";
        return plugin.TrustStatusDisplay;
    }

    private void ListView_SelectedIndexChanged(object? sender, EventArgs e)
    {
        UpdateDetails();
        UpdateButtonStates();
    }

    private void ListView_DoubleClick(object? sender, EventArgs e)
    {
        // Could open plugin settings or info dialog
    }

    private void UpdateDetails()
    {
        var plugin = GetSelectedPlugin();
        if (plugin == null)
        {
            _lblName.Text = "";
            _lblVersion.Text = "";
            _lblAuthor.Text = "";
            _lblDescription.Text = "";
            _lblSignature.Text = "";
            _lblTrust.Text = "";
            _lblHash.Text = "";
            return;
        }

        _lblName.Text = plugin.Name ?? plugin.FileName;
        _lblVersion.Text = $"Version: {plugin.Version ?? "Unknown"}";
        _lblAuthor.Text = $"Author: {plugin.Author ?? "Unknown"}";
        _lblDescription.Text = plugin.Description ?? "No description available.";

        _lblSignature.Text = $"Signature: {plugin.SignatureStatusDisplay}";
        _lblSignature.ForeColor = plugin.SignatureStatus switch
        {
            PluginSignatureStatus.TrustedNexus => Color.Green,
            PluginSignatureStatus.SignedOther => Color.DarkCyan,
            PluginSignatureStatus.Invalid => Color.Red,
            PluginSignatureStatus.Unsigned => Color.Orange,
            _ => ForeColor
        };

        _lblTrust.Text = $"Trust: {plugin.TrustStatusDisplay}";
        _lblTrust.ForeColor = plugin.TrustStatus switch
        {
            PluginTrustStatus.Trusted => Color.Green,
            PluginTrustStatus.UserApproved => Color.DarkCyan,
            PluginTrustStatus.RequiresApproval => Color.Orange,
            PluginTrustStatus.Blocked => Color.Red,
            _ => ForeColor
        };

        _lblHash.Text = $"SHA256:\n{plugin.FileHash}";

        if (!string.IsNullOrEmpty(plugin.LoadError))
        {
            _lblDescription.Text = $"Load Error: {plugin.LoadError}";
            _lblDescription.ForeColor = Color.Red;
        }
        else
        {
            _lblDescription.ForeColor = ForeColor;
        }
    }

    private void UpdateButtonStates()
    {
        var plugin = GetSelectedPlugin();
        var hasSelection = plugin != null;

        _btnApprove.Enabled = hasSelection &&
            plugin!.TrustStatus == PluginTrustStatus.RequiresApproval &&
            plugin.SignatureStatus != PluginSignatureStatus.Invalid;

        _btnBlock.Enabled = hasSelection &&
            plugin!.TrustStatus != PluginTrustStatus.Blocked &&
            plugin.TrustStatus != PluginTrustStatus.Trusted; // Can't block official plugins

        _btnRevoke.Enabled = hasSelection &&
            plugin!.TrustStatus == PluginTrustStatus.UserApproved;
    }

    private PluginInfo? GetSelectedPlugin()
    {
        if (_listView.SelectedItems.Count == 0)
            return null;
        return _listView.SelectedItems[0].Tag as PluginInfo;
    }

    private void BtnApprove_Click(object? sender, EventArgs e)
    {
        var plugin = GetSelectedPlugin();
        if (plugin == null) return;

        var result = MessageBox.Show(
            $"Are you sure you want to approve this plugin?\n\n" +
            $"File: {plugin.FileName}\n" +
            $"Signature: {plugin.SignatureStatusDisplay}\n" +
            $"Hash: {plugin.FileHash[..16]}...\n\n" +
            "The plugin will be loaded and allowed to run.",
            "Approve Plugin",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Question);

        if (result == DialogResult.Yes)
        {
            _loader.TrustSettings.Approve(plugin.FileHash, plugin.FileName, plugin.Name);
            plugin.TrustStatus = PluginTrustStatus.UserApproved;
            _loader.SaveTrustSettings();
            LoadPluginList();

            MessageBox.Show(
                "Plugin approved. Restart Nexus to load the plugin.",
                "Plugin Approved",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }
    }

    private void BtnBlock_Click(object? sender, EventArgs e)
    {
        var plugin = GetSelectedPlugin();
        if (plugin == null) return;

        var result = MessageBox.Show(
            $"Are you sure you want to block this plugin?\n\n" +
            $"File: {plugin.FileName}\n" +
            $"Hash: {plugin.FileHash[..16]}...\n\n" +
            "The plugin will not be loaded.",
            "Block Plugin",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Warning);

        if (result == DialogResult.Yes)
        {
            _loader.TrustSettings.Block(plugin.FileHash);
            plugin.TrustStatus = PluginTrustStatus.Blocked;
            _loader.SaveTrustSettings();
            LoadPluginList();
        }
    }

    private void BtnRevoke_Click(object? sender, EventArgs e)
    {
        var plugin = GetSelectedPlugin();
        if (plugin == null) return;

        var result = MessageBox.Show(
            $"Revoke approval for this plugin?\n\n" +
            $"File: {plugin.FileName}\n\n" +
            "You will be prompted again next time Nexus starts.",
            "Revoke Approval",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Question);

        if (result == DialogResult.Yes)
        {
            _loader.TrustSettings.RevokeApproval(plugin.FileHash);
            plugin.TrustStatus = PluginTrustStatus.RequiresApproval;
            _loader.SaveTrustSettings();
            LoadPluginList();
        }
    }

    private void BtnRefresh_Click(object? sender, EventArgs e)
    {
        _loader.DiscoverPlugins();
        LoadPluginList();
    }

    private void BtnOpenFolder_Click(object? sender, EventArgs e)
    {
        try
        {
            var pluginsPath = Path.GetDirectoryName(_loader.Plugins.FirstOrDefault()?.FilePath);
            if (pluginsPath == null)
            {
                pluginsPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "plugins");
            }

            if (!Directory.Exists(pluginsPath))
            {
                Directory.CreateDirectory(pluginsPath);
            }

            System.Diagnostics.Process.Start("explorer.exe", pluginsPath);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Failed to open plugins folder: {ex.Message}",
                "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }
}

/// <summary>
/// Dialog shown when a plugin requires user approval.
/// </summary>
public class PluginApprovalDialog : Form
{
    private readonly PluginInfo _plugin;
    public bool Approved { get; private set; }
    public bool Blocked { get; private set; }

    public PluginApprovalDialog(PluginInfo plugin)
    {
        _plugin = plugin;
        InitializeComponent();
        NexusTheme.StyleForm(this);
    }

    private void InitializeComponent()
    {
        Text = "Plugin Approval Required";
        Size = new Size(500, 320);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        StartPosition = FormStartPosition.CenterParent;

        var warningIcon = new PictureBox
        {
            Image = SystemIcons.Warning.ToBitmap(),
            Size = new Size(48, 48),
            Location = new Point(20, 20),
            SizeMode = PictureBoxSizeMode.Zoom
        };

        var lblTitle = new Label
        {
            Text = "An unsigned plugin wants to load",
            Font = new Font(Font.FontFamily, 12, FontStyle.Bold),
            Location = new Point(80, 20),
            AutoSize = true
        };

        var lblFile = new Label
        {
            Text = $"File: {_plugin.FileName}",
            Location = new Point(80, 50),
            AutoSize = true
        };

        var lblSignature = new Label
        {
            Text = $"Signature: {_plugin.SignatureStatusDisplay}",
            Location = new Point(80, 75),
            AutoSize = true,
            ForeColor = _plugin.SignatureStatus == PluginSignatureStatus.Unsigned ? Color.Orange : Color.Red
        };

        var lblHash = new Label
        {
            Text = $"SHA256: {_plugin.FileHash}",
            Location = new Point(20, 110),
            Size = new Size(450, 35),
            Font = new Font("Consolas", 8)
        };

        var lblWarning = new Label
        {
            Text = "This plugin is not signed by Nexus Sentinel.\n" +
                   "Only approve plugins from sources you trust.",
            Location = new Point(20, 155),
            Size = new Size(450, 40),
            ForeColor = Color.DarkOrange
        };

        var chkRemember = new CheckBox
        {
            Text = "Remember my choice for this plugin",
            Location = new Point(20, 200),
            AutoSize = true,
            Checked = true
        };

        var btnApprove = new Button
        {
            Text = "Approve",
            Location = new Point(200, 240),
            Size = new Size(90, 32)
        };
        btnApprove.Click += (s, e) =>
        {
            Approved = true;
            DialogResult = DialogResult.OK;
            Close();
        };

        var btnBlock = new Button
        {
            Text = "Block",
            Location = new Point(300, 240),
            Size = new Size(90, 32)
        };
        btnBlock.Click += (s, e) =>
        {
            Blocked = true;
            DialogResult = DialogResult.OK;
            Close();
        };

        var btnSkip = new Button
        {
            Text = "Skip",
            Location = new Point(400, 240),
            Size = new Size(70, 32)
        };
        btnSkip.Click += (s, e) =>
        {
            DialogResult = DialogResult.Cancel;
            Close();
        };

        Controls.Add(warningIcon);
        Controls.Add(lblTitle);
        Controls.Add(lblFile);
        Controls.Add(lblSignature);
        Controls.Add(lblHash);
        Controls.Add(lblWarning);
        Controls.Add(chkRemember);
        Controls.Add(btnApprove);
        Controls.Add(btnBlock);
        Controls.Add(btnSkip);

        AcceptButton = btnSkip;
        CancelButton = btnSkip;
    }
}
