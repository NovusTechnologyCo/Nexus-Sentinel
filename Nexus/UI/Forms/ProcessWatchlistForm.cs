// <file>
// <summary>
// Watchlist management dialog for process and kernel driver monitoring targets.
// </summary>
// </file>
using Nexus.UI.Models;
using Nexus.UI.Services;
using Nexus.UI.Styles;

namespace Nexus.UI.Forms;

/// <summary>
/// Configuration dialog for managing the list of watched process names and kernel driver names.
/// </summary>
public class ProcessWatchlistForm : Form
{
    private readonly ProcessWatchlist _watchlist;
    private ListView _lvEntries = null!;
    private Button _btnAddProcess = null!;
    private Button _btnAddDriver = null!;
    private Button _btnRemove = null!;
    private CheckBox _chkFollowChildren = null!;
    private CheckBox _chkPassiveMode = null!;
    private Button _btnSaveProfile = null!;
    private Button _btnLoadProfile = null!;
    private Button _btnOk = null!;
    private Button _btnCancel = null!;
    private ToolStripStatusLabel _lblStatus = null!;
    private System.Windows.Forms.Timer? _refreshTimer;

    public ProcessWatchlistForm()
    {
        _watchlist = ProcessWatchlist.Instance;
        InitializeComponent();
        NexusTheme.StyleForm(this);
        PopulateList();
        UpdateButtonStates();
    }

    private void InitializeComponent()
    {
        Text = "Process & Driver Watchlist";
        Size = new Size(700, 480);
        MinimumSize = new Size(550, 380);
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.Sizable;

        // ListView for entries
        _lvEntries = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = true,
            MultiSelect = false,
            Font = new Font("Consolas", 9F)
        };

        _lvEntries.Columns.AddRange([
            new ColumnHeader { Text = "Type", Width = 70 },
            new ColumnHeader { Text = "Name", Width = 180 },
            new ColumnHeader { Text = "Status", Width = 90 },
            new ColumnHeader { Text = "PID / Base", Width = 160 },
            new ColumnHeader { Text = "Enabled", Width = 60 }
        ]);

        _lvEntries.SelectedIndexChanged += (s, e) => UpdateButtonStates();

        // Right-side button panel
        var pnlButtons = new Panel
        {
            Dock = DockStyle.Right,
            Width = 150,
            Padding = new Padding(NexusTheme.Space8)
        };

        int btnY = NexusTheme.Space8;
        int btnWidth = 130;
        int btnHeight = NexusTheme.ButtonHeight;
        int btnGap = NexusTheme.Space8;

        _btnAddProcess = new Button
        {
            Text = "Add Process...",
            Location = new Point(NexusTheme.Space8, btnY),
            Size = new Size(btnWidth, btnHeight)
        };
        NexusTheme.StyleButton(_btnAddProcess);
        _btnAddProcess.Click += BtnAddProcess_Click;
        btnY += btnHeight + btnGap;

        _btnAddDriver = new Button
        {
            Text = "Add Driver...",
            Location = new Point(NexusTheme.Space8, btnY),
            Size = new Size(btnWidth, btnHeight)
        };
        NexusTheme.StyleButton(_btnAddDriver);
        _btnAddDriver.Click += BtnAddDriver_Click;
        btnY += btnHeight + btnGap;

        _btnRemove = new Button
        {
            Text = "Remove",
            Location = new Point(NexusTheme.Space8, btnY),
            Size = new Size(btnWidth, btnHeight),
            Enabled = false
        };
        NexusTheme.StyleButton(_btnRemove);
        _btnRemove.Click += BtnRemove_Click;
        btnY += btnHeight + btnGap;

        // Separator gap
        btnY += btnGap;

        btnY += btnHeight + btnGap * 3;

        _btnSaveProfile = new Button
        {
            Text = "Save Profile...",
            Location = new Point(NexusTheme.Space8, btnY),
            Size = new Size(btnWidth, btnHeight)
        };
        NexusTheme.StyleButton(_btnSaveProfile);
        _btnSaveProfile.Click += BtnSaveProfile_Click;
        btnY += btnHeight + btnGap;

        _btnLoadProfile = new Button
        {
            Text = "Load Profile...",
            Location = new Point(NexusTheme.Space8, btnY),
            Size = new Size(btnWidth, btnHeight)
        };
        NexusTheme.StyleButton(_btnLoadProfile);
        _btnLoadProfile.Click += BtnLoadProfile_Click;

        pnlButtons.Controls.AddRange([
            _btnAddProcess, _btnAddDriver, _btnRemove,
            _btnSaveProfile, _btnLoadProfile
        ]);

        // Bottom panel with checkboxes and OK/Cancel
        var pnlBottom = new Panel
        {
            Dock = DockStyle.Bottom,
            Height = 100
        };

        _chkPassiveMode = new CheckBox
        {
            Text = "Passive mode (ETW only - no handle opening or DLL injection)",
            Location = new Point(NexusTheme.DialogPadding, 8),
            AutoSize = true,
            Checked = _watchlist.PassiveMode
        };
        NexusTheme.StyleCheckBox(_chkPassiveMode);
        _chkPassiveMode.CheckedChanged += (s, e) =>
        {
            _watchlist.PassiveMode = _chkPassiveMode.Checked;
        };

        _chkFollowChildren = new CheckBox
        {
            Text = "Follow child processes",
            Location = new Point(NexusTheme.DialogPadding, 30),
            AutoSize = true,
            Checked = _watchlist.FollowChildProcesses
        };
        NexusTheme.StyleCheckBox(_chkFollowChildren);
        _chkFollowChildren.CheckedChanged += (s, e) =>
        {
            _watchlist.FollowChildProcesses = _chkFollowChildren.Checked;
        };

        _btnOk = new Button
        {
            Text = "OK",
            Size = new Size(NexusTheme.ButtonWidth, NexusTheme.ButtonHeight),
            Anchor = AnchorStyles.Bottom | AnchorStyles.Right,
            DialogResult = DialogResult.OK
        };
        NexusTheme.StylePrimaryButton(_btnOk);
        _btnOk.Click += (s, e) => Close();

        _btnCancel = new Button
        {
            Text = "Cancel",
            Size = new Size(NexusTheme.ButtonWidth, NexusTheme.ButtonHeight),
            Anchor = AnchorStyles.Bottom | AnchorStyles.Right,
            DialogResult = DialogResult.Cancel
        };
        NexusTheme.StyleButton(_btnCancel);
        _btnCancel.Click += (s, e) => Close();

        // Position OK/Cancel relative to bottom-right
        _btnCancel.Location = new Point(
            pnlBottom.Width - NexusTheme.DialogPadding - NexusTheme.ButtonWidth,
            pnlBottom.Height - NexusTheme.DialogPadding - NexusTheme.ButtonHeight);
        _btnOk.Location = new Point(
            _btnCancel.Left - NexusTheme.ButtonGap - NexusTheme.ButtonWidth,
            _btnCancel.Top);

        pnlBottom.Controls.AddRange([_chkPassiveMode, _chkFollowChildren, _btnOk, _btnCancel]);

        // Status bar
        var statusStrip = new StatusStrip();
        _lblStatus = new ToolStripStatusLabel { Text = "Ready" };
        statusStrip.Items.Add(_lblStatus);

        AcceptButton = _btnOk;
        CancelButton = _btnCancel;

        Controls.Add(_lvEntries);
        Controls.Add(pnlButtons);
        Controls.Add(pnlBottom);
        Controls.Add(statusStrip);
    }

    protected override void OnShown(EventArgs e)
    {
        base.OnShown(e);

        // Start a timer to refresh entry statuses while the dialog is open
        _refreshTimer = new System.Windows.Forms.Timer { Interval = 2000 };
        _refreshTimer.Tick += (s, e) => RefreshStatuses();
        _refreshTimer.Start();
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        _refreshTimer?.Stop();
        _refreshTimer?.Dispose();
        _watchlist.SaveToSettings();
        base.OnFormClosing(e);
    }

    private void PopulateList()
    {
        _lvEntries.BeginUpdate();
        _lvEntries.Items.Clear();

        foreach (var entry in _watchlist.Entries)
        {
            _lvEntries.Items.Add(CreateListItem(entry));
        }

        _lvEntries.EndUpdate();
        UpdateStatusText();
    }

    private static ListViewItem CreateListItem(WatchlistEntry entry)
    {
        var item = new ListViewItem(entry.Type == WatchlistEntryType.Process ? "Process" : "Driver");

        item.SubItems.Add(entry.Name);

        // Status
        if (entry.Type == WatchlistEntryType.Process)
        {
            item.SubItems.Add(entry.IsActive ? "Running" : "Not found");
        }
        else
        {
            item.SubItems.Add(entry.IsActive ? "Loaded" : "Not loaded");
        }

        // PID / Base
        if (entry.Type == WatchlistEntryType.Process && entry.ActivePids.Count > 0)
        {
            item.SubItems.Add(string.Join(", ", entry.ActivePids));
        }
        else if (entry.Type == WatchlistEntryType.Driver && entry.IsActive)
        {
            item.SubItems.Add($"0x{entry.DriverBase:X16}");
        }
        else
        {
            item.SubItems.Add("");
        }

        item.SubItems.Add(entry.Enabled ? "Yes" : "No");
        item.Tag = entry;
        return item;
    }

    private void RefreshStatuses()
    {
        if (_lvEntries.Items.Count == 0) return;

        var entries = _watchlist.Entries;
        if (entries.Count != _lvEntries.Items.Count)
        {
            PopulateList();
            return;
        }

        _lvEntries.BeginUpdate();
        for (int i = 0; i < _lvEntries.Items.Count && i < entries.Count; i++)
        {
            var entry = entries[i];
            var item = _lvEntries.Items[i];

            // Update status
            if (entry.Type == WatchlistEntryType.Process)
            {
                item.SubItems[2].Text = entry.IsActive ? "Running" : "Not found";
                item.SubItems[3].Text = entry.ActivePids.Count > 0
                    ? string.Join(", ", entry.ActivePids) : "";
            }
            else
            {
                item.SubItems[2].Text = entry.IsActive ? "Loaded" : "Not loaded";
                item.SubItems[3].Text = entry.IsActive
                    ? $"0x{entry.DriverBase:X16}" : "";
            }

            item.Tag = entry;
        }
        _lvEntries.EndUpdate();

        UpdateButtonStates();
    }

    private void UpdateButtonStates()
    {
        var selected = GetSelectedEntry();
        _btnRemove.Enabled = selected != null;
    }

    private WatchlistEntry? GetSelectedEntry()
    {
        if (_lvEntries.SelectedItems.Count == 0) return null;
        return _lvEntries.SelectedItems[0].Tag as WatchlistEntry;
    }

    private void UpdateStatusText()
    {
        int processCount = _watchlist.Entries.Count(e => e.Type == WatchlistEntryType.Process);
        int driverCount = _watchlist.Entries.Count(e => e.Type == WatchlistEntryType.Driver);
        int activeCount = _watchlist.Entries.Count(e => e.IsActive);
        _lblStatus.Text = $"{processCount} process(es), {driverCount} driver(s) | {activeCount} active | Polling: {(_watchlist.IsRunning ? "ON" : "OFF")}";
    }

    #region Button Handlers

    private void BtnAddProcess_Click(object? sender, EventArgs e)
    {
        var name = InputBoxForm.Show("Add Process", "Enter process name (e.g. game.exe):");
        if (string.IsNullOrWhiteSpace(name)) return;

        _watchlist.AddEntry(name.Trim(), WatchlistEntryType.Process);
        PopulateList();
        UpdateStatusText();
    }

    private void BtnAddDriver_Click(object? sender, EventArgs e)
    {
        var name = InputBoxForm.Show("Add Driver", "Enter driver filename (e.g. eaanticheat.sys):");
        if (string.IsNullOrWhiteSpace(name)) return;

        _watchlist.AddEntry(name.Trim(), WatchlistEntryType.Driver);
        PopulateList();
        UpdateStatusText();
    }

    private void BtnRemove_Click(object? sender, EventArgs e)
    {
        var entry = GetSelectedEntry();
        if (entry == null) return;

        _watchlist.RemoveEntry(entry);
        PopulateList();
        UpdateStatusText();
    }


    private void BtnSaveProfile_Click(object? sender, EventArgs e)
    {
        if (_watchlist.Entries.Count == 0)
        {
            _lblStatus.Text = "No entries to save";
            return;
        }

        using var dialog = new SaveFileDialog
        {
            Title = "Save Watchlist Profile",
            Filter = "Watchlist Profile (*.watchlist.json)|*.watchlist.json",
            DefaultExt = "watchlist.json",
            FileName = "default.watchlist.json"
        };

        if (dialog.ShowDialog(this) != DialogResult.OK) return;

        _watchlist.SaveProfile(dialog.FileName);
        _lblStatus.Text = $"Profile saved: {_watchlist.Entries.Count} entries";
    }

    private void BtnLoadProfile_Click(object? sender, EventArgs e)
    {
        using var dialog = new OpenFileDialog
        {
            Title = "Load Watchlist Profile",
            Filter = "Watchlist Profile (*.watchlist.json)|*.watchlist.json|All JSON (*.json)|*.json",
            FilterIndex = 1
        };

        if (dialog.ShowDialog(this) != DialogResult.OK) return;

        _watchlist.LoadProfile(dialog.FileName);
        PopulateList();
        _chkFollowChildren.Checked = _watchlist.FollowChildProcesses;
        _lblStatus.Text = $"Profile loaded: {_watchlist.Entries.Count} entries";
    }

    #endregion
}
