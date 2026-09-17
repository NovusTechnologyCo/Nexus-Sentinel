// <file>
// <summary>
// Code cave scanner finding executable memory regions with unused space.
// </summary>
// </file>
using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using Nexus.UI.Styles;


namespace Nexus.UI.Forms;

/// <summary>
/// Code cave scanner dialog for locating unused executable memory regions in loaded modules.
/// </summary>
public partial class CodeCaveScannerForm : Form
{
    private readonly IntPtr _processHandle;
    private readonly List<CodeCave> _caves = [];
    private volatile bool _isScanning;

    public class CodeCave
    {
        public ulong Address { get; set; }
        public ulong Size { get; set; }
        public string ModuleName { get; set; } = "";
        public byte FillByte { get; set; }
    }

    public ulong SelectedAddress { get; private set; }

    public CodeCaveScannerForm(IntPtr processHandle)
    {
        _processHandle = processHandle;
        InitializeComponent();
        NexusTheme.StyleForm(this);
    }

    private void InitializeComponent()
    {
        Text = "Code Cave Scanner";
        Size = new Size(740, 500);
        StartPosition = FormStartPosition.CenterParent;

        // Top panel - options
        var pnlTop = new Panel
        {
            Dock = DockStyle.Top,
            Height = 90
        };

        // Original positions were at 10px margin, shift to get proper margin
        const int shift = 10;

        var lblMin = new Label { Text = "Minimum size:", Location = new Point(10 + shift, 15), AutoSize = true };
        nudMinSize = new NumericUpDown
        {
            Location = new Point(135 + shift + 5, 12),
            Size = new Size(80, 32),
            Minimum = 1,
            Maximum = 100000,
            Value = 16
        };

        var lblFill = new Label { Text = "Fill byte:", Location = new Point(225 + shift + 5, 15), AutoSize = true };
        cboFillByte = new ComboBox
        {
            Location = new Point(295 + shift + 15, 12),
            Size = new Size(125, 32),
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        cboFillByte.Items.AddRange(["0x00 (NUL)", "0x90 (NOP)", "0xCC (INT3)", "Any"]);
        cboFillByte.SelectedIndex = 0;

        // Checkboxes positioned after dropdown with Space16 gap
        // Dropdown ends at: 295 + shift(10) + 15 + 125 = 445
        int chkX = 445 + NexusTheme.Space16;
        chkExecutableOnly = new CheckBox
        {
            Text = "Executable regions only",
            Location = new Point(chkX, 14),
            AutoSize = true,
            Checked = true
        };

        chkModulesOnly = new CheckBox
        {
            Text = "Module regions only",
            Location = new Point(chkX, 40),
            AutoSize = true,
            Checked = true
        };

        btnScan = new Button { Text = "Scan", Location = new Point(10 + shift, 50), Size = new Size(100, 32) };
        btnScan.Click += BtnScan_Click;

        btnStop = new Button { Text = "Stop", Location = new Point(120 + shift, 50), Size = new Size(70, 32), Enabled = false };
        btnStop.Click += BtnStop_Click;

        lblStatus = new Label { Text = "Ready", Location = new Point(200 + shift, 58), AutoSize = true };

        pnlTop.Controls.AddRange([lblMin, nudMinSize, lblFill, cboFillByte,
            chkExecutableOnly, chkModulesOnly, btnScan, btnStop, lblStatus]);

        // ListView for results
        lvCaves = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = true,
            Font = new Font("Consolas", 9F)
        };
        lvCaves.Columns.Add("Address", 150);
        lvCaves.Columns.Add("Size", 120);
        lvCaves.Columns.Add("Module", 150);
        lvCaves.Columns.Add("Fill Byte", 120);

        // Auto-stretch Address column on resize
        lvCaves.Resize += (s, e) => ResizeColumns();
        Shown += (s, e) => ResizeColumns();
        lvCaves.DoubleClick += LvCaves_DoubleClick;

        // Context menu
        var ctxMenu = new ContextMenuStrip();
        ctxMenu.Items.Add("Use this address", null, CtxUseAddress_Click);
        ctxMenu.Items.Add("Browse memory", null, CtxBrowseMemory_Click);
        ctxMenu.Items.Add("Copy address", null, CtxCopyAddress_Click);
        ctxMenu.Items.Add(new ToolStripSeparator());
        ctxMenu.Items.Add("Disassemble", null, CtxDisassemble_Click);
        lvCaves.ContextMenuStrip = ctxMenu;

        // Bottom panel
        var pnlBottom = new Panel
        {
            Dock = DockStyle.Bottom,
            Height = NexusTheme.Space8 + NexusTheme.ButtonHeight + NexusTheme.Space16
        };

        lblCount = new Label { Text = "0 caves found", Location = new Point(NexusTheme.Space16, NexusTheme.Space8 + 6), AutoSize = true };

        // Right-aligned buttons using Anchor
        var btnCancel = new Button
        {
            Text = "Cancel",
            Size = new Size(NexusTheme.ButtonWidth, NexusTheme.ButtonHeight),
            DialogResult = DialogResult.Cancel,
            Anchor = AnchorStyles.Top | AnchorStyles.Right
        };
        btnCancel.Click += (s, e) => Close();

        var btnOK = new Button
        {
            Text = "Use",
            Size = new Size(NexusTheme.ButtonWidth, NexusTheme.ButtonHeight),
            DialogResult = DialogResult.OK,
            Anchor = AnchorStyles.Top | AnchorStyles.Right
        };
        btnOK.Click += BtnOK_Click;

        // Position buttons after panel is sized (use Load event)
        pnlBottom.Layout += (s, e) =>
        {
            btnCancel.Location = new Point(pnlBottom.ClientSize.Width - NexusTheme.Space16 - NexusTheme.ButtonWidth, NexusTheme.Space8);
            btnOK.Location = new Point(btnCancel.Left - NexusTheme.ButtonGap - NexusTheme.ButtonWidth, NexusTheme.Space8);
        };

        pnlBottom.Controls.AddRange([lblCount, btnOK, btnCancel]);

        Controls.Add(lvCaves);
        Controls.Add(pnlTop);
        Controls.Add(pnlBottom);
        AcceptButton = btnOK;
        CancelButton = btnCancel;
    }

    private void BtnScan_Click(object? sender, EventArgs e)
    {
        _caves.Clear();
        lvCaves.Items.Clear();
        _isScanning = true;
        btnScan.Enabled = false;
        btnStop.Enabled = true;
        lblStatus.Text = "Scanning...";

        int minSize = (int)nudMinSize.Value;
        byte? fillByte = cboFillByte.SelectedIndex switch
        {
            0 => 0x00,
            1 => 0x90,
            2 => 0xCC,
            _ => null // Any
        };
        bool execOnly = chkExecutableOnly.Checked;
        bool modulesOnly = chkModulesOnly.Checked;

        Task.Run(() => PerformScan(minSize, fillByte, execOnly, modulesOnly));
    }

    private void PerformScan(int minSize, byte? fillByte, bool execOnly, bool modulesOnly)
    {
        try
        {
            // Use engine API for code cave scanning
            NexusEngine.Nexus_GetCodeCaveScanDefaultConfig(out var config);
            config.MinSize = (nuint)minSize;
            config.Options = 0;
            if (execOnly) config.Options |= (uint)NexusCodeCaveOptions.Executable;
            if (modulesOnly) config.Options |= (uint)NexusCodeCaveOptions.ModuleOnly;

            // Set fill type based on fillByte
            if (fillByte == null)
                config.FillType = 3; // Any fill
            else if (fillByte == 0x00)
                config.FillType = 0; // Zeros
            else if (fillByte == 0x90)
                config.FillType = 1; // NOPs
            else if (fillByte == 0xCC)
                config.FillType = 2; // INT3s
            else
                config.FillType = 3; // Any fill

            // Scan for caves
            var results = new NexusCodeCaveEntry[10000];
            var scanResult = NexusEngine.Nexus_ScanCodeCavesEx(
                _processHandle, ref config, results, (nuint)results.Length, out nuint resultCount, out var stats);

            if (scanResult != NexusResult.OK)
            {
                UpdateStatus("Scan failed");
                return;
            }

            // Add results to list
            for (int i = 0; i < (int)resultCount && _isScanning; i++)
            {
                var entry = results[i];
                // Filter by specific fill byte if requested
                if (fillByte.HasValue && entry.FillByte != fillByte.Value)
                    continue;

                AddCave(entry.Address, entry.Size, entry.ModuleName, entry.FillByte);
            }

            // Final update
            Invoke(() =>
            {
                lblCount.Text = $"{_caves.Count} caves found";
                lblStatus.Text = _isScanning ? $"Scan complete ({stats.ElapsedMs:F0}ms)" : "Scan stopped";
                _isScanning = false;
                btnScan.Enabled = true;
                btnStop.Enabled = false;
            });
        }
        catch (Exception ex)
        {
            UpdateStatus($"Error: {ex.Message}");
        }
    }

    private void AddCave(ulong address, ulong size, string moduleName, byte fillByte)
    {
        var cave = new CodeCave
        {
            Address = address,
            Size = size,
            ModuleName = moduleName,
            FillByte = fillByte
        };
        _caves.Add(cave);

        Invoke(() =>
        {
            var item = new ListViewItem($"0x{address:X}");
            item.SubItems.Add($"{size} bytes");
            item.SubItems.Add(moduleName);
            item.SubItems.Add($"0x{fillByte:X2}");
            item.Tag = cave;
            lvCaves.Items.Add(item);
        });
    }

    private void UpdateStatus(string message)
    {
        Invoke(() =>
        {
            lblStatus.Text = message;
            _isScanning = false;
            btnScan.Enabled = true;
            btnStop.Enabled = false;
        });
    }

    private void BtnStop_Click(object? sender, EventArgs e)
    {
        _isScanning = false;
        btnStop.Enabled = false;
        lblStatus.Text = "Stopping...";
    }

    private void LvCaves_DoubleClick(object? sender, EventArgs e)
    {
        BtnOK_Click(sender, e);
    }

    private void BtnOK_Click(object? sender, EventArgs e)
    {
        if (lvCaves.SelectedItems.Count == 0)
        {
            MessageBox.Show("Please select a code cave.", "Selection Required",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            DialogResult = DialogResult.None;
            return;
        }

        if (lvCaves.SelectedItems[0].Tag is CodeCave cave)
        {
            SelectedAddress = cave.Address;
        }
    }

    private void CtxUseAddress_Click(object? sender, EventArgs e)
    {
        if (lvCaves.SelectedItems.Count == 0) return;
        if (lvCaves.SelectedItems[0].Tag is CodeCave cave)
        {
            SelectedAddress = cave.Address;
            DialogResult = DialogResult.OK;
            Close();
        }
    }

    private void CtxBrowseMemory_Click(object? sender, EventArgs e)
    {
        if (lvCaves.SelectedItems.Count == 0) return;
        if (lvCaves.SelectedItems[0].Tag is not CodeCave cave) return;

        MessageBox.Show($"Would browse memory at 0x{cave.Address:X}",
            "Browse Memory", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private void CtxCopyAddress_Click(object? sender, EventArgs e)
    {
        if (lvCaves.SelectedItems.Count == 0) return;
        if (lvCaves.SelectedItems[0].Tag is CodeCave cave)
        {
            Clipboard.SetText($"0x{cave.Address:X}");
        }
    }

    private void CtxDisassemble_Click(object? sender, EventArgs e)
    {
        if (lvCaves.SelectedItems.Count == 0) return;
        if (lvCaves.SelectedItems[0].Tag is not CodeCave cave) return;

        MessageBox.Show($"Would open disassembler at 0x{cave.Address:X}",
            "Disassemble", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private void ResizeColumns()
    {
        if (lvCaves == null || lvCaves.Columns.Count < 4) return;

        const int sizeWidth = 120;
        const int moduleWidth = 150;
        const int fillByteWidth = 120;

        // Set fixed columns first
        lvCaves.Columns[1].Width = sizeWidth;
        lvCaves.Columns[2].Width = moduleWidth;
        lvCaves.Columns[3].Width = fillByteWidth;

        // Address fills remaining space (ClientSize already accounts for scrollbar)
        int addressWidth = lvCaves.ClientSize.Width - sizeWidth - moduleWidth - fillByteWidth;
        if (addressWidth < 100) addressWidth = 100;

        lvCaves.Columns[0].Width = addressWidth;
    }

    // Form controls
    private NumericUpDown nudMinSize = null!;
    private ComboBox cboFillByte = null!;
    private CheckBox chkExecutableOnly = null!;
    private CheckBox chkModulesOnly = null!;
    private Button btnScan = null!;
    private Button btnStop = null!;
    private ListView lvCaves = null!;
    private Label lblStatus = null!;
    private Label lblCount = null!;
}
