// <file>
// <summary>
// Process memory map showing color-coded visual representation of address space.
// </summary>
// </file>
using Nexus.UI.Helpers;
using Nexus.UI.Styles;


namespace Nexus.UI.Forms;

/// <summary>
/// Memory region type for coloring
/// </summary>
public enum MemoryRegionType
{
    Free,
    Private,
    Image,
    Mapped,
    Stack,
    Heap,
    Reserved
}

/// <summary>
/// Memory map entry
/// </summary>
public class MemoryMapEntry
{
    public ulong BaseAddress { get; set; }
    public ulong Size { get; set; }
    public MemoryRegionType Type { get; set; }
    public string Protection { get; set; } = string.Empty;
    public string ModuleName { get; set; } = string.Empty;
    public string Details { get; set; } = string.Empty;

    public ulong EndAddress => BaseAddress + Size;
}

/// <summary>
/// Form for displaying a visual memory map of the process.
/// Shows memory regions with color coding by type.
/// </summary>
public partial class ProcessMemoryMapForm : Form
{
    private Panel _pnlMap = null!;
    private ListView _lvDetails = null!;
    private HScrollBar _scrollBar = null!;
    private Label _lblInfo = null!;
    private ComboBox _cbZoom = null!;
    private CheckBox _cbShowFree = null!;
    private Button _btnRefresh = null!;
    private Button _btnClose = null!;

    private readonly List<MemoryMapEntry> _regions = new();
    private int _zoomLevel = 1;
    private ulong _scrollOffset;

    /// <summary>
    /// Event fired when a region is selected
    /// </summary>
    public event EventHandler<MemoryMapEntry>? RegionSelected;

    public ProcessMemoryMapForm()
    {
        InitializeComponent();
        NexusTheme.StyleForm(this);
    }

    private void InitializeComponent()
    {
        Text = "Process Memory Map";
        Size = new Size(900, 650);
        FormBorderStyle = FormBorderStyle.Sizable;
        StartPosition = FormStartPosition.CenterParent;
        MinimumSize = new Size(700, 400);

        // Top toolbar
        var toolPanel = new Panel
        {
            Dock = DockStyle.Top,
            Height = 35
        };

        var lblZoom = new Label { Text = "Zoom:", Location = new Point(10, 9), AutoSize = true };
        toolPanel.Controls.Add(lblZoom);

        _cbZoom = new ComboBox
        {
            Location = new Point(75, 5),
            Size = new Size(80, 32),
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        _cbZoom.Items.AddRange(new[] { "1x", "2x", "4x", "8x", "16x" });
        _cbZoom.SelectedIndex = 0;
        _cbZoom.SelectedIndexChanged += CbZoom_SelectedIndexChanged;
        toolPanel.Controls.Add(_cbZoom);

        _cbShowFree = new CheckBox
        {
            Text = "Show free regions",
            Location = new Point(170, 8),
            AutoSize = true
        };
        _cbShowFree.CheckedChanged += CbShowFree_CheckedChanged;
        toolPanel.Controls.Add(_cbShowFree);

        _btnRefresh = new Button
        {
            Text = "Refresh",
            Location = new Point(350, 3),
            Size = new Size(80, 32)
        };
        _btnRefresh.Click += BtnRefresh_Click;
        toolPanel.Controls.Add(_btnRefresh);

        _lblInfo = new Label
        {
            Text = "",
            Location = new Point(460, 9),
            AutoSize = true
        };
        toolPanel.Controls.Add(_lblInfo);

        // Split container for map and details
        var splitContainer = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Orientation = Orientation.Horizontal,
            SplitterDistance = 200,
            Panel2MinSize = 150
        };

        // Set splitter to give more room to the bottom panel
        Load += (s, e) => splitContainer.SplitterDistance = (int)(splitContainer.Height * 0.55);

        // Map panel
        var mapContainer = new Panel { Dock = DockStyle.Fill };

        _pnlMap = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = Color.Black
        };
        _pnlMap.Paint += PnlMap_Paint;
        _pnlMap.MouseMove += PnlMap_MouseMove;
        _pnlMap.MouseClick += PnlMap_MouseClick;

        _scrollBar = new HScrollBar
        {
            Dock = DockStyle.Bottom,
            Minimum = 0,
            Maximum = 100,
            LargeChange = 10
        };
        _scrollBar.Scroll += ScrollBar_Scroll;

        mapContainer.Controls.Add(_pnlMap);
        mapContainer.Controls.Add(_scrollBar);
        splitContainer.Panel1.Controls.Add(mapContainer);

        // Details list
        _lvDetails = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = true
        };
        _lvDetails.Columns.Add("Base Address", -2);
        _lvDetails.Columns.Add("Size", -2);
        _lvDetails.Columns.Add("Type", -2);
        _lvDetails.Columns.Add("Protection", -2);
        _lvDetails.Columns.Add("Module/Details", -2);
        _lvDetails.DoubleClick += LvDetails_DoubleClick;
        splitContainer.Panel2.Controls.Add(_lvDetails);

        // Button panel
        var buttonPanel = new Panel
        {
            Dock = DockStyle.Bottom,
            Height = 45
        };

        // Legend
        AddLegendItem(buttonPanel, "Private", Color.Blue, 10);
        AddLegendItem(buttonPanel, "Image", Color.Green, 95);
        AddLegendItem(buttonPanel, "Mapped", Color.Yellow, 175);
        AddLegendItem(buttonPanel, "Stack", Color.Red, 270);
        AddLegendItem(buttonPanel, "Heap", Color.Orange, 345);
        AddLegendItem(buttonPanel, "Free", Color.DarkGray, 420);

        _btnClose = new Button
        {
            Text = "Close",
            Size = new Size(80, 32),
            Location = new Point(Width - 100, 10),
            Anchor = AnchorStyles.Top | AnchorStyles.Right
        };
        _btnClose.Click += (s, e) => Close();
        buttonPanel.Controls.Add(_btnClose);

        Controls.Add(splitContainer);
        Controls.Add(toolPanel);
        Controls.Add(buttonPanel);
    }

    private void AddLegendItem(Panel parent, string text, Color color, int x)
    {
        var colorBox = new Panel
        {
            Location = new Point(x, 13),
            Size = new Size(15, 15),
            BackColor = color,
            BorderStyle = BorderStyle.FixedSingle
        };
        parent.Controls.Add(colorBox);

        var lbl = new Label
        {
            Text = text,
            Location = new Point(x + 18, 13),
            AutoSize = true
        };
        parent.Controls.Add(lbl);
    }

    private Color GetRegionColor(MemoryRegionType type)
    {
        return type switch
        {
            MemoryRegionType.Private => Color.Blue,
            MemoryRegionType.Image => Color.Green,
            MemoryRegionType.Mapped => Color.Yellow,
            MemoryRegionType.Stack => Color.Red,
            MemoryRegionType.Heap => Color.Orange,
            MemoryRegionType.Free => Color.DarkGray,
            MemoryRegionType.Reserved => Color.Purple,
            _ => Color.Gray
        };
    }

    private void PnlMap_Paint(object? sender, PaintEventArgs e)
    {
        var g = e.Graphics;

        if (_regions.Count == 0)
        {
            g.DrawString("No memory regions loaded. Click Refresh to load.",
                Font, Brushes.White, 10, 10);
            return;
        }

        // Calculate scale
        var minAddr = _regions.Min(r => r.BaseAddress);
        var maxAddr = _regions.Max(r => r.EndAddress);
        var range = maxAddr - minAddr;

        if (range == 0) return;

        var width = _pnlMap.Width;
        var height = _pnlMap.Height;
        var pixelsPerByte = (double)width * _zoomLevel / range;

        foreach (var region in _regions)
        {
            if (!_cbShowFree.Checked && region.Type == MemoryRegionType.Free)
                continue;

            var x = (int)((region.BaseAddress - minAddr - _scrollOffset) * pixelsPerByte);
            var w = Math.Max(1, (int)(region.Size * pixelsPerByte));

            if (x + w < 0 || x > width)
                continue;

            using var brush = new SolidBrush(GetRegionColor(region.Type));
            g.FillRectangle(brush, x, 0, w, height);

            // Draw border
            g.DrawRectangle(Pens.Black, x, 0, w, height - 1);
        }
    }

    private void PnlMap_MouseMove(object? sender, MouseEventArgs e)
    {
        var region = GetRegionAtPoint(e.X);
        if (region != null)
        {
            _lblInfo.Text = $"{region.BaseAddress:X} - {region.EndAddress:X} ({FormatSize(region.Size)}) - {region.Type}";
        }
        else
        {
            _lblInfo.Text = "";
        }
    }

    private void PnlMap_MouseClick(object? sender, MouseEventArgs e)
    {
        var region = GetRegionAtPoint(e.X);
        if (region != null)
        {
            SelectRegion(region);
            RegionSelected?.Invoke(this, region);
        }
    }

    private MemoryMapEntry? GetRegionAtPoint(int x)
    {
        if (_regions.Count == 0) return null;

        var minAddr = _regions.Min(r => r.BaseAddress);
        var maxAddr = _regions.Max(r => r.EndAddress);
        var range = maxAddr - minAddr;
        if (range == 0) return null;

        var pixelsPerByte = (double)_pnlMap.Width * _zoomLevel / range;
        var addr = minAddr + _scrollOffset + (ulong)(x / pixelsPerByte);

        return _regions.FirstOrDefault(r => addr >= r.BaseAddress && addr < r.EndAddress);
    }

    private void SelectRegion(MemoryMapEntry region)
    {
        foreach (ListViewItem item in _lvDetails.Items)
        {
            if (item.Tag == region)
            {
                item.Selected = true;
                item.EnsureVisible();
                break;
            }
        }
    }

    private void CbZoom_SelectedIndexChanged(object? sender, EventArgs e)
    {
        _zoomLevel = 1 << _cbZoom.SelectedIndex;
        _pnlMap.Invalidate();
    }

    private void CbShowFree_CheckedChanged(object? sender, EventArgs e)
    {
        _pnlMap.Invalidate();
        RefreshDetails();
    }

    private void ScrollBar_Scroll(object? sender, ScrollEventArgs e)
    {
        if (_regions.Count == 0) return;

        var minAddr = _regions.Min(r => r.BaseAddress);
        var maxAddr = _regions.Max(r => r.EndAddress);
        var range = maxAddr - minAddr;

        _scrollOffset = (ulong)(e.NewValue * (long)range / 100);
        _pnlMap.Invalidate();
    }

    private void BtnRefresh_Click(object? sender, EventArgs e)
    {
        // Placeholder - would query process memory
        LoadSampleData();
    }

    private void LvDetails_DoubleClick(object? sender, EventArgs e)
    {
        if (_lvDetails.SelectedItems.Count > 0 &&
            _lvDetails.SelectedItems[0].Tag is MemoryMapEntry region)
        {
            RegionSelected?.Invoke(this, region);
        }
    }

    private void RefreshDetails()
    {
        _lvDetails.Items.Clear();

        var regions = _cbShowFree.Checked
            ? _regions
            : _regions.Where(r => r.Type != MemoryRegionType.Free);

        foreach (var region in regions.OrderBy(r => r.BaseAddress))
        {
            var item = new ListViewItem($"{region.BaseAddress:X16}");
            item.SubItems.Add(FormatSize(region.Size));
            item.SubItems.Add(region.Type.ToString());
            item.SubItems.Add(region.Protection);
            item.SubItems.Add(string.IsNullOrEmpty(region.ModuleName) ? region.Details : region.ModuleName);
            item.BackColor = GetRegionColor(region.Type);
            item.Tag = region;
            _lvDetails.Items.Add(item);
        }
    }

    private static string FormatSize(ulong size)
    {
        if (size >= 1024 * 1024 * 1024)
            return $"{size / (1024.0 * 1024 * 1024):F1} GB";
        if (size >= 1024 * 1024)
            return $"{size / (1024.0 * 1024):F1} MB";
        if (size >= 1024)
            return $"{size / 1024.0:F1} KB";
        return $"{size} B";
    }

    private void LoadSampleData()
    {
        _regions.Clear();
        _regions.AddRange(new[]
        {
            new MemoryMapEntry { BaseAddress = 0x10000, Size = 0x1000, Type = MemoryRegionType.Private, Protection = "RW" },
            new MemoryMapEntry { BaseAddress = 0x400000, Size = 0x100000, Type = MemoryRegionType.Image, Protection = "RX", ModuleName = "program.exe" },
            new MemoryMapEntry { BaseAddress = 0x7FF00000, Size = 0x200000, Type = MemoryRegionType.Image, Protection = "RX", ModuleName = "ntdll.dll" },
            new MemoryMapEntry { BaseAddress = 0x7FFE0000, Size = 0x10000, Type = MemoryRegionType.Stack, Protection = "RW", Details = "Main thread stack" },
        });

        RefreshDetails();
        _pnlMap.Invalidate();
    }

    /// <summary>
    /// Sets the memory regions to display
    /// </summary>
    public void SetRegions(IEnumerable<MemoryMapEntry> regions)
    {
        _regions.Clear();
        _regions.AddRange(regions);
        RefreshDetails();
        _pnlMap.Invalidate();
    }
}
