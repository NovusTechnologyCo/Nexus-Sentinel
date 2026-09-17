// <file>
// <summary>
// Scan history dialog showing previous scan states for restoration.
// </summary>
// </file>
using Nexus.UI.Helpers;
using Nexus.UI.Styles;


namespace Nexus.UI.Forms;

/// <summary>
/// Form for viewing scan history and restoring previous scan states.
/// Allows undo/redo of scan operations.
/// </summary>
public partial class ScanHistoryForm : Form
{
    private ListView _lvHistory = null!;
    private Button _btnRestore = null!;
    private Button _btnDelete = null!;
    private Button _btnClear = null!;
    private Label _lblDetails = null!;
    private Button _btnClose = null!;

    private readonly List<ScanHistoryEntry> _entries = [];

    public class ScanHistoryEntry
    {
        public int Index { get; set; }
        public DateTime Timestamp { get; set; }
        public string ScanType { get; set; } = "";
        public string ValueType { get; set; } = "";
        public string SearchValue { get; set; } = "";
        public int ResultCount { get; set; }
        public object? State { get; set; }
    }

    /// <summary>
    /// Event raised when user wants to restore a scan state
    /// </summary>
    public event EventHandler<ScanHistoryEntry>? RestoreRequested;

    public ScanHistoryForm()
    {
        InitializeComponent();
        NexusTheme.StyleForm(this);
    }

    private void InitializeComponent()
    {
        Text = "Scan History";
        Size = new Size(600, 410);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        StartPosition = FormStartPosition.CenterParent;
        MaximizeBox = false;
        MinimizeBox = false;

        _lvHistory = new ListView
        {
            Location = new Point(15, 15),
            Size = new Size(455, 300),
            View = View.Details,
            FullRowSelect = true,
            GridLines = true
        };
        _lvHistory.Columns.Add("#", -2);
        _lvHistory.Columns.Add("Time", -2);
        _lvHistory.Columns.Add("Scan Type", -2);
        _lvHistory.Columns.Add("Value Type", -2);
        _lvHistory.Columns.Add("Value", -2);
        _lvHistory.Columns.Add("Results", -2);
        _lvHistory.SelectedIndexChanged += LvHistory_SelectedIndexChanged;
        _lvHistory.DoubleClick += LvHistory_DoubleClick;
        Controls.Add(_lvHistory);

        _btnRestore = new Button
        {
            Text = "Restore",
            Location = new Point(485, 15),
            Size = new Size(90, 32)
        };
        _btnRestore.Click += BtnRestore_Click;
        Controls.Add(_btnRestore);

        _btnDelete = new Button
        {
            Text = "Delete",
            Location = new Point(485, 52),
            Size = new Size(90, 32)
        };
        _btnDelete.Click += BtnDelete_Click;
        Controls.Add(_btnDelete);

        _btnClear = new Button
        {
            Text = "Clear All",
            Location = new Point(485, 89),
            Size = new Size(90, 32)
        };
        _btnClear.Click += BtnClear_Click;
        Controls.Add(_btnClear);

        _lblDetails = new Label
        {
            Text = "Select a scan to see details",
            Location = new Point(15, 325),
            AutoSize = true,
            ForeColor = Color.Gray
        };
        Controls.Add(_lblDetails);

        _btnClose = new Button
        {
            Text = "Close",
            Location = new Point(485, 330),
            Size = new Size(80, 32),
            DialogResult = DialogResult.Cancel
        };
        Controls.Add(_btnClose);

        CancelButton = _btnClose;
    }

    /// <summary>
    /// Adds a scan history entry
    /// </summary>
    public void AddEntry(string scanType, string valueType, string searchValue, int resultCount, object? state = null)
    {
        var entry = new ScanHistoryEntry
        {
            Index = _entries.Count + 1,
            Timestamp = DateTime.Now,
            ScanType = scanType,
            ValueType = valueType,
            SearchValue = searchValue,
            ResultCount = resultCount,
            State = state
        };

        _entries.Add(entry);
        RefreshList();
    }

    private void RefreshList()
    {
        _lvHistory.Items.Clear();
        foreach (var entry in _entries)
        {
            var lvi = new ListViewItem(entry.Index.ToString());
            lvi.SubItems.Add(entry.Timestamp.ToString("HH:mm:ss"));
            lvi.SubItems.Add(entry.ScanType);
            lvi.SubItems.Add(entry.ValueType);
            lvi.SubItems.Add(entry.SearchValue);
            lvi.SubItems.Add(entry.ResultCount.ToString("N0"));
            lvi.Tag = entry;
            _lvHistory.Items.Add(lvi);
        }
    }

    private void LvHistory_SelectedIndexChanged(object? sender, EventArgs e)
    {
        if (_lvHistory.SelectedItems.Count > 0 && _lvHistory.SelectedItems[0].Tag is ScanHistoryEntry entry)
        {
            _lblDetails.Text = $"Scan #{entry.Index}: {entry.ScanType} for {entry.ValueType} = {entry.SearchValue} ({entry.ResultCount:N0} results)";
        }
        else
        {
            _lblDetails.Text = "Select a scan to see details";
        }
    }

    private void LvHistory_DoubleClick(object? sender, EventArgs e)
    {
        BtnRestore_Click(sender, e);
    }

    private void BtnRestore_Click(object? sender, EventArgs e)
    {
        if (_lvHistory.SelectedItems.Count > 0 && _lvHistory.SelectedItems[0].Tag is ScanHistoryEntry entry)
        {
            RestoreRequested?.Invoke(this, entry);
        }
    }

    private void BtnDelete_Click(object? sender, EventArgs e)
    {
        if (_lvHistory.SelectedItems.Count > 0)
        {
            var index = _lvHistory.SelectedIndices[0];
            _entries.RemoveAt(index);

            // Renumber entries
            for (int i = 0; i < _entries.Count; i++)
            {
                _entries[i].Index = i + 1;
            }

            RefreshList();
        }
    }

    private void BtnClear_Click(object? sender, EventArgs e)
    {
        if (MessageBox.Show("Clear all scan history?", "Confirm",
            MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
        {
            _entries.Clear();
            RefreshList();
        }
    }

    /// <summary>
    /// Gets the number of history entries
    /// </summary>
    public int EntryCount => _entries.Count;
}
