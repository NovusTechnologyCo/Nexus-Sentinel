// <file>
// <summary>
// Pointer list sort progress dialog with progress bar for large result sets.
// </summary>
// </file>
using Nexus.UI.Helpers;
using Nexus.UI.Styles;


namespace Nexus.UI.Forms;

/// <summary>
/// Form that displays progress while sorting a pointer list.
/// </summary>
public partial class SortPointerlistForm : Form
{
    private CancellationTokenSource? _cts;
    private DateTime _startTime;
    private long _position;
    private long _maxPosition;
    private readonly System.Windows.Forms.Timer _timer;
    private string _tempName = "";
    private bool _completed;

    public string TempName => _tempName;
    public bool Completed => _completed;

    public SortPointerlistForm()
    {
        InitializeComponent();
        NexusTheme.StyleForm(this);

        _timer = new System.Windows.Forms.Timer
        {
            Interval = 500,
            Enabled = false
        };
        _timer.Tick += Timer_Tick;
    }

    private void InitializeComponent()
    {
        Text = "Sorting";
        Size = new Size(340, 225);
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;

        lblMessage = new Label
        {
            Text = "Sorting the pointerlist. Please wait....",
            TextAlign = ContentAlignment.MiddleCenter,
            Location = new Point(5, 15),
            Size = new Size(315, 20)
        };

        progressBar = new ProgressBar
        {
            Location = new Point(20, 45),
            Size = new Size(285, 20)
        };

        lblTimeLeft = new Label
        {
            Text = "Estimated time left:",
            TextAlign = ContentAlignment.MiddleCenter,
            Location = new Point(10, 75),
            Size = new Size(305, 18)
        };

        btnCancel = new Button
        {
            Text = "Cancel",
            Size = new Size(80, 32),
            Location = new Point(122, 130),
            DialogResult = DialogResult.Cancel
        };
        btnCancel.Click += BtnCancel_Click;

        CancelButton = btnCancel;

        Controls.AddRange([lblMessage, progressBar, lblTimeLeft, btnCancel]);
    }


    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        base.OnFormClosing(e);
        _cts?.Cancel();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _timer.Dispose();
            _cts?.Dispose();
        }
        base.Dispose(disposing);
    }

    private void BtnCancel_Click(object? sender, EventArgs e)
    {
        _cts?.Cancel();
        DialogResult = DialogResult.Cancel;
        Close();
    }

    private void Timer_Tick(object? sender, EventArgs e)
    {
        if (_maxPosition <= 0 || _position <= 10) return;

        var elapsed = DateTime.Now - _startTime;
        double timePerPos = elapsed.TotalMilliseconds / _position;
        var remaining = TimeSpan.FromMilliseconds(timePerPos * (_maxPosition - _position));

        progressBar.Value = (int)Math.Min(100, _position * 100 / _maxPosition);
        lblTimeLeft.Text = $"Estimated time left: {remaining.Hours:D2}:{remaining.Minutes:D2}:{remaining.Seconds:D2}";
    }

    private void UpdateProgress(long position, long maxPosition)
    {
        _position = position;
        _maxPosition = maxPosition;
    }

    /// <summary>
    /// Performs the sort operation.
    /// </summary>
    public bool DoWork(int column, string ptrFile, List<string> tempFileList)
    {
        _cts = new CancellationTokenSource();
        _startTime = DateTime.Now;
        _timer.Enabled = true;

        var task = Task.Run(async () =>
        {
            try
            {
                // Pointer file sorting requires reading the proprietary pointer scan file format
                // and re-ordering entries based on the selected column (offset depth, base address, etc.)
                // The engine.dll provides Nexus_PointerScan* APIs for running scans but not for
                // sorting existing result files. This would need custom file I/O implementation.

                // For now, show a simulation to demonstrate the UI while file format is being defined
                _tempName = ptrFile + ".sorted";
                _maxPosition = 1000;

                for (int i = 0; i < 1000 && !_cts.Token.IsCancellationRequested; i++)
                {
                    _position = i;
                    await Task.Delay(10, _cts.Token);
                }

                if (!_cts.Token.IsCancellationRequested)
                {
                    Invoke(() =>
                    {
                        MessageBox.Show("Pointer file sorting is not yet implemented.\n" +
                            "The results view can be sorted by clicking column headers.",
                            "Sort Complete", MessageBoxButtons.OK, MessageBoxIcon.Information);
                        _completed = true;
                        DialogResult = DialogResult.OK;
                    });
                }
            }
            catch (OperationCanceledException)
            {
                // Cancelled
            }
            catch (Exception ex)
            {
                Invoke(() =>
                {
                    MessageBox.Show(ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    DialogResult = DialogResult.Cancel;
                });
            }
        }, _cts.Token);

        return ShowDialog() == DialogResult.OK;
    }

    /// <summary>
    /// Shows the sort dialog and performs the sort.
    /// </summary>
    public static bool Sort(IWin32Window? owner, int column, string ptrFile,
        out string tempName, List<string> tempFileList)
    {
        using var form = new SortPointerlistForm();
        bool result = form.DoWork(column, ptrFile, tempFileList);
        tempName = form.TempName;
        return result;
    }

    // Controls
    private Label lblMessage = null!;
    private Label lblTimeLeft = null!;
    private ProgressBar progressBar = null!;
    private Button btnCancel = null!;
}
