// <file>
// <summary>
// Window spy utility for inspecting window properties of desktop windows.
// </summary>
// </file>
using System.Runtime.InteropServices;
using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using Nexus.UI.Styles;


namespace Nexus.UI.Forms;

/// <summary>
/// Window Spy utility for inspecting window handles, classes, and process info.
/// </summary>
public class WindowSpyForm : Form
{
    // Controls
    private Label _lblInstructions = null!;
    private PictureBox _pbCrosshair = null!;
    private GroupBox _grpWindowInfo = null!;
    private Label _lblWindowHandle = null!;
    private TextBox _txtWindowHandle = null!;
    private Label _lblWindowTitle = null!;
    private TextBox _txtWindowTitle = null!;
    private Label _lblWindowClass = null!;
    private TextBox _txtWindowClass = null!;
    private Label _lblProcessId = null!;
    private TextBox _txtProcessId = null!;
    private Label _lblProcessName = null!;
    private TextBox _txtProcessName = null!;
    private Button _btnClose = null!;
    private ListView _lvWindows = null!;

    // Crosshair dragging state
    private bool _isDragging;
    private IntPtr _lastHighlightedWindow;
#pragma warning disable CS0169 // Reserved for custom crosshair cursor
    private Cursor? _crosshairCursor;
#pragma warning restore CS0169

    // Result
    public uint SelectedProcessId { get; private set; }
    public string SelectedProcessName { get; private set; } = "";

    // Win32 imports
    [DllImport("user32.dll")]
    private static extern IntPtr WindowFromPoint(POINT point);

    [DllImport("user32.dll")]
    private static extern bool GetCursorPos(out POINT lpPoint);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetWindowText(IntPtr hWnd, System.Text.StringBuilder lpString, int nMaxCount);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetClassName(IntPtr hWnd, System.Text.StringBuilder lpClassName, int nMaxCount);

    [DllImport("user32.dll")]
    private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern IntPtr GetParent(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern bool FlashWindow(IntPtr hWnd, bool bInvert);

    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [StructLayout(LayoutKind.Sequential)]
    private struct POINT
    {
        public int X;
        public int Y;
    }

    public WindowSpyForm()
    {
        InitializeComponent();
        NexusTheme.StyleForm(this);
        SetupEventHandlers();
        PopulateWindowList();
    }

    private void InitializeComponent()
    {
        Text = "Window Spy";
        Size = new Size(700, 620);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        StartPosition = FormStartPosition.CenterParent;

        // Instructions
        _lblInstructions = new Label
        {
            Text = "Drag the crosshair over a window to select it, or choose from the list below:",
            Location = new Point(12, 12),
            AutoSize = true
        };

        // Crosshair icon (simulated with a panel)
        _pbCrosshair = new PictureBox
        {
            Location = new Point(12, 40),
            Size = new Size(32, 32),
            BorderStyle = BorderStyle.FixedSingle,
            BackColor = Color.White,
            Cursor = Cursors.Cross
        };
        // Draw crosshair
        var bmp = new Bitmap(32, 32);
        using (var g = Graphics.FromImage(bmp))
        {
            g.Clear(Color.White);
            using var pen = new Pen(Color.Black, 1);
            g.DrawLine(pen, 16, 0, 16, 32);
            g.DrawLine(pen, 0, 16, 32, 16);
            g.DrawEllipse(pen, 8, 8, 16, 16);
        }
        _pbCrosshair.Image = bmp;

        // Window info group
        _grpWindowInfo = new GroupBox
        {
            Text = "Window Information",
            Location = new Point(60, 35),
            Size = new Size(570, 155)
        };

        _lblWindowHandle = new Label { Text = "Handle:", Location = new Point(10, 25), AutoSize = true };
        _txtWindowHandle = new TextBox { Location = new Point(100, 22), Size = new Size(140, 23), ReadOnly = true };

        _lblWindowTitle = new Label { Text = "Title:", Location = new Point(10, 53), AutoSize = true };
        _txtWindowTitle = new TextBox { Location = new Point(100, 50), Size = new Size(455, 23), ReadOnly = true };

        _lblWindowClass = new Label { Text = "Class:", Location = new Point(10, 81), AutoSize = true };
        _txtWindowClass = new TextBox { Location = new Point(100, 78), Size = new Size(455, 23), ReadOnly = true };

        _lblProcessId = new Label { Text = "Process ID:", Location = new Point(10, 109), AutoSize = true };
        _txtProcessId = new TextBox { Location = new Point(115, 106), Size = new Size(90, 23), ReadOnly = true };

        _lblProcessName = new Label { Text = "Process:", Location = new Point(220, 109), AutoSize = true };
        _txtProcessName = new TextBox { Location = new Point(300, 106), Size = new Size(255, 23), ReadOnly = true };

        _grpWindowInfo.Controls.Add(_lblWindowHandle);
        _grpWindowInfo.Controls.Add(_txtWindowHandle);
        _grpWindowInfo.Controls.Add(_lblWindowTitle);
        _grpWindowInfo.Controls.Add(_txtWindowTitle);
        _grpWindowInfo.Controls.Add(_lblWindowClass);
        _grpWindowInfo.Controls.Add(_txtWindowClass);
        _grpWindowInfo.Controls.Add(_lblProcessId);
        _grpWindowInfo.Controls.Add(_txtProcessId);
        _grpWindowInfo.Controls.Add(_lblProcessName);
        _grpWindowInfo.Controls.Add(_txtProcessName);

        // Window list
        _lvWindows = new ListView
        {
            Location = new Point(12, 200),
            Size = new Size(660, 320),
            View = View.Details,
            FullRowSelect = true,
            GridLines = true
        };
        _lvWindows.Columns.Add("Handle", 80);
        _lvWindows.Columns.Add("Title", 200);
        _lvWindows.Columns.Add("Class", 120);
        _lvWindows.Columns.Add("PID", 50);
        _lvWindows.Columns.Add("Process", 90);
        _lvWindows.Resize += (s, e) => ResizeListViewColumns();
        Shown += (s, e) => ResizeListViewColumns();

        // Close button
        _btnClose = new Button
        {
            Text = "Close",
            Location = new Point(590, 530),
            Size = new Size(80, 32),
            DialogResult = DialogResult.Cancel
        };
        _btnClose.Click += (s, e) => Close();

        Controls.Add(_lblInstructions);
        Controls.Add(_pbCrosshair);
        Controls.Add(_grpWindowInfo);
        Controls.Add(_lvWindows);
        Controls.Add(_btnClose);

        CancelButton = _btnClose;
    }

    private void ResizeListViewColumns()
    {
        if (_lvWindows == null || _lvWindows.Columns.Count < 5) return;

        const int handleWidth = 100;
        const int classWidth = 120;
        const int pidWidth = 70;
        const int processWidth = 100;

        _lvWindows.Columns[0].Width = handleWidth;
        _lvWindows.Columns[2].Width = classWidth;
        _lvWindows.Columns[3].Width = pidWidth;
        _lvWindows.Columns[4].Width = processWidth;

        // Title gets remaining space
        int titleWidth = _lvWindows.ClientSize.Width - handleWidth - classWidth - pidWidth - processWidth;
        if (titleWidth < 100) titleWidth = 100;
        _lvWindows.Columns[1].Width = titleWidth;
    }

    private void SetupEventHandlers()
    {
        // Crosshair drag handling
        _pbCrosshair.MouseDown += (s, e) =>
        {
            if (e.Button == MouseButtons.Left)
            {
                _isDragging = true;
                Cursor = Cursors.Cross;
                _pbCrosshair.Capture = true;
            }
        };

        _pbCrosshair.MouseMove += (s, e) =>
        {
            if (_isDragging)
            {
                UpdateWindowFromCursor();
            }
        };

        _pbCrosshair.MouseUp += (s, e) =>
        {
            if (_isDragging)
            {
                _isDragging = false;
                Cursor = Cursors.Default;
                _pbCrosshair.Capture = false;
                ValidateSelection();
            }
        };

        // Window list selection
        _lvWindows.SelectedIndexChanged += (s, e) =>
        {
            if (_lvWindows.SelectedItems.Count > 0)
            {
                var item = _lvWindows.SelectedItems[0];
                var info = (WindowInfo)item.Tag!;
                DisplayWindowInfo(info.Handle, info.Title, info.ClassName, info.ProcessId, info.ProcessName);
                ValidateSelection();
            }
        };

        _lvWindows.DoubleClick += (s, e) =>
        {
            if (_lvWindows.SelectedItems.Count > 0)
            {
                ValidateSelection();
            }
        };
    }

    private void UpdateWindowFromCursor()
    {
        if (!GetCursorPos(out var point)) return;

        var hWnd = WindowFromPoint(point);
        if (hWnd == IntPtr.Zero || hWnd == _lastHighlightedWindow) return;

        _lastHighlightedWindow = hWnd;

        // Get window info
        var titleBuilder = new System.Text.StringBuilder(256);
        GetWindowText(hWnd, titleBuilder, titleBuilder.Capacity);
        var title = titleBuilder.ToString();

        var classBuilder = new System.Text.StringBuilder(256);
        GetClassName(hWnd, classBuilder, classBuilder.Capacity);
        var className = classBuilder.ToString();

        GetWindowThreadProcessId(hWnd, out var processId);

        var processName = "";
        try
        {
            using var proc = System.Diagnostics.Process.GetProcessById((int)processId);
            processName = proc.ProcessName;
        }
        catch { }

        DisplayWindowInfo(hWnd, title, className, processId, processName);
    }

    private void DisplayWindowInfo(IntPtr handle, string title, string className, uint processId, string processName)
    {
        _txtWindowHandle.Text = $"0x{handle.ToInt64():X}";
        _txtWindowTitle.Text = title;
        _txtWindowClass.Text = className;
        _txtProcessId.Text = processId.ToString();
        _txtProcessName.Text = processName;

        SelectedProcessId = processId;
        SelectedProcessName = processName;
    }

    private void ValidateSelection()
    {
        // No-op - kept for potential future use
    }

    private void PopulateWindowList()
    {
        var windows = new List<WindowInfo>();

        EnumWindows((hWnd, lParam) =>
        {
            // Only visible top-level windows
            if (!IsWindowVisible(hWnd)) return true;
            if (GetParent(hWnd) != IntPtr.Zero) return true;

            var titleBuilder = new System.Text.StringBuilder(256);
            GetWindowText(hWnd, titleBuilder, titleBuilder.Capacity);
            var title = titleBuilder.ToString();

            // Skip windows without titles (often system windows)
            if (string.IsNullOrWhiteSpace(title)) return true;

            var classBuilder = new System.Text.StringBuilder(256);
            GetClassName(hWnd, classBuilder, classBuilder.Capacity);

            GetWindowThreadProcessId(hWnd, out var processId);

            var processName = "";
            try
            {
                using var proc = System.Diagnostics.Process.GetProcessById((int)processId);
                processName = proc.ProcessName;
            }
            catch { }

            windows.Add(new WindowInfo
            {
                Handle = hWnd,
                Title = title,
                ClassName = classBuilder.ToString(),
                ProcessId = processId,
                ProcessName = processName
            });

            return true;
        }, IntPtr.Zero);

        // Sort by title
        windows.Sort((a, b) => string.Compare(a.Title, b.Title, StringComparison.OrdinalIgnoreCase));

        foreach (var wnd in windows)
        {
            var item = new ListViewItem($"0x{wnd.Handle.ToInt64():X}");
            item.SubItems.Add(wnd.Title);
            item.SubItems.Add(wnd.ClassName);
            item.SubItems.Add(wnd.ProcessId.ToString());
            item.SubItems.Add(wnd.ProcessName);
            item.Tag = wnd;
            _lvWindows.Items.Add(item);
        }
    }

    private class WindowInfo
    {
        public IntPtr Handle { get; set; }
        public string Title { get; set; } = "";
        public string ClassName { get; set; } = "";
        public uint ProcessId { get; set; }
        public string ProcessName { get; set; } = "";
    }
}
