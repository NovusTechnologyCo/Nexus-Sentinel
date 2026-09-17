// <file>
// <summary>
// Debug log output panel providing a scrollable, color-coded text log for debug messages,
// warnings, and errors. Supports copy, select all, clear, and save-to-file operations.
// Used as a tab in the debugger layout's bottom panel alongside call stack and breakpoints.
// </summary>
// </file>

using Nexus.UI.Core;
using Nexus.UI.Styles;

namespace Nexus.UI.Panels;

/// <summary>
/// Debug log panel displaying timestamped log messages in a read-only rich text box.
/// Supports color-coded entries (info, warning, error), context menu operations,
/// and file export.
/// </summary>
public class LogPanel : UserControl
{
    private readonly RichTextBox _logBox;
    private readonly ContextMenuStrip _contextMenu;

    public LogPanel()
    {
        BackColor = NexusTheme.BackgroundPanel;

        _logBox = new RichTextBox
        {
            Dock = DockStyle.Fill,
            ReadOnly = true,
            BackColor = Color.FromArgb(30, 30, 30),
            ForeColor = Color.FromArgb(200, 200, 200),
            Font = new Font("Consolas", 9f),
            BorderStyle = BorderStyle.None,
            WordWrap = false,
            ScrollBars = RichTextBoxScrollBars.Both
        };

        _contextMenu = new ContextMenuStrip();
        _contextMenu.Items.Add("Copy", null, (s, e) => _logBox.Copy());
        _contextMenu.Items.Add("Select All", null, (s, e) => _logBox.SelectAll());
        _contextMenu.Items.Add(new ToolStripSeparator());
        _contextMenu.Items.Add("Clear", null, (s, e) => Clear());
        _contextMenu.Items.Add(new ToolStripSeparator());
        _contextMenu.Items.Add("Save to File...", null, (s, e) => SaveToFile());
        _logBox.ContextMenuStrip = _contextMenu;

        Controls.Add(_logBox);

        // Subscribe to log events
        EventBus.Instance.Subscribe<LogMessageEvent>(OnLogMessage);
    }

    private void OnLogMessage(LogMessageEvent evt)
    {
        if (InvokeRequired)
        {
            BeginInvoke(() => OnLogMessage(evt));
            return;
        }

        AppendLog(evt.Message, evt.Type);
    }

    public void AppendLog(string message, LogType type = LogType.Info)
    {
        var color = type switch
        {
            LogType.Error => Color.FromArgb(255, 100, 100),
            LogType.Warning => Color.FromArgb(255, 200, 100),
            LogType.Success => Color.FromArgb(100, 255, 100),
            LogType.Debug => Color.FromArgb(150, 150, 150),
            _ => Color.FromArgb(200, 200, 200)
        };

        var timestamp = DateTime.Now.ToString("HH:mm:ss.fff");
        var prefix = type switch
        {
            LogType.Error => "[ERR]",
            LogType.Warning => "[WRN]",
            LogType.Success => "[OK]",
            LogType.Debug => "[DBG]",
            _ => "[INF]"
        };

        _logBox.SelectionStart = _logBox.TextLength;
        _logBox.SelectionLength = 0;
        _logBox.SelectionColor = Color.Gray;
        _logBox.AppendText($"{timestamp} ");
        _logBox.SelectionColor = color;
        _logBox.AppendText($"{prefix} {message}\n");

        // Auto-scroll to bottom
        _logBox.SelectionStart = _logBox.TextLength;
        _logBox.ScrollToCaret();
    }

    public void Clear()
    {
        _logBox.Clear();
    }

    private void SaveToFile()
    {
        using var dialog = new SaveFileDialog
        {
            Filter = "Text files (*.txt)|*.txt|Log files (*.log)|*.log|All files (*.*)|*.*",
            DefaultExt = "txt"
        };

        if (dialog.ShowDialog() == DialogResult.OK)
        {
            File.WriteAllText(dialog.FileName, _logBox.Text);
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            EventBus.Instance.Unsubscribe<LogMessageEvent>(OnLogMessage);
            _contextMenu.Dispose();
        }
        base.Dispose(disposing);
    }
}

public enum LogType
{
    Info,
    Warning,
    Error,
    Success,
    Debug
}

public class LogMessageEvent : IEvent
{
    public string Message { get; }
    public LogType Type { get; }

    public LogMessageEvent(string message, LogType type = LogType.Info)
    {
        Message = message;
        Type = type;
    }
}
