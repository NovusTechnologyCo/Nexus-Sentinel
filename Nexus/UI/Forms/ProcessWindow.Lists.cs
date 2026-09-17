// <file>
// <summary>
// Process/window/application list refresh logic for ProcessWindow.
// </summary>
// </file>
using Nexus.UI.Interop;
using Nexus.UI.Styles;
using System.Text;

namespace Nexus.UI.Forms;

public partial class ProcessWindow
{
    private void RefreshProcessList()
    {
        lvProcesses.BeginUpdate();
        try
        {
            lvProcesses.Items.Clear();
            _processes = NexusHelper.EnumerateProcesses();

            foreach (var proc in _processes)
            {
                // Apply filter
                if (!string.IsNullOrEmpty(_filter))
                {
                    if (!proc.Name.Contains(_filter, StringComparison.OrdinalIgnoreCase) &&
                        !proc.Pid.ToString().Contains(_filter))
                    {
                        continue;
                    }
                }

                string pidStr = _showPidAsDecimal ? $"{proc.Pid}" : $"{proc.Pid:X8}";
                var item = new ListViewItem(pidStr);
                item.SubItems.Add(proc.Name);
                item.SubItems.Add(proc.Is32Bit != 0 ? "32-bit" : "64-bit");
                item.Tag = proc.Pid;
                lvProcesses.Items.Add(item);
            }
        }
        finally
        {
            lvProcesses.EndUpdate();
            AutoSizeColumns(lvProcesses);
        }

        lblCount.Text = $"{lvProcesses.Items.Count} processes";
    }

    private void RefreshWindowList()
    {
        _windows.Clear();
        lvWindows.BeginUpdate();
        try
        {
            lvWindows.Items.Clear();

            // Enumerate all windows
            EnumWindows((hWnd, lParam) =>
            {
                bool isVisible = IsWindowVisible(hWnd);
                if (!_showInvisibleWindows && !isVisible)
                    return true; // Skip invisible windows unless option is set

                int length = GetWindowTextLength(hWnd);

                // Skip windows without title (like CE does) unless showing invisible
                if (!_showInvisibleWindows && length == 0)
                    return true;

                string title = "";
                if (length > 0)
                {
                    var sb = new StringBuilder(length + 1);
                    GetWindowText(hWnd, sb, sb.Capacity);
                    title = sb.ToString();
                }

                // Get class name
                var classNameSb = new StringBuilder(256);
                GetClassName(hWnd, classNameSb, classNameSb.Capacity);
                string className = classNameSb.ToString();

                // Get process ID
                GetWindowThreadProcessId(hWnd, out uint processId);

                var windowInfo = new WindowInfo
                {
                    Handle = hWnd,
                    Title = title,
                    ClassName = className,
                    ProcessId = processId,
                    IsVisible = isVisible
                };
                _windows.Add(windowInfo);

                return true;
            }, IntPtr.Zero);

            // Add to list view
            foreach (var win in _windows)
            {
                // Apply filter
                if (!string.IsNullOrEmpty(_filter))
                {
                    if (!win.Title.Contains(_filter, StringComparison.OrdinalIgnoreCase) &&
                        !win.ClassName.Contains(_filter, StringComparison.OrdinalIgnoreCase) &&
                        !win.ProcessId.ToString().Contains(_filter))
                    {
                        continue;
                    }
                }

                string pidStr = _showPidAsDecimal ? $"{win.ProcessId}" : $"{win.ProcessId:X8}";
                var item = new ListViewItem(pidStr);
                item.SubItems.Add($"0x{win.Handle:X}");
                item.SubItems.Add(win.Title);
                item.SubItems.Add(win.ClassName);
                item.Tag = win.ProcessId;
                lvWindows.Items.Add(item);
            }
        }
        finally
        {
            lvWindows.EndUpdate();
            AutoSizeColumns(lvWindows);
        }
    }

    private void RefreshApplicationList()
    {
        _applications.Clear();
        lvApplications.BeginUpdate();
        try
        {
            lvApplications.Items.Clear();

            // Enumerate windows that are "applications" (visible, top-level with title)
            EnumWindows((hWnd, lParam) =>
            {
                // Skip invisible windows
                if (!IsWindowVisible(hWnd))
                    return true;

                // Skip windows with no title
                int length = GetWindowTextLength(hWnd);
                if (length == 0)
                    return true;

                // Skip windows that have an owner (not top-level)
                if (GetWindow(hWnd, GW_OWNER) != IntPtr.Zero)
                    return true;

                var sb = new StringBuilder(length + 1);
                GetWindowText(hWnd, sb, sb.Capacity);
                string title = sb.ToString();

                // Get class name
                var classNameSb = new StringBuilder(256);
                GetClassName(hWnd, classNameSb, classNameSb.Capacity);
                string className = classNameSb.ToString();

                // Skip some system windows
                if (className == "Progman" || className == "WorkerW" || className == "Shell_TrayWnd")
                    return true;

                // Get process ID
                GetWindowThreadProcessId(hWnd, out uint processId);

                var windowInfo = new WindowInfo
                {
                    Handle = hWnd,
                    Title = title,
                    ClassName = className,
                    ProcessId = processId,
                    IsVisible = true
                };
                _applications.Add(windowInfo);

                return true;
            }, IntPtr.Zero);

            // Add to list view
            foreach (var app in _applications)
            {
                // Apply filter
                if (!string.IsNullOrEmpty(_filter))
                {
                    if (!app.Title.Contains(_filter, StringComparison.OrdinalIgnoreCase) &&
                        !app.ProcessId.ToString().Contains(_filter))
                    {
                        continue;
                    }
                }

                string pidStr = _showPidAsDecimal ? $"{app.ProcessId}" : $"{app.ProcessId:X8}";
                var item = new ListViewItem(pidStr);
                item.SubItems.Add(app.Title);
                item.Tag = app.ProcessId;
                lvApplications.Items.Add(item);
            }
        }
        finally
        {
            lvApplications.EndUpdate();
            AutoSizeColumns(lvApplications);
        }
    }

    private void AutoSizeColumns(ListView lv)
    {
        foreach (ColumnHeader col in lv.Columns)
        {
            col.Width = -2;  // Auto-size to header and content
        }
    }
}
