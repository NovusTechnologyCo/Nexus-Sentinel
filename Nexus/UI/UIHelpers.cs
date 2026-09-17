// <file>
// <summary>
// Common UI utility extension methods used across all forms and panels. Provides
// ListView column auto-sizing with configurable stretch columns, double-buffered
// panel creation, and other shared WinForms helpers.
// </summary>
// </file>

using System.Runtime.InteropServices;

namespace Nexus.UI;

/// <summary>
/// Extension methods for common UI operations.
/// </summary>
public static class UIHelpers
{
    /// <summary>
    /// Stores which column should stretch for each ListView (by name or default).
    /// Key format: "FormName.ListViewName" or just "ListViewName"
    /// </summary>
    private static readonly Dictionary<string, int> _stretchColumnConfig = new()
    {
        // Format: { "FormName.ListViewName", columnIndex }
        // or { "ListViewName", columnIndex } for global default
        // Default is column 0 if not specified
    };

    /// <summary>
    /// Configure which column stretches for a specific ListView.
    /// </summary>
    public static void SetStretchColumn(string listViewKey, int columnIndex)
    {
        _stretchColumnConfig[listViewKey] = columnIndex;
    }

    /// <summary>
    /// Gets the configured stretch column for a ListView.
    /// </summary>
    private static int GetStretchColumn(ListView listView, int defaultColumn)
    {
        var form = listView.FindForm();
        var formName = form?.GetType().Name ?? "";
        var lvName = listView.Name ?? "";

        // Try form-specific, then listview name only, then default
        if (_stretchColumnConfig.TryGetValue($"{formName}.{lvName}", out int col))
            return col;
        if (_stretchColumnConfig.TryGetValue(lvName, out col))
            return col;
        return defaultColumn;
    }

    /// <summary>
    /// Auto-sizes ListView columns and stretches one column to fill remaining space.
    /// </summary>
    /// <param name="listView">The ListView to adjust</param>
    /// <param name="stretchColumn">Column index to stretch (default 0 = first column, -1 = use config)</param>
    public static void AutoSizeColumns(this ListView listView, int stretchColumn = 0)
    {
        if (listView.Columns.Count == 0) return;
        if (listView.Width <= 0) return; // Not yet sized

        // Get configured stretch column if not specified
        if (stretchColumn < 0)
            stretchColumn = GetStretchColumn(listView, 0);

        // Clamp stretch column to valid range
        stretchColumn = Math.Clamp(stretchColumn, 0, listView.Columns.Count - 1);

        // Measure non-stretch columns by their header text
        int nonStretchWidth = 0;
        using (var g = listView.CreateGraphics())
        {
            var font = listView.Font;
            for (int i = 0; i < listView.Columns.Count; i++)
            {
                if (i != stretchColumn)
                {
                    // Measure header text + padding
                    var textWidth = (int)g.MeasureString(listView.Columns[i].Text, font).Width + 12;
                    listView.Columns[i].Width = textWidth;
                    nonStretchWidth += textWidth;
                }
            }
        }

        // Calculate available width
        int availableWidth = listView.ClientSize.Width;

        // Give stretch column all remaining space
        // Note: ClientSize already excludes scrollbar; checkbox column is separate from header columns
        // Subtract small buffer to prevent horizontal scrollbar from appearing
        int stretchWidth = availableWidth - nonStretchWidth - 4;
        listView.Columns[stretchColumn].Width = Math.Max(stretchWidth, 50);

        // Hide horizontal scrollbar after column resize
        if (listView.IsHandleCreated)
            ShowScrollBar(listView.Handle, SB_HORZ, false);
    }

    /// <summary>
    /// Sets up a ListView to auto-size columns on resize.
    /// </summary>
    /// <param name="listView">The ListView to configure</param>
    /// <param name="stretchColumn">Column index to stretch (default 0 = first column)</param>
    public static void EnableAutoSizeColumns(this ListView listView, int stretchColumn = 0)
    {
        // Store the stretch column for this listview
        listView.Tag = stretchColumn;

        // On resize, recalculate
        listView.Resize += (s, e) => listView.AutoSizeColumns(stretchColumn);

        // Use a short timer to ensure form layout is complete
        var timer = new System.Windows.Forms.Timer { Interval = 50 };
        timer.Tick += (s, e) =>
        {
            timer.Stop();
            timer.Dispose();
            listView.AutoSizeColumns(stretchColumn);
        };

        listView.HandleCreated += (s, e) => timer.Start();
    }

    /// <summary>
    /// Hides the horizontal scrollbar on a ListView.
    /// </summary>
    public static void HideHorizontalScrollbar(this ListView listView)
    {
        listView.HandleCreated += (s, e) => ShowScrollBar(listView.Handle, SB_HORZ, false);
    }

    // P/Invoke for hiding scrollbar
    private const int SB_HORZ = 0;

    [DllImport("user32.dll")]
    private static extern bool ShowScrollBar(IntPtr hWnd, int wBar, bool bShow);
}
