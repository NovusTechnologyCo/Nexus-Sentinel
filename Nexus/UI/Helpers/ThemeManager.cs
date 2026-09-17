// <file>
// <summary>
// Theme manager providing dark and light mode color palettes for the WinForms UI.
// Applies Windows immersive dark mode to title bars and recursively themes all controls
// in a form hierarchy. Used alongside NexusTheme for consistent visual styling.
// </summary>
// </file>

using System.Runtime.InteropServices;
using Nexus.UI.Styles;

namespace Nexus.UI.Helpers;

/// <summary>
/// Manages application theming (dark/light mode).
/// </summary>
public static class ThemeManager
{
    // Windows dark mode API for title bar
    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);

    private const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;

    /// <summary>
    /// Dark theme colors.
    /// </summary>
    public static class Dark
    {
        public static readonly Color Background = Color.FromArgb(30, 30, 30);
        public static readonly Color BackgroundAlt = Color.FromArgb(45, 45, 45);
        public static readonly Color BackgroundLight = Color.FromArgb(60, 60, 60);
        public static readonly Color Foreground = Color.FromArgb(220, 220, 220);
        public static readonly Color ForegroundDim = Color.FromArgb(160, 160, 160);
        public static readonly Color Border = Color.FromArgb(70, 70, 70);
        public static readonly Color Accent = Color.FromArgb(0, 122, 204);
        public static readonly Color AccentLight = Color.FromArgb(28, 151, 234);
        public static readonly Color Selection = Color.FromArgb(51, 51, 51);
        public static readonly Color SelectionText = Color.White;
        public static readonly Color Error = Color.FromArgb(255, 85, 85);
        public static readonly Color Success = Color.FromArgb(85, 255, 85);
        public static readonly Color Warning = Color.FromArgb(255, 200, 85);
    }

    /// <summary>
    /// Light theme colors (Windows defaults).
    /// </summary>
    public static class Light
    {
        public static readonly Color Background = SystemColors.Window;
        public static readonly Color BackgroundAlt = SystemColors.Control;
        public static readonly Color BackgroundLight = SystemColors.ControlLight;
        public static readonly Color Foreground = SystemColors.WindowText;
        public static readonly Color ForegroundDim = SystemColors.GrayText;
        public static readonly Color Border = SystemColors.ControlDark;
        public static readonly Color Accent = SystemColors.Highlight;
        public static readonly Color AccentLight = SystemColors.HotTrack;
        public static readonly Color Selection = SystemColors.Highlight;
        public static readonly Color SelectionText = SystemColors.HighlightText;
        public static readonly Color Error = Color.Red;
        public static readonly Color Success = Color.Green;
        public static readonly Color Warning = Color.Orange;
    }

    /// <summary>
    /// Gets whether dark mode is currently enabled.
    /// </summary>
    public static bool IsDarkMode => NexusSettings.Instance.DarkMode;

    /// <summary>
    /// Gets the current background color.
    /// </summary>
    public static Color Background => IsDarkMode ? Dark.Background : Light.Background;

    /// <summary>
    /// Gets the current alternate background color.
    /// </summary>
    public static Color BackgroundAlt => IsDarkMode ? Dark.BackgroundAlt : Light.BackgroundAlt;

    /// <summary>
    /// Gets the current light background color.
    /// </summary>
    public static Color BackgroundLight => IsDarkMode ? Dark.BackgroundLight : Light.BackgroundLight;

    /// <summary>
    /// Gets the current foreground color.
    /// </summary>
    public static Color Foreground => IsDarkMode ? Dark.Foreground : Light.Foreground;

    /// <summary>
    /// Gets the current dim foreground color.
    /// </summary>
    public static Color ForegroundDim => IsDarkMode ? Dark.ForegroundDim : Light.ForegroundDim;

    /// <summary>
    /// Gets the current border color.
    /// </summary>
    public static Color Border => IsDarkMode ? Dark.Border : Light.Border;

    /// <summary>
    /// Gets the current accent color.
    /// </summary>
    public static Color Accent => IsDarkMode ? Dark.Accent : Light.Accent;

    /// <summary>
    /// Applies the current theme to a form and all its controls.
    /// </summary>
    public static void ApplyTheme(Form form)
    {
        // Set dark title bar on Windows 10/11
        SetDarkTitleBar(form.Handle, IsDarkMode);

        // Apply colors to form
        form.BackColor = BackgroundAlt;
        form.ForeColor = Foreground;

        // Recursively apply to all controls
        ApplyThemeToControls(form.Controls);

        // Handle menus
        if (form.MainMenuStrip != null)
        {
            ApplyThemeToMenuStrip(form.MainMenuStrip);
        }
    }

    /// <summary>
    /// Applies theme to a control collection recursively.
    /// </summary>
    public static void ApplyThemeToControls(Control.ControlCollection controls)
    {
        foreach (Control control in controls)
        {
            ApplyThemeToControl(control);

            // Recurse into child controls
            if (control.Controls.Count > 0)
            {
                ApplyThemeToControls(control.Controls);
            }
        }
    }

    /// <summary>
    /// Applies theme to a single control based on its type.
    /// </summary>
    public static void ApplyThemeToControl(Control control)
    {
        switch (control)
        {
            case TextBox textBox:
                textBox.BackColor = IsDarkMode ? Dark.BackgroundLight : SystemColors.Window;
                textBox.ForeColor = Foreground;
                textBox.BorderStyle = BorderStyle.FixedSingle;
                break;

            case RichTextBox rtb:
                rtb.BackColor = IsDarkMode ? Dark.BackgroundLight : SystemColors.Window;
                rtb.ForeColor = Foreground;
                break;

            case ListBox listBox:
                listBox.BackColor = IsDarkMode ? Dark.BackgroundLight : SystemColors.Window;
                listBox.ForeColor = Foreground;
                break;

            case ListView listView:
                listView.BackColor = IsDarkMode ? Dark.BackgroundLight : SystemColors.Window;
                listView.ForeColor = Foreground;
                // Enable owner draw for better dark mode support
                if (IsDarkMode)
                {
                    listView.OwnerDraw = true;
                    listView.DrawColumnHeader += ListView_DrawColumnHeader;
                    listView.DrawItem += ListView_DrawItem;
                    listView.DrawSubItem += ListView_DrawSubItem;
                }
                break;

            case TreeView treeView:
                treeView.BackColor = IsDarkMode ? Dark.BackgroundLight : SystemColors.Window;
                treeView.ForeColor = Foreground;
                break;

            case DataGridView dgv:
                dgv.BackgroundColor = IsDarkMode ? Dark.BackgroundLight : SystemColors.Window;
                dgv.ForeColor = Foreground;
                dgv.GridColor = Border;
                dgv.DefaultCellStyle.BackColor = IsDarkMode ? Dark.BackgroundLight : SystemColors.Window;
                dgv.DefaultCellStyle.ForeColor = Foreground;
                dgv.DefaultCellStyle.SelectionBackColor = IsDarkMode ? Dark.Selection : SystemColors.Highlight;
                dgv.DefaultCellStyle.SelectionForeColor = IsDarkMode ? Dark.SelectionText : SystemColors.HighlightText;
                dgv.ColumnHeadersDefaultCellStyle.BackColor = IsDarkMode ? Dark.BackgroundAlt : SystemColors.Control;
                dgv.ColumnHeadersDefaultCellStyle.ForeColor = Foreground;
                dgv.RowHeadersDefaultCellStyle.BackColor = IsDarkMode ? Dark.BackgroundAlt : SystemColors.Control;
                dgv.RowHeadersDefaultCellStyle.ForeColor = Foreground;
                dgv.EnableHeadersVisualStyles = !IsDarkMode;
                break;

            case ComboBox comboBox:
                comboBox.BackColor = IsDarkMode ? Dark.BackgroundLight : SystemColors.Window;
                comboBox.ForeColor = Foreground;
                comboBox.FlatStyle = FlatStyle.Flat;
                break;

            case Button button:
                button.BackColor = IsDarkMode ? Dark.BackgroundLight : SystemColors.Control;
                button.ForeColor = Foreground;
                button.FlatStyle = FlatStyle.Flat;
                button.FlatAppearance.BorderColor = Border;
                button.FlatAppearance.MouseOverBackColor = IsDarkMode ? Dark.BackgroundAlt : SystemColors.ControlLight;
                break;

            case CheckBox checkBox:
                checkBox.ForeColor = Foreground;
                // Don't change BackColor - let parent handle it
                break;

            case RadioButton radioButton:
                radioButton.ForeColor = Foreground;
                break;

            case Label label:
                label.ForeColor = Foreground;
                break;

            case GroupBox groupBox:
                groupBox.ForeColor = Foreground;
                break;

            case TabControl tabControl:
                // Use NexusTheme for proper owner-drawn tab styling
                NexusTheme.StyleTabControl(tabControl);
                break;

            case TabPage tabPage:
                // Match shell tab bar style - dark background
                tabPage.BackColor = NexusTheme.BackgroundDark;
                tabPage.ForeColor = NexusTheme.TextPrimary;
                tabPage.BorderStyle = BorderStyle.None;
                break;

            case Panel panel:
                panel.BackColor = BackgroundAlt;
                panel.ForeColor = Foreground;
                break;

            case SplitContainer splitContainer:
                splitContainer.BackColor = BackgroundAlt;
                splitContainer.ForeColor = Foreground;
                break;

            case MenuStrip menuStrip:
                ApplyThemeToMenuStrip(menuStrip);
                break;

            case StatusStrip statusStrip:
                ApplyThemeToToolStrip(statusStrip);
                break;

            case ToolStrip toolStrip:
                ApplyThemeToToolStrip(toolStrip);
                break;

            case NumericUpDown numericUpDown:
                numericUpDown.BackColor = IsDarkMode ? Dark.BackgroundLight : SystemColors.Window;
                numericUpDown.ForeColor = Foreground;
                break;

            case ProgressBar progressBar:
                // ProgressBar doesn't support custom colors well in WinForms
                break;

            case TrackBar trackBar:
                trackBar.BackColor = BackgroundAlt;
                break;

            default:
                // Generic fallback
                control.BackColor = BackgroundAlt;
                control.ForeColor = Foreground;
                break;
        }
    }

    /// <summary>
    /// Applies theme to a MenuStrip.
    /// </summary>
    public static void ApplyThemeToMenuStrip(MenuStrip menuStrip)
    {
        menuStrip.BackColor = BackgroundAlt;
        menuStrip.ForeColor = Foreground;

        if (IsDarkMode)
        {
            menuStrip.Renderer = new DarkMenuRenderer();
        }
        else
        {
            menuStrip.RenderMode = ToolStripRenderMode.Professional;
        }

        foreach (ToolStripItem item in menuStrip.Items)
        {
            ApplyThemeToToolStripItem(item);
        }
    }

    /// <summary>
    /// Applies theme to a ToolStrip.
    /// </summary>
    public static void ApplyThemeToToolStrip(ToolStrip toolStrip)
    {
        toolStrip.BackColor = BackgroundAlt;
        toolStrip.ForeColor = Foreground;

        if (IsDarkMode)
        {
            toolStrip.Renderer = new DarkMenuRenderer();
        }
        else
        {
            toolStrip.RenderMode = ToolStripRenderMode.Professional;
        }

        foreach (ToolStripItem item in toolStrip.Items)
        {
            ApplyThemeToToolStripItem(item);
        }
    }

    private static void ApplyThemeToToolStripItem(ToolStripItem item)
    {
        item.BackColor = BackgroundAlt;
        item.ForeColor = Foreground;

        if (item is ToolStripDropDownItem dropDown)
        {
            foreach (ToolStripItem subItem in dropDown.DropDownItems)
            {
                ApplyThemeToToolStripItem(subItem);
            }
        }
    }

    /// <summary>
    /// Sets the title bar to dark mode on Windows 10/11.
    /// </summary>
    public static void SetDarkTitleBar(IntPtr handle, bool dark)
    {
        try
        {
            int value = dark ? 1 : 0;
            DwmSetWindowAttribute(handle, DWMWA_USE_IMMERSIVE_DARK_MODE, ref value, sizeof(int));
        }
        catch
        {
            // Ignore if API not available (older Windows)
        }
    }

    // ListView owner-draw handlers for dark mode
    private static void ListView_DrawColumnHeader(object? sender, DrawListViewColumnHeaderEventArgs e)
    {
        using var brush = new SolidBrush(Dark.BackgroundAlt);
        e.Graphics.FillRectangle(brush, e.Bounds);

        using var textBrush = new SolidBrush(Dark.Foreground);
        var format = new StringFormat
        {
            Alignment = StringAlignment.Near,
            LineAlignment = StringAlignment.Center
        };
        var bounds = new Rectangle(e.Bounds.X + 4, e.Bounds.Y, e.Bounds.Width - 4, e.Bounds.Height);
        e.Graphics.DrawString(e.Header?.Text ?? "", e.Font ?? SystemFonts.DefaultFont, textBrush, bounds, format);

        // Draw border
        using var pen = new Pen(Dark.Border);
        e.Graphics.DrawLine(pen, e.Bounds.Right - 1, e.Bounds.Top, e.Bounds.Right - 1, e.Bounds.Bottom);
    }

    private static void ListView_DrawItem(object? sender, DrawListViewItemEventArgs e)
    {
        e.DrawDefault = true;
    }

    private static void ListView_DrawSubItem(object? sender, DrawListViewSubItemEventArgs e)
    {
        e.DrawDefault = true;
    }
}

/// <summary>
/// Custom renderer for dark mode menus and toolstrips.
/// </summary>
public class DarkMenuRenderer : ToolStripProfessionalRenderer
{
    public DarkMenuRenderer() : base(new DarkColorTable()) { }

    protected override void OnRenderMenuItemBackground(ToolStripItemRenderEventArgs e)
    {
        if (e.Item.Selected || e.Item.Pressed)
        {
            using var brush = new SolidBrush(ThemeManager.Dark.Selection);
            e.Graphics.FillRectangle(brush, new Rectangle(Point.Empty, e.Item.Size));
        }
        else
        {
            using var brush = new SolidBrush(ThemeManager.Dark.BackgroundAlt);
            e.Graphics.FillRectangle(brush, new Rectangle(Point.Empty, e.Item.Size));
        }
    }

    protected override void OnRenderToolStripBackground(ToolStripRenderEventArgs e)
    {
        using var brush = new SolidBrush(ThemeManager.Dark.BackgroundAlt);
        e.Graphics.FillRectangle(brush, e.AffectedBounds);
    }

    protected override void OnRenderImageMargin(ToolStripRenderEventArgs e)
    {
        using var brush = new SolidBrush(ThemeManager.Dark.BackgroundAlt);
        e.Graphics.FillRectangle(brush, e.AffectedBounds);
    }

    protected override void OnRenderSeparator(ToolStripSeparatorRenderEventArgs e)
    {
        using var pen = new Pen(ThemeManager.Dark.Border);
        int y = e.Item.Height / 2;
        e.Graphics.DrawLine(pen, 0, y, e.Item.Width, y);
    }

    protected override void OnRenderItemText(ToolStripItemTextRenderEventArgs e)
    {
        e.TextColor = ThemeManager.Dark.Foreground;
        base.OnRenderItemText(e);
    }

    protected override void OnRenderToolStripBorder(ToolStripRenderEventArgs e)
    {
        using var pen = new Pen(ThemeManager.Dark.Border);
        e.Graphics.DrawRectangle(pen, 0, 0, e.AffectedBounds.Width - 1, e.AffectedBounds.Height - 1);
    }
}

/// <summary>
/// Dark color table for ToolStrip rendering.
/// </summary>
public class DarkColorTable : ProfessionalColorTable
{
    public override Color MenuBorder => ThemeManager.Dark.Border;
    public override Color MenuItemBorder => ThemeManager.Dark.Border;
    public override Color MenuItemSelected => ThemeManager.Dark.Selection;
    public override Color MenuStripGradientBegin => ThemeManager.Dark.BackgroundAlt;
    public override Color MenuStripGradientEnd => ThemeManager.Dark.BackgroundAlt;
    public override Color MenuItemSelectedGradientBegin => ThemeManager.Dark.Selection;
    public override Color MenuItemSelectedGradientEnd => ThemeManager.Dark.Selection;
    public override Color MenuItemPressedGradientBegin => ThemeManager.Dark.Selection;
    public override Color MenuItemPressedGradientEnd => ThemeManager.Dark.Selection;
    public override Color ToolStripDropDownBackground => ThemeManager.Dark.BackgroundAlt;
    public override Color ImageMarginGradientBegin => ThemeManager.Dark.BackgroundAlt;
    public override Color ImageMarginGradientMiddle => ThemeManager.Dark.BackgroundAlt;
    public override Color ImageMarginGradientEnd => ThemeManager.Dark.BackgroundAlt;
    public override Color SeparatorDark => ThemeManager.Dark.Border;
    public override Color SeparatorLight => ThemeManager.Dark.Border;
}
