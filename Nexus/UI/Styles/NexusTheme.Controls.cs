// NexusTheme.Controls.cs - Control styling helpers and tab bar helpers
// Split from NexusTheme.cs for maintainability

using System.Runtime.CompilerServices;

namespace Nexus.UI.Styles;

public static partial class NexusTheme
{
    #region Control Styling Helpers

    // Tracks which buttons are currently hovered, without using the Tag property.
    // ConditionalWeakTable allows entries to be garbage-collected when the Button is collected.
    private static readonly ConditionalWeakTable<Button, object> _hoveredButtons = new();

    /// <summary>
    /// Returns true if the button is currently tracked as hovered by the theme system.
    /// </summary>
    internal static bool IsButtonHovered(Button btn) => _hoveredButtons.TryGetValue(btn, out _);

    /// <summary>
    /// Apply standard dark theme to a form.
    /// </summary>
    public static void ApplyTo(Form form)
    {
        form.BackColor = BackgroundDark;
        form.ForeColor = TextPrimary;
        form.Font = FontBody;

        // Apply dark title bar on Windows 10/11
        // Must be deferred until handle is created if not yet available
        if (_isDarkMode && Environment.OSVersion.Version.Major >= 10)
        {
            if (form.IsHandleCreated)
            {
                ApplyDarkTitleBar(form);
            }
            else
            {
                form.HandleCreated += (s, e) => ApplyDarkTitleBar(form);
            }
        }

        ApplyToControls(form.Controls);
    }

    /// <summary>
    /// Recursively apply theme to all controls.
    /// </summary>
    public static void ApplyToControls(Control.ControlCollection controls)
    {
        foreach (Control control in controls)
        {
            ApplyToControl(control);

            if (control.HasChildren)
            {
                ApplyToControls(control.Controls);
            }
        }
    }

    /// <summary>
    /// Apply theme to a single control based on its type.
    /// </summary>
    public static void ApplyToControl(Control control)
    {
        control.Font = FontBody;

        switch (control)
        {
            case Button btn:
                StyleButton(btn);
                break;
            case TextBox txt:
                StyleTextBox(txt);
                break;
            case ComboBox cmb:
                StyleComboBox(cmb);
                break;
            case ListView lv:
                StyleListView(lv);
                break;
            case TreeView tv:
                StyleTreeView(tv);
                break;
            case DataGridView dgv:
                StyleDataGridView(dgv);
                break;
            case GroupBox gb:
                StyleGroupBox(gb);
                break;
            case Panel pnl:
                StylePanel(pnl);
                break;
            case Label lbl:
                StyleLabel(lbl);
                break;
            case CheckBox chk:
                StyleCheckBox(chk);
                break;
            case ProgressBar pb:
                StyleProgressBar(pb);
                break;
            case TabControl tc:
                StyleTabControl(tc);
                break;
            case MenuStrip ms:
                StyleMenuStrip(ms);
                break;
            case StatusStrip ss:  // StatusStrip inherits from ToolStrip - must come first
                StyleStatusStrip(ss);
                break;
            case ToolStrip ts:
                StyleToolStrip(ts);
                break;
        }
    }

    /// <summary>Disabled button text - readable gray</summary>
    public static Color TextButtonDisabled => Color.FromArgb(140, 140, 150);

    public static void StyleButton(Button btn)
    {
        // Skip tab bar buttons (marked with special tag)
        var tag = btn.Tag as string;
        if (tag == "TabButton" || tag == "Selected")
            return;

        btn.FlatStyle = FlatStyle.Flat;
        btn.UseVisualStyleBackColor = false;  // Required for BackColor to be respected
        btn.FlatAppearance.BorderColor = Border;
        btn.FlatAppearance.BorderSize = BorderWidth;
        btn.BackColor = BackgroundControl;
        btn.ForeColor = TextPrimary;
        // Hover: cyan background with dark text
        btn.FlatAppearance.MouseOverBackColor = Accent;
        btn.FlatAppearance.MouseDownBackColor = AccentDark;
        // Only set default size if button hasn't been explicitly sized
        // (default Size is 75x23, so if it's different, respect it)
        if (btn.Width == 75 && btn.Height == 23)
        {
            btn.Size = new Size(ButtonWidth, ButtonHeight);
        }
        else
        {
            // Keep existing width but ensure minimum height for consistency
            btn.Height = Math.Max(btn.Height, ButtonHeight);
        }
        btn.Margin = new Padding(0); // Zero margin for perfect alignment

        // Track hover state using a dictionary instead of Tag to avoid overwriting user data
        btn.MouseEnter += (s, e) =>
        {
            if (s is Button b)
            {
                _hoveredButtons.AddOrUpdate(b, b.ForeColor);
                b.ForeColor = Accent;  // Make text same as hover bg (invisible)
                b.Invalidate();
            }
        };
        btn.MouseLeave += (s, e) =>
        {
            if (s is Button b && _hoveredButtons.TryGetValue(b, out var stored) && stored is Color originalColor)
            {
                b.ForeColor = originalColor;  // Restore original
                _hoveredButtons.Remove(b);
                b.Invalidate();
            }
        };

        // Set hover colors
        btn.FlatAppearance.MouseOverBackColor = Accent;
        btn.FlatAppearance.MouseDownBackColor = AccentDark;

        btn.Paint += Button_Paint;
    }

    private static void Button_Paint(object? sender, PaintEventArgs e)
    {
        if (sender is not Button btn)
            return;

        var isHovered = IsButtonHovered(btn);
        var isDisabled = !btn.Enabled;

        // Only custom draw when hovered or disabled
        if (!isHovered && !isDisabled)
            return;

        Color textColor;
        if (isDisabled)
            textColor = TextButtonDisabled;
        else // hovered
            textColor = BackgroundDark;  // Dark text on cyan hover background

        // Draw our dark text on top (WordBreak for multiline buttons)
        var flags = TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.WordBreak;
        TextRenderer.DrawText(e.Graphics, btn.Text, btn.Font, btn.ClientRectangle, textColor, flags);
    }

    public static void StyleButtonWide(Button btn)
    {
        StyleButton(btn);
        btn.Width = ButtonWidthWide;
    }

    public static void StyleButtonSmall(Button btn)
    {
        StyleButton(btn);
        btn.Size = new Size(ButtonHeight, ButtonHeight);  // Square button
    }

    public static void StylePrimaryButton(Button btn)
    {
        StyleButton(btn);
        // Dark background with cyan text (flipped from cyan bg with dark text)
        btn.BackColor = BackgroundDark;
        btn.ForeColor = Accent;
        btn.FlatAppearance.BorderColor = Border;
        btn.FlatAppearance.BorderSize = 1;
        btn.Font = new Font(btn.Font, FontStyle.Bold);
    }

    public static void StyleTextBox(TextBox txt)
    {
        txt.BorderStyle = BorderStyle.FixedSingle;
        txt.BackColor = BackgroundControl;
        txt.ForeColor = TextPrimary;
        txt.Height = TextBoxHeight;
        txt.Margin = new Padding(0); // Zero margin for perfect alignment
    }

    public static void StyleMonoTextBox(TextBox txt)
    {
        StyleTextBox(txt);
        txt.Font = FontMono;
    }

    public static void StyleComboBox(ComboBox cmb)
    {
        cmb.FlatStyle = FlatStyle.Popup;  // Popup respects colors better than Flat/Standard
        cmb.BackColor = BackgroundControl;
        cmb.ForeColor = TextPrimary;
        cmb.Height = ComboBoxHeight;
        cmb.Margin = new Padding(0); // Zero margin for perfect alignment
    }

    public static void StyleListView(ListView lv)
    {
        lv.BackColor = BackgroundControl;
        lv.ForeColor = TextPrimary;
        lv.BorderStyle = BorderStyle.FixedSingle;
        lv.FullRowSelect = true;
        lv.GridLines = false;

        // For virtual mode or owner draw, set these colors
        // lv.OwnerDraw = true for full control
    }

    public static void StyleTreeView(TreeView tv)
    {
        tv.BackColor = BackgroundControl;
        tv.ForeColor = TextPrimary;
        tv.BorderStyle = BorderStyle.FixedSingle;
        tv.LineColor = Border;
    }

    public static void StyleDataGridView(DataGridView dgv)
    {
        dgv.BackgroundColor = BackgroundControl;
        dgv.ForeColor = TextPrimary;
        dgv.GridColor = Border;
        dgv.BorderStyle = BorderStyle.FixedSingle;
        dgv.DefaultCellStyle.BackColor = BackgroundControl;
        dgv.DefaultCellStyle.ForeColor = TextPrimary;
        dgv.DefaultCellStyle.SelectionBackColor = Selection;
        dgv.DefaultCellStyle.SelectionForeColor = TextPrimary;
        dgv.ColumnHeadersDefaultCellStyle.BackColor = BackgroundHeader;
        dgv.ColumnHeadersDefaultCellStyle.ForeColor = TextPrimary;
        dgv.EnableHeadersVisualStyles = false;
        dgv.RowHeadersVisible = false;
        dgv.AllowUserToAddRows = false;
    }

    public static void StyleGroupBox(GroupBox gb)
    {
        gb.ForeColor = TextSecondary;
        gb.BackColor = Color.Transparent;
    }

    public static void StylePanel(Panel pnl)
    {
        pnl.BackColor = BackgroundPanel;
    }

    public static void StyleLabel(Label lbl)
    {
        lbl.ForeColor = TextPrimary;
        lbl.BackColor = Color.Transparent;
    }

    public static void StyleCheckBox(CheckBox chk)
    {
        chk.ForeColor = TextPrimary;
        // Use parent's background if available, otherwise dark background
        chk.BackColor = chk.Parent?.BackColor ?? BackgroundDark;
    }

    /// <summary>
    /// Style checkbox for ThemeManager-styled forms (respects light/dark mode setting)
    /// </summary>
    public static void StyleCheckBoxThemed(CheckBox chk)
    {
        chk.ForeColor = Helpers.ThemeManager.Foreground;
        chk.BackColor = Helpers.ThemeManager.BackgroundAlt;
    }

    public static void StyleProgressBar(ProgressBar pb)
    {
        // Note: ProgressBar doesn't support custom colors easily in WinForms
        // Consider owner-draw for full control
    }

    public static void StyleTabControl(TabControl tc)
    {
        tc.DrawMode = TabDrawMode.OwnerDrawFixed;
        tc.BackColor = BackgroundDark;
        tc.Padding = new Point(Space8, Space4);
        tc.ItemSize = new Size(0, ControlHeight);
        tc.SizeMode = TabSizeMode.Normal;
        tc.Appearance = TabAppearance.FlatButtons; // Flat buttons removes 3D borders
        tc.Margin = new Padding(0);

        // Style all tab pages with dark background
        foreach (TabPage tp in tc.TabPages)
        {
            tp.BackColor = BackgroundDark;
            tp.ForeColor = TextPrimary;
            tp.Padding = new Padding(Space8);
            tp.BorderStyle = BorderStyle.None;
            tp.Margin = new Padding(0);
        }

        // Custom paint for flat tab bar style (like shell tab bar)
        tc.DrawItem -= TabControl_DrawItem;  // Prevent duplicate handlers
        tc.DrawItem += TabControl_DrawItem;
    }

    private static void TabControl_DrawItem(object? sender, DrawItemEventArgs e)
    {
        if (sender is not TabControl tc) return;

        var tabPage = tc.TabPages[e.Index];
        var tabBounds = tc.GetTabRect(e.Index);
        var isSelected = tc.SelectedIndex == e.Index;

        // Fill entire tab control background area to eliminate any light borders
        using var bgBrush = new SolidBrush(BackgroundDark);

        // Expand bounds to cover any artifacts from the FlatButtons appearance
        var fillBounds = new Rectangle(tabBounds.X - 2, tabBounds.Y - 2, tabBounds.Width + 4, tabBounds.Height + 4);
        e.Graphics.FillRectangle(bgBrush, fillBounds);

        // No underline - just like shell tab bar
        // Text - use bold + accent for selected, regular + secondary for unselected (matches shell exactly)
        var textColor = isSelected ? Accent : TextSecondary;
        var font = isSelected ? new Font(tc.Font, FontStyle.Bold) : tc.Font;
        var flags = TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter;
        TextRenderer.DrawText(e.Graphics, tabPage.Text, font, tabBounds, textColor, flags);

        if (isSelected) font.Dispose();
    }

    public static void StyleMenuStrip(MenuStrip ms)
    {
        ms.BackColor = BackgroundHeader;
        ms.ForeColor = TextPrimary;
        ms.RenderMode = ToolStripRenderMode.Professional;
        ms.Renderer = new NexusMenuRenderer();
    }

    public static void StyleToolStrip(ToolStrip ts)
    {
        ts.BackColor = BackgroundHeader;
        ts.ForeColor = TextPrimary;
        ts.RenderMode = ToolStripRenderMode.Professional;
        ts.Renderer = new NexusMenuRenderer();
    }

    public static void StyleStatusStrip(StatusStrip ss)
    {
        ss.BackColor = BackgroundHeader;
        ss.ForeColor = TextSecondary;
        ss.RenderMode = ToolStripRenderMode.Professional;
        ss.Renderer = new NexusMenuRenderer();
    }

    #endregion

    #region Tab Bar Helpers (Shell-style)

    /// <summary>
    /// Creates a shell-style tab bar using a Panel with Buttons.
    /// This provides full control over rendering without ToolStrip borders.
    /// </summary>
    /// <param name="tabNames">Array of tab names</param>
    /// <param name="onTabClick">Action called with tab index when a tab is clicked</param>
    /// <returns>Tuple of (Panel, Button[])</returns>
    public static (Panel tabBar, Button[] buttons) CreateTabBar(string[] tabNames, Action<int> onTabClick)
    {
        var tabBar = new Panel
        {
            BackColor = BackgroundDark,
            Height = ToolbarHeight,
            Padding = new Padding(0)
        };

        var buttons = new Button[tabNames.Length];
        int xPos = Space8;
        for (int i = 0; i < tabNames.Length; i++)
        {
            int index = i; // Capture for closure
            bool isFirst = i == 0;
            // Calculate width using bold font to ensure consistent sizing
            var boldFont = new Font(FontFamily, FontSizeBody, FontStyle.Bold);
            var textSize = TextRenderer.MeasureText(tabNames[i], boldFont);
            int buttonWidth = textSize.Width + Space16 * 2;

            var btn = new Button
            {
                Text = tabNames[i],
                FlatStyle = FlatStyle.Flat,
                // First tab starts selected (lighter bg, accent color, bold)
                ForeColor = isFirst ? Accent : TextSecondary,
                BackColor = isFirst ? BackgroundControl : BackgroundDark,
                Font = isFirst ? new Font(FontFamily, FontSizeBody, FontStyle.Bold) : new Font(FontFamily, FontSizeBody),
                Location = new Point(xPos, Space4),
                Size = new Size(buttonWidth, ToolbarHeight - Space8),
                AutoSize = false
            };
            btn.FlatAppearance.BorderSize = 0;
            btn.FlatAppearance.MouseOverBackColor = Accent;
            btn.FlatAppearance.MouseDownBackColor = AccentDark;
            btn.Tag = "TabButton";  // Mark as tab button to skip StyleButton

            // Add hover text color change for tab buttons
            var originalForeColor = btn.ForeColor;
            btn.MouseEnter += (s, e) => { if (s is Button b) b.ForeColor = BackgroundDark; };
            btn.MouseLeave += (s, e) => { if (s is Button b) b.ForeColor = buttons[index].Tag as string == "Selected" ? Accent : TextSecondary; };

            btn.Click += (s, e) => onTabClick(index);
            buttons[i] = btn;
            tabBar.Controls.Add(btn);
            xPos += buttonWidth + Space4;
        }

        return (tabBar, buttons);
    }

    /// <summary>
    /// Updates tab button states to show which tab is selected.
    /// </summary>
    /// <param name="buttons">Array of tab buttons</param>
    /// <param name="selectedIndex">Index of the selected tab</param>
    public static void UpdateTabSelection(Button[] buttons, int selectedIndex)
    {
        for (int i = 0; i < buttons.Length; i++)
        {
            bool isSelected = i == selectedIndex;
            bool isHovered = buttons[i].ClientRectangle.Contains(buttons[i].PointToClient(Cursor.Position));
            // If hovered, keep dark text; otherwise use normal selection colors
            buttons[i].ForeColor = isHovered ? BackgroundDark : (isSelected ? Accent : TextSecondary);
            buttons[i].Font = new Font(buttons[i].Font, isSelected ? FontStyle.Bold : FontStyle.Regular);
            // Selected tab gets lighter background, unselected stays dark
            buttons[i].BackColor = isSelected ? BackgroundControl : BackgroundDark;
            // Keep hover effect - cyan background with dark text
            buttons[i].FlatAppearance.MouseOverBackColor = Accent;
            buttons[i].FlatAppearance.MouseDownBackColor = AccentDark;
            // Update tag to track selection state for MouseLeave handler
            buttons[i].Tag = isSelected ? "Selected" : "TabButton";
        }
    }

    #endregion
}
