// NexusTheme.Renderers.cs - Custom renderers, color tables, and control subclasses
// Split from NexusTheme.cs for maintainability

namespace Nexus.UI.Styles;

/// <summary>
/// Custom renderer for menus and toolstrips with Nexus theme.
/// </summary>
public class NexusMenuRenderer : ToolStripProfessionalRenderer
{
    public NexusMenuRenderer() : base(new NexusColorTable()) { }

    protected override void OnRenderMenuItemBackground(ToolStripItemRenderEventArgs e)
    {
        if (e.Item.Selected || e.Item.Pressed)
        {
            using var brush = new SolidBrush(NexusTheme.Hover);
            e.Graphics.FillRectangle(brush, e.Item.ContentRectangle);
        }
        else
        {
            base.OnRenderMenuItemBackground(e);
        }
    }

    protected override void OnRenderItemText(ToolStripItemTextRenderEventArgs e)
    {
        if (!e.Item.Enabled)
            e.TextColor = NexusTheme.TextDisabled;
        else if (e.Item is ToolStripButton && (e.Item.Selected || e.Item.Pressed))
            e.TextColor = NexusTheme.BackgroundDark;  // Dark text on cyan hover
        else
            e.TextColor = NexusTheme.TextPrimary;
        base.OnRenderItemText(e);
    }

    protected override void OnRenderButtonBackground(ToolStripItemRenderEventArgs e)
    {
        if (e.Item is ToolStripButton btn)
        {
            var bounds = new Rectangle(Point.Empty, e.Item.Size);
            Color bgColor;

            if (btn.Pressed)
                bgColor = NexusTheme.AccentDark;
            else if (btn.Selected)
                bgColor = NexusTheme.Accent;
            else
                bgColor = btn.BackColor;

            using var brush = new SolidBrush(bgColor);
            e.Graphics.FillRectangle(brush, bounds);
        }
        else
        {
            base.OnRenderButtonBackground(e);
        }
    }
}

/// <summary>
/// Custom renderer for tab bar ToolStrip that respects individual button BackColor.
/// </summary>
public class NexusTabBarRenderer : ToolStripProfessionalRenderer
{
    public NexusTabBarRenderer() : base(new NexusTabBarColorTable()) { }

    protected override void OnRenderButtonBackground(ToolStripItemRenderEventArgs e)
    {
        if (e.Item is ToolStripButton btn)
        {
            var bounds = new Rectangle(Point.Empty, e.Item.Size);
            using var brush = new SolidBrush(btn.BackColor);
            e.Graphics.FillRectangle(brush, bounds);
        }
        else
        {
            base.OnRenderButtonBackground(e);
        }
    }

    protected override void OnRenderToolStripBackground(ToolStripRenderEventArgs e)
    {
        using var brush = new SolidBrush(NexusTheme.BackgroundDark);
        e.Graphics.FillRectangle(brush, e.AffectedBounds);
    }

    protected override void OnRenderToolStripBorder(ToolStripRenderEventArgs e)
    {
        // No border for tab bar
    }

    protected override void OnRenderItemBackground(ToolStripItemRenderEventArgs e)
    {
        // No default item background
    }

    protected override void OnRenderSeparator(ToolStripSeparatorRenderEventArgs e)
    {
        // No separators
    }
}

/// <summary>
/// Color table for tab bar - removes all borders.
/// </summary>
public class NexusTabBarColorTable : ProfessionalColorTable
{
    public override Color ToolStripBorder => NexusTheme.BackgroundDark;
    public override Color ToolStripGradientBegin => NexusTheme.BackgroundDark;
    public override Color ToolStripGradientEnd => NexusTheme.BackgroundDark;
    public override Color ToolStripGradientMiddle => NexusTheme.BackgroundDark;
    public override Color MenuBorder => NexusTheme.BackgroundDark;
    public override Color MenuItemBorder => NexusTheme.BackgroundDark;
    public override Color ButtonSelectedBorder => NexusTheme.BackgroundDark;
    public override Color ButtonPressedBorder => NexusTheme.BackgroundDark;
    public override Color ButtonCheckedHighlightBorder => NexusTheme.BackgroundDark;
    public override Color ButtonSelectedHighlightBorder => NexusTheme.BackgroundDark;
}

/// <summary>
/// Color table for menu/toolbar rendering.
/// </summary>
public class NexusColorTable : ProfessionalColorTable
{
    // Menu colors
    public override Color MenuBorder => NexusTheme.Border;
    public override Color MenuItemBorder => NexusTheme.Border;
    public override Color MenuItemSelected => NexusTheme.Hover;
    public override Color MenuItemSelectedGradientBegin => NexusTheme.Hover;
    public override Color MenuItemSelectedGradientEnd => NexusTheme.Hover;
    public override Color MenuItemPressedGradientBegin => NexusTheme.Pressed;
    public override Color MenuItemPressedGradientEnd => NexusTheme.Pressed;
    public override Color MenuStripGradientBegin => NexusTheme.BackgroundHeader;
    public override Color MenuStripGradientEnd => NexusTheme.BackgroundHeader;

    // Dropdown/popup colors
    public override Color ToolStripDropDownBackground => NexusTheme.BackgroundElevated;
    public override Color ImageMarginGradientBegin => NexusTheme.BackgroundElevated;
    public override Color ImageMarginGradientMiddle => NexusTheme.BackgroundElevated;
    public override Color ImageMarginGradientEnd => NexusTheme.BackgroundElevated;

    // Separator colors
    public override Color SeparatorDark => NexusTheme.Separator;
    public override Color SeparatorLight => NexusTheme.Separator;

    // ToolStrip/StatusStrip colors
    public override Color StatusStripGradientBegin => NexusTheme.BackgroundHeader;
    public override Color StatusStripGradientEnd => NexusTheme.BackgroundHeader;
    public override Color ToolStripGradientBegin => NexusTheme.BackgroundHeader;
    public override Color ToolStripGradientEnd => NexusTheme.BackgroundHeader;
    public override Color ToolStripGradientMiddle => NexusTheme.BackgroundHeader;
    public override Color ToolStripBorder => NexusTheme.BackgroundHeader; // Hide border by matching background

    // Content panel colors (eliminate white lines)
    public override Color ToolStripContentPanelGradientBegin => NexusTheme.BackgroundHeader;
    public override Color ToolStripContentPanelGradientEnd => NexusTheme.BackgroundHeader;
    public override Color ToolStripPanelGradientBegin => NexusTheme.BackgroundHeader;
    public override Color ToolStripPanelGradientEnd => NexusTheme.BackgroundHeader;

    // Button colors
    public override Color ButtonSelectedBorder => NexusTheme.Border;
    public override Color ButtonPressedBorder => NexusTheme.Border;
    public override Color ButtonCheckedHighlightBorder => NexusTheme.Border;
    public override Color ButtonSelectedHighlightBorder => NexusTheme.Border;
    public override Color ButtonSelectedGradientBegin => NexusTheme.Hover;
    public override Color ButtonSelectedGradientEnd => NexusTheme.Hover;
    public override Color ButtonSelectedGradientMiddle => NexusTheme.Hover;
    public override Color ButtonPressedGradientBegin => NexusTheme.Pressed;
    public override Color ButtonPressedGradientEnd => NexusTheme.Pressed;
    public override Color ButtonPressedGradientMiddle => NexusTheme.Pressed;
    public override Color ButtonCheckedGradientBegin => NexusTheme.Hover;
    public override Color ButtonCheckedGradientEnd => NexusTheme.Hover;
    public override Color ButtonCheckedGradientMiddle => NexusTheme.Hover;

    // Check/checkbox colors
    public override Color CheckBackground => NexusTheme.BackgroundControl;
    public override Color CheckPressedBackground => NexusTheme.Pressed;
    public override Color CheckSelectedBackground => NexusTheme.Hover;

    // Grip (resize handle) colors
    public override Color GripDark => NexusTheme.Separator;
    public override Color GripLight => NexusTheme.BackgroundHeader;

    // Overflow button colors
    public override Color OverflowButtonGradientBegin => NexusTheme.BackgroundHeader;
    public override Color OverflowButtonGradientEnd => NexusTheme.BackgroundHeader;
    public override Color OverflowButtonGradientMiddle => NexusTheme.BackgroundHeader;

    // Rafting container colors
    public override Color RaftingContainerGradientBegin => NexusTheme.BackgroundHeader;
    public override Color RaftingContainerGradientEnd => NexusTheme.BackgroundHeader;
}

/// <summary>
/// Button subclass that suppresses the dotted focus rectangle.
/// </summary>
public class NexusButton : Button
{
    protected override bool ShowFocusCues => false;
}

/// <summary>
/// ToolStrip subclass that removes the bottom border line.
/// </summary>
public class BorderlessToolStrip : ToolStrip
{
    private const int WM_NCPAINT = 0x85;

    public BorderlessToolStrip()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint, true);
    }

    protected override void WndProc(ref Message m)
    {
        // Suppress non-client area painting (border)
        if (m.Msg == WM_NCPAINT)
            return;

        base.WndProc(ref m);
    }

    protected override void OnPaintBackground(PaintEventArgs e)
    {
        // Fill with background color, no border
        using var brush = new SolidBrush(BackColor);
        e.Graphics.FillRectangle(brush, ClientRectangle);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        // Fill background first
        using var brush = new SolidBrush(BackColor);
        e.Graphics.FillRectangle(brush, ClientRectangle);

        // Then let items paint
        base.OnPaint(e);
    }
}
