// <file>
// <summary>
// Centralized UI theme definition for Nexus Sentinel. Provides color constants, spacing
// values, font definitions, and control styling methods for a consistent visual identity
// across all forms and panels. Supports dark mode (default) and light mode with automatic
// Windows system preference detection. Accent color is cyan/electric blue to match the
// shield logo aesthetic.
// </summary>
// </file>

using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace Nexus.UI.Styles;

/// <summary>
/// Theme mode enumeration.
/// </summary>
public enum ThemeMode
{
    Dark,
    Light,
    System  // Auto-detect from Windows settings
}

/// <summary>
/// Nexus Sentinel UI Theme - Cyan/Electric Blue accent
/// Based on the shield logo aesthetic: tech, security, precision
/// Supports both dark and light modes with Windows system detection.
/// </summary>
public static partial class NexusTheme
{
    private static ThemeMode _currentMode = ThemeMode.System;
    private static bool _isDarkMode = true;

    /// <summary>
    /// Current theme mode setting.
    /// </summary>
    public static ThemeMode Mode
    {
        get => _currentMode;
        set
        {
            _currentMode = value;
            _isDarkMode = value switch
            {
                ThemeMode.Dark => true,
                ThemeMode.Light => false,
                ThemeMode.System => DetectSystemDarkMode(),
                _ => true
            };
        }
    }

    /// <summary>
    /// Whether currently using dark mode colors.
    /// </summary>
    public static bool IsDarkMode => _isDarkMode;

    /// <summary>
    /// Cached application icon for all forms.
    /// </summary>
    private static Icon? _appIcon;

    /// <summary>
    /// Gets the application icon (loaded from embedded resource).
    /// </summary>
    public static Icon? AppIcon
    {
        get
        {
            if (_appIcon == null)
            {
                try
                {
                    var assembly = System.Reflection.Assembly.GetExecutingAssembly();
                    using var stream = assembly.GetManifestResourceStream("Nexus.UI.Resources.logo.ico");
                    if (stream != null)
                    {
                        _appIcon = new Icon(stream);
                    }
                }
                catch
                {
                    // Fallback - no icon if resource not found
                }
            }
            return _appIcon;
        }
    }

    /// <summary>
    /// Initialize theme based on system settings.
    /// </summary>
    static NexusTheme()
    {
        _isDarkMode = DetectSystemDarkMode();
    }

    /// <summary>
    /// Detect Windows dark mode setting from registry.
    /// </summary>
    public static bool DetectSystemDarkMode()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            var value = key?.GetValue("AppsUseLightTheme");
            if (value is int intValue)
            {
                return intValue == 0; // 0 = dark mode, 1 = light mode
            }
        }
        catch
        {
            // Default to dark mode if detection fails
        }
        return true;
    }

    // Windows dark mode API
    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);

    private const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;

    /// <summary>
    /// Apply dark mode to the window title bar.
    /// </summary>
    public static void ApplyDarkTitleBar(Form form)
    {
        try
        {
            var useDark = _isDarkMode ? 1 : 0;
            DwmSetWindowAttribute(form.Handle, DWMWA_USE_IMMERSIVE_DARK_MODE, ref useDark, sizeof(int));
        }
        catch
        {
            // Ignore if API not available
        }
    }

    #region Color Palette

    // === PRIMARY COLORS (from logo - same in both modes) ===

    /// <summary>Primary accent - Electric cyan from the eye/glow</summary>
    public static Color Accent => Color.FromArgb(0, 200, 255);         // #00C8FF

    /// <summary>Accent hover/bright state</summary>
    public static Color AccentLight => Color.FromArgb(80, 220, 255);   // #50DCFF

    /// <summary>Accent pressed/dark state</summary>
    public static Color AccentDark => Color.FromArgb(0, 150, 200);     // #0096C8

    /// <summary>Secondary accent - Teal undertone</summary>
    public static Color AccentSecondary => Color.FromArgb(0, 180, 200); // #00B4C8

    // === BACKGROUND COLORS (theme-dependent) ===

    /// <summary>Main window background</summary>
    public static Color BackgroundDark => _isDarkMode
        ? Color.FromArgb(18, 18, 22)    // #121216 - Near black
        : Color.FromArgb(245, 245, 248); // #F5F5F8 - Off-white

    /// <summary>Panel/container background</summary>
    public static Color BackgroundPanel => _isDarkMode
        ? Color.FromArgb(28, 28, 34)    // #1C1C22
        : Color.FromArgb(255, 255, 255); // #FFFFFF - White

    /// <summary>Control background (textbox, listview)</summary>
    public static Color BackgroundControl => _isDarkMode
        ? Color.FromArgb(35, 35, 42)    // #23232A
        : Color.FromArgb(255, 255, 255); // #FFFFFF

    /// <summary>Elevated surface (popups, tooltips)</summary>
    public static Color BackgroundElevated => _isDarkMode
        ? Color.FromArgb(45, 45, 52)    // #2D2D34
        : Color.FromArgb(250, 250, 252); // #FAFAFC

    /// <summary>Header/toolbar background</summary>
    public static Color BackgroundHeader => _isDarkMode
        ? Color.FromArgb(22, 22, 28)    // #16161C
        : Color.FromArgb(240, 240, 244); // #F0F0F4

    // === TEXT COLORS (theme-dependent) ===

    /// <summary>Primary text</summary>
    public static Color TextPrimary => _isDarkMode
        ? Color.FromArgb(240, 240, 245) // #F0F0F5 - White
        : Color.FromArgb(20, 20, 25);    // #141419 - Near black

    /// <summary>Secondary text</summary>
    public static Color TextSecondary => _isDarkMode
        ? Color.FromArgb(180, 180, 190) // #B4B4BE
        : Color.FromArgb(100, 100, 110); // #64646E

    /// <summary>Disabled/hint text</summary>
    public static Color TextDisabled => _isDarkMode
        ? Color.FromArgb(100, 100, 110) // #64646E
        : Color.FromArgb(160, 160, 170); // #A0A0AA

    /// <summary>Text on accent background</summary>
    public static Color TextOnAccent => Color.FromArgb(10, 10, 15);    // #0A0A0F - Always dark

    // === BORDER COLORS (theme-dependent) ===

    /// <summary>Subtle border for controls</summary>
    public static Color Border => _isDarkMode
        ? Color.FromArgb(55, 55, 65)    // #373741
        : Color.FromArgb(210, 210, 215); // #D2D2D7

    /// <summary>Focused/active border</summary>
    public static Color BorderFocused => Accent;

    /// <summary>Separator lines</summary>
    public static Color Separator => _isDarkMode
        ? Color.FromArgb(45, 45, 55)    // #2D2D37
        : Color.FromArgb(225, 225, 230); // #E1E1E6

    // === STATUS COLORS (same in both modes) ===

    /// <summary>Success/active - Green with cyan tint</summary>
    public static Color Success => Color.FromArgb(40, 200, 120);       // #28C878

    /// <summary>Warning - Amber</summary>
    public static Color Warning => Color.FromArgb(255, 180, 50);       // #FFB432

    /// <summary>Error/danger - Red</summary>
    public static Color Error => Color.FromArgb(255, 80, 80);          // #FF5050

    /// <summary>Info - Use accent</summary>
    public static Color Info => Accent;

    // === SELECTION/HIGHLIGHT (theme-dependent) ===

    /// <summary>Selected row background</summary>
    public static Color Selection => _isDarkMode
        ? Color.FromArgb(0, 120, 160)   // #0078A0
        : Color.FromArgb(0, 180, 230);   // #00B4E6

    /// <summary>Hover highlight</summary>
    public static Color Hover => _isDarkMode
        ? Color.FromArgb(50, 60, 75)    // #323C4B - Visible hover with blue tint
        : Color.FromArgb(230, 240, 250); // #E6F0FA

    /// <summary>Active/pressed state</summary>
    public static Color Pressed => _isDarkMode
        ? Color.FromArgb(0, 100, 140)   // #00648C
        : Color.FromArgb(0, 150, 200);   // #0096C8

    #endregion

    #region Typography

    /// <summary>Primary UI font</summary>
    public static string FontFamily => "Segoe UI";

    /// <summary>Monospace font for code/hex/addresses</summary>
    public static string FontFamilyMono => "Cascadia Mono";

    /// <summary>Fallback monospace if Cascadia not available</summary>
    public static string FontFamilyMonoFallback => "Consolas";

    // Font Sizes
    public static float FontSizeSmall => 8f;
    public static float FontSizeBody => 9f;
    public static float FontSizeMedium => 10f;
    public static float FontSizeLarge => 12f;
    public static float FontSizeHeader => 14f;
    public static float FontSizeTitle => 16f;

    // Pre-built fonts (create once, reuse)
    private static Font? _fontBody;
    private static Font? _fontMono;
    private static Font? _fontHeader;
    private static Font? _fontSmall;

    public static Font FontBody => _fontBody ??= new Font(FontFamily, FontSizeBody);
    public static Font FontMono => _fontMono ??= CreateMonoFont(FontSizeBody);
    public static Font FontHeader => _fontHeader ??= new Font(FontFamily, FontSizeHeader, FontStyle.Bold);
    public static Font FontSmall => _fontSmall ??= new Font(FontFamily, FontSizeSmall);

    private static Font CreateMonoFont(float size)
    {
        try
        {
            return new Font(FontFamilyMono, size);
        }
        catch
        {
            return new Font(FontFamilyMonoFallback, size);
        }
    }

    #endregion

    #region Spacing & Sizing

    // =====================================================
    // STRICT SPACING STANDARDS - USE ONLY THESE VALUES
    // =====================================================

    /// <summary>Small spacing - 4px (between related controls)</summary>
    public const int Space4 = 4;

    /// <summary>Medium spacing - 8px (standard gap, panel padding)</summary>
    public const int Space8 = 8;

    /// <summary>Large spacing - 16px (between sections/groups)</summary>
    public const int Space16 = 16;

    /// <summary>Panel padding - 8px on all sides</summary>
    public static readonly Padding PanelPadding = new(Space8);

    /// <summary>Form padding - 16px on all sides (standard form margin)</summary>
    public static readonly Padding FormPadding = new(Space16);

    // Legacy aliases (prefer Space4/Space8/Space16/Space20)
    public const int SpaceXS = Space4;
    public const int SpaceSM = Space4;
    public const int SpaceMD = Space8;
    public const int SpaceLG = Space16;
    public const int SpaceXL = Space16;
    public const int SpaceSection = Space16;

    // =====================================================
    // CONTROL SIZES - ALL BASED ON 32px BUTTON HEIGHT
    // =====================================================

    /// <summary>Standard control height (buttons, textboxes, combos)</summary>
    public const int ControlHeight = 32;

    /// <summary>Standard button height - 32px</summary>
    public const int ButtonHeight = ControlHeight;

    /// <summary>Standard button width - 88px (fits ~10 chars)</summary>
    public const int ButtonWidth = 88;

    /// <summary>Wide button width - 120px (fits ~14 chars)</summary>
    public const int ButtonWidthWide = 120;

    /// <summary>Standard textbox height - matches buttons</summary>
    public const int TextBoxHeight = ControlHeight;

    /// <summary>ComboBox height - matches buttons</summary>
    public const int ComboBoxHeight = ControlHeight;

    /// <summary>ListView row height - 24px</summary>
    public const int ListRowHeight = 24;

    /// <summary>TreeView row height - 24px</summary>
    public const int TreeRowHeight = 24;

    /// <summary>Toolbar height - 40px (button + padding)</summary>
    public const int ToolbarHeight = ControlHeight + Space8;

    /// <summary>Status bar height - 24px</summary>
    public const int StatusBarHeight = 24;

    // Deprecated - use ButtonWidth instead
    public const int ButtonMinWidth = ButtonWidth;
    public const int ButtonHeightCompact = ControlHeight;

    // === PANEL/FORM SIZES ===

    /// <summary>Minimum panel width</summary>
    public const int PanelMinWidth = 250;

    /// <summary>Default panel width</summary>
    public const int PanelDefaultWidth = 350;

    /// <summary>Side panel width (process list, etc)</summary>
    public const int SidePanelWidth = 280;

    // === BORDERS ===

    /// <summary>Standard border width</summary>
    public const int BorderWidth = 1;

    /// <summary>Control border radius (for custom painting)</summary>
    public const int BorderRadius = 3;

    #endregion
}
