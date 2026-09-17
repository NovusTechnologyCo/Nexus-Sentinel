// <file>
// <summary>
// First-run elevation preference dialog for Administrator or User mode choice.
// </summary>
// </file>
using Nexus.UI.Helpers;
using Nexus.UI.Styles;

namespace Nexus.UI.Forms;

/// <summary>
/// Dialog shown on first launch to choose elevation preference.
/// </summary>
public class ElevationPromptForm : Form
{
    private readonly CheckBox _rememberChoice;
    private ElevationPreference _selectedPreference = ElevationPreference.User;

    /// <summary>
    /// The user's selected elevation preference.
    /// </summary>
    public ElevationPreference SelectedPreference => _selectedPreference;

    /// <summary>
    /// Whether the user wants to remember their choice.
    /// </summary>
    public bool RememberChoice => _rememberChoice.Checked;

    public ElevationPromptForm()
    {
        // Form settings
        Text = "Nexus Sentinel";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        StartPosition = FormStartPosition.CenterScreen;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = true;
        ClientSize = new Size(450, 380);
        BackColor = NexusTheme.BackgroundDark;

        // Apply application icon
        if (NexusTheme.AppIcon != null)
            Icon = NexusTheme.AppIcon;

        // Shield icon or app icon area
        var iconPanel = new Panel
        {
            Location = new Point(20, 20),
            Size = new Size(64, 64),
            BackColor = NexusTheme.BackgroundPanel
        };

        // Draw shield icon
        iconPanel.Paint += (s, e) =>
        {
            var g = e.Graphics;
            g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;

            // Shield shape
            var shieldPath = new System.Drawing.Drawing2D.GraphicsPath();
            shieldPath.AddArc(8, 8, 16, 16, 180, 90);
            shieldPath.AddArc(40, 8, 16, 16, 270, 90);
            shieldPath.AddLine(56, 16, 56, 36);
            shieldPath.AddLine(56, 36, 32, 56);
            shieldPath.AddLine(32, 56, 8, 36);
            shieldPath.AddLine(8, 36, 8, 16);
            shieldPath.CloseFigure();

            using var brush = new SolidBrush(NexusTheme.Accent);
            g.FillPath(brush, shieldPath);

            // Checkmark or admin icon inside
            using var pen = new Pen(NexusTheme.BackgroundDark, 3);
            g.DrawLine(pen, 22, 32, 28, 40);
            g.DrawLine(pen, 28, 40, 42, 24);
        };

        // Title
        var titleLabel = new Label
        {
            Text = "Administrator Privileges",
            Location = new Point(100, 20),
            Size = new Size(330, 33),
            Font = new Font(NexusTheme.FontFamily, 14f, FontStyle.Bold),
            ForeColor = NexusTheme.TextPrimary
        };

        // Description
        var descLabel = new Label
        {
            Text = "Some features in Nexus Sentinel require administrator privileges to function properly:\n\n" +
                   "• ETW system-wide process monitoring\n" +
                   "• Debugging protected processes\n" +
                   "• Reading memory of elevated applications\n\n" +
                   "How would you like to run Nexus Sentinel?",
            Location = new Point(100, 58),
            Size = new Size(330, 130),
            ForeColor = NexusTheme.TextSecondary
        };

        // Remember choice checkbox
        _rememberChoice = new CheckBox
        {
            Text = "Remember my choice",
            Location = new Point(100, 250),
            AutoSize = true,
            ForeColor = NexusTheme.TextPrimary,
            Checked = true
        };

        // Buttons - double height for better visibility
        var btnAdmin = new NexusButton
        {
            Text = "Run as Administrator",
            Location = new Point(100, 295)
        };
        NexusTheme.StylePrimaryButton(btnAdmin);
        btnAdmin.Size = new Size(160, 64); // Override after styling
        btnAdmin.Click += (s, e) =>
        {
            _selectedPreference = ElevationPreference.Administrator;
            DialogResult = DialogResult.OK;
            Close();
        };

        var btnUser = new NexusButton
        {
            Text = "Run as User",
            Location = new Point(270, 295)
        };
        NexusTheme.StyleButton(btnUser);
        btnUser.Size = new Size(120, 64); // Override after styling
        btnUser.Click += (s, e) =>
        {
            _selectedPreference = ElevationPreference.User;
            DialogResult = DialogResult.OK;
            Close();
        };

        Controls.AddRange([iconPanel, titleLabel, descLabel, _rememberChoice, btnAdmin, btnUser]);

        // Apply theme
        NexusTheme.ApplyDarkTitleBar(this);
    }

    protected override void OnShown(EventArgs e)
    {
        base.OnShown(e);
        // Focus on the Admin button as the primary action
        Controls.OfType<Button>().FirstOrDefault()?.Focus();
    }
}
