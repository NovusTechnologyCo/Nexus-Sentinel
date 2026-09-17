// <file>
// <summary>
// Simple find dialog for searching text or byte patterns in the viewer.
// </summary>
// </file>
using System.ComponentModel;
using Nexus.UI.Helpers;
using Nexus.UI.Styles;


namespace Nexus.UI.Forms;

/// <summary>
/// Search direction.
/// </summary>
public enum FindDirection
{
    Up,
    Down
}

/// <summary>
/// Simple find dialog for searching text in editors and lists.
/// </summary>
public partial class FindDialogForm : Form
{
    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public string FindText
    {
        get => txtFind.Text;
        set => txtFind.Text = value;
    }

    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public string Description
    {
        get => lblDescription.Text;
        set => lblDescription.Text = value;
    }

    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public FindDirection Direction
    {
        get => rbDown.Checked ? FindDirection.Down : FindDirection.Up;
        set
        {
            if (value == FindDirection.Down)
                rbDown.Checked = true;
            else
                rbUp.Checked = true;
        }
    }

    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public bool CaseSensitive
    {
        get => chkCaseSensitive.Checked;
        set => chkCaseSensitive.Checked = value;
    }

    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public bool ShowDirection
    {
        get => gbDirection.Visible;
        set => gbDirection.Visible = value;
    }

    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public bool ShowCaseSensitive
    {
        get => chkCaseSensitive.Visible;
        set => chkCaseSensitive.Visible = value;
    }

    public FindDialogForm()
    {
        InitializeComponent();
        NexusTheme.StyleForm(this);
    }

    private void InitializeComponent()
    {
        Text = "Find";
        Size = new Size(350, 260);
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        Padding = new Padding(NexusTheme.Space16, NexusTheme.Space8, NexusTheme.Space16, NexusTheme.Space8);

        int y = NexusTheme.Space8;

        // Description label
        lblDescription = new Label
        {
            Text = "Find what:",
            Location = new Point(NexusTheme.Space16, y),
            AutoSize = true
        };

        y += 32;

        // Find text
        txtFind = new TextBox
        {
            Location = new Point(NexusTheme.Space16, y),
            Width = 300
        };

        y += 37;

        // Direction group
        gbDirection = new GroupBox
        {
            Text = "Direction",
            Location = new Point(NexusTheme.Space16, y),
            Size = new Size(155, 58)
        };

        rbUp = new RadioButton
        {
            Text = "Up",
            Location = new Point(12, 25),
            AutoSize = true
        };

        rbDown = new RadioButton
        {
            Text = "Down",
            Location = new Point(70, 25),
            AutoSize = true,
            Checked = true
        };

        gbDirection.Controls.AddRange([rbUp, rbDown]);

        // Case sensitive - vertically centered with groupbox
        chkCaseSensitive = new CheckBox
        {
            Text = "Case sensitive",
            Location = new Point(180, y + 23),
            AutoSize = true
        };

        y += 72;

        // Buttons - right aligned (16px from right edge)
        int buttonX = 310 - NexusTheme.ButtonWidth;
        btnCancel = new Button
        {
            Text = "Close",
            Size = new Size(NexusTheme.ButtonWidth, NexusTheme.ControlHeight),
            Location = new Point(buttonX, y),
            DialogResult = DialogResult.Cancel
        };
        btnCancel.Click += (s, e) => Close();

        buttonX -= NexusTheme.ButtonWidth + NexusTheme.Space8;
        btnFind = new Button
        {
            Text = "Find",
            Size = new Size(NexusTheme.ButtonWidth, NexusTheme.ControlHeight),
            Location = new Point(buttonX, y),
            DialogResult = DialogResult.OK
        };

        AcceptButton = btnFind;
        CancelButton = btnCancel;

        Controls.AddRange([lblDescription, txtFind, gbDirection, chkCaseSensitive, btnFind, btnCancel]);
    }

    /// <summary>
    /// Executes the find dialog.
    /// </summary>
    public bool Execute()
    {
        return ShowDialog() == DialogResult.OK;
    }

    /// <summary>
    /// Shows the find dialog and returns the search text if OK was clicked.
    /// </summary>
    public static string? ShowFind(IWin32Window? owner, string? initialText = null,
        bool showDirection = true, bool showCaseSensitive = true)
    {
        using var form = new FindDialogForm
        {
            FindText = initialText ?? "",
            ShowDirection = showDirection,
            ShowCaseSensitive = showCaseSensitive
        };

        if (form.ShowDialog(owner) == DialogResult.OK)
        {
            return form.FindText;
        }
        return null;
    }

    // Controls
    private Label lblDescription = null!;
    private TextBox txtFind = null!;
    private GroupBox gbDirection = null!;
    private RadioButton rbUp = null!;
    private RadioButton rbDown = null!;
    private CheckBox chkCaseSensitive = null!;
    private Button btnFind = null!;
    private Button btnCancel = null!;
}
