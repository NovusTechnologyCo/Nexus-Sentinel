// <file>
// <summary>
// Watch list entry dialog for adding a new address to saved addresses.
// </summary>
// </file>
using Nexus.UI.Helpers;
using Nexus.UI.Styles;


namespace Nexus.UI.Forms;

/// <summary>
/// Watch entry type.
/// </summary>
public enum WatchEntryType
{
    Byte,
    TwoBytes,
    FourBytes,
    EightBytes,
    Float,
    Double,
    String
}

/// <summary>
/// Dialog to add a new entry to the watch list.
/// </summary>
public partial class WatchListAddEntryForm : Form
{
    private readonly RadioButton[] _typeRadioButtons = new RadioButton[7];

    public string Expression => txtExpression.Text;

    public WatchEntryType EntryType
    {
        get
        {
            for (int i = 0; i < _typeRadioButtons.Length; i++)
            {
                if (_typeRadioButtons[i].Checked)
                    return (WatchEntryType)i;
            }
            return WatchEntryType.Byte;
        }
    }

    public WatchListAddEntryForm()
    {
        InitializeComponent();
        NexusTheme.StyleForm(this);
    }

    private void InitializeComponent()
    {
        Text = "Add watch entry";
        Size = new Size(420, 230);
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;

        // Expression input
        lblExpression = new Label
        {
            Text = "Expression:",
            Location = new Point(10, 15),
            AutoSize = true
        };

        txtExpression = new TextBox
        {
            Location = new Point(105, 12),
            Width = 290
        };

        // Type selection
        rgType = new GroupBox
        {
            Text = "Type",
            Location = new Point(10, 45),
            Size = new Size(385, 80)
        };

        _typeRadioButtons[0] = new RadioButton { Text = "Byte", Location = new Point(15, 25), AutoSize = true, Checked = true };
        _typeRadioButtons[1] = new RadioButton { Text = "2 Byte", Location = new Point(95, 25), AutoSize = true };
        _typeRadioButtons[2] = new RadioButton { Text = "4 Byte", Location = new Point(185, 25), AutoSize = true };
        _typeRadioButtons[3] = new RadioButton { Text = "8 Byte", Location = new Point(275, 25), AutoSize = true };
        _typeRadioButtons[4] = new RadioButton { Text = "Float", Location = new Point(15, 50), AutoSize = true };
        _typeRadioButtons[5] = new RadioButton { Text = "Double", Location = new Point(95, 50), AutoSize = true };
        _typeRadioButtons[6] = new RadioButton { Text = "String", Location = new Point(195, 50), AutoSize = true };

        rgType.Controls.AddRange(_typeRadioButtons);

        // Buttons
        btnOk = new Button
        {
            Text = "OK",
            Size = new Size(80, 32),
            Location = new Point(220, 145),
            DialogResult = DialogResult.OK
        };
        btnOk.Click += (s, e) => Close();

        btnCancel = new Button
        {
            Text = "Cancel",
            Size = new Size(80, 32),
            Location = new Point(310, 145),
            DialogResult = DialogResult.Cancel
        };
        btnCancel.Click += (s, e) => Close();

        AcceptButton = btnOk;
        CancelButton = btnCancel;

        Controls.AddRange([lblExpression, txtExpression, rgType, btnOk, btnCancel]);
    }

    protected override void OnShown(EventArgs e)
    {
        base.OnShown(e);
        txtExpression.Focus();
    }

    /// <summary>
    /// Shows the add watch entry dialog.
    /// </summary>
    public static (string expression, WatchEntryType type)? ShowAddEntry(IWin32Window? owner)
    {
        using var form = new WatchListAddEntryForm();
        if (form.ShowDialog(owner) == DialogResult.OK && !string.IsNullOrWhiteSpace(form.Expression))
        {
            return (form.Expression, form.EntryType);
        }
        return null;
    }

    // Controls
    private Label lblExpression = null!;
    private TextBox txtExpression = null!;
    private GroupBox rgType = null!;
    private Button btnOk = null!;
    private Button btnCancel = null!;
}
