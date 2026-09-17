// NexusTheme.Dialogs.cs - Dialog layout helpers, form styling, and recursive control styling
// Split from NexusTheme.cs for maintainability

namespace Nexus.UI.Styles;

public static partial class NexusTheme
{
    #region Dialog Layout Helpers

    /// <summary>Standard gap between buttons in dialogs.</summary>
    public static int ButtonGap => 8;

    /// <summary>Standard margin from form edge to content (16px).</summary>
    public const int FormMargin = Space16;

    /// <summary>Standard padding for dialog forms (16px).</summary>
    public static int DialogPadding => Space16;

    /// <summary>Standard gap between form rows.</summary>
    public static int FormRowGap => 8;

    /// <summary>Standard width for labels in forms.</summary>
    public static int LabelWidth => 80;

    /// <summary>Gets the content width for a dialog (excluding padding).</summary>
    public static int GetDialogContentWidth(int formWidth) => formWidth - (DialogPadding * 2);

    /// <summary>Style a dialog form with Nexus theme.</summary>
    public static void StyleDialog(Form form)
    {
        form.BackColor = BackgroundPanel;
        form.ForeColor = TextPrimary;
        form.Font = FontBody;
    }

    /// <summary>
    /// Apply ShellForm's dark theme to a form and all its controls.
    /// This is the standard styling for all Nexus forms.
    /// Also sets ShowInTaskbar based on user preference (default: child windows hidden).
    /// </summary>
    public static void StyleForm(Form form)
    {
        form.BackColor = BackgroundDark;
        form.ForeColor = TextPrimary;
        form.Font = FontBody;

        // Apply application icon
        if (AppIcon != null)
        {
            form.Icon = AppIcon;
        }

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

        // Set ShowInTaskbar based on setting (only for child forms, not the main shell)
        // Child forms have StartPosition = CenterParent or have an Owner
        if (form.StartPosition == FormStartPosition.CenterParent)
        {
            form.ShowInTaskbar = NexusSettings.Instance.ShowAllWindowsInTaskbar;
        }

        // Ensure child forms center properly when shown
        // Skip FormReviewerForm which has its own positioning logic
        if (form.GetType().Name != "FormReviewerForm")
        {
            form.Load += (s, e) =>
            {
                try
                {
                    // Find the parent form to center on
                    Form? parent = form.Owner;
                    if (parent == null)
                    {
                        // Try to find the main shell or active form
                        parent = Application.OpenForms.Cast<Form>()
                            .FirstOrDefault(f => f.GetType().Name == "ShellForm" && f.Visible);
                        if (parent == null)
                        {
                            parent = Form.ActiveForm;
                        }
                    }

                    if (parent != null && parent != form && !parent.IsDisposed)
                    {
                        // Center on parent
                        form.Location = new Point(
                            parent.Location.X + (parent.Width - form.Width) / 2,
                            parent.Location.Y + (parent.Height - form.Height) / 2
                        );
                    }
                    else
                    {
                        // Center on screen
                        var screen = Screen.FromControl(form);
                        form.Location = new Point(
                            screen.WorkingArea.X + (screen.WorkingArea.Width - form.Width) / 2,
                            screen.WorkingArea.Y + (screen.WorkingArea.Height - form.Height) / 2
                        );
                    }
                }
                catch
                {
                    // Silently ignore centering errors
                }
            };
        }

        // Recursively style all controls
        StyleControlsRecursive(form.Controls);
    }

    /// <summary>
    /// Recursively style all controls in a control collection.
    /// </summary>
    public static void StyleControlsRecursive(Control.ControlCollection controls)
    {
        foreach (Control control in controls)
        {
            StyleControl(control);

            // Recurse into child controls
            if (control.HasChildren)
            {
                StyleControlsRecursive(control.Controls);
            }
        }
    }

    /// <summary>
    /// Style a single control based on its type.
    /// </summary>
    public static void StyleControl(Control control)
    {
        switch (control)
        {
            case Button btn:
                StyleButton(btn);
                break;
            case TextBox txt:
                StyleTextBox(txt);
                break;
            case RichTextBox rtb:
                rtb.BackColor = BackgroundControl;
                rtb.ForeColor = TextPrimary;
                rtb.BorderStyle = BorderStyle.FixedSingle;
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
            case ComboBox cbo:
                StyleComboBox(cbo);
                break;
            case CheckBox chk:
                chk.ForeColor = TextPrimary;
                chk.BackColor = chk.Parent?.BackColor ?? BackgroundDark;
                break;
            case RadioButton rb:
                rb.ForeColor = TextPrimary;
                rb.BackColor = rb.Parent?.BackColor ?? BackgroundDark;
                break;
            case Label lbl:
                lbl.ForeColor = TextPrimary;
                break;
            case GroupBox gb:
                gb.ForeColor = TextPrimary;
                gb.BackColor = BackgroundDark;
                break;
            case Panel pnl:
                pnl.BackColor = BackgroundDark;
                break;
            case TabControl tc:
                StyleTabControl(tc);
                break;
            case NumericUpDown nud:
                nud.BackColor = BackgroundControl;
                nud.ForeColor = TextPrimary;
                break;
            case ProgressBar pb:
                StyleProgressBar(pb);
                break;
            case MenuStrip ms:
                StyleMenuStrip(ms);
                break;
            case StatusStrip ss:
                StyleStatusStrip(ss);
                break;
            case ToolStrip ts:
                StyleToolStrip(ts);
                break;
            case SplitContainer sc:
                sc.BackColor = BackgroundDark;
                break;
        }
    }

    /// <summary>Style a dialog form with Nexus theme and set size.</summary>
    public static void StyleDialog(Form form, int width, int height)
    {
        StyleDialog(form);
        form.ClientSize = new Size(width, height);
        form.FormBorderStyle = FormBorderStyle.FixedDialog;
        form.StartPosition = FormStartPosition.CenterParent;
        form.MaximizeBox = false;
        form.MinimizeBox = false;
    }

    /// <summary>Create OK and Cancel buttons for a dialog (using form width/height).</summary>
    public static (Button btnOk, Button btnCancel) CreateDialogButtons(int formWidth, int formHeight)
    {
        var contentWidth = GetDialogContentWidth(formWidth);
        var btnWidth = 80;
        var totalBtnWidth = btnWidth * 2 + ButtonGap;
        var startX = DialogPadding + (contentWidth - totalBtnWidth) / 2;
        var y = formHeight - 28 - DialogPadding;

        var btnOk = new Button
        {
            Text = "OK",
            Location = new Point(startX, y),
            Size = new Size(btnWidth, 28),
            DialogResult = DialogResult.OK
        };
        StylePrimaryButton(btnOk);

        var btnCancel = new Button
        {
            Text = "Cancel",
            Location = new Point(startX + btnWidth + ButtonGap, y),
            Size = new Size(btnWidth, 28),
            DialogResult = DialogResult.Cancel
        };
        StyleButton(btnCancel);

        return (btnOk, btnCancel);
    }

    /// <summary>Create OK and Cancel buttons for a dialog.</summary>
    public static (Button btnOk, Button btnCancel) CreateDialogButtons(Form form, int y)
    {
        var contentWidth = GetDialogContentWidth(form.ClientSize.Width);
        var btnWidth = 80;
        var totalBtnWidth = btnWidth * 2 + ButtonGap;
        var startX = DialogPadding + (contentWidth - totalBtnWidth) / 2;

        var btnOk = new Button
        {
            Text = "OK",
            Location = new Point(startX, y),
            Size = new Size(btnWidth, 28),
            DialogResult = DialogResult.OK
        };
        StylePrimaryButton(btnOk);

        var btnCancel = new Button
        {
            Text = "Cancel",
            Location = new Point(startX + btnWidth + ButtonGap, y),
            Size = new Size(btnWidth, 28),
            DialogResult = DialogResult.Cancel
        };
        StyleButton(btnCancel);

        form.AcceptButton = btnOk;
        form.CancelButton = btnCancel;

        return (btnOk, btnCancel);
    }

    #endregion
}
