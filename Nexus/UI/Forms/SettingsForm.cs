// <file>
// <summary>
// Main settings dialog with tabbed panels for General, Scan, Debugger, Extra options.
// </summary>
// </file>
using Nexus.UI.Helpers;
using Nexus.UI.Styles;

namespace Nexus.UI.Forms;

/// <summary>
/// Application settings dialog providing tabbed panels for General, Scan, Debugger, and Extra configuration.
/// </summary>
public partial class SettingsForm : Form
{
    // Settings panels
    private Panel pnlGeneral = null!;
    private Panel pnlScanSettings = null!;
    private Panel pnlHotkeys = null!;
    private Panel pnlDebugger = null!;
    private Panel pnlExtra = null!;

    // Change tracking
    private bool _hasChanges = false;
    private bool _isLoading = false;

    public SettingsForm()
    {
        InitializeComponent();
        CreateSettingsPanels();
        NexusTheme.StyleForm(this);  // Apply after panels are created
        LoadSettings();
        SetupChangeTracking();

        // Select first node
        if (tvCategories.Nodes.Count > 0)
        {
            tvCategories.SelectedNode = tvCategories.Nodes[0];
        }

        // Initially disable Apply button
        btnApply.Enabled = false;
    }

    private void SetHasChanges(bool value)
    {
        _hasChanges = value;
        btnApply.Enabled = value;
    }

    private void OnSettingChanged(object? sender, EventArgs e)
    {
        if (!_isLoading)
        {
            SetHasChanges(true);
        }
    }

    private void SetupChangeTracking()
    {
        // Hook up change events for all controls
        HookChangeEvents(pnlGeneral);
        HookChangeEvents(pnlScanSettings);
        HookChangeEvents(pnlHotkeys);
        HookChangeEvents(pnlDebugger);
        HookChangeEvents(pnlExtra);
    }

    private void HookChangeEvents(Control parent)
    {
        foreach (Control control in parent.Controls)
        {
            if (control is CheckBox chk)
            {
                chk.CheckedChanged += OnSettingChanged;
            }
            else if (control is TextBox txt)
            {
                txt.TextChanged += OnSettingChanged;
            }
            else if (control is ComboBox cbo)
            {
                cbo.SelectedIndexChanged += OnSettingChanged;
            }
            else if (control is NumericUpDown nud)
            {
                nud.ValueChanged += OnSettingChanged;
            }

            // Recurse into child controls
            if (control.HasChildren)
            {
                HookChangeEvents(control);
            }
        }
    }

    private void CreateSettingsPanels()
    {
        // Create all settings panels (hidden by default)
        pnlGeneral = CreateGeneralSettingsPanel();
        pnlScanSettings = CreateScanSettingsPanel();
        pnlHotkeys = CreateHotkeysPanel();
        pnlDebugger = CreateDebuggerPanel();
        pnlExtra = CreateExtraPanel();

        // Add all to container
        pnlContent.Controls.Add(pnlGeneral);
        pnlContent.Controls.Add(pnlScanSettings);
        pnlContent.Controls.Add(pnlHotkeys);
        pnlContent.Controls.Add(pnlDebugger);
        pnlContent.Controls.Add(pnlExtra);

        // Show first panel
        ShowPanel(pnlGeneral);
    }

    private void ShowPanel(Panel panel)
    {
        foreach (Control c in pnlContent.Controls)
        {
            if (c is Panel p)
                p.Visible = false;
        }
        panel.Visible = true;
        panel.BringToFront();
    }

    #region TreeView Selection

    private void TvCategories_AfterSelect(object? sender, TreeViewEventArgs e)
    {
        if (e.Node == null) return;

        switch (e.Node.Text)
        {
            case "General Settings":
                ShowPanel(pnlGeneral);
                break;
            case "Scan Settings":
                ShowPanel(pnlScanSettings);
                break;
            case "Hotkeys":
                ShowPanel(pnlHotkeys);
                break;
            case "Debugger Options":
                ShowPanel(pnlDebugger);
                break;
            case "Extra":
                ShowPanel(pnlExtra);
                break;
        }
    }

    #endregion
}

partial class SettingsForm
{
    private System.ComponentModel.IContainer? components = null;

    protected override void Dispose(bool disposing)
    {
        if (disposing && (components != null))
        {
            components.Dispose();
        }
        base.Dispose(disposing);
    }

    private void InitializeComponent()
    {
        this.tvCategories = new TreeView();
        this.pnlContent = new Panel();
        this.btnOK = new Button();
        this.btnCancel = new Button();
        this.btnApply = new Button();

        this.SuspendLayout();

        //
        // tvCategories
        //
        this.tvCategories.Dock = DockStyle.Left;
        this.tvCategories.Font = new Font(Font.FontFamily, 9.5f);
        this.tvCategories.HideSelection = false;
        this.tvCategories.Location = new Point(0, 0);
        this.tvCategories.Name = "tvCategories";
        this.tvCategories.Size = new Size(170, 455);
        this.tvCategories.TabIndex = 0;
        this.tvCategories.AfterSelect += new TreeViewEventHandler(this.TvCategories_AfterSelect);

        // Add category nodes
        this.tvCategories.Nodes.Add("General Settings");
        this.tvCategories.Nodes.Add("Scan Settings");
        this.tvCategories.Nodes.Add("Hotkeys");
        this.tvCategories.Nodes.Add("Debugger Options");
        this.tvCategories.Nodes.Add("Extra");

        //
        // pnlContent
        //
        this.pnlContent.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
        this.pnlContent.BorderStyle = BorderStyle.FixedSingle;
        this.pnlContent.Location = new Point(175, 0);
        this.pnlContent.Name = "pnlContent";
        this.pnlContent.Size = new Size(509, 455);
        this.pnlContent.TabIndex = 1;
        this.pnlContent.BackColor = NexusTheme.BackgroundPanel; // Lighter background for contrast

        //
        // btnOK
        //
        this.btnOK.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
        this.btnOK.Location = new Point(445, 465);
        this.btnOK.Name = "btnOK";
        this.btnOK.Size = new Size(NexusTheme.ButtonWidth, NexusTheme.ButtonHeight);
        this.btnOK.TabIndex = 2;
        this.btnOK.Text = "OK";
        this.btnOK.Click += new EventHandler(this.BtnOK_Click);
        NexusTheme.StylePrimaryButton(this.btnOK);

        //
        // btnCancel
        //
        this.btnCancel.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
        this.btnCancel.DialogResult = DialogResult.Cancel;
        this.btnCancel.Location = new Point(445 + NexusTheme.ButtonWidth + NexusTheme.ButtonGap, 465);
        this.btnCancel.Name = "btnCancel";
        this.btnCancel.Size = new Size(NexusTheme.ButtonWidth, NexusTheme.ButtonHeight);
        this.btnCancel.TabIndex = 3;
        this.btnCancel.Text = "Cancel";
        this.btnCancel.Click += new EventHandler(this.BtnCancel_Click);
        NexusTheme.StyleButton(this.btnCancel);

        //
        // btnApply
        //
        this.btnApply.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
        this.btnApply.Location = new Point(445 + (NexusTheme.ButtonWidth + NexusTheme.ButtonGap) * 2, 465);
        this.btnApply.Name = "btnApply";
        this.btnApply.Size = new Size(NexusTheme.ButtonWidth, NexusTheme.ButtonHeight);
        this.btnApply.TabIndex = 4;
        this.btnApply.Text = "Apply";
        this.btnApply.Click += new EventHandler(this.BtnApply_Click);
        NexusTheme.StyleButton(this.btnApply);

        //
        // SettingsForm
        //
        this.AcceptButton = this.btnOK;
        this.CancelButton = this.btnCancel;
        this.AutoScaleDimensions = new SizeF(7F, 15F);
        this.AutoScaleMode = AutoScaleMode.Font;
        this.ClientSize = new Size(694, 501);
        this.Controls.Add(this.tvCategories);
        this.Controls.Add(this.pnlContent);
        this.Controls.Add(this.btnOK);
        this.Controls.Add(this.btnCancel);
        this.Controls.Add(this.btnApply);
        this.MaximizeBox = false;
        this.MinimizeBox = false;
        this.MinimumSize = new Size(600, 450);
        this.Name = "SettingsForm";
        this.ShowIcon = false;
        this.ShowInTaskbar = false;
        this.StartPosition = FormStartPosition.CenterParent;
        this.Text = "Nexus Settings";

        this.ResumeLayout(false);
    }

    // Form controls
    private TreeView tvCategories = null!;
    private Panel pnlContent = null!;
    private Button btnOK = null!;
    private Button btnCancel = null!;
    private Button btnApply = null!;

    // General settings controls
    private CheckBox chkDarkMode = null!;
    private CheckBox chkSaveWindowPos = null!;
    private CheckBox chkShowAllWindows = null!;
    private CheckBox chkRunAsAdmin = null!;
    private CheckBox chkShowAsSigned = null!;
    private CheckBox chkSimplePaste = null!;
    private Button btnAutoAttachConfig = null!;
    private TextBox txtUpdateInterval = null!;
    private TextBox txtFreezeInterval = null!;
    private TextBox txtFoundListInterval = null!;

    // Scan settings controls
    private CheckBox chkScanMemMapped = null!;
    private CheckBox chkScanMemImage = null!;
    private CheckBox chkPauseWhileScanning = null!;
    private CheckBox chkSkipPageFile = null!;
    private TextBox txtScanThreads = null!;
    private CheckBox chkTruncateFloat = null!;
    private CheckBox chkSimpleFloat = null!;
    private CheckBox chkCaseSensitive = null!;
    private CheckBox chkUnicode = null!;

    // Hotkeys controls
    private ListView lvHotkeys = null!;

    // Debugger controls
    private ComboBox cboDebuggerInterface = null!;
    private CheckBox chkBreakOnAttach = null!;
    private CheckBox chkHandleBreakpoints = null!;
    private CheckBox chkVEHGlobalHook = null!;
    private CheckBox chkVEHPageExceptions = null!;

    // Extra controls
    private CheckBox chkQueryMemoryRegion = null!;
    private CheckBox chkReadWriteProcessMemory = null!;
    private CheckBox chkHideDebugger = null!;
    private CheckBox chkPatchNtQuery = null!;
}
