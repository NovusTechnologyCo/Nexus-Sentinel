// <file>
// <summary>
// Development utility listing all forms for visual review and UI layout testing.
// </summary>
// </file>
using Nexus.UI.Core;
using Nexus.UI.Helpers;
using Nexus.UI.Styles;


namespace Nexus.UI.Forms;

/// <summary>
/// Development utility for reviewing all application form layouts in sequence.
/// </summary>
public class FormReviewerForm : Form
{
    private ListBox _lstForms = null!;
    private Button _btnOpen = null!;
    private Button _btnFillData = null!;
    private Button _btnClose = null!;
    private Label _lblStatus = null!;
    private TextBox _txtFilter = null!;
    private CheckBox _chkShowProcessRequired = null!;
    private Form? _lastOpenedForm;

    // Process handle - uses ProcessContext
    private IntPtr ProcessHandle => ProcessContext.Current.NativeProcessHandle;
    private uint ProcessPid => (uint)ProcessContext.Current.ProcessId;

    // List of all forms organized alphabetically
    private readonly List<(string FormName, Func<Form>? Creator, bool RequiresProcess)> _forms;
    private List<(string FormName, Func<Form>? Creator, bool RequiresProcess)> _filteredForms;

    public FormReviewerForm()
    {
        _forms = GetFormList();
        _filteredForms = _forms;
        InitializeComponent();
        NexusTheme.StyleForm(this);
        PopulateList();
    }

    private List<(string FormName, Func<Form>?, bool)> GetFormList()
    {
        // Updated 2026-01-27 - All forms in Nexus.UI.Forms
        return new List<(string, Func<Form>?, bool)>
        {
            // A
            ("AboutForm", () => new AboutForm(), false),
            ("AddAddressForm", () => new AddAddressForm(), false),
            ("AllocateMemoryForm", () => new AllocateMemoryForm(ProcessHandle), true),
            ("AutoInjectForm", () => new AutoInjectForm(ProcessHandle), true),

            // B
            ("BootkitControlForm", () => new BootkitControlForm(), false),
            ("BreakpointConditionForm", () => new BreakpointConditionForm(), false),
            ("BreakThreadForm", () => new BreakThreadForm(ProcessHandle), true),

            // C
            ("ChangeAddressForm", () => new ChangeAddressForm(), false),
            ("ChangeValueForm", () => new ChangeValueForm(), false),
            ("CodeCaveScannerForm", () => new CodeCaveScannerForm(ProcessHandle), true),
            ("CodeInjectForm", () => new CodeInjectForm(ProcessHandle), true),
            ("CopyMemoryForm", () => new CopyMemoryForm(ProcessHandle), true),

            // D
            ("DebuggerForm", () => new DebuggerForm(ProcessHandle, IntPtr.Zero), true),
            ("DiagnosticsForm", () => new DiagnosticsForm(ProcessHandle), true),
            ("DissectDataForm", () => new DissectDataForm(ProcessHandle, 0x400000), true),
            ("DotNetInfoForm", () => new DotNetInfoForm(ProcessHandle, ProcessPid), true),
            ("DumpMemoryForm", () => new DumpMemoryForm(ProcessHandle), true),

            // E
            ("ElevationPromptForm", () => new ElevationPromptForm(), false),
            ("EnumerateDLLsForm", () => new EnumerateDLLsForm(ProcessHandle), true),

            // F
            ("FieldEditForm", null, false), // Requires field context
            ("FillMemoryForm", () => new FillMemoryForm(), false),
            ("FindDialogForm", () => new FindDialogForm(), false),
            ("FindMemoryForm", () => new FindMemoryForm(), false),
            ("FindStaticsForm", () => new FindStaticsForm(), false),
            ("FoundCodeForm", null, false), // Requires watched address
            ("FreezeForm", () => new FreezeForm(ProcessHandle), true),

            // G
            ("GoToAddressForm", () => new GoToAddressForm(), false),
            ("GotoAddressForm", () => new GotoAddressForm(), false),
            ("GroupForm", () => new GroupForm(), false),

            // H
            ("HotkeyConfigForm", () => new HotkeyConfigForm(), false),

            // I
            ("InputBoxForm", () => new InputBoxForm("Test", "Enter value:"), false),

            // L
            ("LoadMemoryForm", () => new LoadMemoryForm(ProcessHandle), true),

            // M
            ("MemoryRecordDescriptionForm", () => new MemoryRecordDescriptionForm(), false),
            ("MemoryRecordForm", () => new MemoryRecordForm(), false),
            ("MemoryViewerForm", CreateMemoryViewerForm, true),
            ("MergePointerScanResultSettingsForm", () => new MergePointerScanResultSettingsForm(), false),

            // N
            ("NetworkConnectionsForm", () => new NetworkConnectionsForm(ProcessPid), true),

            // O
            ("OptionsForm", () => new OptionsForm(), false),

            // P
            ("PluginManagerForm", null, false), // Requires PluginLoader
            ("PointerRescanForm", () => new PointerRescanForm(), false),
            ("PointerScannerForm", () => new PointerScannerForm(ProcessHandle), true),
            ("PointerScannerSettingsForm", () => new PointerScannerSettingsForm(), false),
            ("PointerScanSettingsForm", () => new PointerScanSettingsForm(), false),
            ("ProcessInspectorForm", () => new ProcessInspectorForm(ProcessHandle, ProcessPid), true),
            ("ProcessMemoryMapForm", () => new ProcessMemoryMapForm(), false),
            ("ProcessWindow", () => new ProcessWindow(), false),

            // S
            ("SaveMemoryForm", () => new SaveMemoryForm(ProcessHandle, 0, 0x1000), true),
            ("ScanHistoryForm", () => new ScanHistoryForm(), false),
            ("ScanSettingsForm", () => new ScanSettingsForm(), false),
            ("ScriptEditorForm", () => new ScriptEditorForm(ProcessHandle, (int)ProcessPid), true),
            ("SettingsForm", () => new SettingsForm(), false),
            ("SortPointerlistForm", () => new SortPointerlistForm(), false),
            ("SpeedhackForm", () => new SpeedhackForm(ProcessHandle), true),
            ("StackMemoryForm", () => new StackMemoryForm(ProcessHandle, 0), true),
            ("StackViewForm", () => new StackViewForm(ProcessHandle, 0), true),
            ("StructPointerRescanForm", () => new StructPointerRescanForm(), false),

            // T
            ("TableImportExportForm", () => new TableImportExportForm(), false),
            ("TablePropertiesForm", () => new TablePropertiesForm(), false),

            // V
            ("ValueHistoryForm", () => new ValueHistoryForm(), false),
            ("ValueTypeSelectorForm", () => new ValueTypeSelectorForm(), false),

            // W
            ("WatchListAddEntryForm", () => new WatchListAddEntryForm(), false),
            ("WindowSpyForm", () => new WindowSpyForm(), false),
        };
    }

    private void InitializeComponent()
    {
        Text = "Form Reviewer - UI Debug Tool";
        Size = new Size(500, 700);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        StartPosition = FormStartPosition.CenterParent;

        var lblTitle = new Label
        {
            Text = "Select a form to review its UI:",
            Location = new Point(12, 12),
            AutoSize = true,
            Font = new Font(Font.FontFamily, 10, FontStyle.Bold)
        };

        var lblFilter = new Label
        {
            Text = "Filter:",
            Location = new Point(12, 38),
            AutoSize = true
        };

        _txtFilter = new TextBox
        {
            Location = new Point(55, 35),
            Size = new Size(200, 23)
        };
        _txtFilter.TextChanged += TxtFilter_TextChanged;

        _chkShowProcessRequired = new CheckBox
        {
            Text = "Show process-required forms",
            Location = new Point(270, 37),
            AutoSize = true,
            Checked = true
        };
        _chkShowProcessRequired.CheckedChanged += (s, e) => ApplyFilter();

        var lblNote = new Label
        {
            Text = "(Forms marked with * require a process to be attached)",
            Location = new Point(12, 62),
            AutoSize = true,
            ForeColor = Color.Gray
        };

        _lstForms = new ListBox
        {
            Location = new Point(12, 82),
            Size = new Size(460, 520),
            Font = new Font("Consolas", 9)
        };
        _lstForms.DoubleClick += (s, e) => OpenSelectedForm();

        _btnOpen = new Button
        {
            Text = "Open",
            Location = new Point(12, 610),
            Size = new Size(80, 32)
        };
        _btnOpen.Click += (s, e) => OpenSelectedForm();

        _btnFillData = new Button
        {
            Text = "Fill Sample Data",
            Location = new Point(100, 610),
            Size = new Size(110, 32),
            Enabled = false
        };
        _btnFillData.Click += (s, e) => FillSampleData();

        _btnClose = new Button
        {
            Text = "Close",
            Location = new Point(392, 610),
            Size = new Size(80, 32),
            DialogResult = DialogResult.Cancel
        };

        _lblStatus = new Label
        {
            Text = $"Total forms: {_forms.Count}",
            Location = new Point(220, 618),
            AutoSize = true
        };

        Controls.Add(lblTitle);
        Controls.Add(lblFilter);
        Controls.Add(_txtFilter);
        Controls.Add(_chkShowProcessRequired);
        Controls.Add(lblNote);
        Controls.Add(_lstForms);
        Controls.Add(_btnOpen);
        Controls.Add(_btnFillData);
        Controls.Add(_btnClose);
        Controls.Add(_lblStatus);

        CancelButton = _btnClose;
    }

    private void TxtFilter_TextChanged(object? sender, EventArgs e)
    {
        ApplyFilter();
    }

    private void ApplyFilter()
    {
        var filter = _txtFilter.Text.Trim().ToLowerInvariant();
        var showProcessRequired = _chkShowProcessRequired.Checked;

        _filteredForms = _forms
            .Where(f => (string.IsNullOrEmpty(filter) || f.FormName.ToLowerInvariant().Contains(filter)))
            .Where(f => showProcessRequired || !f.RequiresProcess)
            .ToList();

        PopulateList();
    }

    private void PopulateList()
    {
        _lstForms.Items.Clear();

        foreach (var (formName, creator, requiresProcess) in _filteredForms)
        {
            string marker = requiresProcess ? " *" : "";
            string noOpen = creator == null ? " [N/A]" : "";
            _lstForms.Items.Add($"{formName}{marker}{noOpen}");
        }

        _lblStatus.Text = $"Showing {_filteredForms.Count} of {_forms.Count} forms";
    }

    private void OpenSelectedForm()
    {
        if (_lstForms.SelectedItem == null) return;

        var selected = _lstForms.SelectedItem.ToString();
        if (string.IsNullOrEmpty(selected)) return;

        var formName = selected.Trim().TrimEnd('*').Replace("[N/A]", "").Trim();
        var formEntry = _filteredForms.FirstOrDefault(f => f.FormName == formName);

        if (formEntry.Creator == null)
        {
            MessageBox.Show($"'{formName}' cannot be opened from this reviewer.\n\nThis form requires specific context or is the main form.",
                "Cannot Open", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        if (formEntry.RequiresProcess && ProcessHandle == IntPtr.Zero)
        {
            var result = MessageBox.Show(
                $"'{formName}' requires a process to be attached.\n\nDo you want to open it anyway? (Some features may not work)",
                "Process Required", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
            if (result != DialogResult.Yes) return;
        }

        try
        {
            var form = formEntry.Creator();
            _lastOpenedForm = form;
            _btnFillData.Enabled = SampleDataHelper.HasSampleData(form);
            _lblStatus.Text = $"Opened: {formName}";
            form.FormClosed += (s, e) =>
            {
                if (_lastOpenedForm == form)
                {
                    _lastOpenedForm = null;
                    _btnFillData.Enabled = false;
                }
            };
            form.Show();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error opening {formName}:\n{ex.Message}", "Error",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void FillSampleData()
    {
        if (_lastOpenedForm == null || _lastOpenedForm.IsDisposed)
        {
            _btnFillData.Enabled = false;
            return;
        }

        try
        {
            SampleDataHelper.FillSampleData(_lastOpenedForm);
            _lblStatus.Text = $"Sample data filled for {_lastOpenedForm.GetType().Name}";
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error filling sample data:\n{ex.Message}", "Error",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private Form CreateMemoryViewerForm()
    {
        var form = new MemoryViewerForm();
        form.SetProcess(ProcessHandle);
        return form;
    }
}
