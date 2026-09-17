// <file>
// <summary>
// Thread selection dialog for choosing which thread to break on during debugging.
// </summary>
// </file>
using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using Nexus.UI.Styles;


namespace Nexus.UI.Forms;

public partial class BreakThreadForm : Form
{
    private IntPtr _processHandle;
    private uint _selectedThreadId;

    public uint SelectedThreadId => _selectedThreadId;

    public BreakThreadForm(IntPtr processHandle)
    {
        _processHandle = processHandle;
        InitializeComponent();
        NexusTheme.StyleForm(this);
        // Don't load in constructor - defer to Shown
        Shown += BreakThreadForm_Shown;
    }

    private void BreakThreadForm_Shown(object? sender, EventArgs e)
    {
        try
        {
            LoadThreadList();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"LoadThreadList error: {ex}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void InitializeComponent()
    {
        Text = "Break Thread";
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;

        const int margin = NexusTheme.Space16;
        const int contentWidth = 468;

        // Description label (two lines)
        lblDesc = new Label
        {
            Text = "This process has more than 1 thread. Select the thread you wish to break.",
            Location = new Point(margin, margin),
            Size = new Size(contentWidth, 40),
            AutoSize = false
        };

        // Thread list
        int listY = margin + 40 + NexusTheme.Space8;
        lbThreads = new ListBox
        {
            Location = new Point(margin, listY),
            Size = new Size(contentWidth, 210),
            Font = new Font("Consolas", 10F),
            BackColor = NexusTheme.BackgroundControl,
            ForeColor = NexusTheme.TextPrimary,
            BorderStyle = BorderStyle.FixedSingle
        };
        lbThreads.DoubleClick += LbThreads_DoubleClick;

        // Buttons (no panel, just right-aligned buttons)
        int btnY = listY + 210 + NexusTheme.Space8;
        int buttonX = margin + contentWidth - NexusTheme.ButtonWidth;
        btnCancel = new Button
        {
            Text = "Cancel",
            Location = new Point(buttonX, btnY),
            Size = new Size(NexusTheme.ButtonWidth, NexusTheme.ButtonHeight),
            DialogResult = DialogResult.Cancel
        };
        btnCancel.Click += (s, e) => Close();
        NexusTheme.StyleButton(btnCancel);

        buttonX -= NexusTheme.ButtonWidth + NexusTheme.ButtonGap;
        btnOk = new Button
        {
            Text = "OK",
            Location = new Point(buttonX, btnY),
            Size = new Size(NexusTheme.ButtonWidth, NexusTheme.ButtonHeight),
            DialogResult = DialogResult.OK
        };
        btnOk.Click += BtnOk_Click;
        NexusTheme.StylePrimaryButton(btnOk);

        AcceptButton = btnOk;
        CancelButton = btnCancel;

        Controls.AddRange([lblDesc, lbThreads, btnOk, btnCancel]);

        // Set ClientSize based on content
        ClientSize = new Size(margin + contentWidth + margin, btnY + NexusTheme.ButtonHeight + margin);
    }

    private void LoadThreadList()
    {
        lbThreads.Items.Clear();

        if (_processHandle == IntPtr.Zero)
        {
            lbThreads.Items.Add("(No process attached)");
            btnOk.Enabled = false;
            return;
        }

        // First call to get count
        NexusEngine.Nexus_EnumerateThreads(_processHandle, null, 0, out nuint count);
        if (count == 0)
        {
            lbThreads.Items.Add("(No threads found)");
            btnOk.Enabled = false;
            return;
        }

        // Allocate array and enumerate threads
        var threads = new NexusThreadInfo[count];
        var result = NexusEngine.Nexus_EnumerateThreads(_processHandle, threads, count, out _);

        if (result != NexusResult.OK)
        {
            lbThreads.Items.Add("(Thread enumeration failed)");
            btnOk.Enabled = false;
            return;
        }

        // Add threads to list
        for (int i = 0; i < (int)count; i++)
        {
            var thread = threads[i];
            if (thread.ThreadId == 0) continue;

            string name = !string.IsNullOrEmpty(thread.Name) ? $" - {thread.Name}" : "";
            lbThreads.Items.Add($"{thread.ThreadId:X8}{name}");
        }

        if (lbThreads.Items.Count == 0)
        {
            lbThreads.Items.Add("(No threads found)");
            btnOk.Enabled = false;
        }
        else
        {
            btnOk.Enabled = true;
            lbThreads.SelectedIndex = 0;
        }
    }

    private void BtnOk_Click(object? sender, EventArgs e)
    {
        if (SelectCurrentThread())
        {
            Close();
        }
    }

    private void LbThreads_DoubleClick(object? sender, EventArgs e)
    {
        if (SelectCurrentThread())
        {
            DialogResult = DialogResult.OK;
            Close();
        }
    }

    private bool SelectCurrentThread()
    {
        if (lbThreads.SelectedIndex < 0) return false;

        string? selectedText = lbThreads.SelectedItem?.ToString();
        if (string.IsNullOrEmpty(selectedText) || selectedText.StartsWith("("))
        {
            return false;
        }

        // Extract the hex thread ID from the start of the string.
        // Format is "{ThreadId:X8}" optionally followed by " - {Name}"
        var idPart = selectedText.Contains(" - ") ? selectedText[..selectedText.IndexOf(" - ")] : selectedText;

        if (uint.TryParse(idPart, System.Globalization.NumberStyles.HexNumber,
            null, out uint tid))
        {
            _selectedThreadId = tid;
            return true;
        }

        return false;
    }

    /// <summary>
    /// Shows the thread selection dialog and returns the selected thread ID.
    /// </summary>
    public static bool Show(IWin32Window? owner, IntPtr processHandle, out uint threadId)
    {
        try
        {
            using var form = new BreakThreadForm(processHandle);
            if (form.ShowDialog(owner) == DialogResult.OK)
            {
                threadId = form.SelectedThreadId;
                return true;
            }

            threadId = 0;
            return false;
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error in BreakThreadForm: {ex.Message}\n\n{ex.StackTrace}",
                "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            threadId = 0;
            return false;
        }
    }

    // Controls
    private Label lblDesc = null!;
    private ListBox lbThreads = null!;
    private Button btnOk = null!;
    private Button btnCancel = null!;
}
