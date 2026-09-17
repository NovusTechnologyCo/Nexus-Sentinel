// <file>
// <summary>
// Code injection dialog for injecting assembly or shellcode into the target process.
// </summary>
// </file>
using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using Nexus.UI.Styles;


namespace Nexus.UI.Forms;

/// <summary>
/// Form for injecting code into the target process.
/// Matches CE's code injection capabilities.
/// </summary>
public partial class CodeInjectForm : Form
{
    // Tab bar (shell-style)
    private Panel _tabBar = null!;
    private Button[] _tabButtons = null!;
    private Panel _pnlContent = null!;
    private int _selectedTab = 0;

    // Tab panels
    private Panel _pnlShellcode = null!;
    private Panel _pnlDll = null!;
    private Panel _pnlCodeCave = null!;

    // Shellcode tab
    private Label _lblShellcodeAddr = null!;
    private TextBox _txtShellcodeAddr = null!;
    private RichTextBox _txtShellcode = null!;
    private CheckBox _chkExecuteShellcode = null!;

    // DLL tab
    private Label _lblDllPath = null!;
    private TextBox _txtDllPath = null!;
    private Button _btnBrowseDll = null!;
    private ComboBox _cboInjectionMethod = null!;
    private CheckBox _chkHideFromPeb = null!;
    private CheckBox _chkEraseHeaders = null!;

    // Code cave tab
    private Label _lblTargetAddr = null!;
    private TextBox _txtTargetAddr = null!;
    private Label _lblCaveSize = null!;
    private NumericUpDown _nudCaveSize = null!;
    private RichTextBox _txtCaveCode = null!;
    private CheckBox _chkAutoNop = null!;

    // Bottom panel
    private Panel _pnlBottom = null!;
    private Button _btnInject = null!;
    private Button _btnClose = null!;
    private Label _lblStatus = null!;

    // State
    private IntPtr _processHandle;

    public CodeInjectForm(IntPtr processHandle)
    {
        _processHandle = processHandle;
        InitializeComponent();
        NexusTheme.StyleForm(this);
        SetupEventHandlers();
    }

    private void InitializeComponent()
    {
        Text = "Code Injection";
        Size = new Size(680, 565);
        StartPosition = FormStartPosition.CenterParent;

        const int margin = NexusTheme.Space16;

        // Tab bar (shell-style)
        (_tabBar, _tabButtons) = NexusTheme.CreateTabBar(
            ["Shellcode", "DLL Injection", "Code Cave"],
            SwitchTab
        );
        _tabBar.Location = new Point(margin, margin);
        _tabBar.Size = new Size(600 - margin * 2 - 16, NexusTheme.ToolbarHeight);  // Account for window borders
        _tabBar.Dock = DockStyle.None;

        // Content panel
        _pnlContent = new Panel
        {
            Location = new Point(margin, margin + NexusTheme.ToolbarHeight),
            Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Bottom,
            BackColor = NexusTheme.BackgroundPanel
        };

        // Create tab panels
        _pnlShellcode = new Panel { Dock = DockStyle.Fill, BackColor = NexusTheme.BackgroundPanel };
        _pnlDll = new Panel { Dock = DockStyle.Fill, BackColor = NexusTheme.BackgroundPanel, Visible = false };
        _pnlCodeCave = new Panel { Dock = DockStyle.Fill, BackColor = NexusTheme.BackgroundPanel, Visible = false };

        InitShellcodeTab();
        InitDllTab();
        InitCodeCaveTab();

        _pnlContent.Controls.Add(_pnlShellcode);
        _pnlContent.Controls.Add(_pnlDll);
        _pnlContent.Controls.Add(_pnlCodeCave);

        // Bottom panel
        _pnlBottom = new Panel
        {
            Dock = DockStyle.Bottom,
            Height = NexusTheme.Space8 + NexusTheme.ButtonHeight + NexusTheme.Space16
        };

        _lblStatus = new Label
        {
            Text = "",
            Location = new Point(margin, NexusTheme.Space8 + 6),
            AutoSize = true
        };

        // Right-aligned buttons
        _btnClose = new Button
        {
            Text = "Close",
            Size = new Size(NexusTheme.ButtonWidth, NexusTheme.ButtonHeight),
            DialogResult = DialogResult.Cancel,
            Anchor = AnchorStyles.Top | AnchorStyles.Right
        };
        _btnClose.Click += (s, e) => Close();

        _btnInject = new Button
        {
            Text = "Inject",
            Size = new Size(NexusTheme.ButtonWidth, NexusTheme.ButtonHeight),
            Anchor = AnchorStyles.Top | AnchorStyles.Right
        };
        NexusTheme.StylePrimaryButton(_btnInject);

        _pnlBottom.Layout += (s, e) =>
        {
            _btnClose.Location = new Point(_pnlBottom.ClientSize.Width - margin - NexusTheme.ButtonWidth, NexusTheme.Space8);
            _btnInject.Location = new Point(_btnClose.Left - NexusTheme.ButtonGap - NexusTheme.ButtonWidth, NexusTheme.Space8);
        };

        _pnlBottom.Controls.Add(_btnInject);
        _pnlBottom.Controls.Add(_btnClose);
        _pnlBottom.Controls.Add(_lblStatus);

        Controls.Add(_pnlContent);
        Controls.Add(_tabBar);
        Controls.Add(_pnlBottom);
        CancelButton = _btnClose;

        // Size content panel after form loads
        Load += (s, e) =>
        {
            _pnlContent.Size = new Size(
                ClientSize.Width - margin * 2,
                ClientSize.Height - margin - NexusTheme.ToolbarHeight - _pnlBottom.Height
            );
            SwitchTab(0);
        };
    }

    private void SwitchTab(int tabIndex)
    {
        _selectedTab = tabIndex;
        NexusTheme.UpdateTabSelection(_tabButtons, tabIndex);

        _pnlShellcode.Visible = tabIndex == 0;
        _pnlDll.Visible = tabIndex == 1;
        _pnlCodeCave.Visible = tabIndex == 2;

        if (tabIndex == 0) _pnlShellcode.BringToFront();
        else if (tabIndex == 1) _pnlDll.BringToFront();
        else if (tabIndex == 2) _pnlCodeCave.BringToFront();
    }

    private void InitShellcodeTab()
    {
        _lblShellcodeAddr = new Label
        {
            Text = "Target Address (optional):",
            Location = new Point(0, 15),
            AutoSize = true
        };

        _txtShellcodeAddr = new TextBox
        {
            Location = new Point(220, 12),
            Size = new Size(150, 23),
            Text = "(auto allocate)"
        };
        NexusTheme.StyleTextBox(_txtShellcodeAddr);

        var gbShellcode = new GroupBox
        {
            Text = "Shellcode bytes (hex):",
            Location = new Point(0, 45),
            Size = new Size(615, 290),
            ForeColor = NexusTheme.TextPrimary,
            BackColor = NexusTheme.BackgroundPanel
        };

        _txtShellcode = new RichTextBox
        {
            Dock = DockStyle.Fill,
            Font = new Font("Consolas", 10),
            BackColor = NexusTheme.BackgroundControl,
            ForeColor = NexusTheme.TextPrimary,
            BorderStyle = BorderStyle.None
        };
        gbShellcode.Controls.Add(_txtShellcode);

        _chkExecuteShellcode = new CheckBox
        {
            Text = "Execute shellcode after injection",
            Location = new Point(10, 345),
            AutoSize = true,
            Checked = true,
            ForeColor = NexusTheme.TextPrimary,
            BackColor = NexusTheme.BackgroundPanel
        };

        var lblHint = new Label
        {
            Text = "Enter shellcode as hex bytes separated by spaces (e.g., 90 90 C3)",
            Location = new Point(10, 370),
            AutoSize = true,
            ForeColor = NexusTheme.TextSecondary
        };

        _pnlShellcode.Controls.Add(_lblShellcodeAddr);
        _pnlShellcode.Controls.Add(_txtShellcodeAddr);
        _pnlShellcode.Controls.Add(gbShellcode);
        _pnlShellcode.Controls.Add(_chkExecuteShellcode);
        _pnlShellcode.Controls.Add(lblHint);
    }

    private void InitDllTab()
    {
        _lblDllPath = new Label
        {
            Text = "DLL Path:",
            Location = new Point(0, 15),
            AutoSize = true
        };

        _txtDllPath = new TextBox
        {
            Location = new Point(85, 12),
            Size = new Size(395, 23)
        };
        NexusTheme.StyleTextBox(_txtDllPath);

        _btnBrowseDll = new Button
        {
            Text = "...",
            Location = new Point(488, 11),
            Size = new Size(40, 25)
        };
        NexusTheme.StyleButton(_btnBrowseDll);

        var lblMethod = new Label
        {
            Text = "Injection Method:",
            Location = new Point(0, 50),
            AutoSize = true
        };

        _cboInjectionMethod = new ComboBox
        {
            Location = new Point(160, 47),
            Size = new Size(320, 23),
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        _cboInjectionMethod.Items.Add("LoadLibrary (CreateRemoteThread)");
        _cboInjectionMethod.Items.Add("Manual Map");
        _cboInjectionMethod.Items.Add("Thread Hijack");
        _cboInjectionMethod.Items.Add("APC Injection");
        _cboInjectionMethod.SelectedIndex = 0;
        NexusTheme.StyleComboBox(_cboInjectionMethod);

        _chkHideFromPeb = new CheckBox
        {
            Text = "Hide DLL from PEB module list",
            Location = new Point(10, 85),
            AutoSize = true,
            ForeColor = NexusTheme.TextPrimary,
            BackColor = NexusTheme.BackgroundPanel
        };

        _chkEraseHeaders = new CheckBox
        {
            Text = "Erase PE headers after injection",
            Location = new Point(10, 110),
            AutoSize = true,
            ForeColor = NexusTheme.TextPrimary,
            BackColor = NexusTheme.BackgroundPanel
        };

        var grpInfo = new GroupBox
        {
            Text = "Information",
            Location = new Point(0, 145),
            Size = new Size(550, 200),
            ForeColor = NexusTheme.TextPrimary,
            BackColor = NexusTheme.BackgroundPanel
        };

        var infoText = new Label
        {
            Text = @"LoadLibrary: Standard injection via CreateRemoteThread calling LoadLibraryA/W.
Detected by most anti-cheats.

Manual Map: Maps DLL manually without using LoadLibrary.
Hides from module list but requires PE parsing.

Thread Hijack: Hijacks existing thread to load DLL.
More stealthy but may cause instability.

APC Injection: Queues APC to load DLL.
Works on suspended threads.",
            Location = new Point(15, 25),
            Size = new Size(520, 160),
            AutoSize = false,
            ForeColor = NexusTheme.TextSecondary
        };
        grpInfo.Controls.Add(infoText);

        _pnlDll.Controls.Add(_lblDllPath);
        _pnlDll.Controls.Add(_txtDllPath);
        _pnlDll.Controls.Add(_btnBrowseDll);
        _pnlDll.Controls.Add(lblMethod);
        _pnlDll.Controls.Add(_cboInjectionMethod);
        _pnlDll.Controls.Add(_chkHideFromPeb);
        _pnlDll.Controls.Add(_chkEraseHeaders);
        _pnlDll.Controls.Add(grpInfo);
    }

    private void InitCodeCaveTab()
    {
        _lblTargetAddr = new Label
        {
            Text = "Target Address:",
            Location = new Point(0, 15),
            AutoSize = true
        };

        _txtTargetAddr = new TextBox
        {
            Location = new Point(140, 12),
            Size = new Size(295, 23)
        };
        NexusTheme.StyleTextBox(_txtTargetAddr);

        // Right-align Cave Size: 615 (groupbox width) - 80 (numeric) = 535
        _nudCaveSize = new NumericUpDown
        {
            Location = new Point(535, 12),
            Size = new Size(80, 23),
            Minimum = 32,
            Maximum = 65536,
            Value = 2048,
            BackColor = NexusTheme.BackgroundControl,
            ForeColor = NexusTheme.TextPrimary
        };

        _lblCaveSize = new Label
        {
            Text = "Cave Size:",
            Location = new Point(535 - 95, 15),  // 95px for label width + gap
            AutoSize = true
        };

        var gbCode = new GroupBox
        {
            Text = "Code to inject (assembly):",
            Location = new Point(0, 45),
            Size = new Size(615, 290),
            ForeColor = NexusTheme.TextPrimary,
            BackColor = NexusTheme.BackgroundPanel
        };

        _txtCaveCode = new RichTextBox
        {
            Dock = DockStyle.Fill,
            Font = new Font("Consolas", 10),
            BackColor = NexusTheme.BackgroundControl,
            ForeColor = NexusTheme.TextPrimary,
            BorderStyle = BorderStyle.None,
            Text = @"// Your code here
push rax
push rbx
// ...
pop rbx
pop rax
jmp originalcode

originalcode:
// Original instructions will be placed here
"
        };
        gbCode.Controls.Add(_txtCaveCode);

        _chkAutoNop = new CheckBox
        {
            Text = "Auto-NOP remaining bytes at original location",
            Location = new Point(0, 345),
            AutoSize = true,
            Checked = true,
            ForeColor = NexusTheme.TextPrimary,
            BackColor = NexusTheme.BackgroundPanel
        };

        var lblHint = new Label
        {
            Text = "The assembler will create a jump from Target Address to the allocated cave.",
            Location = new Point(0, 370),
            AutoSize = true,
            ForeColor = NexusTheme.TextSecondary
        };

        _pnlCodeCave.Controls.Add(_lblTargetAddr);
        _pnlCodeCave.Controls.Add(_txtTargetAddr);
        _pnlCodeCave.Controls.Add(_lblCaveSize);
        _pnlCodeCave.Controls.Add(_nudCaveSize);
        _pnlCodeCave.Controls.Add(gbCode);
        _pnlCodeCave.Controls.Add(_chkAutoNop);
        _pnlCodeCave.Controls.Add(lblHint);
    }

    private void SetupEventHandlers()
    {
        _btnBrowseDll.Click += (s, e) => BrowseDll();
        _btnInject.Click += (s, e) => DoInject();
    }
}

/// <summary>
/// Simple dialog for allocating memory in target process.
/// </summary>
public class AllocateMemoryForm : Form
{
    private NumericUpDown _nudSize = null!;
    private ComboBox _cboProtection = null!;
    private TextBox _txtAddress = null!;
    private Button _btnAllocate = null!;
    private Button _btnClose = null!;
    private Label _lblResult = null!;

    private IntPtr _processHandle;

    public ulong AllocatedAddress { get; private set; }

    public AllocateMemoryForm(IntPtr processHandle)
    {
        _processHandle = processHandle;
        InitializeComponent();
        NexusTheme.StyleForm(this);
    }

    private void InitializeComponent()
    {
        Text = "Allocate Memory";
        Size = new Size(400, 225);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        StartPosition = FormStartPosition.CenterParent;

        var lblSize = new Label { Text = "Size:", Location = new Point(12, 17), AutoSize = true };
        _nudSize = new NumericUpDown
        {
            Location = new Point(115, 14),
            Size = new Size(120, 23),
            Minimum = 1,
            Maximum = 1024 * 1024 * 100, // 100 MB
            Value = 4096
        };

        var lblProt = new Label { Text = "Protection:", Location = new Point(12, 47), AutoSize = true };
        _cboProtection = new ComboBox
        {
            Location = new Point(115, 44),
            Size = new Size(235, 23),
            DropDownStyle = ComboBoxStyle.DropDownList
        };
        _cboProtection.Items.Add("PAGE_READWRITE (0x04)");
        _cboProtection.Items.Add("PAGE_EXECUTE_READWRITE (0x40)");
        _cboProtection.Items.Add("PAGE_EXECUTE_READ (0x20)");
        _cboProtection.Items.Add("PAGE_READONLY (0x02)");
        _cboProtection.SelectedIndex = 0;

        var lblAddr = new Label { Text = "Preferred:", Location = new Point(12, 77), AutoSize = true };
        _txtAddress = new TextBox
        {
            Location = new Point(115, 74),
            Size = new Size(120, 23),
            Text = "(auto)"
        };

        _btnAllocate = new Button
        {
            Text = "Allocate",
            Location = new Point(200, 130),
            Size = new Size(85, 32)
        };
        _btnAllocate.Click += BtnAllocate_Click;

        _btnClose = new Button
        {
            Text = "Close",
            Location = new Point(295, 130),
            Size = new Size(80, 32),
            DialogResult = DialogResult.Cancel
        };

        _lblResult = new Label
        {
            Text = "",
            Location = new Point(12, 138),
            AutoSize = true
        };

        Controls.Add(lblSize);
        Controls.Add(_nudSize);
        Controls.Add(lblProt);
        Controls.Add(_cboProtection);
        Controls.Add(lblAddr);
        Controls.Add(_txtAddress);
        Controls.Add(_btnAllocate);
        Controls.Add(_btnClose);
        Controls.Add(_lblResult);

        CancelButton = _btnClose;
    }

    private void BtnAllocate_Click(object? sender, EventArgs e)
    {
        uint protection = _cboProtection.SelectedIndex switch
        {
            0 => 0x04, // PAGE_READWRITE
            1 => 0x40, // PAGE_EXECUTE_READWRITE
            2 => 0x20, // PAGE_EXECUTE_READ
            3 => 0x02, // PAGE_READONLY
            _ => 0x04
        };

        var result = NexusEngine.Nexus_AllocateMemory(
            _processHandle,
            (nuint)_nudSize.Value,
            protection,
            out var addr);

        if (result == NexusResult.Success || result == NexusResult.OK)
        {
            AllocatedAddress = addr;
            _lblResult.Text = $"Allocated at 0x{addr:X}";
            _lblResult.ForeColor = Color.Green;
            DialogResult = DialogResult.OK;
        }
        else
        {
            _lblResult.Text = $"Failed: {result}";
            _lblResult.ForeColor = Color.Red;
        }
    }
}
