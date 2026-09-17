// <file>
// <summary>
// Auto assembler and auto-inject dialog for writing and injecting assembly scripts.
// </summary>
// </file>
using System.ComponentModel;
using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using Nexus.UI.Styles;


namespace Nexus.UI.Forms;

/// <summary>
/// Auto assembler and injection dialog for creating, editing, and injecting assembly scripts into the attached process.
/// </summary>
public partial class AutoInjectForm : Form
{
    // Menu
    private MenuStrip _mainMenu = null!;
    private ToolStripMenuItem _fileMenu = null!;
    private ToolStripMenuItem _editMenu = null!;
    private ToolStripMenuItem _templateMenu = null!;

    // Toolbar
    private ToolStrip _toolbar = null!;

    // Script editor
    private Panel _pnlEditor = null!;
    private RichTextBox _txtScript = null!;
    private Panel _pnlLineNumbers = null!;

    // Bottom panel
    private Panel _pnlBottom = null!;
    private Button _btnExecute = null!;
    private Button _btnInject = null!;
    private CheckBox _chkInjectOnEnable = null!;

    // State
    private IntPtr _processHandle;
    private string _currentFile = "";
    private bool _isModified;
    private bool _isHighlighting;

    public AutoInjectForm(IntPtr processHandle)
    {
        _processHandle = processHandle;
        InitializeComponent();
        NexusTheme.StyleForm(this);
        SetupEventHandlers();
        ApplySyntaxHighlighting();
    }

    private void InitializeComponent()
    {
        Text = "Auto Assembler";
        Size = new Size(700, 550);
        StartPosition = FormStartPosition.CenterParent;

        // Menu
        _mainMenu = new MenuStrip();

        // File menu
        _fileMenu = new ToolStripMenuItem("File");
        _fileMenu.DropDownItems.Add(new ToolStripMenuItem("New", null, (s, e) => NewScript()) { ShortcutKeys = Keys.Control | Keys.N });
        _fileMenu.DropDownItems.Add("-");
        _fileMenu.DropDownItems.Add(new ToolStripMenuItem("Open...", null, (s, e) => OpenScript()) { ShortcutKeys = Keys.Control | Keys.O });
        _fileMenu.DropDownItems.Add(new ToolStripMenuItem("Save", null, (s, e) => SaveScript()) { ShortcutKeys = Keys.Control | Keys.S });
        _fileMenu.DropDownItems.Add(new ToolStripMenuItem("Save As...", null, (s, e) => SaveScriptAs()));
        _fileMenu.DropDownItems.Add("-");
        _fileMenu.DropDownItems.Add("Assign to current Nexus table", null, (s, e) => AssignToTable());
        _fileMenu.DropDownItems.Add("-");
        _fileMenu.DropDownItems.Add("Close", null, (s, e) => Close());

        // Edit menu
        _editMenu = new ToolStripMenuItem("Edit");
        _editMenu.DropDownItems.Add(new ToolStripMenuItem("Undo", null, (s, e) => _txtScript.Undo()) { ShortcutKeys = Keys.Control | Keys.Z });
        _editMenu.DropDownItems.Add(new ToolStripMenuItem("Redo", null, (s, e) => _txtScript.Redo()) { ShortcutKeys = Keys.Control | Keys.Y });
        _editMenu.DropDownItems.Add("-");
        _editMenu.DropDownItems.Add(new ToolStripMenuItem("Cut", null, (s, e) => _txtScript.Cut()) { ShortcutKeys = Keys.Control | Keys.X });
        _editMenu.DropDownItems.Add(new ToolStripMenuItem("Copy", null, (s, e) => _txtScript.Copy()) { ShortcutKeys = Keys.Control | Keys.C });
        _editMenu.DropDownItems.Add(new ToolStripMenuItem("Paste", null, (s, e) => _txtScript.Paste()) { ShortcutKeys = Keys.Control | Keys.V });
        _editMenu.DropDownItems.Add("-");
        _editMenu.DropDownItems.Add(new ToolStripMenuItem("Find...", null, (s, e) => ShowFind()) { ShortcutKeys = Keys.Control | Keys.F });
        _editMenu.DropDownItems.Add(new ToolStripMenuItem("Replace...", null, (s, e) => ShowReplace()) { ShortcutKeys = Keys.Control | Keys.H });

        // Template menu
        _templateMenu = new ToolStripMenuItem("Template");
        _templateMenu.DropDownItems.Add("Code injection", null, (s, e) => InsertCodeInjection());
        _templateMenu.DropDownItems.Add("Full injection", null, (s, e) => InsertFullInjection());
        _templateMenu.DropDownItems.Add("-");
        _templateMenu.DropDownItems.Add("AOB injection", null, (s, e) => InsertAobInjection());
        _templateMenu.DropDownItems.Add("-");
        _templateMenu.DropDownItems.Add("Nexus table framework", null, (s, e) => InsertTableFramework());

        _mainMenu.Items.Add(_fileMenu);
        _mainMenu.Items.Add(_editMenu);
        _mainMenu.Items.Add(_templateMenu);

        // Toolbar - shell style with emoji + text
        _toolbar = new ToolStrip
        {
            GripStyle = ToolStripGripStyle.Hidden,
            Padding = new Padding(NexusTheme.Space4, 0, NexusTheme.Space4, 0),
            AutoSize = false,
            Height = NexusTheme.ToolbarHeight
        };
        NexusTheme.StyleToolStrip(_toolbar);

        var btnNew = CreateToolbarButton("📄 New", "New script (Ctrl+N)", NewScript);
        var btnOpen = CreateToolbarButton("📂 Open", "Open script (Ctrl+O)", OpenScript);
        var btnSave = CreateToolbarButton("💾 Save", "Save script (Ctrl+S)", SaveScript);
        var separator = new ToolStripSeparator();
        var btnExecute = CreateToolbarButton("▶ Execute", "Execute script (enable section)", ExecuteScript);
        var btnDisable = CreateToolbarButton("⏹ Disable", "Execute disable section", DisableScript);

        _toolbar.Items.Add(btnNew);
        _toolbar.Items.Add(btnOpen);
        _toolbar.Items.Add(btnSave);
        _toolbar.Items.Add(separator);
        _toolbar.Items.Add(btnExecute);
        _toolbar.Items.Add(btnDisable);

        // Editor panel with padding for gap on right side
        _pnlEditor = new Panel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(0, 0, NexusTheme.FormMargin, 0)  // Right margin
        };

        _pnlLineNumbers = new Panel
        {
            Dock = DockStyle.Left,
            Width = 45,
            BackColor = NexusTheme.BackgroundPanel
        };
        _pnlLineNumbers.Paint += PnlLineNumbers_Paint;

        _txtScript = new RichTextBox
        {
            Dock = DockStyle.Fill,
            Font = new Font("Consolas", 10),
            AcceptsTab = true,
            WordWrap = false,
            DetectUrls = false,
            BackColor = NexusTheme.BackgroundControl,
            ForeColor = NexusTheme.TextPrimary,
            BorderStyle = BorderStyle.None
        };

        _pnlEditor.Controls.Add(_txtScript);
        _pnlEditor.Controls.Add(_pnlLineNumbers);

        // Bottom panel - align with text editor (after line numbers)
        const int lineNumbersWidth = 45;
        int bottomBtnX = lineNumbersWidth;
        int bottomBtnY = NexusTheme.Space8;

        _pnlBottom = new Panel
        {
            Dock = DockStyle.Bottom,
            Height = bottomBtnY + NexusTheme.ButtonHeight + NexusTheme.Space16,
            BackColor = NexusTheme.BackgroundDark
        };

        _btnExecute = new Button
        {
            Text = "Execute",
            Location = new Point(bottomBtnX, bottomBtnY)
        };
        NexusTheme.StylePrimaryButton(_btnExecute);
        _btnExecute.Width = 90;

        _btnInject = new Button
        {
            Text = "Inject",
            Location = new Point(bottomBtnX + 90 + NexusTheme.ButtonGap, bottomBtnY)
        };
        NexusTheme.StyleButton(_btnInject);
        _btnInject.Width = 70;

        _chkInjectOnEnable = new CheckBox
        {
            Text = "Inject when enabled",
            Location = new Point(bottomBtnX + 90 + NexusTheme.ButtonGap + 70 + NexusTheme.ButtonGap + 10, bottomBtnY + 4),
            AutoSize = true,
            ForeColor = NexusTheme.TextPrimary,
            BackColor = NexusTheme.BackgroundDark
        };

        _pnlBottom.Controls.AddRange(new Control[] { _btnExecute, _btnInject, _chkInjectOnEnable });

        Controls.Add(_pnlEditor);
        Controls.Add(_pnlBottom);
        Controls.Add(_toolbar);
        Controls.Add(_mainMenu);
        MainMenuStrip = _mainMenu;

        // Style menu and toolbar for dark theme
        NexusTheme.StyleMenuStrip(_mainMenu);
        NexusTheme.StyleToolStrip(_toolbar);

        // Default script
        _txtScript.Text = @"[ENABLE]
// Code to enable

[DISABLE]
// Code to disable
";
    }

    private void SetupEventHandlers()
    {
        _txtScript.TextChanged += (s, e) =>
        {
            if (_isHighlighting) return;
            _isModified = true;
            _pnlLineNumbers.Invalidate();
            ApplySyntaxHighlighting();
        };
        _txtScript.VScroll += (s, e) => _pnlLineNumbers.Invalidate();

        _btnExecute.Click += (s, e) => ExecuteScript();
        _btnInject.Click += (s, e) => InjectScript();

        FormClosing += AutoInjectForm_FormClosing;
    }

    private void PnlLineNumbers_Paint(object? sender, PaintEventArgs e)
    {
        var g = e.Graphics;
        g.Clear(_pnlLineNumbers.BackColor);

        var firstIndex = _txtScript.GetCharIndexFromPosition(new Point(0, 0));
        var firstLine = _txtScript.GetLineFromCharIndex(firstIndex);
        var lineHeight = _txtScript.Font.Height;

        using var brush = new SolidBrush(NexusTheme.TextSecondary);
        using var font = new Font("Consolas", 9);

        var y = 0;
        var line = firstLine + 1;
        while (y < _pnlLineNumbers.Height && line <= _txtScript.Lines.Length)
        {
            var text = line.ToString();
            var size = g.MeasureString(text, font);
            g.DrawString(text, font, brush, _pnlLineNumbers.Width - size.Width - 5, y + 2);
            y += lineHeight;
            line++;
        }

        using var pen = new Pen(NexusTheme.Border);
        g.DrawLine(pen, _pnlLineNumbers.Width - 1, 0, _pnlLineNumbers.Width - 1, _pnlLineNumbers.Height);
    }

    private void ApplySyntaxHighlighting()
    {
        if (_isHighlighting) return;
        _isHighlighting = true;

        var selStart = _txtScript.SelectionStart;
        var selLength = _txtScript.SelectionLength;

        _txtScript.SuspendLayout();

        // Reset to default text color
        _txtScript.SelectAll();
        _txtScript.SelectionColor = NexusTheme.TextPrimary;

        // AA keywords
        var keywords = new[] { "alloc", "dealloc", "label", "registersymbol", "unregistersymbol",
            "aobscan", "aobscanmodule", "define", "reassemble", "readmem", "assert", "globalalloc",
            "include", "createthread", "loadlibrary" };

        // Sections
        var sections = new[] { "[ENABLE]", "[DISABLE]" };

        // Highlight sections (bright cyan)
        foreach (var section in sections)
        {
            HighlightWord(section, Color.FromArgb(86, 156, 214), true);  // Blue
        }

        // Highlight keywords (purple/magenta)
        foreach (var keyword in keywords)
        {
            HighlightWord(keyword, Color.FromArgb(197, 134, 192), false);  // Purple
        }

        // Highlight comments (green)
        HighlightPattern(@"//.*$", Color.FromArgb(106, 153, 85));  // Green

        // Highlight hex numbers (light blue)
        HighlightPattern(@"\b[0-9A-Fa-f]+\b", Color.FromArgb(181, 206, 168));  // Light green

        // Highlight strings (orange)
        HighlightPattern(@"""[^""]*""", Color.FromArgb(206, 145, 120));  // Orange
        HighlightPattern(@"'[^']*'", Color.FromArgb(206, 145, 120));

        _txtScript.Select(selStart, selLength);
        _txtScript.SelectionColor = NexusTheme.TextPrimary;
        _txtScript.ResumeLayout();

        _isHighlighting = false;
    }

    private void HighlightWord(string word, Color color, bool caseSensitive)
    {
        var text = _txtScript.Text;
        var comparison = caseSensitive ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase;
        var index = 0;

        while ((index = text.IndexOf(word, index, comparison)) >= 0)
        {
            _txtScript.Select(index, word.Length);
            _txtScript.SelectionColor = color;
            index += word.Length;
        }
    }

    private void HighlightPattern(string pattern, Color color)
    {
        try
        {
            var regex = new System.Text.RegularExpressions.Regex(pattern,
                System.Text.RegularExpressions.RegexOptions.Multiline);
            foreach (System.Text.RegularExpressions.Match match in regex.Matches(_txtScript.Text))
            {
                _txtScript.Select(match.Index, match.Length);
                _txtScript.SelectionColor = color;
            }
        }
        catch { }
    }

    private void AutoInjectForm_FormClosing(object? sender, FormClosingEventArgs e)
    {
        if (_isModified)
        {
            var result = MessageBox.Show("Save changes?", "Auto Assembler",
                MessageBoxButtons.YesNoCancel, MessageBoxIcon.Question);
            if (result == DialogResult.Cancel) { e.Cancel = true; return; }
            if (result == DialogResult.Yes) SaveScript();
        }
    }

    #region Helpers

    private static ToolStripButton CreateToolbarButton(string text, string tooltip, Action onClick)
    {
        var btn = new ToolStripButton
        {
            Text = text,
            DisplayStyle = ToolStripItemDisplayStyle.Text,
            ForeColor = NexusTheme.TextPrimary,
            ToolTipText = tooltip,
            Padding = new Padding(NexusTheme.Space8, NexusTheme.Space4, NexusTheme.Space8, NexusTheme.Space4),
            Margin = new Padding(0, 0, NexusTheme.Space4, 0)
        };
        btn.Click += (s, e) => onClick();
        return btn;
    }

    #endregion

    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public string ScriptText { get => _txtScript.Text; set => _txtScript.Text = value; }
}
