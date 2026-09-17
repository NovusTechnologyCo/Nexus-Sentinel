// <file>
// <summary>
// C# script editor with syntax highlighting and Nexus Engine API access.
// </summary>
// </file>
using Nexus.UI.Helpers;
using Nexus.UI.Scripting;
using Nexus.UI.Styles;


namespace Nexus.UI.Forms;

/// <summary>
/// Form for editing and executing C# scripts.
/// Replaces Lua scripting with native C# compilation via Roslyn.
/// </summary>
public class ScriptEditorForm : Form
{
    // Controls
    private MenuStrip _menuStrip = null!;
    private ToolStrip _toolStrip = null!;
    private SplitContainer _splitContainer = null!;
    private RichTextBox _txtScript = null!;
    private RichTextBox _txtOutput = null!;
    private StatusStrip _statusStrip = null!;
    private ToolStripStatusLabel _lblStatus = null!;
    private ToolStripProgressBar _progressBar = null!;

    // State
    private readonly IntPtr _processHandle;
    private readonly int _processId;
    private ScriptEngine? _scriptEngine;
    private CancellationTokenSource? _cts;
    private string? _currentFilePath;
    private bool _isDirty;

    public ScriptEditorForm(IntPtr processHandle, int processId)
    {
        _processHandle = processHandle;
        _processId = processId;
        InitializeComponent();
        NexusTheme.StyleForm(this);
        SetupEventHandlers();
        LoadDefaultScript();
    }

    private void InitializeComponent()
    {
        Text = "Script Editor - C#";
        Size = new Size(900, 700);
        StartPosition = FormStartPosition.CenterParent;

        // Menu strip
        _menuStrip = new MenuStrip();
        var fileMenu = new ToolStripMenuItem("&File");
        fileMenu.DropDownItems.Add("&New", null, (s, e) => NewScript());
        fileMenu.DropDownItems.Add("&Open...", null, (s, e) => OpenScript());
        fileMenu.DropDownItems.Add("&Save", null, (s, e) => SaveScript());
        fileMenu.DropDownItems.Add("Save &As...", null, (s, e) => SaveScriptAs());
        fileMenu.DropDownItems.Add(new ToolStripSeparator());
        fileMenu.DropDownItems.Add("E&xit", null, (s, e) => Close());
        _menuStrip.Items.Add(fileMenu);

        var editMenu = new ToolStripMenuItem("&Edit");
        editMenu.DropDownItems.Add("&Undo", null, (s, e) => _txtScript.Undo());
        editMenu.DropDownItems.Add("&Redo", null, (s, e) => _txtScript.Redo());
        editMenu.DropDownItems.Add(new ToolStripSeparator());
        editMenu.DropDownItems.Add("Cu&t", null, (s, e) => _txtScript.Cut());
        editMenu.DropDownItems.Add("&Copy", null, (s, e) => _txtScript.Copy());
        editMenu.DropDownItems.Add("&Paste", null, (s, e) => _txtScript.Paste());
        editMenu.DropDownItems.Add(new ToolStripSeparator());
        editMenu.DropDownItems.Add("Select &All", null, (s, e) => _txtScript.SelectAll());
        _menuStrip.Items.Add(editMenu);

        var scriptMenu = new ToolStripMenuItem("&Script");
        scriptMenu.DropDownItems.Add("&Run", null, (s, e) => RunScript());
        scriptMenu.DropDownItems.Add("&Validate", null, (s, e) => ValidateScript());
        scriptMenu.DropDownItems.Add("&Stop", null, (s, e) => StopScript());
        scriptMenu.DropDownItems.Add(new ToolStripSeparator());
        scriptMenu.DropDownItems.Add("&Clear Output", null, (s, e) => _txtOutput.Clear());
        _menuStrip.Items.Add(scriptMenu);

        var helpMenu = new ToolStripMenuItem("&Help");
        helpMenu.DropDownItems.Add("&API Reference", null, (s, e) => ShowApiHelp());
        helpMenu.DropDownItems.Add("&Examples", null, (s, e) => ShowExamples());
        _menuStrip.Items.Add(helpMenu);

        // Tool strip
        _toolStrip = new ToolStrip();
        _toolStrip.Items.Add(new ToolStripButton("New", null, (s, e) => NewScript()) { ToolTipText = "New Script" });
        _toolStrip.Items.Add(new ToolStripButton("Open", null, (s, e) => OpenScript()) { ToolTipText = "Open Script" });
        _toolStrip.Items.Add(new ToolStripButton("Save", null, (s, e) => SaveScript()) { ToolTipText = "Save Script" });
        _toolStrip.Items.Add(new ToolStripSeparator());
        var runButton = new ToolStripButton("Run", null, (s, e) => RunScript()) { ToolTipText = "Run Script (F5)" };
        _toolStrip.Items.Add(runButton);
        var stopButton = new ToolStripButton("Stop", null, (s, e) => StopScript()) { ToolTipText = "Stop Script" };
        _toolStrip.Items.Add(stopButton);
        _toolStrip.Items.Add(new ToolStripSeparator());
        _toolStrip.Items.Add(new ToolStripButton("Validate", null, (s, e) => ValidateScript()) { ToolTipText = "Validate Script" });

        // Split container for script and output
        _splitContainer = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Orientation = Orientation.Horizontal,
            SplitterDistance = 450
        };

        // Script text box
        _txtScript = new RichTextBox
        {
            Dock = DockStyle.Fill,
            Font = new Font("Consolas", 11),
            AcceptsTab = true,
            WordWrap = false,
            ScrollBars = RichTextBoxScrollBars.Both
        };

        // Output text box
        var outputLabel = new Label
        {
            Text = "Output:",
            Dock = DockStyle.Top,
            Height = 20,
            Padding = new Padding(3)
        };

        _txtOutput = new RichTextBox
        {
            Dock = DockStyle.Fill,
            Font = new Font("Consolas", 10),
            ReadOnly = true,
            BackColor = Color.FromArgb(30, 30, 30),
            ForeColor = Color.White
        };

        var outputPanel = new Panel { Dock = DockStyle.Fill };
        outputPanel.Controls.Add(_txtOutput);
        outputPanel.Controls.Add(outputLabel);

        _splitContainer.Panel1.Controls.Add(_txtScript);
        _splitContainer.Panel2.Controls.Add(outputPanel);

        // Status strip
        _statusStrip = new StatusStrip();
        _lblStatus = new ToolStripStatusLabel("Ready") { Spring = true, TextAlign = ContentAlignment.MiddleLeft };
        _progressBar = new ToolStripProgressBar { Visible = false, Width = 100 };
        _statusStrip.Items.Add(_lblStatus);
        _statusStrip.Items.Add(_progressBar);

        // Add controls
        Controls.Add(_splitContainer);
        Controls.Add(_toolStrip);
        Controls.Add(_menuStrip);
        Controls.Add(_statusStrip);

        MainMenuStrip = _menuStrip;
        KeyPreview = true;
    }

    private void SetupEventHandlers()
    {
        _txtScript.TextChanged += (s, e) =>
        {
            if (!_isDirty)
            {
                _isDirty = true;
                UpdateTitle();
            }
        };

        KeyDown += (s, e) =>
        {
            if (e.KeyCode == Keys.F5)
            {
                RunScript();
                e.Handled = true;
            }
            else if (e.Control && e.KeyCode == Keys.S)
            {
                SaveScript();
                e.Handled = true;
            }
        };

        FormClosing += (s, e) =>
        {
            if (_isDirty)
            {
                var result = MessageBox.Show(
                    "Script has unsaved changes. Save before closing?",
                    "Unsaved Changes",
                    MessageBoxButtons.YesNoCancel,
                    MessageBoxIcon.Question);

                if (result == DialogResult.Yes)
                {
                    SaveScript();
                }
                else if (result == DialogResult.Cancel)
                {
                    e.Cancel = true;
                    return;
                }
            }

            _cts?.Cancel();
            _scriptEngine?.Dispose();
        };
    }

    private void LoadDefaultScript()
    {
        _txtScript.Text = @"// Nexus C# Script
// Available: ctx.ReadByte/Int16/Int32/Int64/Float/Double/String/Bytes(address)
//            ctx.WriteByte/Int16/Int32/Int64/Float/Double/Bytes(address, value)
//            ctx.Print(message), ctx.Sleep(ms)
//            ctx.ProcessHandle, ctx.ProcessId

// Example: Read and print a value
ulong address = 0x00400000;
int value = ctx.ReadInt32(address);
ctx.Print($""Value at 0x{address:X}: {value}"");

// Example: Write a value
// ctx.WriteInt32(address, 100);
";
        _isDirty = false;
        UpdateTitle();
    }

    private void UpdateTitle()
    {
        var fileName = _currentFilePath != null ? Path.GetFileName(_currentFilePath) : "Untitled";
        Text = $"Script Editor - {fileName}{(_isDirty ? " *" : "")}";
    }

    private void NewScript()
    {
        if (_isDirty)
        {
            var result = MessageBox.Show(
                "Save current script?",
                "Unsaved Changes",
                MessageBoxButtons.YesNoCancel,
                MessageBoxIcon.Question);

            if (result == DialogResult.Yes) SaveScript();
            else if (result == DialogResult.Cancel) return;
        }

        _currentFilePath = null;
        LoadDefaultScript();
    }

    private void OpenScript()
    {
        if (_isDirty)
        {
            var result = MessageBox.Show(
                "Save current script?",
                "Unsaved Changes",
                MessageBoxButtons.YesNoCancel,
                MessageBoxIcon.Question);

            if (result == DialogResult.Yes) SaveScript();
            else if (result == DialogResult.Cancel) return;
        }

        using var dialog = new OpenFileDialog
        {
            Filter = "C# Scripts (*.cs)|*.cs|All Files (*.*)|*.*",
            Title = "Open Script"
        };

        if (dialog.ShowDialog() == DialogResult.OK)
        {
            try
            {
                _txtScript.Text = File.ReadAllText(dialog.FileName);
                _currentFilePath = dialog.FileName;
                _isDirty = false;
                UpdateTitle();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to open file: {ex.Message}",
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }

    private void SaveScript()
    {
        if (_currentFilePath == null)
        {
            SaveScriptAs();
            return;
        }

        try
        {
            File.WriteAllText(_currentFilePath, _txtScript.Text);
            _isDirty = false;
            UpdateTitle();
            _lblStatus.Text = "Saved";
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Failed to save file: {ex.Message}",
                "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void SaveScriptAs()
    {
        using var dialog = new SaveFileDialog
        {
            Filter = "C# Scripts (*.cs)|*.cs|All Files (*.*)|*.*",
            Title = "Save Script As"
        };

        if (dialog.ShowDialog() == DialogResult.OK)
        {
            _currentFilePath = dialog.FileName;
            SaveScript();
        }
    }

    private async void RunScript()
    {
        if (_processHandle == IntPtr.Zero)
        {
            MessageBox.Show("No process attached", "Error",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        _cts?.Cancel();
        _cts = new CancellationTokenSource();

        _scriptEngine?.Dispose();
        _scriptEngine = new ScriptEngine();
        _scriptEngine.OutputCallback = output =>
        {
            if (InvokeRequired)
                Invoke(() => AppendOutput(output, Color.White));
            else
                AppendOutput(output, Color.White);
        };
        _scriptEngine.ErrorCallback = ex =>
        {
            if (InvokeRequired)
                Invoke(() => AppendOutput($"Exception: {ex.Message}", Color.Red));
            else
                AppendOutput($"Exception: {ex.Message}", Color.Red);
        };

        var context = new ScriptContext(_processHandle, _processId);

        _progressBar.Visible = true;
        _lblStatus.Text = "Running...";
        AppendOutput($"--- Script started at {DateTime.Now:HH:mm:ss} ---\n", Color.Cyan);

        try
        {
            var result = await Task.Run(() =>
                _scriptEngine.Execute(_txtScript.Text, context, _cts.Token));

            _progressBar.Visible = false;

            switch (result)
            {
                case ScriptResult.Success:
                    _lblStatus.Text = "Script completed successfully";
                    AppendOutput($"--- Script completed at {DateTime.Now:HH:mm:ss} ---\n", Color.Lime);
                    break;

                case ScriptResult.CompilationError:
                    _lblStatus.Text = "Compilation errors";
                    AppendOutput("Compilation errors:\n", Color.Red);
                    foreach (var error in _scriptEngine.Errors)
                    {
                        AppendOutput($"  {error}\n", Color.Orange);
                    }
                    break;

                case ScriptResult.RuntimeError:
                    _lblStatus.Text = "Runtime error";
                    foreach (var error in _scriptEngine.Errors)
                    {
                        AppendOutput($"Runtime error: {error.Message}\n", Color.Red);
                    }
                    break;

                case ScriptResult.Timeout:
                    _lblStatus.Text = "Script timed out";
                    AppendOutput("Script execution timed out (30 second limit)\n", Color.Orange);
                    break;

                case ScriptResult.Cancelled:
                    _lblStatus.Text = "Script cancelled";
                    AppendOutput("Script was cancelled\n", Color.Yellow);
                    break;
            }
        }
        catch (Exception ex)
        {
            _progressBar.Visible = false;
            _lblStatus.Text = "Error";
            AppendOutput($"Error: {ex.Message}\n", Color.Red);
        }
    }

    private void ValidateScript()
    {
        _scriptEngine?.Dispose();
        _scriptEngine = new ScriptEngine();

        var isValid = _scriptEngine.Validate(_txtScript.Text);

        if (isValid)
        {
            _lblStatus.Text = "Script is valid";
            AppendOutput("Script validation passed\n", Color.Lime);
        }
        else
        {
            _lblStatus.Text = "Validation errors";
            AppendOutput("Validation errors:\n", Color.Red);
            foreach (var error in _scriptEngine.Errors)
            {
                AppendOutput($"  {error}\n", Color.Orange);
            }
        }
    }

    private void StopScript()
    {
        _cts?.Cancel();
        _lblStatus.Text = "Stopping...";
    }

    private void AppendOutput(string text, Color color)
    {
        _txtOutput.SelectionStart = _txtOutput.TextLength;
        _txtOutput.SelectionLength = 0;
        _txtOutput.SelectionColor = color;
        _txtOutput.AppendText(text);
        _txtOutput.ScrollToCaret();
    }

    private void ShowApiHelp()
    {
        var help = @"Nexus C# Script API Reference
=============================

Your script runs inside a Run(ScriptContext ctx) method.
The 'ctx' variable provides access to the target process.

READING MEMORY
--------------
ctx.ReadByte(ulong address)     -> byte
ctx.ReadInt16(ulong address)    -> short
ctx.ReadInt32(ulong address)    -> int
ctx.ReadInt64(ulong address)    -> long
ctx.ReadFloat(ulong address)    -> float
ctx.ReadDouble(ulong address)   -> double
ctx.ReadString(ulong address, int maxLength = 256) -> string
ctx.ReadBytes(ulong address, int count) -> byte[]

WRITING MEMORY
--------------
ctx.WriteByte(ulong address, byte value)     -> bool
ctx.WriteInt16(ulong address, short value)   -> bool
ctx.WriteInt32(ulong address, int value)     -> bool
ctx.WriteInt64(ulong address, long value)    -> bool
ctx.WriteFloat(ulong address, float value)   -> bool
ctx.WriteDouble(ulong address, double value) -> bool
ctx.WriteBytes(ulong address, byte[] data)   -> bool

UTILITIES
---------
ctx.Print(string message)       - Output text to console
ctx.Sleep(int milliseconds)     - Pause execution

PROPERTIES
----------
ctx.ProcessHandle               - Native process handle (IntPtr)
ctx.ProcessId                   - Process ID (int)

AVAILABLE NAMESPACES
--------------------
System, System.Linq, System.Collections.Generic
Nexus.UI.Scripting
";
        MessageBox.Show(help, "API Reference", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private void ShowExamples()
    {
        var examples = @"Example Scripts
===============

1. Read and modify health:
---------------------------
ulong healthAddr = 0x12345678;
int health = ctx.ReadInt32(healthAddr);
ctx.Print($""Current health: {health}"");
ctx.WriteInt32(healthAddr, 999);
ctx.Print(""Health set to 999"");

2. Search for pattern in range:
-------------------------------
ulong start = 0x00400000;
ulong end = 0x00500000;
byte target = 0x90;

for (ulong addr = start; addr < end; addr++)
{
    if (ctx.ReadByte(addr) == target)
    {
        ctx.Print($""Found 0x{target:X2} at 0x{addr:X}"");
    }
}

3. Monitor value changes:
-------------------------
ulong addr = 0x12345678;
int lastValue = ctx.ReadInt32(addr);
ctx.Print($""Initial value: {lastValue}"");

for (int i = 0; i < 100; i++)
{
    int current = ctx.ReadInt32(addr);
    if (current != lastValue)
    {
        ctx.Print($""Changed: {lastValue} -> {current}"");
        lastValue = current;
    }
    ctx.Sleep(100);
}

4. Freeze a value:
------------------
ulong addr = 0x12345678;
int freezeValue = 100;

ctx.Print($""Freezing value at 0x{addr:X} to {freezeValue}"");
for (int i = 0; i < 300; i++) // 30 seconds
{
    ctx.WriteInt32(addr, freezeValue);
    ctx.Sleep(100);
}
ctx.Print(""Freeze complete"");
";
        MessageBox.Show(examples, "Script Examples", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }
}
