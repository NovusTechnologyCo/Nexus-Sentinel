// AutoInjectForm.Operations.cs — File/edit operations, templates, and script execution.
using Nexus.UI.Interop;


namespace Nexus.UI.Forms;

public partial class AutoInjectForm
{
    #region File Operations

    private void NewScript()
    {
        if (_isModified)
        {
            var result = MessageBox.Show("Save changes?", "New", MessageBoxButtons.YesNoCancel);
            if (result == DialogResult.Cancel) return;
            if (result == DialogResult.Yes) SaveScript();
        }

        _txtScript.Text = @"[ENABLE]
// Code to enable

[DISABLE]
// Code to disable
";
        _currentFile = "";
        _isModified = false;
        Text = "Auto Assembler";
    }

    private void OpenScript()
    {
        using var dialog = new OpenFileDialog
        {
            Filter = "Auto Assembler scripts (*.cea)|*.cea|All files (*.*)|*.*",
            Title = "Open script"
        };

        if (dialog.ShowDialog() == DialogResult.OK)
        {
            _txtScript.Text = File.ReadAllText(dialog.FileName);
            _currentFile = dialog.FileName;
            _isModified = false;
            Text = $"Auto Assembler - {Path.GetFileName(_currentFile)}";
        }
    }

    private void SaveScript()
    {
        if (string.IsNullOrEmpty(_currentFile)) { SaveScriptAs(); return; }
        File.WriteAllText(_currentFile, _txtScript.Text);
        _isModified = false;
    }

    private void SaveScriptAs()
    {
        using var dialog = new SaveFileDialog
        {
            Filter = "Auto Assembler scripts (*.cea)|*.cea|All files (*.*)|*.*",
            Title = "Save script as"
        };

        if (dialog.ShowDialog() == DialogResult.OK)
        {
            _currentFile = dialog.FileName;
            SaveScript();
            Text = $"Auto Assembler - {Path.GetFileName(_currentFile)}";
        }
    }

    #endregion

    #region Edit Operations

    private void ShowFind()
    {
        var search = Microsoft.VisualBasic.Interaction.InputBox("Find:", "Find", "");
        if (!string.IsNullOrEmpty(search))
        {
            var index = _txtScript.Text.IndexOf(search, _txtScript.SelectionStart + _txtScript.SelectionLength,
                StringComparison.OrdinalIgnoreCase);
            if (index >= 0)
            {
                _txtScript.Select(index, search.Length);
                _txtScript.ScrollToCaret();
            }
            else
            {
                index = _txtScript.Text.IndexOf(search, StringComparison.OrdinalIgnoreCase);
                if (index >= 0) { _txtScript.Select(index, search.Length); _txtScript.ScrollToCaret(); }
                else MessageBox.Show("Not found", "Find");
            }
        }
    }

    private void ShowReplace()
    {
        using var dialog = new Form
        {
            Text = "Find and Replace",
            Size = new Size(400, 170),
            FormBorderStyle = FormBorderStyle.FixedDialog,
            StartPosition = FormStartPosition.CenterParent,
            MaximizeBox = false,
            MinimizeBox = false
        };

        var lblFind = new Label { Text = "Find:", Location = new Point(15, 18), AutoSize = true };
        var txtFind = new TextBox { Location = new Point(90, 15), Width = 280 };

        var lblReplace = new Label { Text = "Replace:", Location = new Point(15, 48), AutoSize = true };
        var txtReplace = new TextBox { Location = new Point(90, 45), Width = 280 };

        var chkCase = new CheckBox { Text = "Case sensitive", Location = new Point(90, 75), AutoSize = true };

        var btnFind = new Button { Text = "Find Next", Location = new Point(115, 100), Size = new Size(80, 28) };
        var btnReplace = new Button { Text = "Replace", Location = new Point(200, 100), Size = new Size(80, 28) };
        var btnReplaceAll = new Button { Text = "Replace All", Location = new Point(285, 100), Size = new Size(80, 28) };

        btnFind.Click += (s, e) =>
        {
            var comparison = chkCase.Checked ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase;
            var index = _txtScript.Text.IndexOf(txtFind.Text, _txtScript.SelectionStart + 1, comparison);
            if (index >= 0) { _txtScript.Select(index, txtFind.Text.Length); _txtScript.ScrollToCaret(); }
            else { index = _txtScript.Text.IndexOf(txtFind.Text, comparison); if (index >= 0) { _txtScript.Select(index, txtFind.Text.Length); _txtScript.ScrollToCaret(); } }
        };

        btnReplace.Click += (s, e) =>
        {
            if (_txtScript.SelectedText.Equals(txtFind.Text, chkCase.Checked ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase))
            {
                _txtScript.SelectedText = txtReplace.Text;
            }
            btnFind.PerformClick();
        };

        btnReplaceAll.Click += (s, e) =>
        {
            var comparison = chkCase.Checked ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase;
            var text = _txtScript.Text;
            int count = 0;
            int index = 0;
            while ((index = text.IndexOf(txtFind.Text, index, comparison)) >= 0)
            {
                text = text.Remove(index, txtFind.Text.Length).Insert(index, txtReplace.Text);
                index += txtReplace.Text.Length;
                count++;
            }
            _txtScript.Text = text;
            MessageBox.Show($"Replaced {count} occurrence(s)", "Replace All");
        };

        dialog.Controls.AddRange(new Control[] { lblFind, txtFind, lblReplace, txtReplace, chkCase, btnFind, btnReplace, btnReplaceAll });
        dialog.ShowDialog(this);
    }

    #endregion

    #region Templates

    private void InsertCodeInjection()
    {
        var addr = Microsoft.VisualBasic.Interaction.InputBox("Address to inject at:", "Code Injection", "");
        if (string.IsNullOrEmpty(addr)) return;

        _txtScript.Text = $@"[ENABLE]
alloc(newmem,2048)
label(returnhere)
label(originalcode)
label(exit)

newmem:
  // Your code here

originalcode:
  // Original instructions here

exit:
  jmp returnhere

{addr}:
  jmp newmem
  nop
returnhere:

[DISABLE]
{addr}:
  // Original bytes here

dealloc(newmem)
";
    }

    private void InsertFullInjection()
    {
        _txtScript.Text = @"[ENABLE]
alloc(newmem,2048)
label(returnhere)

newmem:
  // Your code here
  jmp returnhere

// Hook address:
  jmp newmem
returnhere:

[DISABLE]
// Restore original bytes

dealloc(newmem)
";
    }

    private void InsertAobInjection()
    {
        _txtScript.Text = @"[ENABLE]
aobscanmodule(INJECT,module.exe,XX XX XX XX XX)
alloc(newmem,$1000)
label(code)
label(return)

newmem:
code:
  // Original code here
  jmp return

INJECT:
  jmp newmem
  nop
return:
registersymbol(INJECT)

[DISABLE]
INJECT:
  // Restore original bytes
unregistersymbol(INJECT)
dealloc(newmem)
";
    }

    private void InsertTableFramework()
    {
        _txtScript.Text = @"// Nexus Table Framework Script
// This script demonstrates a typical code injection pattern

define(address,""game.exe""+12345)
define(bytes,90 90 90 90 90)

[ENABLE]
// Allocate memory for our code cave
alloc(newmem,$1000)

// Create label for our injected code
label(returnhere)
label(originalcode)
label(exit)

newmem:
  // Your custom code here
  // Example: mov [eax+10],#100

originalcode:
  // Original bytes go here (will be NOPed at injection point)
  nop
  nop
  nop
  nop
  nop

exit:
  jmp returnhere

// Hook the original location
address:
  jmp newmem
  nop
returnhere:

// Register symbol for table access
registersymbol(newmem)

[DISABLE]
// Restore original code
address:
  db bytes

// Clean up
unregistersymbol(newmem)
dealloc(newmem)
";
    }

    #endregion

    #region Execution

    private void ExecuteScript()
    {
        if (_processHandle == IntPtr.Zero)
        {
            MessageBox.Show("No process attached", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        // Create assembler for the process
        var createResult = NexusEngine.Nexus_AssemblerCreate(_processHandle, NexusAssemblerArch.X64, out var assembler);
        if (createResult != NexusResult.OK && createResult != NexusResult.Success)
        {
            MessageBox.Show($"Failed to create assembler: {NexusHelper.GetErrorMessage(createResult)}",
                "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        try
        {
            // Execute the [ENABLE] section
            var result = NexusEngine.Nexus_AssemblerExecuteScript(assembler, _txtScript.Text, true);
            if (result == NexusResult.OK || result == NexusResult.Success)
            {
                MessageBox.Show("Script executed successfully (ENABLE section).",
                    "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
                // Get error details
                if (NexusEngine.Nexus_AssemblerGetLastError(assembler, out var errorInfo) == NexusResult.OK)
                {
                    MessageBox.Show($"Script execution failed:\n\nLine {errorInfo.Line}: {errorInfo.Message}",
                        "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                else
                {
                    MessageBox.Show($"Script execution failed: {NexusHelper.GetErrorMessage(result)}",
                        "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }
        finally
        {
            NexusEngine.Nexus_AssemblerDestroy(assembler);
        }
    }

    private void InjectScript()
    {
        if (_processHandle == IntPtr.Zero)
        {
            MessageBox.Show("No process attached", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        // Create assembler
        var createResult = NexusEngine.Nexus_AssemblerCreate(_processHandle, NexusAssemblerArch.X64, out var assembler);
        if (createResult != NexusResult.OK && createResult != NexusResult.Success)
        {
            MessageBox.Show($"Failed to create assembler: {NexusHelper.GetErrorMessage(createResult)}",
                "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        try
        {
            // Execute the [ENABLE] section
            var result = NexusEngine.Nexus_AssemblerExecuteScript(assembler, _txtScript.Text, true);
            if (result == NexusResult.OK || result == NexusResult.Success)
            {
                MessageBox.Show("Script injected successfully.\n\n" +
                    "Note: Use 'Execute' again with [DISABLE] section to undo changes.",
                    "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
                if (NexusEngine.Nexus_AssemblerGetLastError(assembler, out var errorInfo) == NexusResult.OK)
                {
                    MessageBox.Show($"Injection failed:\n\nLine {errorInfo.Line}: {errorInfo.Message}",
                        "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                else
                {
                    MessageBox.Show($"Injection failed: {NexusHelper.GetErrorMessage(result)}",
                        "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }
        finally
        {
            // Note: Don't destroy assembler if we want to keep allocations
            // For now, just destroy it - real implementation would track state
            NexusEngine.Nexus_AssemblerDestroy(assembler);
        }
    }

    private void AssignToTable()
    {
        // Scripts in auto assembler are code injection scripts, not values to watch.
        // The "table" in Cheat Engine refers to the cheat table which contains both
        // addresses and scripts. For now, inform the user about the distinction.
        MessageBox.Show("Auto Assembler scripts are code injections, not address values.\n\n" +
            "Scripts are enabled/disabled directly in this window.\n" +
            "To add an address to the watch list, use the Memory Scanner panel.",
            "Script Assignment", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private void DisableScript()
    {
        if (_processHandle == IntPtr.Zero)
        {
            MessageBox.Show("No process attached", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        // Create assembler for the process
        var createResult = NexusEngine.Nexus_AssemblerCreate(_processHandle, NexusAssemblerArch.X64, out var assembler);
        if (createResult != NexusResult.OK && createResult != NexusResult.Success)
        {
            MessageBox.Show($"Failed to create assembler: {NexusHelper.GetErrorMessage(createResult)}",
                "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        try
        {
            // Execute the [DISABLE] section
            var result = NexusEngine.Nexus_AssemblerExecuteScript(assembler, _txtScript.Text, false);
            if (result == NexusResult.OK || result == NexusResult.Success)
            {
                MessageBox.Show("Script disabled successfully (DISABLE section).",
                    "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
                if (NexusEngine.Nexus_AssemblerGetLastError(assembler, out var errorInfo) == NexusResult.OK)
                {
                    MessageBox.Show($"Disable failed:\n\nLine {errorInfo.Line}: {errorInfo.Message}",
                        "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                else
                {
                    MessageBox.Show($"Disable failed: {NexusHelper.GetErrorMessage(result)}",
                        "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }
        finally
        {
            NexusEngine.Nexus_AssemblerDestroy(assembler);
        }
    }

    #endregion
}
