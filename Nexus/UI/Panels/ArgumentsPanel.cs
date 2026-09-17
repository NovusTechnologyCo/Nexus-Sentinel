// <file>
// <summary>
// Function arguments display panel showing register-based and stack-based arguments
// for the current function call based on the selected calling convention (x64 fastcall,
// cdecl, stdcall, thiscall). Resolves pointer values to symbols where possible.
// Integrated into the debugger layout alongside registers and stack panels.
// </summary>
// </file>

using Nexus.UI.Core;
using Nexus.UI.Interop;
using Nexus.UI.Styles;

namespace Nexus.UI.Panels;

/// <summary>
/// Function arguments panel displaying register and stack arguments for the current call site.
/// Supports x64 fastcall (RCX, RDX, R8, R9 + stack), cdecl, stdcall, and thiscall conventions.
/// Resolves argument values to module/function symbols when possible.
/// </summary>
public class ArgumentsPanel : UserControl
{
    private readonly ComboBox _callingConventionCombo;
    private readonly NumericUpDown _argCountSpinner;
    private readonly CheckBox _lockCheckbox;
    private readonly ListView _listView;

    private uint _threadId;
    private IntPtr _processHandle;
    private bool _isLocked;

    // Calling conventions
    private static readonly string[] CallingConventions = new[]
    {
        "Default (x64 fastcall)",
        "cdecl",
        "stdcall",
        "thiscall"
    };

    // x64 fastcall register order (lowercase like x64dbg)
    private static readonly string[] X64FastcallRegs = { "rcx", "rdx", "r8", "r9" };

    public ArgumentsPanel()
    {
        BackColor = NexusTheme.BackgroundPanel;

        // Top toolbar panel
        var toolbar = new Panel
        {
            Dock = DockStyle.Top,
            Height = 28,
            Padding = new Padding(2),
            BackColor = NexusTheme.BackgroundDark
        };

        // Calling convention dropdown
        _callingConventionCombo = new ComboBox
        {
            DropDownStyle = ComboBoxStyle.DropDownList,
            Location = new Point(2, 3),
            Width = 180,
            Font = new Font("Segoe UI", 8f)
        };
        _callingConventionCombo.Items.AddRange(CallingConventions);
        _callingConventionCombo.SelectedIndex = 0;
        _callingConventionCombo.SelectedIndexChanged += (s, e) => RefreshArguments();
        NexusTheme.StyleComboBox(_callingConventionCombo);

        // Argument count spinner
        _argCountSpinner = new NumericUpDown
        {
            Location = new Point(188, 3),
            Width = 45,
            Minimum = 1,
            Maximum = 20,
            Value = 5,
            Font = new Font("Segoe UI", 8f)
        };
        _argCountSpinner.ValueChanged += (s, e) => RefreshArguments();
        _argCountSpinner.BackColor = NexusTheme.BackgroundDark;
        _argCountSpinner.ForeColor = NexusTheme.TextPrimary;

        // Lock checkbox
        _lockCheckbox = new CheckBox
        {
            Text = "Unlocked",
            Location = new Point(238, 5),
            AutoSize = true,
            ForeColor = NexusTheme.TextSecondary,
            Font = new Font("Segoe UI", 8f)
        };
        _lockCheckbox.CheckedChanged += (s, e) =>
        {
            _isLocked = _lockCheckbox.Checked;
            _lockCheckbox.Text = _isLocked ? "Locked" : "Unlocked";
            if (!_isLocked) RefreshArguments();
        };

        toolbar.Controls.AddRange(new Control[] { _callingConventionCombo, _argCountSpinner, _lockCheckbox });

        // Arguments list (x64dbg style - single column with formatted text)
        _listView = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = false,
            HeaderStyle = ColumnHeaderStyle.None,
            Font = new Font("Consolas", 9f)
        };
        _listView.Columns.Add("Argument", 600); // Wide enough for full text
        NexusTheme.StyleListView(_listView);

        Controls.Add(_listView);
        Controls.Add(toolbar);
    }

    public void SetProcessHandle(IntPtr handle)
    {
        _processHandle = handle;

        // Try to get first thread if we don't have one
        if (_threadId == 0 && handle != IntPtr.Zero)
        {
            TryGetFirstThread();
        }
    }

    private void TryGetFirstThread()
    {
        if (_processHandle == IntPtr.Zero) return;

        // Enumerate threads to get the first one
        var threads = new NexusThreadInfo[64];
        var result = NexusEngine.Nexus_EnumerateThreads(_processHandle, threads, 64, out nuint count);
        if ((result == NexusResult.OK || result == NexusResult.Success) && count > 0)
        {
            _threadId = threads[0].ThreadId;
            RefreshArguments();
        }
    }

    public void SetThreadId(uint threadId)
    {
        _threadId = threadId;
        if (!_isLocked)
            RefreshArguments();
    }

    public void RefreshArguments()
    {
        if (_isLocked) return;

        _listView.BeginUpdate();
        _listView.Items.Clear();

        if (_threadId == 0)
        {
            _listView.EndUpdate();
            return;
        }

        // Get thread context
        var result = NexusEngine.Nexus_GetThreadContext(_threadId, out CONTEXT64 context);
        if (result != NexusResult.OK && result != NexusResult.Success)
        {
            _listView.EndUpdate();
            return;
        }

        int argCount = (int)_argCountSpinner.Value;
        string callingConvention = _callingConventionCombo.SelectedItem?.ToString() ?? "Default (x64 fastcall)";

        // For x64 fastcall, first 4 args in registers, rest on stack
        if (callingConvention.Contains("x64") || callingConvention.Contains("fastcall"))
        {
            AddX64FastcallArguments(ref context, argCount);
        }
        else
        {
            // For other conventions, all args on stack (simplified)
            AddStackArguments(context.Rsp, argCount, 0);
        }

        _listView.EndUpdate();
    }

    private void AddX64FastcallArguments(ref CONTEXT64 context, int argCount)
    {
        // First 4 arguments in registers
        ulong[] regValues = { context.Rcx, context.Rdx, context.R8, context.R9 };

        for (int i = 0; i < Math.Min(4, argCount); i++)
        {
            string symbol = ResolveSymbol(regValues[i]);
            AddArgumentRow(i + 1, X64FastcallRegs[i], regValues[i], symbol);
        }

        // Additional arguments on stack (after shadow space at rsp+0x28)
        if (argCount > 4)
        {
            ulong stackBase = context.Rsp + 0x28; // Shadow space is 0x20, return addr is 0x8
            AddStackArguments(stackBase, argCount - 4, 4);
        }
    }

    private void AddStackArguments(ulong stackBase, int count, int startIndex)
    {
        if (_processHandle == IntPtr.Zero) return;

        for (int i = 0; i < count; i++)
        {
            ulong stackAddr = stackBase + (ulong)(i * 8);
            ulong value = ReadMemoryUlong(stackAddr);
            string location = $"[rsp+{0x28 + i * 8:X}]";
            string symbol = ResolveSymbol(value);
            AddArgumentRow(startIndex + i + 1, location, value, symbol);
        }
    }

    private void AddArgumentRow(int index, string location, ulong value, string symbol)
    {
        // Format like x64dbg: "1: rcx 00007FFAABC50000 gdi32full.00007FFAABC50000"
        // If no symbol, repeat the value
        string displaySymbol = string.IsNullOrEmpty(symbol) ? $"{value:X16}" : symbol;
        string text = $"{index}: {location} {value:X16} {displaySymbol}";

        var item = new ListViewItem(text);

        // Color code based on value type (like x64dbg)
        if (!string.IsNullOrEmpty(symbol))
        {
            item.ForeColor = Color.FromArgb(0, 200, 200); // Cyan for resolved symbols
        }
        else if (value == 0)
        {
            item.ForeColor = Color.FromArgb(128, 128, 128); // Gray for zero
        }
        else
        {
            item.ForeColor = Color.FromArgb(200, 200, 200); // Light gray for plain values
        }

        _listView.Items.Add(item);
    }

    private ulong ReadMemoryUlong(ulong address)
    {
        if (_processHandle == IntPtr.Zero) return 0;

        byte[] buffer = new byte[8];
        unsafe
        {
            fixed (byte* ptr = buffer)
            {
                var result = NexusEngine.Nexus_ReadMemory(
                    _processHandle, address, (IntPtr)ptr, 8, out var bytesRead);
                if ((result == NexusResult.OK || result == NexusResult.Success) && bytesRead >= 8)
                {
                    return BitConverter.ToUInt64(buffer, 0);
                }
            }
        }
        return 0;
    }

    private string ResolveSymbol(ulong address)
    {
        if (address == 0 || _processHandle == IntPtr.Zero) return "";
        if (address < 0x10000 || address > 0x7FFFFFFFFFFF) return "";

        // Try to find module containing this address
        var modules = new NexusModuleInfo[256];
        var result = NexusEngine.Nexus_EnumerateModules(_processHandle, modules, 256, out var count);
        if (result == NexusResult.OK || result == NexusResult.Success)
        {
            for (int i = 0; i < (int)count; i++)
            {
                var mod = modules[i];
                if (address >= mod.BaseAddress && address < mod.BaseAddress + mod.Size)
                {
                    string moduleName = Path.GetFileNameWithoutExtension(mod.Name ?? "");
                    ulong offset = address - mod.BaseAddress;
                    return $"{moduleName}.{offset:X}";
                }
            }
        }

        return "";
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _callingConventionCombo.Dispose();
            _argCountSpinner.Dispose();
            _lockCheckbox.Dispose();
            _listView.Dispose();
        }
        base.Dispose(disposing);
    }
}
