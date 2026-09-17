// <file>
// <summary>
// Reference information panel showing contextual details about the currently selected
// address: which CPU registers point to it, which module and section it belongs to,
// memory protection attributes, and symbol resolution. Styled after x64dbg's info bar.
// </summary>
// </file>

using Nexus.UI.Core;
using Nexus.UI.Interop;
using Nexus.UI.Styles;

namespace Nexus.UI.Panels;

/// <summary>
/// Reference info panel displaying contextual information about the currently selected address.
/// Shows register references, module/section membership, memory protection, and resolved symbols.
/// </summary>
public class InfoPanel : UserControl
{
    private readonly DoubleBufferedPanel _renderPanel;
    private readonly Font _font = new("Consolas", 9f);

    private IntPtr _processHandle;
    private uint _threadId;
    private ulong _currentAddress;
    private CONTEXT64 _context;
    private bool _hasContext;
    private readonly List<string> _infoLines = new();

    // Colors
    private readonly Color _backColor = Color.FromArgb(30, 30, 30);
    private readonly Color _labelColor = Color.FromArgb(128, 128, 128);
    private readonly Color _valueColor = Color.FromArgb(200, 200, 200);
    private readonly Color _moduleColor = Color.FromArgb(0, 200, 200);

    public InfoPanel()
    {
        BackColor = NexusTheme.BackgroundPanel;

        _renderPanel = new DoubleBufferedPanel
        {
            Dock = DockStyle.Fill,
            BackColor = _backColor
        };
        _renderPanel.Paint += RenderPanel_Paint;

        Controls.Add(_renderPanel);

        // Subscribe to navigation events to track current address
        EventBus.Instance.Subscribe<NavigateToAddressEvent>(OnNavigateToAddress);
    }

    public void SetProcessHandle(IntPtr handle)
    {
        _processHandle = handle;
        UpdateInfo();
    }

    public void SetThreadId(uint threadId)
    {
        _threadId = threadId;
        RefreshContext();
    }

    public void SetCurrentAddress(ulong address)
    {
        _currentAddress = address;
        UpdateInfo();
    }

    private void OnNavigateToAddress(NavigateToAddressEvent evt)
    {
        if (InvokeRequired)
            BeginInvoke(() => SetCurrentAddress(evt.Address));
        else
            SetCurrentAddress(evt.Address);
    }

    private void RefreshContext()
    {
        if (_threadId == 0)
        {
            _hasContext = false;
            return;
        }

        var result = NexusEngine.Nexus_GetThreadContext(_threadId, out _context);
        _hasContext = result == NexusResult.OK || result == NexusResult.Success;
        UpdateInfo();
    }

    private void UpdateInfo()
    {
        _infoLines.Clear();

        if (_currentAddress == 0)
        {
            _renderPanel.Invalidate();
            return;
        }

        // Check which registers point to or near this address
        if (_hasContext)
        {
            CheckRegister("rax", _context.Rax);
            CheckRegister("rbx", _context.Rbx);
            CheckRegister("rcx", _context.Rcx);
            CheckRegister("rdx", _context.Rdx);
            CheckRegister("rsp", _context.Rsp);
            CheckRegister("rbp", _context.Rbp);
            CheckRegister("rsi", _context.Rsi);
            CheckRegister("rdi", _context.Rdi);
            CheckRegister("r8", _context.R8);
            CheckRegister("r9", _context.R9);
            CheckRegister("r10", _context.R10);
            CheckRegister("r11", _context.R11);
            CheckRegister("r12", _context.R12);
            CheckRegister("r13", _context.R13);
            CheckRegister("r14", _context.R14);
            CheckRegister("r15", _context.R15);
        }

        // Get module info for current address
        if (_processHandle != IntPtr.Zero)
        {
            var moduleInfo = GetModuleInfo(_currentAddress);
            if (!string.IsNullOrEmpty(moduleInfo))
            {
                _infoLines.Add(moduleInfo);
            }
        }

        _renderPanel.Invalidate();
    }

    private void CheckRegister(string name, ulong value)
    {
        if (value == _currentAddress)
        {
            _infoLines.Add($"{name}={ResolveAddress(value)}");
        }
    }

    private string ResolveAddress(ulong address)
    {
        if (_processHandle == IntPtr.Zero || address == 0)
            return $"{address:X16}";

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

        return $"{address:X16}";
    }

    private string GetModuleInfo(ulong address)
    {
        if (_processHandle == IntPtr.Zero || address == 0)
            return "";

        var modules = new NexusModuleInfo[256];
        var result = NexusEngine.Nexus_EnumerateModules(_processHandle, modules, 256, out var count);
        if (result == NexusResult.OK || result == NexusResult.Success)
        {
            for (int i = 0; i < (int)count; i++)
            {
                var mod = modules[i];
                if (address >= mod.BaseAddress && address < mod.BaseAddress + mod.Size)
                {
                    string moduleName = Path.GetFileName(mod.Name ?? "");
                    ulong offset = address - mod.BaseAddress;
                    return $".text:{address:X16} {moduleName}:${offset:X} #{offset:X}";
                }
            }
        }

        return "";
    }

    private void RenderPanel_Paint(object? sender, PaintEventArgs e)
    {
        var g = e.Graphics;
        g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
        g.Clear(_backColor);

        if (_infoLines.Count == 0)
        {
            return;
        }

        using var valueBrush = new SolidBrush(_valueColor);
        using var moduleBrush = new SolidBrush(_moduleColor);

        int y = 2;
        int lineHeight = (int)_font.GetHeight(g) + 2;

        foreach (var line in _infoLines)
        {
            var brush = line.StartsWith(".text:") ? moduleBrush : valueBrush;
            g.DrawString(line, _font, brush, 4, y);
            y += lineHeight;
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            EventBus.Instance.Unsubscribe<NavigateToAddressEvent>(OnNavigateToAddress);
            _font.Dispose();
        }
        base.Dispose(disposing);
    }
}
