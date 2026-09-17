// <file>
// <summary>
// Module enumeration dialog showing all loaded DLLs with exported symbols.
// </summary>
// </file>
using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using Nexus.UI.Styles;


namespace Nexus.UI.Forms;

/// <summary>
/// Form to enumerate and display loaded DLLs/modules and their symbols.
/// </summary>
public partial class EnumerateDLLsForm : Form
{
    private readonly IntPtr _processHandle;
    private CancellationTokenSource? _cts;

    public EnumerateDLLsForm(IntPtr processHandle)
    {
        _processHandle = processHandle;
        InitializeComponent();
        NexusTheme.StyleForm(this);
    }

    private void InitializeComponent()
    {
        Text = "Enumerate DLLs";
        Size = new Size(650, 600);
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.Sizable;
        MinimumSize = new Size(400, 350);
        Padding = new Padding(NexusTheme.Space16, NexusTheme.Space8, NexusTheme.Space16, NexusTheme.Space8);

        // Top panel with buttons
        var pnlTop = new Panel
        {
            Dock = DockStyle.Top,
            Height = NexusTheme.ControlHeight + NexusTheme.Space16
        };

        btnRefresh = new Button
        {
            Text = "Refresh",
            Location = new Point(0, 4),
            Size = new Size(80, NexusTheme.ControlHeight)
        };
        btnRefresh.Click += (s, e) => Enumerate();

        btnExpand = new Button
        {
            Text = "Expand",
            Location = new Point(90, 4),
            Size = new Size(80, NexusTheme.ControlHeight)
        };
        btnExpand.Click += (s, e) => tvSymbols.ExpandAll();

        btnCollapse = new Button
        {
            Text = "Collapse",
            Location = new Point(180, 4),
            Size = new Size(90, NexusTheme.ControlHeight)
        };
        btnCollapse.Click += (s, e) => tvSymbols.CollapseAll();

        pnlTop.Controls.AddRange([btnRefresh, btnExpand, btnCollapse]);

        // TreeView for modules and symbols
        tvSymbols = new TreeView
        {
            Dock = DockStyle.Fill,
            Font = new Font("Consolas", 9F),
            HideSelection = false
        };
        tvSymbols.NodeMouseDoubleClick += TvSymbols_NodeMouseDoubleClick;
        tvSymbols.KeyDown += TvSymbols_KeyDown;

        // Context menu
        var ctxMenu = new ContextMenuStrip();
        var miFind = new ToolStripMenuItem("Find", null, (s, e) => ShowFindDialog()) { ShortcutKeys = Keys.Control | Keys.F };
        var miFindNext = new ToolStripMenuItem("Find Next...", null, (s, e) => FindNext()) { ShortcutKeys = Keys.F3, Enabled = false };
        var miCopy = new ToolStripMenuItem("Copy Symbol Name", null, (s, e) => CopySymbolName()) { ShortcutKeys = Keys.Control | Keys.C };
        var miCopyAddr = new ToolStripMenuItem("Copy Address", null, (s, e) => CopyAddress());
        ctxMenu.Items.AddRange([miFind, miFindNext, new ToolStripSeparator(), miCopy, miCopyAddr]);
        _miFindNext = miFindNext;
        tvSymbols.ContextMenuStrip = ctxMenu;

        // Status bar
        statusStrip = new StatusStrip();
        lblStatus = new ToolStripStatusLabel { Text = "Ready" };
        statusStrip.Items.Add(lblStatus);

        Controls.AddRange([tvSymbols, pnlTop, statusStrip]);
    }

    protected override void OnShown(EventArgs e)
    {
        base.OnShown(e);
        Enumerate();
    }

    protected override void OnFormClosed(FormClosedEventArgs e)
    {
        base.OnFormClosed(e);
        CancelEnumeration();
    }

    private void Enumerate()
    {
        if (_processHandle == IntPtr.Zero)
        {
            tvSymbols.Nodes.Clear();
            var noProcessNode = tvSymbols.Nodes.Add("No process attached");
            noProcessNode.ForeColor = Color.Gray;
            lblStatus.Text = "Attach to a process first";
            return;
        }

        tvSymbols.Nodes.Clear();
        _cts = new CancellationTokenSource();
        btnRefresh.Enabled = false;
        lblStatus.Text = "Enumerating modules...";

        Task.Run(async () =>
        {
            try
            {
                await EnumerateModulesAsync(_cts.Token);
            }
            catch (OperationCanceledException)
            {
                // Cancelled - ignore
            }
            catch (Exception ex)
            {
                if (!IsDisposed)
                {
                    Invoke(() => lblStatus.Text = $"Error: {ex.Message}");
                }
            }
            finally
            {
                if (!IsDisposed)
                {
                    Invoke(() =>
                    {
                        btnRefresh.Enabled = true;
                    });
                }
            }
        });
    }

    private async Task EnumerateModulesAsync(CancellationToken ct)
    {
        // Get module count first
        var result = NexusEngine.Nexus_EnumerateModules(_processHandle, null, 0, out nuint moduleCount);
        if (result != NexusResult.OK || moduleCount == 0)
        {
            Invoke(() =>
            {
                var node = tvSymbols.Nodes.Add("No modules found");
                node.ForeColor = Color.Gray;
                lblStatus.Text = "No modules found";
            });
            return;
        }

        // Get all modules
        var modules = new NexusModuleInfo[moduleCount];
        result = NexusEngine.Nexus_EnumerateModules(_processHandle, modules, moduleCount, out _);
        if (result != NexusResult.OK)
        {
            Invoke(() =>
            {
                var node = tvSymbols.Nodes.Add("Failed to enumerate modules");
                node.ForeColor = Color.Gray;
                lblStatus.Text = "Enumeration failed";
            });
            return;
        }

        int totalExports = 0;

        // Sort modules by name
        var sortedModules = modules.OrderBy(m => m.Name).ToArray();

        foreach (var module in sortedModules)
        {
            ct.ThrowIfCancellationRequested();

            // Add module node
            string moduleName = Path.GetFileName(module.Name);
            if (string.IsNullOrEmpty(moduleName))
                moduleName = module.Name;

            TreeNode? moduleNode = null;
            Invoke(() =>
            {
                moduleNode = tvSymbols.Nodes.Add($"{moduleName} (0x{module.BaseAddress:X})");
                moduleNode.Tag = module;
                lblStatus.Text = $"Loading {moduleName}...";
            });

            // Get exports for this module
            var exports = NexusEngine.GetModuleExports(_processHandle, module.BaseAddress);

            if (exports.Length > 0)
            {
                totalExports += exports.Length;

                // Sort exports by name
                var sortedExports = exports.OrderBy(e => e.Name).ToArray();

                Invoke(() =>
                {
                    tvSymbols.BeginUpdate();
                    try
                    {
                        foreach (var export in sortedExports)
                        {
                            string exportText = string.IsNullOrEmpty(export.Name)
                                ? $"0x{export.Address:X} - Ordinal #{export.Ordinal}"
                                : $"0x{export.Address:X} - {export.Name}";

                            var exportNode = moduleNode!.Nodes.Add(exportText);
                            exportNode.Tag = export;

                            if (export.IsForwarded != 0 && !string.IsNullOrEmpty(export.ForwardName))
                            {
                                exportNode.Text += $" -> {export.ForwardName}";
                                exportNode.ForeColor = Color.FromArgb(150, 150, 150);
                            }
                        }

                        moduleNode!.Text = $"{moduleName} (0x{module.BaseAddress:X}) [{exports.Length} exports]";
                    }
                    finally
                    {
                        tvSymbols.EndUpdate();
                    }
                });
            }

            // Small delay to keep UI responsive
            await Task.Delay(1, ct);
        }

        Invoke(() =>
        {
            lblStatus.Text = $"Found {sortedModules.Length} modules, {totalExports} exports";
        });
    }

    private void CancelEnumeration()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;
    }

    private void TvSymbols_NodeMouseDoubleClick(object? sender, TreeNodeMouseClickEventArgs e)
    {
        if (e.Node != null)
            NavigateToSymbol(e.Node);
    }

    private void TvSymbols_KeyDown(object? sender, KeyEventArgs e)
    {
        if (e.KeyCode == Keys.Enter && tvSymbols.SelectedNode != null)
        {
            NavigateToSymbol(tvSymbols.SelectedNode);
            e.Handled = true;
        }
    }

    private void NavigateToSymbol(TreeNode node)
    {
        if (node.Tag is NexusExportInfo export)
        {
            // Get the module base from parent node
            if (node.Parent?.Tag is NexusModuleInfo module)
            {
                ulong absoluteAddress = module.BaseAddress + export.Address;
                // Copy address to clipboard for now
                Clipboard.SetText($"{absoluteAddress:X}");
                lblStatus.Text = $"Address 0x{absoluteAddress:X} copied to clipboard";
            }
        }
        else if (node.Tag is NexusModuleInfo moduleInfo)
        {
            Clipboard.SetText($"{moduleInfo.BaseAddress:X}");
            lblStatus.Text = $"Module base 0x{moduleInfo.BaseAddress:X} copied to clipboard";
        }
    }

    private void CopySymbolName()
    {
        if (tvSymbols.SelectedNode != null)
        {
            if (tvSymbols.SelectedNode.Tag is NexusExportInfo export && !string.IsNullOrEmpty(export.Name))
            {
                Clipboard.SetText(export.Name);
                lblStatus.Text = $"Copied: {export.Name}";
            }
            else
            {
                Clipboard.SetText(tvSymbols.SelectedNode.Text);
                lblStatus.Text = "Copied to clipboard";
            }
        }
    }

    private void CopyAddress()
    {
        if (tvSymbols.SelectedNode?.Tag is NexusExportInfo export)
        {
            if (tvSymbols.SelectedNode.Parent?.Tag is NexusModuleInfo module)
            {
                ulong absoluteAddress = module.BaseAddress + export.Address;
                Clipboard.SetText($"{absoluteAddress:X}");
                lblStatus.Text = $"Copied: 0x{absoluteAddress:X}";
            }
        }
        else if (tvSymbols.SelectedNode?.Tag is NexusModuleInfo moduleInfo)
        {
            Clipboard.SetText($"{moduleInfo.BaseAddress:X}");
            lblStatus.Text = $"Copied: 0x{moduleInfo.BaseAddress:X}";
        }
    }

    #region Find Functionality

    private string _lastFindText = "";
    private int _lastFindIndex = -1;

    private void ShowFindDialog()
    {
        using var input = new Form
        {
            Text = "Find",
            Size = new Size(300, 120),
            FormBorderStyle = FormBorderStyle.FixedDialog,
            StartPosition = FormStartPosition.CenterParent,
            MaximizeBox = false,
            MinimizeBox = false
        };

        var txtFind = new TextBox
        {
            Text = _lastFindText,
            Location = new Point(10, 20),
            Width = 260
        };

        var btnFind = new Button
        {
            Text = "Find",
            DialogResult = DialogResult.OK,
            Location = new Point(100, 50),
            Width = 80
        };

        input.Controls.AddRange([txtFind, btnFind]);
        input.AcceptButton = btnFind;

        NexusTheme.StyleForm(input);

        if (input.ShowDialog(this) == DialogResult.OK && !string.IsNullOrEmpty(txtFind.Text))
        {
            _lastFindText = txtFind.Text;
            _lastFindIndex = -1;
            _miFindNext.Enabled = true;
            FindNext();
        }
    }

    private void FindNext()
    {
        if (string.IsNullOrEmpty(_lastFindText)) return;

        var allNodes = GetAllNodes(tvSymbols.Nodes);
        for (int i = _lastFindIndex + 1; i < allNodes.Count; i++)
        {
            if (allNodes[i].Text.Contains(_lastFindText, StringComparison.OrdinalIgnoreCase))
            {
                tvSymbols.SelectedNode = allNodes[i];
                allNodes[i].EnsureVisible();
                _lastFindIndex = i;
                lblStatus.Text = $"Found: {allNodes[i].Text}";
                return;
            }
        }

        // Wrap around or not found
        if (_lastFindIndex > 0)
        {
            _lastFindIndex = -1;
            FindNext(); // Try from beginning
        }
        else
        {
            lblStatus.Text = "Not found";
            System.Media.SystemSounds.Beep.Play();
        }
    }

    private static List<TreeNode> GetAllNodes(TreeNodeCollection nodes)
    {
        var result = new List<TreeNode>();
        foreach (TreeNode node in nodes)
        {
            result.Add(node);
            result.AddRange(GetAllNodes(node.Nodes));
        }
        return result;
    }

    #endregion

    /// <summary>
    /// Shows the DLL enumeration form.
    /// </summary>
    public static void ShowForm(IWin32Window? owner, IntPtr processHandle)
    {
        var form = new EnumerateDLLsForm(processHandle);
        if (owner != null)
            form.Show(owner);
        else
            form.Show();
    }

    // Controls
    private Button btnRefresh = null!;
    private Button btnExpand = null!;
    private Button btnCollapse = null!;
    private TreeView tvSymbols = null!;
    private StatusStrip statusStrip = null!;
    private ToolStripStatusLabel lblStatus = null!;
    private ToolStripMenuItem _miFindNext = null!;
}
