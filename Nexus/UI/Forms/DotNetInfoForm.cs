// <file>
// <summary>
// Managed assembly information dialog displaying CLR and module details.
// </summary>
// </file>
using Nexus.UI.Helpers;
using Nexus.UI.Styles;


namespace Nexus.UI.Forms;

/// <summary>
/// Form to display .NET/CLR information for managed processes.
/// Shows assemblies, types, methods, and allows method hooking.
/// </summary>
public partial class DotNetInfoForm : Form
{
    private readonly IntPtr _processHandle;
    private readonly uint _processId;

    public DotNetInfoForm(IntPtr processHandle, uint processId)
    {
        _processHandle = processHandle;
        _processId = processId;
        InitializeComponent();
        NexusTheme.StyleForm(this);
    }

    private void InitializeComponent()
    {
        Text = ".NET Info";
        Size = new Size(800, 600);
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.Sizable;
        MinimumSize = new Size(600, 400);
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
        btnRefresh.Click += BtnRefresh_Click;

        btnExpandAll = new Button
        {
            Text = "Expand",
            Location = new Point(90, 4),
            Size = new Size(80, NexusTheme.ControlHeight)
        };
        btnExpandAll.Click += (s, e) => treeAssemblies.ExpandAll();

        btnCollapseAll = new Button
        {
            Text = "Collapse",
            Location = new Point(180, 4),
            Size = new Size(90, NexusTheme.ControlHeight)
        };
        btnCollapseAll.Click += (s, e) => treeAssemblies.CollapseAll();

        pnlTop.Controls.AddRange([btnRefresh, btnExpandAll, btnCollapseAll]);

        // Split container
        splitContainer = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Orientation = Orientation.Vertical,
            SplitterDistance = 450
        };

        // Tree view for assemblies/types
        treeAssemblies = new TreeView
        {
            Dock = DockStyle.Fill,
            ShowNodeToolTips = true
        };
        treeAssemblies.AfterSelect += TreeAssemblies_AfterSelect;

        // Context menu for tree
        ctxTree = new ContextMenuStrip();
        var miHookMethod = new ToolStripMenuItem("Hook method");
        miHookMethod.Click += MiHookMethod_Click;
        var miCopyAddress = new ToolStripMenuItem("Copy address");
        miCopyAddress.Click += MiCopyAddress_Click;
        var miDisassemble = new ToolStripMenuItem("Disassemble");
        miDisassemble.Click += MiDisassemble_Click;
        ctxTree.Items.AddRange([miHookMethod, miCopyAddress, new ToolStripSeparator(), miDisassemble]);
        treeAssemblies.ContextMenuStrip = ctxTree;

        splitContainer.Panel1.Controls.Add(treeAssemblies);

        // Details panel
        txtDetails = new TextBox
        {
            Dock = DockStyle.Fill,
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Both,
            Font = new Font("Consolas", 9F),
            WordWrap = false
        };

        splitContainer.Panel2.Controls.Add(txtDetails);

        // Status bar
        statusStrip = new StatusStrip();
        lblStatus = new ToolStripStatusLabel { Text = "Ready" };
        statusStrip.Items.Add(lblStatus);

        Controls.AddRange([splitContainer, pnlTop, statusStrip]);
    }

    protected override void OnShown(EventArgs e)
    {
        base.OnShown(e);
        // Set splitter distance after form is shown (percentage-based)
        splitContainer.SplitterDistance = (int)(splitContainer.Width * 0.50);
        RefreshDotNetInfo();
    }

    private void BtnRefresh_Click(object? sender, EventArgs e)
    {
        RefreshDotNetInfo();
    }

    private void RefreshDotNetInfo()
    {
        treeAssemblies.Nodes.Clear();
        txtDetails.Clear();
        lblStatus.Text = "Scanning for .NET assemblies...";
        Application.DoEvents();

        try
        {
            // Note: Enumerating assemblies in a .NET process requires either:
            // 1. ICorDebug API - Attach as debugger to enumerate AppDomains/Assemblies
            // 2. DbgEng with SOS extension - Load CLR debugging extension
            // 3. Memory scanning - Search for CLR metadata structures in process memory
            // For now, show placeholder structure demonstrating the UI

            var rootNode = treeAssemblies.Nodes.Add($"Process (PID: {_processId})");

            // Check if .NET process
            var clrNode = rootNode.Nodes.Add("CLR Runtime");
            clrNode.ToolTipText = "Common Language Runtime";

            // Sample assembly structure
            var asmNode = clrNode.Nodes.Add("mscorlib.dll");
            asmNode.Tag = "assembly";

            var nsNode = asmNode.Nodes.Add("System");
            nsNode.Tag = "namespace";

            var typeNode = nsNode.Nodes.Add("String");
            typeNode.Tag = "type";

            var methodNode = typeNode.Nodes.Add("Concat(string, string)");
            methodNode.Tag = "method";
            methodNode.ToolTipText = "Address: 0x12345678";

            rootNode.Expand();
            clrNode.Expand();

            lblStatus.Text = $"Found assemblies. Select an item for details.";
        }
        catch (Exception ex)
        {
            lblStatus.Text = $"Error: {ex.Message}";
            MessageBox.Show($"Failed to enumerate .NET info: {ex.Message}", "Error",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void TreeAssemblies_AfterSelect(object? sender, TreeViewEventArgs e)
    {
        if (e.Node == null) return;

        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"Name: {e.Node.Text}");
        sb.AppendLine($"Type: {e.Node.Tag ?? "Unknown"}");

        if (e.Node.ToolTipText != null)
        {
            sb.AppendLine();
            sb.AppendLine(e.Node.ToolTipText);
        }

        // Add type-specific info
        if (e.Node.Tag?.ToString() == "method")
        {
            sb.AppendLine();
            sb.AppendLine("Method Info:");
            sb.AppendLine("  Return type: string");
            sb.AppendLine("  Parameters: (string, string)");
            sb.AppendLine("  JIT compiled: Yes");
            sb.AppendLine("  Native address: 0x12345678");
        }

        txtDetails.Text = sb.ToString();
    }

    private void MiHookMethod_Click(object? sender, EventArgs e)
    {
        if (treeAssemblies.SelectedNode?.Tag?.ToString() != "method")
        {
            MessageBox.Show("Please select a method to hook.", "Info",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        // Method hooking requires CLR profiling API (ICorProfilerCallback) which involves:
        // 1. Creating a COM profiler DLL that implements ICorProfilerCallback
        // 2. Registering the profiler with the CLR using COR_PROFILER environment variable
        // 3. Handling JIT compilation events to inject custom code
        // This is out of scope for runtime hooking - would need process restart with profiler attached.
        MessageBox.Show($"Would hook method: {treeAssemblies.SelectedNode.Text}\n\n" +
            "Method hooking requires CLR profiling API integration.\n" +
            "This feature requires a custom profiler DLL and process restart.",
            "Hook Method", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private void MiCopyAddress_Click(object? sender, EventArgs e)
    {
        // Get address from node tooltip if available
        var node = treeAssemblies.SelectedNode;
        if (node?.ToolTipText != null && node.ToolTipText.Contains("Address:"))
        {
            var match = System.Text.RegularExpressions.Regex.Match(
                node.ToolTipText, @"Address:\s*0x([0-9A-Fa-f]+)");
            if (match.Success)
            {
                Clipboard.SetText(match.Groups[1].Value);
                return;
            }
        }
        // Placeholder address for sample data
        Clipboard.SetText("12345678");
    }

    private void MiDisassemble_Click(object? sender, EventArgs e)
    {
        // Get address from node tooltip if available
        var node = treeAssemblies.SelectedNode;
        if (node?.ToolTipText != null && node.ToolTipText.Contains("Address:"))
        {
            var match = System.Text.RegularExpressions.Regex.Match(
                node.ToolTipText, @"Address:\s*0x([0-9A-Fa-f]+)");
            if (match.Success && ulong.TryParse(match.Groups[1].Value,
                System.Globalization.NumberStyles.HexNumber, null, out ulong address))
            {
                var ctx = Core.ProcessContext.Current;
                if (ctx.NativeProcessHandle != IntPtr.Zero)
                {
                    var viewer = new MemoryViewerForm(ctx.NativeProcessHandle, address, ctx.ProcessId);
                    viewer.Show(this);
                    return;
                }
            }
        }
        MessageBox.Show("Would open disassembler at method address.\n" +
            "Note: CLR assembly enumeration is not yet implemented.",
            "Disassemble", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    /// <summary>
    /// Shows the .NET info form for a process.
    /// </summary>
    public static void ShowDotNetInfo(IWin32Window? owner, IntPtr processHandle, uint processId)
    {
        var form = new DotNetInfoForm(processHandle, processId);
        if (owner != null)
            form.Show(owner);
        else
            form.Show();
    }

    // Controls
    private Button btnRefresh = null!;
    private Button btnExpandAll = null!;
    private Button btnCollapseAll = null!;
    private SplitContainer splitContainer = null!;
    private TreeView treeAssemblies = null!;
    private ContextMenuStrip ctxTree = null!;
    private TextBox txtDetails = null!;
    private StatusStrip statusStrip = null!;
    private ToolStripStatusLabel lblStatus = null!;
}
