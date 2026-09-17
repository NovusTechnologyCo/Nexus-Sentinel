// <file>
// <summary>
// Network connections viewer showing TCP/UDP connections for the process.
// </summary>
// </file>
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using Nexus.UI.Styles;

namespace Nexus.UI.Forms;

/// <summary>
/// Form to display network connections for a process.
/// </summary>
public class NetworkConnectionsForm : Form
{
    private readonly uint _processId;
    private ListView _lvConnections = null!;
    private Button _btnRefresh = null!;
    private ToolStripStatusLabel _lblStatus = null!;
    private CheckBox _chkTcp = null!;
    private CheckBox _chkUdp = null!;

    public NetworkConnectionsForm(uint processId)
    {
        _processId = processId;
        InitializeComponent();
        NexusTheme.StyleForm(this);
    }

    private void InitializeComponent()
    {
        Text = $"Network Connections - PID {_processId}";
        Size = new Size(800, 500);
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.Sizable;
        MinimumSize = new Size(500, 300);

        // Top panel with controls
        var pnlTop = new Panel
        {
            Dock = DockStyle.Top,
            Height = 40
        };

        _btnRefresh = new Button
        {
            Text = "Refresh",
            Location = new Point(8, 8),
            Size = new Size(80, 24)
        };
        _btnRefresh.Click += (s, e) => RefreshConnections();

        _chkTcp = new CheckBox
        {
            Text = "TCP",
            Location = new Point(100, 10),
            Checked = true,
            AutoSize = true
        };
        _chkTcp.CheckedChanged += (s, e) => RefreshConnections();

        _chkUdp = new CheckBox
        {
            Text = "UDP",
            Location = new Point(160, 10),
            Checked = true,
            AutoSize = true
        };
        _chkUdp.CheckedChanged += (s, e) => RefreshConnections();

        pnlTop.Controls.AddRange([_btnRefresh, _chkTcp, _chkUdp]);

        // ListView for connections
        _lvConnections = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            GridLines = true,
            Font = new Font("Consolas", 9F)
        };

        _lvConnections.Columns.Add("Protocol", 60);
        _lvConnections.Columns.Add("Local Address", 180);
        _lvConnections.Columns.Add("Local Port", 80);
        _lvConnections.Columns.Add("Remote Address", 180);
        _lvConnections.Columns.Add("Remote Port", 80);
        _lvConnections.Columns.Add("State", 100);

        // Context menu
        var ctxMenu = new ContextMenuStrip();
        ctxMenu.Items.Add("Copy Local Address", null, (s, e) => CopyColumn(1));
        ctxMenu.Items.Add("Copy Remote Address", null, (s, e) => CopyColumn(3));
        ctxMenu.Items.Add("Copy Row", null, (s, e) => CopyRow());
        _lvConnections.ContextMenuStrip = ctxMenu;

        // Status bar
        var statusStrip = new StatusStrip();
        _lblStatus = new ToolStripStatusLabel { Text = "Ready" };
        statusStrip.Items.Add(_lblStatus);

        Controls.Add(_lvConnections);
        Controls.Add(pnlTop);
        Controls.Add(statusStrip);
    }

    protected override void OnShown(EventArgs e)
    {
        base.OnShown(e);
        RefreshConnections();
    }

    private void RefreshConnections()
    {
        _lvConnections.BeginUpdate();
        _lvConnections.Items.Clear();

        int tcpCount = 0, udpCount = 0;

        try
        {
            if (_chkTcp.Checked)
            {
                tcpCount = EnumerateTcpConnections();
            }

            if (_chkUdp.Checked)
            {
                udpCount = EnumerateUdpConnections();
            }
        }
        catch (Exception ex)
        {
            _lblStatus.Text = $"Error: {ex.Message}";
        }
        finally
        {
            _lvConnections.EndUpdate();
        }

        _lblStatus.Text = $"Found {tcpCount} TCP, {udpCount} UDP connections for PID {_processId}";
    }

    private int EnumerateTcpConnections()
    {
        int count = 0;

        // Get TCP table
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, false, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);

        IntPtr tcpTable = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(tcpTable, ref size, false, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0) == 0)
            {
                int rowCount = Marshal.ReadInt32(tcpTable);
                IntPtr rowPtr = tcpTable + 4;

                for (int i = 0; i < rowCount; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                    rowPtr += Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

                    if (row.dwOwningPid == _processId)
                    {
                        var localAddr = new IPAddress(row.dwLocalAddr);
                        var remoteAddr = new IPAddress(row.dwRemoteAddr);
                        int localPort = (int)(((row.dwLocalPort & 0xFF) << 8) | ((row.dwLocalPort >> 8) & 0xFF));
                        int remotePort = (int)(((row.dwRemotePort & 0xFF) << 8) | ((row.dwRemotePort >> 8) & 0xFF));

                        var lvi = new ListViewItem("TCP");
                        lvi.SubItems.Add(localAddr.ToString());
                        lvi.SubItems.Add(localPort.ToString());
                        lvi.SubItems.Add(remoteAddr.ToString());
                        lvi.SubItems.Add(remotePort.ToString());
                        lvi.SubItems.Add(GetTcpStateName(row.dwState));
                        _lvConnections.Items.Add(lvi);
                        count++;
                    }
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(tcpTable);
        }

        return count;
    }

    private int EnumerateUdpConnections()
    {
        int count = 0;

        // Get UDP table
        int size = 0;
        GetExtendedUdpTable(IntPtr.Zero, ref size, false, AF_INET, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);

        IntPtr udpTable = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedUdpTable(udpTable, ref size, false, AF_INET, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0) == 0)
            {
                int rowCount = Marshal.ReadInt32(udpTable);
                IntPtr rowPtr = udpTable + 4;

                for (int i = 0; i < rowCount; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(rowPtr);
                    rowPtr += Marshal.SizeOf<MIB_UDPROW_OWNER_PID>();

                    if (row.dwOwningPid == _processId)
                    {
                        var localAddr = new IPAddress(row.dwLocalAddr);
                        int localPort = (int)(((row.dwLocalPort & 0xFF) << 8) | ((row.dwLocalPort >> 8) & 0xFF));

                        var lvi = new ListViewItem("UDP");
                        lvi.SubItems.Add(localAddr.ToString());
                        lvi.SubItems.Add(localPort.ToString());
                        lvi.SubItems.Add("*");
                        lvi.SubItems.Add("*");
                        lvi.SubItems.Add("-");
                        _lvConnections.Items.Add(lvi);
                        count++;
                    }
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(udpTable);
        }

        return count;
    }

    private static string GetTcpStateName(uint state)
    {
        return state switch
        {
            1 => "CLOSED",
            2 => "LISTEN",
            3 => "SYN_SENT",
            4 => "SYN_RCVD",
            5 => "ESTABLISHED",
            6 => "FIN_WAIT1",
            7 => "FIN_WAIT2",
            8 => "CLOSE_WAIT",
            9 => "CLOSING",
            10 => "LAST_ACK",
            11 => "TIME_WAIT",
            12 => "DELETE_TCB",
            _ => $"UNKNOWN({state})"
        };
    }

    private void CopyColumn(int columnIndex)
    {
        if (_lvConnections.SelectedItems.Count > 0)
        {
            var text = _lvConnections.SelectedItems[0].SubItems[columnIndex].Text;
            Clipboard.SetText(text);
        }
    }

    private void CopyRow()
    {
        if (_lvConnections.SelectedItems.Count > 0)
        {
            var item = _lvConnections.SelectedItems[0];
            var parts = new List<string>();
            foreach (ListViewItem.ListViewSubItem sub in item.SubItems)
            {
                parts.Add(sub.Text);
            }
            Clipboard.SetText(string.Join("\t", parts));
        }
    }

    #region P/Invoke

    private const int AF_INET = 2;

    private enum TCP_TABLE_CLASS
    {
        TCP_TABLE_BASIC_LISTENER,
        TCP_TABLE_BASIC_CONNECTIONS,
        TCP_TABLE_BASIC_ALL,
        TCP_TABLE_OWNER_PID_LISTENER,
        TCP_TABLE_OWNER_PID_CONNECTIONS,
        TCP_TABLE_OWNER_PID_ALL,
        TCP_TABLE_OWNER_MODULE_LISTENER,
        TCP_TABLE_OWNER_MODULE_CONNECTIONS,
        TCP_TABLE_OWNER_MODULE_ALL
    }

    private enum UDP_TABLE_CLASS
    {
        UDP_TABLE_BASIC,
        UDP_TABLE_OWNER_PID,
        UDP_TABLE_OWNER_MODULE
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
        public uint dwOwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UDPROW_OWNER_PID
    {
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwOwningPid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int pdwSize,
        bool bOrder,
        int ulAf,
        TCP_TABLE_CLASS TableClass,
        int Reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetExtendedUdpTable(
        IntPtr pUdpTable,
        ref int pdwSize,
        bool bOrder,
        int ulAf,
        UDP_TABLE_CLASS TableClass,
        int Reserved);

    #endregion
}
