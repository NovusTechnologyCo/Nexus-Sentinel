// <file>
// <summary>
// Partial class for ApiMonPanel handling the detail view: parameter list with
// names/types/values, hex buffer display for raw parameter data, and call stack
// display for the selected API call event.
// </summary>
// </file>

using System.Text;
using Nexus.UI.Models;
using Nexus.UI.Styles;

namespace Nexus.UI.Panels;

public partial class ApiMonPanel
{
    /// <summary>
    /// Displays the details of a selected API call event.
    /// </summary>
    private void ShowEventDetails(ApiCallEvent evt)
    {
        // Parameters tab
        _parameterList.BeginUpdate();
        _parameterList.Items.Clear();

        foreach (var param in evt.Parameters)
        {
            var item = new ListViewItem(param.DirectionString);
            item.SubItems.Add(param.Name);
            item.SubItems.Add(param.Type);
            item.SubItems.Add(param.Value);
            item.Tag = param;

            // Color output parameters differently
            if (param.IsOutput)
                item.ForeColor = NexusTheme.Accent;

            _parameterList.Items.Add(item);
        }

        // Add return value as a special row
        if (!string.IsNullOrEmpty(evt.ReturnValue))
        {
            var retItem = new ListViewItem("RET");
            retItem.SubItems.Add("return");
            retItem.SubItems.Add("");
            retItem.SubItems.Add(evt.ReturnValue);
            retItem.ForeColor = evt.Success ? NexusTheme.Success : NexusTheme.Error;
            _parameterList.Items.Add(retItem);
        }

        _parameterList.EndUpdate();

        // Hex Buffer tab
        if (evt.Buffer != null && evt.Buffer.Length > 0)
        {
            _hexDumpBox.Text = FormatHexDump(evt.Buffer);
        }
        else
        {
            // Show hex dump of the first buffer parameter if available
            var bufferParam = evt.Parameters.FirstOrDefault(p => p.BufferData != null);
            if (bufferParam?.BufferData != null)
            {
                _hexDumpBox.Text = FormatHexDump(bufferParam.BufferData);
            }
            else
            {
                _hexDumpBox.Text = "(No buffer data available for this call)";
            }
        }

        // Call Stack tab
        _callStackList.BeginUpdate();
        _callStackList.Items.Clear();

        foreach (var frame in evt.CallStack)
        {
            var item = new ListViewItem(frame.Index.ToString());
            item.SubItems.Add(frame.AddressString);
            item.SubItems.Add(frame.Module);
            item.SubItems.Add(frame.FunctionDisplay);
            _callStackList.Items.Add(item);
        }

        _callStackList.EndUpdate();
    }

    /// <summary>
    /// Clears all detail panel tabs.
    /// </summary>
    private void ClearDetailPanel()
    {
        _parameterList.Items.Clear();
        _hexDumpBox.Text = "";
        _callStackList.Items.Clear();
    }

    /// <summary>
    /// Formats a byte array as a hex dump with addresses, hex values, and ASCII.
    /// </summary>
    private static string FormatHexDump(byte[] data)
    {
        var sb = new StringBuilder();
        int bytesPerLine = 16;

        for (int offset = 0; offset < data.Length; offset += bytesPerLine)
        {
            // Address
            sb.Append($"{offset:X8}  ");

            // Hex bytes
            int count = Math.Min(bytesPerLine, data.Length - offset);
            for (int i = 0; i < bytesPerLine; i++)
            {
                if (i < count)
                    sb.Append($"{data[offset + i]:X2} ");
                else
                    sb.Append("   ");

                if (i == 7) sb.Append(' '); // Gap at midpoint
            }

            sb.Append(" ");

            // ASCII representation
            for (int i = 0; i < count; i++)
            {
                byte b = data[offset + i];
                sb.Append(b is >= 32 and <= 126 ? (char)b : '.');
            }

            sb.AppendLine();
        }

        return sb.ToString();
    }
}
