using System.Drawing.Drawing2D;
using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using Nexus.UI.Styles;

namespace Nexus.UI.Forms;

public partial class MemoryViewerForm
{
    #region Memory Write Operations

    private void WriteByteAtSelection(byte value)
    {
        if (_processHandle == IntPtr.Zero) return;

        unsafe
        {
            NexusEngine.Nexus_WriteMemory(
                _processHandle,
                _selectedAddress,
                (IntPtr)(&value),
                1,
                out _);
        }
        RefreshMemory();
    }

    private void WriteValueAtSelection(byte[] bytes)
    {
        if (_processHandle == IntPtr.Zero || bytes.Length == 0) return;

        unsafe
        {
            fixed (byte* ptr = bytes)
            {
                NexusEngine.Nexus_WriteMemory(
                    _processHandle,
                    _selectedAddress,
                    (IntPtr)ptr,
                    (nuint)bytes.Length,
                    out _);
            }
        }
        RefreshMemory();
    }

    private void FillMemory(ulong startAddress, ulong length, byte value)
    {
        if (_processHandle == IntPtr.Zero) return;

        var buffer = new byte[length];
        Array.Fill(buffer, value);

        unsafe
        {
            fixed (byte* ptr = buffer)
            {
                NexusEngine.Nexus_WriteMemory(
                    _processHandle,
                    startAddress,
                    (IntPtr)ptr,
                    (nuint)length,
                    out _);
            }
        }
        RefreshMemory();
    }

    private void ShowEditValueDialog()
    {
        if (_processHandle == IntPtr.Zero) return;

        // Get current value based on display type
        string currentValue = "";
        int size = GetDisplayTypeSize();

        if (size > 0)
        {
            var bytes = new byte[size];
            unsafe
            {
                fixed (byte* ptr = bytes)
                {
                    NexusEngine.Nexus_ReadMemory(
                        _processHandle,
                        _selectedAddress,
                        (IntPtr)ptr,
                        (nuint)size,
                        out _);
                }
            }

            currentValue = cboDisplayType.SelectedIndex switch
            {
                0 => bytes[0].ToString(),
                1 => BitConverter.ToInt16(bytes, 0).ToString(),
                2 => BitConverter.ToInt32(bytes, 0).ToString(),
                3 => BitConverter.ToInt64(bytes, 0).ToString(),
                4 => BitConverter.ToSingle(bytes, 0).ToString("G"),
                5 => BitConverter.ToDouble(bytes, 0).ToString("G"),
                _ => bytes[0].ToString()
            };
        }

        using var dialog = new ChangeValueForm(currentValue, false);
        dialog.Text = "Edit Value";
        if (dialog.ShowDialog(this) == DialogResult.OK)
        {
            byte[]? bytes = null;
            try
            {
                bytes = cboDisplayType.SelectedIndex switch
                {
                    0 => [byte.Parse(dialog.Value)],
                    1 => BitConverter.GetBytes(short.Parse(dialog.Value)),
                    2 => BitConverter.GetBytes(int.Parse(dialog.Value)),
                    3 => BitConverter.GetBytes(long.Parse(dialog.Value)),
                    4 => BitConverter.GetBytes(float.Parse(dialog.Value)),
                    5 => BitConverter.GetBytes(double.Parse(dialog.Value)),
                    _ => [byte.Parse(dialog.Value)]
                };
            }
            catch
            {
                MessageBox.Show("Invalid value", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            if (bytes != null)
            {
                WriteValueAtSelection(bytes);
            }
        }
    }

    private int GetDisplayTypeSize()
    {
        return cboDisplayType.SelectedIndex switch
        {
            0 => 1, // Byte
            1 => 2, // 2 Bytes
            2 => 4, // 4 Bytes
            3 => 8, // 8 Bytes
            4 => 4, // Float
            5 => 8, // Double
            _ => 1
        };
    }

    #endregion
}
