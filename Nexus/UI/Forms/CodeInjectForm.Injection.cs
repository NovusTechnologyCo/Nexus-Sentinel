// <file>
// <summary>
// Code injection logic — shellcode, DLL, and code cave injection operations.
// </summary>
// </file>
using Nexus.UI.Helpers;
using Nexus.UI.Interop;


namespace Nexus.UI.Forms;

public partial class CodeInjectForm
{
    private void BrowseDll()
    {
        using var dialog = new OpenFileDialog
        {
            Filter = "DLL files (*.dll)|*.dll|All files (*.*)|*.*",
            Title = "Select DLL to inject"
        };

        if (dialog.ShowDialog() == DialogResult.OK)
        {
            _txtDllPath.Text = dialog.FileName;
        }
    }

    private void DoInject()
    {
        try
        {
            switch (_selectedTab)
            {
                case 0:
                    InjectShellcode();
                    break;
                case 1:
                    InjectDll();
                    break;
                case 2:
                    InjectCodeCave();
                    break;
            }
        }
        catch (Exception ex)
        {
            _lblStatus.Text = $"Error: {ex.Message}";
            _lblStatus.ForeColor = Color.Red;
        }
    }

    private void InjectShellcode()
    {
        var hexText = _txtShellcode.Text
            .Replace("\n", " ")
            .Replace("\r", " ")
            .Replace("\t", " ");

        var bytes = ParseHexBytes(hexText);
        if (bytes.Length == 0)
        {
            MessageBox.Show("No valid shellcode bytes entered", "Error",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        // Use engine's shellcode injection
        var ptr = System.Runtime.InteropServices.Marshal.AllocHGlobal(bytes.Length);
        try
        {
            System.Runtime.InteropServices.Marshal.Copy(bytes, 0, ptr, bytes.Length);

            var result = NexusEngine.Nexus_InjectShellcode(
                _processHandle,
                ptr,
                (nuint)bytes.Length,
                out ulong execAddr);

            if (result == NexusResult.Success || result == NexusResult.OK)
            {
                _lblStatus.Text = $"Shellcode injected at 0x{execAddr:X}";
                _lblStatus.ForeColor = Color.Green;

                if (_chkExecuteShellcode.Checked)
                {
                    // Execute via CreateRemoteThread
                    var execResult = NexusEngine.Nexus_CreateRemoteThread(
                        _processHandle, execAddr, 0, out uint threadId);

                    if (execResult == NexusResult.Success || execResult == NexusResult.OK)
                    {
                        MessageBox.Show($"Shellcode executed.\n" +
                            $"Address: 0x{execAddr:X}\n" +
                            $"Thread: {threadId}",
                            "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                    else
                    {
                        MessageBox.Show($"Shellcode written but execution failed: {NexusHelper.GetErrorMessage(execResult)}",
                            "Warning", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    }
                }
                else
                {
                    MessageBox.Show($"Shellcode written to 0x{execAddr:X}\n(not executed)",
                        "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
            else
            {
                MessageBox.Show($"Failed to inject shellcode: {NexusHelper.GetErrorMessage(result)}",
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
        finally
        {
            System.Runtime.InteropServices.Marshal.FreeHGlobal(ptr);
        }
    }

    private void InjectDll()
    {
        if (string.IsNullOrEmpty(_txtDllPath.Text) || !File.Exists(_txtDllPath.Text))
        {
            MessageBox.Show("Please select a valid DLL file", "Error",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        var method = (NexusInjectionMethod)_cboInjectionMethod.SelectedIndex;

        NexusResult result;
        NexusEngine.NexusInjectResult injectResult;

        switch (method)
        {
            case NexusInjectionMethod.LoadLibrary:
                result = NexusEngine.Nexus_InjectDllEx(
                    _processHandle,
                    _txtDllPath.Text,
                    (uint)NexusEngine.NexusInjectMethod.LoadLibrary,
                    (uint)NexusEngine.NexusInjectFlags.Wait,
                    5000,
                    out injectResult);
                break;

            case NexusInjectionMethod.ManualMap:
                result = NexusEngine.Nexus_InjectDllManualMap(
                    _processHandle,
                    _txtDllPath.Text,
                    (uint)(NexusEngine.NexusInjectFlags.HideFromPeb | NexusEngine.NexusInjectFlags.EraseHeaders),
                    out injectResult);
                break;

            case NexusInjectionMethod.ThreadHijack:
                result = NexusEngine.Nexus_InjectDllEx(
                    _processHandle,
                    _txtDllPath.Text,
                    (uint)NexusEngine.NexusInjectMethod.ThreadHijack,
                    (uint)NexusEngine.NexusInjectFlags.Wait,
                    5000,
                    out injectResult);
                break;

            case NexusInjectionMethod.Apc:
                result = NexusEngine.Nexus_InjectDllEx(
                    _processHandle,
                    _txtDllPath.Text,
                    (uint)NexusEngine.NexusInjectMethod.ApcQueue,
                    (uint)NexusEngine.NexusInjectFlags.Wait,
                    5000,
                    out injectResult);
                break;

            default:
                MessageBox.Show("Unknown injection method", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
        }

        if ((result == NexusResult.Success || result == NexusResult.OK) && injectResult.Success != 0)
        {
            _lblStatus.Text = $"DLL loaded at 0x{injectResult.ModuleBase:X}";
            _lblStatus.ForeColor = Color.Green;
            MessageBox.Show($"DLL injected via {method}.\n" +
                $"Base: 0x{injectResult.ModuleBase:X}\n" +
                $"Entry: 0x{injectResult.EntryPoint:X}",
                "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        else
        {
            var errorMsg = !string.IsNullOrEmpty(injectResult.ErrorMessage)
                ? injectResult.ErrorMessage
                : NexusHelper.GetErrorMessage(result);
            MessageBox.Show($"{method} injection failed:\n{errorMsg}",
                "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void InjectCodeCave()
    {
        if (!ulong.TryParse(_txtTargetAddr.Text.Replace("0x", ""),
            System.Globalization.NumberStyles.HexNumber, null, out var targetAddr))
        {
            MessageBox.Show("Invalid target address", "Error",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        int caveSize = (int)_nudCaveSize.Value;

        // Allocate memory for code cave
        var allocResult = NexusEngine.Nexus_AllocateMemory(
            _processHandle,
            (nuint)caveSize,
            0x40, // PAGE_EXECUTE_READWRITE
            out var caveAddr);

        if (allocResult != NexusResult.Success && allocResult != NexusResult.OK)
        {
            MessageBox.Show($"Failed to allocate code cave: {NexusHelper.GetErrorMessage(allocResult)}",
                "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        // Read original bytes at target (enough for a jump - 14 bytes for far jmp on x64)
        const int jumpSize = 14; // jmp [rip+0]; dq address
        var originalBytes = new byte[jumpSize];
        var readResult = NexusEngine.Nexus_ReadProcessMemory(
            _processHandle, targetAddr, originalBytes, (nuint)jumpSize, out _);

        if (readResult != NexusResult.Success && readResult != NexusResult.OK)
        {
            NexusEngine.Nexus_FreeMemory(_processHandle, caveAddr);
            MessageBox.Show($"Failed to read original bytes: {NexusHelper.GetErrorMessage(readResult)}",
                "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        // Parse user's shellcode from the textbox
        var userCode = _txtCaveCode.Text
            .Split('\n')
            .Where(l => !l.TrimStart().StartsWith("//")) // Skip comments
            .SelectMany(l => l.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            .Where(s => s.Length == 2 && s.All(c => char.IsAsciiHexDigit(c)))
            .Select(s => byte.Parse(s, System.Globalization.NumberStyles.HexNumber))
            .ToList();

        if (userCode.Count == 0)
        {
            // Show help for entering raw bytes
            MessageBox.Show(
                "Code cave requires raw bytes (hex).\n\n" +
                "Enter bytes like: 50 53 48 8B C1\n" +
                "(Use // for comments)\n\n" +
                "Code cave allocated at: 0x" + caveAddr.ToString("X") + "\n" +
                "You can write bytes there manually.",
                "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);

            _lblStatus.Text = $"Cave at 0x{caveAddr:X} (no code written)";
            _lblStatus.ForeColor = Color.Orange;
            return;
        }

        // Build cave code: user code + original bytes + jump back
        var caveCode = new List<byte>(userCode);

        // Add original bytes (what we're overwriting at target)
        caveCode.AddRange(originalBytes);

        // Add jump back to target + jumpSize (after the jump we're placing)
        ulong returnAddr = targetAddr + jumpSize;
        // jmp [rip+0] = FF 25 00 00 00 00 + 8-byte address
        caveCode.AddRange(new byte[] { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 });
        caveCode.AddRange(BitConverter.GetBytes(returnAddr));

        // Write cave code
        var ptr = System.Runtime.InteropServices.Marshal.AllocHGlobal(caveCode.Count);
        try
        {
            System.Runtime.InteropServices.Marshal.Copy(caveCode.ToArray(), 0, ptr, caveCode.Count);
            var writeResult = NexusEngine.Nexus_WriteMemory(
                _processHandle, caveAddr, ptr, (nuint)caveCode.Count, out _);

            if (writeResult != NexusResult.Success && writeResult != NexusResult.OK)
            {
                NexusEngine.Nexus_FreeMemory(_processHandle, caveAddr);
                MessageBox.Show($"Failed to write cave code: {NexusHelper.GetErrorMessage(writeResult)}",
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
        }
        finally
        {
            System.Runtime.InteropServices.Marshal.FreeHGlobal(ptr);
        }

        // Build jump to cave: jmp [rip+0] = FF 25 00 00 00 00 + 8-byte address
        var jumpBytes = new byte[14];
        jumpBytes[0] = 0xFF;
        jumpBytes[1] = 0x25;
        // [rip+0] displacement is 0
        Buffer.BlockCopy(BitConverter.GetBytes(caveAddr), 0, jumpBytes, 6, 8);

        // NOP remaining bytes if requested
        if (_chkAutoNop.Checked && jumpSize < originalBytes.Length)
        {
            // Already using all 14 bytes for jump
        }

        // Write jump at target
        var jumpPtr = System.Runtime.InteropServices.Marshal.AllocHGlobal(jumpBytes.Length);
        try
        {
            System.Runtime.InteropServices.Marshal.Copy(jumpBytes, 0, jumpPtr, jumpBytes.Length);
            var patchResult = NexusEngine.Nexus_WriteMemory(
                _processHandle, targetAddr, jumpPtr, (nuint)jumpBytes.Length, out _);

            if (patchResult != NexusResult.Success && patchResult != NexusResult.OK)
            {
                MessageBox.Show($"Failed to write jump at target: {NexusHelper.GetErrorMessage(patchResult)}",
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
        }
        finally
        {
            System.Runtime.InteropServices.Marshal.FreeHGlobal(jumpPtr);
        }

        _lblStatus.Text = $"Code cave at 0x{caveAddr:X}";
        _lblStatus.ForeColor = Color.Green;
        MessageBox.Show($"Code cave injection successful!\n\n" +
            $"Target: 0x{targetAddr:X}\n" +
            $"Cave: 0x{caveAddr:X}\n" +
            $"Cave size: {caveCode.Count} bytes\n" +
            $"Original bytes saved and will execute in cave.",
            "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private byte[] ParseHexBytes(string hex)
    {
        var parts = hex.Split(new[] { ' ', ',', ';' },
            StringSplitOptions.RemoveEmptyEntries);
        var bytes = new List<byte>();

        foreach (var part in parts)
        {
            var clean = part.Trim().Replace("0x", "").Replace("\\x", "");
            if (byte.TryParse(clean, System.Globalization.NumberStyles.HexNumber,
                null, out var b))
            {
                bytes.Add(b);
            }
        }

        return bytes.ToArray();
    }
}
