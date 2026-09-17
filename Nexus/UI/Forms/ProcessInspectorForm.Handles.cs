// <file>
// <summary>
// Process inspector: handles tab and heaps tab logic.
// </summary>
// </file>
using System.Runtime.InteropServices;
using Nexus.UI.Helpers;
using Nexus.UI.Interop;
using Nexus.UI.Providers;
using Nexus.UI.Styles;
using static Nexus.UI.UIHelpers;

namespace Nexus.UI.Forms;

public partial class ProcessInspectorForm
{
    #region Handles Tab

    private void RefreshHandles()
    {
        _allHandles.Clear();
        try { EnumerateHandles(); }
        catch (Exception ex) { MessageBox.Show($"Failed: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error); }
        ApplyHandleFilter();
    }

    private void EnumerateHandles()
    {
        int bufferSize = 0x10000;
        IntPtr buffer = IntPtr.Zero;
        try
        {
            while (true)
            {
                buffer = Marshal.AllocHGlobal(bufferSize);
                int status = NtQuerySystemInformation(SystemHandleInformation, buffer, bufferSize, out int returnLength);
                if (status == STATUS_INFO_LENGTH_MISMATCH) { Marshal.FreeHGlobal(buffer); buffer = IntPtr.Zero; bufferSize *= 2; continue; }
                if (status != 0) throw new Exception($"NtQuerySystemInformation failed: 0x{status:X8}");
                break;
            }

            int handleCount = Marshal.ReadInt32(buffer);
            IntPtr handleEntry = buffer + IntPtr.Size;

            for (int i = 0; i < handleCount && i < 100000; i++)
            {
                var handle = Marshal.PtrToStructure<SYSTEM_HANDLE_ENTRY>(handleEntry);
                if (handle.OwnerPid == _processId)
                {
                    _allHandles.Add(new HandleEntry
                    {
                        Handle = handle.HandleValue, ObjectType = handle.ObjectType,
                        GrantedAccess = handle.GrantedAccess, TypeName = GetHandleTypeName(handle.ObjectType), Name = ""
                    });
                }
                handleEntry += Marshal.SizeOf<SYSTEM_HANDLE_ENTRY>();
            }
        }
        finally { if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer); }
    }

    private string GetHandleTypeName(byte typeIndex) => typeIndex switch
    {
        7 => "Process", 8 => "Thread", 12 => "Event", 13 => "Mutant", 32 => "File",
        37 => "Section", 40 => "Key", 3 => "Directory", _ => $"Type_{typeIndex}"
    };

    private void ApplyHandleFilter()
    {
        var textFilter = _txtHandleFilter.Text.ToLowerInvariant();
        var typeFilter = _cboHandleType.SelectedIndex > 0 ? _cboHandleType.Text : null;

        _lvHandles.BeginUpdate();
        _lvHandles.Items.Clear();

        foreach (var h in _allHandles)
        {
            if (typeFilter != null && !h.TypeName.Equals(typeFilter, StringComparison.OrdinalIgnoreCase)) continue;
            if (!string.IsNullOrEmpty(textFilter) && !h.Name.ToLowerInvariant().Contains(textFilter) &&
                !h.TypeName.ToLowerInvariant().Contains(textFilter)) continue;

            var item = new ListViewItem($"0x{h.Handle:X}");
            item.SubItems.Add(h.TypeName);
            item.SubItems.Add($"0x{h.GrantedAccess:X8}");
            item.SubItems.Add(h.Name);
            item.Tag = h;
            _lvHandles.Items.Add(item);
        }
        _lvHandles.EndUpdate();
        _lblHandleCount.Text = _lvHandles.Items.Count != _allHandles.Count
            ? $"{_lvHandles.Items.Count} handles (of {_allHandles.Count})" : $"{_lvHandles.Items.Count} handles";
    }

    private HandleEntry? GetSelectedHandle() =>
        _lvHandles.SelectedItems.Count > 0 ? _lvHandles.SelectedItems[0].Tag as HandleEntry : null;

    private void CopyHandleValue() { var h = GetSelectedHandle(); if (h != null) Clipboard.SetText($"0x{h.Handle:X}"); }
    private void CopyHandleName() { var h = GetSelectedHandle(); if (h != null) Clipboard.SetText(h.Name); }

    private void CloseSelectedHandle()
    {
        var h = GetSelectedHandle(); if (h == null) return;
        if (MessageBox.Show($"Close handle 0x{h.Handle:X} ({h.TypeName})?\n\nWarning: May crash target!",
            "Confirm", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;

        IntPtr hProcess = OpenProcess(PROCESS_DUP_HANDLE, false, _processId);
        if (hProcess == IntPtr.Zero) { MessageBox.Show("Failed to open process.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error); return; }

        try
        {
            bool success = DuplicateHandle(hProcess, (IntPtr)h.Handle, GetCurrentProcess(), out IntPtr dup, 0, false, DUPLICATE_CLOSE_SOURCE);
            if (success) { if (dup != IntPtr.Zero) CloseHandle(dup); MessageBox.Show("Handle closed.", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information); RefreshHandles(); }
            else MessageBox.Show($"Failed. Error: {Marshal.GetLastWin32Error()}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally { CloseHandle(hProcess); }
    }

    #endregion

    #region Heaps Tab

    private void RefreshHeaps()
    {
        _heaps.Clear();
        _lvHeaps.Items.Clear();
        _lvHeapBlocks.Items.Clear();
        _lblHeapStatus.Text = "Enumerating heaps...";
        Application.DoEvents();

        try
        {
            IntPtr hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST, _processId);
            if (hSnapshot == INVALID_HANDLE_VALUE) { _lblHeapStatus.Text = "Failed to create snapshot"; return; }

            try
            {
                var heapList = new HEAPLIST32 { dwSize = (uint)Marshal.SizeOf<HEAPLIST32>() };
                if (Heap32ListFirst(hSnapshot, ref heapList))
                {
                    do
                    {
                        var heapInfo = new HeapInfo { BaseAddress = (ulong)heapList.th32HeapID, Flags = heapList.dwFlags };
                        var heapEntry = new HEAPENTRY32 { dwSize = (uint)Marshal.SizeOf<HEAPENTRY32>() };
                        if (Heap32First(ref heapEntry, _processId, (UIntPtr)heapList.th32HeapID))
                        {
                            ulong totalSize = 0;
                            do
                            {
                                heapInfo.Blocks.Add(new HeapBlock
                                {
                                    Address = (ulong)heapEntry.dwAddress, Size = (ulong)heapEntry.dwBlockSize,
                                    Flags = heapEntry.dwFlags, IsFree = (heapEntry.dwFlags & LF32_FREE) != 0
                                });
                                totalSize += (ulong)heapEntry.dwBlockSize;
                                heapEntry.dwSize = (uint)Marshal.SizeOf<HEAPENTRY32>();
                            } while (Heap32Next(ref heapEntry));
                            heapInfo.Size = totalSize;
                            heapInfo.BlockCount = heapInfo.Blocks.Count;
                        }
                        _heaps.Add(heapInfo);
                        heapList.dwSize = (uint)Marshal.SizeOf<HEAPLIST32>();
                    } while (Heap32ListNext(hSnapshot, ref heapList));
                }
            }
            finally { CloseHandle(hSnapshot); }

            foreach (var heap in _heaps)
            {
                var item = new ListViewItem($"0x{heap.BaseAddress:X}");
                item.SubItems.Add(FormatSize(heap.Size));
                item.SubItems.Add(heap.BlockCount.ToString());
                item.SubItems.Add($"0x{heap.Flags:X}");
                item.Tag = heap;
                _lvHeaps.Items.Add(item);
            }
            _lblHeapStatus.Text = $"{_heaps.Count} heaps found";
        }
        catch (Exception ex) { _lblHeapStatus.Text = $"Error: {ex.Message}"; }
    }

    private void UpdateHeapBlockList()
    {
        _lvHeapBlocks.Items.Clear();
        if (_lvHeaps.SelectedItems.Count == 0 || _lvHeaps.SelectedItems[0].Tag is not HeapInfo heap) return;

        foreach (var block in heap.Blocks)
        {
            if (!_chkShowFreeBlocks.Checked && block.IsFree) continue;
            var item = new ListViewItem($"0x{block.Address:X}");
            item.SubItems.Add(FormatSize(block.Size));
            item.SubItems.Add(block.IsFree ? "Free" : "Used");
            item.SubItems.Add($"0x{block.Flags:X}");
            item.Tag = block;
            if (block.IsFree) item.ForeColor = Color.Gray;
            _lvHeapBlocks.Items.Add(item);
        }
    }

    private void BrowseHeapBase()
    {
        if (_lvHeaps.SelectedItems.Count > 0 && _lvHeaps.SelectedItems[0].Tag is HeapInfo h)
            OnNavigateToAddress?.Invoke(this, h.BaseAddress);
    }

    private void CopyHeapBase()
    {
        if (_lvHeaps.SelectedItems.Count > 0 && _lvHeaps.SelectedItems[0].Tag is HeapInfo h)
            Clipboard.SetText($"0x{h.BaseAddress:X}");
    }

    private void BrowseHeapBlock()
    {
        if (_lvHeapBlocks.SelectedItems.Count > 0 && _lvHeapBlocks.SelectedItems[0].Tag is HeapBlock b)
            OnNavigateToAddress?.Invoke(this, b.Address);
    }

    private void CopyHeapBlockAddress()
    {
        if (_lvHeapBlocks.SelectedItems.Count > 0 && _lvHeapBlocks.SelectedItems[0].Tag is HeapBlock b)
            Clipboard.SetText($"0x{b.Address:X}");
    }

    #endregion
}
