// <file>
// <summary>
// RegistersPanel rendering: Paint handler and all Draw* helper methods for rendering
// register groups (GP, segment, flags, XMM, FPU, debug, MXCSR) to the panel surface.
// </summary>
// </file>

using Nexus.UI.Interop;

namespace Nexus.UI.Panels;

public partial class RegistersPanel
{
    private void RenderPanel_Paint(object? sender, PaintEventArgs e)
    {
        var g = e.Graphics;
        g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
        g.Clear(_backColor);

        using var labelBrush = new SolidBrush(_labelColor);
        using var valueBrush = new SolidBrush(_valueColor);
        using var changedBrush = new SolidBrush(_changedColor);
        using var zeroBrush = new SolidBrush(_zeroColor);
        using var sectionBrush = new SolidBrush(_sectionColor);
        using var selectionBrush = new SolidBrush(Color.FromArgb(60, 60, 80));

        int y = 4 - _scrollOffset;
        int x = 4;
        int panelWidth = _renderPanel.Width - (_scrollBar.Visible ? _scrollBar.Width : 0);

        if (!_hasContext)
        {
            g.DrawString("No context available", _font, zeroBrush, x, y);
            _totalContentHeight = RowHeight + 8;
            return;
        }

        int regIndex = 0;

        // === GP Registers ===
        foreach (var reg in _gpRegisters)
        {
            DrawRegister(g, reg, x, y, panelWidth, regIndex++, labelBrush, valueBrush, changedBrush, zeroBrush, selectionBrush);
            y += RowHeight;
        }

        y += 4;

        // === Extended Registers (R8-R15) ===
        foreach (var reg in _extRegisters)
        {
            DrawRegister(g, reg, x, y, panelWidth, regIndex++, labelBrush, valueBrush, changedBrush, zeroBrush, selectionBrush);
            y += RowHeight;
        }

        y += 4;

        // === RIP ===
        DrawRegisterSpecial(g, "RIP", _context.Rip, _previousContext.Rip, x, y, panelWidth, regIndex++, labelBrush, valueBrush, changedBrush, selectionBrush);
        y += RowHeight;

        y += 4;

        // === RFLAGS ===
        DrawFlags(g, x, y, panelWidth, regIndex++, labelBrush, valueBrush, changedBrush, selectionBrush);
        y += RowHeight * 2;

        y += 8;

        // === Segment Registers ===
        g.DrawString("─── Segment Registers ───", _font, sectionBrush, x, y);
        y += RowHeight;

        DrawSegmentRegister(g, "GS", _context.SegGs, x, y, labelBrush, valueBrush);
        DrawSegmentRegister(g, "FS", _context.SegFs, x + 90, y, labelBrush, valueBrush);
        DrawSegmentRegister(g, "ES", _context.SegEs, x + 180, y, labelBrush, valueBrush);
        y += RowHeight;
        DrawSegmentRegister(g, "DS", _context.SegDs, x, y, labelBrush, valueBrush);
        DrawSegmentRegister(g, "CS", _context.SegCs, x + 90, y, labelBrush, valueBrush);
        DrawSegmentRegister(g, "SS", _context.SegSs, x + 180, y, labelBrush, valueBrush);
        y += RowHeight;

        y += 8;

        // === Debug Registers ===
        g.DrawString("─── Debug Registers ───", _font, sectionBrush, x, y);
        y += RowHeight;

        DrawRegisterSpecial(g, "DR0", _context.Dr0, _previousContext.Dr0, x, y, panelWidth, -1, labelBrush, valueBrush, changedBrush, selectionBrush);
        y += RowHeight;
        DrawRegisterSpecial(g, "DR1", _context.Dr1, _previousContext.Dr1, x, y, panelWidth, -1, labelBrush, valueBrush, changedBrush, selectionBrush);
        y += RowHeight;
        DrawRegisterSpecial(g, "DR2", _context.Dr2, _previousContext.Dr2, x, y, panelWidth, -1, labelBrush, valueBrush, changedBrush, selectionBrush);
        y += RowHeight;
        DrawRegisterSpecial(g, "DR3", _context.Dr3, _previousContext.Dr3, x, y, panelWidth, -1, labelBrush, valueBrush, changedBrush, selectionBrush);
        y += RowHeight;
        DrawRegisterSpecial(g, "DR6", _context.Dr6, _previousContext.Dr6, x, y, panelWidth, -1, labelBrush, valueBrush, changedBrush, selectionBrush);
        y += RowHeight;
        DrawRegisterSpecial(g, "DR7", _context.Dr7, _previousContext.Dr7, x, y, panelWidth, -1, labelBrush, valueBrush, changedBrush, selectionBrush);
        y += RowHeight;

        y += 8;

        // === MxCsr ===
        g.DrawString("─── SIMD Control ───", _font, sectionBrush, x, y);
        y += RowHeight;

        DrawMxCsr(g, x, y, labelBrush, valueBrush);
        y += RowHeight * 2;

        y += 8;

        // === XMM Registers ===
        g.DrawString("─── XMM Registers ───", _font, sectionBrush, x, y);
        y += RowHeight;

        // XMM registers are in FltSave at offset 160 (16 bytes each)
        if (_context.FltSave != null && _context.FltSave.Length >= 160 + 256)
        {
            for (int i = 0; i < 16; i++)
            {
                DrawXmmRegisterFromFltSave(g, i, x, y, labelBrush, valueBrush);
                y += RowHeight;
            }
        }
        else
        {
            g.DrawString("XMM registers not available", _font, zeroBrush, x, y);
            y += RowHeight;
        }

        y += 8;

        // === FPU x87 ===
        g.DrawString("─── FPU x87 ───", _font, sectionBrush, x, y);
        y += RowHeight;

        DrawFpuRegisters(g, x, y, labelBrush, valueBrush, zeroBrush);
        y += RowHeight * 12; // ST0-ST7 + control/status/tag words

        _totalContentHeight = y + _scrollOffset + 20;
        UpdateScrollBar();
    }

    private void DrawRegister(Graphics g, RegisterEntry reg, int x, int y, int panelWidth,
        int index, Brush labelBrush, Brush valueBrush, Brush changedBrush, Brush zeroBrush, Brush selectionBrush)
    {
        if (y < -RowHeight || y > _renderPanel.Height) return;

        var value = reg.GetValue(_context);
        var prevValue = reg.GetValue(_previousContext);
        bool changed = _previousContext.Rip != 0 && value != prevValue;
        bool isZero = value == 0;

        // Selection highlight
        if (index == _selectedRegister)
        {
            g.FillRectangle(selectionBrush, x - 2, y - 1, panelWidth - 4, RowHeight);
        }

        // Label (left-aligned)
        g.DrawString(reg.Name, _font, labelBrush, x, y);

        // Value (after label)
        var brush = changed ? changedBrush : (isZero ? zeroBrush : valueBrush);
        g.DrawString($"{value:X16}", _font, brush, x + LabelWidth, y);
    }

    private void DrawRegisterSpecial(Graphics g, string name, ulong value, ulong prevValue, int x, int y, int panelWidth,
        int index, Brush labelBrush, Brush valueBrush, Brush changedBrush, Brush selectionBrush)
    {
        if (y < -RowHeight || y > _renderPanel.Height) return;

        bool changed = _previousContext.Rip != 0 && value != prevValue;

        if (index >= 0 && index == _selectedRegister)
        {
            g.FillRectangle(selectionBrush, x - 2, y - 1, panelWidth - 4, RowHeight);
        }

        g.DrawString(name, _font, labelBrush, x, y);
        var brush = changed ? changedBrush : valueBrush;
        g.DrawString($"{value:X16}", _font, brush, x + LabelWidth, y);
    }

    private void DrawSegmentRegister(Graphics g, string name, ushort value, int x, int y, Brush labelBrush, Brush valueBrush)
    {
        if (y < -RowHeight || y > _renderPanel.Height) return;
        g.DrawString(name, _font, labelBrush, x, y);
        g.DrawString($"{value:X4}", _font, valueBrush, x + 25, y);
    }

    private void DrawFlags(Graphics g, int x, int y, int panelWidth, int index,
        Brush labelBrush, Brush valueBrush, Brush changedBrush, Brush selectionBrush)
    {
        if (y < -RowHeight * 2 || y > _renderPanel.Height) return;

        uint flags = (uint)_context.EFlags;
        uint prevFlags = (uint)_previousContext.EFlags;
        bool changed = _previousContext.Rip != 0 && flags != prevFlags;

        if (index == _selectedRegister)
        {
            g.FillRectangle(selectionBrush, x - 2, y - 1, panelWidth - 4, RowHeight);
        }

        g.DrawString("RFLAGS", _font, labelBrush, x, y);
        var brush = changed ? changedBrush : valueBrush;
        g.DrawString($"{flags:X16}", _font, brush, x + LabelWidth + 20, y);

        // Draw individual flags on next line
        y += RowHeight;
        var flagStr = GetFlagsString(flags, prevFlags);
        g.DrawString(flagStr, _font, valueBrush, x + 8, y);
    }

    private void DrawMxCsr(Graphics g, int x, int y, Brush labelBrush, Brush valueBrush)
    {
        if (y < -RowHeight * 2 || y > _renderPanel.Height) return;

        uint mxcsr = _context.MxCsr;
        g.DrawString("MxCsr", _font, labelBrush, x, y);
        g.DrawString($"{mxcsr:X8}", _font, valueBrush, x + LabelWidth, y);

        // Second line - breakdown
        y += RowHeight;
        var parts = new List<string>();

        // Exception flags
        if ((mxcsr & 0x0001) != 0) parts.Add("IE");  // Invalid Operation
        if ((mxcsr & 0x0002) != 0) parts.Add("DE");  // Denormalized
        if ((mxcsr & 0x0004) != 0) parts.Add("ZE");  // Divide-by-Zero
        if ((mxcsr & 0x0008) != 0) parts.Add("OE");  // Overflow
        if ((mxcsr & 0x0010) != 0) parts.Add("UE");  // Underflow
        if ((mxcsr & 0x0020) != 0) parts.Add("PE");  // Precision

        // Masks
        if ((mxcsr & 0x0080) != 0) parts.Add("IM");
        if ((mxcsr & 0x0100) != 0) parts.Add("DM");
        if ((mxcsr & 0x0200) != 0) parts.Add("ZM");
        if ((mxcsr & 0x0400) != 0) parts.Add("OM");
        if ((mxcsr & 0x0800) != 0) parts.Add("UM");
        if ((mxcsr & 0x1000) != 0) parts.Add("PM");

        // Rounding control
        int rc = (int)((mxcsr >> 13) & 3);
        string[] rcNames = { "RN", "RD", "RU", "RZ" };
        parts.Add(rcNames[rc]);

        // Flush to zero
        if ((mxcsr & 0x8000) != 0) parts.Add("FZ");
        // Denormals are zeros
        if ((mxcsr & 0x0040) != 0) parts.Add("DAZ");

        g.DrawString(string.Join(" ", parts), _font, valueBrush, x + 8, y);
    }

    private void DrawXmmRegisterFromFltSave(Graphics g, int index, int x, int y, Brush labelBrush, Brush valueBrush)
    {
        if (y < -RowHeight || y > _renderPanel.Height) return;

        // XMM registers start at offset 160 in FltSave, 16 bytes each
        int offset = 160 + (index * 16);

        string name = index < 10 ? $"XMM{index}" : $"XMM{index}";
        g.DrawString(name, _font, labelBrush, x, y);

        // Read 16 bytes (128 bits) and display as hex
        ulong low = BitConverter.ToUInt64(_context.FltSave, offset);
        ulong high = BitConverter.ToUInt64(_context.FltSave, offset + 8);

        string value = $"{high:X16}{low:X16}";
        g.DrawString(value, _font, valueBrush, x + XmmLabelWidth, y);
    }

    private void DrawFpuRegisters(Graphics g, int x, int y, Brush labelBrush, Brush valueBrush, Brush zeroBrush)
    {
        if (_context.FltSave == null || _context.FltSave.Length < 160)
        {
            g.DrawString("FPU state not available", _font, zeroBrush, x, y);
            return;
        }

        // FltSave layout (XSAVE area):
        // 0-1: FCW (FPU Control Word)
        // 2-3: FSW (FPU Status Word)
        // 4: FTW (Abridged Tag Word)
        // 6-7: FOP
        // 8-15: FIP (Instruction Pointer)
        // 16-23: FDP (Data Pointer)
        // 32-159: ST(0) through ST(7), 16 bytes each (10 bytes used, 6 padding)

        ushort fcw = BitConverter.ToUInt16(_context.FltSave, 0);
        ushort fsw = BitConverter.ToUInt16(_context.FltSave, 2);
        byte ftw = _context.FltSave[4];

        // Control Word
        g.DrawString("FCW", _font, labelBrush, x, y);
        g.DrawString($"{fcw:X4}", _font, valueBrush, x + 40, y);
        DrawFpuControlFlags(g, fcw, x + 90, y, valueBrush);
        y += RowHeight;

        // Status Word
        g.DrawString("FSW", _font, labelBrush, x, y);
        g.DrawString($"{fsw:X4}", _font, valueBrush, x + 40, y);
        DrawFpuStatusFlags(g, fsw, x + 90, y, valueBrush);
        y += RowHeight;

        // Tag Word
        g.DrawString("FTW", _font, labelBrush, x, y);
        g.DrawString($"{ftw:X2}", _font, valueBrush, x + 40, y);
        y += RowHeight;

        // ST(0) through ST(7)
        for (int i = 0; i < 8; i++)
        {
            int offset = 32 + (i * 16);
            if (offset + 10 <= _context.FltSave.Length)
            {
                // Read 10 bytes of the extended precision float
                byte[] stBytes = new byte[10];
                Array.Copy(_context.FltSave, offset, stBytes, 0, 10);

                // Display as hex (extended precision is complex to decode)
                string hex = BitConverter.ToString(stBytes).Replace("-", "");
                g.DrawString($"ST{i}", _font, labelBrush, x, y);
                g.DrawString(hex, _font, valueBrush, x + 30, y);
            }
            y += RowHeight;
        }
    }

    private void DrawFpuControlFlags(Graphics g, ushort fcw, int x, int y, Brush brush)
    {
        var parts = new List<string>();

        // Exception masks
        if ((fcw & 0x01) != 0) parts.Add("IM");
        if ((fcw & 0x02) != 0) parts.Add("DM");
        if ((fcw & 0x04) != 0) parts.Add("ZM");
        if ((fcw & 0x08) != 0) parts.Add("OM");
        if ((fcw & 0x10) != 0) parts.Add("UM");
        if ((fcw & 0x20) != 0) parts.Add("PM");

        // Precision control
        int pc = (fcw >> 8) & 3;
        string[] pcNames = { "24", "??", "53", "64" };
        parts.Add($"PC{pcNames[pc]}");

        // Rounding control
        int rc = (fcw >> 10) & 3;
        string[] rcNames = { "RN", "RD", "RU", "RZ" };
        parts.Add(rcNames[rc]);

        g.DrawString(string.Join(" ", parts), _font, brush, x, y);
    }

    private void DrawFpuStatusFlags(Graphics g, ushort fsw, int x, int y, Brush brush)
    {
        var parts = new List<string>();

        // Exception flags
        if ((fsw & 0x01) != 0) parts.Add("IE");
        if ((fsw & 0x02) != 0) parts.Add("DE");
        if ((fsw & 0x04) != 0) parts.Add("ZE");
        if ((fsw & 0x08) != 0) parts.Add("OE");
        if ((fsw & 0x10) != 0) parts.Add("UE");
        if ((fsw & 0x20) != 0) parts.Add("PE");
        if ((fsw & 0x40) != 0) parts.Add("SF");

        // Condition codes
        if ((fsw & 0x0100) != 0) parts.Add("C0");
        if ((fsw & 0x0200) != 0) parts.Add("C1");
        if ((fsw & 0x0400) != 0) parts.Add("C2");
        if ((fsw & 0x4000) != 0) parts.Add("C3");

        // TOP (stack pointer)
        int top = (fsw >> 11) & 7;
        parts.Add($"TOP{top}");

        // Busy
        if ((fsw & 0x8000) != 0) parts.Add("B");

        g.DrawString(string.Join(" ", parts), _font, brush, x, y);
    }

    private string GetFlagsString(uint flags, uint prevFlags)
    {
        var parts = new List<string>();

        void AddFlag(string name, uint mask)
        {
            bool set = (flags & mask) != 0;
            bool wasSet = (prevFlags & mask) != 0;
            bool changed = _previousContext.Rip != 0 && set != wasSet;
            // Use brackets for set flags, parentheses for changed
            if (set)
                parts.Add(changed ? $"[{name}]" : name);
        }

        AddFlag("CF", 0x0001);
        AddFlag("PF", 0x0004);
        AddFlag("AF", 0x0010);
        AddFlag("ZF", 0x0040);
        AddFlag("SF", 0x0080);
        AddFlag("TF", 0x0100);
        AddFlag("IF", 0x0200);
        AddFlag("DF", 0x0400);
        AddFlag("OF", 0x0800);

        return string.Join(" ", parts);
    }
}
