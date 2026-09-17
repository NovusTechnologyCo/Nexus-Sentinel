using Nexus.UI.Core;
using Nexus.UI.Interop;

namespace Nexus.UI.Panels;

public partial class StructuresPanel
{
    #region Value Reading

    private void RefreshValues()
    {
        if (!Context.IsAttached || _selectedClass == null || _baseAddress == 0)
        {
            ClearValues();
            return;
        }

        var handle = Context.NativeProcessHandle;
        if (handle == IntPtr.Zero) return;

        // Read preview buffer
        _previewBuffer = NexusEngine.ReadBytes(handle, _baseAddress, 256);
        _hexPreview.Invalidate();

        // Read field values
        foreach (DataGridViewRow row in _fieldsGrid.Rows)
        {
            var field = row.Tag as StructureField;
            if (field == null) continue;

            var address = _baseAddress + (ulong)field.Offset;
            field.CachedValue = ReadFieldValue(handle, address, field.Type, field);
            row.Cells["Value"].Value = field.CachedValue;
        }
    }

    private void ClearValues()
    {
        _previewBuffer = new byte[256];
        _hexPreview.Invalidate();

        foreach (DataGridViewRow row in _fieldsGrid.Rows)
        {
            row.Cells["Value"].Value = "???";
        }
    }

    private static string ReadFieldValue(IntPtr handle, ulong address, FieldType type, StructureField? field = null)
    {
        try
        {
            int size = type switch
            {
                FieldType.Padding => field?.ArrayCount ?? 1,
                FieldType.Struct => 8,
                FieldType.Array => (field?.ArrayCount ?? 1) * GetFieldSize(field?.ArrayBaseType ?? FieldType.UInt8),
                FieldType.Bitfield => 4,  // Read 4 bytes for bitfield extraction
                FieldType.GUID => 16,
                FieldType.Union => field?.ArrayCount ?? 8,
                _ => GetFieldSize(type)
            };

            var bytes = NexusEngine.ReadBytes(handle, address, size);
            if (bytes.Length == 0) return "???";

            return type switch
            {
                FieldType.Int8 => ((sbyte)bytes[0]).ToString(),
                FieldType.UInt8 => bytes[0].ToString(),
                FieldType.Int16 => BitConverter.ToInt16(bytes, 0).ToString(),
                FieldType.UInt16 => BitConverter.ToUInt16(bytes, 0).ToString(),
                FieldType.Int32 => BitConverter.ToInt32(bytes, 0).ToString(),
                FieldType.UInt32 => BitConverter.ToUInt32(bytes, 0).ToString(),
                FieldType.Int64 => BitConverter.ToInt64(bytes, 0).ToString(),
                FieldType.UInt64 => BitConverter.ToUInt64(bytes, 0).ToString(),
                FieldType.Float => BitConverter.ToSingle(bytes, 0).ToString("F3"),
                FieldType.Double => BitConverter.ToDouble(bytes, 0).ToString("F3"),
                FieldType.Bool => (bytes[0] != 0).ToString(),
                FieldType.Pointer => FormatPointerValue(handle, bytes, field),
                FieldType.String => ReadString(handle, address, false),
                FieldType.WString => ReadString(handle, address, true),
                FieldType.Bytes => BitConverter.ToString(bytes).Replace("-", " "),
                FieldType.Struct => field?.NestedStructName != null
                    ? $"[{field.NestedStructName}] @ 0x{address:X}"
                    : $"[struct] @ 0x{address:X}",
                FieldType.Padding => $"[{bytes.Length} bytes]",
                FieldType.Array => FormatArrayValue(bytes, field),
                FieldType.Bitfield => FormatBitfieldValue(bytes, field),
                FieldType.Enum => FormatEnumValue(bytes, field),
                FieldType.GUID => FormatGuidValue(bytes),
                FieldType.Timestamp => FormatTimestampValue(bytes),
                FieldType.Union => $"[union {bytes.Length} bytes]",
                _ => "???"
            };
        }
        catch
        {
            return "???";
        }
    }

    private static string FormatPointerValue(IntPtr handle, byte[] bytes, StructureField? field)
    {
        var ptr = BitConverter.ToUInt64(bytes, 0);
        if (ptr == 0) return "nullptr";

        // If pointer chain is defined, resolve it
        if (field?.PointerOffsets != null && field.PointerOffsets.Count > 0)
        {
            var resolved = ResolvePointerChain(handle, ptr, field.PointerOffsets);
            field.ResolvedAddress = resolved;
            return resolved != 0 ? $"0x{ptr:X} -> 0x{resolved:X}" : $"0x{ptr:X} -> ???";
        }

        return $"0x{ptr:X}";
    }

    private static ulong ResolvePointerChain(IntPtr handle, ulong basePtr, List<long> offsets)
    {
        var current = basePtr;
        foreach (var offset in offsets)
        {
            // Apply offset
            current = (ulong)((long)current + offset);

            // Read pointer at this address
            var bytes = NexusEngine.ReadBytes(handle, current, 8);
            if (bytes.Length != 8) return 0;

            current = BitConverter.ToUInt64(bytes, 0);
            if (current == 0) return 0;
        }
        return current;
    }

    private static string FormatArrayValue(byte[] bytes, StructureField? field)
    {
        if (field == null) return $"[{bytes.Length} bytes]";

        var baseType = field.ArrayBaseType;
        var count = field.ArrayCount;
        var elemSize = GetFieldSize(baseType);

        if (count <= 0 || elemSize <= 0) return $"[{bytes.Length} bytes]";

        // Show first few elements
        var maxShow = Math.Min(count, 4);
        var values = new List<string>();

        for (int i = 0; i < maxShow && i * elemSize < bytes.Length; i++)
        {
            var value = baseType switch
            {
                FieldType.Int8 => ((sbyte)bytes[i * elemSize]).ToString(),
                FieldType.UInt8 => bytes[i * elemSize].ToString(),
                FieldType.Int16 => BitConverter.ToInt16(bytes, i * elemSize).ToString(),
                FieldType.UInt16 => BitConverter.ToUInt16(bytes, i * elemSize).ToString(),
                FieldType.Int32 => BitConverter.ToInt32(bytes, i * elemSize).ToString(),
                FieldType.UInt32 => BitConverter.ToUInt32(bytes, i * elemSize).ToString(),
                FieldType.Float => BitConverter.ToSingle(bytes, i * elemSize).ToString("F2"),
                _ => bytes[i * elemSize].ToString()
            };
            values.Add(value);
        }

        var result = $"[{string.Join(", ", values)}";
        if (count > maxShow) result += $", ...+{count - maxShow}";
        return result + "]";
    }

    private static string FormatBitfieldValue(byte[] bytes, StructureField? field)
    {
        if (field == null || bytes.Length < 4) return "???";

        var value = BitConverter.ToUInt32(bytes, 0);
        var bitOffset = field.BitOffset;
        var bitSize = field.BitSize;

        if (bitSize <= 0 || bitSize > 32) return "???";

        // Extract bits
        var mask = (1u << bitSize) - 1;
        var extracted = (value >> bitOffset) & mask;

        return $"{extracted} (bits {bitOffset}-{bitOffset + bitSize - 1})";
    }

    private static string FormatEnumValue(byte[] bytes, StructureField? field)
    {
        if (bytes.Length < 4) return "???";

        var value = BitConverter.ToInt32(bytes, 0);

        // Look up enum name
        if (field?.EnumValues != null && field.EnumValues.TryGetValue(value, out var name))
        {
            return $"{name} ({value})";
        }

        return value.ToString();
    }

    private static string FormatGuidValue(byte[] bytes)
    {
        if (bytes.Length < 16) return "???";

        try
        {
            var guid = new Guid(bytes);
            return guid.ToString("B");  // {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
        }
        catch
        {
            return BitConverter.ToString(bytes).Replace("-", "");
        }
    }

    private static string FormatTimestampValue(byte[] bytes)
    {
        if (bytes.Length < 4) return "???";

        var timestamp = BitConverter.ToUInt32(bytes, 0);
        if (timestamp == 0) return "0 (null)";

        try
        {
            var dt = DateTimeOffset.FromUnixTimeSeconds(timestamp).LocalDateTime;
            return $"{dt:yyyy-MM-dd HH:mm:ss}";
        }
        catch
        {
            return timestamp.ToString();
        }
    }

    private static string ReadString(IntPtr handle, ulong address, bool unicode)
    {
        var bytes = NexusEngine.ReadBytes(handle, address, 64);
        if (bytes.Length == 0) return "???";

        if (unicode)
        {
            int len = 0;
            for (int i = 0; i < bytes.Length - 1; i += 2)
            {
                if (bytes[i] == 0 && bytes[i + 1] == 0) break;
                len += 2;
            }
            return $"\"{System.Text.Encoding.Unicode.GetString(bytes, 0, len)}\"";
        }
        else
        {
            int len = Array.IndexOf(bytes, (byte)0);
            if (len < 0) len = bytes.Length;
            return $"\"{System.Text.Encoding.ASCII.GetString(bytes, 0, len)}\"";
        }
    }

    #endregion

    #region Value Writing

    private void WriteFieldValue(StructureField field, string newValue)
    {
        var handle = Context.NativeProcessHandle;
        if (handle == IntPtr.Zero) return;

        var address = _baseAddress + (ulong)field.Offset;

        try
        {
            byte[]? bytes = field.Type switch
            {
                FieldType.Int8 => [unchecked((byte)sbyte.Parse(newValue))],
                FieldType.UInt8 => [byte.Parse(newValue)],
                FieldType.Int16 => BitConverter.GetBytes(short.Parse(newValue)),
                FieldType.UInt16 => BitConverter.GetBytes(ushort.Parse(newValue)),
                FieldType.Int32 => BitConverter.GetBytes(int.Parse(newValue)),
                FieldType.UInt32 => BitConverter.GetBytes(uint.Parse(newValue)),
                FieldType.Int64 => BitConverter.GetBytes(long.Parse(newValue)),
                FieldType.UInt64 => BitConverter.GetBytes(ulong.Parse(newValue)),
                FieldType.Float => BitConverter.GetBytes(float.Parse(newValue)),
                FieldType.Double => BitConverter.GetBytes(double.Parse(newValue)),
                FieldType.Bool => [(byte)(bool.Parse(newValue) ? 1 : 0)],
                FieldType.Pointer => BitConverter.GetBytes(ParseHexOrDecimal(newValue)),
                FieldType.Enum => BitConverter.GetBytes(ParseEnumValue(newValue, field)),
                FieldType.Timestamp => BitConverter.GetBytes(ParseTimestamp(newValue)),
                FieldType.Bitfield => WriteBitfieldValue(handle, address, field, newValue),
                _ => null
            };

            if (bytes != null)
            {
                // Use protected write for code pages
                if (NexusEngine.WriteMemoryProtected(handle, address, bytes))
                {
                    field.CachedValue = newValue;
                    UpdateStatus($"Wrote {bytes.Length} bytes to 0x{address:X}");
                }
                else if (NexusEngine.WriteBytes(handle, address, bytes))
                {
                    field.CachedValue = newValue;
                    UpdateStatus($"Wrote {bytes.Length} bytes to 0x{address:X}");
                }
                else
                {
                    UpdateStatus($"Failed to write to 0x{address:X}", true);
                }
            }
            else
            {
                UpdateStatus($"Cannot write {field.Type} type directly", true);
            }
        }
        catch (Exception ex)
        {
            UpdateStatus($"Parse error: {ex.Message}", true);
        }
    }

    private static int ParseEnumValue(string value, StructureField field)
    {
        // Try to parse as name first
        if (field.EnumValues != null)
        {
            var match = field.EnumValues.FirstOrDefault(kv => kv.Value.Equals(value, StringComparison.OrdinalIgnoreCase));
            if (match.Value != null)
                return (int)match.Key;
        }
        // Try to parse "(123)" format from display
        var parenIdx = value.LastIndexOf('(');
        if (parenIdx >= 0)
        {
            var numStr = value[(parenIdx + 1)..].TrimEnd(')');
            if (int.TryParse(numStr, out var num))
                return num;
        }
        return int.Parse(value);
    }

    private static uint ParseTimestamp(string value)
    {
        // Try to parse as datetime
        if (DateTime.TryParse(value, out var dt))
            return (uint)new DateTimeOffset(dt).ToUnixTimeSeconds();
        // Try to parse as number
        return uint.Parse(value);
    }

    private static byte[]? WriteBitfieldValue(IntPtr handle, ulong address, StructureField field, string newValue)
    {
        // Read current value
        var currentBytes = NexusEngine.ReadBytes(handle, address, 4);
        if (currentBytes.Length < 4) return null;

        var current = BitConverter.ToUInt32(currentBytes, 0);

        // Parse new value (strip bit info if present)
        var valueStr = newValue.Split(' ')[0];
        if (!uint.TryParse(valueStr, out var newVal)) return null;

        // Apply bitfield mask
        var mask = ((1u << field.BitSize) - 1) << field.BitOffset;
        var cleared = current & ~mask;
        var updated = cleared | ((newVal << field.BitOffset) & mask);

        return BitConverter.GetBytes(updated);
    }

    private static ulong ParseHexOrDecimal(string value)
    {
        value = value.Trim();
        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return ulong.Parse(value[2..], System.Globalization.NumberStyles.HexNumber);
        if (value.All(c => char.IsDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
        {
            // Try hex first if it looks like hex
            if (value.Any(c => (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                return ulong.Parse(value, System.Globalization.NumberStyles.HexNumber);
        }
        return ulong.Parse(value);
    }

    #endregion
}
