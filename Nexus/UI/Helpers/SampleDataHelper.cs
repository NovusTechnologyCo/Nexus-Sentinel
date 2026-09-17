// <file>
// <summary>
// Temporary helper for populating forms with sample/mock data during UI review and
// development. Fills ListViews and other controls with representative data so forms
// can be visually audited without connecting to a live process.
// NOTE: This is a development utility -- remove before final release.
// </summary>
// </file>

using Nexus.UI.Forms;
using Nexus.UI.Interop;

namespace Nexus.UI.Helpers;

/// <summary>
/// Helper class for filling forms with sample data for UI review purposes.
/// </summary>
public static class SampleDataHelper
{
    /// <summary>
    /// Checks if a form has sample data available (any form with a ListView).
    /// </summary>
    public static bool HasSampleData(Form form)
    {
        // Check if form has any ListView
        return GetListView(form) != null || GetAllListViews(form).Count > 0;
    }

    /// <summary>
    /// Fills the form with sample data based on its type.
    /// </summary>
    public static void FillSampleData(Form form)
    {
        switch (form)
        {
            case ScanHistoryForm:
                FillScanHistory(form);
                break;
            case ValueHistoryForm:
                FillValueHistory(form);
                break;
            case CodeCaveScannerForm:
                FillCodeCaveScanner(form);
                break;
            case DissectDataForm:
                FillDissectData(form);
                break;
            case FindStaticsForm:
                FillFindStatics(form);
                break;
            case WindowSpyForm:
                FillWindowSpy(form);
                break;
            case HotkeyConfigForm:
                FillHotkeyConfig(form);
                break;
            case PluginManagerForm:
                FillPluginManager(form);
                break;
            case PointerScannerForm:
                FillPointerScanner(form);
                break;
            case ProcessMemoryMapForm:
                FillProcessMemoryMap(form);
                break;
            case StackViewForm:
                FillStackView(form);
                break;
            case SpeedhackForm:
                FillSpeedhack(form);
                break;
            case ChangeValueForm:
                FillChangeValue(form);
                break;
            default:
                // Generic fill for any form with a ListView
                FillGenericListView(form);
                break;
        }
    }

    private static void FillScanHistory(Form form)
    {
        var listView = GetListView(form);
        if (listView == null) return;

        listView.Items.Clear();
        AddRows(listView, new[]
        {
            new[] { "1", "Exact Value", "100", "4 Bytes", "1,234,567" },
            new[] { "2", "Exact Value", "100", "4 Bytes", "45,231" },
            new[] { "3", "Decreased", "-", "4 Bytes", "12,456" },
            new[] { "4", "Decreased", "-", "4 Bytes", "3,421" },
            new[] { "5", "Exact Value", "95", "4 Bytes", "1" },
        });
    }

    private static void FillValueHistory(Form form)
    {
        var listView = GetListView(form);
        if (listView == null) return;

        listView.Items.Clear();
        AddRows(listView, new[]
        {
            new[] { "0x01234560", "100", "12:00:00", "Initial" },
            new[] { "0x01234560", "95", "12:00:15", "Took damage" },
            new[] { "0x01234560", "90", "12:00:30", "Took damage" },
            new[] { "0x01234560", "100", "12:00:45", "Healed" },
            new[] { "0x01234560", "50", "12:01:00", "Boss hit" },
        });
    }

    private static void FillCodeCaveScanner(Form form)
    {
        var listView = GetListView(form);
        if (listView == null) return;

        listView.Items.Clear();
        AddRows(listView, new[]
        {
            new[] { "0x00401500", "47 bytes", "game.exe", "0x00" },
            new[] { "0x00402800", "112 bytes", "game.exe", "0x00" },
            new[] { "0x00450000", "289 bytes", "game.exe", "0xCC" },
            new[] { "0x10005000", "534 bytes", "engine.dll", "0x00" },
            new[] { "0x10008000", "1847 bytes", "engine.dll", "0x90" },
        });

        // Update count label
        var countLabel = FindControl<Label>(form, l => l.Text.Contains("caves found"));
        if (countLabel != null)
            countLabel.Text = $"{listView.Items.Count} caves found";
    }

    private static void FillDissectData(Form form)
    {
        var listView = GetListView(form);
        if (listView == null) return;

        listView.Items.Clear();
        AddRows(listView, new[]
        {
            new[] { "0x00", "Health", "int32", "100" },
            new[] { "0x04", "MaxHealth", "int32", "100" },
            new[] { "0x08", "PosX", "float", "123.456" },
            new[] { "0x0C", "PosY", "float", "789.012" },
            new[] { "0x10", "PosZ", "float", "45.678" },
            new[] { "0x14", "Gold", "int32", "99999" },
            new[] { "0x18", "Inventory", "pointer", "0x02345678" },
        });
    }

    private static void FillFindStatics(Form form)
    {
        var listView = GetListView(form);
        if (listView == null) return;

        listView.Items.Clear();
        AddRows(listView, new[]
        {
            new[] { "game.exe+0x123456", "0x00523456", "g_PlayerHealth" },
            new[] { "game.exe+0x123460", "0x00523460", "g_PlayerGold" },
            new[] { "engine.dll+0x45000", "0x10045000", "g_GameState" },
            new[] { "engine.dll+0x45008", "0x10045008", "g_EntityList" },
        });
    }

    private static void FillWindowSpy(Form form)
    {
        var listView = GetListView(form);
        if (listView == null) return;

        listView.Items.Clear();
        AddRows(listView, new[]
        {
            new[] { "0x000A0B0C", "Game Window", "GameWindowClass", "12345" },
            new[] { "0x000D0E0F", "Settings", "DialogClass", "12345" },
            new[] { "0x00102030", "Console", "ConsoleWindowClass", "12346" },
            new[] { "0x00405060", "Debug Output", "DebugClass", "12345" },
        });
    }

    private static void FillHotkeyConfig(Form form)
    {
        var listView = GetListView(form);
        if (listView == null) return;

        listView.Items.Clear();
        AddRows(listView, new[]
        {
            new[] { "Speedhack x0.5", "Numpad 1", "Set" },
            new[] { "Speedhack x1.0", "Numpad 2", "Set" },
            new[] { "Speedhack x2.0", "Numpad 3", "Set" },
            new[] { "Pause Process", "Pause", "Toggle" },
            new[] { "Toggle Speedhack", "~", "Toggle" },
        });
    }

    private static void FillPluginManager(Form form)
    {
        var listView = GetListView(form);
        if (listView == null) return;

        listView.Items.Clear();
        var items = new[]
        {
            ("Trainer Helper", "1.0.0", "Nexus Team", true),
            ("Auto-Updater", "2.1.0", "Community", true),
            ("Lua Scripting", "1.5.0", "Community", false),
            ("D3D Overlay", "0.9.0", "External", true),
        };

        foreach (var (name, version, author, enabled) in items)
        {
            var item = new ListViewItem(name) { Checked = enabled };
            item.SubItems.Add(version);
            item.SubItems.Add(author);
            item.SubItems.Add(enabled ? "Enabled" : "Disabled");
            listView.Items.Add(item);
        }
    }

    private static void FillPointerScanner(Form form)
    {
        var listViews = GetAllListViews(form);
        if (listViews.Count == 0) return;

        var listView = listViews[0];
        listView.Items.Clear();
        AddRows(listView, new[]
        {
            new[] { "game.exe+0x123456", "0x10, 0x20, 0x8", "0x01234560" },
            new[] { "game.exe+0x123456", "0x10, 0x30, 0x8", "0x01234560" },
            new[] { "engine.dll+0x45000", "0x0, 0x48", "0x01234560" },
            new[] { "engine.dll+0x45000", "0x8, 0x20, 0x48", "0x01234560" },
            new[] { "game.exe+0x234567", "0x100, 0x0", "0x01234560" },
        });
    }

    private static void FillProcessMemoryMap(Form form)
    {
        var listView = GetListView(form);
        if (listView == null) return;

        listView.Items.Clear();
        AddRows(listView, new[]
        {
            new[] { "0x00400000", "0x00600000", "0x00200000", "game.exe", "Image" },
            new[] { "0x01000000", "0x01100000", "0x00100000", "", "Heap" },
            new[] { "0x02000000", "0x02010000", "0x00010000", "", "Stack" },
            new[] { "0x10000000", "0x10800000", "0x00800000", "engine.dll", "Image" },
            new[] { "0x7FFE0000", "0x7FFF0000", "0x00010000", "ntdll.dll", "Image" },
        });
    }

    private static void FillStackView(Form form)
    {
        var listView = GetListView(form);
        if (listView == null) return;

        listView.Items.Clear();
        AddRows(listView, new[]
        {
            new[] { "0x000FF000", "0x00401234", "game.exe!main+0x34" },
            new[] { "0x000FEFF8", "0x00405678", "game.exe!GameLoop+0x78" },
            new[] { "0x000FEFF0", "0x00408ABC", "game.exe!ProcessInput+0x1C" },
            new[] { "0x000FEFE8", "0x7FFE1234", "ntdll.dll!NtWaitForSingleObject+0x14" },
            new[] { "0x000FEFE0", "0x7FFD5678", "kernel32.dll!WaitForSingleObjectEx+0x8E" },
        });
    }

    private static void FillSpeedhack(Form form)
    {
        var listView = GetListView(form);
        if (listView == null) return;

        listView.Items.Clear();
        AddRows(listView, new[]
        {
            new[] { "QueryPerformanceCounter", "Hooked", "2.0x" },
            new[] { "GetTickCount", "Hooked", "2.0x" },
            new[] { "GetTickCount64", "Hooked", "2.0x" },
            new[] { "timeGetTime", "Not Hooked", "-" },
        });
    }

    private static void FillChangeValue(Form form)
    {
        var listView = GetListView(form);
        if (listView == null) return;

        listView.Items.Clear();
        AddRows(listView, new[]
        {
            new[] { "Byte", "100", "0x64" },
            new[] { "2 Bytes", "1000", "0x3E8" },
            new[] { "4 Bytes", "99999", "0x1869F" },
            new[] { "Float", "123.456", "0x42F6E979" },
            new[] { "Double", "123456.789", "0x40FE240C9FBE76C9" },
        });
    }

    private static void FillGenericListView(Form form)
    {
        var listViews = GetAllListViews(form);
        foreach (var listView in listViews)
        {
            if (listView.Items.Count > 0) continue; // Skip if already has data

            int colCount = listView.Columns.Count;
            if (colCount == 0) colCount = 4;

            listView.Items.Clear();
            for (int row = 0; row < 5; row++)
            {
                var item = new ListViewItem($"Sample {row + 1}");
                for (int col = 1; col < colCount; col++)
                {
                    item.SubItems.Add($"Data {row + 1}-{col + 1}");
                }
                listView.Items.Add(item);
            }
        }
    }

    // Helper to add rows to ListView
    private static void AddRows(ListView listView, string[][] rows)
    {
        foreach (var row in rows)
        {
            if (row.Length == 0) continue;
            var item = new ListViewItem(row[0]);
            for (int i = 1; i < row.Length; i++)
            {
                item.SubItems.Add(row[i]);
            }
            listView.Items.Add(item);
        }
    }

    private static ListView? GetListView(Form form)
    {
        var fields = form.GetType().GetFields(System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        foreach (var field in fields)
        {
            if (field.FieldType == typeof(ListView))
                return field.GetValue(form) as ListView;
        }
        return FindControl<ListView>(form);
    }

    private static List<ListView> GetAllListViews(Form form)
    {
        var result = new List<ListView>();

        var fields = form.GetType().GetFields(System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        foreach (var field in fields)
        {
            if (field.FieldType == typeof(ListView))
            {
                var lv = field.GetValue(form) as ListView;
                if (lv != null) result.Add(lv);
            }
        }

        if (result.Count == 0)
            FindAllControls(form, result);

        return result;
    }

    private static void FindAllControls<T>(Control parent, List<T> result) where T : Control
    {
        foreach (Control control in parent.Controls)
        {
            if (control is T t)
                result.Add(t);
            FindAllControls(control, result);
        }
    }

    private static T? FindControl<T>(Control parent) where T : Control
    {
        foreach (Control control in parent.Controls)
        {
            if (control is T t)
                return t;
            var found = FindControl<T>(control);
            if (found != null)
                return found;
        }
        return null;
    }

    private static T? FindControl<T>(Control parent, Func<T, bool> predicate) where T : Control
    {
        foreach (Control control in parent.Controls)
        {
            if (control is T t && predicate(t))
                return t;
            var found = FindControl<T>(control, predicate);
            if (found != null)
                return found;
        }
        return null;
    }
}
