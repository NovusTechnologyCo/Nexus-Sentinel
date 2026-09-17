// <file>
// <summary>
// Partial class for SettingsForm containing the hotkey configuration panel.
// </summary>
// </file>
using Nexus.UI.Styles;

namespace Nexus.UI.Forms;

public partial class SettingsForm
{
    #region Hotkeys Panel

    private Panel CreateHotkeysPanel()
    {
        var panel = new Panel
        {
            Dock = DockStyle.Fill,
            AutoScroll = true,
            Visible = false,
            BackColor = NexusTheme.BackgroundPanel
        };

        int y = 10;
        const int indent = 10;

        // Title
        panel.Controls.Add(new Label
        {
            Text = "Hotkeys",
            Font = new Font(Font.FontFamily, 12, FontStyle.Bold),
            Location = new Point(indent, y),
            AutoSize = true
        });
        y += 30;

        // Hotkey list
        lvHotkeys = new ListView
        {
            Location = new Point(indent, y),
            Size = new Size(450, 300),
            View = View.Details,
            FullRowSelect = true,
            GridLines = true
        };
        lvHotkeys.Columns.Add("Action", 200);
        lvHotkeys.Columns.Add("Hotkey", 150);
        lvHotkeys.Columns.Add("Behavior", 100);

        // Hotkeys will be loaded from settings in LoadSettings()

        panel.Controls.Add(lvHotkeys);
        y += 310;

        // Edit buttons
        var btnEdit = new Button
        {
            Text = "Edit",
            Location = new Point(indent, y),
            Size = new Size(80, 32)
        };
        btnEdit.Click += (s, e) => EditSelectedHotkey();
        panel.Controls.Add(btnEdit);

        var btnClear = new Button
        {
            Text = "Clear",
            Location = new Point(indent + 110, y),
            Size = new Size(80, 30)
        };
        btnClear.Click += (s, e) => ClearSelectedHotkey();
        panel.Controls.Add(btnClear);

        // Double-click to edit
        lvHotkeys.DoubleClick += (s, e) => EditSelectedHotkey();

        return panel;
    }

    private void EditSelectedHotkey()
    {
        if (lvHotkeys.SelectedItems.Count == 0)
        {
            MessageBox.Show("Please select a hotkey to edit.", "No Selection",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var item = lvHotkeys.SelectedItems[0];

        if (HotkeyConfigForm.ShowHotkeyPicker(this, Keys.None, HotkeyAction.Toggle,
            out var hotkey, out var action, out _))
        {
            // Update the list item with the new hotkey
            var newHotkeyText = FormatKeysForDisplay(hotkey);
            var newBehavior = action switch
            {
                HotkeyAction.Toggle => "Toggle",
                HotkeyAction.Enable => "Enable",
                HotkeyAction.Disable => "Disable",
                HotkeyAction.SetValue => "Set",
                HotkeyAction.IncreaseValue => "Increase",
                HotkeyAction.DecreaseValue => "Decrease",
                _ => "Toggle"
            };

            item.SubItems[1].Text = newHotkeyText;
            item.SubItems[2].Text = newBehavior;
            SetHasChanges(true);
        }
    }

    private void ClearSelectedHotkey()
    {
        if (lvHotkeys.SelectedItems.Count == 0)
        {
            MessageBox.Show("Please select a hotkey to clear.", "No Selection",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var item = lvHotkeys.SelectedItems[0];
        item.SubItems[1].Text = "(None)";
        SetHasChanges(true);
    }

    private string FormatKeysForDisplay(Keys key)
    {
        if (key == Keys.None) return "(None)";

        var parts = new List<string>();

        if ((key & Keys.Control) != 0) parts.Add("Ctrl");
        if ((key & Keys.Alt) != 0) parts.Add("Alt");
        if ((key & Keys.Shift) != 0) parts.Add("Shift");

        var baseKey = key & Keys.KeyCode;
        if (baseKey != Keys.None)
        {
            var keyName = baseKey switch
            {
                Keys.NumPad0 => "Numpad 0",
                Keys.NumPad1 => "Numpad 1",
                Keys.NumPad2 => "Numpad 2",
                Keys.NumPad3 => "Numpad 3",
                Keys.NumPad4 => "Numpad 4",
                Keys.NumPad5 => "Numpad 5",
                Keys.NumPad6 => "Numpad 6",
                Keys.NumPad7 => "Numpad 7",
                Keys.NumPad8 => "Numpad 8",
                Keys.NumPad9 => "Numpad 9",
                Keys.Oemtilde => "~",
                Keys.Pause => "Pause",
                _ => baseKey.ToString()
            };
            parts.Add(keyName);
        }

        return string.Join(" + ", parts);
    }

    #endregion
}
