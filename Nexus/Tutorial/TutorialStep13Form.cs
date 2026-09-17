// Tutorial Step 13 - Different Value Types
// Split from TutorialForms.cs for maintainability

using System.Drawing;

namespace Nexus.Tutorial;

/// <summary>
/// Tutorial Step 13 - Different Value Types (Byte, 2-Byte, 8-Byte).
/// Tests scanning for non-4-byte integer types.
/// </summary>
public class TutorialStep13Form : Form
{
    private byte _byteValue = 200;
    private short _shortValue = 30000;
    private long _longValue = 9999999999L;
    private readonly Label _lblByte;
    private readonly Label _lblShort;
    private readonly Label _lblLong;
    private readonly Button _btnNext;
    private readonly System.Windows.Forms.Timer _checkTimer;

    private const string Step13Text = @"Step 13: Different Value Types

So far you've mostly worked with 4-byte integers. But games use various data types:

- Byte (1 byte): 0 to 255 - often used for percentages, small counters
- 2 Bytes (short): -32768 to 32767 - older games, limited ranges
- 8 Bytes (int64): Very large numbers - modern games, timestamps

Below are three values of different types. Find and modify each:
- Byte Value: Change to 255
- 2-Byte Value: Change to 32000
- 8-Byte Value: Change to 1234567890123

Tips:
- Select the correct value type in NS before scanning
- Byte values are common for health percentages (0-100)
- 8-byte scans take longer but find large numbers

All three must be correct to proceed.";

    public TutorialStep13Form()
    {
        Text = "Nexus Sentinel Tutorial - Step 13";
        Size = new Size(600, 560);
        Font = new Font("Segoe UI", 10);
        StartPosition = FormStartPosition.Manual;

        var instructions = new TextBox
        {
            Multiline = true,
            ReadOnly = true,
            TabStop = false,
            ScrollBars = ScrollBars.Vertical,
            Location = new Point(10, 10),
            Size = new Size(580, 230),
            Text = Step13Text
        };
        Controls.Add(instructions);

        // Byte value
        var lblByteTitle = new Label { Text = "Byte (1 byte):", Location = new Point(10, 260), AutoSize = true };
        Controls.Add(lblByteTitle);
        _lblByte = new Label
        {
            Text = _byteValue.ToString(),
            Location = new Point(150, 260),
            Size = new Size(100, 25),
            Font = new Font("Segoe UI", 12, FontStyle.Bold)
        };
        Controls.Add(_lblByte);

        var btnDecByte = new Button { Text = "-1", Location = new Point(260, 255), Size = new Size(40, 35) };
        btnDecByte.Click += (s, e) => { if (_byteValue > 0) _byteValue--; UpdateLabels(); };
        Controls.Add(btnDecByte);

        // 2-byte value
        var lblShortTitle = new Label { Text = "2 Bytes (short):", Location = new Point(10, 300), AutoSize = true };
        Controls.Add(lblShortTitle);
        _lblShort = new Label
        {
            Text = _shortValue.ToString(),
            Location = new Point(150, 300),
            Size = new Size(100, 25),
            Font = new Font("Segoe UI", 12, FontStyle.Bold)
        };
        Controls.Add(_lblShort);

        var btnDecShort = new Button { Text = "-10", Location = new Point(260, 295), Size = new Size(50, 35) };
        btnDecShort.Click += (s, e) => { _shortValue -= 10; UpdateLabels(); };
        Controls.Add(btnDecShort);

        // 8-byte value
        var lblLongTitle = new Label { Text = "8 Bytes (int64):", Location = new Point(10, 340), AutoSize = true };
        Controls.Add(lblLongTitle);
        _lblLong = new Label
        {
            Text = _longValue.ToString(),
            Location = new Point(150, 340),
            Size = new Size(200, 25),
            Font = new Font("Segoe UI", 12, FontStyle.Bold)
        };
        Controls.Add(_lblLong);

        var btnDecLong = new Button { Text = "-1", Location = new Point(360, 335), Size = new Size(50, 35) };
        btnDecLong.Click += (s, e) => { _longValue -= 1; UpdateLabels(); };
        Controls.Add(btnDecLong);

        _btnNext = new Button { Text = "Next", Location = new Point(480, 435), Size = new Size(80, 36), Enabled = false };
        _btnNext.Click += (s, e) => { Hide(); new TutorialStep14Form { Location = Location }.Show(); };
        Controls.Add(_btnNext);

        _checkTimer = new System.Windows.Forms.Timer { Interval = 100 };
        _checkTimer.Tick += (s, e) =>
        {
            if (_byteValue == 255 && _shortValue == 32000 && _longValue == 1234567890123L)
            {
                _btnNext.Enabled = true;
            }
            UpdateLabels();
        };
        _checkTimer.Start();

        TutorialNavigation.AddNavigationControls(this, 13);
        FormClosing += (s, e) => Environment.Exit(0);
    }

    private void UpdateLabels()
    {
        _lblByte.Text = _byteValue.ToString();
        _lblShort.Text = _shortValue.ToString();
        _lblLong.Text = _longValue.ToString();
    }
}
