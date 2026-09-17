// Tutorial Step 12 - Speed Hack
// Split from TutorialForms.cs for maintainability

using System.Drawing;

namespace Nexus.Tutorial;

/// <summary>
/// Tutorial Step 12 - Speed Hack.
/// Teaches using the speed hack feature.
/// </summary>
public class TutorialStep12Form : Form
{
    private readonly Label _lblCounter;
    private readonly Label _lblSpeed;
    private readonly Button _btnNext;
    private readonly System.Windows.Forms.Timer _pollTimer;
    private readonly System.Diagnostics.Stopwatch _gameStopwatch; // Uses QueryPerformanceCounter - affected by speed hack
    private readonly DateTime _realStartTime; // Not affected by speed hack
    private int _lastSecond = -1;

    private const string Step12Text = @"Step 12: Speed Hack

The Speed Hack manipulates timing functions (QueryPerformanceCounter, GetTickCount) to make games run faster or slower.

Below is a counter that uses QueryPerformanceCounter. Your task is to use a speed hack to make it count faster.

Steps:
1. Enable Speedhack in Nexus Sentinel (Edit menu or checkbox)
2. Set the speed to 5.0 or higher
3. The counter should now increment much faster
4. Reach 100 seconds to proceed

The counter uses QueryPerformanceCounter internally, which speed hacks modify. At 5x speed, you'll reach 100 in ~20 real seconds.

Reach 100 seconds (game time) to proceed.";

    public TutorialStep12Form()
    {
        Text = "Nexus Sentinel Tutorial - Step 12";
        Size = new Size(600, 560);
        Font = new Font("Segoe UI", 10);
        StartPosition = FormStartPosition.Manual;

        _realStartTime = DateTime.Now;
        _gameStopwatch = new System.Diagnostics.Stopwatch();
        _gameStopwatch.Start();

        var instructions = new TextBox
        {
            Multiline = true,
            ReadOnly = true,
            TabStop = false,
            ScrollBars = ScrollBars.Vertical,
            Location = new Point(10, 10),
            Size = new Size(560, 220),
            Text = Step12Text
        };
        Controls.Add(instructions);

        _lblCounter = new Label
        {
            Text = "Game Time: 0 seconds",
            Location = new Point(10, 250),
            Size = new Size(350, 40),
            Font = new Font("Segoe UI", 18, FontStyle.Bold)
        };
        Controls.Add(_lblCounter);

        _lblSpeed = new Label
        {
            Text = "Speed: 1.0x (normal)",
            Location = new Point(10, 300),
            Size = new Size(350, 25),
            ForeColor = Color.Gray
        };
        Controls.Add(_lblSpeed);

        var progressBar = new ProgressBar
        {
            Location = new Point(10, 330),
            Size = new Size(400, 25),
            Minimum = 0,
            Maximum = 100,
            Value = 0
        };
        Controls.Add(progressBar);

        _btnNext = new Button { Text = "Next", Location = new Point(480, 435), Size = new Size(80, 36), Enabled = false };
        _btnNext.Click += (s, e) => { Hide(); new TutorialStep13Form { Location = Location }.Show(); };
        Controls.Add(_btnNext);

        // Poll frequently to detect speed hack effects
        _pollTimer = new System.Windows.Forms.Timer { Interval = 50 };
        _pollTimer.Tick += (s, e) =>
        {
            // Game time from Stopwatch (uses QueryPerformanceCounter - affected by speed hack)
            int gameSeconds = (int)_gameStopwatch.Elapsed.TotalSeconds;

            // Real time from DateTime (not affected by speed hack)
            double realSeconds = (DateTime.Now - _realStartTime).TotalSeconds;

            // Calculate speed multiplier
            double speedMultiplier = realSeconds > 0.5 ? gameSeconds / realSeconds : 1.0;

            // Update display only when second changes
            if (gameSeconds != _lastSecond)
            {
                _lastSecond = gameSeconds;
                _lblCounter.Text = $"Game Time: {gameSeconds} seconds";
                progressBar.Value = Math.Min(gameSeconds, 100);

                if (speedMultiplier > 1.5)
                {
                    _lblSpeed.Text = $"Speed: {speedMultiplier:F1}x (speedhack active!)";
                    _lblSpeed.ForeColor = Color.Green;
                }
                else
                {
                    _lblSpeed.Text = $"Speed: {speedMultiplier:F1}x (normal)";
                    _lblSpeed.ForeColor = Color.Gray;
                }
            }

            // Win condition
            if (gameSeconds >= 100)
            {
                _btnNext.Enabled = true;
                _pollTimer.Stop();
                _gameStopwatch.Stop();
            }
        };
        _pollTimer.Start();

        TutorialNavigation.AddNavigationControls(this, 12);
        FormClosing += (s, e) =>
        {
            _pollTimer.Stop();
            _gameStopwatch.Stop();
            Environment.Exit(0);
        };
    }
}
