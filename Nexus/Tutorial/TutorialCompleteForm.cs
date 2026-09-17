// Tutorial Complete - Final completion screen
// Split from TutorialForms.cs for maintainability

using System.Drawing;

namespace Nexus.Tutorial;

/// <summary>
/// Tutorial Complete - Final completion screen.
/// </summary>
public class TutorialCompleteForm : Form
{
    private const string CompleteText = @"Congratulations!

You have completed the Nexus Sentinel Extended Tutorial!

You have mastered ALL 18 steps:
- Process attachment and basic scanning
- Exact value, unknown value, float/double scanning
- Code finder and code injection
- Single and multi-level pointers
- Shared code identification
- String scanning (ASCII/Unicode)
- AOB/Signature scanning with wildcards
- Speed hack manipulation
- Byte, 2-byte, and 8-byte value types
- Value freezing/locking
- Memory viewer and hex editing
- Nexus Sentinel Table (.NST) files
- Structure dissection
- Hotkey configuration

You now have COMPLETE knowledge of all Nexus Sentinel features!

Total steps completed: 18
Test coverage: Comprehensive

Thank you for completing the Nexus Sentinel Tutorial!";

    public TutorialCompleteForm()
    {
        Text = "Nexus Sentinel Tutorial - Complete!";
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
            Size = new Size(560, 400),
            Text = CompleteText
        };
        Controls.Add(instructions);

        var btnClose = new Button
        {
            Text = "Close",
            Location = new Point(480, 435),
            Size = new Size(80, 36)
        };
        btnClose.Click += (s, e) => Application.Exit();
        Controls.Add(btnClose);

        // Add Back button to go back to Step 19
        var btnBack = new Button
        {
            Text = "Back",
            Location = new Point(395, 435),
            Size = new Size(75, 36)
        };
        btnBack.Click += (s, e) => TutorialNavigation.GoToStep(21, this);
        Controls.Add(btnBack);
        FormClosing += (s, e) => Environment.Exit(0);
    }
}
