// Tutorial Step 1 - Introduction
// Split from TutorialForms.cs for maintainability

using System.Drawing;

namespace Nexus.Tutorial;

/// <summary>
/// Main tutorial form - Step 1 introduction.
/// </summary>
public class TutorialMainForm : Form
{
    private const string Tutorial1Text = @"Welcome to the Nexus Sentinel Tutorial (v1.0)

This tutorial will teach you the basics of cheating in video games. It will also show you foundational aspects of using Nexus Sentinel (or NS for short). Follow the steps below to get started.

1: Open Nexus Sentinel if it currently isn't running.
2: Click on the ""Open Process"" icon to open the process selection window.
3: With the Process List window now open, look for this tutorial's process in the list. It will look something like ""NexusTutorial"" or ""NexusTutorial.exe"".
4: Once you've found the process, click on it to select it, then click the ""Open"" button. (Don't worry about all the other buttons right now. You can learn about them later if you're interested.)

Congratulations! If you did everything correctly, the process window should be gone with Nexus Sentinel now attached to the tutorial (you will see the process name in NS).

Click the ""Next"" button below to continue to the next step.";

    public TutorialMainForm()
    {
        Text = "Nexus Sentinel Tutorial - Step 1";
        Size = new Size(600, 560);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        StartPosition = FormStartPosition.CenterScreen;
        Font = new Font("Segoe UI", 10);

        var instructions = new TextBox
        {
            Multiline = true,
            ReadOnly = true,
            TabStop = false,
            ScrollBars = ScrollBars.Vertical,
            Location = new Point(10, 10),
            Size = new Size(560, 400),
            Text = Tutorial1Text
        };
        Controls.Add(instructions);

        var btnNext = new Button
        {
            Text = "Next",
            Location = new Point(480, 435),
            Size = new Size(80, 36)
        };
        btnNext.Click += (s, e) => { Hide(); new TutorialStep2Form { Location = Location }.Show(); };
        Controls.Add(btnNext);

        TutorialNavigation.AddNavigationControls(this, 1);
        FormClosing += (s, e) => Environment.Exit(0);
    }
}
