// Tutorial Navigation Helper
// Split from TutorialForms.cs for maintainability

using System.Drawing;

namespace Nexus.Tutorial;

/// <summary>
/// Helper class for step-based navigation across all tutorial forms.
/// </summary>
public static class TutorialNavigation
{
    public const int TotalSteps = 18;

    private static readonly Dictionary<int, Func<Form>> Steps = new()
    {
        { 1, () => new TutorialMainForm() },
        { 2, () => new TutorialStep2Form() },
        { 3, () => new TutorialStep3Form() },
        { 4, () => new TutorialStep4Form() },
        { 5, () => new TutorialStep5Form() },
        { 6, () => new TutorialStep6Form() },
        { 7, () => new TutorialStep7Form() },
        { 8, () => new TutorialStep8Form() },
        { 9, () => new TutorialStep9Form() },
        { 10, () => new TutorialStep10Form() },
        { 11, () => new TutorialStep11Form() },
        { 12, () => new TutorialStep12Form() },
        { 13, () => new TutorialStep13Form() },
        { 14, () => new TutorialStep14Form() },
        { 15, () => new TutorialStep15Form() },
        { 16, () => new TutorialStep17Form() },
        { 17, () => new TutorialStep19Form() },
        { 18, () => new TutorialStep21Form() }
    };

    /// <summary>
    /// Adds navigation buttons (Skip/Back) to a tutorial form. Each form manages its own Next button
    /// since it needs to control when Next is enabled (after completing the step task).
    /// Skip allows users to advance without completing the step's challenge.
    /// </summary>
    public static void AddNavigationControls(Form form, int currentStep, int yPosition = 435)
    {
        // Layout: [Skip] [Back] [Next]
        // Next is at 480, so Back at 395, Skip at 310

        // Add Skip button if not on first or last step
        if (currentStep > 1 && currentStep < TotalSteps)
        {
            var btnSkip = new Button
            {
                Text = "Skip",
                Location = new Point(310, yPosition),
                Size = new Size(75, 36)
            };
            btnSkip.Click += (s, e) => GoToStep(currentStep + 1, form);
            form.Controls.Add(btnSkip);
        }

        // Add Back button if not on first step
        if (currentStep > 1)
        {
            var btnBack = new Button
            {
                Text = "Back",
                Location = new Point(395, yPosition),
                Size = new Size(75, 36)
            };
            btnBack.Click += (s, e) => GoToStep(currentStep - 1, form);
            form.Controls.Add(btnBack);
        }
    }

    /// <summary>
    /// Navigate to a specific step number.
    /// </summary>
    public static void GoToStep(int step, Form currentForm)
    {
        if (Steps.TryGetValue(step, out var createForm))
        {
            currentForm.Hide();
            var newForm = createForm();
            newForm.Location = currentForm.Location;
            newForm.Show();
        }
    }
}
