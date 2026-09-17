namespace Nexus.Tutorial;

static class Program
{
    /// <summary>
    /// The main entry point for the Tutorial application.
    /// </summary>
    [STAThread]
    static void Main()
    {
        ApplicationConfiguration.Initialize();
        Application.Run(new TutorialMainForm());
    }
}
