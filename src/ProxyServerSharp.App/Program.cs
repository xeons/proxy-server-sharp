namespace ProxyServerSharp.App;

/// <summary>Entry point for the Windows desktop front-end.</summary>
internal static class Program
{
    [STAThread]
    private static void Main()
    {
        // Replaces the old EnableVisualStyles/SetCompatibleTextRenderingDefault pair and picks up
        // the high-DPI mode declared in the project file.
        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
    }
}
