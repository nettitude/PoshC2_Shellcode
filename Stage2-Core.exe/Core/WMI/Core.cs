using System;
using System.Management;
using System.Text;
using System.Threading.Tasks;

namespace Core.WMI
{
    class Core
    {
        internal static Task wmitasklistall(string machineName)
        {
            StringBuilder output = new StringBuilder();
            try
            {
                var resultUserName = string.Empty;
                output.Append($"\n[+] Running WMI process list against: {machineName}\n");
                ConnectionOptions opt = new ConnectionOptions();
                string path = string.Format(@"\\{0}\root\cimv2", machineName);
                ManagementScope scope = new ManagementScope(path, opt);
                scope.Connect();
                var query = new ObjectQuery(string.Format("Select * From Win32_Process"));
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query);
                var processList = searcher.Get();
                foreach (ManagementObject obj in processList)
                {
                    string[] argList = new string[] { string.Empty, string.Empty };
                    int returnVal = Convert.ToInt32(obj.InvokeMethod("GetOwner", argList));
                    if (returnVal == 0)
                    {
                        var userName = argList[1] + "\\" + argList[0];
                        output.Append($"[>] {obj["Name"]} ({obj["ProcessId"]}) running under {userName} on {machineName}\n");
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot run WMI: {e.Message}");
            }
            Console.WriteLine(output.ToString());
            return Task.CompletedTask;
        }

        internal static Task wmitasklist(string machineName, string processName)
        {
            StringBuilder output = new StringBuilder();
            try
            {
                var resultUserName = string.Empty;
                output.Append($"\n[+] Running WMI process list against: {machineName} for process: {processName}\n");
                ConnectionOptions opt = new ConnectionOptions();
                string path = string.Format(@"\\{0}\root\cimv2", machineName);
                ManagementScope scope = new ManagementScope(path, opt);
                scope.Connect();
                var query = new ObjectQuery(string.Format("Select * From Win32_Process Where Name = '{0}'", processName));
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query);
                var processList = searcher.Get();
                foreach (ManagementObject obj in processList)
                {
                    string[] argList = new string[] { string.Empty, string.Empty };
                    int returnVal = Convert.ToInt32(obj.InvokeMethod("GetOwner", argList));
                    if (returnVal == 0)
                    {
                        var userName = argList[1] + "\\" + argList[0];
                        output.Append($"[>] {processName} running under {userName} on {machineName}\n");
                    }
                }
            }
            catch (Exception e)
            {
                output.Append($"[-] Cannot run WMI: {e.Message}");
            }
            Console.WriteLine(output.ToString());
            return Task.CompletedTask;
        }
    }
}
