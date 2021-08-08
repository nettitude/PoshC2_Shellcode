using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Security.Principal;
using System.Diagnostics;
using System.Linq;
using System.Collections.Generic;

namespace Core.ProcessHandler
{
    public static class ProcHandler
    {
        //inner enum used only internally
        [Flags]
        private enum SnapshotFlags : uint
        {
            HeapList = 0x00000001,
            Process = 0x00000002,
            Thread = 0x00000004,
            Module = 0x00000008,
            Module32 = 0x00000010,
            Inherit = 0x80000000,
            All = 0x0000001F,
            NoHeaps = 0x40000000
        }
        //inner struct used only internally
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct PROCESSENTRY32
        {
            const int MAX_PATH = 260;
            internal UInt32 dwSize;
            internal UInt32 cntUsage;
            internal UInt32 th32ProcessID;
            internal IntPtr th32DefaultHeapID;
            internal UInt32 th32ModuleID;
            internal UInt32 cntThreads;
            internal UInt32 th32ParentProcessID;
            internal Int32 pcPriClassBase;
            internal UInt32 dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
            internal string szExeFile;
        }

        [DllImport("kernel32", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)] static extern IntPtr CreateToolhelp32Snapshot([In]UInt32 dwFlags, [In]UInt32 th32ProcessID);
        [DllImport("kernel32", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)] static extern bool Process32First([In]IntPtr hSnapshot, ref PROCESSENTRY32 lppe);
        [DllImport("kernel32", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)] static extern bool Process32Next([In]IntPtr hSnapshot, ref PROCESSENTRY32 lppe);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CloseHandle([In] IntPtr hObject);
        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)] [return: MarshalAs(UnmanagedType.Bool)] public static extern bool IsWow64Process([In] IntPtr processHandle, [Out, MarshalAs(UnmanagedType.Bool)] out bool wow64Process);

        // get processes
        // https://www.pinvoke.net/default.aspx/kernel32.createtoolhelp32snapshot
        public static string GetProcesses()
        {
            Process Proc = null;
            IntPtr handleToSnapshot = IntPtr.Zero;
            StringBuilder pids = new StringBuilder();
            try
            {
                PROCESSENTRY32 procEntry = new PROCESSENTRY32();
                procEntry.dwSize = (UInt32)Marshal.SizeOf(typeof(PROCESSENTRY32));
                handleToSnapshot = CreateToolhelp32Snapshot((uint)SnapshotFlags.Process, 0);

                pids.Append("PID".PadRight(10) + "USER".PadRight(15) + "ARCH".PadRight(10) + "PPID".PadRight(10) + "NAME" + "\n");
                pids.Append("===".PadRight(10) + "====".PadRight(15) + "====".PadRight(10) + "====".PadRight(10) + "====" + "\n");
                for (Process32First(handleToSnapshot, ref procEntry); Process32Next(handleToSnapshot, ref procEntry);)
                {
                    string x = "";
                    Proc = Process.GetProcessById((int)procEntry.th32ProcessID);
                    IntPtr processArch = IntPtr.Zero;
                    bool is64bit;
                    bool is32os = is32bitarch();
                    if (is32os == false)
                    {
                        try
                        {
                            IsWow64Process(Proc.Handle, out is64bit);
                            if (is64bit)
                            {
                                x = "x86";
                            }
                            else
                            {
                                x = "x64";
                            }
                        }
                        catch { }
                    }
                    else
                    {
                        x = "x86";
                    }

                    pids.Append(procEntry.th32ProcessID.ToString().PadRight(10));
                    pids.Append(GetProcessUser(Proc).PadRight(15));
                    pids.Append(x.ToString().PadRight(10));
                    pids.Append(procEntry.th32ParentProcessID.ToString().PadRight(10));
                    pids.Append(procEntry.szExeFile.ToString());
                    pids.Append("\n");
                }
            }
            catch
            {

            }
            finally
            {
                CloseHandle(handleToSnapshot);
            }
            return pids.ToString();
        }

        private static bool is32bitarch()
        {
            string v = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITEW6432");

            if ((IntPtr.Size == 4) && (v == null))
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        // Get username from process
        // https://stackoverflow.com/questions/777548/how-do-i-determine-the-owner-of-a-process-in-c

        private static string GetProcessUser(Process process)
        {
            IntPtr processHandle = IntPtr.Zero;
            try
            {
                OpenProcessToken(process.Handle, 8, out processHandle);
                WindowsIdentity wi = new WindowsIdentity(processHandle);
                string user = wi.Name;
                return user.Contains(@"\") ? user.Substring(user.IndexOf(@"\") + 1) : user;
            }
            catch
            {
                return "";
            }
            finally
            {
                if (processHandle != IntPtr.Zero)
                {
                    CloseHandle(processHandle);
                }
            }
        }
        public static void DllSearcher(List<string> checks)
        {
            List<string> results = new List<string>();
            Process[] localAll = Process.GetProcesses();
            foreach (var proc in localAll)
            {
                try
                {
                    foreach (var module in proc.Modules)
                    {
                        string modulename = module.ToString().Replace("System.Diagnostics.ProcessModule (", "").Replace(")", "").ToLower();
                        if (checks.Contains(modulename))
                        {
                            results.Add(string.Format(modulename));
                        }
                    }
                }
                catch (Exception e)
                {
                    //Console.WriteLine("Access Denied"); 
                }
                if (results.Count > 0)
                {
                    Console.WriteLine("\nProcess Name: {0} & PID:{1}", proc.ProcessName, proc.Id);
                    foreach (string r in results)
                    {
                        Console.WriteLine("Found: {0}", r);
                    }
                    results.Clear();
                }
            }
        }
    }
}
