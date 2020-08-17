using System;
using System.Collections.Generic;

namespace Core.Arp
{
    class Core
    {
        internal static void RunArp(string[] args)
        {
            try
            {
                if (args.Length < 2)
                {
                    Console.WriteLine("Usage: Arpscan.exe 172.16.0.1/24 true");
                }
                else
                {
                    ArpScanner ArpScanner = new ArpScanner();
                    Dictionary<String, String> result = ArpScanner.DoScan(args[1]);

                    if (args.Length > 2 && !String.IsNullOrEmpty(args[2]))
                    {
                        Console.WriteLine("");
                        Console.WriteLine("[+] Arpscan / IP resolution against: " + args[1]);
                        Console.WriteLine("================================================================");
                        foreach (KeyValuePair<string, string> kvp in result)
                        {
                            string hostname = ArpScanner.gethostbyaddrNetBIOS(kvp.Key);
                            Console.WriteLine("IP Address = {0}, Hostname = {1}, MAC = {2}", kvp.Key, hostname, kvp.Value);
                        }
                    }
                    else
                    {
                        Console.WriteLine("[+] Arpscan against: " + args[1]);
                        Console.WriteLine("=================================================");
                        foreach (KeyValuePair<string, string> kvp in result)
                        {
                            Console.WriteLine("IP Address = {0}, MAC = {1}", kvp.Key, kvp.Value);
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("Error: " + e);
            }
        }
    }
}
