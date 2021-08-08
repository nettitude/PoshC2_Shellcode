using System;
using System.Collections.Generic;
using System.Management;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Collections;

namespace Core.Host
{
    class Get_UserInfo
    {
        public static void Run()
        {
            try
            {
                ManagementObjectSearcher wmiData = new ManagementObjectSearcher(@"root\cimv2", "Select * from win32_operatingsystem");
                ManagementObjectCollection data = wmiData.Get();

                foreach (ManagementObject result in data)
                {
                    Console.WriteLine("LastBootTime: " + ManagementDateTimeConverter.ToDateTime(result["LastBootUpTime"].ToString()));
                }

                wmiData = new ManagementObjectSearcher(@"root\cimv2", "Select * from Win32_UserAccount Where LocalAccount = True");
                data = wmiData.Get();

                Console.WriteLine("\r\n======================");
                Console.WriteLine("Local Users");
                Console.WriteLine("======================");
                foreach (ManagementObject result in data)
                {
                    Console.WriteLine(result["Name"]);
                }

                Console.WriteLine("\r\n======================");
                Console.WriteLine("Local Groups");
                Console.WriteLine("======================");
                wmiData = new ManagementObjectSearcher(@"root\cimv2", "Select * from Win32_Group Where LocalAccount = True");
                data = wmiData.Get();

                foreach (ManagementObject result in data)
                {
                    Console.WriteLine(result["Name"]);
                }

                Console.WriteLine("\r\n=========================");
                Console.WriteLine("Members of Local Groups");
                Console.WriteLine("=========================");
                wmiData = new ManagementObjectSearcher(@"root\cimv2", "Select * from Win32_Group Where LocalAccount = True");
                data = wmiData.Get();

                List<string> members = new List<string>();
                var cn = System.Environment.GetEnvironmentVariable("COMPUTERNAME");
                foreach (ManagementObject result in data)
                {
                    ManagementObjectSearcher wmiDataG = new ManagementObjectSearcher(@"root\cimv2", "Select * from Win32_GroupUser Where GroupComponent=\"Win32_Group.Domain='" + cn + "',Name='" + result["Name"] + "'\"");
                    ManagementObjectCollection gData = wmiDataG.Get();

                    if (gData.Count > 0)
                    {
                        Console.WriteLine("\r\n> " + result["Name"]);
                        Console.WriteLine("======================");
                        foreach (ManagementObject gMember in gData)
                        {
                            var splitargs = gMember.GetPropertyValue("PartComponent").ToString().Split(new string[] { "," }, StringSplitOptions.RemoveEmptyEntries);
                            var sDomain = splitargs[0].Split(new string[] { "=" }, StringSplitOptions.RemoveEmptyEntries)[1].Replace("\"", "");
                            var sUser = splitargs[1].Split(new string[] { "=" }, StringSplitOptions.RemoveEmptyEntries)[1].Replace("\"", "");
                            members.Add(sDomain + "\\" + sUser);
                        }
                        members.ForEach(i => Console.Write("{0}\r\n", i));
                        members.Clear();
                    }
               
                }

                try
                {
                    Console.WriteLine("\r\n==========================");
                    Console.WriteLine($"Domain UserInfo ({Environment.UserName})");
                    Console.WriteLine("==========================");
                    DirectorySearcher searcher = new DirectorySearcher();
                    searcher.Filter = $"(&(objectCategory=user)(cn={Environment.UserName}))";
                    SearchResultCollection results = searcher.FindAll();

                    foreach (SearchResult searchResult in searcher.FindAll())
                    {
                        foreach (string propName in searchResult.Properties.PropertyNames)
                        {
                            ResultPropertyValueCollection valueCollection =
                            searchResult.Properties[propName];
                            foreach (Object propertyValue in valueCollection)
                            {
                                Console.WriteLine(propName + ": " + propertyValue.ToString());
                            }
                        }
                    }


                }
                catch (Exception e)
                {
                    Console.WriteLine($"Error: {e.Message}");
                }

                try
                {
                    Console.WriteLine("\r\n===================================");
                    Console.WriteLine($"Domain Password Policy ({Environment.UserDomainName})");
                    Console.WriteLine("===================================");

                    Console.WriteLine($"Using DirectoryEntry: WinNT://{Environment.UserDomainName}");

                    DirectoryEntry root = new DirectoryEntry($"WinNT://{Environment.UserDomainName}");
                    Console.WriteLine("Name: " + root.Properties["Name"].Value);
                    Console.WriteLine("MinPasswordLength: " + root.Properties["MinPasswordLength"].Value);
                    Console.WriteLine("MinPasswordAge: " + (int)root.Properties["MinPasswordAge"].Value / 86400);
                    Console.WriteLine("MaxPasswordAge: " + (int)root.Properties["MaxPasswordAge"].Value / 86400);
                    Console.WriteLine("PasswordHistoryLength: " + root.Properties["PasswordHistoryLength"].Value);
                    Console.WriteLine("MaxBadPasswordsAllowed: " + root.Properties["MaxBadPasswordsAllowed"].Value);
                    Console.WriteLine("AutoUnlockInterval: " + (int)root.Properties["AutoUnlockInterval"].Value / 60);
                    Console.WriteLine("LockoutObservationInterval: " + (int)root.Properties["LockoutObservationInterval"].Value / 60);
                }
                catch(Exception e) {
                    Console.WriteLine($"Error: {e.Message}");
                }

                try
                {
                    Console.WriteLine("\r\n===================================");
                    Console.WriteLine("GetEnvironmentVariables: ");
                    Console.WriteLine("\r\n===================================");
                    foreach (DictionaryEntry de in Environment.GetEnvironmentVariables())
                    {
                        Console.WriteLine("{0} = {1}", de.Key, de.Value);
                    }                        
                }
                catch (Exception e) {
                    Console.WriteLine($"Error GetEnvironmentVariables: {e.Message}");                
                }
        }
            catch (Exception ex)
            {
                Console.WriteLine("Error: {0}", ex);
            }
        }
    }
}
