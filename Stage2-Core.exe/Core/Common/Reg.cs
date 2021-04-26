using System;
using Microsoft.Win32;

namespace Core.Common
{
    class Reg
    {
        public static void RegReadUninstall()
        {
            string regKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
            using (Microsoft.Win32.RegistryKey uninstallKey = Registry.LocalMachine.OpenSubKey(regKey))
            {
                if (uninstallKey != null)
                {
                    string[] productKeys = uninstallKey.GetSubKeyNames();
                    foreach (var keyName in productKeys)
                    {
                        string InstallPath = (string)Registry.GetValue($"HKEY_LOCAL_MACHINE\\{regKey}\\{keyName}", "UninstallString", null);
                        string DisplayName = (string)Registry.GetValue($"HKEY_LOCAL_MACHINE\\{regKey}\\{keyName}", "DisplayName", null);
                        if (InstallPath != null)
                        {
                            Console.WriteLine($"Key Value {keyName}:\n > {DisplayName.ToString()} : {InstallPath.ToString()}");
                        }
                    }
                }
            }
        }
        public static void LsReg(string regKey, string hive = "HKEY_LOCAL_MACHINE")
        {

            RegistryKey openRegKey = hive switch
            {
                "HKEY_CLASSES_ROOT" => Registry.ClassesRoot.OpenSubKey(regKey, false),
                "HKEY_CURRENT_USER" => Registry.CurrentUser.OpenSubKey(regKey, false),
                "HKEY_LOCAL_MACHINE" => Registry.LocalMachine.OpenSubKey(regKey, false),
                "HKEY_USERS" => Registry.Users.OpenSubKey(regKey, false),
                "HKEY_CURRENT_CONFIG" => Registry.CurrentConfig.OpenSubKey(regKey, false),
                _ => throw new NotSupportedException("Incorrent hive")
            };

            using (openRegKey)
            {
                if (openRegKey != null)
                {
                    string[] productKeys = openRegKey.GetSubKeyNames();
                    foreach (var keyName in productKeys)
                    {
                        try
                        {
                            Console.WriteLine(keyName);
                            using (RegistryKey key2 = openRegKey.OpenSubKey(keyName))
                            {
                                foreach (string valuename in key2.GetValueNames())
                                {
                                    try
                                    {
                                        string value = null;
                                        string[] straValue = null;
                                        byte[] byteValue = null;
                                        try
                                        {
                                            value = (string)Registry.GetValue($"{hive}\\{regKey}\\{keyName}", valuename, null).ToString();
                                        }
                                        catch { }
                                        try
                                        {
                                            straValue = (string[])Registry.GetValue($"{hive}\\{regKey}\\{keyName}", valuename, null);
                                        }
                                        catch { }
                                        try
                                        {
                                            byteValue = (byte[])Registry.GetValue($"{hive}\\{regKey}\\{keyName}", valuename, null);
                                        }
                                        catch { }
                                        if (straValue != null)
                                        {
                                            Console.WriteLine($" > {valuename} : ");
                                            foreach (string val in straValue)
                                            {
                                                Console.WriteLine($"  >> {val}");

                                            }
                                        }
                                        else if (byteValue != null)
                                        {
                                            Console.Write($" > {valuename} : \n  >> ");
                                            foreach (byte val in byteValue)
                                            {
                                                Console.Write(val);
                                            }
                                            Console.WriteLine($"");
                                        }
                                        else if (value != null)
                                        {
                                            var strKeyname = "";
                                            if (String.IsNullOrEmpty(valuename))
                                            {
                                                strKeyname = "Default";
                                            }
                                            else
                                            {
                                                strKeyname = valuename;
                                            }
                                            Console.WriteLine($" > {strKeyname} : {value.ToString()}");
                                        }
                                        else
                                        {
                                            Console.WriteLine(valuename);
                                        }
                                    }
                                    catch (Exception e)
                                    {
                                        Console.WriteLine(e.Message);
                                    }

                                }
                            }
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine(e.Message);
                        }
                    }
                }
            }
        }
        public static void ReadReg(string regpath, string regkey)
        {
            try
            {
                string InstallPath = (string)Registry.GetValue(regpath, regkey, null);
                if (InstallPath != null)
                {
                    Console.WriteLine($"Key Value: {InstallPath.ToString()}");
                }
            }
            catch (Exception ex) 
            {
                Console.WriteLine($"Error reading RegKey: {ex.Message}");
            }
        }
    }
}
