using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Text;

namespace PSeeLibrary
{
    //https://docs.microsoft.com/en-us/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed#net_a
    public static class ClrVer
    {
        struct MinVerInstalled
        {
            public static bool V2 { get; set; }
            public static bool V35Sp1 { get; set; }
            public static bool V4 { get; set; }
            public static bool V45 { get; set; }
        }

        static Int32 net45MinVer = 379893;
        static Dictionary<int, String> net45Versions = new Dictionary<Int32, String>
            {{378389, ".NET Framework 4.5"},
            {378675, ".NET Framework 4.5.1"},
            {379893, ".NET Framework 4.5.2"},
            {393295, ".NET Framework 4.6"},
            {394254, ".NET Framework 4.6.1"},
            {394802, ".NET Framework 4.6.2"},
            {460798, ".NET Framework 4.7"},
            {461308, ".NET Framework 4.7.1"},
            {461808, ".NET Framework 4.7.2"}};

        public static String GetVersionFromRegistry()
        {
            var resultsBuilder = new StringBuilder();

            using (var lmHive = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, ""))
            using (var ndpKey = lmHive.OpenSubKey(@"SOFTWARE\Microsoft\NET Framework Setup\NDP\"))
            {
                if (null != ndpKey)
                {
                    foreach (string versionKeyName in ndpKey.GetSubKeyNames())
                    {
                        if (versionKeyName.StartsWith("v"))
                        {
                            if (versionKeyName.StartsWith("v2"))
                                MinVerInstalled.V2 = true;
                            if (versionKeyName.StartsWith("v4"))
                                MinVerInstalled.V4 = true;
                            var versionKey = ndpKey.OpenSubKey(versionKeyName);
                            var name = (string)versionKey.GetValue("Version", "");
                            var sp = versionKey.GetValue("SP", "").ToString();
                            var install = versionKey.GetValue("Install", "").ToString();
                            if (install == "")
                                resultsBuilder.AppendLine($"\t[+] {versionKeyName} {name}");
                            else
                                if (!String.IsNullOrEmpty(sp) && !String.IsNullOrEmpty(install))
                            {
                                resultsBuilder.AppendLine($"\t[+] {versionKeyName} {name} SP {sp}");
                                if (versionKeyName.StartsWith("v3.5") && sp == "1")
                                    MinVerInstalled.V35Sp1 = true;
                            }

                            if (name != "")
                                continue;

                            foreach (string subKeyName in versionKey.GetSubKeyNames())
                            {
                                var subKey = versionKey.OpenSubKey(subKeyName);
                                name = (string)subKey.GetValue("Version", "");
                                var release = subKey.GetValue("Release", -1) as Int32?;
                                if (!String.IsNullOrEmpty(name))
                                    sp = subKey.GetValue("SP", "").ToString();

                                String net45Ver = null;
                                String net45Error = null;
                                if (release.HasValue && release.Value > -1)
                                {
                                    if (net45Versions.ContainsKey(release.Value))
                                        net45Ver = $"{net45Versions[release.Value]}";
                                    else
                                        net45Error = $"\t\t[!] Unrecognised .Net 4.5+ version {release.Value} please update this tool";

                                    if (release.Value >= net45MinVer)
                                        MinVerInstalled.V45 = true;
                                }
                                install = subKey.GetValue("Install", "").ToString();
                                if (install == "")
                                    resultsBuilder.Append($"{versionKeyName} {name}");
                                else
                                    if (sp != "" && install == "1")
                                    resultsBuilder.Append($"\t\t{subKeyName} {name} SP {sp}");
                                else if (install == "1")
                                    resultsBuilder.Append($"\t\t{subKeyName} {name}");

                                if (!String.IsNullOrEmpty(net45Ver))
                                    resultsBuilder.AppendLine($" ({net45Ver})");
                                else
                                    resultsBuilder.AppendLine("");

                                if (!String.IsNullOrEmpty(net45Error))
                                    resultsBuilder.AppendLine($"{net45Error}");
                            }
                        }
                    }
                }
                else
                    resultsBuilder.AppendLine(@"[!] No key at HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP .Net possibly not installed");
            }

            if (MinVerInstalled.V2 && !MinVerInstalled.V35Sp1)
                resultsBuilder.AppendLine(@"[X] End of Life Version of .Net v2 installed. Minimun version is .Net 3.5 SP1");

            if (MinVerInstalled.V4 && !MinVerInstalled.V45)
                resultsBuilder.AppendLine(@"[X] End of Life Version of .Net v4 installed. Minimun version is .Net 4.5.2");

            return resultsBuilder.ToString();
        }
    }
}
