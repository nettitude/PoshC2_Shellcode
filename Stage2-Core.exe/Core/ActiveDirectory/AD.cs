using System;
using System.Collections.Generic;
using System.Management;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Text;
using System.Runtime.Serialization.Formatters.Binary;
using System.IO;
using System.Collections;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.Reflection;

namespace Core.ActiveDirectory
{
    public class NetAPI32
    {
        public const int ErrorSuccess = 0;

        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int NetGetJoinInformation(string server, out IntPtr domain, out NetJoinStatus status);

        [DllImport("Netapi32.dll")]
        public static extern int NetApiBufferFree(IntPtr Buffer);

        public enum NetJoinStatus
        {
            NetSetupUnknownStatus = 0,
            NetSetupUnjoined,
            NetSetupWorkgroupName,
            NetSetupDomainName
        }
        public enum DSREG_JOIN_TYPE
        {
            DSREG_UNKNOWN_JOIN,
            DSREG_DEVICE_JOIN,
            DSREG_WORKPLACE_JOIN
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct DSREG_USER_INFO
        {
            [MarshalAs(UnmanagedType.LPWStr)] public string UserEmail;
            [MarshalAs(UnmanagedType.LPWStr)] public string UserKeyId;
            [MarshalAs(UnmanagedType.LPWStr)] public string UserKeyName;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct CERT_CONTEX
        {
            public uint dwCertEncodingType;
            public byte pbCertEncoded;
            public uint cbCertEncoded;
            public IntPtr pCertInfo;
            public IntPtr hCertStore;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct DSREG_JOIN_INFO
        {
            public int joinType;
            public IntPtr pJoinCertificate;
            [MarshalAs(UnmanagedType.LPWStr)] public string DeviceId;
            [MarshalAs(UnmanagedType.LPWStr)] public string IdpDomain;
            [MarshalAs(UnmanagedType.LPWStr)] public string TenantId;
            [MarshalAs(UnmanagedType.LPWStr)] public string JoinUserEmail;
            [MarshalAs(UnmanagedType.LPWStr)] public string TenantDisplayName;
            [MarshalAs(UnmanagedType.LPWStr)] public string MdmEnrollmentUrl;
            [MarshalAs(UnmanagedType.LPWStr)] public string MdmTermsOfUseUrl;
            [MarshalAs(UnmanagedType.LPWStr)] public string MdmComplianceUrl;
            [MarshalAs(UnmanagedType.LPWStr)] public string UserSettingSyncUrl;
            public IntPtr pUserInfo;
        }

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern void NetFreeAadJoinInformation(
                IntPtr pJoinInfo);

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int NetGetAadJoinInformation(
                string pcszTenantId,
                out IntPtr ppJoinInfo);
    }
    class AD
    {
        //https://stackoverflow.com/questions/926227/how-to-detect-if-machine-is-joined-to-domain
        public static bool IsInDomain()
        {
            NetAPI32.NetJoinStatus status = NetAPI32.NetJoinStatus.NetSetupUnknownStatus;
            IntPtr pDomain = IntPtr.Zero;
            int result = NetAPI32.NetGetJoinInformation(null, out pDomain, out status);
            if (pDomain != IntPtr.Zero)
            {
                NetAPI32.NetApiBufferFree(pDomain);
            }
            if (result == NetAPI32.ErrorSuccess)
            {
                return status == NetAPI32.NetJoinStatus.NetSetupDomainName;
            }
            else
            {
                throw new Exception("Domain Info Get Failed", new Win32Exception());
            }
        }
        // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/18d8fbe8-a967-4f1c-ae50-99ca8e491d2d
        // https://docs.microsoft.com/en-us/windows/win32/api/lmjoin/nf-lmjoin-netgetaadjoininformation
        // https://support.microsoft.com/en-us/help/2909958/exceptions-in-windows-powershell-other-dynamic-languages-and-dynamical
        // https://deploywindows.com/2020/09/16/dont-wrap-dsregcmd-with-powershell-use-this-to-get-azure-ad-information-from-the-local-computer/
        public static void getaadjoininformation()
        {
            string pcszTenantId = null;
            var ptrJoinInfo = IntPtr.Zero;
            var ptrUserInfo = IntPtr.Zero;
            var ptrJoinCertificate = IntPtr.Zero;
            NetAPI32.DSREG_JOIN_INFO joinInfo = new NetAPI32.DSREG_JOIN_INFO();

            NetAPI32.NetFreeAadJoinInformation(IntPtr.Zero);
            var retValue = NetAPI32.NetGetAadJoinInformation(pcszTenantId, out ptrJoinInfo);

            if (retValue == 0)
            {
                Console.WriteLine($"[+] Starting Aad Enum:");

                try
                {
                    NetAPI32.DSREG_JOIN_INFO ptrJoinInfoObject = new NetAPI32.DSREG_JOIN_INFO();
                    joinInfo = (NetAPI32.DSREG_JOIN_INFO)System.Runtime.InteropServices.Marshal.PtrToStructure(ptrJoinInfo, (System.Type)ptrJoinInfoObject.GetType());

                    FieldInfo[] fi = typeof(NetAPI32.DSREG_JOIN_INFO).GetFields(BindingFlags.Public | BindingFlags.Instance);
                    foreach (FieldInfo info in fi)
                    {
                        var x = info.GetValue(joinInfo);
                        Console.WriteLine($" > {info.Name} : {x}");
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine($"[-] Error running Aad Enum: {e.Message}");
                }

                try 
                {
                    Console.WriteLine($"\n[+] Starting UserInfo Enum:");
                    ptrUserInfo = joinInfo.pUserInfo;
                    NetAPI32.DSREG_USER_INFO ptrUserInfoObject = new NetAPI32.DSREG_USER_INFO();
                    NetAPI32.DSREG_USER_INFO userInfo = (NetAPI32.DSREG_USER_INFO)System.Runtime.InteropServices.Marshal.PtrToStructure(ptrUserInfo, (System.Type)ptrUserInfoObject.GetType());

                    FieldInfo[] fi = typeof(NetAPI32.DSREG_USER_INFO).GetFields(BindingFlags.Public | BindingFlags.Instance);
                    foreach (FieldInfo info in fi)
                    {
                        var x = info.GetValue(userInfo);
                        Console.WriteLine($" > {info.Name} : {x}");
                    }                   
                }
                catch (Exception e)
                {
                    Console.WriteLine($"[-] Error running UserInfo Enum: {e.Message}");
                }
                
                try
                {
                    Console.WriteLine($"\n[+] Starting JoinCertificate Enum:");
                    ptrJoinCertificate = joinInfo.pJoinCertificate;
                    NetAPI32.CERT_CONTEX ptrJoinCertificateObject = new NetAPI32.CERT_CONTEX();
                    var joinCertificate = Marshal.PtrToStructure(ptrJoinCertificate, (System.Type)ptrJoinCertificateObject.GetType());
                    FieldInfo[] fi = typeof(NetAPI32.CERT_CONTEX).GetFields(BindingFlags.Public | BindingFlags.Instance);
                    foreach (FieldInfo info in fi)
                    {
                        var x = info.GetValue(joinCertificate);
                        Console.WriteLine($" > {info.Name} : {x}");
                    }                    
                }
                catch (Exception e)
                {
                    Console.WriteLine($"[-] Error running JoinCertificate Enum: {e.Message}");
                }

                Console.WriteLine($"\n[+] Starting Connect Enum:");
                try
                {
                    if (IsInDomain())
                    {
                        Console.WriteLine($" > DomainJoined : true");
                    } else
                    {
                        Console.WriteLine($" > DomainJoined : false");
                    }                     
                }
                catch (Exception e)
                {
                    Console.WriteLine($"[-] Error running Domain Join Check Enum: {e.Message}");
                }

                switch ((NetAPI32.DSREG_JOIN_TYPE)joinInfo.joinType)
                {
                    case (NetAPI32.DSREG_JOIN_TYPE.DSREG_DEVICE_JOIN): { Console.WriteLine(" > AzureAD Joined : true"); break; }
                    case (NetAPI32.DSREG_JOIN_TYPE.DSREG_UNKNOWN_JOIN): { Console.WriteLine(" > Device is not joined"); break; }
                    case (NetAPI32.DSREG_JOIN_TYPE.DSREG_WORKPLACE_JOIN): { Console.WriteLine(" > Workplace Joined : true"); break; }
                }

                try
                {
                    if (ptrJoinInfo != IntPtr.Zero) 
                    { 
                        Marshal.Release(ptrJoinInfo); 
                    }
                    if (ptrUserInfo != IntPtr.Zero)
                    {
                        Marshal.Release(ptrUserInfo);
                    }
                    if (ptrJoinCertificate != IntPtr.Zero)
                    {
                        Marshal.Release(ptrJoinCertificate);
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine($"\n[-] Error Releasing PTRs: {e.Message}");
                }
            }
            else
            {
                Console.WriteLine("[-] No NetGetAadJoinInformation Info");
            }
        }

        // Convert an object to a byte array
        private static byte[] ObjectToByteArray(Object obj)
        {
            if (obj == null)
                return null;

            BinaryFormatter bf = new BinaryFormatter();
            MemoryStream ms = new MemoryStream();
            bf.Serialize(ms, obj);

            return ms.ToArray();
        }

        public static void LocalGroupMember(string Computer, string GroupName)
        {
            try
            {
                Console.WriteLine("\r\n===================================");
                Console.WriteLine($"LocalGroupMember ({Computer})");
                Console.WriteLine("===================================");

                Console.WriteLine($"Using DirectoryEntry: WinNT://{Computer}/{GroupName},group");

                DirectoryEntry root = new DirectoryEntry($"WinNT://{Computer}/{GroupName},group");

                Console.WriteLine("Name: " + root.Properties["Name"].Value);
                Console.WriteLine("AccountName: " + root.Properties["AccountName"].Value);


                foreach (string propName in root.Properties.PropertyNames)
                {
                    PropertyValueCollection valueCollection = root.Properties[propName];
                    foreach (Object propertyValue in valueCollection)
                    {                       

                        if (propName.Contains("objectSid"))
                        {
                            var x = ObjectToByteArray(propertyValue);
                            string asciiString = Encoding.UTF8.GetString(x);
                            Console.WriteLine(propName + ": " + asciiString.ToString()); ;
                        }
                        else
                        {
                            Console.WriteLine(propName + ": " + propertyValue.ToString());
                        }

                    }
                }
                foreach (object member in (IEnumerable)root.Invoke("Members"))
                {
                    using (DirectoryEntry memberEntry = new DirectoryEntry(member))
                    {
                        //string accountName = memberEntry.Path.Replace(string.Format("WinNT://{0}/", _domainName), string.Format(@"{0}\", _domainName));
                        Console.WriteLine("- " + memberEntry.Path); // No groups displayed...
                    }
                }

            }
            catch (Exception e) {
                Console.WriteLine(e.Message);
            }
        }

        public static void ADSearcher(string ldapsearch, string searchRoot, string Property)
        {
            Console.WriteLine("\r\n==============================================================================");
            Console.WriteLine($"Domain Searcher ({ldapsearch})");
            Console.WriteLine("==============================================================================");
            DirectorySearcher searcher = new DirectorySearcher();
            if (!String.IsNullOrEmpty(searchRoot))
            {
                Console.WriteLine($"searchRoot ({searchRoot})");
                DirectoryEntry entry = new DirectoryEntry(searchRoot);
                searcher = new DirectorySearcher(entry);
            }                       
            //searcher.Filter = $"(&(objectCategory=user)(cn=))";
            searcher.Filter = ldapsearch;
            //SearchResultCollection results = searcher.FindAll();

            foreach (SearchResult searchResult in searcher.FindAll())
            {
                Console.WriteLine("\r\n==============================================================================");
                foreach (string propName in searchResult.Properties.PropertyNames)
                {

                    ResultPropertyValueCollection valueCollection = searchResult.Properties[propName];
                    foreach (Object propertyValue in valueCollection)
                    {
                        if (!String.IsNullOrEmpty(Property))
                        {
                            if (propName.Contains(Property))
                            {
                                if (propName.Contains("userpassword"))
                                {
                                    var x = ObjectToByteArray(propertyValue);
                                    string asciiString = Encoding.ASCII.GetString(x);
                                    Console.WriteLine(propName + ": " + asciiString.ToString()); ;
                                }
                                else if (propName.Contains("badpasswordtime") || propName.Contains("pwdlastset") || propName.Contains("lastlogontimestamp"))
                                {
                                    var Time = DateTime.FromFileTime((long)propertyValue);
                                    Console.WriteLine(propName + ": (CONVERTED) " + Time.ToString());
                                }
                                else
                                {
                                    Console.WriteLine(propName + ": " + propertyValue.ToString());
                                }
                            }
                        }
                        else
                        {
                            if (propName.Contains("userpassword"))
                            {
                                var x = ObjectToByteArray(propertyValue);
                                string asciiString = Encoding.ASCII.GetString(x);
                                Console.WriteLine(propName + ": " + asciiString.ToString()); ;
                            }
                            else if (propName.Contains("badpasswordtime") || propName.Contains("pwdlastset") || propName.Contains("lastlogontimestamp"))
                            {
                                var Time = DateTime.FromFileTime((long)propertyValue);
                                Console.WriteLine(propName + ": (CONVERTED) " + Time.ToString());
                            }
                            else
                            {
                                Console.WriteLine(propName + ": " + propertyValue.ToString());
                            }
                        }
                    }                   
                }
            }
        }
    }
}
