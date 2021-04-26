using System;
using System.Linq;
using System.Management;

namespace Core.Common
{
    class Core
    {

        internal static void FindFile(string name, string extension, string drive = "C:", string host = "127.0.0.1")
        {
            try
            {
                ManagementScope Scope = new ManagementScope($"\\\\{host}\\root\\CIMV2", null);
                Scope.Connect();
                ObjectQuery query = new ObjectQuery($"Select * from CIM_DataFile Where ((Drive = '{drive}') AND (FileName = '{name}') AND (Extension = '{extension}'))");
                ManagementObjectSearcher Searcher = new ManagementObjectSearcher(Scope, query);

                foreach (ManagementObject WmiObject in Searcher.Get())
                {
                    Console.WriteLine("{0}", (string)WmiObject["Name"]);
                }
                Console.WriteLine("End of search");
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }

        internal static byte[] Combine(byte[] first, byte[] second)
        {
            byte[] ret = new byte[first.Length + second.Length];
            Buffer.BlockCopy(first, 0, ret, 0, first.Length);
            Buffer.BlockCopy(second, 0, ret, first.Length, second.Length);
            return ret;
        }

        internal static Type LoadAss(string assemblyqNme)
        {
            return Type.GetType(assemblyqNme, (name) =>
            {
                return AppDomain.CurrentDomain.GetAssemblies().Where(z => z.FullName == name.FullName).LastOrDefault();
            }, null, true);
        }
    }
}
