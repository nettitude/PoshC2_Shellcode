using System;
using System.Linq;

namespace Core.Common
{
    class Core
    {
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
