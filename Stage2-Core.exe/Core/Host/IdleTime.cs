using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace Core.Host
{
    public static class UserInput
    {
        private struct LASTINPUTINFO
        {
            public uint cbSize;

            public int dwTime;
        }

        public static DateTime LastInput => DateTime.UtcNow.AddMilliseconds((double)(-Environment.TickCount)).AddMilliseconds((double)LastInputTicks);

        public static TimeSpan IdleTime => DateTime.UtcNow.Subtract(LastInput);

        public static int LastInputTicks
        {
            get
            {
                LASTINPUTINFO plii = default(LASTINPUTINFO);
                plii.cbSize = (uint)Marshal.SizeOf(typeof(LASTINPUTINFO));
                GetLastInputInfo(ref plii);
                return plii.dwTime;
            }
        }

        [DllImport("user32.dll")]
        private static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);
    }

}
