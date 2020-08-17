using System;
using System.Text.RegularExpressions;
using System.Threading;

namespace Core.Common
{
    class Timer
    {
        internal static void Turtle(string[] args)
        {
            string beacon = args[1];
            int beacontime = 0;
            beacontime = checktime(beacon);
            Thread.Sleep(beacontime);
        }

        internal static int checktime(String beacon)
        {
            int beacontime = 0;
            if (beacon.ToLower().Contains("s"))
            {
                beacon = Regex.Replace(beacon, "s", "", RegexOptions.IgnoreCase);
                if (!Int32.TryParse(beacon, out beacontime))
                {
                    beacontime = 5;
                }
            }
            else if (beacon.ToLower().Contains("m"))
            {
                beacon = Regex.Replace(beacon, "m", "", RegexOptions.IgnoreCase);
                if (!Int32.TryParse(beacon, out beacontime))
                {
                    beacontime = 5;
                }
                beacontime = beacontime * 60;
            }
            else if (beacon.ToLower().Contains("h"))
            {
                beacon = Regex.Replace(beacon, "h", "", RegexOptions.IgnoreCase);
                if (!Int32.TryParse(beacon, out beacontime))
                {
                    beacontime = 5;
                }
                beacontime = beacontime * 60;
                beacontime = beacontime * 60;
            }
            else if (!Int32.TryParse(beacon, out beacontime))
            {
                beacontime = 5;
            }
            return beacontime * 1000;
        }
    }
}
