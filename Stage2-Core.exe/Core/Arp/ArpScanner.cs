using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using System.Collections;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Net.Sockets;

namespace Core.Arp
{
    public class ArpScanner
    {
        public class MacState
        {
            public Int32 Counter = 0;
            public AutoResetEvent DoneEvent = new AutoResetEvent(false);
            public Dictionary<String, String> Results
            {
                get { return _results; }
                set { _results = value; }
            }
            Dictionary<String, String> _results;
        }
        public class IPQueryState
        {
            public IPQueryState(MacState state)
            {
                CurrentState = state;
            }
            public MacState CurrentState { get { return _currentState; } private set { _currentState = value; } }
            MacState _currentState;

            public string Query { get { return _query; } set { _query = value; } }
            String _query;
        }

        public Dictionary<String, String> DoScan(String ipString)
        {
            return DoScan(ipString, 100);
        }


        public Dictionary<String, String> DoScan(String ipString, ushort maxThreads)
        {
            ThreadPool.SetMaxThreads(maxThreads, maxThreads);
            Dictionary<String, String> Results = new Dictionary<String, String>();
            if ((!ipString.StartsWith("127.0.0.1")) && !ipString.StartsWith("169"))
            {
                MacState state = new MacState();
                state.Results = Results;
                if (ArpScanner.IPv4Tools.IsIPRangeFormat(ipString))
                {
                    ArpScanner.IPv4Tools.IPRange iprange = IPv4Tools.IPEnumerator[ipString];

                    foreach (string n in iprange)
                    {
                        state.Counter++;
                    }

                    foreach (string ip in iprange)
                    {
                        IPQueryState ipq = new IPQueryState(state);
                        ipq.Query = ip;
                        ThreadPool.QueueUserWorkItem(GetMAC, ipq);
                    }
                    state.DoneEvent.WaitOne();
                }
                else
                {
                    IPQueryState ipq = new IPQueryState(state);
                    ipq.Query = ipString;
                    GetMAC(ipq);
                }


            }
            return Results;
        }
        public static String gethostbyaddrNetBIOS(String ipaddress)
        {
            try
            {
                IPAddress src = IPAddress.Parse(ipaddress);
                uint intAddress = BitConverter.ToUInt32(src.GetAddressBytes(), 0);
                IntPtr nameInt = Kernel32Imports.gethostbyaddr(ref intAddress, 4, ProtocolFamily.NetBios);
                IntPtr name = Marshal.ReadIntPtr(nameInt);
                String NetbiosName = Marshal.PtrToStringAnsi(name);
                return NetbiosName;
            }
            catch
            {
                return "N/A";
            }

        }
        static void GetMAC(object state)
        {
            IPQueryState queryState = state as IPQueryState;
            try
            {
                IPAddress dst = null;
                if (!IPAddress.TryParse(queryState.Query, out dst))
                {
                    Console.WriteLine(String.Format("IP Address {0} is invalid ", queryState.Query));
                    return;
                }

                uint uintAddress = BitConverter.ToUInt32(dst.GetAddressBytes(), 0);
                byte[] macAddr = new byte[6];
                int macAddrLen = macAddr.Length;
                int retValue = Kernel32Imports.SendARP(uintAddress, 0, macAddr, ref macAddrLen);
                if (retValue != 0)
                {
                    return;
                }
                string[] str = new string[(int)macAddrLen];
                for (int i = 0; i < macAddrLen; i++)
                    str[i] = macAddr[i].ToString("x2");
                string mac = string.Join(":", str);

                if (queryState.Query != null && mac != null)
                    queryState.CurrentState.Results.Add(queryState.Query, mac);

            }
            finally
            {
                int temp = 0;
                if ((temp = Interlocked.Decrement(ref queryState.CurrentState.Counter)) == 0)
                    queryState.CurrentState.DoneEvent.Set();
            }
        }

        static class Kernel32Imports
        {
            [DllImport("iphlpapi.dll", ExactSpelling = true)]
            public static extern int SendARP(uint DestIP, uint SrcIP, byte[] pMacAddr, ref int PhyAddrLen);
            [DllImport("ws2_32.dll", SetLastError = true)]
            internal static extern IntPtr gethostbyaddr(
              [In] ref uint addr,
              [In] int len,
              [In] ProtocolFamily type
              );
        }

        class IPv4Tools
        {
            private static readonly Regex _ipCidrRegex = new Regex(@"^(?<ip>(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))(\/(?<cidr>(\d|[1-2]\d|3[0-2])))$");
            private static readonly Regex _ipRegex = new Regex(@"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$");
            private static readonly Regex _ipRangeRegex = new Regex(@"^(?<ip>(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?<from>([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])))(\-(?<to>([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])))$");

            public static IPv4Tools IPEnumerator
            {
                get
                {
                    return new IPv4Tools();
                }
            }

            public IPRange this[string value]
            {
                get
                {
                    return new IPRange(value);
                }
            }

            public static bool IsIPRangeFormat(string IpRange)
            {
                return (_ipCidrRegex.Match(IpRange).Success || _ipRangeRegex.Match(IpRange).Success);
            }

            public static bool IsIPCidr(string ip_cidr)
            {
                return _ipCidrRegex.Match(ip_cidr).Success;
            }

            public static bool IsIPRange(string IpRange)
            {
                return _ipRangeRegex.Match(IpRange).Success;
            }

            public static bool IsIP(string ip)
            {
                return _ipRegex.Match(ip).Success;
            }

            public static Match IpCidrMatch(string ip_cidr)
            {
                return _ipCidrRegex.Match(ip_cidr);
            }

            public static Match IpRangeMatch(string IpRange)
            {
                return _ipRangeRegex.Match(IpRange);
            }

            public class IPRange : IEnumerable<string>
            {
                string _ip_cidr;
                public IPRange(string ip_cidr)
                {
                    _ip_cidr = ip_cidr;
                }

                public IEnumerator<string> GetEnumerator()
                {
                    return new IPRangeEnumerator(_ip_cidr);
                }

                private IEnumerator GetEnumerator1()
                {
                    return this.GetEnumerator();
                }
                IEnumerator IEnumerable.GetEnumerator()
                {
                    return GetEnumerator1();
                }
            }

            class IPRangeEnumerator : IEnumerator<string>
            {
                string _ipcidr = null;
                UInt32 _loAddr;
                UInt32 _hiAddr;
                UInt32? _current = null;

                public IPRangeEnumerator(string ip_cidr)
                {
                    _ipcidr = ip_cidr;
                    Match cidrmch = IPv4Tools.IpCidrMatch(ip_cidr);
                    Match rangeMch = IPv4Tools.IpRangeMatch(ip_cidr);
                    if (cidrmch.Success)
                        ProcessCidrRange(cidrmch);
                    else if (rangeMch.Success)
                        ProcessIPRange(rangeMch);

                    if (!cidrmch.Success && !rangeMch.Success)
                        throw new Exception("IP Range must either be in IP/CIDR or IP to-from format");
                }
                public void ProcessIPRange(Match rangeMch)
                {
                    System.Net.IPAddress startIp = IPAddress.Parse(rangeMch.Groups["ip"].Value);
                    ushort fromRange = ushort.Parse(rangeMch.Groups["from"].Value);
                    ushort toRange = ushort.Parse(rangeMch.Groups["to"].Value);

                    if (fromRange > toRange)
                        throw new Exception("IP Range the from must be less than the to");
                    else if (toRange > 254)
                        throw new Exception("IP Range the to must be less than 254");
                    else
                    {
                        byte[] arrIpBytes = startIp.GetAddressBytes();
                        Array.Reverse(arrIpBytes);
                        uint ipuint = System.BitConverter.ToUInt32(arrIpBytes, 0);
                        _loAddr = ipuint;
                        _hiAddr = ipuint + ((uint)(toRange - fromRange)) + 1;
                    }
                }

                public void ProcessCidrRange(Match cidrmch)
                {
                    System.Net.IPAddress ip = IPAddress.Parse(cidrmch.Groups["ip"].Value);
                    Int32 cidr = Int32.Parse(cidrmch.Groups["cidr"].Value);

                    if (cidr <= 0)
                        throw new Exception("CIDR can't be negative");
                    else if (cidr > 32)
                        throw new Exception("CIDR can't be more 32");
                    else if (cidr == 32)
                    {
                        byte[] arrIpBytes = ip.GetAddressBytes();
                        Array.Reverse(arrIpBytes);
                        UInt32 ipuint = System.BitConverter.ToUInt32(arrIpBytes, 0);
                        _loAddr = ipuint;
                        _hiAddr = ipuint;
                    }
                    else
                    {
                        byte[] arrIpBytes = ip.GetAddressBytes();
                        Array.Reverse(arrIpBytes);
                        UInt32 ipuint = System.BitConverter.ToUInt32(arrIpBytes, 0);
                        uint umsk = uint.MaxValue >> cidr;
                        uint lmsk = (umsk ^ uint.MaxValue);
                        _loAddr = ipuint & lmsk;
                        _hiAddr = ipuint | umsk;
                    }
                }

                UInt32 HostToNetwork(UInt32 host)
                {
                    byte[] hostBytes = System.BitConverter.GetBytes(host);
                    Array.Reverse(hostBytes);
                    return System.BitConverter.ToUInt32(hostBytes, 0);
                }

                public string Current
                {
                    get
                    {
                        if (String.IsNullOrEmpty(_ipcidr) || !_current.HasValue)
                            throw new InvalidOperationException();

                        return IPv4Tools.UIntToIpString(HostToNetwork(_current.Value));
                    }
                }

                public bool MoveNext()
                {
                    if (!_current.HasValue)
                    {
                        _current = _loAddr;
                        if (_current == _hiAddr) //handles if /32 used
                            return true;
                    }
                    else
                        _current++;

                    if ((0xFF & _current) == 0 || (0xFF & _current) == 255)
                        _current++;

                    if (_current < _hiAddr)
                        return true;
                    else
                        return false;
                }

                public void Reset()
                {
                    _current = _loAddr;
                    if ((0xFF & _current) == 0 || (0xFF & _current) == 255)
                        _current++;
                }

                object Current1
                {
                    get { return this.Current; }
                }

                object IEnumerator.Current
                {
                    get { return Current1; }
                }

                public void Dispose()
                { }
            }
            static string UIntToIpString(UInt32 address)
            {
                int num1 = 15;
                char[] chPtr = new char[15];
                int num2 = (int)(address >> 24 & (long)byte.MaxValue);
                do
                {
                    chPtr[--num1] = (char)(48 + num2 % 10);
                    num2 /= 10;
                }
                while (num2 > 0);
                int num3;
                chPtr[num3 = num1 - 1] = '.';
                int num4 = (int)(address >> 16 & (long)byte.MaxValue);
                do
                {
                    chPtr[--num3] = (char)(48 + num4 % 10);
                    num4 /= 10;
                }
                while (num4 > 0);
                int num5;
                chPtr[num5 = num3 - 1] = '.';
                int num6 = (int)(address >> 8 & (long)byte.MaxValue);
                do
                {
                    chPtr[--num5] = (char)(48 + num6 % 10);
                    num6 /= 10;
                }
                while (num6 > 0);

                int startIndex;
                chPtr[startIndex = num5 - 1] = '.';
                int num7 = (int)(address & (long)byte.MaxValue);
                do
                {
                    chPtr[--startIndex] = (char)(48 + num7 % 10);
                    num7 /= 10;
                }
                while (num7 > 0);

                return new string(chPtr, startIndex, 15 - startIndex);
            }
        }
    }
}
