using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Core.Host
{
    class SSLInspection
    {
        public static void Check(string[] args)
        {
            string URL = args[1];
            //string URL = @"https://www.google.com";
            string ProxyURL = "";
            string ProxyUser = "";
            string ProxyPass = "";
            string UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; Trident/7.0; rv:11.0) like Gecko"; ;

            try { ProxyURL = args[2]; } catch { }
            try { ProxyUser = args[3]; } catch { }
            try { ProxyPass = args[4]; } catch { }
            try { UserAgent = args[5]; } catch { }

            var expiration = "";
            var certName = "";
            //var certPublicKeyString = "";
            //var certSerialNumber = "";
            //var certThumbprint = "";
            var certEffectiveDate = "";
            var certIssuer = "";

            ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;

            Console.WriteLine("[+] Starting SSLChecker\n");
            HttpWebRequest req = (HttpWebRequest)WebRequest.Create(URL);
            req.UserAgent = UserAgent;

            if (!String.IsNullOrEmpty(ProxyURL))
            {
                WebProxy proxy = new WebProxy();
                proxy.Address = new Uri(ProxyURL);
                proxy.Credentials = new NetworkCredential(ProxyUser, ProxyPass);
                if (String.IsNullOrEmpty(ProxyUser))
                {
                    proxy.UseDefaultCredentials = true;
                }
                proxy.BypassProxyOnLocal = false;
                req.Proxy = proxy;
            }
            else
            {
                if (null != req.Proxy)
                    req.Proxy.Credentials = CredentialCache.DefaultCredentials;
            }
            req.Timeout = 10000;
            try
            {
                req.GetResponse();
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error in SSLInspection.Check(): {e.Message}\n");
            }

            expiration = req.ServicePoint.Certificate.GetExpirationDateString();
            certName = req.ServicePoint.Certificate.Subject;
            //certPublicKeyString = req.ServicePoint.Certificate.GetPublicKeyString();
            //certSerialNumber = req.ServicePoint.Certificate.GetSerialNumberString();
            //certThumbprint = req.ServicePoint.Certificate.GetCertHashString();
            certEffectiveDate = req.ServicePoint.Certificate.GetEffectiveDateString();
            certIssuer = req.ServicePoint.Certificate.Issuer;

            Console.WriteLine("Cert for site {0}. Check details:\n", URL);
            Console.WriteLine("Cert name: {0}", certName);
            //Console.WriteLine("Cert public key: {0}", certPublicKeyString);
            //Console.WriteLine("Cert serial number: {0}", certSerialNumber);
            //Console.WriteLine("Cert thumbprint: {0}", certThumbprint);
            Console.WriteLine("Cert effective date: {0}", certEffectiveDate);
            Console.WriteLine("Cert Expiry: {0}", expiration);
            Console.WriteLine("Cert issuer: {0}", certIssuer);

        }
    }
}
