using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Core.Common
{
    class WebRequest
    {
        internal static System.Net.WebClient Curl(string df = null, string purl=null, string puser=null, string ppass=null)
        {
			try
			{
				ServicePointManager.SecurityProtocol = (SecurityProtocolType)192 | (SecurityProtocolType)768 | (SecurityProtocolType)3072;
			}
			catch (Exception e)
			{
				Console.WriteLine(e.Message);
			}
			var WebClientObject = new System.Net.WebClient();

			if (!String.IsNullOrEmpty(purl))
			{
				Console.WriteLine(purl);
				WebProxy proxy = new WebProxy();
				proxy.Address = new Uri(purl);
				proxy.Credentials = new NetworkCredential(puser, ppass);
				if (String.IsNullOrEmpty(puser))
				{
					proxy.UseDefaultCredentials = true;
				}
				proxy.BypassProxyOnLocal = false;
				WebClientObject.Proxy = proxy;
			}
			else
			{
				if (null != WebClientObject.Proxy)
					WebClientObject.Proxy.Credentials = CredentialCache.DefaultCredentials;
			}

			if (!String.IsNullOrEmpty(df))
            {
				WebClientObject.Headers.Add("Host", df);
			}

			WebClientObject.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome / 80.0.3987.122 Safari / 537.36");
			WebClientObject.Headers.Add("Referer", "");

			return WebClientObject;
			
		}
    }
}
