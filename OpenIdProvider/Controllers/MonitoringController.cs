using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using OpenIdProvider.Helpers;
using System.Text;

namespace OpenIdProvider.Controllers
{
    /// <summary>
    /// This entire controllers purpose is to respond to all requests, 
    /// no matter what.
    /// 
    /// No cookie checks, no SSL enforcement, no nothing.
    /// We point whatever monitoring services at it just to see if
    /// the AppPool & Site are even running, routing is ok, etc.
    /// </summary>
    public class MonitoringController : Controller
    {
        public ActionResult Ping()
        {
            return
                new ContentResult
                {
                    Content = Environment.MachineName,
                    ContentType = "text/plain",
                    ContentEncoding = Encoding.UTF8
                };
        }

        public ActionResult Report()
        {
            var ret = new StringBuilder();

#if DEBUG
            ret.AppendFormat("IP: {0}\r\nTime: {1}\r\n\r\n", Current.RemoteIP, Current.Now);

            ret.AppendLine("Headers:");

            for(int i = 0; i < Request.Headers.Count; i++)
            {
                var name = Request.Headers.AllKeys[i];
                var header = Request.Headers[i];

                ret.AppendFormat(
                    "\t{0}: {1}\r\n",
                    name,
                    string.Join("", header.Select(h => h))
                );
            }
#endif

            return
                new ContentResult
                {
                    Content = ret.ToString(),
                    ContentType = "text/plain",
                    ContentEncoding = Encoding.UTF8
                };
        }
    }
}
