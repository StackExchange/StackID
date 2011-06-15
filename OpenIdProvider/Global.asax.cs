using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Routing;
using MvcMiniProfiler;

namespace OpenIdProvider
{   
    public class MvcApplication : System.Web.HttpApplication
    {
        public static readonly string ProfilerCookieName = "im-on-a-boat";

        public static void RegisterRoutes(RouteCollection routes)
        {
            // Dodging RouteAttribute magic to keep the Monitoring controller as simple as possible
            routes.MapRoute("ping", new { controller = "Monitoring", action = "Ping" });
            routes.MapRoute("report", new { controller = "Monitoring", action = "Report" });

            // We need to opt out of our POST/GET semantic magic, so doing this route RAW
            routes.MapRoute("openid/provider", new { controller = "OpenId", action = "Provider" });

            // any controller methods that are decorated with our attribute will be registered
            Helpers.RouteAttribute.MapDecoratedRoutes(routes);

            // MUST be the last route as a catch-all!
            routes.MapRoute("{*url}", new { controller = "Home", action = "NotFound" });
        }

        protected void Application_BeginRequest(object sender, EventArgs e)
        {
            if (HttpContext.Current.Request.Cookies[ProfilerCookieName] != null)
            {
                MiniProfiler.Start();
            }
            
            var cur = HttpContext.Current;
            var path = cur.Request.Path;

            var cshtml = ".cshtml";

            // Hack: MVC doesn't like routes which contain ".cshtml"
            //       so intercept such requests, re-write them, and redirect
            if (path.EndsWith(cshtml) && path.Count(c => c == '/') == 1)
            {
                cur.Response.Redirect(path.Substring(0, path.Length - cshtml.Length) + "~cshtml", true);
            }
        }

        protected void Application_EndRequest(object sender, EventArgs e)
        {
            if (MiniProfiler.Current != null) // they had a cookie
            {
                var abandon = Current.LoggedInUser == null || !Current.LoggedInUser.IsAdministrator;
                MiniProfiler.Stop(discardResults: abandon);
            }
        }

        protected void Application_Error(object sender, EventArgs e)
        {
            try
            {
                var exception = Context.Error;

                if (exception != null)
                    Current.LogException(exception);
            }
            catch (Exception)
            {
                // About to die a horrible spiny death, so stop it
            }
        }

        protected void Application_Start()
        {
            MvcHandler.DisableMvcResponseHeader = true;

            RegisterRoutes(RouteTable.Routes);

            MiniProfiler.Settings.RenderPopupButtonOnRight = true;
            MiniProfiler.Settings.LongTermCacheGetter = (Guid id) => Current.GetFromCache<MiniProfiler>("profiler-long-" + id);
            MiniProfiler.Settings.LongTermCacheSetter = (MiniProfiler profiler) => Current.AddToCache("profiler-long-" + profiler.Id, profiler, TimeSpan.FromDays(1));

            MiniProfiler.Settings.ShortTermCacheGetter = (Guid id) => Current.GetFromCache<MiniProfiler>("profiler-short-" + id);
            MiniProfiler.Settings.ShortTermCacheSetter = (MiniProfiler profiler) => Current.AddToCache("profiler-short-" + profiler.Id, profiler, TimeSpan.FromSeconds(30));
        }
    }
}