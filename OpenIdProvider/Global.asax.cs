using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Routing;

namespace OpenIdProvider
{   
    public class MvcApplication : System.Web.HttpApplication
    {
        public static void RegisterRoutes(RouteCollection routes)
        {
            // Dodging RouteAttribute magic to keep the Monitoring controller as simple as possible
            routes.MapRoute("ping", new { controller = "Monitoring", action = "Ping" });
            routes.MapRoute("report", new { controller = "Monitoring", action = "Report" });

            // any controller methods that are decorated with our attribute will be registered
            Helpers.RouteAttribute.MapDecoratedRoutes(routes);

            // We need to opt out of our POST/GET semantic magic, so doing this route RAW
            routes.MapRoute("openid/provider", new { controller = "OpenId", action = "Provider" });

            // MUST be the last route as a catch-all!
            routes.MapRoute("{*url}", new { controller = "Home", action = "NotFound" });
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
        }

        
    }
}