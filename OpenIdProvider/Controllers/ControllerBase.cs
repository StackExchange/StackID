using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using OpenIdProvider.Helpers;
using OpenIdProvider;
using System.IO.Compression;
using MvcMiniProfiler;

namespace OpenIdProvider.Controllers
{
    // During dev, we've got a self signed cert somewhere and can just delegate all SSL stuff to
    [ValidateInput(false)]
    public class ControllerBase : Controller
    {
        protected override void OnActionExecuting(ActionExecutingContext filterContext)
        {
            using (MiniProfiler.Current.Step("OnActionExecuting"))
            {
                Current.Controller = filterContext.Controller;
                var path = filterContext.HttpContext.Request.Url.AbsolutePath.ToLowerInvariant();

                // Sometimes we know that we want to reject a request, but also want to show the user
                //   something when it happens, so we check here.
                //   Special exception for /openid/provider, since its a "special" route that dodges all our Route magic
                if (path != "/openid/provider" && path != "/affiliate/form/switch" && Current.RejectRequest)
                {
                    filterContext.Result = NotFound();
                    return;
                }

                if (IPBanner.IsBanned(Current.RemoteIP))
                {
                    filterContext.Result = Banned();
                    return;
                }

                // On prod, we can either be running with IIS handling SSL, *or* behind an SSL accelerator
                //   If we're not getting direct SSL, check against the a trusted port we've locked down
                //   for discussion between the accelerator(s) and the web tier
#if !DEBUG
            if (!filterContext.HttpContext.Request.IsSecureConnection)
            {
                var serverVars = filterContext.HttpContext.Request.ServerVariables;
                var originatingIP = serverVars["REMOTE_ADDR"];

                var forwardedProto = filterContext.HttpContext.Request.Headers["X-Forwarded-Proto"];

                if (forwardedProto != "https" || !Current.LoadBalancerIPs.Contains(originatingIP))
                {
                    Current.LogException(new Exception("Warning!  Something is talking to the OpenIdProvider nefariously"));

                    filterContext.Result = GenericSecurityError();
                    return;
                }
            }
#endif

                // Handle Acccept-Encoding
                //   As a site note: why, in the year 2011 (offically "the future") do we have to opt into this stuff?
                var acceptEncoding = filterContext.HttpContext.Request.Headers["Accept-Encoding"];
                if (acceptEncoding.HasValue())
                {
                    acceptEncoding = acceptEncoding.ToLowerInvariant();
                    var response = filterContext.HttpContext.Response;

                    if (acceptEncoding.Contains("gzip"))
                    {
                        response.AppendHeader("Content-Encoding", "gzip");
                        response.Filter = new GZipStream(response.Filter, CompressionMode.Compress);
                    }
                    else
                    {
                        if (acceptEncoding.Contains("deflate"))
                        {
                            response.AppendHeader("Content-Encoding", "deflate");
                            response.Filter = new DeflateStream(response.Filter, CompressionMode.Compress);
                        }
                    }
                }

                base.OnActionExecuting(filterContext);
            }
        }

        protected override void OnResultExecuting(ResultExecutingContext filterContext)
        {
            using (MiniProfiler.Current.Step("OnResultExecuting"))
            {
                // An extra layer of defense against embedding frames in unauthorized domains
                //   We still need the javascript frame busting since older browsers (IE7 and FF3.5) don't
                //   honor this header.
                // See: https://developer.mozilla.org/en/the_x-frame-options_response_header
                if (Current.ShouldBustFrames)
                {
                    filterContext.HttpContext.Response.Headers.Add("X-Frame-Options", "DENY");
                }

                // Generic "try that again" infrastrcture to shove previously seen values back into forms.
                if (filterContext.HttpContext.Request.QueryString.AllKeys.Contains("recover") && filterContext.HttpContext.Request.HttpMethod == "GET")
                {
                    var recoverKey = filterContext.HttpContext.Request.QueryString["recover"];

                    if (recoverKey.HasValue())
                    {
                        var recover = Current.GetFromCache<Dictionary<string, string>>(recoverKey);

                        if (recover != null)
                        {
                            foreach (var key in recover.Keys)
                            {
                                ViewData[key] = recover[key];
                            }

                            Current.RemoveFromCache(recoverKey);
                        }
                    }
                }

                // Advertise the xrds location
                filterContext.HttpContext.Response.Headers.Add(
                    "X-XRDS-Location",
                    new Uri(Current.AppRootUri, filterContext.HttpContext.Response.ApplyAppPathModifier("~/xrds")).ToString()
                );

                if (Current.NoCache)
                {
                    // http://stackoverflow.com/questions/49547/making-sure-a-web-page-is-not-cached-across-all-browsers
                    var response = filterContext.HttpContext.Response;
                    response.AppendHeader("Cache-Control", "no-cache, no-store, must-revalidate"); // HTTP 1.1.
                    response.AppendHeader("Pragma", "no-cache"); // HTTP 1.0.
                    response.AppendHeader("Expires", "0"); // Proxies.
                }

                base.OnResultExecuting(filterContext);
            }
        }

        public ActionResult PostExpectedAndNotReceived()
        {
            return View("PostExpectedAndNotReceived");
        }

        /// <summary>
        /// A curt "you've been banned" message.
        /// </summary>
        public ActionResult Banned()
        {
            Response.StatusCode = (int)System.Net.HttpStatusCode.Forbidden;
            return TextPlain("This IP address has been banned from making further requests.  If you believe this to be in error, contact us.");
        }

        /// <summary>
        /// Common Not Found
        /// </summary>
        public ActionResult NotFound()
        {
            Response.StatusCode = (int)System.Net.HttpStatusCode.NotFound;
            return View("NotFound");
        }

        /// <summary>
        /// text/plain result with the given content.
        /// </summary>
        public ActionResult TextPlain(string text)
        {
            return
                new ContentResult
                {
                    Content = text,
                    ContentType = "text/plain"
                };
        }

        /// <summary>
        /// Displays a whole-page error with the given title and message.
        /// 
        /// Use when whatever we encountered needs to be communicated to the user, but we can't expect them to be able
        /// to take any action to recover from it.
        /// 
        /// Example: whenever a user lands a page from a link in an email.  If something goes wrong with validation, they can't 
        /// modify the request (since it has an auth code) nor can they go "back" and fix any fields since there is no back to go to.
        /// 
        /// This method centralizes reporting these kinds of errors, to make changes to the underlying view easier.
        /// </summary>
        public ActionResult IrrecoverableError(string title, string message)
        {
            ViewData["title"] = title;
            ViewData["message"] = message;

            return View("IrrecoverableError");
        }

        /// <summary>
        /// Identical to IrrecoverableError, but shows the user some guidance since the problem is suspected to be on
        /// their end.
        /// 
        /// Advises them to try 
        /// </summary>
        public ActionResult IrrecoverableErrorWithHelp(string title, string message)
        {
            ViewData["title"] = title;
            ViewData["message"] = message;

            return View("IrrecoverableErrorWithHelp");
        }

        /// <summary>
        /// Common "what happened here?" result, displays message to the user.
        /// </summary>
        public ActionResult UnexpectedState(string message)
        {
            Current.LogException(new Exception(message));
            return IrrecoverableError("Unexpected Situation", message);
        }

        /// <summary>
        /// Common "something is fishy, bail" security error
        /// </summary>
        public ActionResult GenericSecurityError()
        {
            return IrrecoverableError("Authentication Failure", "It appears that the security of this request has been tampered with.");
        }

        /// <summary>
        /// If called from a "/submit" route, redirects to the *preceeding* route with the given message and the passed fields restored.
        /// 
        /// If called from any other route type, this throws an exception.
        /// 
        /// We fill values to be rendered into ViewData (after clearing it, for security purposes) to accomplish this.
        /// Anything that also appears in the target method signature will be set as a query parameter as well.
        /// 
        /// So, if you call this from "/login/submit" with passBack = { username = "blah" } it will render "/login" with ViewData["username"] = "blah".
        /// message is stashed into ViewData["error_message"].
        /// 
        /// Note that this method does not work from route with parameters in the path.
        /// </summary>
        public ActionResult RecoverableError(string message, object passBack)
        {
            const string submit = "/submit";

            var request = Current.RequestUri.AbsolutePath.ToLower();

            if (!request.EndsWith(submit)) throw new InvalidOperationException("Cannot recover from an error if a route isn't handling a POST");

            var previousRoute = request.Substring(0, request.Length - submit.Length);

            var trueRandom = Current.UniqueId().ToString();

            var toStore = passBack.PropertiesAsStrings();
            toStore["error_message"] = message;

            Current.AddToCache(trueRandom, toStore, TimeSpan.FromMinutes(5));

            var queryString = "?recover=" + trueRandom;

            var route = RouteAttribute.GetDecoratedRoutes()[previousRoute.Substring(1)];

            foreach (var param in route.GetParameters())
            {
                if (toStore.ContainsKey(param.Name))
                {
                    queryString += "&" + param.Name + "=" + HttpUtility.UrlEncode(toStore[param.Name]);
                }
            }

            return Redirect(previousRoute + queryString);
        }

        /// <summary>
        /// Show the user some generic success message.  Meant to centralize all sorts of 
        /// "great, now you're done!" messages into a single code path.
        /// 
        /// Example usages:
        ///  - Logout
        ///  - Registration Step #1
        ///  - Registration via Affiliate Step #1
        ///  - Affiliate Registration
        /// </summary>
        public ActionResult Success(string title, string message)
        {
            ViewData["title"] = title;
            ViewData["message"] = message;

            return View("Success");
        }

        /// <summary>
        /// Analogous to Success(), but displays a "if you didn't get the e-mail, blah blah blah" text too.
        /// </summary>
        public ActionResult SuccessEmail(string title, string message)
        {
            ViewData["title"] = title;
            ViewData["message"] = message;
            ViewData["isEmail"] = true;

            return View("Success");
        }

        /// <summary>
        /// Redirect to a given method (which is decorated with a RouteAttribute), 
        /// with the given parameters.
        /// 
        /// Lets us centralize all parameter encoding to reduce the odds of mistakenly
        /// passing things unencoded.  Also lets us catch re-named or unadorned routes
        /// a little easier.
        /// 
        /// Makes it less tempting to resort to error prone string.Format() stuff everywhere
        /// too.
        /// 
        /// Also, not that { Controller = "Blah", Action = "MoreBlah" } stuff that's just as nasty
        /// as string.Format IMO.
        /// 
        /// Note does not work with routes with "in path" parameters, only query string passed
        /// parameters.
        /// 
        /// As an aside, boy would it be handy if you could actually use MethodGroups for something,
        /// instead of just being a source of compiler errors.
        /// </summary>
        public RedirectResult SafeRedirect(Delegate target, object @params = null)
        {
            var toAction = target.Method;

            var routes = RouteAttribute.GetDecoratedRoutes();

            if (!routes.Values.Contains(toAction)) throw new ArgumentException("Method not decorated with RouteAttribute: " + toAction);

            var registered = routes.Where(v => v.Value == toAction).Select(v => v.Key).Single();

            return UnsafeRedirect(registered, @params);
        }

        /// <summary>
        /// Redirect to a specific route, this is unsafe as it doesn't guarantee the route exists
        /// before creating the redirect.
        /// </summary>
        public RedirectResult UnsafeRedirect(string route, object @params = null)
        {
            var encoded = new List<string>();

            if (@params != null)
            {
                foreach (var k in @params.PropertiesAsStrings())
                    encoded.Add(k.Key + "=" + Server.UrlEncode(k.Value));
            }

            var paramStr = string.Join("&", encoded);

            var url = "/" + route;

            if (paramStr.Length != 0) url += "?" + paramStr;

            var vals = @params == null ? "" : string.Join(", ", @params.PropertiesAsStrings().Select(s => s.Key + "=" + s.Value));

            return Redirect(url);
        }
    }
}
