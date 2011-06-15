using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Web.Mvc;
using System.Web.Routing;

namespace OpenIdProvider.Helpers
{
    /// <summary>
    /// Allows MVC routing urls to be declared on the action they map to.
    /// </summary>
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = true)]
    public class RouteAttribute : ActionMethodSelectorAttribute, IComparable<RouteAttribute>
    {
        private static Dictionary<string, MethodInfo> DecoratedRoutes;
        public static Dictionary<string, MethodInfo> GetDecoratedRoutes()
        {
            if (DecoratedRoutes != null) return DecoratedRoutes;

            var decoratedMethods = from t in Assembly.GetCallingAssembly().GetTypes()
                                   where t.IsSubclassOf(typeof(System.Web.Mvc.Controller))
                                   from m in t.GetMethods()
                                   where m.IsDefined(typeof(RouteAttribute), false)
                                   select m;

            var ret = new Dictionary<string, MethodInfo>();

            foreach (var method in decoratedMethods)
            {
                foreach (var attr in method.GetCustomAttributes(typeof(RouteAttribute), false))
                {
                    var ra = (RouteAttribute)attr;
                    ret.Add(ra.Url, method);
                }
            }

            DecoratedRoutes = ret;

            return DecoratedRoutes;
        }

        /// <summary>
        /// Within the assembly, looks for any action methods that have the RouteAttribute defined, 
        /// adding the routes to the parameter 'routes' collection.
        /// </summary>
        public static void MapDecoratedRoutes(RouteCollection routes)
        {
            var decoratedMethods = GetDecoratedRoutes().Values;

            var methodsToRegister = new SortedDictionary<RouteAttribute, MethodInfo>(); // sort urls alphabetically via RouteAttribute's IComparable implementation

            // first, collect all the methods decorated with our RouteAttribute
            foreach (var method in decoratedMethods)
            {
                foreach (var attr in method.GetCustomAttributes(typeof(RouteAttribute), false))
                {
                    var ra = (RouteAttribute)attr;
                    if (!methodsToRegister.Any(p => p.Key.Url.Equals(ra.Url)))
                        methodsToRegister.Add(ra, method);
                }
            }

            // now register the unique urls to the Controller.Method that they were decorated upon
            foreach (var pair in methodsToRegister)
            {
                var attr = pair.Key;
                var method = pair.Value;
                var action = method.Name;

                var controllerType = method.ReflectedType;
                var controllerName = controllerType.Name.Replace("Controller", "");
                var controllerNamespace = controllerType.FullName.Replace("." + controllerType.Name, "");

                var route = new Route(attr.Url, new MvcRouteHandler());
                route.Defaults = new RouteValueDictionary(new { controller = controllerName, action = action });

                // optional parameters are specified like: "users/filter/{filter?}"
                if (attr.OptionalParameters != null)
                {
                    foreach (var optional in attr.OptionalParameters)
                        route.Defaults.Add(optional, "");
                }

                // constraints are specified like: @"users/{id:\d+}" or "users/{id:INT}"
                if (attr.Constraints != null)
                {
                    route.Constraints = new RouteValueDictionary();

                    foreach (var constraint in attr.Constraints)
                        route.Constraints.Add(constraint.Key, constraint.Value);
                }

                // fully-qualify route to its controller method by adding the namespace; allows multiple assemblies to share controller names/routes
                route.DataTokens = new RouteValueDictionary(new { namespaces = new[] { controllerNamespace } });

                routes.Add(attr.Name, route);
            }
        }


        public RouteAttribute(string url)
            : this(url, "", null, RoutePriority.Default, AuthorizedUser.Administrator | AuthorizedUser.Anonymous | AuthorizedUser.LoggedIn)
        {
        }

        public RouteAttribute(string url, bool acceptAll) 
            : this(url)
        {
            AcceptAll = acceptAll;
        }

        public RouteAttribute(string url, AuthorizedUser users)
            : this(url, "", null, RoutePriority.Default, users)
        {
        }

        public RouteAttribute(string url, HttpVerbs verbs)
            : this(url, "", verbs, RoutePriority.Default, AuthorizedUser.Administrator | AuthorizedUser.Anonymous | AuthorizedUser.LoggedIn)
        {
        }

        public RouteAttribute(string url, HttpVerbs verbs, AuthorizedUser users)
            : this(url, "", verbs, RoutePriority.Default, AuthorizedUser.Administrator | AuthorizedUser.Anonymous | AuthorizedUser.LoggedIn)
        {
        }

        public RouteAttribute(string url, RoutePriority priority, AuthorizedUser users)
            : this(url, "", null, priority, users)
        {
        }

        public RouteAttribute(string url, HttpVerbs verbs, RoutePriority priority, AuthorizedUser users)
            : this(url, "", verbs, priority, users)
        {
        }

        private RouteAttribute(string url, string name, HttpVerbs? verbs, RoutePriority priority, AuthorizedUser users)
        {
            Url = url.ToLower();
            Name = name;
            AcceptVerbs = verbs;
            Priority = priority;
            AuthorizedUsers = users;

            if (AuthorizedUsers == 0) throw new ArgumentException("users must permit at least one class of user to reach this route");
        }

        /// <summary>
        /// Accept *everything*, GET POST XSRF whatever, and pass through to code.
        /// </summary>
        public bool AcceptAll { get; set; }

        /// <summary>
        /// A bitmask of the user types permitted to access a given route
        /// </summary>
        public AuthorizedUser AuthorizedUsers { get; set; }

        /// <summary>
        /// The explicit verbs that the route will allow.  If null, all verbs are valid.
        /// </summary>
        public HttpVerbs? AcceptVerbs { get; set; }

        /// <summary>
        /// Optional name to allow this route to be referred to later.
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// The request url that will map to the decorated action method.
        /// </summary>
        public string Url { get; set; }

        /// <summary>
        /// Determines when this route is registered in the <see cref="System.Web.Routing.RouteCollection"/>.  The higher the priority, the sooner
        /// this route is added to the collection, making it match before other registered routes for a given url.
        /// </summary>
        public RoutePriority Priority { get; set; }

        /// <summary>
        /// Gets any optional parameters contained by this Url. Optional parameters are specified with a ?, e.g. "users/{id}/{name?}".
        /// </summary>
        public string[] OptionalParameters { get; private set; }

        /// <summary>
        /// Based on /users/{id:(\d+)(;\d+)*}
        /// </summary>
        public Dictionary<string, string> Constraints { get; private set; }

        /// <summary>
        /// Run prior to a route being executed, to make sure registered constraints are respected.
        /// 
        /// See: http://stackoverflow.com/questions/2648783/how-do-the-httppost-httpput-etc-attributes-in-asp-net-mvc-2-work/2648852#2648852
        /// </summary>
        public override bool IsValidForRequest(ControllerContext cc, MethodInfo mi)
        {
            // Absolutely, positively, do not cache *anything* that is in response to a POST
            if (AcceptVerbs.HasValue && (AcceptVerbs.Value & HttpVerbs.Post) != 0)
            {
                Current.NoCache = true;
            }

            if (AcceptAll) return true;

            var verbCheck = !AcceptVerbs.HasValue || (new AcceptVerbsAttribute(AcceptVerbs.Value).IsValidForRequest(cc, mi));

            var xsrfCheck = true;

            if(AcceptVerbs.HasValue && (AcceptVerbs.Value | HttpVerbs.Post) != 0 && cc.RequestContext.HttpContext.Request.RequestType != "POST")
            {
                Current.RejectRequest = true;
                Current.PostExpectedAndNotReceived = true;
                return true;
            }

            if (AcceptVerbs.HasValue && (AcceptVerbs.Value | HttpVerbs.Post) != 0)
            {
                var fkeyRaw = cc.HttpContext.Request.Form["fkey"];
                Guid fkey;

                if (!Guid.TryParse(fkeyRaw, out fkey))
                {
                    Current.RejectRequest = true;
                    return true;
                }
                
                var fkeyShouldBe = Current.XSRFToken;

                xsrfCheck = fkey == fkeyShouldBe;
            }

            var userCheck = false;

            if ((AuthorizedUsers & AuthorizedUser.LoggedIn) != 0) userCheck |= Current.LoggedInUser != null;
            if ((AuthorizedUsers & AuthorizedUser.Anonymous) != 0) userCheck |= Current.LoggedInUser == null;
            if ((AuthorizedUsers & AuthorizedUser.Administrator) != 0) userCheck |= Current.LoggedInUser != null && Current.LoggedInUser.IsAdministrator;

            Current.RejectRequest = !(verbCheck && xsrfCheck && userCheck);

            if (!xsrfCheck)
            {
                IPBanner.BadXSRFToken(Current.RemoteIP);
            }

            return true;
        }

        public override string ToString()
        {
            return (AcceptVerbs.HasValue ? AcceptVerbs.Value.ToString().ToUpper() + " " : "") + Url;
        }

        public int CompareTo(RouteAttribute other)
        {
            var result = other.Priority.CompareTo(this.Priority);

            if (result == 0) // sort like priorities in asc alphabetical order
                result = this.Url.CompareTo(other.Url);

            return result;
        }
    }

    /// <summary>
    /// Contains values that control when routes are added to the main <see cref="System.Web.Routing.RouteCollection"/>.
    /// </summary>
    /// <remarks>Routes with identical RoutePriority are registered in alphabetical order.  RoutePriority allows for different strata of routes.</remarks>
    public enum RoutePriority
    {
        /// <summary>
        /// A route with Low priority will be registered after routes with Default and High priorities.
        /// </summary>
        Low = 0,
        Default = 1,
        High = 2
    }

    /// <summary>
    /// Indicates which users are allowed to access a route
    /// </summary>
    [Flags]
    public enum AuthorizedUser
    {
        Anonymous = 1,
        LoggedIn = 2,
        Administrator = 4
    }
}
