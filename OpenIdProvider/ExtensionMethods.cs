using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Routing;
using System.Web.Mvc;
using System.Web.UI;
using Recaptcha;
using System.Text;
using System.IO;
using System.Net;
using DotNetOpenAuth.OpenId.Provider;
using System.Runtime.Serialization.Formatters.Binary;

namespace OpenIdProvider
{
    /// <summary>
    /// Holds all project extension methods to allow for a constant (and simple!) include.
    /// </summary>
    public static class ExtensionMethods
    {
        /// <summary>
        /// Returns true if this String is neither null or empty.
        /// </summary>
        public static bool HasValue(this string s)
        {
            return !string.IsNullOrEmpty(s);
        }

        /// <summary>
        /// Convenience wrapper for static string.IsNullOrEmpty
        /// </summary>
        public static bool IsNullOrEmpty(this string s)
        {
            return string.IsNullOrEmpty(s);
        }

        /// <summary>
        /// Adds the url to the RouteCollection with the specified defaults.
        /// </summary>
        public static void MapRoute(this RouteCollection routes, string url, object defaults)
        {
            routes.MapRoute("", url, defaults);
        }

        /// <summary>
        /// Find a cookie in either the response to the current request, or the request itself.
        /// 
        /// Preferentially checks the response.
        /// </summary>
        public static HttpCookie CookieSentOrReceived(this HttpContext context, string cookieName)
        {
            var responseCookie = context.Response.Cookies.AllKeys.Contains(cookieName) ? context.Response.Cookies[cookieName] : null;
            var requestCookie = context.Request.Cookies.AllKeys.Contains(cookieName) ? context.Request.Cookies[cookieName] : null;

            // Only return the response if its not a kill cookie
            if (responseCookie != null && responseCookie.Expires > DateTime.UtcNow) return responseCookie;

            // Only return the request if there isn't a response kill cookie
            if (requestCookie != null && responseCookie == null) return requestCookie;

            return null;
        }

        /// <summary>
        /// Writes an error message to out in a standard manner.
        /// 
        /// Meant to genericize our error handling.
        /// </summary>
        public static HtmlString HandleErrorMessage(this ViewDataDictionary viewData)
        {
            if (!viewData.ContainsKey("error_message")) return null;

            var message = viewData["error_message"];

            return
                new HtmlString(
                    string.Format(
                        @"<div class=""error""><p>{0}</p></div>",
                        HttpUtility.HtmlEncode(message)
                    )
                );
        }

        /// <summary>
        /// Reads all properties on an object into a dictionary as strings.
        /// 
        /// Handy utility for when we want to wrap up a bunch of values in an anonymous object
        /// for later retrevial.  Examples include auth codes and template replacements.
        /// </summary>
        public static Dictionary<string, string> PropertiesAsStrings(this object @params)
        {
            var ret = new Dictionary<string, string>();

            var props = @params.GetType().GetProperties();

            foreach (var prop in props.OrderBy(p => p.Name))
            {
                var key = prop.Name;
                var value = prop.GetValue(@params, null);
                
                if(value != null)
                    ret[key] = value.ToString();
            }

            return ret;
        }

        /// <summary>
        /// Render a Control to a string.
        /// </summary>
        public static string RenderControl(this System.Web.UI.Control control)
        {
            StringBuilder sb = new StringBuilder();
            using (var sw = new System.IO.StringWriter(sb))
            {
                using (var textWriter = new System.Web.UI.HtmlTextWriter(sw))
                {
                    control.RenderControl(textWriter);
                }
            }
            return sb.ToString();
        }

        /// <summary>
        /// Converts a DateTime into a SPAN html element with a human friendly
        /// visible value (like, "X days ago") and a precision title (to be shown on hover).
        /// </summary>
        public static HtmlString ToRelativeTimeSpan(this DateTime time)
        {
            var html = @"<span class=""relative-time"" title=""{0:u}"">{1}</span>";

            html = string.Format(html, time, ToRelativeTime(time));

            return new HtmlString(html);
        }

        /// <summary>
        /// Converts a DateTime into a human friendly value (like, "X days ago").
        /// </summary>
        public static string ToRelativeTime(this DateTime time)
        {
            var now = Current.Now;

            return
                time <= now ?
                    ToRelativeTimePast(time, now) :
                    ToRelativeTimeFuture(time, now);
        }

        /// <summary>
        /// Implmenentation detail for ToRelativeTime.
        /// 
        /// Handle the "this time is in the past" conversion case.
        /// </summary>
        private static string ToRelativeTimePast(DateTime past, DateTime now)
        {
            TimeSpan ts = now - past;
            double delta = ts.TotalSeconds;

            if (delta < 60)
            {
                return ts.Seconds == 1 ? "1 sec ago" : ts.Seconds + " secs ago";
            }
            if (delta < 3600) // 60 mins * 60 sec
            {
                return ts.Minutes == 1 ? "1 min ago" : ts.Minutes + " mins ago";
            }
            if (delta < 86400)  // 24 hrs * 60 mins * 60 sec
            {
                return ts.Hours == 1 ? "1 hour ago" : ts.Hours + " hours ago";
            }

            int days = ts.Days;
            if (days == 1)
            {
                return "yesterday";
            }
            else if (days <= 2)
            {
                return days + " days ago";
            }
            else if (now.Year == past.Year)
            {
                return past.ToString("MMM %d 'at' %H:mmm");
            }
            return past.ToString(@"MMM %d \'yy 'at' %H:mmm");
        }

        /// <summary>
        /// Implmenentation detail for ToRelativeTime.
        /// 
        /// Handle the "this time is in the future" conversion case.
        /// </summary>
        private static string ToRelativeTimeFuture(DateTime future, DateTime now)
        {
            TimeSpan ts = future - now;
            double delta = ts.TotalSeconds;

            if (delta < 60)
            {
                return ts.Seconds == 1 ? "in 1 second" : "in " + ts.Seconds + " seconds";
            }
            if (delta < 3600) // 60 mins * 60 sec
            {
                return ts.Minutes == 1 ? "in 1 minute" : "in " + ts.Minutes + " minutes";
            }
            if (delta < 86400) // 24 hrs * 60 mins * 60 sec
            {
                return ts.Hours == 1 ? "in 1 hour" : "in " + ts.Hours + " hours";
            }

            // use our own rounding so we can round the correct direction for future
            int days = (int)Math.Round(ts.TotalDays, 0);
            if (days == 1)
            {
                return "tomorrow";
            }
            else if (days <= 10)
            {
                return "in " + days + " day" + (days > 1 ? "s" : "");
            }
            // if the date is in the future enough to be in a different year, display the year
            if (now.Year != future.Year)
                return "on " + future.ToString(@"MMM %d \'yy 'at' %H:mmm");
            else
                return "on " + future.ToString("MMM %d 'at' %H:mmm");
        }

        /// <summary>
        /// Renders a "tab" link.
        /// 
        /// Basically, just drops an anchor into the page *but* if the
        /// url path matches the current URI its gets class="current" added to it.
        /// </summary>
        public static HtmlString RenderTab(this HtmlHelper ignored, string tabName, string url)
        {
            var path = Current.RequestUri.AbsolutePath;

            var @class = "";

            if (url.Equals(path, StringComparison.InvariantCultureIgnoreCase))
                @class = @"class=""current""";

            // HACK: make /user/{id} tab highlighting work
            if (url == "/user" && @class.IsNullOrEmpty())
            {
                var loggedIn = Current.LoggedInUser;
                if (loggedIn != null)
                {
                    var ownPath = "/user/" + loggedIn.ProviderId;

                    if (path == ownPath) @class = @"class=""current""";
                }
            }

            return
                new HtmlString(
                    string.Format(
                        @"<a href=""{0}"" {1}>{2}</a>",
                        url,
                        @class,
                        HttpUtility.HtmlEncode(tabName)));
        }

        /// <summary>
        /// Strips out funky characters in css.
        /// 
        /// Doesn't check for anything html-y (thus the string and not the HtmlString return), so be careful
        /// there.
        /// </summary>
        public static string SanitizeCss(string rawCss)
        {
            // ; and , are not permitted, at all
            var ret = rawCss.Replace(";", "").Replace(",", "");

            bool theColonJigIsUp = false;

            // : is only permitted when part of a url [ie. url('http://example.com')]
            int i = 0;
            while ((i = rawCss.IndexOf(':', i)) != -1)
            {
                var prevUrl = rawCss.ToLower().LastIndexOf("url(", i);

                if (prevUrl == -1)
                {
                    theColonJigIsUp = true;
                    break;
                }

                var closingParen = rawCss.IndexOf(")", prevUrl);

                if (closingParen == -1)
                {
                    theColonJigIsUp = true;
                    break;
                }

                var nextParenFromColon = rawCss.IndexOf(")", i);

                if (nextParenFromColon != closingParen)
                {
                    theColonJigIsUp = true;
                    break;
                }

                i++;
            }

            // don't bother stripping out just the invalid ones, kill them all
            if (theColonJigIsUp) ret = ret.Replace(":", "");

            return ret;
        }

        /// <summary>
        /// Writes out a style tag with third party styles (as passed via ViewData).
        /// 
        /// It does sanitize the input.
        /// </summary>
        public static HtmlString IncludeThirdPartyStyles(this ViewDataDictionary viewData, out bool hasBackground)
        {
            var background = (string)viewData["Background"];
            var color = (string)viewData["Color"];

            var template = 
                @"<style type=""text/css"">
                body
                {{
                    {0}
                    {1}
                }}
                h2
                {{
                    {1}
                }}
                </style>";

            hasBackground = background.HasValue();

            if (hasBackground)
                background = "background: " + WebUtility.HtmlEncode(SanitizeCss(background)) + " !important;";

            if (color.HasValue())
                color = "color: " + WebUtility.HtmlEncode(SanitizeCss(color)) + " !important;";

            var css = string.Format(template, background, color);

            return new HtmlString(css);
        }

        /// <summary>
        /// Slap a cache breaker on a url
        /// </summary>
        public static HtmlString CacheBreak(this HtmlHelper ignored, string url)
        {
            var cacheBreaker = HttpUtility.UrlEncode(Current.CacheBreaker);

            if (url.LastIndexOf('/') < url.LastIndexOf('?'))
                return new HtmlString(url + "&v=" + cacheBreaker);

            return new HtmlString(url + "?v=" + cacheBreaker);
        }

        /// <summary>
        /// Run action on each element in source.
        /// 
        /// Returns source for chaining purposes.
        /// </summary>
        public static IEnumerable<T> ForEach<T>(this IEnumerable<T> source, Action<T> action)
        {
            foreach (var item in source)
            {
                action(item);
            }
            return source;
        }

        public static byte[] Serialize(this IAuthenticationRequest request)
        {
            byte[] bytes;
            using (var stream = new MemoryStream())
            {
                var formatter = new BinaryFormatter();
                formatter.Serialize(stream, request);

                bytes = stream.ToArray();
            }

            return bytes;
        }

        public static IAuthenticationRequest DeSerialize(this IAuthenticationRequest ignored, byte[] serialized)
        {
            using (var stream = new MemoryStream(serialized))
            {
                var formatter = new BinaryFormatter();
                return (IAuthenticationRequest)formatter.Deserialize(stream);
            }
        }
    }
}