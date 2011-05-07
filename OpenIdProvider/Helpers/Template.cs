using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Text;
using System.IO;
using System.Web.UI;
using System.Dynamic;

namespace OpenIdProvider.Helpers
{
    public class TemplateController : Controller { }

    /// <summary>
    /// Handles common template functions.
    /// 
    /// Lets use pretty easily switch out the "branded" bits of the
    /// provider, though most views will be sufficiently generic to
    /// be directly embedded.
    /// </summary>
    public static class Template
    {
        /// <summary>
        /// For templates without models, just cache them for speeds sake.
        /// </summary>
        private static Dictionary<string, string> CachedTemplates = new Dictionary<string, string>();

        /// <summary>
        /// Check the template cache for a quickly returnable result
        /// </summary>
        private static bool CheckCache(string name, out string cached)
        {
            lock (CachedTemplates)
                return CachedTemplates.TryGetValue(name, out cached);
        }

        /// <summary>
        /// Place a cachable template in the cache.
        /// </summary>
        private static void PlaceInCache(string name, string cache)
        {
            lock (CachedTemplates)
                CachedTemplates[name] = cache;
        }

        /// <summary>
        /// Returns a template view with the given parameters passed as the model.
        /// 
        /// @params gets shunted into a dynamic for sanity's sake.
        /// </summary>
        public static string FormatTemplate(string templateName, object @params = null)
        {
            string ret;
            if (@params == null && CheckCache(templateName, out ret)) return ret;

            var expando = new ExpandoObject();
            var dictView = ((IDictionary<string, object>)expando);

            if (@params != null)
            {
                foreach (var prop in @params.PropertiesAsStrings())
                {
                    dictView.Add(prop.Key, prop.Value);
                }
            }

            dictView.Add("SiteName", Current.SiteName);

            ret = RenderTemplateToString(Current.Controller.ControllerContext, @"~/Views/Templates/" + templateName + ".cshtml", expando);

            if (@params == null) PlaceInCache(templateName, ret);

            return ret;
        }

        /// <summary>
        /// Renders a .cshtml view into a string.
        /// </summary>
        private static string RenderTemplateToString(ControllerContext ctx, string controlName, object viewData)
        {
            if (ctx == null) throw new InvalidOperationException("RenderTemplateToString needs a controller-context");

            using (StringWriter sw = new StringWriter())
            {
                ViewEngineResult viewResult = ViewEngines.Engines.FindPartialView(ctx, controlName);
                var data = new ViewDataDictionary(viewData);
                var tmp = new TempDataDictionary();
                ViewContext viewContext = new ViewContext(ctx, viewResult.View, data, tmp, sw);
                viewResult.View.Render(viewContext, sw);

                return sw.ToString();
            }
        }
    }
}