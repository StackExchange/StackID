using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using OpenIdProvider.Helpers;
using OpenIdProvider;

namespace OpenIdProvider.Controllers
{
    public class HomeController : ControllerBase
    {
        [Route("favicon.ico")]
        public ActionResult Favicon()
        {
            return new EmptyResult();
        }

        [Route("")]
        public ActionResult Index()
        {
            var accepts = Request.AcceptTypes;

            if (accepts != null && accepts.Contains("application/xrds+xml"))
            {
                ViewData["OPIdentifier"] = true;
                return View("Xrds", null);
            }

            return View();
        }

        [Route("xrds")]
        public ActionResult Xrds()
        {
            ViewData["OPIdentifier"] = true;
            return View();
        }
    }
}
