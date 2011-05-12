using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Security.Cryptography;

using OpenIdProvider.Models;
using OpenIdProvider.Helpers;
using OpenIdProvider;
using System.IO;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Runtime.Serialization;
using System.Collections.Specialized;
using System.Net;
using System.Text.RegularExpressions;

namespace OpenIdProvider.Controllers
{
    /// <summary>
    /// This actually services requests for the forms sign up/in made by affiliates.
    /// 
    /// These will only be served to proper registered affiliates (there is no anon option).
    /// Unlike the entire rest of the site, we allow authorized third-parties to frame these
    /// things.
    /// </summary>
    public class AffiliateFormsController : ControllerBase
    {
        /// <summary>
        /// The affiliate who requested any form on this page
        /// </summary>
        protected Affiliate CurrentAffiliate;

        /// <summary>
        /// We greatly restrict access to this controller.
        /// 
        /// It can only be entered with a request signed by a registered affiliate.
        /// That is, all GETs must carry a signed authCode.  All POSTs are protected by 
        /// our standard XSRF tricks.
        /// </summary>
        protected override void OnActionExecuting(ActionExecutingContext filterContext)
        {
            var @params = filterContext.HttpContext.Request.QueryString;

            var method = filterContext.HttpContext.Request.HttpMethod;

            string failureReason = null;

            var failure = false;
            if (!@params.AllKeys.Contains("affId"))
            {
                failureReason = "No affId";
                failure = true;
            }

            // OK, this is tricky so pay attention
            if (!failure)
            {
                ViewData["affId"] = @params["affId"];

                // Anything that's a GET in this controller comes from an affiliate
                //    that means the whole thing needs to be signed (all parameters)
                if (method == "GET")
                {
                    // HACK: Ok, we need *one* exception to all this chicanery, so we're just
                    //       hacking it in here
                    var reqUrl = filterContext.RouteData.Route as System.Web.Routing.Route;
                    if (reqUrl != null && reqUrl.Url == "affiliate/form/switch")
                    {
                        int affId;
                        if (int.TryParse(@params["affId"], out affId))
                        {
                            CurrentAffiliate = Current.ReadDB.Affiliates.SingleOrDefault(a => a.Id == affId);

                            if (CurrentAffiliate != null)
                            {
                                Current.ShouldBustFrames = false;

                                base.OnActionExecuting(filterContext);
                                return;
                            }
                        }
                    }
                    else
                    {
                        // For all other routes, confirm that they came from a registered affiliate
                        if (!@params.AllKeys.Contains("nonce"))
                        {
                            failureReason = "No Nonce";
                            failure = true;
                        }
                        if (!@params.AllKeys.Contains("authCode"))
                        {
                            failureReason = "No Nonce";
                            failure = true;
                        }


                        if(!VerifySignature(@params, out CurrentAffiliate))
                        {
                            failure = true;
                            failureReason = "Signature invalid";
                        }
                    }
                }
                else if (method == "POST")
                {
                    // Anything that's a POST comes from our own forms (in iframes)
                    //   We know this because of the XSRF token.
                    CurrentAffiliate = Current.ReadDB.Affiliates.SingleOrDefault(a => a.Id == int.Parse(@params["affId"].ToString()));

                    if (CurrentAffiliate == null)
                    {
                        failure = true;
                        failureReason = "On Post, invalid affId";
                    }
                }
                else
                {
                    // ... and anything else is a garbage request
                    failure = true;
                    failureReason = " Not GET or POST";
                }
            }

            Current.ShouldBustFrames = false; // no frame busting in this controller

            if (failure)
            {
                Current.LogException(new Exception("Affiliate Forms failure: " + failureReason));
                filterContext.Result = NotFound();
                return;
            }

            base.OnActionExecuting(filterContext);
        }

        /// <summary>
        /// Returns true if the parameters contain a valid signature for a request.
        /// </summary>
        private static bool VerifySignature(NameValueCollection @params, out Affiliate validFor)
        {
            validFor = null;

            var authCode = @params["authCode"].ToString();
            int affId;

            if (!int.TryParse(@params["affId"], out affId))
            {
                return false;
            }

            var nonce = @params["nonce"].ToString();

            if (!Nonces.IsValid(nonce))
            {
                return false;
            }

            var affiliate = Current.ReadDB.Affiliates.SingleOrDefault(a => a.Id == affId);

            if (affiliate == null)
            {
                return false;
            }

            var copy = new Dictionary<string, string>();
            foreach (var item in @params.AllKeys.Where(k => k != "authCode"))
            {
                copy[item] = @params[item];
            }

            if (authCode.HasValue() && !affiliate.ConfirmSignature(authCode, Current.RequestUri.AbsolutePath, copy))
            {
                return false;
            }

            validFor = affiliate;

            Nonces.MarkUsed(nonce);

            return true;
        }

        /// <summary>
        /// This route lets a user switch between login & signup affiliate forms.
        /// 
        /// We have to authenticate this request, otherwise somebody could just embed a link
        /// to *this* switcher and bypass all the affiliate checking stuff.
        /// </summary>
        [Route("affiliate/form/switch")]
        public ActionResult SwitchAffiliateForms(string to, string nonce, string authCode, string affId, string background, string color)
        {
            var shouldMatch = Current.MakeAuthCode(new { nonce, to, affId, background, color });

            if (shouldMatch != authCode) return GenericSecurityError();

            Nonces.MarkUsed(nonce);

            switch (to)
            {
                case "login":
                    var cookie = System.Web.HttpContext.Current.CookieSentOrReceived(Current.AnonymousCookieName);

                    return LoginIFrame(null, background, color);
                case "signup": return SignupIFrame(null, background, color);
            }

            return NotFound();
        }

        private static Regex OnLoadMessageRegex = new Regex(@"[a-z]+", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        /// <summary>
        /// Returns a page intended for embedding in third party pages.
        /// 
        /// Conditionally displays a login or signup form, which can be toggled around
        /// if the user isn't currently logged in.
        /// </summary>
        [Route("affiliate/form")]
        public ActionResult LoginOrSignupIFrame(string callback, bool? signupByDefault, string onLoad, string background, string color)
        {
            if (!CurrentAffiliate.IsValidCallback(callback)) return IrrecoverableError("Invalid Affiliate Callback", "The callback provided is not valid for the detected affiliate, and as such login or signup operations cannot proceed for security reasons.");

            if (onLoad != null && !OnLoadMessageRegex.IsMatch(onLoad)) return IrrecoverableError("Unsafe onLoad message", "The provided onLoad parameter has been deemed too dangerous to proceed with.");

            // There isn't really a standard for this, but this is how MyOpenId does it
            //    so at least we're not inventing something out of whole cloth
            var required = HttpContext.Request.QueryString["openid.sreg.required"];
            var optional = HttpContext.Request.QueryString["openid.sreg.optional"];
            var policy = HttpContext.Request.QueryString["openid.sreg.policy_url"];

            if (Current.LoggedInUser != null) return ConfirmLoginIFrame(callback, onLoad, background, color);

            Current.GenerateAnonymousXSRFCookie();

            var cookie = System.Web.HttpContext.Current.CookieSentOrReceived(Current.AnonymousCookieName);

            Current.AddToCache(CallbackKey(cookie), callback, TimeSpan.FromHours(1));

            return 
                signupByDefault.GetValueOrDefault(false) ? 
                    SignupIFrame(onLoad, background, color) : 
                    LoginIFrame(onLoad, background, color);
        }

        /// <summary>
        /// Returns a "give us your email" signup form for embedding in an iframe.
        /// </summary>
        public ActionResult SignupIFrame(string onLoad, string background, string color)
        {
            // We need this check, as we call this action directly bypassing the RouteAttribute check as well
            if (Current.LoggedInUser != null) return NotFound();

            var affId = ViewData["affId"].ToString();

            var nonce = Nonces.Create();
            var to = "login";
            var authCode = Current.MakeAuthCode(new { nonce, to, affId, background, color  });

            var @switch =
                SafeRedirect(
                    (Func<string, string, string, string, string, string, ActionResult>)SwitchAffiliateForms,
                    new
                    {
                        to = "login",
                        nonce,
                        authCode,
                        affId,
                        background,
                        color
                    }
                );

            var switchLink = Current.Url(@switch.Url);

            ViewData["SwitchUrl"] = switchLink;

            ViewData["OnLoad"] = onLoad;
            ViewData["Background"] = background;
            ViewData["Color"] = color;

            return View("SignupIFrame");
        }

        /// <summary>
        /// Handles submission from SignupIFrame
        /// </summary>
        [Route("affiliate/form/signup/submit", HttpVerbs.Post, AuthorizedUser.Anonymous)]
        public ActionResult SignupIFrameSubmit(string email, string password, string password2, string realname, string background, string color)
        {
            if (email.IsNullOrEmpty())
            {
                // Can't use standard RecoverableError things in affiliate forms, do it by hand
                ViewData["error_message"] = "Email is required";
                ViewData["affId"] = CurrentAffiliate.Id;
                ViewData["realname"] = realname;

                return SignupIFrame(null, background, color);
            }

            // Check that the captcha succeeded
            string error;
            if (!Captcha.Verify(Request.Form, out error) || !Password.CheckPassword(password, password2, email, null, null, out error))
            {
                // Can't use standard RecoverableError things in affiliate forms, do it by hand
                ViewData["error_message"] = error;
                ViewData["affId"] = CurrentAffiliate.Id;
                ViewData["email"] = email;
                ViewData["realname"] = realname;

                return SignupIFrame(null, background, color);
            }

            var cookie = System.Web.HttpContext.Current.CookieSentOrReceived(Current.AnonymousCookieName);

            var callback = Current.GetFromCache<string>(CallbackKey(cookie));

            var token = Current.UniqueId().ToString();
            var authCode = Current.MakeAuthCode(new { email, token, realname, callback, affId = CurrentAffiliate.Id });

            string pwSalt;
            string pwHash = Current.SecureHash(password, out pwSalt);

            var pendingUser = new PendingUser
            {
                AuthCode = authCode,
                CreationDate = Current.Now,
                PasswordSalt = pwSalt,
                PasswordHash = pwHash
            };

            Current.WriteDB.PendingUsers.InsertOnSubmit(pendingUser);
            Current.WriteDB.SubmitChanges();

            var complete =
                SafeRedirect(
                    (Func<string, string, string, string, string, string, ActionResult>)
                    (new AccountController()).CompleteAffiliateTriggeredRegistration,
                    new
                    {
                        email,
                        affId = CurrentAffiliate.Id,
                        token,
                        callback,
                        realname,
                        authCode
                    }
                );

            var completeLink = Current.Url(complete.Url);

            Current.Email.SendEmail(
                email,
                Email.Template.CompleteRegistrationViaAffiliate,
                new {
                    AffiliateName = CurrentAffiliate.HostFilter,
                    RegistrationLink = completeLink
                });

            ViewData["Background"] = background;
            ViewData["Color"] = color;

            return Success("Registration Email Sent", "Check your email for the link to complete your registration.");
        }

        /// <summary>
        /// Returns a "Confirm" form, for users who are logged in.
        /// 
        /// We don't want to *just* slam them into a site because they drove past it, after all.
        /// </summary>
        private ActionResult ConfirmLoginIFrame(string callback, string onLoad, string background, string color)
        {
            if (Current.LoggedInUser == null) return NotFound();

            var cookie = System.Web.HttpContext.Current.CookieSentOrReceived(Current.UserCookieName);

            Current.AddToCache(CallbackKey(cookie), callback, TimeSpan.FromMinutes(15));

            ViewData["OnLoad"] = onLoad;
            ViewData["Background"] = background;
            ViewData["Color"] = color;

            return View("ConfirmLoginIFrame");
        }

        /// <summary>
        /// Handles submission from ConfirmLoginIFrame
        /// </summary>
        [Route("affiliate/form/confirm/submit", HttpVerbs.Post, AuthorizedUser.LoggedIn)]
        public ActionResult HandleConfirmLogin()
        {
            var cookie = System.Web.HttpContext.Current.CookieSentOrReceived(Current.UserCookieName);

            var callback = Current.GetFromCache<string>(CallbackKey(cookie));

            Current.RemoveFromCache(CallbackKey(cookie));

            if (callback == null) return IrrecoverableError("No Callback Found", "We were unable to find a callback to finish the authentication session.");
            
            return AffiliateRedirect(AddIdentifier(callback, Current.LoggedInUser.GetClaimedIdentifier()));
        }

        /// <summary>
        /// Displays a handy login IFrame (username and password) as well
        /// as any asked for attributes (though it *DOES NOT* actually display those attributes, 
        /// mearly their type)
        /// </summary>
        public ActionResult LoginIFrame(string onLoad, string background, string color)
        {
            if (Current.LoggedInUser != null) return NotFound();

            var affId = ViewData["affId"].ToString();
            var nonce = Nonces.Create();
            var to = "signup";
            var authCode = Current.MakeAuthCode(new { nonce, to, affId, background, color });

            var @switch =
                SafeRedirect(
                    (Func<string, string, string, string, string, string, ActionResult>)SwitchAffiliateForms,
                    new
                    {
                        to = "signup",
                        nonce,
                        authCode,
                        affId,
                        background,
                        color
                    }
                );

            var switchLink = Current.Url(@switch.Url);

            ViewData["SwitchUrl"] = switchLink;

            ViewData["OnLoad"] = onLoad;
            ViewData["Background"] = background;
            ViewData["Color"] = color;

            return View("LoginIFrame");
        }

        /// <summary>
        /// Handles submission from LoginIFrame
        /// </summary>
        [Route("affiliate/form/login/submit", HttpVerbs.Post, AuthorizedUser.Anonymous)]
        public ActionResult HandleAffiliateLogin(string email, string password, string background, string color)
        {
            var now = Current.Now;

            var cookie = System.Web.HttpContext.Current.CookieSentOrReceived(Current.AnonymousCookieName);
            var user = Models.User.FindUserByEmail(email);

            if (user == null || user.PasswordHash != Current.SecureHash(password, user.PasswordSalt))
            {
                // Standard recoverable error stuff doesn't work here, so do it manually
                ViewData["error_message"] = "Invalid email or password";
                ViewData["email"] = email;
                ViewData["affId"] = CurrentAffiliate.Id;

                return LoginIFrame(null, background, color);
            }
                        
            var callback = Current.GetFromCache<string>(CallbackKey(cookie));

            Current.RemoveFromCache(CallbackKey(cookie));

            user.Login(now);

            if (callback == null) return IrrecoverableError("No Callback Found", "We were unable to find a callback to finish the authentication session.");

            return AffiliateRedirect(AddIdentifier(callback, Current.LoggedInUser.GetClaimedIdentifier()));
        }

        // Just a convenience method to keep from having this code copied everywhere.
        private string CallbackKey(HttpCookie cookie)
        {
            var hash = Current.WeakHash(cookie.Value);
            return "callback-" + hash + "-" + CurrentAffiliate.Id;
        }
        
        /// <summary>
        /// When we redirect from an affiliate form, we're being framed.
        /// 
        /// This means a simple redirect won't work, we actually need to serve something
        /// to do some javascript magic to bust out of the frame (though we're pushing the user
        /// to the site *doing* the framing, which is a tad odd).
        /// </summary>
        private ActionResult AffiliateRedirect(string redirectUrl)
        {
            return View("Redirect", (object)redirectUrl);
        }

        // Just a convenience method to keep from having this code copied everywhere
        private string AddIdentifier(string callback, Uri identifier)
        {
            return
                callback +
                (callback.Contains('?') ? '&' : '?') +
                "openid_identifier=" + Server.UrlEncode(identifier.AbsoluteUri);
        }
    }
}
