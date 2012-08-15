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
    public partial class AffiliateFormsController : ControllerBase
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
            Current.NoCache = true;

            if (Current.PostExpectedAndNotReceived)
            {
                Current.ShouldBustFrames = false;
                filterContext.Result = PostExpectedAndNotReceived();
                return;
            }

            var @params = new Dictionary<string, string>();

            foreach (var x in filterContext.HttpContext.Request.QueryString.AllKeys)
            {
                @params[x] = filterContext.HttpContext.Request.QueryString[x];
            }

            if (!@params.ContainsKey("affId") && Request.Form.AllKeys.Contains("affId"))
            {
                @params["affId"] = Request.Form["affId"];
            }

            var method = filterContext.HttpContext.Request.HttpMethod;

            string failureReason = null;

            var failure = false;
            if (!@params.ContainsKey("affId"))
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
                        if (!@params.ContainsKey("nonce"))
                        {
                            failureReason = "No Nonce";
                            failure = true;
                        }
                        if (!@params.ContainsKey("authCode"))
                        {
                            failureReason = "No Auth Code";
                            failure = true;
                        }

                        string sigError;
                        if(!VerifySignature(@params, out CurrentAffiliate, out sigError))
                        {
                            failure = true;
                            failureReason = "Signature invalid - " + sigError;
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
                filterContext.Result = IrrecoverableErrorWithHelp("Affiliate Form failure:", failureReason);
                return;
            }

            var formCanaryCookie = new HttpCookie("canary", "1");
            formCanaryCookie.HttpOnly = false; // the whole point is to check for this via javascript
            formCanaryCookie.Expires = Current.Now + TimeSpan.FromMinutes(5);

            filterContext.HttpContext.Response.Cookies.Add(formCanaryCookie);

            base.OnActionExecuting(filterContext);
        }

        /// <summary>
        /// Returns true if the parameters contain a valid signature for a request.
        /// </summary>
        private static bool VerifySignature(Dictionary<string, string> @params, out Affiliate validFor, out string failureReason)
        {
            if (!@params.ContainsKey("authCode") || !@params.ContainsKey("affId") || !@params.ContainsKey("nonce"))
            {
                validFor = null;
                failureReason = "Missing parameter";
                return false;
            }

            validFor = null;

            var authCode = @params["authCode"].ToString();
            int affId;

            if (!int.TryParse(@params["affId"], out affId))
            {
                failureReason = "No affId";
                return false;
            }

            var nonce = @params["nonce"].ToString();

            string nonceMsg;
            if (!Nonces.IsValid(nonce, Current.RemoteIP, out nonceMsg))
            {
                failureReason = "Invalid Nonce [" + nonceMsg + "]";
                return false;
            }

            var affiliate = Current.ReadDB.Affiliates.SingleOrDefault(a => a.Id == affId);

            if (affiliate == null)
            {
                failureReason = "Could not find affiliate";
                return false;
            }

            var copy = new Dictionary<string, string>();
            foreach (var item in @params.Keys.Where(k => k != "authCode"))
            {
                copy[item] = @params[item];
            }

            if (authCode.HasValue() && !affiliate.ConfirmSignature(authCode, Current.RequestUri.AbsolutePath, copy))
            {
                failureReason = "Affiliate signature confirmation failed";
                return false;
            }

            validFor = affiliate;

            Nonces.MarkUsed(nonce, Current.RemoteIP);

            failureReason = null;
            return true;
        }

        /// <summary>
        /// Set a message to display to users when they don't have third-party cookies enabled, which really shoots the
        /// whole iframe approach to hell.
        /// </summary>
        private void SetThirdPartyCookieFallbackHtml(string html)
        {
            ViewData["ThirdPartyCookieFallback"] = html;
        }

        /// <summary>
        /// This route lets a user switch between login & signup affiliate forms.
        /// 
        /// We have to authenticate this request, otherwise somebody could just embed a link
        /// to *this* switcher and bypass all the affiliate checking stuff.
        /// </summary>
        [Route("affiliate/form/switch")]
        public ActionResult SwitchAffiliateForms(string to, string nonce, string authCode, string affId, string background, string color, string callback, string newCookie)
        {
            var shouldMatch = Current.MakeAuthCode(new { nonce, to, affId, background, color, callback, newCookie });

            if (shouldMatch != authCode) return GenericSecurityError();

            Nonces.MarkUsed(nonce, Current.RemoteIP);

            bool addCookie;
            if (bool.TryParse(newCookie, out addCookie) && addCookie)
            {
                Current.GenerateAnonymousXSRFCookie();

                // Pull the callback forward into the new cookie
                var cookie = System.Web.HttpContext.Current.CookieSentOrReceived(Current.AnonymousCookieName);
                Current.AddToCache(CallbackKey(cookie), callback, TimeSpan.FromMinutes(15));
            }

            switch (to)
            {
                case "login":
                    var cookie = System.Web.HttpContext.Current.CookieSentOrReceived(Current.AnonymousCookieName);

                    return LoginIFrame(null, background, color);
                case "signup": return SignupIFrame(null, background, color);
            }

            return UnexpectedState("Tried to switch to an unknown form [" + to + "]");
        }

        /// <summary>
        /// Generate a link to switch to a specific form
        /// </summary>
        private string SwitchLink(string to, string affId, string background, string color, string callback, bool newCookie)
        {
            var nonce = Nonces.Create();
            var authCode = Current.MakeAuthCode(new { nonce, to, affId, background, color, callback, newCookie = newCookie.ToString() });

            var @switch =
                UnsafeRedirect(
                    "affiliate/form/switch",
                    new
                    {
                        to,
                        nonce,
                        authCode,
                        affId,
                        background,
                        color,
                        callback,
                        newCookie = newCookie.ToString()
                    }
                );

            return Current.Url(@switch.Url);
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
            if (!CurrentAffiliate.IsValidCallback(callback))
                return IrrecoverableErrorWithHelp("Invalid Affiliate Callback", "The callback provided is not valid for the detected affiliate, and as such login or signup operations cannot proceed for security reasons.");

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
            if (Current.LoggedInUser != null) return UnexpectedState("Signing up while already logged in");

            var cookie = System.Web.HttpContext.Current.CookieSentOrReceived(Current.AnonymousCookieName);
            var callback = Current.GetFromCache<string>(CallbackKey(cookie));

            var affId = ViewData["affId"].ToString();
            var switchLink = SwitchLink("login", affId, background, color, callback, false);
            var refreshLink = SwitchLink("signup", affId, background, color, callback,  true);

            ViewData["SwitchUrl"] = switchLink;
            ViewData["RefreshUrl"] = refreshLink;

            ViewData["OnLoad"] = onLoad;
            ViewData["Background"] = background;
            ViewData["Color"] = color;

            var registerUrl = Current.Url(SafeRedirect((Func<ActionResult>)(new AccountController()).Register).Url);

            SetThirdPartyCookieFallbackHtml(@"<p>You can still <a href=""" + registerUrl + @""">register manually for a " + Server.UrlEncode(Current.SiteName) + " OpenID</a>.</p>");

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
                ViewData["password"] = password;
                ViewData["password2"] = password2;

                return SignupIFrame(null, background, color);
            }

            if (!Models.User.IsValidEmail(ref email))
            {
                // Can't use standard RecoverableError things in affiliate forms, do it by hand
                ViewData["error_message"] = "Email is not valid";
                ViewData["affId"] = CurrentAffiliate.Id;
                ViewData["realname"] = realname;
                ViewData["email"] = email;
                ViewData["password"] = password;
                ViewData["password2"] = password2;

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
                ViewData["password"] = password;
                ViewData["password2"] = password2;

                return SignupIFrame(null, background, color);
            }

            var cookie = System.Web.HttpContext.Current.CookieSentOrReceived(Current.AnonymousCookieName);

            var callback = Current.GetFromCache<string>(CallbackKey(cookie));

            string token, authCode;
            if (!PendingUser.CreatePendingUser(email, password, realname, out token, out authCode, out error))
            {
                // Can't use standard RecoverableError things in affiliate forms, do it by hand
                ViewData["error_message"] = error;
                ViewData["affId"] = CurrentAffiliate.Id;
                ViewData["email"] = email;
                ViewData["realname"] = realname;
                ViewData["password"] = password;
                ViewData["password2"] = password2;

                return SignupIFrame(null, background, color);
            }

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

            string affName = CurrentAffiliate.HostFilter;
            Uri callbackUri;
            if (Uri.TryCreate(callback, UriKind.Absolute, out callbackUri))
            {
                affName = callbackUri.Host;
            }

            var success = 
                Current.Email.SendEmail(
                    email,
                    Email.Template.CompleteRegistrationViaAffiliate,
                    new {
                        AffiliateName = affName,
                        RegistrationLink = completeLink.AsLink()
                    });

            if (!success)
            {
                return IrrecoverableError("An error occurred sending the email", "This has been recorded, and will be looked into shortly");
            }

            ViewData["Background"] = background;
            ViewData["Color"] = color;

            return SuccessEmail("Registration Email Sent to " + email, "Check your email for the link to complete your registration.");
        }

        /// <summary>
        /// Returns a "Confirm" form, for users who are logged in.
        /// 
        /// We don't want to *just* slam them into a site because they drove past it, after all.
        /// </summary>
        private ActionResult ConfirmLoginIFrame(string callback, string onLoad, string background, string color)
        {
            if (Current.LoggedInUser == null) return UnexpectedState("Confirming a delegate login while not logged in");

            Uri parsedCallback;
            if(Uri.TryCreate(callback, UriKind.Absolute, out parsedCallback))
            {
                if (Current.LoggedInUser.HasGrantedAuthorization(parsedCallback.Host))
                {
                    return AffiliateRedirect(AddIdentifier(callback, Current.LoggedInUser.GetClaimedIdentifier()));
                }
            }

            var cookie = System.Web.HttpContext.Current.CookieSentOrReceived(Current.UserCookieName);

            Current.AddToCache(CallbackKey(cookie), callback, TimeSpan.FromMinutes(15));

            ViewData["OnLoad"] = onLoad;
            ViewData["Background"] = background;
            ViewData["Color"] = color;

            var continueLink = AddIdentifier(callback, Current.LoggedInUser.GetClaimedIdentifier());
            SetThirdPartyCookieFallbackHtml(@"<p>You can <a href=""" + continueLink + @""" target=""_top"">continue and log in manually</a> however.</p>");

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

            Uri parsedCallback;
            if (Uri.TryCreate(callback, UriKind.Absolute, out parsedCallback))
            {
                Current.LoggedInUser.GrantAuthorization(parsedCallback.Host);
            }

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
            if (Current.LoggedInUser != null) return UnexpectedState("Displaying login form while already logged in");

            var cookie = System.Web.HttpContext.Current.CookieSentOrReceived(Current.AnonymousCookieName);
            var callback = Current.GetFromCache<string>(CallbackKey(cookie)); // like /users/authenticate

            var affId = ViewData["affId"].ToString();
            var switchLink = SwitchLink("signup", affId, background, color, callback, false);
            var refreshLink = SwitchLink("login", affId, background, color, callback, true);

            ViewData["SwitchUrl"] = switchLink;
            ViewData["RefreshUrl"] = refreshLink;

            ViewData["OnLoad"] = onLoad;
            ViewData["Background"] = background;
            ViewData["Color"] = color;

            var continueLink = AddIdentifier(callback, new Uri(Current.Url("")));
            SetThirdPartyCookieFallbackHtml(@"<p>You can <a href=""" + continueLink + @""" target=""_top"">continue and log in manually</a> however.</p>");

            return View("LoginIFrame");
        }

        /// <summary>
        /// Handles submission from LoginIFrame
        /// </summary>
        [Route("affiliate/form/login/submit", HttpVerbs.Post, AuthorizedUser.Anonymous)]
        public ActionResult HandleAffiliateLogin(string email, string password, string background, string color)
        {
            var now = Current.Now;

            if (!Models.User.IsValidEmail(ref email))
            {
                // Standard recoverable error stuff doesn't work here, so do it manually
                ViewData["error_message"] = "Invalid email address";
                ViewData["email"] = email;
                ViewData["affId"] = CurrentAffiliate.Id;

                return LoginIFrame(null, background, color);
            }

            var cookie = System.Web.HttpContext.Current.CookieSentOrReceived(Current.AnonymousCookieName);
            var user = Models.User.FindUserByEmail(email);

            if (user == null)
            {
                // Standard recoverable error stuff doesn't work here, so do it manually
                ViewData["error_message"] = "No account with this email found";
                ViewData["email"] = email;
                ViewData["affId"] = CurrentAffiliate.Id;

                return LoginIFrame(null, background, color);
            }

            if(!user.PasswordMatch(password))
            {
                // Standard recoverable error stuff doesn't work here, so do it manually
                ViewData["error_message"] = "Incorrect password";
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

        /// <summary>
        /// Affiliates can use this route to trigger us into sending an email to a user who forgot their
        /// password/account information.
        /// 
        /// Basically, looks up a user by email; and if that user has auth'd to the affiliate in question before,
        /// sends them an email to reset their password.
        /// 
        /// After following through with the password reset, the user will be redirected to whatever
        /// callback the affiliate provided (assuming that it is a kosher callback).
        /// </summary>
        [Route("affiliate/form/password-recovery")]
        public ActionResult AccountRecovery(string callback, string email)
        {
            if (!CurrentAffiliate.IsValidCallback(callback)) return GenericSecurityError();

            Uri callbackUri;
            if(!Uri.TryCreate(callback, UriKind.Absolute, out callbackUri)) return GenericSecurityError();

            var user = Models.User.FindUserByEmail(email);

            if (user == null) return UnexpectedState("Recovering an account that does not exist");

            // Don't allow just any affiliate to send these e-mails, only those that the user has
            //   auth'd to sometime in the past.
            if (!user.HasGrantedAuthorization(callbackUri.Host)) return GenericSecurityError();

            var now = Current.Now;
            var token = Current.UniqueId().ToString();
            var toInsert =
                new PasswordReset
                {
                    CreationDate = now,
                    TokenHash = Current.WeakHash(token),
                    UserId = user.Id
                };

            Current.WriteDB.PasswordResets.InsertOnSubmit(toInsert);
            Current.WriteDB.SubmitChanges();

            var authCode = Current.MakeAuthCode(new { token, callback });

            var toReset =
                SafeRedirect
                (
                    (Func<string, string, string, ActionResult>)(new AccountController()).NewPassword,
                    new
                    {
                        token,
                        authCode,
                        callback
                    }
                );

            var resetLink = Current.Url(toReset.Url);

            var affiliateLink = callbackUri.Scheme + "://" + callbackUri.Host;
            var affiliateName = callbackUri.Host;

            var deAuthCode = Current.MakeAuthCode(new { email, affHost = callbackUri.Host });

            var toDeAuth =
                SafeRedirect
                (
                    (Func<string, string, string, ActionResult>)(new AccountController()).DeAuthAffiliate,
                    new
                    {
                        email,
                        affHost = callbackUri.Host,
                        authCode = deAuthCode
                    }
                );

            var deAuthLink = Current.Url(toDeAuth.Url);

            if (!Current.Email.SendEmail(email, Email.Template.ResetPasswordAffiliate, new { RecoveryLink = resetLink.AsLink(), AffiliateLink = affiliateLink.AsLink(), AffiliateName = affiliateName, DeAuthLink = deAuthLink.AsLink() }))
            {
                return IrrecoverableError("Could not send email", "This error has been logged");
            }

            return SuccessEmail("Email sent to " + email, "Check your email and follow the link to recover your account");
        }

        /// <summary>
        /// Cause the user to be logged out (if they're logged in at all), provided
        /// that the affiliate has been authenticated in the past
        /// </summary>
        [Route("affiliate/form/logout")]
        public ActionResult TriggerLogout(string callback)
        {
            Uri uri;
            if (!Uri.TryCreate(callback, UriKind.Absolute, out uri)) return GenericSecurityError();

            // Not logged in, just hop where-ever
            if (Current.LoggedInUser == null) return Redirect(callback);
            
            var writeUser = Current.WriteDB.Users.Single(u => u.Id == Current.LoggedInUser.Id);
            writeUser.Logout(Current.Now, uri.Host);

            // Need that redirect bounce page so you can
            return View("Redirect", (object)callback);
        }
    }
}
