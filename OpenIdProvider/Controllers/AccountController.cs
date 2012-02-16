using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using OpenIdProvider.Helpers;
using OpenIdProvider.Models;
using System.Net;
using DotNetOpenAuth.OpenId.Provider;

namespace OpenIdProvider.Controllers
{
    /// <summary>
    /// Handles creation of, and updates to, user accounts.
    /// </summary>
    public class AccountController : ControllerBase
    {
        /// <summary>
        /// Logout page for logged in users.
        /// </summary>
        [Route("account/logout", AuthorizedUser.LoggedIn)]
        public ActionResult Logout(string returnUrl)
        {
            return View((object)returnUrl);
        }

        /// <summary>
        /// Handles the submission of /account/logout
        /// </summary>
        [Route("account/logout/submit", HttpVerbs.Post, AuthorizedUser.LoggedIn)]
        public ActionResult DoLogout(string returnUrl)
        {
            Current.LoggedInUser.Logout(Current.Now);
            Current.LoggedInUser = null;

            if (returnUrl.HasValue())
            {
                return Redirect(returnUrl);
            }

            return
                SafeRedirect(
                    (Func<ActionResult>)(new HomeController()).Index
                );
        }

        /// <summary>
        /// Login page for existing users.
        /// </summary>
        [Route("account/login", AuthorizedUser.Anonymous | AuthorizedUser.LoggedIn)]
        public ActionResult Login(string session)
        {
            if (Current.LoggedInUser != null)
            {
                return SafeRedirect((Func<ActionResult>)(new UserController()).ViewUser);
            }

            Current.GenerateAnonymousXSRFCookie();

            ViewData["session"] = session;

            return View();
        }

        /// <summary>
        /// Handles the submission of /account/login
        /// </summary>
        [Route("account/login/submit", HttpVerbs.Post, AuthorizedUser.Anonymous)]
        public ActionResult DoLogin(string email, string password, string session)
        {
            var now = Current.Now;

            if (!Models.User.IsValidEmail(ref email))
            {
                return RecoverableError("Invalid email address", new { email, session });
            }

            var user = Models.User.FindUserByEmail(email);

            if (user == null)
            {
                IPBanner.BadLoginAttempt(user, Current.RemoteIP);
                return RecoverableError("No account with this email found", new { email, session });
            }

            if (user.PasswordHash != Current.SecureHash(password, user.PasswordSalt))
            {
                IPBanner.BadLoginAttempt(user, Current.RemoteIP);
                return RecoverableError("Incorrect password", new { email, session });
            }

            user.Login(now);

            if (session.HasValue())
            {
                return 
                    SafeRedirect(
                        (Func<string, string, ActionResult>)(new OpenIdController()).ResumeAfterLogin,
                        new
                        {
                            session
                        }
                    );
            }

            return
                SafeRedirect(
                    (Func<ActionResult>)(new UserController()).ViewUser
                );
        }

        /// <summary>
        /// Part one of our registration process.
        /// 
        /// Here the user provides an email address for us to verify.
        /// </summary>
        [Route("account/register", AuthorizedUser.Anonymous)]
        public ActionResult Register()
        {
            Current.GenerateAnonymousXSRFCookie();

            return View();
        }

        /// <summary>
        /// Handles the submission fro /account/register
        /// 
        /// Actually sends out a verification email.
        /// </summary>
        [Route("account/register/submit", HttpVerbs.Post, AuthorizedUser.Anonymous)]
        public ActionResult SendEmailVerficationToken(string email, string password, string password2, string realname)
        {
            if (email.IsNullOrEmpty()) return RecoverableError("Email is required", new { realname });
            if (!Models.User.IsValidEmail(ref email)) return RecoverableError("Email is not valid", new { email, realname, password, password2 });

            // Check that the captcha succeeded
            string error;
            if (!Captcha.Verify(Request.Form, out error)) return RecoverableError(error, new { email, realname });

            string message;
            if (!Password.CheckPassword(password, password2, email, null, null, out message)) return RecoverableError(message, new { email, realname });

            string token, authCode;
            if (!PendingUser.CreatePendingUser(email, password, realname, out token, out authCode, out error))
            {
                return RecoverableError(error, new { email, realname, password, password2 });
            }

            var toComplete = 
                SafeRedirect(
                    (Func<string, string, string, string, ActionResult>)CompleteRegistration,
                    new
                    {
                        token,
                        email,
                        realname,
                        authCode
                    }
                );

            var completeLink = Current.Url(toComplete.Url);

            if (!Current.Email.SendEmail(email, Email.Template.CompleteRegistration, new { RegistrationLink = completeLink.AsLink() }))
            {
                return IrrecoverableError("An error occurred sending the email", "This has been recorded, and will be looked into shortly");
            }

            return SuccessEmail("Registration Email Sent to " + email, "Check your email for the link to complete your registration");
        }

        /// <summary>
        /// Part two of our registration process.
        /// 
        /// Getting here with a valid token/email pair means they got our email,
        /// so we can trust it now.
        /// </summary>
        [Route("account/complete-registration", AuthorizedUser.Anonymous)]
        public ActionResult CompleteRegistration(string token, string email, string realname, string authCode)
        {
            var shouldMatch = Current.MakeAuthCode(new { email, token, realname });

            if (shouldMatch != authCode) return GenericSecurityError();

            var t = Current.ReadDB.PendingUsers.SingleOrDefault(u => u.AuthCode == authCode);

            if (t == null) return IrrecoverableError("No Pending User Found", "We could not find a pending registration for you.  Please register again.");

            if (t.DeletionDate != null)
            {
                return IrrecoverableError("Account already confirmed", "This account has already been created, log in to begin using it.");
            }

            var now = Current.Now;

            // Switching to a writing context
            var db = Current.WriteDB;
            var pending = db.PendingUsers.Single(p => p.Id == t.Id);

            string error;
            User newUser;
            if (!Models.User.CreateAccount(email, pending, now, null, realname, out newUser, out error))
            {
                return IrrecoverableError("Registration Failed", error);
            }

            pending.DeletionDate = now;
            db.SubmitChanges();

            newUser.Login(now);

            // Hack: We can't redirect or the cookie doesn't attach under most browsers
            return View("../User/View", newUser);
        }

        /// <summary>
        /// User account recovery entry point
        /// </summary>
        [Route("account/recovery", AuthorizedUser.Anonymous)]
        public ActionResult Recovery()
        {
            Current.GenerateAnonymousXSRFCookie();

            return View();
        }

        /// <summary>
        /// Handles the submission from /account/recovery.
        /// 
        /// Actually sends an email containing a 
        /// </summary>
        /// <param name="email"></param>
        /// <returns></returns>
        [Route("account/recovery/submit", HttpVerbs.Post, AuthorizedUser.Anonymous)]
        public ActionResult SendRecovery(string email)
        {
            IPBanner.AttemptedToSendRecoveryEmail(Current.RemoteIP);

            var user = Models.User.FindUserByEmail(email);

            if (user == null) return RecoverableError("No account with that email was found", new { email });

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

            var toReset =
                SafeRedirect(
                    (Func<string, string, string, ActionResult>)NewPassword,
                    new { token }
                );

            var resetLink = Current.Url(toReset.Url);

            if (!Current.Email.SendEmail(email, Email.Template.ResetPassword, new { RecoveryLink = resetLink.AsLink() }))
            {
                return IrrecoverableError("An error occurred sending the email", "This has been recorded, and will be looked into shortly");
            }

            return SuccessEmail("Password Recovery Email Sent to " + email, "Check your email for the link to reset your password.");
        }

        /// <summary>
        /// Entry point for a user resetting their password.
        /// 
        /// token is a single use token that was previously sent
        /// to a user via email.
        /// </summary>
        [Route("account/password-reset", AuthorizedUser.Anonymous | AuthorizedUser.LoggedIn)]
        public ActionResult NewPassword(string token, string callback, string authCode)
        {
            // Has a callback, indicating it is from an affiliate and thus needs to be validated
            if (callback.HasValue())
            {
                var shouldMatch = Current.MakeAuthCode(new { token, callback });

                if (shouldMatch != authCode)
                {
                    return GenericSecurityError();
                }

                ViewData["callback"] = callback;
                ViewData["authCode"] = authCode;
            }

            if (token.HasValue())
            {
                ViewData["token"] = token;
            }

            if (Current.LoggedInUser == null)
            {
                var hash = Current.WeakHash(token);

                var t = Current.ReadDB.PasswordResets.Where(p => p.TokenHash == hash).SingleOrDefault();

                if (t == null) return IrrecoverableError("Password Reset Request Not Found", "We could not find a pending password reset request.");

                Current.GenerateAnonymousXSRFCookie();

                return View();
            }

            return View();
        }

        /// <summary>
        /// Repeated logic from SetNewPassword.
        /// 
        /// Pass it a resetToken to destroy on success (if user is anonymous).
        /// 
        /// Returns null if everything is OK, and an ActionResult if an error occurred.
        /// </summary>
        private ActionResult ChangePasswordAndSendEmail(string password, string password2, string token, PasswordReset resetToken, User user, DateTime now)
        {
            string message;
            if (!Password.CheckPassword(password, password2, user.Email, user.VanityProviderId, user.ProviderId, out message))
                return RecoverableError(message, new { token });

            user.ChangePassword(now, password);

            if (resetToken != null)
            {
                Current.WriteDB.PasswordResets.DeleteOnSubmit(resetToken);
            }

            Current.WriteDB.SubmitChanges();

            var account = SafeRedirect((Func<ActionResult>)(new UserController()).ViewUser);

            if (!Current.Email.SendEmail(user.Email, Email.Template.PasswordChanged, new { AccountLink = Current.Url(account.Url).AsLink() }))
            {
                return IrrecoverableError("An error occurred sending the email", "This has been recorded, and will be looked into shortly");
            }

            return null;
        }

        /// <summary>
        /// Handles the submission of /account/password-rest.
        /// 
        /// Actually updates the user's password.
        /// </summary>
        [Route("account/password-reset/submit", HttpVerbs.Post, AuthorizedUser.Anonymous | AuthorizedUser.LoggedIn)]
        public ActionResult SetNewPassword(string token, string password, string password2, string callback, string authCode)
        {
            // Has a callback, indicating it is from an affiliate and thus needs to be validated
            if (callback.HasValue())
            {
                var shouldMatch = Current.MakeAuthCode(new { token, callback });

                if (shouldMatch != authCode)
                {
                    return GenericSecurityError();
                }
            }

            var now = Current.Now;
            var success = Success("Password Reset", "Your password has been reset.");
            
            if (Current.LoggedInUser == null)
            {
                var hash = Current.WeakHash(token);
                var t = Current.WriteDB.PasswordResets.SingleOrDefault(u => u.TokenHash == hash);

                if (t == null) return IrrecoverableError("Password Reset Request Not Found", "We could not find a pending password reset request.");
                
                var user = t.User;

                var res = ChangePasswordAndSendEmail(password, password2, token, t, user, now);
                if (res != null) return res;

                user.Login(now);

                if (callback.HasValue())
                {
                    var redirectUrl =
                        callback +
                        (callback.Contains('?') ? '&' : '?') +
                        "openid_identifier=" + Server.UrlEncode(user.GetClaimedIdentifier().AbsoluteUri);

                    return Redirect(redirectUrl);
                }
                else
                {
                    return success;
                }
            }

            var ret = ChangePasswordAndSendEmail(password, password2, token, null, Current.LoggedInUser, now);
            if (ret != null) return ret;

            if (callback.HasValue())
            {
                var redirectUrl =
                    callback +
                    (callback.Contains('?') ? '&' : '?') +
                    "openid_identifier=" + Server.UrlEncode(Current.LoggedInUser.GetClaimedIdentifier().AbsoluteUri);

                return Redirect(redirectUrl);
            }
            else
            {
                return success;
            }
        }

        /// <summary>
        /// When a user has registered via an affiliate, we need to do some extra work.
        /// 
        /// Thus, a distinct landing for completing that registration.
        /// </summary>
        [Route("account/affiliate/complete-registration", AuthorizedUser.Anonymous)]
        public ActionResult CompleteAffiliateTriggeredRegistration(string email, string realname, string affId, string token, string callback, string authCode)
        {
            var shouldMatch = Current.MakeAuthCode(new { email, token, realname, callback, affId });

            if (shouldMatch != authCode) return GenericSecurityError();

            var t = Current.ReadDB.PendingUsers.SingleOrDefault(u => u.AuthCode == authCode);

            if (t == null) return IrrecoverableError("No Pending User Found", "We could not find a pending registration for you.  Please register again.");

            if (t.DeletionDate != null)
            {
                return IrrecoverableError("Account already confirmed", "This account has already been created, log in to begin using it.");
            }

            var now = Current.Now;

            // Switching to a writing context
            var db = Current.WriteDB;
            var pending = db.PendingUsers.Single(p => p.Id == t.Id);

            string error;
            User newUser;
            if (!Models.User.CreateAccount(email, pending, now, null, realname, out newUser, out error))
            {
                return IrrecoverableError("Registration Failed", error);
            }

            pending.DeletionDate = now;
            db.SubmitChanges();

            newUser.Login(now);

            // This account was created to faciliate this login, there's no need to prompt for permission.
            Uri parsedCallback;
            if (Uri.TryCreate(callback, UriKind.Absolute, out parsedCallback))
            {
                newUser.GrantAuthorization(parsedCallback.Host);
            }

            var redirectUrl =
                callback +
                (callback.Contains('?') ? '&' : '?') +
                "openid_identifier=" + Server.UrlEncode(newUser.GetClaimedIdentifier().AbsoluteUri);

            // Hack: We can't redirect or the cookie doesn't attach under most browsers
            return View("AffiliateRegistrationRedirect", (object)redirectUrl);
        }


        /// <summary>
        /// Prompt's the logged in user for their permission to send credentials to
        /// the site identified in an auth session.
        /// </summary>
        [Route("account/prompt", AuthorizedUser.LoggedIn)]
        public ActionResult PromptForAuthorization(string session)
        {
            if (!session.HasValue()) return IrrecoverableError("Could Not Find Pending Authentication Request", "No session was provided.");

            var authRequestBytes = Current.GetFromCache<byte[]>(session);

            if (authRequestBytes == null) return IrrecoverableError("Could Not Find Pending Authentication Request", "We were unable to find the pending authentication request, and cannot resume login.");

            IAuthenticationRequest authRequest = null;
            authRequest = authRequest.DeSerialize(authRequestBytes);

            ViewData["session"] = session;

            return View((object)authRequest.Realm.Host);
        }

        /// <summary>
        /// Handles the submission from PromptForAuthorization.
        /// 
        /// The user grants authorization to the site identified in the session, and resumes the
        /// auth session.
        /// </summary>
        [Route("account/prompt/submit", HttpVerbs.Post, AuthorizedUser.LoggedIn)]
        public ActionResult ConfirmAuthorization(string session)
        {
            if (!session.HasValue()) return IrrecoverableError("Could Not Find Pending Authentication Request", "No session was provided.");

            var authRequestBytes = Current.GetFromCache<byte[]>(session);

            if (authRequestBytes == null) return IrrecoverableError("Could Not Find Pending Authentication Request", "We were unable to find the pending authentication request, and cannot resume login.");

            IAuthenticationRequest authRequest = null;
            authRequest = authRequest.DeSerialize(authRequestBytes);

            Current.LoggedInUser.GrantAuthorization(authRequest.Realm.Host);

            return
                SafeRedirect(
                    (Func<string, string, ActionResult>)(new OpenIdController()).ResumeAfterLogin,
                    new
                    {
                        session
                    }
                );
        }

        /// <summary>
        /// De-authorize an affiliate.
        /// 
        /// We don't link this in the UI, as its the kind of bogus account management you shouldn't
        /// have to deal with.  We *do*, however, include it in any affiliate triggered transmissions
        /// so users can stop affiliates from spamming them.
        /// </summary>
        [Route("account/de-auth")]
        public ActionResult DeAuthAffiliate(string email, string affHost, string authCode)
        {
            var shouldMatch = Current.MakeAuthCode(new { email, affHost });

            if (shouldMatch != authCode) return GenericSecurityError();

            if (Current.LoggedInUser == null)
            {
                Current.GenerateAnonymousXSRFCookie();
            }

            ViewData["email"] = email;
            ViewData["affHost"] = affHost;
            ViewData["authCode"] = authCode;

            return View();
        }

        /// <summary>
        /// Handle the submission from /account/de-auth .
        /// 
        /// Removes the affiliate grant.
        /// </summary>
        [Route("account/de-auth/submit", HttpVerbs.Post)]
        public ActionResult HandleDeAuthAffiliate(string email, string affHost, string authCode)
        {
            var shouldMatch = Current.MakeAuthCode(new { email, affHost });

            if (shouldMatch != authCode) return GenericSecurityError();

            var user = Current.LoggedInUser ?? Models.User.FindUserByEmail(email);

            if (user == null)
            {
                return IrrecoverableError("Could not find user", "No user record found.");
            }

            user.RemoveAuthorization(affHost);

            return Success("You have revoked " + affHost + "'s authorization", "They will be unable to contact you, and must prompt again for authorization to access your information.");
        }
    }
}
