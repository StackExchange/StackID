using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using OpenIdProvider.Helpers;
using OpenIdProvider.Models;
using System.Net;

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
        public ActionResult Logout()
        {
            return View();
        }

        /// <summary>
        /// Handles the submission of /account/logout
        /// </summary>
        [Route("account/logout/submit", HttpVerbs.Post, AuthorizedUser.LoggedIn)]
        public ActionResult DoLogout()
        {
            Current.LoggedInUser.Logout(Current.Now);
            Current.LoggedInUser = null;

            return
                SafeRedirect(
                    (Func<ActionResult>)(new HomeController()).Index
                );
        }

        /// <summary>
        /// Login page for existing users.
        /// </summary>
        [Route("account/login", AuthorizedUser.Anonymous)]
        public ActionResult Login(string session)
        {
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
            var user = Models.User.FindUserByEmail(email);

            if (user == null || user.PasswordHash != Current.SecureHash(password, user.PasswordSalt))
            {
                IPBanner.BadLoginAttempt(user, Current.RemoteIP);
                return RecoverableError("Unknown e-mail or incorrect password", new { email, session });
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
        /// Here the user provides an e-mail address for us to verify.
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
        /// Actually sends out a verification e-mail.
        /// </summary>
        [Route("account/register/submit", HttpVerbs.Post, AuthorizedUser.Anonymous)]
        public ActionResult SendEmailVerficationToken(string email, string password, string password2, string realname)
        {
            if (email.IsNullOrEmpty()) return RecoverableError("Email is required", new { realname });

            // Check that the captcha succeeded
            string error;
            if (!Captcha.Verify(Request.Form, out error)) return RecoverableError(error, new { email, realname });

            string message;
            if (!Password.CheckPassword(password, password2, email, null, null, out message)) return RecoverableError(message, new { email, realname });

            string pwSalt;
            string pwHash = Current.SecureHash(password, out pwSalt);

            var token = Current.UniqueId().ToString();
            var authCode = Current.MakeAuthCode(new { email, token, realname });

            var pendingUser = new PendingUser
            {
                AuthCode = authCode,
                CreationDate = Current.Now,
                PasswordHash = pwHash,
                PasswordSalt = pwSalt
            };

            Current.WriteDB.PendingUsers.InsertOnSubmit(pendingUser);
            Current.WriteDB.SubmitChanges();

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

            Email.SendEmail(email, Email.Template.CompleteRegistration, new { RegistrationLink = completeLink });

            return Success("Registration E-mail Sent", "Check your e-mail for the link to complete your registration");
        }

        /// <summary>
        /// Part two of our registration process.
        /// 
        /// Getting here with a valid token/email pair means they got our e-mail,
        /// so we can trust it now.
        /// </summary>
        [Route("account/complete-registration", AuthorizedUser.Anonymous)]
        public ActionResult CompleteRegistration(string token, string email, string realname, string authCode)
        {
            var shouldMatch = Current.MakeAuthCode(new { email, token, realname });

            if (shouldMatch != authCode) return GenericSecurityError();

            var t = Current.ReadDB.PendingUsers.SingleOrDefault(u => u.AuthCode == authCode && u.DeletionDate == null);

            if (t == null) return IrrecoverableError("No Pending User Found", "We could not find a pending registration for you.  Please register again.");

            var now = Current.Now;

            // Switching to a writing context
            var db = Current.WriteDB;
            var pending = db.PendingUsers.Single(p => p.Id == t.Id);

            string error;
            User newUser;
            if (!Models.User.CreateAccount(email, pending, now, null, realname, out newUser, out error))
            {
                return IrrecoverableError("Registration Failed", "New user could not be created");
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
        /// Actually sends an e-mail containing a 
        /// </summary>
        /// <param name="email"></param>
        /// <returns></returns>
        [Route("account/recovery/submit", HttpVerbs.Post, AuthorizedUser.Anonymous)]
        public ActionResult SendRecovery(string email)
        {
            IPBanner.AttemptedToSendRecoveryEmail(Current.RemoteIP);

            var user = Models.User.FindUserByEmail(email);

            if (user == null) return RecoverableError("No account with that e-mail was found", new { email });

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
                    (Func<string, ActionResult>)NewPassword,
                    new { token }
                );

            var resetLink = Current.Url(toReset.Url);

            Email.SendEmail(email, Email.Template.ResetPassword, new { RecoveryLink = resetLink });

            return Success("Password Recovery E-mail Sent", "Check your e-mail for the link to reset your password.");
        }

        /// <summary>
        /// Entry point for a user resetting their password.
        /// 
        /// token is a single use token that was previously sent
        /// to a user via e-mail.
        /// </summary>
        [Route("account/password-reset", AuthorizedUser.Anonymous)]
        public ActionResult NewPassword(string token)
        {
            var hash = Current.WeakHash(token);

            var t = Current.ReadDB.PasswordResets.Where(p => p.TokenHash == hash).SingleOrDefault();

            if (t == null) return IrrecoverableError("Password Reset Request Not Found", "We could not find a pending password reset request.");

            Current.GenerateAnonymousXSRFCookie();

            ViewData["token"] = token;

            return View();
        }

        /// <summary>
        /// Handles the submission of /account/password-rest.
        /// 
        /// Actually updates the user's password.
        /// </summary>
        [Route("account/password-reset/submit", HttpVerbs.Post, AuthorizedUser.Anonymous)]
        public ActionResult SetNewPassword(string token, string password, string password2)
        {
            var hash = Current.WeakHash(token);
            var t = Current.WriteDB.PasswordResets.SingleOrDefault(u => u.TokenHash == hash);

            if (t == null) return IrrecoverableError("Password Reset Request Not Found", "We could not find a pending password reset request.");

            var now = Current.Now;
            var user = t.User;

            string message;
            if (!Password.CheckPassword(password, password2, user.Email, user.VanityProviderId, user.ProviderId, out message)) 
                return RecoverableError(message, new { token });

            user.ChangePassword(now, password);

            Current.WriteDB.PasswordResets.DeleteOnSubmit(t);
            Current.WriteDB.SubmitChanges();

            Email.SendEmail(user.Email, Email.Template.PasswordChanged);

            user.Login(now);

            return Success("Password Reset", "Your password has been reset.");
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

            var t = Current.ReadDB.PendingUsers.SingleOrDefault(u => u.AuthCode == authCode && u.DeletionDate == null);

            if (t == null) return IrrecoverableError("No Pending User Found", "We could not find a pending registration for you.  Please register again.");

            var now = Current.Now;

            // Switching to a writing context
            var db = Current.WriteDB;
            var pending = db.PendingUsers.Single(p => p.Id == t.Id);

            string error;
            User newUser;
            if (!Models.User.CreateAccount(email, pending, now, null, realname, out newUser, out error))
            {
                return IrrecoverableError("Registration Failed", "New user could not be created");
            }

            pending.DeletionDate = now;
            db.SubmitChanges();

            newUser.Login(now);

            var redirectUrl =
                callback +
                (callback.Contains('?') ? '&' : '?') +
                "openid_identifier=" + Server.UrlEncode(newUser.GetClaimedIdentifier().AbsoluteUri);

            // Hack: We can't redirect or the cookie doesn't attach under most browsers
            return View("AffiliateRegistrationRedirect", (object)redirectUrl);
        }
    }
}
