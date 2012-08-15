using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using OpenIdProvider.Helpers;
using System.Web.Mvc;
using System.Text;
using System.Net;
using OpenIdProvider.Models;

namespace OpenIdProvider.Controllers
{

    public partial class AffiliateFormsController
    {
        protected ActionResult ApiFailure(string message, int? responseCode = null)
        {
            Response.StatusCode = (responseCode ?? (int?)HttpStatusCode.BadRequest).Value;
            return new ContentResult { Content = message, ContentType = "text/plain", ContentEncoding = Encoding.UTF8 };
        }

        protected ActionResult ApiSuccess(string content = null)
        {
            Response.StatusCode = (int)HttpStatusCode.OK;
            return new ContentResult { Content = content ?? "success", ContentType = "text/plain", ContentEncoding = Encoding.UTF8 };
        }

        /// <summary>
        /// Returns text/plain "true" if the email is in use and "false" if it isn't.
        /// </summary>
        [Route("affiliate/trusted/email-existance", HttpVerbs.Post, true)]
        public ActionResult EmailInUse(string email)
        {
            if (!CurrentAffiliate.IsTrusted) return NotFound();

            var user = Models.User.FindUserByEmail(email);

            if (user != null) return ApiSuccess("true");

            return ApiSuccess("false");
        }

        /// <summary>
        /// Logs a user in given their email and password.
        /// 
        /// On success it redirects to `callback` with provider id.
        /// </summary>
        [Route("affiliate/trusted/login", HttpVerbs.Post, true)]
        public ActionResult TrustedLogin(string email, string password, string callback)
        {
            if (!CurrentAffiliate.IsTrusted) return NotFound();

            if (!Models.User.IsValidEmail(ref email))
            {
                return ApiFailure("Invalid email [" + email + "]");
            }

            var user = Models.User.FindUserByEmail(email);

            if (user == null)
            {
                return ApiFailure("No user found with email [" + email + "]", (int)HttpStatusCode.NotFound);
            }

            if (!user.PasswordMatch(password))
            {
                // different status code 
                return ApiFailure("Bad Password", (int)HttpStatusCode.Forbidden);
            }

            user.Login(Current.Now);

            var response = AddIdentifier(callback, Current.LoggedInUser.GetClaimedIdentifier());

            return Redirect(response);
        }

        /// <summary>
        /// Sends an email to a user, identified by email address, using the given MARKDOWN template.
        /// 
        /// Replaces the string {RecoveryLink} with callback + a query string parameter that (in `resetToken`) that
        /// will allow that site to reset a user's password.
        /// 
        /// Naturally, you better really really trust affiliates.
        /// </summary>
        [Route("affiliate/trusted/password-recovery", HttpVerbs.Post, true)]
        public ActionResult TrustedPasswordRecovery(string email, string emailTemplate, string emailSubject, string callback)
        {
            if (!CurrentAffiliate.IsTrusted) return NotFound();

            if (!Models.User.IsValidEmail(ref email))
            {
                return ApiFailure("Invalid email [" + email + "]");
            }

            var user = Models.User.FindUserByEmail(email);

            if (user == null)
            {
                return ApiFailure("No user found with email [" + email + "]", (int)HttpStatusCode.NotFound);
            }

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

            var toReset = callback;

            if (toReset.Contains("?"))
            {
                toReset += "&resetToken=" + HttpUtility.UrlEncode(token);
            }
            else
            {
                toReset += "?resetToken=" + HttpUtility.UrlEncode(token);
            }

            if (!Current.Email.SendEmail(email, emailTemplate, emailSubject, new { RecoveryLink = toReset }))
            {
                return ApiFailure("An error occurred sending the email");
            }

            return ApiSuccess();
        }

        /// <summary>
        /// Takes a token created via affiliate/trusted/password-recovery and and performs
        /// the password change.
        /// </summary>
        [Route("affiliate/trusted/password-recovery/complete", HttpVerbs.Post, true)]
        public ActionResult CompleteTrustedPasswordRecovery(string email, string resetToken, string password)
        {
            if (!CurrentAffiliate.IsTrusted) return NotFound();

            if (!Models.User.IsValidEmail(ref email))
            {
                return ApiFailure("Invalid email [" + email + "]");
            }

            var user = Models.User.FindUserByEmail(email);

            if (user == null)
            {
                return ApiFailure("No user found with email [" + email + "]", (int)HttpStatusCode.NotFound);
            }

            var hash = Current.WeakHash(resetToken);
            var t = Current.WriteDB.PasswordResets.Where(p => p.TokenHash == hash).SingleOrDefault();

            if (t == null) return ApiFailure("Could not find a pending password reset request.");

            if (t.UserId != user.Id) return ApiFailure("Token user doesn't match email user");

            string errorMessage;
            if (!Password.CheckPassword(password, password, email, user.VanityProviderId, user.ProviderId, out errorMessage))
                return ApiFailure(errorMessage);

            user.ChangePassword(Current.Now, password, "via " + CurrentAffiliate.DisplayableHostFilter);

            // Don't let that token be used twice.
            Current.WriteDB.PasswordResets.DeleteOnSubmit(t);
            Current.WriteDB.SubmitChanges();

            return ApiSuccess();
        }
    }
}