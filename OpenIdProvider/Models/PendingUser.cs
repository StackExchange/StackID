using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace OpenIdProvider.Models
{
    public partial class PendingUser
    {
        /// <summary>
        /// Create a pending user in the DB.
        /// 
        /// Returns the authCode and token necessary to complete registration via e-mail.
        /// 
        /// If an error occurs, returns false and sets a user displayable message in `error`.
        /// </summary>
        public static bool CreatePendingUser(string email, string password, string realname, out string token, out string authCode, out string error)
        {
            if (Models.User.FindUserByEmail(email) != null)
            {
                token = null;
                authCode = null;
                error = "Email already in use.";
                return false;
            }

            var db = Current.WriteDB;

            string pwSalt;
            string pwHash = Current.SecureHash(password, out pwSalt);

            token = Current.UniqueId().ToString();
            authCode = Current.MakeAuthCode(new { email, token, realname });

            var pendingUser = new PendingUser
            {
                AuthCode = authCode,
                CreationDate = Current.Now,
                PasswordHash = pwHash,
                PasswordSalt = pwSalt
            };

            db.PendingUsers.InsertOnSubmit(pendingUser);
            db.SubmitChanges();

            error = null;
            return true;
        }
    }
}