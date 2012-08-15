using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using OpenIdProvider.Helpers;
using System.Text.RegularExpressions;
using MvcMiniProfiler;

namespace OpenIdProvider.Models
{
    public partial class User
    {
        /// <summary>
        /// A users (decrypted) email address.
        /// 
        /// We are guaranteed to have this.  All other attributes, less so.
        /// </summary>
        public string Email
        {
            get
            {
                using (MiniProfiler.Current.Step("User.Email"))
                {
                    var encryptedEmail = Current.ReadDB.UserAttributes.Single(a => a.UserId == this.Id && a.UserAttributeTypeId == UserAttributeTypeId.Email);

                    bool outOfDate;
                    var email = Current.Decrypt(encryptedEmail.Encrypted, encryptedEmail.IV, encryptedEmail.KeyVersion, encryptedEmail.HMAC, out outOfDate);

                    // The key has changed since we looked at this record, go ahead and do a spot update
                    if (outOfDate)
                    {
                        string ignored;
                        UpdateAttribute(email, UserAttributeTypeId.Email, out ignored);
                        Current.WriteDB.SubmitChanges();
                    }

                    return email;
                }
            }
        }

        /// <summary>
        /// A users (decrypted) real name.
        /// 
        /// This is an optional attribute.
        /// </summary>
        public string RealName
        {
            get
            {
                using (MiniProfiler.Current.Step("User.RealName"))
                {
                    var encryptedRealName = Current.ReadDB.UserAttributes.SingleOrDefault(a => a.UserId == this.Id && a.UserAttributeTypeId == UserAttributeTypeId.RealName);

                    if (encryptedRealName == null) return null;

                    bool outOfDate;
                    var realName = Current.Decrypt(encryptedRealName.Encrypted, encryptedRealName.IV, encryptedRealName.KeyVersion, encryptedRealName.HMAC, out outOfDate);

                    // The key has changed since we looked at this record, go ahead and do a spot update
                    if (outOfDate)
                    {
                        string ignored;
                        UpdateAttribute(realName, UserAttributeTypeId.RealName, out ignored);
                        Current.WriteDB.SubmitChanges();
                    }

                    return realName;
                }
            }
        }

        /// <summary>
        /// Whether or not this user can access administrative functions
        /// </summary>
        public bool IsAdministrator
        {
            get
            {
                return UserTypeId == Models.UserTypeId.Administrator;
            }
        }

        /// <summary>
        /// Update an existing attribute to the same value (provided for performance sake) but with the latest key version.
        /// 
        /// Requires a subsequent call to SubmitChanges on Current.WriteDB
        /// </summary>
        public bool UpdateAttribute(string value, byte attribute, out string message)
        {
            using (MiniProfiler.Current.Step("UpdateAttribute"))
            {
                var db = Current.WriteDB;

                var toUpdate =
                    (from user in db.Users
                     join attr in db.UserAttributes on user.Id equals attr.UserId
                     where attr.UserAttributeTypeId == attribute && user.Id == this.Id
                     select attr).SingleOrDefault();

                if (value.IsNullOrEmpty())
                {
                    if (toUpdate != null)
                    {
                        db.UserAttributes.DeleteOnSubmit(toUpdate);
                    }

                    message = null;
                    return true;
                }

                if (toUpdate == null)
                {
                    toUpdate = new UserAttribute();
                    toUpdate.CreationDate = Current.Now;
                    toUpdate.UserId = this.Id;
                    toUpdate.UserAttributeTypeId = attribute;

                    db.UserAttributes.InsertOnSubmit(toUpdate);
                }

                string iv, hmac;
                byte version;
                var updated = Current.Encrypt(value, out iv, out version, out hmac);

                if (updated.Length > 267)
                {
                    message = UserAttributeTypeId.GetDisplayName(attribute) + " is too long.";
                    return false;
                }

                toUpdate.Encrypted = updated;
                toUpdate.IV = iv;
                toUpdate.KeyVersion = version;
                toUpdate.HMAC = hmac;

                message = null;
                return true;
            }
        }

        private static Regex AllowedVanityIdRegex = new Regex(@"^[a-z0-9\.\-]+$", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        /// <summary>
        /// Returns true if this is a valid vanity id.
        /// 
        /// Doesn't check if the id has already been issued, or similar
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        public static bool IsValidVanityId(string id, out string errorMsg)
        {
            if (id.Length > 40)
            {
                errorMsg = "Vanity OpenId cannot be more than 40 characters long.";
                return false;
            }

            if (!AllowedVanityIdRegex.IsMatch(id))
            {
                errorMsg = "Vanity OpenId can only contain letters, numbers, dashes, and periods.";
                return false;
            }

            var existingRoutes = RouteAttribute.GetDecoratedRoutes().Keys.Select(k => k.ToLower());

            if (existingRoutes.Contains(id.ToLower()))
            {
                errorMsg = "This Vanity OpenId is reserved.";
                return false;
            }

            // These two routes are manually mapped and *don't* contain illegal characters,
            //    so we need to check for them seperately
            if (id.ToLower() == "ping" || id.ToLower() == "report")
            {
                errorMsg = "This Vanity OpenId is reserved.";
                return false;
            }

            errorMsg = null;
            return true;
        }

        private static Regex ValidEmailRegex = new Regex(@"^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        /// <summary>
        /// Very simple email validation logic, just checks for a @ and . after it.
        /// 
        /// Also strips any bogus white space off the email address.
        /// </summary>
        public static bool IsValidEmail(ref string email)
        {
            if (email.IsNullOrEmpty()) return false;

            email = email.Trim();

            return ValidEmailRegex.IsMatch(email);
        }

        /// <summary>
        /// Create a new account given an email and password
        /// </summary>
        public static bool CreateAccount(string email, PendingUser pendingUser, DateTime now, string vanity, string realname, out User created, out string errorMessage)
        {
            email = email.ToLowerInvariant();

            if (vanity.HasValue() && !Models.User.IsValidVanityId(vanity, out errorMessage))
            {
                created = null;

                return false;
            }

            var db = Current.WriteDB;

            // Quick check to make sure the vanity id is not in use elsewhere
            if (vanity.HasValue() && db.Users.Any(u => u.VanityProviderId == vanity))
            {
                created = null;
                errorMessage = "That Vanity OpenId is already in use";

                return false;
            }

            var provider = Current.UniqueId();

            // Odds of colision are miniscule, but might as well check
            while (db.Users.Any(u => u.ProviderId == provider))
                provider = Current.UniqueId();

            // We need to compute these way before we use them for some length checks
            byte emailVersion;
            string emailIV, emailHMAC;
            var emailEncrypted = Current.Encrypt(email, out emailIV, out emailVersion, out emailHMAC);

            byte nameVersion = 0xFF;
            string nameEncrypted= null, nameIV = null, nameHMAC = null;

            if (realname.HasValue())
            {
                nameEncrypted = Current.Encrypt(realname, out nameIV, out nameVersion, out nameHMAC);
            }

            if (emailEncrypted.Length > 267)
            {
                created = null;
                errorMessage = "Email is too long";

                return false;
            }

            if (nameEncrypted.HasValue() && nameEncrypted.Length > 267)
            {
                created = null;
                errorMessage = "Name is too long";

                return false;
            }

            string emailHash;
            byte emailSaltVersion;
            emailHash = Current.SystemHash(email, out emailSaltVersion);

            var newUser =
                new User
                {
                    LastActivityDate = DateTime.UtcNow,
                    EmailHash = emailHash,
                    EmailSaltVersion = emailSaltVersion,
                    ProviderId = provider,
                    PasswordHash = pendingUser.PasswordHash,
                    PasswordSalt = pendingUser.PasswordSalt,
                    CreationDate = now,
                    VanityProviderId = vanity,
                    UserTypeId = Models.UserTypeId.Normal
                };

            try
            {
                db.Users.InsertOnSubmit(newUser);
                db.SubmitChanges();
            }
            catch (Exception e)
            {
                // Hack: There isn't really a nice way to detect a unique constraint conflict,
                //       so... check the message.  Checking for the constraint name so this isn't
                //       *guaranteed* to break on non-English language systems... still not guaranteed
                //       to work though.
                if(e is System.Data.SqlClient.SqlException && e.Message.Contains("Users_EmailHash_EmailSaltVersion"))
                {
                    created = null;
                    errorMessage = "Email address already registered.";
                    return false;
                }

                Current.LogException(e);
                created = null;
                errorMessage = "User account could not be created.";
                return false;
            }

            // Open season on this user until the context is torn down.
            db.LiftUserRestrictionsOnId = newUser.Id;

            // Can't put a unique constrain on VanityProviderId (as its normally null), so
            //    this is a hack to make sure no two users end up slipping in and getting the 
            //    same vanity id.
            if (vanity.HasValue() && db.Users.Count(u => u.VanityProviderId == vanity) != 1)
            {
                newUser.VanityProviderId = null;
                db.SubmitChanges();
            }

            var emailAttr =
                new UserAttribute
                {
                    UserId = newUser.Id,
                    CreationDate = now,
                    UserAttributeTypeId = UserAttributeTypeId.Email,
                    Encrypted = emailEncrypted,
                    IV = emailIV,
                    KeyVersion = emailVersion,
                    HMAC = emailHMAC
                };

            db.UserAttributes.InsertOnSubmit(emailAttr);
            db.SubmitChanges();

            if (realname.HasValue())
            {
                var nameAttr =
                    new UserAttribute
                    {
                        UserId = newUser.Id,
                        CreationDate = now,
                        UserAttributeTypeId = UserAttributeTypeId.RealName,
                        Encrypted = nameEncrypted,
                        IV = nameIV,
                        KeyVersion = nameVersion,
                        HMAC = nameHMAC
                    };

                db.UserAttributes.InsertOnSubmit(nameAttr);
                db.SubmitChanges();
            }

            created = newUser;
            errorMessage = null;

            return true;
        }

        /// <summary>
        /// Returns true if this user has already granted authorization to the given host,
        /// and should thus not be prompted to confirm login.
        /// </summary>
        public bool HasGrantedAuthorization(string host)
        {
            var db = Current.ReadDB;
            
            return db.UserSiteAuthorizations.Any(u => u.UserId == this.Id && u.SiteHostAddress == host);
        }

        /// <summary>
        /// Grants authorization to the given host, such
        /// that subsequent calls to HasGrantedAuthorization with the same host
        /// will return true.
        /// </summary>
        public void GrantAuthorization(string host)
        {
            host = host.ToLowerInvariant();

            var db = Current.WriteDB;

            var newGrant = new UserSiteAuthorization
            {
                CreationDate = Current.Now,
                SiteHostAddress = host,
                UserId = this.Id
            };

            db.UserSiteAuthorizations.InsertOnSubmit(newGrant);
            db.SubmitChanges();
        }

        /// <summary>
        /// Revokes authorization to the given host, such
        /// that subsequent calls to HasGrantedAuthorization with the same host
        /// will return false.
        /// </summary>
        public void RemoveAuthorization(string host)
        {
            host = host.ToLowerInvariant();

            var db = Current.WriteDB;

            var existingGrant = db.UserSiteAuthorizations.SingleOrDefault(g => g.UserId == this.Id && g.SiteHostAddress == host);

            if (existingGrant != null)
            {
                db.UserSiteAuthorizations.DeleteOnSubmit(existingGrant);
                db.SubmitChanges();
            }
        }

        /// <summary>
        /// Get the most recent activity of this user.
        /// </summary>
        public List<UserHistory> GetHistory(int mostRecentN = 30)
        {
            return Current.ReadDB.UserHistory.Where(h => h.UserId == Id).OrderByDescending(h => h.CreationDate).Take(mostRecentN).ToList();
        }

        /// <summary>
        /// Creates a Uri describing this users "claimed identifier".
        /// </summary>
        public Uri GetClaimedIdentifier()
        {
            return new Uri(Current.AppRootUri, "/user/" + ProviderId.ToString());
        }

        /// <summary>
        /// Creates a Uri describing this user's vanity "claimed identifier"
        /// </summary>
        /// <returns></returns>
        public Uri GetVanityClaimedIdentifier()
        {
            if (VanityProviderId == null) return null;

            return new Uri(Current.AppRootUri, VanityProviderId);
        }

        /// <summary>
        /// Returns true if this user owns the given id.
        /// 
        /// Basically, return true if id is the url containing ProviderId or VanityProviderId
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        public bool ClaimsId(string id)
        {
            var claimedId = GetClaimedIdentifier();
            var vanityClaimedId = GetVanityClaimedIdentifier();

            if (id == claimedId.AbsoluteUri) return true;
            if (vanityClaimedId != null && id == vanityClaimedId.AbsoluteUri) return true;

            return false;
        }

        /// <summary>
        /// Find a user given the "id" portion of the provider URL.
        /// </summary>
        public static User GetFromProviderId(string id)
        {
            Guid guid;

            if (!Guid.TryParse(id, out guid)) return null;

            return Current.ReadDB.Users.SingleOrDefault(u => u.ProviderId == guid);
        }

        /// <summary>
        /// Find a user given the "id" portion of their vanity URL.
        /// 
        /// The vanity url is of the form
        /// http://example.com/vanity/john.smith
        /// </summary>
        public static User GetFromVanityId(string id)
        {
            return Current.ReadDB.Users.SingleOrDefault(u => u.VanityProviderId == id);
        }

        public void AuthenticatedTo(DateTime now, string host)
        {
            var authenticatedEvent = new UserHistory
            {
                Comment = "Authenticated to "+host,
                CreationDate = now,
                UserHistoryTypeId = UserHistoryTypeId.AuthenticatedTo,
                UserId = Id,
                IP = Current.RemoteIP
            };

            Current.WriteDB.UserHistory.InsertOnSubmit(authenticatedEvent);

            LastActivityDate = now;

            Current.WriteDB.SubmitChanges();
        }

        /// <summary>
        /// Record a logout event for the user, destoy their cookie, and invalidate their session.
        /// </summary>
        public void Logout(DateTime now, string careOfHost = null)
        {
            // Delete this users session cookie
            Current.KillCookie(Current.UserCookieName);

            var comment = "Logged Out";
            if (careOfHost.HasValue())
            {
                var cleanHost = careOfHost.ToLowerInvariant();
                if (cleanHost.Length + 3 + comment.Length > 400)
                {
                    cleanHost = cleanHost.Substring(0, 400 - 3 - comment.Length);
                }

                comment += " (" + cleanHost + ")";
            }

            var logoutEvent = new UserHistory
            {
                Comment = comment,
                CreationDate = now,
                UserHistoryTypeId = UserHistoryTypeId.Logout,
                UserId = Id,
                IP = Current.RemoteIP
            };

            Current.WriteDB.UserHistory.InsertOnSubmit(logoutEvent);

            SessionHash = null;
            SessionCreationDate = null;
            LastActivityDate = now;

            Current.WriteDB.SubmitChanges();
        }

        /// <summary>
        /// Record a login event for a user, run any needed cleanup, and give the user a session.
        /// </summary>
        public void Login(DateTime now)
        {
            // Kill the anonymous cookie
            Current.KillCookie(Current.AnonymousCookieName);

            // Write a login event
            var loginEvent = new UserHistory
            {
                Comment = "Logged In",
                CreationDate = now,
                UserHistoryTypeId = UserHistoryTypeId.Login,
                UserId = Id,
                IP = Current.RemoteIP
            };

            Current.WriteDB.UserHistory.InsertOnSubmit(loginEvent);

            // Generate and write a session
            var session = Convert.ToBase64String(Current.Random(32));
            var sessionHash = Current.WeakHash(session);

            SessionHash = sessionHash;
            SessionCreationDate = now;
            LastActivityDate = now;

            // Add the user session cookie
            Current.AddCookie(Current.UserCookieName, session, TimeSpan.FromDays(7));

            Current.WriteDB.SubmitChanges();
        }

        /// <summary>
        /// Change this users password, recording in their history that they have done so.
        /// </summary>
        public void ChangePassword(DateTime now, string newPassword, string comment = null)
        {
            var changeEvent = new UserHistory
            {
                Comment = comment ?? "Changed Password",
                CreationDate = now,
                UserHistoryTypeId = UserHistoryTypeId.PasswordChanged,
                IP = Current.RemoteIP,
                UserId = Id
            };

            Current.WriteDB.UserHistory.InsertOnSubmit(changeEvent);

            var thisUser = Current.WriteDB.Users.Single(u => u.Id == this.Id);

            string salt;
            var pwdHash = Current.SecureHash(newPassword, out salt);

            thisUser.PasswordSalt = salt;
            thisUser.PasswordHash = pwdHash;
            thisUser.LastActivityDate = now;
            thisUser.PasswordVersion = null; // We have a strong password now, regardless of what was there before

            Current.WriteDB.SubmitChanges();
        }

        /// <summary>
        /// Returns true if the given password is correct for this user.
        /// 
        /// Note that if the user is using an unusual PasswordVersion, 
        /// it will be updated to the new hotness.
        /// </summary>
        public bool PasswordMatch(string password)
        {
            if (!PasswordVersion.HasValue)
            {
                return PasswordHash == Current.SecureHash(password, PasswordSalt);
            }

            // ASP.NET MembershipProvider import
            if (PasswordVersion == MembershipCompat.PasswordVersion)
            {
                var isMatch = PasswordHash == MembershipCompat.Hash(password, PasswordSalt);

                if (!isMatch) return false;

                ChangePassword(Current.Now, password, "Security Upgraded");

                return true;
            }

            throw new InvalidOperationException("Unknown PasswordVersion [" + PasswordVersion + "]");
        }

        /// <summary>
        /// Find a user given their email.
        /// 
        /// This user is *writable* (access via Current.WriteDB)
        /// </summary>
        public static User FindUserByEmail(string email)
        {
            email = email.ToLowerInvariant();

            using (MiniProfiler.Current.Step("FindUserByEmail"))
            {
                var db = Current.WriteDB;

                string emailHash;
                byte emailSaltVersion;
                emailHash = Current.SystemHash(email, out emailSaltVersion);

                // Checking against the current salt...
                var user = db.Users.SingleOrDefault(u => u.EmailHash == emailHash && u.EmailSaltVersion == emailSaltVersion);

                // Didn't find the user?  Maybe the salt has changed
                if (user == null)
                {
                    foreach (var oldSalt in KeyStore.OldSalts)
                    {
                        var emailSalt = oldSalt.Item2;
                        emailHash = Current.SecureHash(email, emailSalt);

                        user = db.Users.SingleOrDefault(u => u.EmailHash == emailHash && u.EmailSaltVersion == oldSalt.Item1);

                        if (user != null) break;
                    }

                    // Update the user's hash and salt, so they're on the latest and greatest one
                    if (user != null)
                    {
                        byte newSaltVersion;
                        var newHash = Current.SystemHash(email, out newSaltVersion);

                        user.EmailHash = newHash;
                        user.EmailSaltVersion = newSaltVersion;

                        try
                        {
                            db.SubmitChanges();
                        }
                        catch (Exception e)
                        {
                            Current.LogException(new Exception("Updating email hash lead to conflict", e));
                            // Data is still fine, continue until we can intervene manually...
                        }
                    }
                }

                return user;
            }
        }
    }
}