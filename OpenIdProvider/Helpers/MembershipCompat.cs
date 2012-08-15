using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Text;
using System.Security.Cryptography;

namespace OpenIdProvider.Helpers
{
    public static class MembershipCompat
    {
        public const byte PasswordVersion = 1;

        /// <summary>
        /// This implements that default ASP.NET Membership provider password
        /// hashing scheme (yes, it really is this simple).
        /// 
        /// Note that if you're using some other hash provider (not SHA1) or
        /// a different PasswordFormat then you're out of luck.
        /// 
        /// This is meant for migrating users from the built-in
        /// membership provider to the new hotness that is StackID (and PBKDF2).
        /// </summary>
        public static string Hash(string password, string salt)
        {
            var passwordBytes = Encoding.Unicode.GetBytes(password);
            var saltBytes = Convert.FromBase64String(salt);

            var hash = SHA1.Create();

            var total = new byte[saltBytes.Length + passwordBytes.Length];

            Buffer.BlockCopy(saltBytes, 0, total, 0, saltBytes.Length);
            Buffer.BlockCopy(passwordBytes, 0, total, saltBytes.Length, passwordBytes.Length);

            var hashed = hash.ComputeHash(total);

            return Convert.ToBase64String(hashed);
        }
    }
}