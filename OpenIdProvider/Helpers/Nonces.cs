using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Collections.Concurrent;

namespace OpenIdProvider.Helpers
{
    /// <summary>
    /// Helper class for managing nonce/token validation and expiration
    /// </summary>
    public static class Nonces
    {
        public static readonly DateTime UnixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        
        /// <summary>
        /// Extracts the encoded creation date, and validates the form.
        /// </summary>
        internal static bool Parse(string nonce, out DateTime created)
        {
            created = DateTime.MinValue;

            try
            {
                var bytes = Convert.FromBase64String(nonce);

                if (bytes.Length != 16) return false;

                long secs = BitConverter.ToInt64(bytes, 0);

                created = UnixEpoch + TimeSpan.FromSeconds(secs);

                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>
        /// Create a new nonce.
        /// 
        /// Note that many times a purely random string is preferable
        /// Only use these nonces if we:
        ///   - aren't storing and checking against a value
        ///   - need expiration semantics
        /// </summary>
        public static string Create()
        {
            var ret = new List<byte>();
            ret.AddRange(BitConverter.GetBytes((long)(Current.Now - UnixEpoch).TotalSeconds));
            ret.AddRange(Current.Random(8));

            return Convert.ToBase64String(ret.ToArray());
        }

        /// <summary>
        /// Returns true if this nonce is valid (ie. parsable, and has not been used yet).
        /// </summary>
        public static bool IsValid(string nonce, out string failureReason)
        {
            DateTime created;
            if (!Parse(nonce, out created))
            {
                failureReason = "Could not parse (" + nonce + ")";
                return false;
            }

            var dif = (Current.Now - created).TotalMinutes;

            // 10 minute total drift permissable
            if (Math.Abs(dif) >= 5)
            {
                failureReason = "Too much drift (" + dif + ")";
                return false;
            }

            // Cannot have already used this nonce
            if (Current.GetFromCache<string>("nonce-" + nonce) != null)
            {
                failureReason = "Re-used nonce (" + nonce + ")";
                return false;
            }

            failureReason = null;
            return true;
        }

        /// <summary>
        /// Marks the given nonce as unusable.
        /// </summary>
        public static void MarkUsed(string nonce)
        {
            DateTime created;

            if (!Parse(nonce, out created)) throw new InvalidOperationException("Invalid nonce passed [" + nonce + "]");

            Current.AddToCache("nonce-" + nonce, "", TimeSpan.FromMinutes(10));
        }
    }
}