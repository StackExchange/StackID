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
        public static bool Parse(string nonce, out DateTime created)
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
        public static string Create(DateTime? createFor = null)
        {
            var from = createFor ?? Current.Now;

            var ret = new List<byte>();
            ret.AddRange(BitConverter.GetBytes((long)(from - UnixEpoch).TotalSeconds));
            ret.AddRange(Current.Random(8));

            return Convert.ToBase64String(ret.ToArray());
        }

        /// <summary>
        /// Returns true if this nonce is valid (ie. parsable, and has not been used yet).
        /// </summary>
        public static bool IsValid(string nonce, string remoteIp, out string failureReason, DateTime? now = null)
        {
            DateTime created;
            if (!Parse(nonce, out created))
            {
                failureReason = "Could not parse (" + nonce + ")";
                return false;
            }

            var acceptWinCenter = now ?? Current.Now;

            var dif = (acceptWinCenter - created).TotalMinutes;

            // 60 minute total drift permissable
            if (Math.Abs(dif) >= 30)
            {
                failureReason = "Too much drift (" + dif + ")";
                return false;
            }

            // Cannot have already used this nonce from a different IP
            //   Ideally, the nonce wouldn't be re-used by anyone ever... but in practice
            //   proxies and bogus caches in browsers cause a lot of nonce re-use from the same
            //   IP.  Sucks, and less secure, but that's the reality.
            var seenBeforeFrom = Current.GetFromCache<string>("nonce-" + nonce);
            if (seenBeforeFrom != null && seenBeforeFrom != remoteIp)
            {
                failureReason = "Re-used nonce (" + nonce + " from " + seenBeforeFrom + ")";
                return false;
            }

            failureReason = null;
            return true;
        }

        /// <summary>
        /// Marks the given nonce as unusable.
        /// </summary>
        public static void MarkUsed(string nonce, string byIP)
        {
            DateTime created;

            if (!Parse(nonce, out created)) throw new InvalidOperationException("Invalid nonce passed [" + nonce + "]");

            Current.AddToCache("nonce-" + nonce, byIP, TimeSpan.FromMinutes(30));
        }
    }
}