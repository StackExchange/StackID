using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace OpenIdProvider.Models
{
    public partial class Affiliate
    {
        /// <summary>
        /// Returns true if we trust this affiliate to handle usernames and passwords.
        /// </summary>
        public bool IsTrusted
        {
            get
            {
                return Current.TrustedAffiliateIds.Contains(Id);
            }
        }

        /// <summary>
        /// A value derived from HostFilter that can be shown to a user.
        /// 
        /// So, something like meta.*.stackexchange.com -> stackexchange.com.
        /// </summary>
        public string DisplayableHostFilter
        {
            get
            {
                var wildcard = HostFilter.IndexOf("*.");

                if (wildcard == -1) return HostFilter;

                return HostFilter.Substring(wildcard + 2);
            }
        }

        public static byte[] FixedExponent { get { return new byte[] { 0x1, 0x00, 0x1 }; } }  // 65537

        /// <summary>
        /// Returns true if sig is infact a signature by this affiliate for request to the given path with the given parameters.
        /// </summary>
        public bool ConfirmSignature(string sig, string path, Dictionary<string, string> @params)
        {
            var rsa = new RSACryptoServiceProvider();
            var key = new RSAParameters();
            key.Exponent = FixedExponent;
            key.Modulus = Convert.FromBase64String(this.VerificationModulus);
            rsa.ImportParameters(key);

            var wasSigned = path + "?";

            foreach (var param in @params.Keys.OrderBy(s => s))
            {
                wasSigned += param + "=" + @params[param] + "&";
            }

            wasSigned = wasSigned.Trim('&');

            return rsa.VerifyData(Encoding.UTF8.GetBytes(wasSigned), new SHA1CryptoServiceProvider(), Convert.FromBase64String(sig));
        }

        /// <summary>
        /// Returns true if the url is actually "under" this Affiliate's HostFilter
        /// </summary>
        public bool IsValidCallback(string url)
        {
            var regex = new Regex(@"^http(|s)://" + HostFilter.Replace(".", @"\.").Replace("*", @".[^\.]*?") + @"/.*?", RegexOptions.IgnoreCase);

            return regex.IsMatch(url);
        }

        private static Regex ValidFilter = new Regex(@"[a-z0-9\.\*]+", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        /// <summary>
        /// A valid filter either, does not contain * (must be an exact path match) OR
        /// contains exactly 1 "*", which cannot be in the "second level domain" position
        /// 
        /// Valid:
        ///  - example.com
        ///  - *.example.com
        ///  - sub.*.example.com
        ///  
        /// Invalid:
        ///  - *.com (tld's can't be bound)
        ///  - *.example.*.com (2 wildcards)
        ///  - example.*.com (can't bind for all domains in a top level)
        ///  - example.*.indeed.com (likewise)
        /// 
        /// This method checks that, and returns false if it is not a valid filter.
        /// </summary>
        public static bool IsValidFilter(string filter)
        {
            // maximum filter length in the DB
            if (filter.Length > 100) return false;

            // Only alpha-numeric, '.', or '*' valid in filters
            if (!ValidFilter.IsMatch(filter)) return false;

            if (filter.Count(t => t == '*') > 1) return false;

            var parts = filter.Split('.');
            if (parts.Length < 2) return false;
            if (parts.Any(p => p.Length == 0)) return false;

            if (parts[parts.Length - 1] == "*" || parts[parts.Length - 2] == "*") return false;

            return true;
        }
    }
}