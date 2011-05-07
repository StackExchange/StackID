using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace OpenIdProvider.Models
{
    public static class UserAttributeTypeId
    {
        /// <summary>
        /// A user's primary, and verified, email address.
        /// </summary>
        public const byte Email = 1;

        /// <summary>
        /// A user's real name, as self-reported.
        /// </summary>
        public const byte RealName = 2;

        /// <summary>
        /// Gets a human displayable name of the attribute.
        /// </summary>
        public static string GetDisplayName(byte id)
        {
            switch (id)
            {
                case Email: return "Email";
                case RealName: return "Name";
                default: throw new NotImplementedException("id of " + id);
            }
        }

        /// <summary>
        /// Returns the byte equivalent of the given attribute name.
        /// 
        /// Inverse of GetDisplayName
        /// </summary>
        public static byte GetTypeId(string name)
        {
            switch (name.ToLower())
            {
                case "email": return Email;
                case "nameperson": return RealName;
                case "realname": return RealName;
                default: throw new NotImplementedException("name of " + name);
            }
        }

        /// <summary>
        /// Returns true if we recognize the attribute name, and support user's setting it.
        /// </summary>
        public static bool IsSupportedAttribute(string name)
        {
            return name.Equals("Email", StringComparison.InvariantCultureIgnoreCase) || name.Equals("RealName", StringComparison.InvariantCultureIgnoreCase);
        }
    }
}