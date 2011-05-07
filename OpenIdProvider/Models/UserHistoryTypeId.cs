using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace OpenIdProvider.Models
{
    public static class UserHistoryTypeId
    {
        /// <summary>
        /// User logged into provider.
        /// </summary>
        public const byte Login = 1;

        /// <summary>
        /// User explicitly logged out of provider.
        /// </summary>
        public const byte Logout = 2;

        /// <summary>
        /// User changed their password.
        /// </summary>
        public const byte PasswordChanged = 3;

        /// <summary>
        /// User changed their email.
        /// </summary>
        public const byte EmailChanged = 4;

        /// <summary>
        /// User changed their real name.
        /// </summary>
        public const byte RealNameChanged = 5;

        /// <summary>
        /// User authenticated to another website via OpenId.
        /// </summary>
        public const byte AuthenticatedTo = 6;

        /// <summary>
        /// User changed their vanity id.
        /// </summary>
        public const byte VanityIdChanged = 7;

        public static string GetDisplayName(byte b)
        {
            switch (b)
            {
                case Login: return "Login";
                case Logout: return "Logout";
                case PasswordChanged: return "Password Changed";
                case EmailChanged: return "Email Changed";
                case RealNameChanged: return "Real Name Changed";
                case AuthenticatedTo: return "Authenticated To";
                case VanityIdChanged: return "Vanity OpenId Changed";
                default: throw new NotImplementedException("for value " + b);
            }
        }
    }
}