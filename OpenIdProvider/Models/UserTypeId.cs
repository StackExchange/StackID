using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace OpenIdProvider.Models
{
    public static class UserTypeId
    {
        /// <summary>
        /// A registered user with an OpenId
        /// </summary>
        public const byte Normal = 1;

        /// <summary>
        /// A user with access to administrative functions
        /// </summary>
        public const byte Administrator = 2;
    }
}