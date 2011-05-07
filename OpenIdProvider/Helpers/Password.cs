using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Text.RegularExpressions;

namespace OpenIdProvider.Helpers
{
    /// <summary>
    /// Helper class for password related things.
    /// </summary>
    public static class Password
    {
        private static int MinPasswordLength = 8;
        
        private static Regex HasLowerCase = new Regex(@"[a-z]", RegexOptions.Compiled);
        private static Regex HasUpperCase = new Regex(@"[A-Z]", RegexOptions.Compiled);
        private static Regex HasDigit = new Regex(@"\d", RegexOptions.Compiled);
        private static Regex HasNonWord = new Regex(@"(_|[^\w\d])", RegexOptions.Compiled);

        /// <summary>
        /// Take the (two) password entries from a user, and determine if they're
        /// kosher for use.
        /// 
        /// Returns true if they are, and false otherwise (and sets messages to something user displayable to explain what).
        /// </summary>
        public static bool CheckPassword(string password, string password2, string email, string vanity, Guid? id, out string message)
        {
            if (password != password2)
            {
                message = "Passwords did not match.";
                return false;
            }

            if (password.ToLower().Contains(email.ToLower()) || email.ToLower().Contains(password.ToLower()))
            {
                message = "Password cannot match your account name, in whole or in part.";
                return false;
            }

            if (vanity.HasValue() && (vanity.ToLower().Contains(password.ToLower()) || password.ToLower().Contains(vanity.ToLower())))
            {
                message = "Password cannot match your vanity identifier, in whole or in part.";
                return false;
            }

            if (id.HasValue && id.ToString().ToLower() == password.ToLower())
            {
                message = "Password cannot be your public identifier.";
                return false;
            }

            if (password.Distinct().Count() < MinPasswordLength)
            {
                message = "Password insufficiently complex, must contain at least " + MinPasswordLength + " unique characters.";
                return false;
            }

            var charClassCount = 0;

            if (HasLowerCase.IsMatch(password)) charClassCount++;
            if (HasUpperCase.IsMatch(password)) charClassCount++;
            if (HasDigit.IsMatch(password)) charClassCount++;
            if (HasNonWord.IsMatch(password)) charClassCount++;

            if (charClassCount < 3)
            {
                message = "Password must contain at least 3 of the following: lower-case character, upper-case character, digit, and special character.";

                return false;
            }

            message = null;
            return true;
        }
    }
}