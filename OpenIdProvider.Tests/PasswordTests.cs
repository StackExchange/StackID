using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using NUnit.Framework;
using OpenIdProvider.Helpers;

namespace OpenIdProvider.Tests
{
    /// <summary>
    /// Summary description for AuthCodeTests
    /// </summary>
    [TestFixture]
    public class PasswordTests
    {
        [Test]
        public void SaltSize()
        {
            var sizes = new List<int>();

            for (int i = 0; i < 100; i++)
            {
                var salt = Current.GenerateSalt(Int32.MaxValue);

                sizes.Add(salt.Length);
            }

            Assert.IsTrue(sizes.Max() <= 33, "Max length = " + sizes.Max());
        }

        [Test]
        public void HashSize()
        {
            var sizes = new List<int>();

            string salt;
            for (int i = 0; i < 100; i++)
            {
                var hash = Current.SecureHash(Convert.ToBase64String(Current.Random(32)), out salt);

                sizes.Add(hash.Length);
            }

            Assert.IsTrue(sizes.Max() <= 32, "hash.Length = " + sizes.Max());
        }

        [Test]
        public void ValidPasswords()
        {
            string ignored;
            Assert.IsTrue(Password.CheckPassword("Password1234-", "Password1234-", "example@example.com", "blah.so", null, out ignored));
            Assert.IsTrue(Password.CheckPassword("!@#$asdF6-", "!@#$asdF6-", "example@example.com", "blah.so", null, out ignored));
            Assert.IsTrue(Password.CheckPassword("Password1234", "Password1234", "blah@blah.com", "blah.so", null, out ignored));
            Assert.IsTrue(Password.CheckPassword("-password1234", "-password1234", "blah@blah.com", "blah.so", null, out ignored));
            Assert.IsTrue(Password.CheckPassword("-Password", "-Password", "blah@blah.com", "blah.so", null, out ignored));
        }

        [Test]
        public void InvalidPasswords()
        {
            string msg;
            Assert.IsFalse(Password.CheckPassword("password", "Password", "example@example.com", "blah.so", null, out msg));
            Assert.IsNotNull(msg);

            Assert.IsFalse(Password.CheckPassword("Password", "Password", "example@example.com", "blah.so", null, out msg));
            Assert.IsNotNull(msg);

            Assert.IsFalse(Password.CheckPassword("password", "password", "example@example.com", "blah.so", null, out msg));
            Assert.IsNotNull(msg);

            Assert.IsFalse(Password.CheckPassword("12345678", "12345678", "example@example.com", "blah.so", null, out msg));
            Assert.IsNotNull(msg);

            Assert.IsFalse(Password.CheckPassword("Pass1234", "Pass1234", "example@example.com", "blah.so", null, out msg));
            Assert.IsNotNull(msg);

            Assert.IsFalse(Password.CheckPassword("1234!@#$", "1234!@#$", "example@example.com", "blah.so", null, out msg));
            Assert.IsNotNull(msg);

            Assert.IsFalse(Password.CheckPassword("pP1-", "pP1-", "example@example.com", "blah.so", null, out msg));
            Assert.IsNotNull(msg);

            Assert.IsFalse(Password.CheckPassword("pass!@#$", "pass!@#$", "example@example.com", "blah.so", null, out msg));
            Assert.IsNotNull(msg);

            Assert.IsFalse(Password.CheckPassword("PASS!@#$", "PASS!@#$", "example@example.com", "blah.so", null, out msg));
            Assert.IsNotNull(msg);

            Assert.IsFalse(Password.CheckPassword("eMail1234@something.com", "eMail1234@something.com", "eMail1234@something.com", "blah.so", null, out msg));
            Assert.IsNotNull(msg);

            Assert.IsFalse(Password.CheckPassword("eMail1234@", "eMail1234@", "eMail1234@something.com", "blah.so", null, out msg));
            Assert.IsNotNull(msg);

            Assert.IsFalse(Password.CheckPassword("Indeed.1234", "Indeed.1234", "example@example.com", "so.Indeed.1234.go", null, out msg));
            Assert.IsNotNull(msg);

            var guid = Guid.NewGuid();
            Assert.IsFalse(Password.CheckPassword(guid.ToString(), guid.ToString(), "example@example.com", "hello", guid, out msg));
            Assert.IsNotNull(msg);
        }
    }
}
