using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using NUnit.Framework;
using System.Security.Cryptography;

namespace OpenIdProvider.Tests
{
    /// <summary>
    /// Summary description for AuthCodeTests
    /// </summary>
    [TestFixture]
    public class AuthCodeTests
    {
        [Test]
        public void IdenticalMatches()
        {
            var obj = new { a = "a", b = "b", c = true, d = false, e = 1, f = 2};

            var hmac = new HMACSHA1();
            hmac.Key = Current.Random(64);

            var code = Current.MakeAuthCode(obj, hmac);

            Assert.AreEqual(code, Current.MakeAuthCode(obj, hmac));
        }

        [Test]
        public void DiffValueFailure()
        {
            var obj1 = new { a = "a", b = "b", c = true, d = false, e = 1, f = 2 };
            var obj2 = new { a = "a", b = "b", c = true, d = false, e = 1, f = 3 };

            var hmac = new HMACSHA1();
            hmac.Key = Current.Random(64);

            Assert.AreNotEqual(Current.MakeAuthCode(obj1, hmac), Current.MakeAuthCode(obj2, hmac));
        }

        [Test]
        public void OmittedFieldFailure()
        {
            var obj1 = new { a = "a", b = "b", c = true, d = false, e = 1, f = 2 };
            var obj2 = new { a = "a", b = "b", c = true, d = false, e = 1 };

            var hmac = new HMACSHA1();
            hmac.Key = Current.Random(64);

            Assert.AreNotEqual(Current.MakeAuthCode(obj1, hmac), Current.MakeAuthCode(obj2, hmac));
        }
    }
}
