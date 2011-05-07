using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using System.Diagnostics;
using System.Security.Cryptography;
using OpenIdProvider.Models;
using NUnit.Framework;

namespace OpenIdProvider.Tests
{
    [TestFixture]
    public class LoadTests
    {
        [Test]
        public void AuthCode()
        {
            var toAuth = new { a = "xyz", b = "1234567890", c = Convert.ToBase64String(Current.Random(16)), d = false };

            var y = new StringBuilder(4096);

            var hmac = new HMACSHA1();
            hmac.Key = Current.Random(64);

            var clock = new Stopwatch();
            clock.Start();

            for (int i = 0; i < 100000; i++)
            {
                var x = Current.MakeAuthCode(toAuth, hmac);
                y.Append(x); // Make sure no weird optimizations happen
            }

            clock.Stop();

            Assert.IsNotNull(y.ToString());

            Console.WriteLine(clock.Elapsed);

            Assert.IsTrue(clock.Elapsed < TimeSpan.FromSeconds(5), "100k in 5s");
        }

        [Test]
        public void VerifySignature()
        {
            var toSign = new Dictionary<string, string> { { "a", "xyz" }, { "b", "1234567890" }, { "c", Convert.ToBase64String(Current.Random(16)) }, { "d", "false" } };
            var sig = GetSignature("/some/dummy/path", toSign);

            var fakeAffiliate = new Affiliate { VerificationModulus = "zB3eUr66GkFESizQCnjrm1jCbhHW/vy2UoCHAMIlsOweMOnbU2y8IohlRBEBaS80CqAPlRNfjtRjzdZU3F+J/lUZqipH5sZjXyE6/rPXbvp3tlRSF0pgcQDlFYmAQWKbPKwt2PCg8/Od+wI7cBnHEfveRTjzMzfeFUzoWPiYEo0=" };
            
            var clock = new Stopwatch();
            clock.Start();

            for (int i = 0; i < 100000; i++)
            {
                Assert.IsTrue(fakeAffiliate.ConfirmSignature(sig, "/some/dummy/path", toSign), "Signature didn't pass and should have");
            }

            clock.Stop();

            Assert.IsTrue(clock.Elapsed < TimeSpan.FromSeconds(120), "100k in 30s [" + clock.Elapsed + "]");
        }

        [Test]
        public void RejectSignature()
        {
            var toSign = new Dictionary<string, string> { { "a", "xyz" }, { "b", "1234567890" }, { "c", Convert.ToBase64String(Current.Random(16)) }, { "d", "false" } };
            var sig = GetSignature("/some/dummy/path", toSign);

            var fakeAffiliate = new Affiliate { VerificationModulus = "zB3eUr66GkFESizQCnjrm1jCbhHW/vy2UoCHAMIlsOweMOnbU2y8IohlRBEBaS80CqAPlRNfjtRjzdZU3F+J/lUZqipH5sZjXyE6/rPXbvp3tlRSF0pgcQDlFYmAQWKbPKwt2PCg8/Od+wI7cBnHEfveRTjzMzfeFUzoWPiYEo0=" };

            var clock = new Stopwatch();
            clock.Start();

            toSign.Remove("b");

            for (int i = 0; i < 100000; i++)
            {
                Assert.IsFalse(fakeAffiliate.ConfirmSignature(sig, "/some/dummy/path", toSign), "Affiliate signature check passed and should not have");
            }

            clock.Stop();

            Assert.IsTrue(clock.Elapsed < TimeSpan.FromSeconds(120), "100k in 30s [" + clock.Elapsed + "]");
        }

        private static string GetSignature(string path, Dictionary<string, string> dict)
        {
            Dictionary<string, string> key = new Dictionary<string, string>()
            {
                {"D","xVLqpptzVgZaekqwJC+ZtWgtLjNY4NB1gXR3Dqihv1PELA0n1pJ7nfa1zwORlZnoeY0bA0bjTjTM9ySIjTJfNx90WFY2znIQ18zcbNR2LUjqjj4njcJ6eIoAgP4IM6WYPG7I9DcBVxEnGGnKg23BsgggS40yd68PH+f8u2huioE="},
                {"DP","LKzx39yRLLKJBnZqErYFk2PHhc17fpWwQbJ3XbX42IpjeONhEp3/NkoHw4E5P+gPNYDZxZ4hZqt6p1knTQe2CQ=="},
                {"DQ","Yb9zCNF0DjuvWaPbXer9rtCH/swYDV+qAV4booj2gK+xJXBmcgE2UoMeTA5C9rzU3STpgF7ex4ETz3e0MvHmOQ=="},
                {"InverseQ","JblfMJNugK729H/HIurrEjYX20EVsmpBNQxMG16aIg9B31lIezJ/W0YfVfbfmu3eQiWfqCfzbN8/z7+CdUMoyQ=="},
                {"Modulus","zB3eUr66GkFESizQCnjrm1jCbhHW/vy2UoCHAMIlsOweMOnbU2y8IohlRBEBaS80CqAPlRNfjtRjzdZU3F+J/lUZqipH5sZjXyE6/rPXbvp3tlRSF0pgcQDlFYmAQWKbPKwt2PCg8/Od+wI7cBnHEfveRTjzMzfeFUzoWPiYEo0="},
                {"P","/xDlAsDA5HN4sjjKs7VXNVp0DFU4lKTqsDLfEIK+jmah2U2s8uNiHHCfzYf9WVjaJPo1LW0ZjZzJlIvvRyRxOQ=="},
                {"Q","zN02cbOkG/a+3FDLkfTc3F97CqCMoLhcWugehoedLtRx76wAvXi5gn4MzB3sOp2TVCh22Xnk1uKJ1jX24qBv9Q=="}
            };

            var toSign = path + "?";

            foreach (var d in dict.OrderBy(s => s.Key))
            {
                toSign += d.Key + "=" + d.Value + "&";
            }

            toSign = toSign.Trim('&');

            var rsa = new RSACryptoServiceProvider();
            var k = new RSAParameters();
            k.D = Convert.FromBase64String(key["D"]);
            k.DP = Convert.FromBase64String(key["DP"]);
            k.DQ = Convert.FromBase64String(key["DQ"]);
            k.Exponent = new byte[] { 0x1, 0x00, 0x1 };
            k.InverseQ = Convert.FromBase64String(key["InverseQ"]);
            k.Modulus = Convert.FromBase64String(key["Modulus"]);
            k.P = Convert.FromBase64String(key["P"]);
            k.Q = Convert.FromBase64String(key["Q"]);

            rsa.ImportParameters(k);

            var sig = rsa.SignData(Encoding.UTF8.GetBytes(toSign), new SHA1CryptoServiceProvider());

            return Convert.ToBase64String(sig);
        }
    }
}
