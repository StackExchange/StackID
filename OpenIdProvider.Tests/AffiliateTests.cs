using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using NUnit.Framework;
using OpenIdProvider.Models;
using OpenIdProvider.Helpers;

namespace OpenIdProvider.Tests
{
    /// <summary>
    /// Summary description for AuthCodeTests
    /// </summary>
    [TestFixture]
    public class AffiliateTests
    {
        [Test]
        public void AcceptableNonceDrift()
        {
            var offsetFromNow = TimeSpan.FromSeconds(-60 * 5).Add(TimeSpan.FromSeconds(1));
            var max = TimeSpan.FromMinutes(5);

            while (offsetFromNow < max)
            {
                string ignored;
                for (int i = 0; i < 1000; i++)
                {
                    var now = DateTime.UtcNow;

                    var nonce = Nonces.Create(now + offsetFromNow);

                    if (!Nonces.IsValid(nonce, "127.0.0.1", out ignored, now))
                    {
                        DateTime created;
                        Nonces.Parse(nonce, out created);
                        Assert.Fail("Failed on [" + nonce + "] on [" + created + "] diff of [" + (created - now) + "]");
                    }
                }

                offsetFromNow = offsetFromNow.Add(TimeSpan.FromSeconds(1));
            }
        }

        [Test]
        public void ValidNonces()
        {
            string ignored;
            for (int i = 0; i < 1000000; i++)
            {
                var nonce = Nonces.Create();
                Assert.IsTrue(Nonces.IsValid(nonce, "127.0.0.1", out ignored), "Failed on " + nonce);
            }
        }

        [Test]
        public void DoubleNonceUseFails()
        {
            string ignored;
            for (int i = 0; i < 1000000; i++)
            {
                var nonce = Nonces.Create();
                Assert.IsTrue(Nonces.IsValid(nonce, "127.0.0.1", out ignored), "Failed on " + nonce);
                Nonces.MarkUsed(nonce, "127.0.0.1");
                Assert.IsFalse(Nonces.IsValid(nonce, "127.0.0.2", out ignored), "Accepted twice " + nonce);
            }
        }

        [Test]
        public void ValidFilters()
        {
            Assert.IsTrue(Affiliate.IsValidFilter("stackoverflow.com"));
            Assert.IsTrue(Affiliate.IsValidFilter("meta.stackoverflow.com"));
            Assert.IsTrue(Affiliate.IsValidFilter("*.stackoverflow.com"));
            Assert.IsTrue(Affiliate.IsValidFilter("meta.*.stackexchange.com"));
        }

        [Test]
        public void InvalidFilters()
        {
            Assert.IsFalse(Affiliate.IsValidFilter("stackoverflow.*.com"));
            Assert.IsFalse(Affiliate.IsValidFilter("*"));
            Assert.IsFalse(Affiliate.IsValidFilter(".stackoverflow.com"));
            Assert.IsFalse(Affiliate.IsValidFilter("hello world"));
            Assert.IsFalse(Affiliate.IsValidFilter("stackoverflow.*"));
        }

        [Test]
        public void ValidCallback()
        {
            var affiliate = new Affiliate { HostFilter = "dev.stackoverflow.com" };
            Assert.IsTrue(affiliate.IsValidCallback("http://dev.stackoverflow.com/blah-blah-blah"));
            Assert.IsTrue(affiliate.IsValidCallback("http://dev.stackoverflow.com/blah-blah-blah/more-blah"));
            Assert.IsTrue(affiliate.IsValidCallback("http://dev.stackoverflow.com/blah-blah-blah/more-blah?param=yesyes"));
            Assert.IsTrue(affiliate.IsValidCallback("http://dev.stackoverflow.com/blah-blah-blah/more-blah?param=yesyes&indeed=nono"));

            affiliate = new Affiliate { HostFilter = "dev.*.stackexchange.com" };
            Assert.IsTrue(affiliate.IsValidCallback("http://dev.webapps.stackexchange.com/blah-blah-blah"));
            Assert.IsTrue(affiliate.IsValidCallback("http://dev.webapps.stackexchange.com/blah-blah-blah/more-blah"));
            Assert.IsTrue(affiliate.IsValidCallback("http://dev.webapps.stackexchange.com/blah-blah-blah/more-blah?param=yesyes"));
            Assert.IsTrue(affiliate.IsValidCallback("http://dev.webapps.stackexchange.com/blah-blah-blah/more-blah?param=yesyes&indeed=nono"));
        }

        [Test]
        public void InvalidCallback()
        {
            var affiliate = new Affiliate { HostFilter = "dev.stackoverflow.com" };
            Assert.IsFalse(affiliate.IsValidCallback("http://dev.stackexchange.com/blah-blah-blah"));
            Assert.IsFalse(affiliate.IsValidCallback("http://dev.superuser.com/blah-blah-blah/more-blah"));
            Assert.IsFalse(affiliate.IsValidCallback("http://dev.etc.com/blah-blah-blah/more-blah?param=yesyes"));
            Assert.IsFalse(affiliate.IsValidCallback("http://example.com?indeed=http://dev.stackoverflow.com/"));

            affiliate = new Affiliate { HostFilter = "dev.*.stackexchange.com" };
            Assert.IsFalse(affiliate.IsValidCallback("http://other.stackexchange.com/blah-blah-blah"));
            Assert.IsFalse(affiliate.IsValidCallback("http://stackexchange.com/blah-blah-blah/more-blah"));
            Assert.IsFalse(affiliate.IsValidCallback("http://dev.stackexchange.com/blah-blah-blah/more-blah?param=yesyes"));
            Assert.IsFalse(affiliate.IsValidCallback("http://dev.stackoverflow.com/"));

            affiliate = new Affiliate { HostFilter = "*.stackexchange.com" };
            Assert.IsFalse(affiliate.IsValidCallback("http://one.two.stackexchange.com/"));
        }
    }
}
