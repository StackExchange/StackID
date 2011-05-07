using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using NUnit.Framework;
using OpenIdProvider.Models;

namespace OpenIdProvider.Tests
{
    /// <summary>
    /// Summary description for AuthCodeTests
    /// </summary>
    [TestFixture]
    public class AffiliateTests
    {
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
