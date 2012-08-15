using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using NUnit.Framework;
using OpenIdProvider.Helpers;
using OpenIdProvider.Models;

namespace OpenIdProvider.Tests
{
    [TestFixture]
    public class SanitizeTests
    {
        [Test]
        public void ValidEmails()
        {
            string email = "kevin@somewhere.com";
            Assert.IsTrue(Models.User.IsValidEmail(ref email));

            string email2 = "     kevin@somewhere.com";
            Assert.IsTrue(Models.User.IsValidEmail(ref email2));

            string bad1 = "kevin+somewhere.com";
            Assert.IsFalse(Models.User.IsValidEmail(ref bad1));

            string bad2 = "kevin@somewhere";
            Assert.IsFalse(Models.User.IsValidEmail(ref bad2));
        }

        [Test]
        public void VanityIds()
        {
            string ignored;
            Assert.IsTrue(User.IsValidVanityId("kevin.montrose", out ignored));
            Assert.IsTrue(User.IsValidVanityId("kevinmontrose", out ignored));
            Assert.IsTrue(User.IsValidVanityId("kevin-montrose1", out ignored));

            Assert.IsFalse(User.IsValidVanityId("_", out ignored));
            Assert.IsFalse(User.IsValidVanityId("+", out ignored));
            Assert.IsFalse(User.IsValidVanityId("bcddfkljasdfjiojasdfiojiojasdfjiojiojasdfjiojiojiojiojiojiojioasdfjiojiojasdfij", out ignored));
        }

        [Test]
        public void Css()
        {
            var good = "#0000";
            var bad = ";do something";
            var bad2 = "#0000; font: arial";
            var bad3 = "#0000, -23px";
            var urlGood = "url('http://example.com')";
            var urlBad = "http://example.com";
            var urlWithPort = "url('http://example.com:90')";
            var urlGoodNoQuotes = "url(http://example.com)";

            Assert.AreEqual(good, ExtensionMethods.SanitizeCss(good));
            Assert.AreEqual(urlGood, ExtensionMethods.SanitizeCss(urlGood));
            Assert.AreEqual(urlWithPort, ExtensionMethods.SanitizeCss(urlWithPort));
            Assert.AreEqual(urlGoodNoQuotes, ExtensionMethods.SanitizeCss(urlGoodNoQuotes));

            Assert.AreNotEqual(bad, ExtensionMethods.SanitizeCss(bad));
            Assert.AreNotEqual(bad2, ExtensionMethods.SanitizeCss(bad2));
            Assert.AreNotEqual(bad3, ExtensionMethods.SanitizeCss(bad3));
            Assert.AreNotEqual(urlBad, ExtensionMethods.SanitizeCss(urlBad));
        }

        // For lack of a better place to put this
        [Test]
        public void GuidGeneration()
        {
            var validYs = new char[]{'8','9','A','B'};

            for (int i = 0; i < 100000; i++)
            {
                var randGuid = Current.UniqueId();
                
                // "Version 4 UUIDs have the form xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx where x is any hexadecimal digit and y is one of 8, 9, A, or B."
                // From: http://en.wikipedia.org/wiki/Universally_unique_identifier
                var asString = randGuid.ToString();

                var x = asString[14];
                var y = asString[19];

                Assert.AreEqual('4', x);
                Assert.IsTrue(validYs.Any(v => v == y));
            }
        }

        [Test]
        public void RemoteIP()
        {
            Assert.AreEqual("127.0.0.1", Current.GetRemoteIP("", "127.0.0.1", "127.0.0.1"));
            Assert.AreEqual("64.34.128.1", Current.GetRemoteIP("", "64.34.128.1", "127.0.0.1"));
            Assert.AreEqual("12.34.56.78", Current.GetRemoteIP("", "64.34.128.1", "12.34.56.78"));
            Assert.AreEqual("64.34.128.1", Current.GetRemoteIP("", "64.34.128.1", "10.10.10.1"));
            Assert.AreEqual("66.90.104.167", Current.GetRemoteIP("", "64.34.119.10", "66.90.104.167"));
        }
    }
}
