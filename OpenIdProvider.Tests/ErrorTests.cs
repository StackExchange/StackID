using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using NUnit.Framework;
using OpenIdProvider.Helpers;
using System.IO;

namespace OpenIdProvider.Tests
{
    /*[TestFixture]
    public class ErrorTests
    {
        private static string CreateTempDir()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
            Directory.CreateDirectory(tempDir);

            return tempDir;
        }

        private static void DestroyTempDir(string tempDir)
        {
            if (tempDir.HasValue())
            {
                try
                {
                    foreach (var f in Directory.EnumerateFiles(tempDir))
                        File.Delete(f);

                    Directory.Delete(tempDir);
                }
                catch (Exception e) { }
            }
        }

        [Test]
        public void Log()
        {
            string tempDir = CreateTempDir();

            try
            {
                for (int i = 0; i < 100; i++)
                {
                    var error = new Error(new Exception(i.ToString()));
                    error.Log(tempDir);
                }

                Assert.AreEqual(100, Directory.EnumerateFiles(tempDir).Count());

                var errors = Error.LoadErrors(tempDir, 100, 0);

                Assert.AreEqual(100, errors.Count());

                for (var i = 0; i < 100; i++)
                {
                    Assert.IsTrue(errors.SingleOrDefault(e => e.Message == i.ToString()) != null);
                }
            }
            finally
            {
                DestroyTempDir(tempDir);
            }
        }

        [Test]
        public void Cull()
        {
            string tempDir = CreateTempDir();

            try
            {
                for (int i = 0; i < 1000; i++)
                {
                    var error = new Error(new Exception(i.ToString()));
                    error.Log(tempDir);
                }

                Assert.AreEqual(200, Directory.EnumerateFiles(tempDir).Count());

                var errors = Error.LoadErrors(tempDir, 200, 0);

                Assert.AreEqual(200, errors.Count());

                for (var i = 800; i < 1000; i++)
                {
                    Assert.IsTrue(errors.SingleOrDefault(e => e.Message == i.ToString()) != null);
                }
            }
            finally
            {
                DestroyTempDir(tempDir);
            }
        }
    }*/
}
