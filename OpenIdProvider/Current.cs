using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using OpenIdProvider.Models;
using OpenIdProvider.Helpers;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Net.Sockets;
using System.Net;
using System.Web.Caching;
using System.IO;
using System.Globalization;
using System.Web.Configuration;
using System.Web.Mvc;
using System.Reflection;

namespace OpenIdProvider
{
    /// <summary>
    /// Convenience class for accessing information about the current request.
    /// </summary>
    public static class Current
    {
        private static string _readConnectionString;
        /// <summary>
        /// Connection string with read-only access to the DB
        /// </summary>
        private static string ReadConnectionString
        {
            get
            {
                if(_readConnectionString == null)
                    _readConnectionString = WebConfigurationManager.ConnectionStrings["ReadConnectionString"].ConnectionString;

                return _readConnectionString;
            }
        }

        private static string _writeConnectionString;
        /// <summary>
        /// Connection string that allows write access to the DB
        /// </summary>
        private static string WriteConnectionString
        {
            get
            {
                if (_writeConnectionString == null)
                    _writeConnectionString = WebConfigurationManager.ConnectionStrings["WriteConnectionString"].ConnectionString;

                return _writeConnectionString;
            }
        }

        /// <summary>
        /// Name of this site, as configured in web.config
        /// </summary>
        public static string SiteName
        {
            get
            {
                return WebConfigurationManager.AppSettings["SiteName"];
            }
        }

        /// <summary>
        /// Path to the key store file for this OpenIdProvider.
        /// </summary>
        public static string KeyStorePath
        {
            get
            {
                var k = WebConfigurationManager.AppSettings["KeyStore"];

                return k;
            }
        }

        /// <summary>
        /// Path to log errors to.
        /// </summary>
        public static string ErrorLogPath
        {
            get
            {
                string path = @"~\Error\";

                try
                {
                    path = WebConfigurationManager.AppSettings["ErrorPath"];
                }
                catch (Exception) { }

                if (!path.EndsWith("\\")) path += "\\";

                return HttpContext.Current.Server.MapPath(path);
            }
        }

        /// <summary>
        /// The IP of any SSL accelerator/load-balancer we're running behind.
        /// 
        /// If set (and not running as DEBUG) we can *only* accept HTTP requests
        /// from this IP.  Everything else must be over HTTPS.
        /// </summary>
        public static string LoadBalancerIP
        {
            get
            {
                return WebConfigurationManager.AppSettings["LoadBalancerIP"];
            }
        }

        /// <summary>
        /// The name of the cookie used to identify a logged in user.
        /// </summary>
        public static readonly string UserCookieName = "usr";

        /// <summary>
        /// The name of the cookie used to identify an anonymous user.
        /// 
        /// Useful for when we want to make sure a submitted token actually
        /// goes with a "user".
        /// </summary>
        public static readonly string AnonymousCookieName = "anon";

        /// <summary>
        /// This is salt is used for anything we want *hashed* but need to be able to lookup.
        /// 
        /// The salt only serves to make correlating data *between* databases more difficult, 
        /// it doesn't make rainbow table style pre-computation (provided the salt has been leaked) impossible.
        /// 
        /// As such the system wide salt should be treated as pseudo-secret.  Don't publish it, and routintely cycle it.
        /// </summary>
        private static string SiteWideSalt { get { return KeyStore.GetKey(KeyStore.LatestKeyVersion).Salt; } }

        /// <summary>
        /// In memory copy of the AES key for this instance.
        /// </summary>
        private static byte[] AesKey { get { return Convert.FromBase64String(KeyStore.GetKey(AesKeyVersion).Encryption); } }

        /// <summary>
        /// The "version" of the key.
        /// 
        /// In the event of a key leak, storing this alongside encrypted values
        /// will let us do piece-meal re-encryption.
        /// </summary>
        private static byte AesKeyVersion { get { return KeyStore.LatestKeyVersion; } }

        /// <summary>
        /// Provides encryption & decryption services for the entire instance.
        /// </summary>
        private static AesCryptoServiceProvider AesProvider;

        /// <summary>
        /// Instance wide source for all random numbers.
        /// 
        /// Only access through Random(), for locking purposes.
        /// </summary>
        private static RandomNumberGenerator RandomSource = RandomNumberGenerator.Create();

        private static HMAC HMACProvider;
        /// <summary>
        /// Provides message authentication codes for the entire instance.
        /// </summary>
        private static HMAC HMAC
        {
            get
            {
                if (HMACProvider != null) return HMACProvider;

                HMACProvider = new HMACSHA1();
                HMAC.Key = Convert.FromBase64String(KeyStore.GetKey(AesKeyVersion).HMAC);

                return HMACProvider;
            }
        }

        private static string CacheBreakerCached;
        /// <summary>
        /// Site wide cache breaker.
        /// 
        /// Guaranteed to cycle across builds (but not across AppPool cycles).
        /// 
        /// Stick it onto resources we need clients to re-load after each build, 
        /// so as to pickup changes.
        /// </summary>
        public static string CacheBreaker
        {
            get
            {
                if (CacheBreakerCached == null)
                {
                    // Whenever we build, the dll write time should change
                    var asm = Assembly.GetExecutingAssembly();
                    var dllLoc = asm.Location;

                    var dllLastModified = File.GetLastWriteTimeUtc(dllLoc);

                    var ms = dllLastModified.Ticks / 10000;
                    var secs = ms / 1000;
                    var mins = ms / 60;
                    var fiveMins = mins / 5;

                    CacheBreakerCached = Current.WeakHash(fiveMins.ToString());
                }

                return CacheBreakerCached;
            }
        }

        static Current()
        {
            AesProvider = new AesCryptoServiceProvider();
        }

        /// <summary>
        /// Right this instant.
        /// 
        /// This date it UTC (and all dates in the system should also be UTC).
        /// </summary>
        public static DateTime Now
        {
            get { return DateTime.UtcNow; }
        }

        /// <summary>
        /// Returns true if the current request should be rejected due to failing
        /// some integrity check.
        /// 
        /// This is handled in Current, as rejections at "lower levels" are often
        /// hard to direct to meaningful error pages.
        /// </summary>
        public static bool RejectRequest
        {
            get
            {
                var cached = GetFromContext<string>("RejectRequest");

                if (cached == null || bool.Parse(cached)) return true;

                return false;
            }
            set
            {
                SetInContext("RejectRequest", value.ToString());
            }
        }

        /// <summary>
        /// Returns whether the current request should result in a 
        /// page that tries to bust out of frames.
        /// 
        /// Defaults to true.
        /// </summary>
        public static bool ShouldBustFrames
        {
            get
            {
                var cached = GetFromContext<string>("ShouldBustFrames");

                if (cached == null || bool.Parse(cached)) return true;

                return false;
            }

            set
            {
                SetInContext("ShouldBustFrames", value.ToString());
            }
        }

        /// <summary>
        /// A read-only connection to the DB.
        /// 
        /// Should be used in all cases where update/inserts/deletes are not needed.
        /// </summary>
        public static DBContext ReadDB
        {
            get
            {
                var cached = GetFromContext<DBContext>("ReadDB");

                if (cached != null) return cached;

                cached = new DBContext(ReadConnectionString);

                SetInContext("ReadDB", cached);
                return cached;
            }
        }

        /// <summary>
        /// A read-write connection to the DB.
        /// 
        /// Should be touched by routes which themselves are the result of a 
        /// POST being received, or in response to internal "needs update" checks.
        /// </summary>
        public static DBContext WriteDB
        {
            get
            {
                var isPost = HttpContext.Current != null ? HttpContext.Current.Request.HttpMethod == "POST" : false;

                var cached = GetFromContext<DBContext>("WriteDB");

                if (cached == null)
                {
                    cached = new DBContext(WriteConnectionString);

                    SetInContext("WriteDB", cached);
                }

                // If this isn't in response to a POST, severly restrict what this connection can do
                cached.RestrictToCurrentUserAttributes = !isPost;

                return cached;
            }
        }

        /// <summary>
        /// The path this request is being served from.
        /// 
        /// http://example.com/ for instance
        /// </summary>
        public static Uri AppRootUri
        {
            get
            {
                string protocol;
#if DEBUG_HTTP
                protocol = "http://";
#else
                protocol = "https://";
#endif

                var ret = RequestUri.Host;
                ret = protocol + ret;

                if (!ret.EndsWith("/")) ret += "/";

                return new Uri(ret);
            }
        }

        /// <summary>
        /// The URL the current request was made to.
        /// </summary>
        public static Uri RequestUri
        {
            get
            {
                var url = HttpContext.Current.Request.Url.ToString();

                return new Uri(CorrectHttpAndPort(url));
            }
        }

        /// <summary>
        /// The currently logged in user (or null, if the user is annonymous).
        /// </summary>
        public static User LoggedInUser
        {
            get
            {
                var cached = GetFromContext<User>("LoggedInUser");

                if (cached != null) return cached;

                var cookie = HttpContext.Current.CookieSentOrReceived(UserCookieName);

                if (cookie == null || cookie.Value == null) return null;

                var hash = Current.WeakHash(cookie.Value);
                cached = Current.ReadDB.Users.SingleOrDefault(u => u.SessionHash == hash);
                
                SetInContext("LoggedInUser", cached);

                return cached;
            }

            set
            {
                if (value != null) throw new ArgumentException("Can only clear the LoggedInUser (forcing a new lookup), not set it directly.");

                SetInContext<User>("LoggedInUser", null);
            }
        }

        

        /// <summary>
        /// The IP address (v4 or v6) that the current request originated from.
        /// 
        /// This is not a valid source of user id or uniqueness, but should be logged
        /// with most modifying operations.
        /// </summary>
        public static string RemoteIP
        {
            get
            {
                var serverVars = HttpContext.Current.Request.ServerVariables;

                var headers = HttpContext.Current.Request.Headers;

                return GetRemoteIP(serverVars["REMOTE_ADDR"], headers["X-Forwarded-For"]);
            }
        }

        // Pulls out whatever "looks" like an IPv4 or v6 address that ends a string
        private static Regex LastAddress = new Regex(@"\b(\d|a-f|\.|:)+$", RegexOptions.Compiled);

        /// <summary>
        /// Takes in the REMOTE_ADDR and X-Forwarded-For headers and returns what
        /// we consider the current requests IP to be, for logging and throttling 
        /// purposes.
        /// 
        /// The logic is, basically, if xForwardedFor *has* a value and the apparent
        /// IP (the last one in the hop) is not local; use that.  Otherwise, use remoteAddr.
        /// </summary>
        public static string GetRemoteIP(string remoteAddr, string xForwardedFor)
        {
            // check if we were forwarded from a proxy
            if (xForwardedFor.HasValue())
            {
                xForwardedFor = LastAddress.Match(xForwardedFor).Value;
                if (xForwardedFor.HasValue() && !IsPrivateIP(xForwardedFor))
                    remoteAddr = xForwardedFor;
            }

            // Something weird is going on, bail
            if (!remoteAddr.HasValue()) throw new Exception("Cannot determine source of request");

            return remoteAddr;
        }

        /// <summary>
        /// Returns true if the current request is from an internal IP address.
        /// </summary>
        public static bool IsInternalRequest
        {
            get
            {
                return IsPrivateIP(RemoteIP);
            }
        }

        /// <summary>
        /// Returns the XSRF token expected on the current request (if any).
        /// 
        /// This value is dependent on the presense of either the user cookie, or 
        /// a temporary anonymous cookie (as in login).
        /// </summary>
        public static Guid? XSRFToken
        {
            get
            {
                var user = HttpContext.Current.CookieSentOrReceived(UserCookieName);

                string toHash;

                if (user != null && user.Value.HasValue())
                {
                    toHash = user.Value;
                }
                else
                {
                    var anon = HttpContext.Current.CookieSentOrReceived(AnonymousCookieName);

                    if (anon == null) return null;

                    toHash = anon.Value;
                }

                if (toHash == null) return null;

                var hash = Current.WeakHash(toHash);

                var retStr = Current.GetFromCache<string>("xsrf-" + hash);

                // If the user is logged in and *needs* an XSRF, we should just create one if there isn't already one
                if (retStr == null && user != null)
                    return GenerateXSRFToken();

                return Guid.Parse(retStr);
            }
        }

        /// <summary>
        /// Returns the current controller.
        /// 
        /// Useful for places where you need a Controller or ControllerContext.
        /// 
        /// Honestly, this is a tad hacky; since the only place we need those
        /// Controllers or ControllerContexts is when we're rendering a view
        /// to a string.
        /// 
        /// Would be nice if asp.net mvc supported that "out of the box".
        /// </summary>
        public static ControllerBase Controller
        {
            get
            {
                return GetFromContext<Controller>("Controller");
            }
            set
            {
                SetInContext("Controller", value);
            }
        }

        /// <summary>
        /// Destroys any existing tokens for the current user, and creates a new one.
        /// </summary>
        private static Guid GenerateXSRFToken()
        {
            if (LoggedInUser == null) throw new Exception("Cannot generated an XSRF token this way for an anonymous user.");

            var ret = UniqueId();

            var newToken =
                new
                {
                    CookieHash = LoggedInUser.SessionHash,
                    CreationDate = Current.Now,
                    Token = ret
                };

            Current.AddToCache("xsrf-" + newToken.CookieHash, ret.ToString(), TimeSpan.FromDays(1));

            return ret;
        }

        /// <summary>
        /// Create a new XSRF token, and attach a cookie to the user so we can look it up after a POST.
        /// </summary>
        public static void GenerateAnonymousXSRFCookie()
        {
            var random = UniqueId().ToString();

            Current.AddCookie(Current.AnonymousCookieName, random, TimeSpan.FromMinutes(15));

            var token = UniqueId();
            var cookieHash = Current.WeakHash(random);

            Current.AddToCache("xsrf-" + cookieHash, token.ToString(), TimeSpan.FromMinutes(15));

            // Can't allow for anon and usr to coexist, things get funky.
            if (HttpContext.Current.Request.Cookies.AllKeys.Contains(Current.UserCookieName))
            {
                Current.KillCookie(Current.UserCookieName);
            }
        }

        private static Regex _httpMatch = new Regex(@"^http://", RegexOptions.Compiled);
        private static Regex _portMatch = new Regex(@":\d+", RegexOptions.Compiled);
        /// <summary>
        /// Anything we expose needs to be sanitized of our port/ssl tricks.
        /// 
        /// Thus, all urls must start https:// and must *not* have :post-number on them.
        /// </summary>
        public static string CorrectHttpAndPort(string url)
        {
#if !DEBUG_HTTP
            url = _httpMatch.Replace(url, "https://");
            url = _portMatch.Replace(url, "");
#endif

            return url;
        }

        /// <summary>
        /// Takes in url fragment, and rebases it as under the domain of the current request.
        /// 
        /// ie. Url("hello-world?testing") on the http://example.com/ domain becomes
        /// http://example.com/hello-world?testing
        /// </summary>
        public static string Url(string fragment)
        {
            return new Uri(AppRootUri, fragment).AbsoluteUri;
        }

        /// <summary>
        /// Adds a "kill cookie" to the response to the current request.
        /// 
        /// Causes (well, asks nicely) the client to discard any cookie they have with the given name.
        /// 
        /// Does nothing if the cookie can't be found in the request.
        /// </summary>
        public static void KillCookie(string cookieName)
        {
            if (!HttpContext.Current.Request.Cookies.AllKeys.Contains(cookieName)) return;

            var killCookie = new HttpCookie(cookieName);
            killCookie.Expires = Current.Now.AddMinutes(-15);
            killCookie.HttpOnly = true;
            killCookie.Secure = true;

            HttpContext.Current.Response.Cookies.Add(killCookie);
        }

        /// <summary>
        /// Adds (or updates) a cookie to the response to the current request.
        /// 
        /// Should always be used in favor 
        /// </summary>
        public static void AddCookie(string cookieName, string value, TimeSpan expiresIn)
        {
            var cookie = new HttpCookie(cookieName);
            cookie.Value = value;
            cookie.Expires = Current.Now + expiresIn;
            cookie.HttpOnly = true;

#if !DEBUG_HTTP
            cookie.Secure = true;
#endif

            HttpContext.Current.Response.Cookies.Add(cookie);

            // http://stackoverflow.com/questions/389456/cookie-blocked-not-saved-in-iframe-in-internet-explorer
            //   Basically, this tells IE that we're not doing anything nefarious (just tracking for tailoring and dev purposes)
            //   ... no other browser even pretends to care.
            HttpContext.Current.Response.Headers["p3p"] = @"CP=""NOI CURa ADMa DEVa TAIa OUR BUS IND UNI COM NAV INT""";
        }

        /// <summary>
        /// Insert something into the (machine local) cache.
        /// </summary>
        public static void AddToCache<T>(string name, T o, TimeSpan expiresIn) where T : class
        {
            // No point trying to cache null values
            if(o != null)
                HttpRuntime.Cache.Insert(name, o, null, Current.Now + expiresIn, Cache.NoSlidingExpiration);
        }

        /// <summary>
        /// Get something from the (machine local) cache.
        /// </summary>
        public static T GetFromCache<T>(string name) where T : class
        {
            return HttpRuntime.Cache[name] as T;
        }

        /// <summary>
        /// Invalidate a key in teh (machine local) cache.
        /// </summary>
        public static void RemoveFromCache(string name)
        {
            HttpRuntime.Cache.Remove(name);
        }

        /// <summary>
        /// Get something from the per-request cache.
        /// 
        /// Returns null if not found.
        /// </summary>
        private static T GetFromContext<T>(string name) where T : class
        {
            return HttpContext.Current.Items[name] as T;
        }

        /// <summary>
        /// Place something in the per-request cache.
        /// 
        /// Once this HttpRequest is complete, it will be lost.
        /// 
        /// Reference types only.
        /// </summary>
        private static void SetInContext<T>(string name, T value) where T : class
        {
            HttpContext.Current.Items[name] = value;
        }

        /// <summary>
        /// Returns true if this is a private network IP (v4 or v6)
        /// http://en.wikipedia.org/wiki/Private_network
        /// </summary>
        internal static bool IsPrivateIP(string s)
        {
            var ipv4Check = (s.StartsWith("192.168.") || s.StartsWith("10.") || s.StartsWith("127.0.0."));

            if (ipv4Check) return true;

            IPAddress addr;
            
            if(!IPAddress.TryParse(s, out addr) || addr.AddressFamily != AddressFamily.InterNetworkV6) return false;

            // IPv6 reserves fc00::/7 for local usage
            // http://en.wikipedia.org/wiki/Unique_local_address
            var address = addr.GetAddressBytes();
            return address[0] == (byte)0xFD;    //FC + the L-bit set to make FD
        }

        /// <summary>
        /// Generate a *truly* random (that is, version 4) GUID.
        /// 
        /// Guids that are never exposed externally can be safely obtained from Guid.NewGuid(), 
        /// but when in doubt use this function.
        /// 
        /// Nice overview of normal GUID generation: http://blogs.msdn.com/b/oldnewthing/archive/2008/06/27/8659071.aspx
        /// 
        /// Version 4 is described here: http://en.wikipedia.org/wiki/Universally_unique_identifier
        /// </summary>
        public static Guid UniqueId()
        {
            var bytes = Random(16);
            bytes[7] = (byte)((bytes[7] & 0x0F) | 0x40);  // Set the GUID version to 4
            bytes[8] = (byte)((bytes[8] & 0x0F) | (0x80 + (Random(1)[0] % 4))); // tweaking 8th byte as required
            
            return new Guid(bytes);
        }

        /// <summary>
        /// Return a base64 encoded version of an HMAC for
        /// the give byte array.
        /// 
        /// Note that this uses the *current* key version,
        /// generally this is correct but may require some...
        /// finese in others.
        /// </summary>
        private static string MakeAuthCode(byte[] toSign, HMAC hmac = null)
        {
            if (hmac == null) hmac = HMAC;

            lock (hmac)
                return Convert.ToBase64String(hmac.ComputeHash(toSign));
        }

        /// <summary>
        /// Imposes a canonical ordering on a key=>value pair set, 
        /// and then HMACs it.  Returns a base64 encoded version of the
        /// result.
        /// 
        /// The actual key=>value pairs are the properties on an object,
        /// expected usage is
        /// MakeAuthCode(new { blah, moreBlah, andSoOn });
        /// </summary>
        public static string MakeAuthCode(object toSign, HMAC hmac = null)
        {
            var props = toSign.PropertiesAsStrings();

            string signString = "";

            foreach (var prop in props.OrderBy(p => p.Key))
            {
                signString = prop.Key + "=" + prop.Value + "&";
            }

            signString = signString.Substring(0, signString.Length - 1);

            return MakeAuthCode(Encoding.UTF8.GetBytes(signString), hmac);
        }

        /// <summary>
        /// Encrypts a value using the system wide key.
        /// 
        /// Returns the key *version*, which should be stored with
        /// any encrypted value in the event that the key is leaked 
        /// and all values need to be re-encrypted.
        /// 
        /// The result is base64 encoded.
        /// </summary>
        public static string Encrypt(string value, out string iv, out byte version, out string hmac)
        {
            version = AesKeyVersion;
            var ivBytes = Random(16);
            iv = Convert.ToBase64String(ivBytes);

            ICryptoTransform encryptor;

            lock (AesProvider)
                encryptor = AesProvider.CreateEncryptor(AesKey, ivBytes);

            byte[] output;

            using (encryptor)
            {
                var input = Encoding.UTF8.GetBytes(value);
                output = encryptor.TransformFinalBlock(input, 0, input.Length);
            }

            hmac = MakeAuthCode(output);

            return Convert.ToBase64String(output);
        }

        /// <summary>
        /// Decrypts a value using the system wide key.
        /// 
        /// Expects encrypted to be encoded in base64.
        /// 
        /// If the byte version doesn't match the current key version,
        /// outOfDate will be set and the value should be re-encrypted and stored
        /// before completing any other operation.
        /// </summary>
        public static string Decrypt(string encrypted, string iv, byte version, string hmac, out bool outOfDate)
        {
            outOfDate = false;

            var encryptedBytes = Convert.FromBase64String(encrypted);
            var ivBytes = Convert.FromBase64String(iv);

            // Value encrypted using an old key encountered
            if (version != AesKeyVersion)
            {
                var oldKey = KeyStore.GetKey(version);

                // Different crypto keys means different hmac keys, gotta spin up an old one
                var oldHmac = new HMACSHA1();
                oldHmac.Key = Convert.FromBase64String(oldKey.HMAC);

                if (hmac != Convert.ToBase64String(oldHmac.ComputeHash(Convert.FromBase64String(encrypted))))
                    throw new Exception("HMAC validation failed on encrypted value (key version = " + oldKey.Version + ")");

                ICryptoTransform oldDecryptor;

                lock (AesProvider)
                    oldDecryptor = AesProvider.CreateDecryptor(Convert.FromBase64String(oldKey.Encryption), ivBytes);
                

                var retBytes = oldDecryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);

                outOfDate = true;
                return Encoding.UTF8.GetString(retBytes);
            }

            var shouldMatchHMAC = MakeAuthCode(Convert.FromBase64String(encrypted));

            if (hmac != shouldMatchHMAC)
                throw new Exception("HMAC validation failed on encrypted value");

            ICryptoTransform decryptor;
            lock (AesProvider)
                decryptor = AesProvider.CreateDecryptor(AesKey, ivBytes);

            var ret = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);

            return Encoding.UTF8.GetString(ret);
        }

        /// <summary>
        /// Cranks out a collision resistant hash, relatively quickly.
        /// 
        /// Not suitable for passwords, or sensitive information.
        /// </summary>
        public static string WeakHash(string value)
        {
            var hasher = SHA1.Create();

            byte[] bytes = value.HasValue() ? Encoding.UTF8.GetBytes(value) : new byte[0];

            return Convert.ToBase64String(hasher.ComputeHash(bytes));
        }

        /// <summary>
        /// Cranks out a hash suitable for a lookup.
        /// 
        /// In cases where arbitrary lookup is not required, but 
        /// potentially valuable information is involved,
        /// use SecureHash instead.
        /// 
        /// In cases where the hash is ephemeral (quickly expiring, or
        /// not of valuable information), use WeakHash.
        /// </summary>
        public static string SystemHash(string value, out byte saltVersion)
        {
            var salt = SiteWideSalt;
            saltVersion = KeyStore.LatestKeyVersion;

            return SecureHash(value, salt);
        }

        /// <summary>
        /// Cranks out a secure hash, generating a new salt.
        /// </summary>
        public static string SecureHash(string value, out string salt)
        {
            salt = BCrypt.GenerateSalt();

            var saltAndHash = BCrypt.HashPassword(value, salt);

            return saltAndHash.Substring(salt.Length);
        }

        /// <summary>
        /// Cranks out a secure hash with a specific salt
        /// </summary>
        public static string SecureHash(string value, string salt)
        {
            var saltAndHash = BCrypt.HashPassword(value, salt);

            return saltAndHash.Substring(salt.Length);
        }

        /// <summary>
        /// Universal random provider.
        /// 
        /// Just for paranoia's sake, use it for all random purposes.
        /// </summary>
        public static byte[] Random(int bytes)
        {
            var ret = new byte[bytes];

            lock (RandomSource)
                RandomSource.GetBytes(ret);

            return ret;
        }

        /// <summary>
        /// Log an exception to disk.
        /// </summary>
        public static void LogException(Exception e)
        {
            (new Error(e)).Log(ErrorLogPath);
        }
    }
}