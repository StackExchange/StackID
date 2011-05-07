using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.IO;

namespace OpenIdProvider.Helpers
{
    /// <summary>
    /// Manage access to keys.
    /// 
    /// Just a dumb JSON wrapper 
    /// </summary>
    public static class KeyStore
    {
        public class Key
        {
            public byte Version { get; internal set; }
            public string Encryption { get; internal set; }
            public string Salt { get; internal set; }
            public string HMAC { get; internal set; }
        }

        private static Dictionary<byte, Key> KeyCache = new Dictionary<byte, Key>();

        /// <summary>
        /// The current key version we're using.
        /// </summary>
        public static byte LatestKeyVersion { get { return KeyCache.Keys.Max(); } }

        /// <summary>
        /// All the salts for older keys.
        /// 
        /// Useful for detecting that a record needs an update.
        /// </summary>
        public static IEnumerable<Tuple<byte, string>> OldSalts { get { return KeyCache.Where(k => k.Key != LatestKeyVersion).Select(k => new Tuple<byte, string>(k.Key, k.Value.Salt)).ToList(); } }

        static KeyStore()
        {
            try
            {
                var json = File.ReadAllText(Current.KeyStorePath);

                foreach (var key in Newtonsoft.Json.JsonConvert.DeserializeObject<Key[]>(json))
                {
                    KeyCache[key.Version] = key;
                }
            }
            catch (Exception e)
            {
                Current.LogException(e);
                throw;
            }
        }

        /// <summary>
        /// Get the key that corresponds to the given version.
        /// 
        /// While it will *generally* be the case that all versions less than LatestKeyVersion exist,
        /// don't rely on it.  `version` should come from a datastore, not a code inference.
        /// </summary>
        public static Key GetKey(byte version) { return KeyCache[version]; }
    }
}