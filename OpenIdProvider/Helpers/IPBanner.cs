using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Collections.Concurrent;
using OpenIdProvider.Models;
using System.Data.SqlTypes;
using ProtoBuf;

namespace OpenIdProvider.Helpers
{
    /// <summary>
    /// Helper for tracking infractions and IP bans that result from them.
    /// </summary>
    public static class IPBanner
    {
        // Distinct from LINQ class to avoid capturing a data context (also, don't need Id or Reason)
        class BanPeriod
        {
            public DateTime CreationDate;
            public DateTime ExpirationDate;
        }

        [ProtoContract]
        public class Infraction
        {
            public enum InfractionType { Login, XSRF, Recovery }

            [ProtoMember(1)]
            public InfractionType Type;
            [ProtoMember(2)]
            public int? RelatedId;
            [ProtoMember(3)]
            public DateTime Expires;
        }

        private static object UpdateLock = new object();
        private static ConcurrentDictionary<string, BanPeriod> BannedIPCache = new ConcurrentDictionary<string, BanPeriod>();
        private static DateTime NextRefresh { get; set; }

        static IPBanner() { NextRefresh = DateTime.MinValue; }

        /// <summary>
        /// Call to periodically slurp down new bans and the like.
        /// 
        /// We want this stuff in the DB for persistence (so an App cycle doesn't lift bans),
        /// but we don't want an extra DB hit on every page either.
        /// 
        /// Thus, we maintain a copy of the "important" parts of the IPBans table in memory.
        /// </summary>
        private static void TryRefreshCache()
        {
            if (Current.Now < NextRefresh) return;

            lock (UpdateLock)
            {
                if (Current.Now < NextRefresh) return;

                var now = Current.Now;

                var getNewBansFrom = BannedIPCache.Count == 0 ? SqlDateTime.MinValue.Value : BannedIPCache.Max(i => i.Value.CreationDate);

                var newBans = Current.ReadDB.IPBans.Where(b => b.CreationDate > getNewBansFrom);

                foreach(var b in newBans){
                    var period = new BanPeriod{ CreationDate = b.CreationDate, ExpirationDate = b.ExpirationDate};
                    BannedIPCache.AddOrUpdate(b.IP, period, (string key, BanPeriod old) => period);
                }

                var expiredBans = BannedIPCache.Where(i => i.Value.ExpirationDate < now).Select(i => i.Key);

                BanPeriod ignored;
                foreach (var expired in expiredBans) BannedIPCache.TryRemove(expired, out ignored);

                NextRefresh = Current.Now + TimeSpan.FromMinutes(5);
            }
        }

        /// <summary>
        /// Return true if the given IP is banned.
        /// </summary>
        public static bool IsBanned(string ip)
        {
            // Never enforce an internal IP ban
            if (Current.IsPrivateIP(ip)) return false;
            
            TryRefreshCache();

            BanPeriod ban;
            if (!BannedIPCache.TryGetValue(ip, out ban)) return false;

            if (ban.ExpirationDate > Current.Now) return true;

            return false;
        }

        /// <summary>
        /// Create a new ban for the given ip lasting for the given period.
        /// </summary>
        public static void Ban(string ip, TimeSpan @for, string reason)
        {
            // Never ban an internal IP
            if (Current.IsPrivateIP(ip)) return;

            var db = Current.WriteDB;

            var now = Current.Now;

            var newBan =
                new IPBan
                {
                    CreationDate = now,
                    ExpirationDate = now + @for,
                    IP = ip,
                    Reason = reason
                };

            db.IPBans.InsertOnSubmit(newBan);
            db.SubmitChanges();

            var period = new BanPeriod { CreationDate = newBan.CreationDate, ExpirationDate = newBan.ExpirationDate };
            BannedIPCache.AddOrUpdate(ip, period, (string key, BanPeriod old) => period);
        }

        /// <summary>
        /// Get the existing infractions for this IP.
        /// </summary>
        private static List<Infraction> GetInfractionList(string ip)
        {
            var key = "infraction-" + ip;

            var inCache = Current.GetFromCache<List<Infraction>>(key);

            if (inCache.RemoveAll(i => i.Expires < Current.Now) != 0) Current.AddToCache(key, inCache, TimeSpan.FromDays(1));

            return new List<Infraction>(inCache);
        }

        /// <summary>
        /// Add new infractions for this IP.
        /// </summary>
        private static void UpdateInfractionList(string ip, Infraction addToList)
        {
            var key = "infraction-" + ip;
            var inCache = Current.GetFromCache<List<Infraction>>(key) ?? new List<Infraction>();
            
            inCache.Add(addToList);
            
            Current.AddToCache(key, inCache, TimeSpan.FromDays(1));
        }

        /// <summary>
        /// Gives a black mark for a bad POST (as evidenced by a forged or missing XSRF token) request.
        /// </summary>
        public static void BadXSRFToken(string ip)
        {
            UpdateInfractionList(ip, new Infraction { Type = Infraction.InfractionType.XSRF, Expires = Current.Now.Add(TimeSpan.FromMinutes(5)) });

            var existingInfactions = GetInfractionList(ip);
            if (existingInfactions.Count(i => i.Type == Infraction.InfractionType.XSRF) > 10) Ban(ip, TimeSpan.FromMinutes(10), "Too many bad XSRF tokens.");
        }

        /// <summary>
        /// Gives a black mark to an IP for sending a recovery email.
        /// 
        /// We want to cut these off after a while (faster in the face of other "iffy" behavior) since you can
        /// use recovery email error messages as a ghetto way to scan for usernames (registered email addresses).
        /// </summary>
        public static void AttemptedToSendRecoveryEmail(string ip)
        {
            UpdateInfractionList(ip, new Infraction { Type = Infraction.InfractionType.Recovery, Expires = Current.Now.Add(TimeSpan.FromMinutes(30)) });

            var existingInfractions = GetInfractionList(ip);
            if (existingInfractions.Count(i => i.Type == Infraction.InfractionType.Recovery) > 5) Ban(ip, TimeSpan.FromMinutes(60), "Too many attempts at recovering an account.");
        }

        /// <summary>
        /// Gives a black mark to an IP that just failed a login attempt.
        /// 
        /// Passes the user, if the account exists at all.
        /// 
        /// Repeated attempts to login to a single account can be very worrying past
        /// a certain number, but fat fingering does happen so we don't want to panic
        /// immediately.
        /// 
        /// Repeated attempts to *different* accounts is almost certainly a sign of an
        /// attack, once the number of involved accounts grows to a certain size.
        /// </summary>
        public static void BadLoginAttempt(User user, string ip)
        {
            UpdateInfractionList(ip,
                new Infraction
                { 
                    Type = Infraction.InfractionType.Login, 
                    Expires = Current.Now.Add(TimeSpan.FromMinutes(5)), 
                    RelatedId = user != null ? user.Id : -1
                }
            );

            var existingInfractions = GetInfractionList(ip);

            var singleUser = existingInfractions.Where(i => i.Type == Infraction.InfractionType.Login && i.RelatedId != -1).GroupBy(i => i.RelatedId).Max(g => (int?)g.Count());

            if (singleUser > 10)
            {
                Ban(ip, TimeSpan.FromMinutes(5), "More than 10 attempts to login as a user.");
                return;
            }

            var noUser = existingInfractions.Count(i => i.Type == Infraction.InfractionType.Login && i.RelatedId == -1);

            if (noUser > 20)
            {
                Ban(ip, TimeSpan.FromMinutes(30), "More than 20 attempts to login.");
                return;
            }

            var total = existingInfractions.Count(i => i.Type == Infraction.InfractionType.Login);

            // This suggests they're trying to actually dodge our single and scan behavior; drop the hammer
            if (total > 30)
            {
                Ban(ip, TimeSpan.FromMinutes(60), "Appears to be spamming login attempts, while dodging throttles.");
                return;
            }
        }
    }
}