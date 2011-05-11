using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using NUnit.Framework;
using OpenIdProvider.Helpers;
using OpenIdProvider.Models;
using System.Data.Linq;

namespace OpenIdProvider.Tests
{
    [TestFixture]
    public class RestrictionsTests
    {
        [Test]
        public void NoDeletions()
        {
            var r = new Restrictions();

            string ignored;
            Assert.IsFalse(r.IsValidChangeSet(new Dictionary<object, Restrictions.ShadowModifiedMember[]>(), new List<object>() { new User() }, new List<object>(), new List<object>(), new List<int>(), out ignored));
        }

        [Test]
        public void NoUserUpdatesIfNotInList()
        {
            var r = new Restrictions();

            var user = new User
            {
                Id = 1,
                CreationDate = DateTime.UtcNow
            };

            var updates = new Dictionary<object, Restrictions.ShadowModifiedMember[]>();
            updates[user] = new Restrictions.ShadowModifiedMember[]
                { 
                    new Restrictions.ShadowModifiedMember
                    { 
                        Member = typeof(User).GetProperty("CreationDate"),
                        CurrentValue = user.CreationDate,
                        OriginalValue = null
                    }
                };

            string ignored;
            Assert.IsFalse(r.IsValidChangeSet(updates, new List<object>(), new List<object>(), new List<object>() { user }, new List<int>(), out ignored), ignored);
        }

        [Test]
        public void UpdateUsersInList()
        {
            var r = new Restrictions();

            var user = new User
            {
                Id = 1,
                CreationDate = DateTime.UtcNow
            };

            var updates = new Dictionary<object, Restrictions.ShadowModifiedMember[]>();
            updates[user] = new Restrictions.ShadowModifiedMember[]
                { 
                    new Restrictions.ShadowModifiedMember
                    { 
                        Member = typeof(User).GetProperty("CreationDate"),
                        CurrentValue = user.CreationDate,
                        OriginalValue = null
                    }
                };

            string ignored;
            Assert.IsTrue(r.IsValidChangeSet(updates, new List<object>(), new List<object>(), new List<object>() { user }, new List<int>() { 1 }, out ignored), ignored);
        }

        [Test]
        public void NoUserTypeIdUpdate()
        {
            var r = new Restrictions();

            var user = new User
            {
                Id = 1,
                UserTypeId = 2
            };

            var updates = new Dictionary<object, Restrictions.ShadowModifiedMember[]>();
            updates[user] = new Restrictions.ShadowModifiedMember[]
                { 
                    new Restrictions.ShadowModifiedMember
                    { 
                        Member = typeof(User).GetProperty("UserTypeId"),
                        CurrentValue = user.UserTypeId,
                        OriginalValue = 1
                    }
                };

            string ignored;
            Assert.IsFalse(r.IsValidChangeSet(updates, new List<object>(), new List<object>(), new List<object>() { user }, new List<int>() { 1 }, out ignored));
            Assert.IsFalse(r.IsValidChangeSet(updates, new List<object>(), new List<object>(), new List<object>() { user }, new List<int>(), out ignored));
        }

        [Test]
        public void NoUserHistoryUpdates()
        {
            var r = new Restrictions();

            var history = new UserHistory
            {
                Id = 1
            };

            var updates = new Dictionary<object, Restrictions.ShadowModifiedMember[]>();
            updates[history] = new Restrictions.ShadowModifiedMember[]
                {
                    new Restrictions.ShadowModifiedMember
                    {
                        Member = typeof(UserHistory).GetProperty("Id"),
                        CurrentValue = history.Id,
                        OriginalValue = 2
                    }
                };

            string ignored;
            Assert.IsFalse(r.IsValidChangeSet(updates, new List<object>(), new List<object>(), new List<object>() { history }, new List<int>() { 1 }, out ignored));
        }

        [Test]
        public void NoUserHistoryInsertsWithoutIds()
        {
            var r = new Restrictions();

            var history = new UserHistory
            {
                Id = 1
            };

            var updates = new Dictionary<object, Restrictions.ShadowModifiedMember[]>();

            string ignored;
            Assert.IsFalse(r.IsValidChangeSet(updates, new List<object>(), new List<object>() { history }, new List<object>(), new List<int>(), out ignored));
        }

        [Test]
        public void UserHistoryInsertWithUserId()
        {
            var r = new Restrictions();

            var history = new UserHistory
            {
                UserId = 1
            };

            var updates = new Dictionary<object, Restrictions.ShadowModifiedMember[]>();

            string ignored;
            Assert.IsTrue(r.IsValidChangeSet(updates, new List<object>(), new List<object>() { history }, new List<object>(), new List<int>() { 1 }, out ignored));
        }

        [Test]
        public void NoUserAttributeUpdateWithoutUserId()
        {
            var r = new Restrictions();

            var attr = new UserAttribute
            {
                UserId = 1
            };

            var updates = new Dictionary<object, Restrictions.ShadowModifiedMember[]>();
            updates[attr] = new Restrictions.ShadowModifiedMember[]
                {
                    new Restrictions.ShadowModifiedMember
                    {
                        Member = typeof(UserAttribute).GetProperty("UserId"),
                        CurrentValue = attr.Id,
                        OriginalValue = 2
                    }
                };

            string ignored;
            Assert.IsFalse(r.IsValidChangeSet(updates, new List<object>(), new List<object>(), new List<object>() { attr }, new List<int>(), out ignored));
        }

        [Test]
        public void UserAttributeUpdateWithUserId()
        {
            var r = new Restrictions();

            var attr = new UserAttribute
            {
                UserId = 1
            };

            var updates = new Dictionary<object, Restrictions.ShadowModifiedMember[]>();
            updates[attr] = new Restrictions.ShadowModifiedMember[]
                {
                    new Restrictions.ShadowModifiedMember
                    {
                        Member = typeof(UserAttribute).GetProperty("UserId"),
                        CurrentValue = attr.Id,
                        OriginalValue = 2
                    }
                };

            string ignored;
            Assert.IsTrue(r.IsValidChangeSet(updates, new List<object>(), new List<object>(), new List<object>() { attr }, new List<int>() { 1 }, out ignored));
        }

        [Test]
        public void NoUserAttributeInsertWithoutUserId()
        {
            var r = new Restrictions();

            var attr = new UserAttribute
            {
                UserId = 1
            };

            var updates = new Dictionary<object, Restrictions.ShadowModifiedMember[]>();

            string ignored;
            Assert.IsFalse(r.IsValidChangeSet(updates, new List<object>(), new List<object>() { attr }, new List<object>(), new List<int>(), out ignored));
        }

        [Test]
        public void UserAttributeInsertWithUserId()
        {
            var r = new Restrictions();

            var attr = new UserAttribute
            {
                UserId = 1
            };

            var updates = new Dictionary<object, Restrictions.ShadowModifiedMember[]>();

            string ignored;
            Assert.IsTrue(r.IsValidChangeSet(updates, new List<object>(), new List<object>() { attr }, new List<object>(), new List<int>() { 1 }, out ignored));
        }

        [Test]
        public void NoUserSiteAuthorizationInsertWithoutUserId()
        {
            var r = new Restrictions();

            var siteAuth = new UserSiteAuthorization
            {
                UserId = 1
            };

            var updates = new Dictionary<object, Restrictions.ShadowModifiedMember[]>();

            string ignored;
            Assert.IsFalse(r.IsValidChangeSet(updates, new List<object>(), new List<object>() { siteAuth }, new List<object>(), new List<int>(), out ignored));
        }

        [Test]
        public void UserSiteAuthorizationInsertWithUserId()
        {
            var r = new Restrictions();

            var siteAuth = new UserSiteAuthorization
            {
                UserId = 1
            };

            var updates = new Dictionary<object, Restrictions.ShadowModifiedMember[]>();

            string ignored;
            Assert.IsTrue(r.IsValidChangeSet(updates, new List<object>(), new List<object>() { siteAuth }, new List<object>(), new List<int>() { 1 }, out ignored));
        }

        [Test]
        public void NoPendingUserInsert()
        {
            var r = new Restrictions();

            var pending = new PendingUser
            {
                Id = 1
            };

            var updates = new Dictionary<object, Restrictions.ShadowModifiedMember[]>();

            string ignored;
            Assert.IsFalse(r.IsValidChangeSet(updates, new List<object>(), new List<object>() { pending }, new List<object>(), new List<int>(), out ignored));
            Assert.IsFalse(r.IsValidChangeSet(updates, new List<object>(), new List<object>() { pending }, new List<object>(), new List<int>() { 1 }, out ignored));
        }

        [Test]
        public void NoPendingUserUpdateOnNonDeletionDate()
        {
            var r = new Restrictions();

            var pending = new PendingUser
            {
                Id = 1
            };

            var updates = new Dictionary<object, Restrictions.ShadowModifiedMember[]>();
            updates[pending] = new Restrictions.ShadowModifiedMember[]
                {
                    new Restrictions.ShadowModifiedMember
                    {
                        Member = typeof(PendingUser).GetProperty("Id"),
                        CurrentValue = pending.Id,
                        OriginalValue = 2
                    }
                };

            string ignored;
            Assert.IsFalse(r.IsValidChangeSet(updates, new List<object>(), new List<object>(), new List<object>(){pending}, new List<int>(), out ignored));
            Assert.IsFalse(r.IsValidChangeSet(updates, new List<object>(), new List<object>(), new List<object>(){pending}, new List<int>() { 1 }, out ignored));
        }

        [Test]
        public void PendingUserUpdateDeletionDate()
        {
            var r = new Restrictions();

            var pending = new PendingUser
            {
                Id = 1,
                DeletionDate = DateTime.Now
            };

            var updates = new Dictionary<object, Restrictions.ShadowModifiedMember[]>();
            updates[pending] = new Restrictions.ShadowModifiedMember[]
                {
                    new Restrictions.ShadowModifiedMember
                    {
                        Member = typeof(PendingUser).GetProperty("DeletionDate"),
                        CurrentValue = pending.DeletionDate,
                        OriginalValue = null
                    }
                };

            string ignored;
            Assert.IsTrue(r.IsValidChangeSet(updates, new List<object>(), new List<object>(), new List<object>() { pending }, new List<int>(), out ignored));
        }
    }
}
