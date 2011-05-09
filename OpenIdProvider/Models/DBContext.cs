using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Reflection;

namespace OpenIdProvider.Models
{
    public partial class DBContext
    {
        private static MemberInfo UserType { get; set; }
        private static MemberInfo DeletionDate { get; set; }

        static DBContext()
        {
            // Explicitly not try/catch'ing this, we *want* it to explode as soon as possible if we haven't updated this
            //    code after a schema change
            UserType = typeof(User).GetMember("UserTypeId", MemberTypes.Property, BindingFlags.Instance | BindingFlags.DeclaredOnly | BindingFlags.Public)[0];
            DeletionDate = typeof(PendingUser).GetMember("DeletionDate", MemberTypes.Property, BindingFlags.Instance | BindingFlags.DeclaredOnly | BindingFlags.Public)[0];
        }

        /// <summary>
        /// This is a bit of a hack, but there are some special places
        /// (mostly around the actual OpenId authentication process) where
        /// we need to do updates in response to a GET.
        /// 
        /// However, there are *no* cases where we want free ranging updates, so what this property does
        /// is restrict the insertion and updating of rows (no deletes allowed) to those that are keyed
        /// off the currently logged in user.
        /// </summary>
        public bool RestrictToCurrentUserAttributes { get; set; }

        private int? unrestrictedUserId;
        /// <summary>
        /// Continueing the hack.
        /// 
        /// Sometimes we want fair game on a single user id (such as during registration).
        /// 
        /// Basically, we'll allow *inserts* of certain rows provided they contain this UserId.
        /// It can only be set once.
        /// </summary>
        public int? LiftUserRestrictionsOnId {
            get
            {
                return unrestrictedUserId;
            }
            set
            {
                if (unrestrictedUserId.HasValue) throw new InvalidOperationException("Cannot change ListUserRestrictionsOnId after it has been set");

                unrestrictedUserId = value;
            }
        }

        // TODO: This has got to be refactor to be declarative, this method has become insane
        public override void SubmitChanges(System.Data.Linq.ConflictMode failureMode)
        {
            if (!RestrictToCurrentUserAttributes)
            {
                base.SubmitChanges(failureMode);
                return;
            }

            var pendingChanges = GetChangeSet();

            if (pendingChanges.Deletes.Any(d => d.GetType() != typeof(PendingUser)))
                throw new InvalidOperationException("Cannot delete non-PendingUsers rows with this restricted connection");

            var permittedUserIds = new List<int>();
            if (Current.LoggedInUser != null)
                permittedUserIds.Add(Current.LoggedInUser.Id);
            if (LiftUserRestrictionsOnId.HasValue)
                permittedUserIds.Add(LiftUserRestrictionsOnId.Value);

            if (pendingChanges.Inserts.Count > 0)
            {
                // Only allow inserts to the UserHistory table
                if (pendingChanges.Inserts.Any(t => t.GetType() != typeof(UserHistory) && t.GetType() != typeof(User) && t.GetType() != typeof(UserAttribute) && t.GetType() != typeof(UserSiteAuthorization)))
                    throw new InvalidOperationException("Cannot insert any records except new users, new attributes, new user site authorizations, and new user histories");

                // Only allow inserts of new records if they refer to the currently logged in user or the user being created
                if (pendingChanges.Inserts.OfType<UserHistory>().Any(h => !permittedUserIds.Contains(h.UserId)) ||
                    pendingChanges.Inserts.OfType<UserAttribute>().Any(a => !permittedUserIds.Contains(a.UserId)) ||
                    pendingChanges.Inserts.OfType<UserSiteAuthorization>().Any(au => !permittedUserIds.Contains(au.UserId)))
                        throw new InvalidOperationException("Cannot insert any history records except for the currently logged in user");
            }

            // Only allow Updates to UserAttributes and User rows
            if (pendingChanges.Updates.Any(t => t.GetType() != typeof(UserAttribute) && t.GetType() != typeof(User) && t.GetType() != typeof(PendingUser)))
                throw new InvalidOperationException("This connection can only be used for spot updates of UserAttributes, PendingUsers & Users");

            // Only allow updates to rows keyed off the current user
            if (pendingChanges.Updates.OfType<UserAttribute>().Any(a => 
                {
                    return permittedUserIds.Contains(a.UserId) || 
                        pendingChanges.Updates.OfType<User>().Any(u => permittedUserIds.Contains(u.Id));
                }))
                throw new InvalidOperationException("This connection can only be used for spot updates of UserAttributes and User rows owned by the currently logged in user");

            // Don't allow updates to User.UserTypeId
            if (pendingChanges.Updates.OfType<User>().Any(u => 
                    {
                        var modified = this.Users.GetModifiedMembers(u);
                        return modified.Any(m => m.Member == UserType) && !permittedUserIds.Contains(u.Id);
                    }))
                throw new InvalidOperationException("This connection cannot be used to modify a User.UserTypeId column");

            if (pendingChanges.Updates.OfType<PendingUser>().Any(u => this.PendingUsers.GetModifiedMembers(u).Any(m => m.Member != DeletionDate)))
                throw new InvalidOperationException("This connection cannot be used to modify anything other than DeletionDate on PendingUser");

            base.SubmitChanges(failureMode);
        }
    }
}