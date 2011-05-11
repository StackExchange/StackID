using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Reflection;
using System.ComponentModel.DataAnnotations;

namespace OpenIdProvider.Models
{
    public partial class DBContext
    {
        private static Restrictions Restrictions = new Restrictions();

        /*private static MemberInfo UserType { get; set; }
        private static MemberInfo DeletionDate { get; set; }

        static DBContext()
        {
            // Explicitly not try/catch'ing this, we *want* it to explode as soon as possible if we haven't updated this
            //    code after a schema change
            UserType = typeof(User).GetMember("UserTypeId", MemberTypes.Property, BindingFlags.Instance | BindingFlags.DeclaredOnly | BindingFlags.Public)[0];
            DeletionDate = typeof(PendingUser).GetMember("DeletionDate", MemberTypes.Property, BindingFlags.Instance | BindingFlags.DeclaredOnly | BindingFlags.Public)[0];
        }*/

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
        /// Continuing the hack.
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

        public override void SubmitChanges(System.Data.Linq.ConflictMode failureMode)
        {
            if (!RestrictToCurrentUserAttributes)
            {
                base.SubmitChanges(failureMode);
                return;
            }

            var permittedUserIds = new List<int>();
            if (Current.LoggedInUser != null)
                permittedUserIds.Add(Current.LoggedInUser.Id);
            if (LiftUserRestrictionsOnId.HasValue)
                permittedUserIds.Add(LiftUserRestrictionsOnId.Value);

            // new inserts on User.Id should be allowed, everything else is an FK where this would be invalid
            permittedUserIds.Add(default(int));

            string error;
            if (!Restrictions.IsValidChangeSet(this, permittedUserIds, out error))
            {
                throw new InvalidOperationException(error);
            }

            base.SubmitChanges(failureMode);
        }
    }
}