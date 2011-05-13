using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Mvc;
using OpenIdProvider.Helpers;
using OpenIdProvider.Models;

namespace OpenIdProvider.Controllers
{
    public class UserController : ControllerBase
    {
        /// <summary>
        /// Bounce to a user's profile based on vanity id.
        /// </summary>
        [Route("{vanityId}", RoutePriority.Low, AuthorizedUser.LoggedIn | AuthorizedUser.Anonymous | AuthorizedUser.Administrator)]
        public ActionResult VanityIdentifier(string vanityId)
        {
            var user = Models.User.GetFromVanityId(vanityId);

            if (user != null)
                return Redirect(user.GetClaimedIdentifier().AbsoluteUri);

            return NotFound();
        }

        /// <summary>
        /// For the logged in user, shows they're profile.
        /// </summary>
        /// <returns></returns>
        [Route("user", AuthorizedUser.LoggedIn)]
        public ActionResult ViewUser()
        {
            return View("View", Current.LoggedInUser);
        }

        /// <summary>
        /// Identities the specified id.
        /// </summary>
        [Route("user/{id}", RoutePriority.Low, AuthorizedUser.LoggedIn | AuthorizedUser.Anonymous | AuthorizedUser.Administrator)]
        public ActionResult Identity(string id, bool? xrds)
        {
            if (id.IsNullOrEmpty()) return NotFound();

            var user = Models.User.GetFromProviderId(id);

            if (user == null) return NotFound();

            var loggedIn = Current.LoggedInUser;

            // Need to be an administrator to view a user, unless you *are* that user
            if (loggedIn != null && (loggedIn.Id == user.Id || loggedIn.IsAdministrator))
            {
                return View("View", user);
            }

            if (xrds.GetValueOrDefault(false) || (Request.AcceptTypes != null && Request.AcceptTypes.Contains("application/xrds+xml")))
            {
                return View("Xrds", user);
            }

            return View("HtmlDiscovery", user);
        }

        /// <summary>
        /// Profile editor for arbitrary users, only accessible to Administrators.
        /// </summary>
        [Route("user/{id}/edit", AuthorizedUser.Administrator)]
        public ActionResult EditUser(string id)
        {
            if (id.IsNullOrEmpty()) return NotFound();

            var user = Models.User.GetFromProviderId(id) ?? Models.User.GetFromVanityId(id);

            if (user == null) return NotFound();

            return View("EditUser", user);
        }

        /// <summary>
        /// Profile editor for the currently logged in user.
        /// </summary>
        /// <returns></returns>
        [Route("user/edit", AuthorizedUser.LoggedIn)]
        public ActionResult Edit()
        {
            return View("EditUser", Current.LoggedInUser);
        }

        /// <summary>
        /// Handles submissions from the various profile editing routes.
        /// </summary>
        [Route("user/edit/submit", HttpVerbs.Post, AuthorizedUser.LoggedIn)]
        public ActionResult EditUserSubmit(string id)
        {
            if (!id.HasValue()) return NotFound();

            Guid providerId;
            if (!Guid.TryParse(id, out providerId)) return NotFound();

            var toUpdate = Current.WriteDB.Users.SingleOrDefault(u => u.ProviderId == providerId);

            if (toUpdate == null) return NotFound();

            if (toUpdate.Id != Current.LoggedInUser.Id && !Current.LoggedInUser.IsAdministrator) return IrrecoverableError("Cannot modify that user", "You can only modify profiles you are logged into.");

            var db = Current.WriteDB;
            var now = Current.Now;

            foreach (var p in Request.Form.AllKeys)
            {
                var value = Request.Form[p];

                if (p == "realname")
                {
                    var old = toUpdate.RealName;
                    if (old == value || (old.IsNullOrEmpty() && value.IsNullOrEmpty())) continue;

                    var hadPreviously = old.HasValue();

                    string errorMessage;
                    if (!toUpdate.UpdateAttribute(value.IsNullOrEmpty() ? null : value, UserAttributeTypeId.RealName, out errorMessage))
                    {
                        if (Current.LoggedInUser.Id == toUpdate.Id)
                        {
                            return RecoverableError(errorMessage, new { });
                        }
                        else
                        {
                            // Hack: URL structure means administrators cannot *really* recover from this error.
                            return IrrecoverableError("Admin edit failed", errorMessage);
                        }

                    }

                    string comment = "Changed";
                    if (hadPreviously && value.IsNullOrEmpty()) comment = "Removed";
                    if (!hadPreviously && value.HasValue()) comment = "Added";

                    var editedRealName =
                        new UserHistory
                        {
                            Comment = comment,
                            CreationDate = now,
                            IP = Current.RemoteIP,
                            UserHistoryTypeId = UserHistoryTypeId.RealNameChanged,
                            UserId = toUpdate.Id
                        };

                    db.UserHistory.InsertOnSubmit(editedRealName);
                }

                if (p == "vanity")
                {
                    var old = toUpdate.VanityProviderId;
                    if (old == value || (old.IsNullOrEmpty() && value.IsNullOrEmpty())) continue;

                    var hadPreviously = old.HasValue();

                    string errorMsg;
                    if (value.HasValue() && !Models.User.IsValidVanityId(value, out errorMsg))
                    {
                        return RecoverableError(errorMsg, new { realname = Request.Form["realname"], vanity = value });
                    }

                    if (value.HasValue() && db.Users.Any(u => u.VanityProviderId == value)) return RecoverableError("That Vanity OpenId is already in use", new { realname = Request.Form["realname"], vanity = value });

                    toUpdate.VanityProviderId = value.IsNullOrEmpty() ? null : value;

                    string comment = "Changed";
                    if (hadPreviously && value.IsNullOrEmpty()) comment = "Removed";
                    if (!hadPreviously && value.HasValue()) comment = "Added";

                    var editedVanity =
                        new UserHistory
                        {
                            Comment = comment,
                            CreationDate = now,
                            IP = Current.RemoteIP,
                            UserHistoryTypeId = UserHistoryTypeId.VanityIdChanged,
                            UserId = toUpdate.Id
                        };

                    db.UserHistory.InsertOnSubmit(editedVanity);
                }
            }

            db.SubmitChanges();

            // post submit sanity check to make sure we've got no duplicate vanity id's out there
            //   this is a bit of hack, to work around the inability to set a meaningful unique constraint
            //   on a nullable column
            if (toUpdate.VanityProviderId.HasValue())
            {
                if (db.Users.Count(u => u.VanityProviderId == toUpdate.VanityProviderId) != 1)
                {
                    toUpdate.VanityProviderId = null;

                    var editedVanity =
                        new UserHistory
                        {
                            Comment = "Removed",
                            CreationDate = now,
                            IP = "127.0.0.1",
                            UserHistoryTypeId = UserHistoryTypeId.VanityIdChanged,
                            UserId = toUpdate.Id
                        };

                    db.UserHistory.InsertOnSubmit(editedVanity);
                    db.SubmitChanges();
                }
            }

            return
                SafeRedirect(
                    (Func<ActionResult>)this.ViewUser
                );
        }

        /// <summary>
        /// Displays the XRDS (or Yardis) document appropriate for
        /// discovering a user's claimed identifier.
        /// </summary>
        [Route("user/xrds")]
        public ActionResult Xrds(string id)
        {
            return View();
        }
    }
}
