using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using OpenIdProvider.Helpers;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using OpenIdProvider.Models;

namespace OpenIdProvider.Controllers
{
    /// <summary>
    /// Contains all adminstrative functions.
    /// </summary>
    public class AdminController : ControllerBase
    {
        /// <summary>
        /// Simple index of all /admin routes
        /// </summary>
        [Route("admin", AuthorizedUser.Administrator)]
        public ActionResult Index()
        {
            return View();
        }

        [Route("admin/find-user", AuthorizedUser.Administrator)]
        public ActionResult FindUser(string email)
        {
            var user = Models.User.FindUserByEmail(email);

            return
                user == null ?
                TextPlain("Not Found") :
                new ContentResult { ContentType = "text/html", Content = "<html><body><a href='" + user.GetClaimedIdentifier() + "'>user</a></body></html>" };
        }

        /// <summary>
        /// List all errors in a handy web interface
        /// </summary>
        [Route("admin/errors", AuthorizedUser.Administrator)]
        public ActionResult ListErrors(int? pagesize, int? page)
        {
            int total;
            var errors = Error.LoadErrors(Current.ErrorLogPath, pagesize.GetValueOrDefault(30), page.GetValueOrDefault(1) - 1, out total);

            ViewData["total"] = total;
            ViewData["pagesize"] = pagesize.GetValueOrDefault(30);
            ViewData["page"] = page.GetValueOrDefault(1);

            return View(errors);
        }

        /// <summary>
        /// View a single error.
        /// </summary>
        [Route("admin/error/{id}", RoutePriority.Low, AuthorizedUser.Administrator)]
        public ActionResult ViewError(string id)
        {
            Guid errorId;
            if (id.IsNullOrEmpty() || !Guid.TryParse(id, out errorId)) return NotFound();

            var error = Error.LoadError(Current.ErrorLogPath, errorId);

            if (error == null) return NotFound();

            return View(error);
        }

        /// <summary>
        /// Delete an error, given its id.
        /// </summary>
        [Route("admin/error/delete/submit", HttpVerbs.Post, AuthorizedUser.Administrator)]
        public ActionResult DeleteError(string id, int? pagesize, int? page)
        {
            //if (!Current.IsInternalRequest) return NotFound();

            Guid errorId;
            if (id.IsNullOrEmpty() || !Guid.TryParse(id, out errorId)) return NotFound();

            var error = Error.LoadError(Current.ErrorLogPath, errorId);

            if (error == null) return NotFound();

            error.Delete();

            return
                SafeRedirect(
                    (Func<int?, int?, ActionResult>)ListErrors,
                    new {
                        pagesize,
                        page
                    });
        }

#if DEBUG

        /// <summary>
        /// Generate a new key, that can be added to the keystore file.
        /// 
        /// Not really protected by much, as generating the key does nothing,
        /// it still has to be added to the actual file.
        /// </summary>
        [Route("admin/key-gen", AuthorizedUser.Administrator | AuthorizedUser.LoggedIn | AuthorizedUser.Anonymous)]
        public ActionResult GenerateKey()
        {
            var crypto = new AesCryptoServiceProvider();
            crypto.GenerateKey();

            var key = Convert.ToBase64String(crypto.Key);
            var salt = Current.GenerateSalt();
            var hmac = Convert.ToBase64String(Current.Random(64));

            var ret =
                Newtonsoft.Json.JsonConvert.SerializeObject(
                    new KeyStore.Key
                        {
                            Version = 255,
                            Encryption = key,
                            Salt = salt,
                            HMAC = hmac
                        });

            return TextPlain(ret);
        }

#endif

        /// <summary>
        /// List all ip bans for the site, and provides some minor
        /// UI for adding/removing them.
        /// </summary>
        [Route("admin/ip-bans", AuthorizedUser.Administrator)]
        public ActionResult IPBans(bool? showall, int? page, int? pagesize)
        {
            var all = showall.GetValueOrDefault(false);
            var p = page.GetValueOrDefault(0);
            var ps = pagesize.GetValueOrDefault(30);

            var bans = Current.ReadDB.IPBans.AsQueryable();

            if (!all) bans = bans.Where(b => b.ExpirationDate > Current.Now);

            ViewData["count"] = bans.Count();

            bans = bans.OrderByDescending(b => b.CreationDate).Skip(ps * p).Take(ps);

            ViewData["page"] = p;
            ViewData["pagesize"] = ps;
            ViewData["showall"] = all;

            return View(bans.ToList());
        }

        /// <summary>
        /// Landing route for when an error is encountered with admin/ip-bans/create/submit.
        /// 
        /// Lets us get away with using RecoverableError in some convenient places.
        /// </summary>
        [Route("admin/ip-bans/create", AuthorizedUser.Administrator)]
        public ActionResult IPBansCreateLanding(bool? showAll, int? page, int? pagesize)
        {
            return IPBans(showAll, page, pagesize);
        }

        /// <summary>
        /// Deletes (sets expiration to *now*) an IP ban.
        /// </summary>
        [Route("admin/ip-bans/delete/submit", HttpVerbs.Post, AuthorizedUser.Administrator)]
        public ActionResult DeleteIPBan(int? id, int? pagesize, int? page, bool? showall)
        {
            if (id.HasValue)
            {
                var db = Current.WriteDB;

                var ban = db.IPBans.SingleOrDefault(i => i.Id == id);

                if (ban != null)
                {
                    ban.ExpirationDate = Current.Now;
                    db.SubmitChanges();
                }
            }
            else
            {
                return NotFound();
            }

            return SafeRedirect(
                (Func<bool?, int?, int?, ActionResult>)IPBans,
                new 
                {
                    showall,
                    page,
                    pagesize
                });
        }

        /// <summary>
        /// Creates a new IP ban.
        /// </summary>
        [Route("admin/ip-bans/create/submit", HttpVerbs.Post, AuthorizedUser.Administrator)]
        public ActionResult CreateIPBan(string ip, string expires, string reason, bool? showall, int? page, int? pagesize)
        {
            var retryValues = new { ip, expires, reason };

            if (!ip.HasValue()) return RecoverableError("IP must be set.", retryValues);
            if (!expires.HasValue()) return RecoverableError("Expires must be set.", retryValues);
            if (!reason.HasValue()) return RecoverableError("Reason must be set.", retryValues);

            DateTime expDate;
            if (!DateTime.TryParse(expires, out expDate)) return RecoverableError("Expires not recognized as a date.", retryValues);

            var now = Current.Now;

            if (expDate < now) return RecoverableError("Expiration date must be in the future.", retryValues);

            var newBan =
                new IPBan
                {
                    CreationDate = now,
                    ExpirationDate = expDate,
                    IP = ip,
                    Reason = reason
                };

            var db = Current.WriteDB;
            db.IPBans.InsertOnSubmit(newBan);
            db.SubmitChanges();

            return SafeRedirect(
                (Func<bool?, int?, int?, ActionResult>)IPBans,
                new
                {
                    showall,
                    page,
                    pagesize
                });
        }
    }
}
