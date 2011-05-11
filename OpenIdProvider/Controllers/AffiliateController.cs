using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using OpenIdProvider.Helpers;
using System.Security.Cryptography;

using OpenIdProvider.Models;
using System.Text.RegularExpressions;

namespace OpenIdProvider.Controllers
{
    /// <summary>
    /// Provides creation and modification of affiliate accounts.
    /// </summary>
    public class AffiliateController : ControllerBase
    {
        /// <summary>
        /// List all the affiliates the currently logged in user owns.
        /// </summary>
        [Route("affiliate/list", AuthorizedUser.LoggedIn)]
        public ActionResult ListAffiliates()
        {
            var affiliates = Current.ReadDB.Affiliates.Where(a => a.OwnerUserId == Current.LoggedInUser.Id).OrderBy(u => u.CreationDate).ToList();

            return View(affiliates);
        }

        /// <summary>
        /// Entry point for registering a new affiliate.
        /// </summary>
        [Route("affiliate/register", AuthorizedUser.LoggedIn)]
        public ActionResult RegisterAffiliate()
        {
            return View();
        }

        /// <summary>
        /// Handles the submission from /affiliate/register
        /// 
        /// Creates a new affilaite if everything checks out.
        /// </summary>
        [Route("affiliate/register/submit", HttpVerbs.Post, AuthorizedUser.LoggedIn)]
        public ActionResult CreateAffiliate(string filter)
        {
            if (!Affiliate.IsValidFilter(filter)) return RecoverableError("Invalid host filter", new { filter });

            var c = new RSACryptoServiceProvider();
            var key = c.ExportParameters(true);

            // meeeh... it would be nice if there were a way to *fix* the exponent.  May just need to store it...
            for (int i = 0; i < key.Exponent.Length; i++)
                if (key.Exponent[i] != Affiliate.FixedExponent[i])
                    throw new Exception("Exponent not as expected!");

            var modulus = Convert.ToBase64String(key.Modulus);

            var now = Current.Now;

            var newAffiliate = new Affiliate
            {
                CreationDate = now,
                HostFilter = filter,
                OwnerUserId = Current.LoggedInUser.Id,
                VerificationModulus = modulus
            };

            Current.LoggedInUser.LastActivityDate = now;

            Current.WriteDB.Affiliates.InsertOnSubmit(newAffiliate);
            Current.WriteDB.SubmitChanges();

            // This is your key, don't lose it!
            var jsonKey =
                Json(
                    new
                    {
                        D = Convert.ToBase64String(key.D),
                        DP = Convert.ToBase64String(key.DP),
                        DQ = Convert.ToBase64String(key.DQ),
                        InverseQ = Convert.ToBase64String(key.InverseQ),
                        Modulus = Convert.ToBase64String(key.Modulus),
                        P = Convert.ToBase64String(key.P),
                        Q = Convert.ToBase64String(key.Q)
                    });

            Current.Email.SendEmail(
                Current.LoggedInUser.Email,
                Email.Template.AffiliateRegistered,
                new
                {
                    D = Convert.ToBase64String(key.D),
                    DP = Convert.ToBase64String(key.DP),
                    DQ = Convert.ToBase64String(key.DQ),
                    InverseQ = Convert.ToBase64String(key.InverseQ),
                    Modulus = Convert.ToBase64String(key.Modulus),
                    P = Convert.ToBase64String(key.P),
                    Q = Convert.ToBase64String(key.Q),
                    Id = newAffiliate.Id,
                    Host = newAffiliate.HostFilter
                });

            return jsonKey;
        }
    }
}
