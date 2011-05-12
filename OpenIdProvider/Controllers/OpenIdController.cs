using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Mvc.Ajax;
using DotNetOpenAuth.Messaging;
using DotNetOpenAuth.OpenId;
using DotNetOpenAuth.OpenId.Behaviors;
using DotNetOpenAuth.OpenId.Extensions.ProviderAuthenticationPolicy;
using DotNetOpenAuth.OpenId.Provider;
using System.Web.Security;
using OpenIdProvider.Helpers;
using DotNetOpenAuth.OpenId.Extensions.SimpleRegistration;
using DotNetOpenAuth.OpenId.Extensions.AttributeExchange;

using OpenIdProvider.Models;

namespace OpenIdProvider.Controllers
{
    /// <summary>
    /// Handles the nitty gritty of the actual OpenId process.
    /// 
    /// Credit to dotNetOpenAuth, as their reference projects formed the basis of this code.
    /// </summary>
    public class OpenIdController : ControllerBase
    {
        private DotNetOpenAuth.OpenId.Provider.OpenIdProvider OpenIdProvider = new DotNetOpenAuth.OpenId.Provider.OpenIdProvider();

        /// <summary>
        /// Common code to stash an authRequest behind in a session.
        /// </summary>
        private static string CreationSession(IAuthenticationRequest authRequest)
        {
            var session = Current.UniqueId().ToString();
            Current.AddToCache(session, authRequest, TimeSpan.FromMinutes(15));

            return session;
        }

        /// <summary>
        /// Entry point for logging in using an OpenId provided by this site.
        /// </summary>
        //[Route("openid/provider")] - mapped in global to bypass XSRF POST check
        [ValidateInput(false)]
        public ActionResult Provider()
        {
            IRequest request = OpenIdProvider.GetRequest();
            if (request != null)
            {
                var authRequest = request as IAuthenticationRequest;
                if (authRequest != null)
                {
                    var sendAssertion = Current.LoggedInUser != null &&
                        (authRequest.IsDirectedIdentity || this.UserControlsIdentifier(authRequest));

                    if (sendAssertion)
                    {
                        if (!Current.LoggedInUser.HasGrantedAuthorization(authRequest.Realm.Host))
                        {
                            var session = CreationSession(authRequest);

                            return
                                SafeRedirect(
                                    (Func<string, ActionResult>)(new AccountController()).PromptForAuthorization,
                                    new
                                    {
                                        session
                                    }
                                );
                        }

                        // We know who the user is, and how to respond
                        return this.SendAssertion(authRequest);
                    }
                    else
                    {
                        // A logged in user is trying to auth as somebody else.
                        //    Proper response here is going to be to log them out, so they can log in.
                        if (Current.LoggedInUser != null)
                        {
                            Current.LoggedInUser.Logout(Current.Now);
                        }

                        // Stash the pending request into cache until they have
                        var session = CreationSession(authRequest);

                        return
                            SafeRedirect(
                                (Func<string, ActionResult>)(new AccountController()).Login,
                                new
                                {
                                    session
                                }
                            );
                    }
                }

                if (request.IsResponseReady)
                {
                    var resp = OpenIdProvider.PrepareResponse(request).AsActionResult();
                    return resp;
                }
                else
                {
                    return
                        SafeRedirect(
                            (Func<string, ActionResult>)(new AccountController()).Login
                        );
                }
            }
            else
            {
                return NotFound();
            }
        }

        /// <summary>
        /// Resume an openid login session that was interrupted (ie. to have the user login).
        /// </summary>
        [Route("openid/resume", AuthorizedUser.LoggedIn)]
        public ActionResult ResumeAfterLogin(string session, string noPrompt)
        {
            var authRequest = Current.GetFromCache<IAuthenticationRequest>(session);

            if (authRequest == null) return IrrecoverableError("Could Not Find Pending Authentication Request", "We were unable to find the pending authentication request, and cannot resume login.");

            Current.RemoveFromCache(session);

            var sendAssertion = (authRequest.IsDirectedIdentity || this.UserControlsIdentifier(authRequest));

            if (!sendAssertion)
            {
                return IrrecoverableError(
                    "Cannot Complete Login",
                    "Detected an attempt to send an assertion when the identifier (" + authRequest.LocalIdentifier + ") is not owned by the logged in user."
                );
            }

            if (!Current.LoggedInUser.HasGrantedAuthorization(authRequest.Realm.Host))
            {
                session = CreationSession(authRequest);

                return
                    SafeRedirect(
                        (Func<string, ActionResult>)(new AccountController()).PromptForAuthorization,
                        new
                        {
                            session
                        }
                    );
            }

            bool noPromptB = false;
            if (noPrompt.HasValue())
                bool.TryParse(noPrompt, out noPromptB);

            return SendAssertion(authRequest, noPrompt: noPromptB);
        }

        /// <summary>
        /// Actually send a response to the given request if possible.
        /// 
        /// May also result in some prompting for permissions, unless noPrompt is set.
        /// </summary>
        protected ActionResult SendAssertion(IAuthenticationRequest authReq, bool noPrompt = false)
        {
            if (authReq == null)
            {
                throw new InvalidOperationException("There's no pending authentication request!");
            }

            if (authReq.IsDirectedIdentity)
            {
                authReq.LocalIdentifier = Current.LoggedInUser.GetClaimedIdentifier();
            }
            if (!authReq.IsDelegatedIdentifier)
            {
                authReq.ClaimedIdentifier = authReq.LocalIdentifier;
            }

            authReq.IsAuthenticated = this.UserControlsIdentifier(authReq);

            if (authReq.IsAuthenticated.Value)
            {
                authReq.LocalIdentifier = Current.LoggedInUser.GetClaimedIdentifier();

                // Respond to SREG extension requests.
                var claimsReq = authReq.GetExtension<ClaimsRequest>();
                if (claimsReq != null)
                {
                    var claimsResp = claimsReq.CreateResponse();

                    if (claimsReq.Email != DemandLevel.NoRequest)
                    {
                        claimsResp.Email = Current.LoggedInUser.Email;
                    }

                    if (claimsReq.FullName != DemandLevel.NoRequest)
                    {
                        var realName = Current.LoggedInUser.RealName;

                        if (realName.HasValue())
                            claimsResp.FullName = realName;
                    }

                    authReq.AddResponseExtension(claimsResp);
                }

                // Response to AX extension requests
                var fetchReq = authReq.GetExtension<FetchRequest>();
                if (fetchReq != null)
                {
                    var fetchResp = new FetchResponse();

                    if (fetchReq.Attributes.Contains(WellKnownAttributes.Contact.Email))
                    {
                        fetchResp.Attributes.Add(WellKnownAttributes.Contact.Email, Current.LoggedInUser.Email);
                    }

                    if (fetchReq.Attributes.Contains(WellKnownAttributes.Name.FullName))
                    {
                        var realName = Current.LoggedInUser.RealName;

                        if (realName.HasValue())
                            fetchResp.Attributes.Add(WellKnownAttributes.Name.FullName, realName);
                    }

                    authReq.AddResponseExtension(fetchResp);
                }
            }

            var writeableUser = Current.WriteDB.Users.Single(u => u.Id == Current.LoggedInUser.Id);
            writeableUser.AuthenticatedTo(Current.Now, authReq.Realm.Host);

            var req = OpenIdProvider.PrepareResponse(authReq).AsActionResult();

            return req;
        }

        /// <summary>
        /// Checks whether the logged in user controls the OP local identifier in the given authentication request.
        /// </summary>
        /// <param name="authReq">The authentication request.</param>
        /// <returns><c>true</c> if the user controls the identifier; <c>false</c> otherwise.</returns>
        private bool UserControlsIdentifier(IAuthenticationRequest authReq)
        {
            if (authReq == null)
            {
                throw new ArgumentNullException("authReq");
            }
            return Current.LoggedInUser.ClaimsId(authReq.LocalIdentifier);
        }
    }
}
