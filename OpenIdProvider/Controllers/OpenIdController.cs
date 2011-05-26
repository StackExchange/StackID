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
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using ProtoBuf;

namespace OpenIdProvider.Controllers
{
    /// <summary>
    /// Let's us run the provider on a cluster of servers.
    /// 
    /// Heavily inspired by 
    /// https://knowledgeexchange.svn.codeplex.com/svn/binaries/DotNetOpenAuth-3.2.2.9257/Samples/OpenIdProviderWebForms/Code/CustomStore.cs
    /// by Andrew Arnott
    /// </summary>
    class ProviderStore : IProviderApplicationStore
    {
        [ProtoContract]
        class Wrapper
        {
            [ProtoMember(1)]
            public DateTime Expires { get; set; }

            [ProtoMember(2)]
            public byte[] PrivateData { get; set; }

            [ProtoMember(3)]
            public string Handle { get; set; }
        }

        public void StoreAssociation(AssociationRelyingPartyType distinguishingFactor, Association association)
        {
            var keyWithoutHandle = "assoc-" + distinguishingFactor.ToString();
            var keyWithHandle = keyWithoutHandle + "-" + association.Handle;

            var expireIn = association.Expires - Current.Now;

            var @private = association.SerializePrivateData();

            var newRecord = new Wrapper
            {
                Expires = association.Expires,
                PrivateData = @private,
                Handle = association.Handle
            };

            Current.AddToCache(keyWithoutHandle, newRecord, expireIn);
            Current.AddToCache(keyWithHandle, newRecord, expireIn);
        }

        public Association GetAssociation(AssociationRelyingPartyType distinguishingFactor, string handle)
        {
            var keyWithHandle = "assoc-" + distinguishingFactor.ToString() + "-" + handle;

            var wrapper = Current.GetFromCache<Wrapper>(keyWithHandle);

            if (wrapper == null) return null;

            return Association.Deserialize(wrapper.Handle, wrapper.Expires, wrapper.PrivateData);
        }

        public Association GetAssociation(AssociationRelyingPartyType distinguishingFactor, SecuritySettings securityRequirements)
        {
            var keyWithoutHandle = "assoc-" + distinguishingFactor.ToString();

            var wrapper = Current.GetFromCache<Wrapper>(keyWithoutHandle);

            if(wrapper == null) return null;

            return Association.Deserialize(wrapper.Handle, wrapper.Expires, wrapper.PrivateData);
        }

        public bool RemoveAssociation(AssociationRelyingPartyType distinguishingFactor, string handle)
        {
            var keyWithoutHandle = "assoc-" + distinguishingFactor.ToString();
            var keyWithHandle = keyWithoutHandle + "-" + handle;

            // lack of short-circuit here is important, both these calls need to run
            return Current.RemoveFromCache(keyWithoutHandle) | Current.RemoveFromCache(keyWithHandle);
        }

        public bool StoreNonce(string context, string nonce, DateTime timestampUtc)
        {
            var longGoodFor = (timestampUtc - Nonces.UnixEpoch);

            var key = "assoc-nonce-" + context + "-" + nonce + "-" + (long)longGoodFor.TotalSeconds;

            if (Current.GetFromCache<string>(key) != null) return false;

            Current.AddToCache(key, "", longGoodFor);

            return true;
        }
    }

    /// <summary>
    /// Handles the nitty gritty of the actual OpenId process.
    /// 
    /// Credit to dotNetOpenAuth, as their reference projects formed the basis of this code.
    /// </summary>
    public class OpenIdController : ControllerBase
    {
        private DotNetOpenAuth.OpenId.Provider.OpenIdProvider OpenIdProvider = new DotNetOpenAuth.OpenId.Provider.OpenIdProvider(new ProviderStore());

        /// <summary>
        /// Common code to stash an authRequest behind in a session.
        /// </summary>
        private static string CreationSession(IAuthenticationRequest authRequest)
        {
            var session = Current.UniqueId().ToString();
            Current.AddToCache(session, authRequest.Serialize(), TimeSpan.FromMinutes(15));

            return session;
        }

        /// <summary>
        /// Returns true if we got passed some localId that is garbage.
        /// 
        /// Used to detect when a relying party is sort of screwing things up, 
        /// so we can fix things up for them.
        /// </summary>
        private bool NobodyClaims(string localId)
        {
            Uri uri;
            if (!Uri.TryCreate(localId, UriKind.Absolute, out uri)) return false;

            var path = uri.AbsolutePath.ToLower();

            if (!path.StartsWith("/user/")) return false;

            var id = path.Substring("/user/".Length);

            return Models.User.GetFromProviderId(id) == null;
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
                    // Hack: loads of people seem to jack up discovery and send the claimed id as the local id
                    //       or maybe that's to "spec", for some definition of the OpenID Spec...
                    if (Current.LoggedInUser != null)
                    {
                        var localId = authRequest.LocalIdentifier;

                        if (localId != null && NobodyClaims(localId.ToString()))
                        {
                            Current.LogException(new Exception("Rewrote [" + localId.ToString()+ "]"));
                            authRequest.LocalIdentifier = Current.LoggedInUser.GetClaimedIdentifier();
                        }
                    }

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
            var authRequestBytes = Current.GetFromCache<byte[]>(session);

            if (authRequestBytes == null) return IrrecoverableError("Could Not Find Pending Authentication Request", "We were unable to find the pending authentication request, and cannot resume login.");

            IAuthenticationRequest authRequest = null;
            authRequest = authRequest.DeSerialize(authRequestBytes);

            Current.RemoveFromCache(session);

            // HACK: fix up bad local ids sent from a relying party
            var localId = authRequest.LocalIdentifier;
            if (localId != null && NobodyClaims(localId.ToString()))
            {
                Current.LogException(new Exception("Rewrote [" + localId.ToString() + "]"));
                authRequest.LocalIdentifier = Current.LoggedInUser.GetClaimedIdentifier();
            }

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

                var writeableUser = Current.WriteDB.Users.Single(u => u.Id == Current.LoggedInUser.Id);
                writeableUser.AuthenticatedTo(Current.Now, authReq.Realm.Host);
            }

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
