using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.IO;
using System.Collections.Specialized;
using System.Net;
using System.Web.Configuration;

namespace OpenIdProvider.Helpers
{
    /// <summary>
    /// Helper class for dealing with Captchas
    /// 
    /// This is backed by ReCaptcha
    /// http://www.google.com/recaptcha
    /// </summary>
    public static class Captcha
    {
        /// <summary>
        /// Write a Captcha out as part of a form on a page.
        /// </summary>
        public static void Render(TextWriter writer)
        {
            var captcha = new Recaptcha.RecaptchaControl();
            captcha.OverrideSecureMode = true;

            writer.Write(@"<div class=""captcha"">");
            writer.Write(captcha.RenderControl());
            writer.Write("</div>");
        }

        /// <summary>
        /// Verify that the given form contains a solution to a captcha.
        /// 
        /// If not, message will contain something suitable for display to a user.
        /// </summary>
        public static bool Verify(NameValueCollection form, out string message)
        {
            var challenge = form["recaptcha_challenge_field"];
            var response = form["recaptcha_response_field"];

            if (!challenge.HasValue() || !response.HasValue())
            {
                message = "Captcha failed";

                return false;
            }

            var captcha = new Recaptcha.RecaptchaValidator();
            captcha.RemoteIP = Current.RemoteIP;
            captcha.Challenge = challenge;
            captcha.Response = response;
            captcha.PrivateKey = WebConfigurationManager.AppSettings["ReCaptchaPrivateKey"];

            try
            {
                var res = captcha.Validate();
                if (res != Recaptcha.RecaptchaResponse.Valid)
                {
                    message = "Captcha failed - " + res.ErrorMessage;
                    return false;
                }
            }
            catch (WebException)
            {
                message = "There was a problem communicating with ReCaptcha, please try again";

                return false;
            }

            message = "";

            return true;
        }
    }
}