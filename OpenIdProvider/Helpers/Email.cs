using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Net.Mail;
using System.Net;
using MarkdownSharp;
using System.IO;
using System.Text;

namespace OpenIdProvider.Helpers
{
    /// <summary>
    /// Helper class for sending e-mails.
    /// 
    /// Abstracts away all the nasty SMTP and
    /// message formatting non-sense.
    /// </summary>
    public class Email
    {
        public enum Template
        {
            AffiliateRegistered,
            CompleteRegistration,
            CompleteRegistrationViaAffiliate,
            PasswordChanged,
            ResetPassword
        }

        private static SmtpClient Client = new SmtpClient();

        // Rather than have this be a site setting, lets just infer it
        //   Might need to change it later, but configs are death by a thousand
        //   cuts in an OSS project.
        private static string _from;
        private static string FromEmailAddress
        {
            get
            {
                if (_from != null) return _from;

                NetworkCredential creds;

                lock (Client)
                {
                    creds = Client.Credentials.GetCredential(Client.Host, Client.Port, Client.DeliveryMethod.ToString());

                    _from = creds.UserName + "@" + Current.AppRootUri.Host;
                }

                return _from;
            }
        }

        /// <summary>
        /// Returns an e-mail template, with all the {Names} replaced with the corresponding properties on params and some
        /// default "SiteWide" ones like {SiteName}.
        /// 
        /// Also pushes an appropriate subject into subject.
        /// </summary>
        private static string GetEmailText(string templateName, object @params, out string subject, out string textVersion)
        {
            var markdown = Helpers.Template.FormatTemplate(templateName, @params).Trim();
            int i = markdown.IndexOf('\n');
            subject = markdown.Substring(0, i + 1).Trim();

            textVersion = markdown.Substring(i + 1).Trim();

            return (new Markdown()).Transform(textVersion);
        }

        /// <summary>
        /// Sends a raw (text/plain) e-mail.
        /// 
        /// to, from, subject, and message must be set and singular.
        /// 
        /// cc and bcc accept semi-colon delimitted lists of addresses.
        /// </summary>
        public static void SendEmail(string to, Template templateName, object @params = null, string cc = null, string bcc = null)
        {
#if DEBUG
            if (!(to.EndsWith("@stackexchange.com") || to.EndsWith("@stackoverflow.com")))
                throw new InvalidOperationException("Only e-mail SOIS employees for now.");
#endif

            string subject, textMessage;
            var htmlMessage = GetEmailText(Enum.GetName(typeof(Template), templateName), @params, out subject, out textMessage);

            var msg = new MailMessage();
            msg.To.Add(new MailAddress(to));
            msg.Subject = subject;
            msg.Body = textMessage;
            msg.From = new MailAddress(FromEmailAddress);
            msg.IsBodyHtml = false;

            // It may seem odd for the HTML (the intended primary view) to be an alternate view
            //    But trust me, it has to be.  Most viewers grab the *last* thing in the message to display,
            //    GMail for instance, so a "primary" html view will get overridden by an alternate text/plain one.
            msg.AlternateViews.Add(new AlternateView(new MemoryStream(Encoding.UTF8.GetBytes(htmlMessage)), "text/html"));

            if (cc.HasValue())
            {
                foreach (var c in cc.Split(';'))
                    msg.CC.Add(new MailAddress(c));
            }

            if (bcc.HasValue())
            {
                foreach (var bc in bcc.Split(';'))
                    msg.Bcc.Add(new MailAddress(bc));
            }

            lock (Client)
            {
                Client.Send(msg);
            }
        }
    }
}