using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Net.Mail;
using System.IO;
using System.Text;
using System.Net;

namespace OpenIdProvider.Helpers
{
    /// <summary>
    /// An implementation of Email that relies *only* on .NET built in classes.
    /// </summary>
    [Priority(1)]
    public class DotNetEmail : Email
    {
        private SmtpClient Client = new SmtpClient();

        private string _from;
        protected string FromEmailAddress
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

        protected override bool SendEmailImpl(string to, IEnumerable<string> cc, IEnumerable<string> bcc, string subject, string bodyHtml, string bodyText)
        {
            try
            {
                var msg = new MailMessage();
                msg.To.Add(new MailAddress(to));
                msg.Subject = subject;
                msg.Body = bodyText;
                msg.From = new MailAddress(FromEmailAddress);
                msg.IsBodyHtml = false;

                // It may seem odd for the HTML (the intended primary view) to be an alternate view
                //    But trust me, it has to be.  Most viewers grab the *last* thing in the message to display,
                //    GMail for instance, so a "primary" html view will get overridden by an alternate text/plain one.
                msg.AlternateViews.Add(new AlternateView(new MemoryStream(Encoding.UTF8.GetBytes(bodyHtml)), "text/html"));

                foreach (var c in cc)
                    msg.CC.Add(new MailAddress(c));

                foreach (var bc in bcc)
                    msg.Bcc.Add(new MailAddress(bc));

                lock (Client)
                {
                    Client.Send(msg);
                }

                return true;
            }
            catch (Exception e)
            {
                Current.LogException(e);
                return false;
            }
        }
    }
}