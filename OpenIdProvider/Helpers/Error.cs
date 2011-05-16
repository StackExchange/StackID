using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Diagnostics;
using Newtonsoft.Json;
using System.IO;

namespace OpenIdProvider.Helpers
{
    /// <summary>
    /// Simple error logging implementation.
    /// 
    /// Looked at some third-party stuff, all adds a lot of undesirable
    /// complexity.
    /// </summary>
    public class Error
    {
        public string Url { get; set; }
        public Dictionary<string, string> Parameters { get; set; }
        public Dictionary<string, string> ReceivedCookies { get; set; }
        public Dictionary<string, string> SendingCookies { get; set; }
        public Dictionary<string, string> ReceivedHeaders { get; set; }
        public Dictionary<string, string> SendingHeaders { get; set; }
        public string Message { get; set; }
        public string StackTrace { get; set; }
        public Guid Id { get; set; }
        public DateTime CreationDate { get; set; }
        public string RemoteIP { get; set; }
        public string Type { get; set; }
        public string UserId { get; set; }

        private string Location { get; set; }

        public Error() { }

        /// <summary>
        /// Constructs a new ready-to-log error
        /// </summary>
        public Error(Exception e)
        {
            if (HttpContext.Current != null)
            {
                try
                {
                    var req = HttpContext.Current.Request;
                    var resp = HttpContext.Current.Response;

                    Url = req.RawUrl;

                    Parameters = new Dictionary<string, string>();
                    foreach (var p in req.Params.AllKeys)
                    {
                        var val = req.Params[p];

                        // Shouldn't ask people to trust us with these in the error logs
                        if (p.Equals("password", StringComparison.InvariantCultureIgnoreCase) || p.Equals("password2", StringComparison.InvariantCultureIgnoreCase))
                        {
                            if (val.HasValue())
                            {
                                for (int i = 0; i < val.Length; i++)
                                {
                                    val += "*";
                                }
                            }
                        }
                        Parameters[p] = val;
                    }

                    ReceivedCookies = new Dictionary<string, string>();
                    foreach (var c in req.Cookies.AllKeys)
                    {
                        ReceivedCookies[c] = req.Cookies[c].Value;
                    }

                    SendingCookies = new Dictionary<string, string>();
                    foreach (var c in resp.Cookies.AllKeys)
                    {
                        SendingCookies[c] = resp.Cookies[c].Value;
                    }

                    ReceivedHeaders = new Dictionary<string, string>();
                    foreach (var h in req.Headers.AllKeys)
                    {
                        ReceivedHeaders[h] = req.Headers[h];
                    }

                    SendingHeaders = new Dictionary<string, string>();
                    foreach (var h in resp.Headers.AllKeys)
                    {
                        SendingHeaders[h] = resp.Headers[h];
                    }
                }
                catch (Exception f)
                {
                    Debug.WriteLine(f.Message);
                }

            }

            Message = e.Message;
            StackTrace = e.StackTrace;
            Id = Guid.NewGuid();
            CreationDate = Current.Now;
            Type = e.GetType().FullName;

            try
            {
                if (Current.LoggedInUser != null)
                    UserId = Current.LoggedInUser.ProviderId.ToString();

                // Useful if we've got it
                RemoteIP = Current.RemoteIP;
            }
            catch (Exception) { }
        }

        /// <summary>
        /// Error logging can turn into a DOS attack if its unbounded,
        /// so we're bounding it at 200 errors.
        /// 
        /// Past that, we cull the oldest "*.log" files.
        /// </summary>
        private static void TryCullErrors(string errorLog)
        {
            var files = Directory.EnumerateFiles(errorLog, "*.log");

            if (files.Count() < 200) return;

            var toCull = files.OrderByDescending(e => File.GetCreationTime(e)).Skip(200);

            foreach (var cull in toCull)
                File.Delete(cull);
        }

        /// <summary>
        /// Log this error in the given directory.
        /// </summary>
        public void Log(string path)
        {
            try
            {
                var json = JsonConvert.SerializeObject(this, Formatting.Indented);

                var writeTo = Path.Combine(path, Id + ".log");

                File.WriteAllText(writeTo, json);

                TryCullErrors(path);
            }
            catch (Exception f)
            {
                Debug.WriteLine(f.Message);
            }
        }

        /// <summary>
        /// Loads the first topN errors (by creation date) starting with the (0-based index) one at startingAt.
        /// </summary>
        public static IEnumerable<Error> LoadErrors(string path, int topN, int startingAt)
        {
            var allFiles = Directory.EnumerateFiles(path, "*.log");

            var toLoad = allFiles.OrderByDescending(f => File.GetLastWriteTimeUtc(f)).Skip(startingAt).Take(topN);

            var ret = new List<Error>();

            foreach (var file in toLoad)
            {
                var error = JsonConvert.DeserializeObject<Error>(File.ReadAllText(file));
                error.Location = file;

                ret.Add(error);
            }

            return ret;
        }

        /// <summary>
        /// Load a single error by id.
        /// </summary>
        public static Error LoadError(string path, Guid id)
        {
            var file = Path.Combine(path, id + ".log");

            string json;

            try
            {
                json = File.ReadAllText(file);
            }
            catch (FileNotFoundException) { json = null; }

            if (json == null) return null;

            var ret = JsonConvert.DeserializeObject<Error>(json);
            ret.Location = file;

            return ret;
        }

        /// <summary>
        /// Delete the on disk.
        /// </summary>
        public void Delete()
        {
            if (Location == null) return;

            var copy = Location;
            Location = null;

            try
            {
                File.Delete(copy);
            }
            catch (Exception) { }
        }
    }
}