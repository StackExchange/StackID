Setup
=====

1. Setup a database
   - We assume SQL Server 2008 R2, although we aren't using anything too fancy so you might get away with something else.
   - Run make-db-build-script.bat in \OpenIdProvider\Migrations\ to create a build.sql file
   - Create a new database in SSMS and run build.sql on it.
2. Configure Web.config
   - ReadConnectionString should specify a connection to the new database with *READ ONLY* permissions
   - WriteConnectionString should specify a connection to the new database with *READ AND WRITE* permissions
   - KeyStore can be ignored for now, we'll get back to it
   - SiteName can be anything
   - ReCaptchaPublicKey & ReCaptchaPrivateKey need to be obtained from http://www.google.com/recaptcha
   - HashIterations is the "work factor" for password hashing, it can be changed at anytime and the system will recover gracefully.
   - Configure <mailSettings> section (see: http://msdn.microsoft.com/en-us/library/w355a94k.aspx), basically any SMTP mail server should be fine.
     * No fancy signing options are supported
3. Setup the site in IIS
   - WebDev will not work, as StackID plays some header games
4. Generate a new key file
   - run StackID under either DEBUG build, and hit /admin/key-gen
   - place the result in a json array, tweak the version # down (0 is the lowest acceptable id, and generally what you want to setup with)
   - save the result into a text file
   - place the full path to the file into KeyStore
     * Note, on a production system KeyStore should be on a *heavily monitored* share not a web tier machine
5. Sign up for an account
6. Flip the UserTypeId to 2 on your new (and now administrative) account via SSMS (or some other direct SQL query)
   - We intentionally don't set this field via code anywhere, so setting up an admin account is a bit painfull... by design.

SSL Notes
=========

If you're using an accelerator (Stack Exchange Inc. uses nginx, http://nginx.org/) you can configure StackID to use it.

In Web.config add an appSetting key LoadBalancerIP with your load balancer IP address.
 * ex: <add key="LoadBalancerIP" value="127.0.0.1" />

Configure your load balancer to place the "X-Forwarded-Proto" header on incoming requests with a value of "https".
 * This isn't super flexible, but... well, SSL acceleration isn't super flexible either.

Long, Boring, Security Discussion
=================================

The overriding principle of this project is that no single failure should be catastrophic, ie. defense in depth.
Where possible, we're making it very hard to do the wrong thing in the code.

Things worth protecting:
 - email addresses
 - user attributes (real names, etc.)
 - passwords

 Explicit threats protected against:
  - attacker with read/write db access (but no keys)
  - attacker with keys, but no db access
  - XSS/XSRF
  - Man in the Middle Attacks

Tricks
------

1. There are two connection strings, a ReadOnly and a Write one.
   Access to a DBContext with the Write connection string is restricted to:
     - POSTs
     - updates to records owned by the currently logged in user

   This greatly reduces the attack surface of the application, as the majority of requests
   are not capable of affecting the database.

2. No SQL
   Not the sexy kind of No SQL, the "no strings" kind.  Relying entirely on LINQ for db 
   access kills the entire class of SQL injection attacks.

   We're protected from LINQ bugs/attacks to a small degree by our distinct connection strings (#1).

   There is a bit of loss on perf, but in the name of security its acceptable.  We have the option
   of tightening it up some with compiled queries.

3. No token storage
   Excluding values that need to be recoverable (User.ProviderId, primarily) nothing for which
   possession is significant (passwords, account recovery tokens, registration tokens, etc.) is stored
   directly in the database.

   Instead, we store a one-way hash of the value.  This protects "in flight" requests from being compromised
   by (partial or total) database leaks.

3. XSRF tokens
   Nearly all updates occur in reponse to POSTs (#1), and POSTs themselves are protected by requiring
   a randomly generated token (which is not stored, it is instead transient in memory for a small fixed time).

   This provides protection from Cross Site Request Forgery by requiring that both the user and the page
   submitting the POST request posses secret values (a session cookie and a XSRF token, respectively).

4. Database independent encryption
   Sensitive values that need to be recovered (ie. NOT passwords) are encrypted using keys stored outside
   the database.  Some examples of these values would be email addresses (required) and users' real names
   (optional).

   Storing these values *in* the database would be pointless, so they are held on a separate filesystem.
   Ideally this file system would be locked down hard, and closely monitored.

   Since the keys are just as much a target for attackers as the database, we have provisions for re-keying 
   (and re-hashing) all values in the database.

5. HTTPS
   We force all pages (with a few "is the site even up" monitoring exceptions) to be sent over HTTPS.
   It is sometimes adventageous to use another machine to do the actual SSL bits of HTTPS, and as such
   we include some provisions for that case.

   This effectively eliminates the possibility of Man in the Middle Attacks.

   Note that a Debug_HTTP build configuration exists for development purposes, but SSL is expected (or an SSL accelerator) for all Release builds.