Long, Boring, Security Discussion
=================================

The overriding principle of this project is that no single failure should be catastrophic, ie. defense in depth.
Where possible, we're making it very hard to do the wrong thing in the code.

Things worth protecting:
 - e-mail addresses
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
   of tightening it up some compiled queries.

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
   the database.  Some examples of these values would be e-mail addresses (required) and users' real names
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