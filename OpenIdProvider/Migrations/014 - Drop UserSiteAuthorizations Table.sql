-- Drop the UserSiteAuthorizations table
   -- We only track name and email, we think its OK to provide those to everyone
   -- accordingly, all this UserSiteAuthorizations stuff is pointless complexity

IF dbo.fnTableExists('UserSiteAuthorizations') = 1
BEGIN
	DROP TABLE UserSiteAuthorizations
END