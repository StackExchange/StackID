-- Drop the UserSiteAuthorizations table
   -- We only track name and e-mail, we think its OK to provide those to everyone
   -- accordingly, all this UserSiteAuthorizations stuff is pointless complexity

IF dbo.fnColumnExists('PendingUsers', 'PasswordSalt') = 0
BEGIN
	ALTER TABLE dbo.PendingUsers ADD PasswordSalt nvarchar(29) not null
END

IF dbo.fnColumnExists('PendingUsers', 'PasswordHash') = 0
BEGIN
	ALTER TABLE dbo.PendingUsers ADD PasswordHash nvarchar(31) not null
END