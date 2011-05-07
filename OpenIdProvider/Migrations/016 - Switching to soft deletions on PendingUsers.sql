-- Drop the UserSiteAuthorizations table
   -- We only track name and e-mail, we think its OK to provide those to everyone
   -- accordingly, all this UserSiteAuthorizations stuff is pointless complexity

IF dbo.fnColumnExists('PendingUsers', 'DeletionDate') = 0
BEGIN
	ALTER TABLE dbo.PendingUsers ADD DeletionDate datetime null
END

IF dbo.fnConstraintExists('PendingUsers', 'PendingUsers_Token') = 1
BEGIN
	DROP Index PendingUsers_Token ON dbo.PendingUsers
END

IF dbo.fnConstraintExists('PendingUsers', 'PendingUsers_AuthCode_DeletionDate') = 0
BEGIN
	CREATE INDEX PendingUsers_AuthCode_DeletionDate ON dbo.PendingUsers(AuthCode, DeletionDate)
END