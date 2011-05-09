-- Switching to soft deletions on PendingUsers
   -- Hard deletes just cause too many diagnostic problems, though we'll still probably
   -- need to start culling these at some point

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