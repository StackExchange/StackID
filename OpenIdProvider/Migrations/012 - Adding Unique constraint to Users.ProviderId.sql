-- Add a unique constraint to Users.ProviderId
   -- we double check this in code, but it would be *very* bad for it to get into the DB at all

IF dbo.fnConstraintExists('Users', 'Unique_ProviderId') = 0
BEGIN
	ALTER TABLE [dbo].Users ADD CONSTRAINT Unique_ProviderId UNIQUE(ProviderId)
END

