-- Add a PasswordVersion column to Users
   -- this is used to indicate that a non-standard password/salt combo exists for a user
   -- it will be converted to the "proper" password format

IF dbo.fnColumnExists('Users', 'PasswordVersion') = 0
BEGIN
	ALTER TABLE dbo.Users ADD PasswordVersion tinyint null
END