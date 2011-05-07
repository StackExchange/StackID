-- Create the UserTypes table
IF [dbo].fnTableExists('UserTypes') = 0
BEGIN
	CREATE TABLE [UserTypes]
		([Id] tinyint not null primary key,
	     [Name] nvarchar(50) not null,
	     [Description] nvarchar(300) not null)
	 
	-- Insert Normal and Administrator user types
	   -- explicitly NOT creating any sort of 'suspended' user type
	INSERT INTO [dbo].UserTypes
	([Id], [Name], [Description])
	VALUES
	(1, 'Normal', 'A registered user with an OpenId'),
	(2, 'Administrator', 'A user with access to administrative functions')
END

-- Add UserTypeId column to Users
IF [dbo].fnColumnExists('Users', 'UserTypeId') = 0
BEGIN
	ALTER TABLE [dbo].Users ADD UserTypeId tinyint not null foreign key references UserTypes(Id)
END



GO

