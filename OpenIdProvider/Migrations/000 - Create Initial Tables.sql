-- Create some migration helper functions

	-- drop functions if they exist
	IF OBJECT_ID('fnColumnExists') IS NOT NULL
	BEGIN
		 DROP FUNCTION fnColumnExists
	END
	
    IF OBJECT_ID('fnIndexExists') IS NOT NULL
	BEGIN
		 DROP FUNCTION fnIndexExists
	END
	
	IF OBJECT_ID('fnTableExists') IS NOT NULL
	BEGIN
		DROP FUNCTION fnTableExists
	END
	
	IF OBJECT_ID('fnConstraintExists') IS NOT NULL
	BEGIN
		DROP FUNCTION fnConstraintExists
	END
	
	GO

	-- create fnColumnExists(table, column)
	CREATE FUNCTION fnColumnExists(
		@table_name nvarchar(max),
		@column_name nvarchar(max) 
	)
	RETURNS bit 
	BEGIN  
		DECLARE @found bit
		SET @found = 0
		IF	EXISTS (
				SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS 
				WHERE TABLE_NAME = @table_name AND COLUMN_NAME = @column_name ) 
		BEGIN
			SET @found = 1
		END
		 
		
		RETURN @found
	END
	GO

	-- create fnIndexExists(table, index)
	CREATE FUNCTION fnIndexExists(
		@table_name nvarchar(max),
		@index_name nvarchar(max) 
	)
	RETURNS bit 
	BEGIN  
		DECLARE @found bit
		SET @found = 0
		IF	EXISTS (
				SELECT 1 FROM sys.indexes
				WHERE object_id = OBJECT_ID(@table_name) AND name = @index_name ) 
		BEGIN
			SET @found = 1
		END
		 
		
		RETURN @found
	END
	GO

	-- create fnTableExists(table)
	-- see: http://stackoverflow.com/questions/167576/sql-server-check-if-table-exists/167680#167680
	CREATE FUNCTION fnTableExists(
		@table_name nvarchar(max)
	)
	RETURNS bit
	BEGIN
		DECLARE @found bit
		SET @found = 0
		IF EXISTS (
			SELECT 1 FROM INFORMATION_SCHEMA.TABLES WHERE 
				TABLE_TYPE = 'BASE TABLE' AND  
				TABLE_NAME = @table_name)
		BEGIN
			SET @found = 1
		END
		
		RETURN @found
	END
	GO
	
	--create fnConstraintExists(table, constraint)
	CREATE FUNCTION fnConstraintExists(
		@table_name nvarchar(max),
		@constraint_name nvarchar(max)
	)
	RETURNS bit
	BEGIN
		DECLARE @found  bit
		SET @found = 0
		IF EXISTS (
			SELECT 1 FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS WHERE
				TABLE_NAME = @table_name AND
				CONSTRAINT_NAME = @constraint_name)
		BEGIN
			SET @found = 1
		END
		
		RETURN @found
	END
	GO

-- Create the Users table

	-- Id and LastActivityDate are clear

	-- EmailHash for easy lookup (should be salted with a *system* common salt, just to make correlation difficult)
	   -- EmailHashSalt is a copy of the system salt, so we don't have to resalt everything at once (which is potentially quite expensive)
	-- EmailEncrypted is the users e-mail, encrypted with a system wide symmetric cipher
	   -- EmailEncryptedKeyVersion is the key version used, for error recovery purposes if we ever need to re-key the database
	   -- Note that 152 base64 chars is the # of chars needed to encoded an encrypted 100 char email

	-- PasswordHash is a obvious (but does not contain a copy of the salt, which isn't)
	   -- PasswordSalt is the corresponding salt.  This is pulled out to make determining
	   -- which users need password rehashing easier, should we ever need to crank the # of
	   -- hashing rounds up
	-- ProviderId is random, and forms the "/user/PROVIDER_ID" part of an openid url
	-- SessionHash is a hash of the user's currently valid login session, if any

IF dbo.fnTableExists('Users') = 0
BEGIN
	CREATE TABLE [Users]
		([Id] int not null primary key identity,
		 [CreationDate] datetime not null,
		 [LastActivityDate] datetime not null,
		 [EmailHash] nvarchar(31) not null,
		 [EmailSaltVersion] tinyint not null,
		 [PasswordHash] nvarchar(31) not null,
		 [PasswordSalt] nvarchar(29) not null,
		 [ProviderId] uniqueidentifier not null,
		 [SessionHash] nvarchar(28) null,
		 [SessionCreationDate] datetime null)

	-- Anticipating search for users by:
	   -- Email
	   -- ProviderId
	   -- Session
	CREATE UNIQUE INDEX Users_EmailHash_EmailSaltVersion ON Users(EmailHash,EmailSaltVersion)
	CREATE INDEX Users_ProviderId ON Users(ProviderId)
	CREATE INDEX Users_SessionHash ON Users(SessionHash)
END

GO

-- Create UserAttributeTypes table

IF dbo.fnTableExists('UserAttributeTypes') = 0
BEGIN
	CREATE TABLE [UserAttributeTypes]
		([Id] tinyint not null primary key,
		 [Name] nvarchar(50) not null,
		 [Description] nvarchar(300) not null)
END

GO

-- Create UserAttributes table

IF dbo.fnTableExists('UserAttributes') = 0
BEGIN
	CREATE TABLE [UserAttributes]
		([Id] int not null primary key identity,
		 [UserId] int not null foreign key references Users(Id),
		 [UserAttributeTypeId] tinyint not null foreign key references UserAttributeTypes(Id),
		 [CreationDate] datetime not null,
		 [Encrypted] nvarchar(267) not null,	-- This should be about 200 characters for plaintext value
		 [HMAC] nvarchar(28) not null,
		 [IV] nvarchar(24) not null,
		 [KeyVersion] tinyint not null)
	 
	-- Anticipated search for attributes by:
	   -- UserId & UserAttributeType
	CREATE INDEX UserAttributes_UserId_UserAtributeTypeId ON UserAttributes(UserId, UserAttributeTypeId)
END

GO

-- Create UserHistoryTypes table

IF dbo.fnTableExists('UserHistoryTypes') = 0
BEGIN
	CREATE TABLE [UserHistoryTypes]
		([Id] tinyint not null primary key,
		 [Name] nvarchar(50) not null,
		 [Description] nvarchar(300) not null)
END

GO

-- Create UserHistory table

IF dbo.fnTableExists('UserHistory') = 0
BEGIN
	CREATE TABLE [UserHistory]
		([Id] int not null primary key identity,
		 [UserHistoryTypeId] tinyint not null foreign key references UserHistoryTypes(Id),
		 [UserId] int not null foreign key references Users(Id),
		 [CreationDate] datetime not null,
		 [Comment] nvarchar(400) not null,
		 [IP] nvarchar(41) not null)	-- Might as well allocate enough space for IPv6 addresses
		 
	-- Anticipated search for user history by:
	   -- UserId and UserHistoryType
	   -- UserId and CreationDate
	CREATE INDEX UserHistory_UserId_UserHistoryTypeId ON UserHistory(UserId, UserHistoryTypeId)
	CREATE INDEX UserHistory_UserId_CreationDate ON UserHistory(UserId, CreationDate)
END

GO

