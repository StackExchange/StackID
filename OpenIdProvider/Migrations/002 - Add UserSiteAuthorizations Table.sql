-- Create UserSiteAuthorizations table

IF dbo.fnTableExists('UserSiteAuthorizations') = 0
BEGIN
	CREATE TABLE [UserSiteAuthorizations]
		([Id] int not null primary key identity,
		 [UserId] int not null foreign key references Users(Id),
		 [UserAttributeTypeId] tinyint not null foreign key references UserAttributeTypes(Id),
		 [CreationDate] datetime not null,
		 [SiteHostAddress] nvarchar(255) not null)
END

GO

-- Anticipated search for user site authorizations by:
   -- UserId & SiteHostAddress

IF dbo.fnIndexExists('UserSiteAuthorizations', 'UserSiteAuthorizations_UserId_SiteHostAddress') = 0
BEGIN
	CREATE INDEX UserSiteAuthorizations_UserId_SiteHostAddress ON UserSiteAuthorizations(UserId, SiteHostAddress)
END

