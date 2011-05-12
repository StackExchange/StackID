-- Create the PasswordResets table

IF dbo.fnTableExists('PasswordResets') = 0
BEGIN
	CREATE TABLE [PasswordResets]
		([Id] int not null primary key identity,
		 [UserId] int not null foreign key references Users([Id]),
		 [TokenHash] nvarchar(31) not null,
		 [CreationDate] datetime not null)
END

GO
		 
	-- Anticipated lookups by
	   -- TokenHash

IF dbo.fnIndexExists('PasswordResets', 'PasswordResets_Token') = 0
BEGIN
	CREATE INDEX PasswordResets_Token ON PasswordResets([TokenHash])
END

GO
	
-- Create PendingUsers table

IF dbo.fnTableExists('PendingUsers') = 0
BEGIN
	CREATE TABLE [PendingUsers]
		([Id] int not null primary key identity,
		 -- Ok, this requires some explanation
		    -- We don't want to store an email in plain text, but we can't lookup an encrypted value
		    -- Neither can we just pass a token around, as that token wouldn't be tied to an email
		    -- BUT, if we HMAC a url containing a nonce AND the email address we're sending the "confirm URL" to
		    -- we can validate that a) the email address is valid, b) *we've seen that email before*, because we hmac'd it*
		    -- Means we don't have to store a *hash* of the user's email until they've created an account, which is awesome
		 [AuthCode] nvarchar(28) not null,
		 [CreationDate] datetime not null)
END

GO
		 
	-- Anticipated lookups by
		-- AuthCode

IF dbo.fnIndexExists('PendingUsers', 'PendingUsers_Token') = 0
BEGIN
	CREATE INDEX PendingUsers_Token ON PendingUsers([AuthCode])
END

GO

