-- Create the Affiliates table
    -- Id, OwnerUserId, and CreationDate are obvious
	-- VerificationModulus is a RSA modulus, used to verify signatures (exponent is fixed at a popular value [0x10001])
	   -- we present the other half to a user during affiliate registration, and then discard
	   -- this means that affiliate codes are irrecoverable, but also makes it highly unlikely
	   -- that they can be forged
	-- HostFilter is address of this affiliate site
	   -- may optionally begin with *. to indicate that all domains 'under' the given one may
	   -- also use the same code
	   -- For example: *.example.com would match "example.com" "test.example.com" "login.example.com" etc.
	   -- wildcards are not valid on top-level domains (ie. *.com is no-good)

IF dbo.fnTableExists('Affiliates') = 0
BEGIN
	CREATE TABLE [Affiliates]
		([Id] int not null primary key identity,
		 [OwnerUserId] int not null foreign key references Users(Id),
		 [VerificationModulus] nvarchar(172) not null unique,
		 [HostFilter] nvarchar(100) not null unique,
		 [CreationDate] datetime not null)
		 
	-- Anticipate lookups based on
	   -- OwnerUserId
	CREATE INDEX Affiliates_OwnerUserId ON Affiliates(OwnerUserId)
END

