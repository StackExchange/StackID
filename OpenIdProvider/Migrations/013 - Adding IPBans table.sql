-- Create the IPBans table
   -- We'll actually handle the initial "decided to ban this IP" logic and tracking in code/cache
   -- but once they're in the can, write it to the DB for permanence

IF dbo.fnTableExists('IPBans') = 0
BEGIN
	CREATE TABLE [IPBans]
		([Id] int not null primary key identity,
		 [IP] nvarchar(41) not null,
		 [CreationDate] datetime not null,
		 [ExpirationDate] datetime not null,
		 [Reason] nvarchar(400) not null)
		 
    -- Anticipate searching by IP & ExpirationDate
    CREATE INDEX IPBans_IP_ExpirationDate ON IPBans([IP],[ExpirationDate])
END