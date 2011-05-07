-- Add Email attribute type
IF NOT EXISTS (SELECT * FROM [dbo].UserAttributeTypes WHERE [Id] = 1)
BEGIN
	INSERT INTO [dbo].[UserAttributeTypes]
			   ([Id]
			   ,[Name]
			   ,[Description])
		 VALUES
			   (1
			   ,'Email'
			   ,'A user''s primary, and verified, email address.')
END

GO

-- Add Login and Logout user history types

IF NOT EXISTS (SELECT * FROM [dbo].UserHistoryTypes WHERE [Id] = 1)
BEGIN
	INSERT INTO [dbo].[UserHistoryTypes]
			  ([Id]
			   ,[Name]
			   ,[Description])
		 VALUES
			   (1
			   ,'Login'
			   ,'User logged into provider.')
END

GO

IF NOT EXISTS (SELECT * FROM [dbo].UserHistoryTypes WHERE [Id] = 2)
BEGIN
	INSERT INTO [dbo].[UserHistoryTypes]
			  ([Id]
			   ,[Name]
			   ,[Description])
		 VALUES
			   (2
			   ,'Logout'
			   ,'User explicitly logged out of provider.')
END

GO

