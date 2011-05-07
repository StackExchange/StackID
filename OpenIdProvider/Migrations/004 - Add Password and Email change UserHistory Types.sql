-- Add PasswordChanged and EmailChanged user history types

IF NOT EXISTS (SELECT * FROM [dbo].UserHistoryTypes WHERE [Id] = 3)
BEGIN
	INSERT INTO [dbo].[UserHistoryTypes]
			  ([Id]
			   ,[Name]
			   ,[Description])
		 VALUES
			   (3
			   ,'PasswordChanged'
			   ,'User changed their password.')
END
GO

IF NOT EXISTS (SELECT * FROM [dbo].UserHistoryTypes WHERE [Id] = 4)
BEGIN
	INSERT INTO [dbo].[UserHistoryTypes]
			  ([Id]
			   ,[Name]
			   ,[Description])
		 VALUES
			   (4
			   ,'EmailChanged'
			   ,'User changed their email.')
END
GO

