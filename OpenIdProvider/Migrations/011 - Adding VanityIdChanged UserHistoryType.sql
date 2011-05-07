-- Add the VanityIdChanged UserHistoryType
IF NOT EXISTS(SELECT * FROM [dbo].[UserHistoryTypes] WHERE Id = 7)
BEGIN
	INSERT INTO [dbo].[UserHistoryTypes]
			   ([Id]
			   ,[Name]
			   ,[Description])
		 VALUES
			   (7
			   ,'VanityIdChanged'
			   ,'User changed their vanity id.')
END

GO
