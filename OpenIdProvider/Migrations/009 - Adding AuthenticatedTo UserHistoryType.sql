-- Add AuthenticatedTo UserHistoryType
IF NOT EXISTS(SELECT * FROM [dbo].UserHistoryTypes WHERE [Id] = 6)
BEGIN
	INSERT INTO [dbo].UserHistoryTypes
				([Id]
			    ,[Name]
			    ,[Description])
		   VALUES
			    (6
			    ,'AuthenticatedTo'
			    ,'User authenticated to another website via OpenId.')
END

GO

