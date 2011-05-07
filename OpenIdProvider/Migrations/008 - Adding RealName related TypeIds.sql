-- Add RealName UserAttributeType
IF NOT EXISTS(SELECT * FROM [dbo].UserAttributeTypes WHERE [Id] = 2)
BEGIN
	INSERT INTO [dbo].UserAttributeTypes
				([Id]
			    ,[Name]
			    ,[Description])
		   VALUES
			    (2
			    ,'RealName'
			    ,'A user''s real name, as self-reported.')
END

GO

-- Adding RealNameChange UserHistoryType
IF NOT EXISTS(SELECT * FROM [dbo].UserHistoryTypes WHERE [Id] = 5)
BEGIN
	INSERT INTO [dbo].UserHistoryTypes
				([Id]
				,[Name]
				,[Description])
		   VALUES
				(5
				,'RealNameChanged'
				,'User changed their real name.')
END

GO

