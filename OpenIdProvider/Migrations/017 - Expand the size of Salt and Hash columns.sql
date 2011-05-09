-- Switching away from BCrypt, having to roll our own "Iterations" encoding in the Salt
   -- Accordingly, the salt and hash fields have gotten larger

ALTER TABLE dbo.Users ALTER COLUMN PasswordHash nvarchar(32)
ALTER TABLE dbo.Users ALTER COLUMN PasswordSalt nvarchar(33)
ALTER TABLE dbo.Users ALTER COLUMN EmailHash nvarchar(32)

ALTER TABLE dbo.PendingUsers ALTER COLUMN PasswordHash nvarchar(32)
ALTER TABLE dbo.PendingUsers ALTER COLUMN PasswordSalt nvarchar(33)