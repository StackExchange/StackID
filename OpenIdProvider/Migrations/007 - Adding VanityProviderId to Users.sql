-- Add the VanityProviderId column to Users

IF dbo.fnColumnExists('Users', 'VanityProviderId') = 0
BEGIN
	ALTER TABLE [dbo].Users ADD VanityProviderId nvarchar(40) NULL

	-- Anticipate needing to do lookups on this column	
	CREATE INDEX Users_VanityProviderId ON Users(VanityProviderId)
END

