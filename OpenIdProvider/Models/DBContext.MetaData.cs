using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.ComponentModel.DataAnnotations;

/// This meta data maps the various restrictions placed on  Current.WriteDB when accessed
/// in response to a non-POST request.
/// 
/// In Summary, on a non-POST request:
///  - User can be created and updated
///   * UserTypeId cannot
///  - UserHistory can be created only
///   * UserId must be in the restricted id list
///  - UserAttribute can be created or updated
///   * UserId must be in the restricted id list
///  - UserSiteAuthorization can be created only
///   * UserId must be in the restricted id list
///  - PendingUser can have DeletionDate updated
///  
/// All other updates, creations, or deletions are forbidden
namespace OpenIdProvider.Models
{
    [AllowNonPostInsert]
    [MetadataType(typeof(UserMetaData))]
    public partial class User { }

    public class UserMetaData
    {
        [RestrictIdsOnNonPost]
        public int Id { get; set; }

        [ForbidNonPostUpdate]
        public byte UserTypeId { get; set; }
    }

    [AllowNonPostInsert]
    [MetadataType(typeof(UserHistoryMetaData))]
    public partial class UserHistory { }

    public class UserHistoryMetaData
    {
        [RestrictIdsOnNonPost]
        public int UserId { get; set; }
    }

    [AllowNonPostInsert]
    [MetadataType(typeof(UserAttributeMetaData))]
    public partial class UserAttribute { }

    public class UserAttributeMetaData
    {
        [RestrictIdsOnNonPost]
        public int UserId { get; set; }
    }

    [AllowNonPostInsert]
    [MetadataType(typeof(UserSiteAuthorizationMetaData))]
    public partial class UserSiteAuthorization { }

    public class UserSiteAuthorizationMetaData
    {
        [RestrictIdsOnNonPost]
        public int UserId { get; set; }
    }

    [MetadataType(typeof(PendingUserMetaData))]
    public partial class PendingUser { }

    public class PendingUserMetaData
    {
        [AllowNonPostColumnUpdate]
        public DateTime? DeletionDate { get; set; }
    }
}