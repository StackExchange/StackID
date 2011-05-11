using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.ComponentModel.DataAnnotations;
using System.Reflection;
using System.Data.Linq;

namespace OpenIdProvider.Models
{
    /// <summary>
    /// When placed on a class, denotes that instances of this class can be *inserted* as a result of a non-POST request.
    /// </summary>
    [AttributeUsage(AttributeTargets.Class, AllowMultiple = false)]
    class AllowNonPostInsertAttribute : Attribute { }

    /// <summary>
    /// When placed on a class, denotes that instances of this class can be *updated* as a result of a non-POST request.
    /// </summary>
    [AttributeUsage(AttributeTargets.Class, AllowMultiple = false)]
    class AllowNonPostUpdateAttribute : Attribute { }

    /// <summary>
    /// When placed on a property, denotes that the value must be one of the explicitly permitted ids if its row is being updated.
    /// 
    /// Implicitly ops the class that declares the property to allow updates.
    /// 
    /// These ids are generally those of newly inserted rows, or the currently logged in user's id.
    /// 
    /// Example:
    ///  Changing CreationDate on a User of Id = 2, you'd need to provide '2' because User.Id has this property.
    /// </summary>
    [AttributeUsage(AttributeTargets.Property, AllowMultiple = false)]
    class RestrictIdsOnNonPostAttribute : Attribute { }

    /// <summary>
    /// When placed on a field of an object with one of the Allow*NonPost attributes,
    /// it restricts updates to that field *anyway*.
    /// </summary>
    [AttributeUsage(AttributeTargets.Property, AllowMultiple = false)]
    class ForbidNonPostUpdateAttribute : Attribute { }

    /// <summary>
    /// When placed on a field of an object that does *not* have one of the Allow*NonPost attributes,
    /// it allows that single field to be updated modified as part ofa  non-POST request.
    /// </summary>
    [AttributeUsage(AttributeTargets.Property, AllowMultiple = false)]
    class AllowNonPostColumnUpdate : Attribute { }

    /// <summary>
    /// Models and checks update restriction on a DataContext.
    /// 
    /// See the above attributes for what restrictions are supported on
    /// linq model objects.
    /// </summary>
    public class Restrictions
    {
        public class ShadowModifiedMember
        {
            public MemberInfo Member { get; set; }
            public object CurrentValue { get; set; }
            public object OriginalValue { get; set; }
        }

        private HashSet<Type> InsertsAllowed;
        private HashSet<Type> UpdatesAllowed;

        private Dictionary<Type, HashSet<MemberInfo>> ForbiddenColumns;
        private Dictionary<Type, HashSet<MemberInfo>> AllowedColumns;
        private Dictionary<Type, HashSet<MemberInfo>> RestrictedColumns;

        public Restrictions()
        {
            var asm = GetType().Assembly;

            var withMetaData =
                asm.GetTypes().Where(
                    a => a.GetCustomAttributes(typeof(MetadataTypeAttribute), false).Count() > 0
                ).Select(p => new { Type = p, Attribute = (MetadataTypeAttribute)p.GetCustomAttributes(typeof(MetadataTypeAttribute), false).Single() }
                ).ToDictionary(p => p.Attribute.MetadataClassType, p => p.Type);

            InsertsAllowed = new HashSet<Type>(GetTypeAttributes<AllowNonPostInsertAttribute>(asm));
            UpdatesAllowed = new HashSet<Type>(GetTypeAttributes<AllowNonPostUpdateAttribute>(asm));

            var forbiddenColumns = GetPropertyAttributes<ForbidNonPostUpdateAttribute>(asm);
            var allowedColumns = GetPropertyAttributes<AllowNonPostColumnUpdate>(asm);
            var restrictedColumns = GetPropertyAttributes<RestrictIdsOnNonPostAttribute>(asm);

            var fcGrouped = forbiddenColumns.GroupBy(g => g.DeclaringType);
            var acGrouped = allowedColumns.GroupBy(g => g.DeclaringType);
            var rcGrouped = restrictedColumns.GroupBy(g => g.DeclaringType);

            ForbiddenColumns = fcGrouped.ToDictionary(g => g.Key, h => new HashSet<MemberInfo>(h.AsEnumerable()));
            AllowedColumns = acGrouped.ToDictionary(g => g.Key, h => new HashSet<MemberInfo>(h.AsEnumerable()));
            RestrictedColumns = rcGrouped.ToDictionary(g => g.Key, h => new HashSet<MemberInfo>(h.AsEnumerable()));

            ForbiddenColumns = MapMetaData(ForbiddenColumns, withMetaData);
            AllowedColumns = MapMetaData(AllowedColumns, withMetaData);
            RestrictedColumns = MapMetaData(RestrictedColumns, withMetaData);
        }

        private static Dictionary<Type, HashSet<MemberInfo>> MapMetaData(Dictionary<Type, HashSet<MemberInfo>> toMap, Dictionary<Type, Type> metaDataToReal)
        {
            var ret = new Dictionary<Type, HashSet<MemberInfo>>();

            foreach (var k in toMap.Keys)
            {
                Type mapTo;
                if (!metaDataToReal.TryGetValue(k, out mapTo))
                {
                    ret[k] = toMap[k];
                    continue;
                }

                var copy = new HashSet<MemberInfo>();
                foreach (var m in toMap[k])
                {
                    copy.Add(mapTo.GetProperty(m.Name));
                }

                ret[mapTo] = copy;
            }

            return ret;
        }

        private static IEnumerable<MemberInfo> GetPropertyAttributes<T>(Assembly asm)
            where T : Attribute
        {
            foreach (Type type in asm.GetTypes())
            {
                foreach (PropertyInfo p in type.GetProperties())
                {
                    if (p.GetCustomAttributes(typeof(T), true).Length > 0)
                    {
                        yield return p;
                    }
                }
            }
        }

        // See: http://stackoverflow.com/questions/607178/c-how-enumerate-all-classes-with-custom-class-attribute/607204#607204
        private static IEnumerable<Type> GetTypeAttributes<T>(Assembly asm)
            where T : Attribute
        {
            foreach (Type type in asm.GetTypes())
            {
                if (type.GetCustomAttributes(typeof(T), true).Length > 0)
                {
                    yield return type;
                }
            }
        }

        public bool IsValidChangeSet(Dictionary<object, ShadowModifiedMember[]> changes, IList<object> deletes, IList<object> inserts, IList<object> updated, List<int> permittedIds, out string error)
        {
            // Absolutely *no* deletes in restricted mode
            if (deletes.Count > 0)
            {
                error = "illegal hard delete";
                return false;
            }

            if (inserts.Count > 0)
            {
                foreach (var i in inserts)
                {
                    var t = i.GetType();

                    // Only explicitly allowed inserts are valid
                    if (!InsertsAllowed.Contains(t))
                    {
                        error = "illegal insert of " + t.Name;
                        return false;
                    }

                    // Even in explicitly allowed inserts, id restrictions must be honored
                    HashSet<MemberInfo> restricted;
                    if (RestrictedColumns.TryGetValue(t, out restricted))
                    {
                        foreach (var m in restricted.Cast<PropertyInfo>())
                        {
                            var check = (int)m.GetValue(i, null);
                            if (!permittedIds.Contains(check))
                            {
                                error = "illegal id placed into " + m.Name + " of " + t.Name + ", " + check;
                                return false;
                            }
                        }
                    }
                }
            }

            if (updated.Count > 0)
            {
                foreach (var i in updated)
                {
                    var t = i.GetType();
                    var modified = changes[i];

                    // Any columns that have explicit "do not update" attributes trigger a rejection
                    HashSet<MemberInfo> explicitForbid;
                    if (ForbiddenColumns.TryGetValue(t, out explicitForbid))
                    {
                        if (modified.Any(m => explicitForbid.Contains(m.Member)))
                        {
                            error = "illegal update (" + i + ") of type " + t.Name;
                            return false;
                        }
                    }

                    // Any columns with an id constraint need to be checked too
                    HashSet<MemberInfo> restricted;
                    if (RestrictedColumns.TryGetValue(t, out restricted))
                    {
                        foreach (var m in restricted)
                        {
                            var value = ((PropertyInfo)m).GetValue(i, null);

                            if (!permittedIds.Contains((int)value))
                            {
                                error = "illegal id placed in " + m.Name + " of " + t.Name + ", " + value;
                                return false;
                            }
                        }

                        // Passed the checks, so equivalent to an [AllowNonPostUpdate]
                        continue;
                    }

                    // If the whole *row* is good to update, carry on
                    if (UpdatesAllowed.Contains(t)) continue;

                    // Check if any the changeset is covered by single column permissions
                    HashSet<MemberInfo> explicitAllow;
                    if (AllowedColumns.TryGetValue(t, out explicitAllow))
                    {
                        if (modified.All(m => explicitAllow.Contains(m.Member)))
                            continue;
                    }

                    error = "illegal update to (" + i + ") of type " + t.Name;
                    return false;
                }
            }

            error = null;
            return true;
        }

        public bool IsValidChangeSet(DataContext context, List<int> permittedIds, out string error)
        {
            var changes = context.GetChangeSet();
            var updates = new Dictionary<object, ShadowModifiedMember[]>();

            foreach (var m in changes.Updates)
            {
                var modified = context.GetTable(m.GetType()).GetModifiedMembers(m);

                updates[m] =
                    modified.Select(
                        x =>
                            new ShadowModifiedMember
                            {
                                Member = x.Member,
                                CurrentValue = x.CurrentValue,
                                OriginalValue = x.OriginalValue
                            }
                    ).ToArray();
            }

            return IsValidChangeSet(updates, changes.Deletes, changes.Inserts, changes.Updates, permittedIds, out error);
        }
    }
}