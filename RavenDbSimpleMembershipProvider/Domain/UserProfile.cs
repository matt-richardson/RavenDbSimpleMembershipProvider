using System;
using System.Collections.Generic;

namespace RavenDbSimpleMembershipProvider.Domain
{
    public class UserProfile
    {
        private const string IdPrefix = "authorization/userprofile/";

        public string Id { get; set; }
        public string UserName { get; set; }
        public IList<string> Roles { get; set; }

        public UserProfile()
        {
            Id = IdPrefix; // db assigns id (appended due to trailing slash)
            Roles = new List<string>();
        }

        public static string ToRavenDbId(int userId)
        {
            return IdPrefix + userId;
        }

        internal int IdAsInt()
        {
            return Convert.ToInt32(Id.Replace(IdPrefix, ""));
        }
    }
}