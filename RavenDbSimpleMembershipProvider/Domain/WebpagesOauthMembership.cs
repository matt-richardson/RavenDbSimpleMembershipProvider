using System;

namespace RavenDbSimpleMembershipProvider.Domain
{
    public class WebpagesOauthMembership
    {
        private const string IdPrefix = "authorization/oauthmembership/";

        public string Id { get; set; }
        public string Provider { get; set; }
        public string ProviderUserId { get; set; }
        public string UserId { get; set; }

        public WebpagesOauthMembership()
        {
            Id = IdPrefix; // db assigns id (appended due to trailing slash)
        }

        internal int IdAsInt()
        {
            return Convert.ToInt32(Id.Replace(IdPrefix, ""));
        }
    }
}