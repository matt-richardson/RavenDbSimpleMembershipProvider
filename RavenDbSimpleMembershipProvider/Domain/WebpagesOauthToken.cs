namespace RavenDbSimpleMembershipProvider.Domain
{
    public class WebpagesOauthToken
    {
        private const string IdPrefix = "authorization/oauthtoken/";

        public string Id { get; set; }
        public string Token { get; set; }
        public string Secret { get; set; }

        public WebpagesOauthToken()
        {
            Id = IdPrefix; // db assigns id (appended due to trailing slash)
        }
    }
}