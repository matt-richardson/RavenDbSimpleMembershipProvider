namespace RavenDbSimpleMembershipProvider.Domain
{
    public class WebpagesRole
    {
        private const string IdPrefix = "authorization/role/";

        public string Id { get; set; }
        public string RoleName { get; set; }

        public WebpagesRole()
        {
            Id = IdPrefix; // db assigns id (appended due to trailing slash)
        }
    }
}
