using System;

namespace RavenDbSimpleMembershipProvider.Domain
{
    public class WebpagesMembership
    {
        private const string IdPrefix = "authorization/membership/";

        public string Id { get; set; }
        public string UserId { get; set; }
        public string ConfirmationToken { get; set; }
        public DateTime? CreateDate { get; set; }
        public bool IsConfirmed { get; set; }
        public DateTime? LastPasswordFailureDate { get; set; }
        public string Password { get; set; }
        public DateTime? PasswordChangedDate { get; set; }
        public int PasswordFailuresSinceLastSuccess { get; set; }
        public string PasswordSalt { get; set; }
        public string PasswordVerificationToken { get; set; }
        public DateTime? PasswordVerificationTokenExpirationDate { get; set; }

        public WebpagesMembership()
        {
            Id = IdPrefix; // db assigns id (appended due to trailing slash)
        }

        internal int UserIdAsInt()
        {
            return Convert.ToInt32(Id.Replace(IdPrefix, ""));
        }
    }
}