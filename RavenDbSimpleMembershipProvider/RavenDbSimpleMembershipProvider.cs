using Raven.Client;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration.Provider;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Web;
using System.Web.Helpers;
using System.Web.Security;
using RavenDbSimpleMembershipProvider.Domain;
using WebMatrix.WebData;

namespace RavenDbSimpleMembershipProvider
{
    public class RavenDbSimpleMembershipProvider : ExtendedMembershipProvider
    {
        public static IDocumentStore DocumentStore { get; set; }

        public override void Initialize(string name, NameValueCollection config)
        {
            if (config == null)
                throw new ArgumentNullException("config");
            if (string.IsNullOrEmpty(name))
            {
                name = "ExtendedAdapterMembershipProvider";
            }
            if (string.IsNullOrEmpty(config["description"]))
            {
                config.Remove("description");
                config.Add("description", "Adapter Extended Membership Provider");
            }
            base.Initialize(name, config);

            ApplicationName = GetValueOrDefault(config, "applicationName", o => o.ToString(), "MySampleApp");

            // membership settings
            EnablePasswordRetrievalInternal = GetValueOrDefault(config, "enablePasswordRetrieval", Convert.ToBoolean, false);
            EnablePasswordResetInternal = GetValueOrDefault(config, "enablePasswordReset", Convert.ToBoolean, true);
            RequiresQuestionAndAnswerInternal = GetValueOrDefault(config, "requiresQuestionAndAnswer", Convert.ToBoolean, false);
            RequiresUniqueEmailInternal = GetValueOrDefault(config, "requiresUniqueEmail", Convert.ToBoolean, true);
            MaxInvalidPasswordAttemptsInternal = GetValueOrDefault(config, "maxInvalidPasswordAttempts", Convert.ToInt32, 3);
            PasswordAttemptWindowInternal = GetValueOrDefault(config, "passwordAttemptWindow", Convert.ToInt32, 10);
            PasswordFormatInternal = GetValueOrDefault(config, "passwordFormat", o =>
             {
                 MembershipPasswordFormat format;
                 return Enum.TryParse(o.ToString(), true, out format) ? format : MembershipPasswordFormat.Hashed;
             }, MembershipPasswordFormat.Hashed);
            MinRequiredPasswordLengthInternal = GetValueOrDefault(config, "minRequiredPasswordLength", Convert.ToInt32, 6);
            MinRequiredNonAlphanumericCharactersInternal = GetValueOrDefault(config, "minRequiredNonalphanumericCharacters", Convert.ToInt32, 1);
            PasswordStrengthRegularExpressionInternal = GetValueOrDefault(config, "passwordStrengthRegularExpression", o => o.ToString(), string.Empty);
            HashAlgorithmType = GetValueOrDefault(config, "hashAlgorithmType", o => o.ToString(), "SHA1");

            config.Remove("name");
            config.Remove("description");
            config.Remove("applicationName");
            config.Remove("connectionStringName");
            config.Remove("enablePasswordRetrieval");
            config.Remove("enablePasswordReset");
            config.Remove("requiresQuestionAndAnswer");
            config.Remove("requiresUniqueEmail");
            config.Remove("maxInvalidPasswordAttempts");
            config.Remove("passwordAttemptWindow");
            config.Remove("passwordFormat");
            config.Remove("minRequiredPasswordLength");
            config.Remove("minRequiredNonalphanumericCharacters");
            config.Remove("passwordStrengthRegularExpression");
            config.Remove("hashAlgorithmType");

            if (config.Count <= 0)
                return;
            var key = config.GetKey(0);
            if (string.IsNullOrEmpty(key))
                return;

            throw new ProviderException(
                string.Format(CultureInfo.CurrentCulture, "The membership provider does not recognize the configuration attribute {0}.", key));
        }

        private string HashAlgorithmType { get; set; }

        public override string ApplicationName { get; set; }

        public override bool EnablePasswordReset
        {
            get { return EnablePasswordResetInternal; }
        }

        private bool EnablePasswordResetInternal { get; set; }

        public override bool EnablePasswordRetrieval
        {
            get { return EnablePasswordRetrievalInternal; }
        }

        private bool EnablePasswordRetrievalInternal { get; set; }

        public override int MaxInvalidPasswordAttempts
        {
            get { return MaxInvalidPasswordAttemptsInternal; }
        }

        private int MaxInvalidPasswordAttemptsInternal { get; set; }

        public override int MinRequiredNonAlphanumericCharacters
        {
            get { return MinRequiredNonAlphanumericCharactersInternal; }
        }

        private int MinRequiredNonAlphanumericCharactersInternal { get; set; }

        public override int MinRequiredPasswordLength
        {
            get { return MinRequiredPasswordLengthInternal; }
        }

        private int MinRequiredPasswordLengthInternal { get; set; }

        public override int PasswordAttemptWindow
        {
            get { return PasswordAttemptWindowInternal; }
        }

        private int PasswordAttemptWindowInternal { get; set; }

        public override MembershipPasswordFormat PasswordFormat
        {
            get { return PasswordFormatInternal; }
        }

        private MembershipPasswordFormat PasswordFormatInternal { get; set; }

        public override string PasswordStrengthRegularExpression
        {
            get { return PasswordStrengthRegularExpressionInternal; }
        }

        private string PasswordStrengthRegularExpressionInternal { get; set; }

        public override bool RequiresQuestionAndAnswer
        {
            get { return RequiresQuestionAndAnswerInternal; }
        }

        private bool RequiresQuestionAndAnswerInternal { get; set; }

        public override bool RequiresUniqueEmail
        {
            get { return RequiresUniqueEmailInternal; }
        }

        private bool RequiresUniqueEmailInternal { get; set; }

        public override bool ConfirmAccount(string accountConfirmationToken)
        {
            using (var session = DocumentStore.OpenSession())
            {
                var account = session.Query<WebpagesMembership>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .FirstOrDefault(x => x.ConfirmationToken == accountConfirmationToken);
                if (account != null)
                {
                    account.IsConfirmed = true;
                    session.Store(account);
                    session.SaveChanges();
                    return true;
                }
                return false;
            }
        }

        public override bool ConfirmAccount(string userName, string accountConfirmationToken)
        {
            using (var session = DocumentStore.OpenSession())
            {
                var user = session.Query<UserProfile>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .FirstOrDefault(x => x.UserName == userName);
                if (user != null)
                {
                    var account = session.Query<WebpagesMembership>()
                        .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                        .FirstOrDefault(x => x.ConfirmationToken == accountConfirmationToken);

                    if (account != null)
                    {
                        account.IsConfirmed = true;
                        session.Store(account);
                        session.SaveChanges();
                        return true;
                    }
                }
                return false;
            }
        }

        public override string CreateUserAndAccount(string userName, string password, bool requireConfirmation, IDictionary<string, object> values)
        {
            CreateUser(userName, values);
            return CreateAccount(userName, password, requireConfirmation);
        }

        public override bool DeleteAccount(string userName)
        {
            using (var session = DocumentStore.OpenSession())
            {
                var user = session.Query<UserProfile>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .FirstOrDefault(x => x.UserName == userName);
                
                if (user == null)
                    return false;
                
                var membership = session.Query<WebpagesMembership>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .FirstOrDefault(x => x.UserId == user.Id);
                
                if (membership == null)
                    return false;
                
                session.Delete(membership);
                session.SaveChanges();
                return true;
            }
        }

        public override string GeneratePasswordResetToken(string userName, int tokenExpirationInMinutesFromNow)
        {
            if (string.IsNullOrEmpty(userName))
                throw new ArgumentException("Username cannot be empty", "UserName");

            using (var session = DocumentStore.OpenSession())
            {
                const bool throwException = true;
                var userId = GetUserIdIfUserNameHasConfirmedAccount(userName, throwException);

                var membership = session.Query<WebpagesMembership>().FirstOrDefault(x => x.UserId == userId);
                if (membership != null)
                {
                    if (membership.PasswordVerificationTokenExpirationDate != null && membership.PasswordVerificationTokenExpirationDate.Value > DateTime.UtcNow)
                    {
                        return membership.PasswordVerificationToken;
                    }
                    var token = GenerateToken();
                    membership.PasswordVerificationToken = token;
                    membership.PasswordVerificationTokenExpirationDate = DateTime.UtcNow.AddMinutes(tokenExpirationInMinutesFromNow);

                    session.Store(membership);
                    session.SaveChanges();

                    return token;
                }
            }
            return string.Empty;
        }

        public override ICollection<OAuthAccountData> GetAccountsForUser(string userName)
        {
            using (var session = DocumentStore.OpenSession())
            {
                var user = session.Query<UserProfile>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .FirstOrDefault(x => x.UserName == userName);
                if (user != null)
                {
                    var oauthMems = session.Query<WebpagesOauthMembership>()
                        .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                        .Where(x => x.UserId == user.Id)
                        .ToList();
                    
                    return oauthMems
                        .Select(x => new OAuthAccountData(x.Provider, x.ProviderUserId))
                        .ToList();
                }
            }
            return new OAuthAccountData[] { };
        }

        public override DateTime GetCreateDate(string userName)
        {
            using (var session = DocumentStore.OpenSession())
            {
                var user = session.Query<UserProfile>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .FirstOrDefault(x => x.UserName == userName);
                if (user != null)
                {
                    var membership = session.Query<WebpagesMembership>()
                        .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                        .FirstOrDefault(x => x.UserId == user.Id);
                    if (membership != null && membership.CreateDate != null)
                    {
                        return membership.CreateDate.Value;
                    }
                }
                return DateTime.MinValue;
            }
        }

        public override DateTime GetLastPasswordFailureDate(string userName)
        {
            using (var session = DocumentStore.OpenSession())
            {
                var user = session.Query<UserProfile>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .FirstOrDefault(x => x.UserName == userName);

                if (user == null)
                    return DateTime.MinValue;
                
                var membership = session.Query<WebpagesMembership>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .FirstOrDefault(x => x.UserId == user.Id);
                
                if (membership != null && membership.LastPasswordFailureDate != null)
                    return membership.LastPasswordFailureDate.Value;
                
                return DateTime.MinValue;
            }
        }

        public override DateTime GetPasswordChangedDate(string userName)
        {
            using (var session = DocumentStore.OpenSession())
            {
                var user = session.Query<UserProfile>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .FirstOrDefault(x => x.UserName == userName);
                if (user == null)
                    return DateTime.MinValue;

                var membership = session.Query<WebpagesMembership>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .FirstOrDefault(x => x.UserId == user.Id);

                if (membership != null && membership.PasswordChangedDate != null)
                    return membership.PasswordChangedDate.Value;
                return DateTime.MinValue;
            }
        }

        public override int GetPasswordFailuresSinceLastSuccess(string userName)
        {
            using (var session = DocumentStore.OpenSession())
            {
                var user = session.Query<UserProfile>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .FirstOrDefault(x => x.UserName == userName);
                if (user == null)
                    throw new InvalidOperationException(string.Format("User {0} does not exist!", userName));

                var membership = session.Query<WebpagesMembership>().FirstOrDefault(x => x.UserId == user.Id);
                if (membership != null)
                    return membership.PasswordFailuresSinceLastSuccess;
                return -1;
            }
        }

        public override int GetUserIdFromPasswordResetToken(string token)
        {
            using (var session = DocumentStore.OpenSession())
            {
                var membership = session.Query<WebpagesMembership>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .FirstOrDefault(x => x.PasswordVerificationToken == token);
                if (membership != null)
                    return membership.UserIdAsInt();
                return -1;
            }
        }

        public override bool IsConfirmed(string userName)
        {
            if (string.IsNullOrEmpty(userName))
                throw new ArgumentException("Username cannot be empty", "UserName");

            const bool throwException = false;
            return (GetUserIdIfUserNameHasConfirmedAccount(userName, throwException) != null);
        }

        public override bool ResetPasswordWithToken(string token, string newPassword)
        {
            if (string.IsNullOrEmpty(newPassword))
                throw new ArgumentException("NewPassword cannot be empty", "newPassword");

            using (var session = DocumentStore.OpenSession())
            {
                var memberships = session.Query<WebpagesMembership>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .Where(x => x.PasswordVerificationToken == token && x.PasswordVerificationTokenExpirationDate > DateTime.UtcNow);

                if (memberships.Count() == 1)
                {
                    var membership = memberships.First();
                    var passwordSet = SetPasswordInternal(session, membership.UserId, newPassword);
                    if (passwordSet)
                    {
                        membership.PasswordVerificationToken = null;
                        membership.PasswordVerificationTokenExpirationDate = null;
                        session.Store(membership);
                        session.SaveChanges();
                    }
                    return passwordSet;
                }
            }
            return false;
        }

        public override bool ChangePassword(string username, string oldPassword, string newPassword)
        {
            if (string.IsNullOrEmpty(username))
                throw new ArgumentException("Username cannot be empty", "UserName");
            if (string.IsNullOrEmpty(oldPassword))
                throw new ArgumentException("OldPassword cannot be empty", "oldPassword");
            if (string.IsNullOrEmpty(newPassword))
                throw new ArgumentException("NewPassword cannot be empty", "newPassword");

            UserProfile user;
            using (var session = DocumentStore.OpenSession())
            {
                user = session.Query<UserProfile>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .FirstOrDefault(x => x.UserName == username);
                if (user == null)
                    return false;

                if (!CheckPassword(session, user.Id, oldPassword))
                    return false;

                var result = SetPasswordInternal(session, user.Id, newPassword);
                session.SaveChanges();
                return result;
            }

        }

        public override bool DeleteUser(string username, bool deleteAllRelatedData)
        {
            using (var session = DocumentStore.OpenSession())
            {
                var user = session.Query<UserProfile>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .FirstOrDefault(x => x.UserName == username);
                if (user == null)
                    return false;

                if (deleteAllRelatedData)
                {
                    //TODO: delete some stuff here
                }

                var oauthMemberships = session.Query<WebpagesOauthMembership>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .Where(x => x.UserId == user.Id);
                
                foreach (var oauthMembership in oauthMemberships)
                    session.Delete(oauthMembership);

                var memberships = session.Query<WebpagesMembership>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .Where(x => x.UserId == user.Id);
                
                foreach (var membership in memberships)
                    session.Delete(membership);

                session.Delete(user);

                session.SaveChanges();

                return true;
            }
        }

        public override MembershipUser GetUser(string username, bool userIsOnline)
        {
            using (var session = DocumentStore.OpenSession())
            {
                var user = session.Query<UserProfile>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .FirstOrDefault(x => x.UserName == username);
                if (user == null)
                    return null;

                return new MembershipUser(Membership.Provider.Name, username, user.IdAsInt(), null, null, null, true, false, DateTime.MinValue, DateTime.MinValue, DateTime.MinValue, DateTime.MinValue, DateTime.MinValue);
            }
        }

        public override bool ValidateUser(string username, string password)
        {
            if (string.IsNullOrEmpty(username))
                throw new ArgumentException("Username cannot be empty", "UserName");
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password cannot be empty", "Password");

            const bool throwException = false;
            var userId = GetUserIdIfUserNameHasConfirmedAccount(username, throwException);
            
            if (userId == null)
                return false;

            return CheckPassword(userId, password);
        }

        public override void CreateOrUpdateOAuthAccount(string provider, string providerUserId, string userName)
        {
            if (string.IsNullOrEmpty(userName))
                throw new ArgumentException("Username cannot be empty", "UserName");

            using (var session = DocumentStore.OpenSession())
            {
                var user = session.Query<UserProfile>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .FirstOrDefault(x => x.UserName == userName);

                if (user == null)
                {
                    user = new UserProfile { UserName = userName };
                    session.Store(user);
                    session.SaveChanges();
                }

                var oAuth = session.Query<WebpagesOauthMembership>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .FirstOrDefault(x => x.ProviderUserId == providerUserId && x.Provider == provider);

                if (oAuth == null)
                    oAuth = new WebpagesOauthMembership { ProviderUserId = providerUserId, Provider = provider, UserId = user.Id };
                else
                    oAuth.UserId = user.Id;

                session.Store(oAuth);
                session.SaveChanges();
            }
        }

        public override void DeleteOAuthAccount(string provider, string providerUserId)
        {
            using (var session = DocumentStore.OpenSession())
            {
                var oauthMembership = session.Query<WebpagesOauthMembership>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .First(x => x.Provider == provider && x.ProviderUserId == providerUserId);
                session.Delete(oauthMembership);
                session.SaveChanges();
            }
        }

        public override void DeleteOAuthToken(string token)
        {
            using (var session = DocumentStore.OpenSession())
            {
                var tokenEntity = session.Query<WebpagesOauthToken>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .First(x => x.Token == token);
                session.Delete(tokenEntity);
                session.SaveChanges();
            }
        }

        public override string GetOAuthTokenSecret(string token)
        {
            using (var session = DocumentStore.OpenSession())
            {
                var oauthToken = session.Query<WebpagesOauthToken>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .FirstOrDefault(x => x.Token == token);
                if (oauthToken != null)
                    return oauthToken.Secret;
                return null;
            }
        }

        public override int GetUserIdFromOAuth(string provider, string providerUserId)
        {
            using (var session = DocumentStore.OpenSession())
            {
                var oAuthMembership = session.Query<WebpagesOauthMembership>()
                    .Customize(x=> x.WaitForNonStaleResultsAsOfNow())
                    .FirstOrDefault(x => x.Provider == provider && x.ProviderUserId == providerUserId);
                if (oAuthMembership != null)
                    return oAuthMembership.IdAsInt();
                return -1;
            }
        }

        public override string GetUserNameFromId(int userId)
        {
            using (var session = DocumentStore.OpenSession())
            {
                var userProfile = session.Load<UserProfile>(UserProfile.ToRavenDbId(userId));
                if (userProfile != null)
                    return userProfile.UserName;
                return null;
            }
        }

        public int GetUserIdFromUserName(string userName)
        {
            using (var session = DocumentStore.OpenSession())
            {
                var userProfile = session.Query<UserProfile>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .FirstOrDefault(x => x.UserName == userName);
                if (userProfile != null)
                    return userProfile.IdAsInt();
                return -1;
            }
        }

        public override bool HasLocalAccount(int userId)
        {
            using (var session = DocumentStore.OpenSession())
            {
                var account = session.Query<WebpagesMembership>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .FirstOrDefault(x => x.UserId == UserProfile.ToRavenDbId(userId));
                return account != null;
            }
        }

        public override void ReplaceOAuthRequestTokenWithAccessToken(string requestToken, string accessToken, string accessTokenSecret)
        {
            using (var session = DocumentStore.OpenSession())
            {
                var tokenEntity = session.Query<WebpagesOauthToken>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .First(x => x.Token == requestToken);
                session.Delete(tokenEntity);
                session.SaveChanges();
            }
            StoreOAuthRequestToken(accessToken, accessTokenSecret);
        }

        public override void StoreOAuthRequestToken(string requestToken, string requestTokenSecret)
        {
            using (var session = DocumentStore.OpenSession())
            {
                var tokenEntity = session.Query<WebpagesOauthToken>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .FirstOrDefault(x => x.Token == requestToken);

                if (tokenEntity == null)
                    tokenEntity = new WebpagesOauthToken {Token = requestToken};
                else if (tokenEntity.Secret == requestTokenSecret) 
                    return;
                
                tokenEntity.Secret = requestTokenSecret;
                session.Store(tokenEntity);
                session.SaveChanges();
            }
        }

        private static void CreateUser(string userName, IEnumerable<KeyValuePair<string, object>> values)
        {
            using (var session = DocumentStore.OpenSession())
            {
                var user = session.Query<UserProfile>().FirstOrDefault(x => x.UserName == userName);
                if (user != null)
                    throw new MembershipCreateUserException(MembershipCreateStatus.DuplicateUserName);

                user = new UserProfile { UserName = userName };

                // TODO check vhat can be assigned here???? 
                if (values != null)
                {
                    foreach (var v in values)
                    {
                        var value = v;
                        if (value.Key.Equals("UserName", StringComparison.OrdinalIgnoreCase))
                            continue;

                        var type = user.GetType();
                        var field = type.GetProperties()
                                        .SingleOrDefault(f => f.Name.Equals(value.Key, StringComparison.OrdinalIgnoreCase));
                        if (field != null)
                        {
                            var property = type.GetProperty(field.Name);
                            property.SetValue(user, value.Value, null);
                        }
                    }
                }

                session.Store(user);
                session.SaveChanges();
            }
        }

        public override string CreateAccount(string userName, string password, bool requireConfirmationToken)
        {
            if (string.IsNullOrEmpty(password))
                throw new MembershipCreateUserException(MembershipCreateStatus.InvalidPassword);

            string hashedPassword = Crypto.HashPassword(password);

            if (hashedPassword.Length > 0x80)
                throw new MembershipCreateUserException(MembershipCreateStatus.InvalidPassword);

            if (string.IsNullOrEmpty(userName))
                throw new MembershipCreateUserException(MembershipCreateStatus.InvalidUserName);

            using (var session = DocumentStore.OpenSession())
            {
                var user = session.Query<UserProfile>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .FirstOrDefault(x => x.UserName == userName);

                if (user == null)
                    throw new MembershipCreateUserException(MembershipCreateStatus.InvalidUserName);

                string token = null;
                if (requireConfirmationToken)
                    token = GenerateToken();

                var membership = new WebpagesMembership
                {
                    UserId = user.Id,
                    Password = hashedPassword,
                    PasswordSalt = string.Empty,
                    IsConfirmed = !requireConfirmationToken,
                    ConfirmationToken = token,
                    CreateDate = DateTime.UtcNow,
                    PasswordChangedDate = DateTime.UtcNow,
                    PasswordFailuresSinceLastSuccess = 0
                };

                session.Store(membership);
                session.SaveChanges();

                return token;
            }
        }

        private static bool SetPasswordInternal(IDocumentSession session, string userId, string newPassword)
        {
            var hashedPassword = Crypto.HashPassword(newPassword);
            if (hashedPassword.Length > 0x80)
                throw new ArgumentException("Password is too long!");

            var membershipUser = session.Query<WebpagesMembership>()
                .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                .FirstOrDefault(x => x.UserId == userId);
            membershipUser.Password = hashedPassword;
            membershipUser.PasswordSalt = string.Empty;
            membershipUser.PasswordChangedDate = DateTime.Now;
            session.Store(membershipUser);
            return true;
        }

        private static bool CheckPassword(string userId, string password)
        {
            using (var session = DocumentStore.OpenSession())
            {
                return CheckPassword(session, userId, password);
            }
        }

        private static bool CheckPassword(IDocumentSession session, string userId, string password)
        {
            var membership = session.Query<WebpagesMembership>()
                .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                .FirstOrDefault(x => x.UserId == userId);

            var hashedPassword = (membership == null) ? null : membership.Password;

            var matches = (hashedPassword != null) && Crypto.VerifyHashedPassword(hashedPassword, password);
            if (membership != null)
            {
                if (matches)
                {
                    membership.PasswordFailuresSinceLastSuccess = 0;
                    session.Store(membership);
                    session.SaveChanges();
                    return true;
                }
                membership.PasswordFailuresSinceLastSuccess = membership.PasswordFailuresSinceLastSuccess + 1;
                membership.LastPasswordFailureDate = DateTime.Now;
                session.Store(membership);
                session.SaveChanges();
            }
            return false;
        }

        private static T GetValueOrDefault<T>(NameValueCollection nvc, string key, Func<object, T> converter, T defaultIfNull)
        {
            var val = nvc[key];

            if (val == null)
                return defaultIfNull;

            try
            {
                return converter(val);
            }
            catch
            {
                return defaultIfNull;
            }
        }

        private static string GenerateToken()
        {
            using (var provider = new RNGCryptoServiceProvider())
            {
                return GenerateToken(provider);
            }
        }

        private static string GenerateToken(RandomNumberGenerator generator)
        {
            var data = new byte[0x10];
            generator.GetBytes(data);
            return HttpServerUtility.UrlTokenEncode(data);
        }

        private static string GetUserIdIfUserNameHasConfirmedAccount(string username, bool throwException)
        {
            using (var session = DocumentStore.OpenSession())
            {
                var user = session.Query<UserProfile>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .FirstOrDefault(x => x.UserName == username);
                if (user == null)
                {
                    if (throwException)
                        throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, "User {0} does not exist!", new object[] { username }));
                    return null;
                }
                Console.WriteLine("looking for membership object with userid " + user.Id);

                var membership = session.Query<WebpagesMembership>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .FirstOrDefault(x => x.UserId == user.Id && x.IsConfirmed);
                if (membership == null)
                {
                    if (throwException)
                        throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, "User {0} does not exist!", new object[] { username }));
                    return null;
                }
                return membership.UserId;
            }
        }

        public override MembershipUser CreateUser(string username, string password, string email, string passwordQuestion, string passwordAnswer, bool isApproved, object providerUserKey, out MembershipCreateStatus status)
        {
            throw new NotSupportedException();
        }

        public override bool ChangePasswordQuestionAndAnswer(string username, string password, string newPasswordQuestion, string newPasswordAnswer)
        {
            throw new NotSupportedException();
        }

        public override MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            throw new NotSupportedException();
        }

        public override MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            throw new NotSupportedException();
        }

        public override MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords)
        {
            throw new NotSupportedException();
        }

        public override int GetNumberOfUsersOnline()
        {
            throw new NotSupportedException();
        }

        public override string GetPassword(string username, string answer)
        {
            throw new NotSupportedException();
        }

        public override MembershipUser GetUser(object providerUserKey, bool userIsOnline)
        {
            throw new NotSupportedException();
        }

        public override string GetUserNameByEmail(string email)
        {
            throw new NotSupportedException();
        }

        public override string ResetPassword(string username, string answer)
        {
            throw new NotSupportedException();
        }

        public override bool UnlockUser(string userName)
        {
            throw new NotSupportedException();
        }

        public override void UpdateUser(MembershipUser user)
        {
            throw new NotSupportedException();
        }
    }
}
