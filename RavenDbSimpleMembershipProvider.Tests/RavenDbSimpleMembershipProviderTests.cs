using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Web.Security;
using NUnit.Framework;
using Raven.Client;
using Raven.Client.Embedded;

namespace RavenDbSimpleMembershipProvider.Tests
{
    [TestFixture]
    internal class RavenDbSimpleMembershipProviderTests
    {
        private IDocumentStore documentStore;
        private RavenDbSimpleMembershipProvider membershipProvider;

        [SetUp]
        public void Before_each_test()
        {
            documentStore = new EmbeddableDocumentStore {RunInMemory = true}.Initialize();

            RavenDbSimpleRoleProvider.DocumentStore = documentStore;
            RavenDbSimpleMembershipProvider.DocumentStore = documentStore;
            membershipProvider = new RavenDbSimpleMembershipProvider();
        }

        [TearDown]
        public void After_each_test()
        {
            documentStore.Dispose();
            documentStore = null;
        }

        [Test]
        public void Can_create_user()
        {
            membershipProvider.CreateUserAndAccount("user", "password");
            const bool userIsOnline = false;
            var result = membershipProvider.GetUser("user", userIsOnline);
            Assert.That(result, Is.Not.Null);
            Assert.That(result.UserName, Is.EqualTo("user"));
        }

        [Test]
        public void Get_user_returns_null_for_unknown_user()
        {
            const bool userIsOnline = false;
            var result = membershipProvider.GetUser("unknown user", userIsOnline);
            Assert.That(result, Is.Null);
        }

        [Test]
        public void Validate_user_returns_true_for_correct_username_and_password()
        {
            membershipProvider.CreateUserAndAccount("user", "password");
            var result = membershipProvider.ValidateUser("user", "password");
            Assert.That(result, Is.True);
        }

        [Test]
        public void Validate_user_returns_false_for_invalid_user()
        {
            membershipProvider.CreateUserAndAccount("user", "password");
            var result = membershipProvider.ValidateUser("user2", "password");
            Assert.That(result, Is.False);
        }

        [Test]
        public void Validate_user_returns_false_for_invalid_password()
        {
            membershipProvider.CreateUserAndAccount("user", "password");
            var result = membershipProvider.ValidateUser("user", "wrongpassword");
            Assert.That(result, Is.False);
        }

        [Test]
        public void Creating_user_sets_last_password_failure_date_to_datetime_minvalue()
        {
            membershipProvider.CreateUserAndAccount("user", "password");
            var result = membershipProvider.GetLastPasswordFailureDate("user");
            Assert.That(result, Is.EqualTo(DateTime.MinValue));
        }

        [Test]
        public void Creating_user_sets_last_password_change_date_to_now()
        {
            membershipProvider.CreateUserAndAccount("user", "password");
            var result = membershipProvider.GetPasswordChangedDate("user");
            Assert.That(result, Is.GreaterThan(DateTime.Now.AddSeconds(-5)));
        }

        [Test]
        public void Creating_user_sets_password_failure_count_to_zero()
        {
            membershipProvider.CreateUserAndAccount("user", "password");
            var result = membershipProvider.GetPasswordFailuresSinceLastSuccess("user");
            Assert.That(result, Is.EqualTo(0));
        }

        [Test]
        public void Get_password_failures_since_last_success_throws_exception_for_unknown_user()
        {
            var exception = Assert.Throws<InvalidOperationException>(() => membershipProvider.GetPasswordFailuresSinceLastSuccess("user"));
            Assert.That(exception.Message, Is.EqualTo("User user does not exist."));
        }

        [Test]
        public void Get_password_failures_since_last_success_returns_negative_one_for_user_with_no_memberships()
        {
            membershipProvider.CreateUser("user", null);
            var result = membershipProvider.GetPasswordFailuresSinceLastSuccess("user");
            Assert.That(result, Is.EqualTo(-1));
        }

        [Test]
        public void Get_last_password_failure_date_throws_exception_for_invalid_username()
        {
            var exception = Assert.Throws<InvalidOperationException>(() => membershipProvider.GetLastPasswordFailureDate("userxyz"));
            Assert.That(exception.Message, Is.EqualTo("User userxyz does not exist."));
        }

        [Test]
        public void Get_password_change_date_throws_exception_for_invalid_username()
        {
            var exception = Assert.Throws<InvalidOperationException>(() => membershipProvider.GetPasswordChangedDate("userxyz"));
            Assert.That(exception.Message, Is.EqualTo("User userxyz does not exist."));
        }

        [Test]
        public void Get_password_change_date_returns_datetime_minvalue_for_user_that_has_no_membership()
        {
            membershipProvider.CreateUser("user", null);
            var result = membershipProvider.GetPasswordChangedDate("user");
            Assert.That(result, Is.EqualTo(DateTime.MinValue));
        }

        [Test]
        public void Change_password_updates_password_change_date()
        {
            membershipProvider.CreateUserAndAccount("user", "password");
            var originalChangePasswordDate = membershipProvider.GetPasswordChangedDate("user");
            membershipProvider.ChangePassword("user", "password", "newpassword");
            var newChangePasswordDate = membershipProvider.GetPasswordChangedDate("user");
            Assert.That(newChangePasswordDate, Is.GreaterThan(originalChangePasswordDate));
        }

        [Test]
        public void Change_password_returns_true_if_password_change_was_successful()
        {
            membershipProvider.CreateUserAndAccount("user", "password");
            var result = membershipProvider.ChangePassword("user", "password", "newpassword");
            Assert.That(result, Is.True);
            var loginResult = membershipProvider.ValidateUser("user", "newpassword");
            Assert.That(loginResult, Is.True);
        }

        [Test]
        public void Change_password_returns_false_if_invalid_username()
        {
            membershipProvider.CreateUserAndAccount("user", "password");
            var result = membershipProvider.ChangePassword("user123", "password", "newpassword");
            Assert.That(result, Is.False);
        }

        [Test]
        public void Change_password_returns_false_if_old_password_does_not_match()
        {
            membershipProvider.CreateUserAndAccount("user", "password");
            var result = membershipProvider.ChangePassword("user", "incorrect password", "newpassword");
            Assert.That(result, Is.False);
        }

        [Test]
        public void Change_password_throws_exception_if_user_name_is_null()
        {
            membershipProvider.CreateUserAndAccount("user", "password");
            var exception = Assert.Throws<ArgumentException>(() => membershipProvider.ChangePassword(null, "password", "newpassword"));
            Assert.That(exception.Message, Is.EqualTo("User name cannot be empty." + Environment.NewLine + "Parameter name: userName"));
        }

        [Test]
        public void Change_password_throws_exception_if_user_name_is_empty()
        {
            membershipProvider.CreateUserAndAccount("user", "password");
            var exception = Assert.Throws<ArgumentException>(() => membershipProvider.ChangePassword(string.Empty, "password", "newpassword"));
            Assert.That(exception.Message, Is.EqualTo("User name cannot be empty." + Environment.NewLine + "Parameter name: userName"));
        }

        [Test]
        public void Change_password_throws_exception_if_old_password_is_null()
        {
            membershipProvider.CreateUserAndAccount("user", "password");
            var exception = Assert.Throws<ArgumentException>(() => membershipProvider.ChangePassword("user", null, "newpassword"));
            Assert.That(exception.Message, Is.EqualTo("Old password cannot be empty." + Environment.NewLine + "Parameter name: oldPassword"));
        }

        [Test]
        public void Change_password_throws_exception_if_old_password_is_empty()
        {
            membershipProvider.CreateUserAndAccount("user", "password");
            var exception = Assert.Throws<ArgumentException>(() => membershipProvider.ChangePassword("user", string.Empty, "newpassword"));
            Assert.That(exception.Message, Is.EqualTo("Old password cannot be empty." + Environment.NewLine + "Parameter name: oldPassword"));
        }

        [Test]
        public void Change_password_throws_exception_if_new_password_is_null()
        {
            membershipProvider.CreateUserAndAccount("user", "password");
            var exception = Assert.Throws<ArgumentException>(() => membershipProvider.ChangePassword("user", "password", null));
            Assert.That(exception.Message, Is.EqualTo("New password cannot be empty." + Environment.NewLine + "Parameter name: newPassword"));
        }

        [Test]
        public void Change_password_throws_exception_if_new_password_is_empty()
        {
            membershipProvider.CreateUserAndAccount("user", "password");
            var exception = Assert.Throws<ArgumentException>(() => membershipProvider.ChangePassword("user", "password", string.Empty));
            Assert.That(exception.Message, Is.EqualTo("New password cannot be empty." + Environment.NewLine + "Parameter name: newPassword"));
        }

        [Test]
        public void Validate_user_updates_last_password_failure_date()
        {
            membershipProvider.CreateUserAndAccount("user", "password");
            membershipProvider.ValidateUser("user", "wrongpassword");
            var result = membershipProvider.GetLastPasswordFailureDate("user");
            Assert.That(result, Is.GreaterThan(DateTime.Now.AddSeconds(-5)));
        }

        [Test]
        public void Validate_user_throws_exception_if_user_name_is_null()
        {
            var exception = Assert.Throws<ArgumentException>(() => membershipProvider.ValidateUser(null, "password"));
            Assert.That(exception.Message, Is.EqualTo("User name cannot be empty." + Environment.NewLine + "Parameter name: userName"));
        }

        [Test]
        public void Validate_user_throws_exception_if_user_name_is_empty()
        {
            var exception = Assert.Throws<ArgumentException>(() => membershipProvider.ValidateUser(string.Empty, "password"));
            Assert.That(exception.Message, Is.EqualTo("User name cannot be empty." + Environment.NewLine + "Parameter name: userName"));
        }

        [Test]
        public void Validate_user_throws_exception_if_password_is_null()
        {
            var exception = Assert.Throws<ArgumentException>(() => membershipProvider.ValidateUser("user", null));
            Assert.That(exception.Message, Is.EqualTo("Password cannot be empty." + Environment.NewLine + "Parameter name: password"));
        }

        [Test]
        public void Validate_user_throws_exception_if_password_is_empty()
        {
            var exception = Assert.Throws<ArgumentException>(() => membershipProvider.ValidateUser("user", string.Empty));
            Assert.That(exception.Message, Is.EqualTo("Password cannot be empty." + Environment.NewLine + "Parameter name: password"));
        }

        [Test]
        public void Creating_user_and_account_with_required_confirmation_sets_is_confirmed_to_false()
        {
            const bool requireConfirmation = true;
            membershipProvider.CreateUserAndAccount("user", "password", requireConfirmation);
            Assert.That(membershipProvider.IsConfirmed("user"), Is.False);
        }

        [Test]
        public void Can_confirm_user_by_token_only()
        {
            const bool requireConfirmation = true;
            var token = membershipProvider.CreateUserAndAccount("user", "password", requireConfirmation);
            Assert.That(token, Is.Not.Null);
            var result = membershipProvider.ConfirmAccount(token);
            Assert.That(result, Is.True);
            Assert.That(membershipProvider.IsConfirmed("user"), Is.True);
        }

        [Test]
        public void Confirm_user_by_token_returns_false_when_token_not_found()
        {
            const bool requireConfirmation = true;
            membershipProvider.CreateUserAndAccount("user", "password", requireConfirmation);
            var result = membershipProvider.ConfirmAccount("fake token");
            Assert.That(result, Is.False);
            Assert.That(membershipProvider.IsConfirmed("user"), Is.False);
        }

        [Test]
        public void Can_confirm_user_by_username_and_token()
        {
            const bool requireConfirmation = true;
            var token = membershipProvider.CreateUserAndAccount("user", "password", requireConfirmation);
            Assert.That(token, Is.Not.Null);
            membershipProvider.ConfirmAccount("user", token);
            Assert.That(membershipProvider.IsConfirmed("user"), Is.True);
        }

        [Test]
        public void Confirm_user_by_username_and_token_returns_false_when_token_not_found()
        {
            const bool requireConfirmation = true;
            membershipProvider.CreateUserAndAccount("user", "password", requireConfirmation);
            var result = membershipProvider.ConfirmAccount("user", "fake token");
            Assert.That(result, Is.False);
            Assert.That(membershipProvider.IsConfirmed("user"), Is.False);
        }

        [Test]
        public void Confirm_user_by_username_and_token_returns_false_when_user_not_found()
        {
            const bool requireConfirmation = true;
            var token = membershipProvider.CreateUserAndAccount("user", "password", requireConfirmation);
            var result = membershipProvider.ConfirmAccount("fake user", token);
            Assert.That(result, Is.False);
            Assert.That(membershipProvider.IsConfirmed("user"), Is.False);
            Assert.That(membershipProvider.IsConfirmed("fake user"), Is.False);
        }

        [Test]
        public void Is_confirmed_throws_exception_for_null_username()
        {
            var exception = Assert.Throws<ArgumentException>(() => membershipProvider.IsConfirmed(null));
            Assert.That(exception.Message, Is.EqualTo("Username cannot be empty" + Environment.NewLine + "Parameter name: userName"));
        }

                [Test]
        public void Is_confirmed_throws_exception_for_empty_username()
        {
            var exception = Assert.Throws<ArgumentException>(() => membershipProvider.IsConfirmed(string.Empty));
            Assert.That(exception.Message, Is.EqualTo("Username cannot be empty" + Environment.NewLine + "Parameter name: userName"));
        }

        [Test]
        public void Can_delete_account()
        {
            //not the nicest way of testing this, but dont know of a better way at present
            membershipProvider.CreateUserAndAccount("user", "password");
            var result = membershipProvider.GetCreateDate("user");
            Assert.That(result, Is.GreaterThan(DateTime.Now.AddSeconds(-5)));
            var deleteResult = membershipProvider.DeleteAccount("user");
            Assert.That(deleteResult, Is.True);
            result = membershipProvider.GetCreateDate("user");
            Assert.That(result, Is.EqualTo(DateTime.MinValue));
        }

        [Test]
        public void Delete_account_returns_false_for_unknown_user()
        {
            membershipProvider.CreateUserAndAccount("user", "password");
            var result = membershipProvider.DeleteAccount("unknown user");
            Assert.That(result, Is.False);
        }

        [Test]
        public void Delete_account_returns_false_when_only_user_profile_exists()
        {
            membershipProvider.CreateUser("user", null);
            var result = membershipProvider.DeleteAccount("user");
            Assert.That(result, Is.False);
        }

        [Test]
        public void Get_create_date_throws_exception_for_unknown_user()
        {
            var exception = Assert.Throws<InvalidOperationException>(() => membershipProvider.GetCreateDate("user"));
            Assert.That(exception.Message, Is.EqualTo("User user does not exist."));
        }

        [Test]
        public void Get_create_date_returns_membership_creation_date()
        {
            var minDate = DateTime.UtcNow;
            membershipProvider.CreateUserAndAccount("user", "password");
            var maxDate = DateTime.UtcNow;
            var actualDate = membershipProvider.GetCreateDate("user");
            Assert.That(minDate, Is.LessThanOrEqualTo(actualDate));
            Assert.That(maxDate, Is.GreaterThanOrEqualTo(actualDate));
        }
        
        [Test]
        public void Can_get_password_reset_token()
        {
            membershipProvider.CreateUserAndAccount("user", "password");
            var result = membershipProvider.GeneratePasswordResetToken("user");
            Assert.That(result, Is.Not.Null);
            Assert.That(result, Is.Not.Empty);
        }

        [Test]
        public void Generate_password_reset_token_throws_exception_for_null_username()
        {
            var exception = Assert.Throws<ArgumentNullException>(() => membershipProvider.GeneratePasswordResetToken(null));
            Assert.That(exception.Message, Is.EqualTo("Value cannot be null." + Environment.NewLine + "Parameter name: userName"));
        }

        [Test]
        public void Generate_password_reset_token_throws_exception_for_empty_username()
        {
            var exception = Assert.Throws<ArgumentException>(() => membershipProvider.GeneratePasswordResetToken(string.Empty));
            Assert.That(exception.Message, Is.EqualTo("Username cannot be empty." + Environment.NewLine + "Parameter name: userName"));
        }

        [Test]
        public void Generate_password_reset_token_throws_exception_for_unknown_username()
        {
            var exception = Assert.Throws<InvalidOperationException>(() => membershipProvider.GeneratePasswordResetToken("unknown user"));
            Assert.That(exception.Message, Is.EqualTo("User unknown user does not exist."));
        }

        [Test]
        public void Generate_password_reset_token_throws_exception_when_user_has_no_membership()
        {
            membershipProvider.CreateUser("user", null);
            var exception = Assert.Throws<InvalidOperationException>(() => membershipProvider.GeneratePasswordResetToken("user"));
            Assert.That(exception.Message, Is.EqualTo("User user does not exist."));
        }


        [Test]
        public void Get_password_reset_token_returns_same_token_if_old_token_is_still_valid()
        {
            membershipProvider.CreateUserAndAccount("user", "password");
            var result1 = membershipProvider.GeneratePasswordResetToken("user");
            var result2 = membershipProvider.GeneratePasswordResetToken("user");
            Assert.That(result1, Is.EqualTo(result2));
        }

        [Test]
        public void Get_user_id_from_password_reset_token_returns_negative_one_for_unknown_token()
        {
            const string passwordResetToken = "fake token";
            var userId = membershipProvider.GetUserIdFromPasswordResetToken(passwordResetToken);
            Assert.That(userId, Is.EqualTo(-1));
        }

        [Test]
        public void Can_get_user_id_from_password_reset_token()
        {
            membershipProvider.CreateUserAndAccount("user", "password");
            var passwordResetToken = membershipProvider.GeneratePasswordResetToken("user");
            var userId = membershipProvider.GetUserIdFromPasswordResetToken(passwordResetToken);
            var username = membershipProvider.GetUserNameFromId(userId);
            Assert.That(username, Is.EqualTo("user"));
        }

        [Test]
        public void Get_user_name_from_id_returns_null_for_invalid_user_id()
        {
            var result = membershipProvider.GetUserNameFromId(-1);
            Assert.That(result, Is.Null);
        }

        [Test]
        public void Can_reset_password_with_token()
        {
            membershipProvider.CreateUserAndAccount("user", "password");
            var passwordResetToken = membershipProvider.GeneratePasswordResetToken("user");
            membershipProvider.ResetPasswordWithToken(passwordResetToken, "newpassword");
            var result = membershipProvider.ValidateUser("user", "newpassword");
            Assert.That(result, Is.True);
        }

        [Test]
        public void Reset_password_with_token_throws_exception_for_null_new_password()
        {
            var exception = Assert.Throws<ArgumentException>(() => membershipProvider.ResetPasswordWithToken("token", null));
            Assert.That(exception.Message, Is.EqualTo("New password cannot be empty." + Environment.NewLine + "Parameter name: newPassword"));
        }

        [Test]
        public void Reset_password_with_token_throws_exception_for_empty_new_password()
        {
            var exception = Assert.Throws<ArgumentException>(() => membershipProvider.ResetPasswordWithToken("token", string.Empty));
            Assert.That(exception.Message, Is.EqualTo("New password cannot be empty." + Environment.NewLine + "Parameter name: newPassword"));
        }
        
        [Test]
        public void Reset_password_with_token_returns_false_for_unknown_token()
        {
            var result = membershipProvider.ResetPasswordWithToken("fake token", "new password");
            Assert.That(result, Is.False);
        }

        [Test]
        public void Can_create_oauth_account()
        {
            membershipProvider.CreateUserAndAccount("username", "password");
            membershipProvider.CreateOrUpdateOAuthAccount("provider", "provideruserid", "username");
            var accounts = membershipProvider.GetAccountsForUser("username");
            Assert.That(accounts.Count, Is.EqualTo(1));
        }

        [Test]
        public void Can_modify_the_association_of_an_oauth_account_from_one_user_to_another()
        {
            membershipProvider.CreateUserAndAccount("username1", "password");
            membershipProvider.CreateOrUpdateOAuthAccount("provider", "user@provider", "username1");

            membershipProvider.CreateUserAndAccount("username2", "password");
            membershipProvider.CreateOrUpdateOAuthAccount("provider", "user@provider", "username2");

            var accounts = membershipProvider.GetAccountsForUser("username1");
            Assert.That(accounts.Count, Is.EqualTo(0));
            accounts = membershipProvider.GetAccountsForUser("username2");
            Assert.That(accounts.Count, Is.EqualTo(1));
        }

        [Test]
        public void Create_or_update_oauth_account_throws_exception_if_user_name_is_null()
        {
            var exception = Assert.Throws<ArgumentException>(() => membershipProvider.CreateOrUpdateOAuthAccount("provider", "user@provider", null));
            Assert.That(exception.Message, Is.EqualTo("Username cannot be empty." + Environment.NewLine + "Parameter name: userName"));
        }

        [Test]
        public void Create_or_update_oauth_account_throws_exception_if_user_name_is_empty()
        {
            var exception = Assert.Throws<ArgumentException>(() => membershipProvider.CreateOrUpdateOAuthAccount("provider", "user@provider", string.Empty));
            Assert.That(exception.Message, Is.EqualTo("Username cannot be empty." + Environment.NewLine + "Parameter name: userName"));
        }

        [Test]
        public void Create_or_update_oauth_account_throws_exception_if_user_name_is_uknown()
        {
            var exception = Assert.Throws<MembershipCreateUserException>(() => membershipProvider.CreateOrUpdateOAuthAccount("provider", "user@provider", "UnknownUser"));
            Assert.That(exception.Message, Is.EqualTo("The username supplied is invalid."));
        }

        [Test]
        public void Can_delete_oauth_account()
        {
            membershipProvider.CreateUserAndAccount("username", "password");
            membershipProvider.CreateOrUpdateOAuthAccount("provider", "provideruserid", "username");
            var accounts = membershipProvider.GetAccountsForUser("username");
            Assert.That(accounts.Count, Is.EqualTo(1));
            membershipProvider.DeleteOAuthAccount("provider", "provideruserid");
            accounts = membershipProvider.GetAccountsForUser("username");
            Assert.That(accounts.Count, Is.EqualTo(0));
        }

        [Test]
        public void Get_accounts_for_user_returns_empty_collection_for_invalid_username()
        {
            var accounts = membershipProvider.GetAccountsForUser("unknown_username");
            Assert.That(accounts.Count, Is.EqualTo(0));
        }

        [Test]
        public void Can_store_oauth_request_token()
        {
            const string requestTokenSecret = "requestTokenSecret";
            const string requestToken = "requestToken";

            membershipProvider.StoreOAuthRequestToken(requestToken, requestTokenSecret);
            var result = membershipProvider.GetOAuthTokenSecret(requestToken);
            Assert.That(result, Is.EqualTo(requestTokenSecret));
        }

        [Test]
        public void Store_oauth_token_does_not_modify_database_if_secret_has_not_changed()
        {
            const string requestTokenSecret = "requestTokenSecret";
            const string requestToken = "requestToken";

            membershipProvider.StoreOAuthRequestToken(requestToken, requestTokenSecret);
            var firstCallStats = documentStore.DatabaseCommands.GetStatistics();
            membershipProvider.StoreOAuthRequestToken(requestToken, requestTokenSecret);
            var secondCallStats = documentStore.DatabaseCommands.GetStatistics();
            Assert.That(firstCallStats.LastDocEtag, Is.EqualTo(secondCallStats.LastDocEtag));
        }

        [Test]
        public void Can_delete_oauth_request_token()
        {
            const string requestToken = "requestToken";

            membershipProvider.StoreOAuthRequestToken(requestToken, "requestTokenSecret");
            membershipProvider.DeleteOAuthToken(requestToken);
            var result = membershipProvider.GetOAuthTokenSecret(requestToken);
            Assert.That(result, Is.Null);
        }

        [Test]
        public void Has_local_account_returns_false_when_only_oauth_account_exists()
        {
            membershipProvider.CreateUser("username", null);
            membershipProvider.CreateOrUpdateOAuthAccount("provider", "provideruserid", "username");
            var userId = membershipProvider.GetUserIdFromOAuth("provider", "provideruserid");
            var result = membershipProvider.HasLocalAccount(userId);
            Assert.That(result, Is.False);
        }

        [Test]
        public void Create_user_throws_exception_if_user_name_already_exists()
        {
            membershipProvider.CreateUser("user", null);
            var exception = Assert.Throws<MembershipCreateUserException>(() => membershipProvider.CreateUser("user", null));
            Assert.That(exception.Message, Is.EqualTo("The username is already in use."));
        }


        [Test]
        public void Get_user_id_from_oauth_returns_negative_one_when_oauth_account_not_registered()
        {
            var userId = membershipProvider.GetUserIdFromOAuth("provider", "unknown@provider");
            Assert.That(userId, Is.EqualTo(-1));
        }

        [Test]
        public void Has_local_account_returns_true_when_local_account_exists()
        {
            membershipProvider.CreateUserAndAccount("user", "password");
            var userId = membershipProvider.GetUserIdFromUserName("user");
            var result = membershipProvider.HasLocalAccount(userId);
            Assert.That(result, Is.True);
        }

        [Test]
        public void Get_user_id_from_user_name_returns_negative_one_when_user_not_found()
        {
            membershipProvider.CreateUserAndAccount("user", "password");
            var userId = membershipProvider.GetUserIdFromUserName("user2");
            Assert.That(userId, Is.EqualTo(-1));
        }

        [Test]
        public void Can_replace_oauth_request_token_with_access_token()
        {
            const string requestTokenSecret = "requestTokenSecret";
            const string requestToken = "requestToken";

            membershipProvider.StoreOAuthRequestToken(requestToken, requestTokenSecret);
            membershipProvider.ReplaceOAuthRequestTokenWithAccessToken(requestToken, "accessToken", "accessTokenSecret");

            var result = membershipProvider.GetOAuthTokenSecret("accessToken");
            Assert.That(result, Is.EqualTo("accessTokenSecret"));
        }

        [Test]
        public void Can_delete_user()
        {
            membershipProvider.CreateUserAndAccount("user", "password");
            membershipProvider.CreateOrUpdateOAuthAccount("provider", "providerUserId", "user");
            var userId = membershipProvider.GetUserIdFromUserName("user");
            Assert.That(membershipProvider.HasLocalAccount(userId), Is.True);
            var accounts = membershipProvider.GetAccountsForUser("user");
            Assert.That(accounts.Count, Is.EqualTo(1));

            const bool deleteAllRelatedData = false;
            membershipProvider.DeleteUser("user", deleteAllRelatedData);

            accounts = membershipProvider.GetAccountsForUser("user");
            Assert.That(accounts.Count, Is.EqualTo(0));
            userId = membershipProvider.GetUserIdFromUserName("user");
            Assert.That(userId, Is.EqualTo(-1));            
        }

        [Test]
        public void Delete_user_returns_false_if_user_name_is_unknown()
        {
            var result = membershipProvider.DeleteUser("unknown user", false);
            Assert.That(result, Is.False);
        }

        [Test]
        public void Create_account_throws_exception_if_password_is_null()
        {
            var exception = Assert.Throws<MembershipCreateUserException>(() => membershipProvider.CreateAccount("user", null));
            Assert.That(exception.Message, Is.EqualTo("The password supplied is invalid.  Passwords must conform to the password strength requirements configured for the default provider."));
        }

        [Test]
        public void Create_account_throws_exception_if_password_is_empty()
        {
            var exception = Assert.Throws<MembershipCreateUserException>(() => membershipProvider.CreateAccount("user", null));
            Assert.That(exception.Message, Is.EqualTo("The password supplied is invalid.  Passwords must conform to the password strength requirements configured for the default provider."));
        }

        [Test]
        public void Create_account_throws_exception_if_user_name_is_null()
        {
            var exception = Assert.Throws<MembershipCreateUserException>(() => membershipProvider.CreateAccount(null, "password"));
            Assert.That(exception.Message, Is.EqualTo("The username supplied is invalid."));
        }

        [Test]
        public void Create_account_throws_exception_if_user_name_is_empty()
        {
            var exception = Assert.Throws<MembershipCreateUserException>(() => membershipProvider.CreateAccount(string.Empty, "password"));
            Assert.That(exception.Message, Is.EqualTo("The username supplied is invalid."));
        }

        [Test]
        public void Create_account_throws_exception_if_user_name_is_unknown()
        {
            var exception = Assert.Throws<MembershipCreateUserException>(() => membershipProvider.CreateAccount("user", "password"));
            Assert.That(exception.Message, Is.EqualTo("The Provider encountered an unknown error."));
        }

        [Test]
        public void Create_account_throws_exception_if_duplicate_user_name()
        {
            membershipProvider.CreateUserAndAccount("user", "password");
            var exception = Assert.Throws<MembershipCreateUserException>(() => membershipProvider.CreateAccount("user", "password"));
            Assert.That(exception.Message, Is.EqualTo("The username is already in use."));
        }
    }
}
    