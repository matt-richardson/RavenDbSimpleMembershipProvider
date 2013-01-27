using NUnit.Framework;
using Raven.Client;
using Raven.Client.Embedded;
using System.Configuration.Provider;
using System.Linq;

namespace RavenDbSimpleMembershipProvider.Tests
{
    [TestFixture]
    public class RavenDbSimpleRoleProviderTests
    {
        private IDocumentStore documentStore;
        private RavenDbSimpleRoleProvider roleProvider;
        private RavenDbSimpleMembershipProvider membershipProvider;

        [SetUp]
        public void Before_each_test()
        {
            documentStore = new EmbeddableDocumentStore { RunInMemory = true }.Initialize();

            RavenDbSimpleRoleProvider.DocumentStore = documentStore;
            roleProvider = new RavenDbSimpleRoleProvider();
            RavenDbSimpleMembershipProvider.DocumentStore = documentStore;
            membershipProvider = new RavenDbSimpleMembershipProvider();
        }

        [TearDown]
        public void After_each_test()
        {
            documentStore.Dispose();
            documentStore = null;
            roleProvider = null;
        }

        [Test]
        public void Can_create_role()
        {
            roleProvider.CreateRole("My test role");

            var roles = roleProvider.GetAllRoles();

            Assert.That(roles.Length, Is.EqualTo(1));
            Assert.That(roles[0], Is.EqualTo("My test role"));
        }


        [Test]
        public void Creating_a_role_with_the_same_name_as_an_existing_role_throws_exception()
        {
            roleProvider.CreateRole("My test role");
            var exception = Assert.Throws<ProviderException>(() => roleProvider.CreateRole("My test role"));
            Assert.That(exception.Message, Is.EqualTo("Role My test role already exists. Cannot create a new role with the same name."));
        }

        [Test]
        public void Can_delete_role_with_no_users()
        {
            roleProvider.CreateRole("My test role");

            var roles = roleProvider.GetAllRoles(); //this will wait until data is not stale

            roleProvider.DeleteRole("My test role", true);

            Assert.That(roles.Length, Is.EqualTo(1));
            Assert.That(roles[0], Is.EqualTo("My test role"));
        }

        [Test]
        public void Cannot_delete_role_when_users_attached()
        {
            roleProvider.CreateRole("My test role");
            membershipProvider.CreateUserAndAccount("bob", "password");
            roleProvider.AddUsersToRoles(new[] { "bob" }, new[] { "My Test role" });
            const bool throwOnPopulatedRole = false;
            var result = roleProvider.DeleteRole("My test role", throwOnPopulatedRole);
            Assert.That(result, Is.False);
        }

        [Test]
        public void Deleting_role_when_users_attached_throws_exception()
        {
            roleProvider.CreateRole("My test role");
            membershipProvider.CreateUserAndAccount("bob", "password");
            roleProvider.AddUsersToRoles(new[] { "bob" }, new[] { "My Test role" });
            const bool throwOnPopulatedRole = true;
            Assert.Throws<ProviderException>(() => roleProvider.DeleteRole("My test role", throwOnPopulatedRole));
        }

        [Test]
        public void Role_exists_returns_true_if_role_exists()
        {
            roleProvider.CreateRole("My test role");
            Assert.That(roleProvider.RoleExists("My test role"), Is.True);
        }

        [Test]
        public void Role_exists_returns_false_if_role_does_not_exists()
        {
            roleProvider.CreateRole("My test role");
            Assert.That(roleProvider.RoleExists("a completely different role"), Is.False);
        }

        [Test]
        public void Get_all_roles_returns_all_created_roles()
        {
            roleProvider.CreateRole("test role 1");
            roleProvider.CreateRole("test role 2");
            roleProvider.CreateRole("test role 3");

            var roles = roleProvider.GetAllRoles();

            Assert.That(roles.Length, Is.EqualTo(3));
            Assert.That(roles.Contains("test role 1"), Is.True);
            Assert.That(roles.Contains("test role 2"), Is.True);
            Assert.That(roles.Contains("test role 3"), Is.True);
        }

        [Test]
        public void Can_add_user_to_role()
        {
            roleProvider.CreateRole("test role");
            membershipProvider.CreateUserAndAccount("user1", "password");
            roleProvider.AddUsersToRoles(new[] { "user1" }, new[] { "test role" });

            var results = roleProvider.GetRolesForUser("user1");
            Assert.That(results.Length, Is.EqualTo(1));
            Assert.That(results[0], Is.EqualTo("test role"));
        }

        [Test]
        public void Can_add_multiple_users_to_role()
        {
            roleProvider.CreateRole("test role");
            membershipProvider.CreateUserAndAccount("user1", "password");
            membershipProvider.CreateUserAndAccount("user2", "password");
            roleProvider.AddUsersToRoles(new[] { "user1", "user2" }, new[] { "test role" });

            var results = roleProvider.GetUsersInRole("test role");
            Assert.That(results.Length, Is.EqualTo(2));
            Assert.That(results.Contains("user1"), Is.True);
            Assert.That(results.Contains("user2"), Is.True);
        }

        [Test]
        public void Can_determine_if_user_is_in_role()
        {
            roleProvider.CreateRole("test role");
            membershipProvider.CreateUserAndAccount("user1", "password");
            roleProvider.AddUsersToRoles(new[] { "user1" }, new[] { "test role" });

            var result = roleProvider.IsUserInRole("user1", "test role");
            Assert.That(result, Is.True);
        }

        [Test]
        public void Is_in_role_returns_false_when_user_is_not_in_role()
        {
            roleProvider.CreateRole("test role");
            membershipProvider.CreateUserAndAccount("user1", "password");
            membershipProvider.CreateUserAndAccount("user2", "password");
            roleProvider.AddUsersToRoles(new[] { "user1" }, new[] { "test role" });

            var result = roleProvider.IsUserInRole("user2", "test role");
            Assert.That(result, Is.False);
        }

        [Test]
        public void Is_in_role_throws_exception_when_user_doesnt_exist()
        {
            roleProvider.CreateRole("test role");
            membershipProvider.CreateUserAndAccount("user1", "password");
            roleProvider.AddUsersToRoles(new[] { "user1" }, new[] { "test role" });

            Assert.Throws<ProviderException>(() => roleProvider.IsUserInRole("user2", "test role"));
        }

        [Test]
        public void Is_in_role_throws_exception_when_role_doesnt_exist()
        {
            roleProvider.CreateRole("test role");
            membershipProvider.CreateUserAndAccount("user1", "password");
            roleProvider.AddUsersToRoles(new[] { "user1" }, new[] { "test role" });

            Assert.Throws<ProviderException>(() => roleProvider.IsUserInRole("user1", "role that does exist"));
        }

        [Test]
        public void Can_remove_users_from_roles()
        {
            roleProvider.CreateRole("test role 1");
            roleProvider.CreateRole("test role 2");
            membershipProvider.CreateUserAndAccount("user1", "password");
            membershipProvider.CreateUserAndAccount("user2", "password");
            roleProvider.AddUsersToRoles(new[] { "user1", "user2" }, new[] { "test role 1", "test role 2" });
            
            roleProvider.RemoveUsersFromRoles(new[] { "user1", "user2" }, new[] { "test role 2" });

            Assert.That(roleProvider.IsUserInRole("user1", "test role 1"), Is.True);
            Assert.That(roleProvider.IsUserInRole("user2", "test role 1"), Is.True);
            Assert.That(roleProvider.IsUserInRole("user1", "test role 2"), Is.False);
            Assert.That(roleProvider.IsUserInRole("user2", "test role 2"), Is.False);
        }

        [Test]
        public void Can_find_users_in_role_by_contains()
        {
            roleProvider.CreateRole("test role 1");
            roleProvider.CreateRole("test role 2");
            membershipProvider.CreateUserAndAccount("user1", "password");
            membershipProvider.CreateUserAndAccount("user2", "password");
            roleProvider.AddUsersToRoles(new[] { "user1", "user2" }, new[] { "test role 1" });
            roleProvider.AddUsersToRoles(new[] { "user2" }, new[] { "test role 2" });
            
            var results = roleProvider.FindUsersInRole("test role 1", "user");
            Assert.That(results.Length, Is.EqualTo(2));
            Assert.That(results.Contains("user1"), Is.True);
            Assert.That(results.Contains("user2"), Is.True);
        }

        [Test]
        public void Can_find_users_in_role_by_exact_match()
        {
            roleProvider.CreateRole("test role 1");
            membershipProvider.CreateUserAndAccount("user1", "password");
            membershipProvider.CreateUserAndAccount("user2", "password");
            roleProvider.AddUsersToRoles(new[] { "user1", "user2" }, new[] { "test role 1" });

            var results = roleProvider.FindUsersInRole("test role 1", "user1");
            Assert.That(results.Length, Is.EqualTo(1));
            Assert.That(results.Contains("user1"), Is.True);
        }

        [Test]
        public void Find_users_in_role_throws_exception_for_unknown_role()
        {
            Assert.Throws<ProviderException>(() => roleProvider.FindUsersInRole("fake role", "fake user"));
        }

        [Test]
        public void Get_users_in_role_throws_exception_for_unknown_role()
        {
            Assert.Throws<ProviderException>(() => roleProvider.GetUsersInRole("fake role"));
        }

        [Test]
        public void Get_roles_for_user_throws_exception_for_unknown_user()
        {
            Assert.Throws<ProviderException>(() => roleProvider.GetRolesForUser("fake user"));
        }
    }
}
