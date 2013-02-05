using System;
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
        public void Creating_a_role_with_an_empty_string_for_the_name_throws_exception()
        {
            var exception = Assert.Throws<ArgumentException>(() => roleProvider.CreateRole(string.Empty));
            Assert.That(exception.Message, Is.EqualTo("Role name cannot be empty." + Environment.NewLine + "Parameter name: roleName"));
        }

        [Test]
        public void Creating_a_role_with_null_for_the_name_throws_exception()
        {
            var exception = Assert.Throws<ArgumentNullException>(() => roleProvider.CreateRole(null));
            Assert.That(exception.Message, Is.EqualTo("Value cannot be null." + Environment.NewLine + "Parameter name: roleName"));
        }

        [Test]
        public void Creating_a_role_with_a_comma_in_the_name_throws_exception()
        {
            var exception = Assert.Throws<ArgumentException>(() => roleProvider.CreateRole("Commas are cool, aren't they?"));
            Assert.That(exception.Message, Is.EqualTo("Role name cannot contain a comma." + Environment.NewLine + "Parameter name: roleName"));
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
        public void Can_delete_role_when_users_attached()
        {
            roleProvider.CreateRole("My test role");
            membershipProvider.CreateUserAndAccount("bob", "password");
            roleProvider.AddUsersToRoles(new[] { "bob" }, new[] { "My test role" });
            const bool throwOnPopulatedRole = false;
            var result = roleProvider.DeleteRole("My test role", throwOnPopulatedRole);

            Assert.That(result, Is.True);
        }

        [Test]
        public void Deleting_role_when_users_attached_throws_exception()
        {
            roleProvider.CreateRole("My test role");
            membershipProvider.CreateUserAndAccount("bob", "password");
            roleProvider.AddUsersToRoles(new[] { "bob" }, new[] { "My test role" });
            const bool throwOnPopulatedRole = true;
            var exception = Assert.Throws<ProviderException>(() => roleProvider.DeleteRole("My test role", throwOnPopulatedRole));
            Assert.That(exception.Message, Is.EqualTo("Role My test role contains users. As throwOnPopulatedRole is true, refusing to delete."));
        }

        [Test]
        public void Deleting_role_that_does_not_exist_throws_exception()
        {
            const bool throwOnPopulatedRole = true;
            var exception = Assert.Throws<ProviderException>(() => roleProvider.DeleteRole("Role that doesnt exist", throwOnPopulatedRole));
            Assert.That(exception.Message, Is.EqualTo("Role Role that doesnt exist does not exist."));
        }

        [Test]
        public void Deleting_role_with_null_name_throws_exception()
        {
            const bool throwOnPopulatedRole = true;
            var exception = Assert.Throws<ArgumentNullException>(() => roleProvider.DeleteRole(null, throwOnPopulatedRole));
            Assert.That(exception.Message, Is.EqualTo("Value cannot be null." + Environment.NewLine + "Parameter name: roleName"));
        }

        [Test]
        public void Deleting_role_with_empty_name_throws_exception()
        {
            const bool throwOnPopulatedRole = true;
            var exception = Assert.Throws<ArgumentException>(() => roleProvider.DeleteRole(string.Empty, throwOnPopulatedRole));
            Assert.That(exception.Message, Is.EqualTo("Role name cannot be empty." + Environment.NewLine + "Parameter name: roleName"));
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
        public void Role_exists_throws_exception_if_role_name_is_null()
        {
            var exception = Assert.Throws<ArgumentNullException>(() => roleProvider.RoleExists(null));
            Assert.That(exception.Message, Is.EqualTo("Value cannot be null." + Environment.NewLine + "Parameter name: roleName"));
        }

        [Test]
        public void Role_exists_throws_exception_if_role_name_is_empty()
        {
            var exception = Assert.Throws<ArgumentException>(() => roleProvider.RoleExists(string.Empty));
            Assert.That(exception.Message, Is.EqualTo("Value cannot be empty." + Environment.NewLine + "Parameter name: roleName"));
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
        public void Get_all_roles_returns_an_empty_array_if_no_roles_exist()
        {
            var roles = roleProvider.GetAllRoles();
            Assert.That(roles.Length, Is.EqualTo(0));
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
        public void Add_users_to_role_throws_exception_if_one_of_the_roles_does_not_exist()
        {
            roleProvider.CreateRole("test role");
            membershipProvider.CreateUserAndAccount("user1", "password");
            var exception = Assert.Throws<ProviderException>(() => roleProvider.AddUsersToRoles(new[] { "user1" }, new[] { "test role", "test role 2"}));
            Assert.That(exception.Message, Is.EqualTo("Role test role 2 doesn't exist."));
        }

        [Test]
        public void Add_users_to_role_throws_exception_if_one_of_the_roles_is_null()
        {
            roleProvider.CreateRole("test role");
            membershipProvider.CreateUserAndAccount("user1", "password");
            var exception = Assert.Throws<ArgumentException>(() => roleProvider.AddUsersToRoles(new[] { "user1" }, new[] { "test role", null }));
            Assert.That(exception.Message, Is.EqualTo("Role name cannot be null." + Environment.NewLine + "Parameter name: roleNames"));
        }

        [Test]
        public void Add_users_to_role_throws_exception_if_one_of_the_roles_is_empty()
        {
            roleProvider.CreateRole("test role");
            membershipProvider.CreateUserAndAccount("user1", "password");
            var exception = Assert.Throws<ArgumentException>(() => roleProvider.AddUsersToRoles(new[] { "user1" }, new[] { "test role", string.Empty }));
            Assert.That(exception.Message, Is.EqualTo("Role name cannot be empty." + Environment.NewLine + "Parameter name: roleNames"));
        }

        [Test]
        public void Add_users_to_role_throws_exception_roles_names_array_is_null()
        {
            membershipProvider.CreateUserAndAccount("user1", "password");

            var exception = Assert.Throws<ArgumentNullException>(() => roleProvider.AddUsersToRoles(new[] { "user1" }, null));
            Assert.That(exception.Message, Is.EqualTo("Value cannot be null." + Environment.NewLine + "Parameter name: roleNames"));
        }

        [Test]
        public void Add_users_to_role_throws_exception_if_one_of_the_users_does_not_exist()
        {
            roleProvider.CreateRole("test role");
            membershipProvider.CreateUserAndAccount("user1", "password");
            var exception = Assert.Throws<ProviderException>(() => roleProvider.AddUsersToRoles(new[] { "user1", "user2" }, new[] { "test role" }));
            Assert.That(exception.Message, Is.EqualTo("User user2 doesn't exist."));
        }

        [Test]
        public void Add_users_to_role_throws_exception_if_one_of_the_users_is_null()
        {
            roleProvider.CreateRole("test role");
            membershipProvider.CreateUserAndAccount("user1", "password");
            var exception = Assert.Throws<ArgumentException>(() => roleProvider.AddUsersToRoles(new[] { "user1", null }, new[] { "test role" }));
            Assert.That(exception.Message, Is.EqualTo("User name cannot be null." + Environment.NewLine + "Parameter name: userNames"));
        }

        [Test]
        public void Add_users_to_role_throws_exception_if_one_of_the_users_is_an_empty_string()
        {
            roleProvider.CreateRole("test role");
            membershipProvider.CreateUserAndAccount("user1", "password");
            var exception = Assert.Throws<ArgumentException>(() => roleProvider.AddUsersToRoles(new[] { "user1", string.Empty }, new[] { "test role" }));
            Assert.That(exception.Message, Is.EqualTo("User name cannot be empty." + Environment.NewLine + "Parameter name: userNames")); 
        }

        [Test]
        public void Add_users_to_role_throws_exception_if_user_names_array_is_null()
        {
            roleProvider.CreateRole("test role");
            var exception = Assert.Throws<ArgumentNullException>(() => roleProvider.AddUsersToRoles(null, new[] { "test role" }));
            Assert.That(exception.Message, Is.EqualTo("Value cannot be null." + Environment.NewLine + "Parameter name: userNames"));
        }

        [Test]
        public void Add_users_to_role_throws_exception_if_user_is_already_in_role()
        {
            roleProvider.CreateRole("test role");
            membershipProvider.CreateUserAndAccount("user1", "password");
            roleProvider.AddUsersToRoles(new[] { "user1"}, new[] { "test role" });
            var exception = Assert.Throws<ProviderException>(() => roleProvider.AddUsersToRoles(new[] { "user1" }, new[] { "test role" }));
            Assert.That(exception.Message, Is.EqualTo("User user1 is already in role test role."));
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
        public void Is_in_role_throws_exception_when_user_does_not_exist()
        {
            roleProvider.CreateRole("test role");
            membershipProvider.CreateUserAndAccount("user1", "password");
            roleProvider.AddUsersToRoles(new[] { "user1" }, new[] { "test role" });

            var exception = Assert.Throws<ProviderException>(() => roleProvider.IsUserInRole("user2", "test role"));
            Assert.That(exception.Message, Is.EqualTo("User user2 does not exist."));
        }

        [Test]
        public void Is_in_role_throws_exception_when_user_name_is_null()
        {
            roleProvider.CreateRole("test role");
            var exception = Assert.Throws<ArgumentNullException>(() => roleProvider.IsUserInRole(null, "test role"));
            Assert.That(exception.Message, Is.EqualTo("Value cannot be null." + Environment.NewLine + "Parameter name: userName"));
        }

        [Test]
        public void Is_in_role_throws_exception_when_user_name_is_empty()
        {
            roleProvider.CreateRole("test role");
            var exception = Assert.Throws<ArgumentException>(() => roleProvider.IsUserInRole(string.Empty, "test role"));
            Assert.That(exception.Message, Is.EqualTo("User name cannot be empty." + Environment.NewLine + "Parameter name: userName"));
        }

        [Test]
        public void Is_in_role_throws_exception_when_role_does_not_exist()
        {
            roleProvider.CreateRole("test role");
            membershipProvider.CreateUserAndAccount("user1", "password");
            roleProvider.AddUsersToRoles(new[] { "user1" }, new[] { "test role" });

            var exception = Assert.Throws<ProviderException>(() => roleProvider.IsUserInRole("user1", "nonexistant role"));
            Assert.That(exception.Message, Is.EqualTo("Role nonexistant role does not exist."));
        }

        [Test]
        public void Is_in_role_throws_exception_when_role_name_is_null()
        {
            var exception = Assert.Throws<ArgumentNullException>(() => roleProvider.IsUserInRole("user1", null));
            Assert.That(exception.Message, Is.EqualTo("Value cannot be null." + Environment.NewLine + "Parameter name: roleName"));
        }

        [Test]
        public void Is_in_role_throws_exception_when_role_name_is_empty()
        {
            var exception = Assert.Throws<ArgumentException>(() => roleProvider.IsUserInRole("user1", string.Empty));
            Assert.That(exception.Message, Is.EqualTo("Role name cannot be empty." + Environment.NewLine + "Parameter name: roleName"));
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
        public void Remove_users_from_roles_throws_exception_if_any_of_the_roles_do_not_exist()
        {
            roleProvider.CreateRole("test role 1");
            membershipProvider.CreateUserAndAccount("user1", "password");
            var exception = Assert.Throws<ProviderException>(() => roleProvider.RemoveUsersFromRoles(new[] { "user1" }, new[] { "test role 1", "test role 2" }));
            Assert.That(exception.Message, Is.EqualTo("Role test role 2 does not exist."));
        }

        [Test]
        public void Remove_users_from_roles_throws_exception_if_any_of_the_role_names_is_null()
        {
            roleProvider.CreateRole("test role 1");
            membershipProvider.CreateUserAndAccount("user1", "password");
            var exception = Assert.Throws<ArgumentException>(() => roleProvider.RemoveUsersFromRoles(new[] { "user1" }, new[] { "test role 1", null }));
            Assert.That(exception.Message, Is.EqualTo("Role name cannot be null." + Environment.NewLine + "Parameter name: roleNames"));
        }

        [Test]
        public void Remove_users_from_roles_throws_exception_if_any_of_the_role_names_is_empty()
        {
            roleProvider.CreateRole("test role 1");
            membershipProvider.CreateUserAndAccount("user1", "password");
            var exception = Assert.Throws<ArgumentException>(() => roleProvider.RemoveUsersFromRoles(new[] { "user1" }, new[] { "test role 1", string.Empty }));
            Assert.That(exception.Message, Is.EqualTo("Role name cannot be empty." + Environment.NewLine + "Parameter name: roleNames"));
        }
        
        [Test]
        public void Remove_users_from_roles_throws_exception_if_role_names_array_is_null()
        {
            var exception = Assert.Throws<ArgumentNullException>(() => roleProvider.RemoveUsersFromRoles(new[] { "user1" }, null));
            Assert.That(exception.Message, Is.EqualTo("Value cannot be null." + Environment.NewLine + "Parameter name: roleNames"));
        }

        [Test]
        public void Remove_users_from_roles_throws_exception_if_any_of_the_users_do_not_exist()
        {
            roleProvider.CreateRole("test role 1");
            membershipProvider.CreateUserAndAccount("user1", "password");
            var exception = Assert.Throws<ProviderException>(() => roleProvider.RemoveUsersFromRoles(new[] { "user1", "user2" }, new[] { "test role 1" }));
            Assert.That(exception.Message, Is.EqualTo("User user2 does not exist."));
        }

        [Test]
        public void Remove_users_from_roles_throws_exception_if_any_of_the_user_names_is_null()
        {
            roleProvider.CreateRole("test role 1");
            membershipProvider.CreateUserAndAccount("user1", "password");
            var exception = Assert.Throws<ArgumentException>(() => roleProvider.RemoveUsersFromRoles(new[] { "user1", null }, new[] { "test role 1" }));
            Assert.That(exception.Message, Is.EqualTo("User name cannot be null." + Environment.NewLine + "Parameter name: userNames"));
        }

        [Test]
        public void Remove_users_from_roles_throws_exception_if_any_of_the_user_names_is_empty()
        {
            membershipProvider.CreateUserAndAccount("user1", "password");
            roleProvider.CreateRole("test role 1");
            var exception = Assert.Throws<ArgumentException>(() => roleProvider.RemoveUsersFromRoles(new[] { "user1", string.Empty }, new[] { "test role 1" }));
            Assert.That(exception.Message, Is.EqualTo("User name cannot be empty." + Environment.NewLine + "Parameter name: userNames"));
        }

        [Test]
        public void Remove_users_from_roles_throws_exception_if_user_names_array_is_null()
        {
            var exception = Assert.Throws<ArgumentNullException>(() => roleProvider.RemoveUsersFromRoles(null, new[] { "test role 1" }));
            Assert.That(exception.Message, Is.EqualTo("Value cannot be null." + Environment.NewLine + "Parameter name: userNames"));
        }

        [Test]
        public void Remove_users_from_roles_throws_exception_if_any_of_the_users_are_not_already_in_role()
        {
            roleProvider.CreateRole("test role 1");
            membershipProvider.CreateUserAndAccount("user1", "password");
            membershipProvider.CreateUserAndAccount("user2", "password");
            roleProvider.AddUsersToRoles(new[] { "user1" }, new[] { "test role 1" });
            var exception = Assert.Throws<ProviderException>(() => roleProvider.RemoveUsersFromRoles(new[] { "user1", "user2" }, new[] { "test role 1" }));
            Assert.That(exception.Message, Is.EqualTo("User user2 is not currently in role test role 1."));
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
        public void Find_users_in_role_returns_in_alphabetical_order()
        {
            roleProvider.CreateRole("test role 1");
            membershipProvider.CreateUserAndAccount("user2", "password");
            membershipProvider.CreateUserAndAccount("user1", "password");
            roleProvider.AddUsersToRoles(new[] { "user2" }, new[] { "test role 1" });
            roleProvider.AddUsersToRoles(new[] { "user1" }, new[] { "test role 1" });

            var results = roleProvider.FindUsersInRole("test role 1", "user");
            Assert.That(results.Length, Is.EqualTo(2));
            Assert.That(results.ElementAt(0), Is.EqualTo("user1"));
            Assert.That(results.ElementAt(1), Is.EqualTo("user2"));
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
            var exception = Assert.Throws<ProviderException>(() => roleProvider.FindUsersInRole("fake role", "fake user"));
            Assert.That(exception.Message, Is.EqualTo("Role fake role does not exist."));
        }

        [Test]
        public void Get_users_in_role_returns_an_empty_array_if_role_has_no_users()
        {
            roleProvider.CreateRole("test role 1");
            var users = roleProvider.GetUsersInRole("test role 1");
            Assert.That(users.Length, Is.EqualTo(0));
        }

        [Test]
        public void Get_users_in_role_throws_exception_for_unknown_role_name()
        {
            var exception = Assert.Throws<ProviderException>(() => roleProvider.GetUsersInRole("fake role"));
            Assert.That(exception.Message, Is.EqualTo("Role fake role does not exist."));
        }

        [Test]
        public void Get_users_in_role_throws_exception_for_null_role_name()
        {
            var exception = Assert.Throws<ArgumentNullException>(() => roleProvider.GetUsersInRole(null));
            Assert.That(exception.Message, Is.EqualTo("Value cannot be null." + Environment.NewLine + "Parameter name: roleName"));
        }
        
        [Test]
        public void Get_users_in_role_throws_exception_for_empty_role_name()
        {
            var exception = Assert.Throws<ArgumentException>(() => roleProvider.GetUsersInRole(string.Empty));
            Assert.That(exception.Message, Is.EqualTo("Role name cannot be empty." + Environment.NewLine + "Parameter name: roleName"));
        }

        [Test]
        public void Get_roles_for_user_returns_an_empty_array_if_user_is_not_in_any_role()
        {
            membershipProvider.CreateUserAndAccount("user1", "password");

            var roles = roleProvider.GetRolesForUser("user1");
            Assert.That(roles.Length, Is.EqualTo(0));
        }

        [Test]
        public void Get_roles_for_user_throws_exception_for_unknown_user_name()
        {
            var exception = Assert.Throws<ProviderException>(() => roleProvider.GetRolesForUser("fake user"));
            Assert.That(exception.Message, Is.EqualTo("User fake user does not exist."));
        }

        [Test]
        public void Get_roles_for_user_throws_exception_for_null_user_name()
        {
            var exception = Assert.Throws<ArgumentNullException>(() => roleProvider.GetRolesForUser(null));
            Assert.That(exception.Message, Is.EqualTo("Value cannot be null." + Environment.NewLine + "Parameter name: userName"));
        }

        [Test]
        public void Get_roles_for_user_throws_exception_for_empty_user_name()
        {
            var exception = Assert.Throws<ArgumentException>(() => roleProvider.GetRolesForUser(string.Empty));
            Assert.That(exception.Message, Is.EqualTo("User name cannot be empty." + Environment.NewLine + "Parameter name: userName"));
        }
    }
}
