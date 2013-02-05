using Raven.Client;
using Raven.Client.Indexes;
using Raven.Client.Linq;
using System;
using System.Collections.Specialized;
using System.Configuration.Provider;
using System.Globalization;
using System.Linq;
using System.Web.Security;
using RavenDbSimpleMembershipProvider.Domain;
using RavenDbSimpleMembershipProvider.Indexes;

namespace RavenDbSimpleMembershipProvider
{
    public class RavenDbSimpleRoleProvider : RoleProvider
    {
        private static IDocumentStore documentStore { get; set; }

        public static IDocumentStore DocumentStore
        {
            get { return documentStore; }
            set 
            {
                if (documentStore == value) return;
                documentStore = value;
                SetupIndexes();
            }
        }

        private static void SetupIndexes()
        {
            IndexCreation.CreateIndexes(typeof(UserNameContainsIndex).Assembly, documentStore);
        }

        public override void Initialize(string name, NameValueCollection config)
        {
            if (config == null)
                throw new ArgumentNullException("config");
            
            if (string.IsNullOrEmpty(name))
                name = "ExtendedAdapterRoleProvider";
            
            if (string.IsNullOrEmpty(config["description"]))
            {
                config.Remove("description");
                config.Add("description", "Adapter Extended Role Provider");
            }
            base.Initialize(name, config);

            ApplicationName = GetValueOrDefault(config, "applicationName", o => o.ToString(), "MySampleApp");

            EnsureWeDidntGetTooManyConfigAttributes(config);
        }

        private static void EnsureWeDidntGetTooManyConfigAttributes(NameValueCollection config)
        {
            config.Remove("name");
            config.Remove("description");
            config.Remove("applicationName");
            config.Remove("connectionString");

            if (config.Count <= 0)
                return;
            var key = config.GetKey(0);
            if (string.IsNullOrEmpty(key))
                return;

            throw new ProviderException(
                string.Format(CultureInfo.CurrentCulture, "The role provider does not recognize the configuration attribute {0}.", key));
        }

        public string ConnectionStringName { get; set; }

        public override string ApplicationName { get; set; }

        public override void AddUsersToRoles(string[] userNames, string[] roleNames)
        {
            if (userNames == null) throw new ArgumentNullException("userNames");
            if (roleNames == null) throw new ArgumentNullException("roleNames");

            if (userNames.Length == 0 || roleNames.Length == 0) return;

            if (userNames.Any(x => x == null)) throw new ArgumentException("User name cannot be null.", "userNames");
            if (userNames.Any(x => x == string.Empty)) throw new ArgumentException("User name cannot be empty.", "userNames");

            if (roleNames.Any(x => x == null)) throw new ArgumentException("Role name cannot be null.", "roleNames");
            if (roleNames.Any(x => x == string.Empty)) throw new ArgumentException("Role name cannot be empty.", "roleNames");

            using (var session = documentStore.OpenSession())
            {
                var roles = session.Query<WebpagesRole>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .Where(x => x.RoleName.In(roleNames));
                var rolesThatDontExist = roleNames.Except(roles.Select(x => x.RoleName));
                if (rolesThatDontExist.Any()) throw new ProviderException("Role " + rolesThatDontExist.First() + " doesn't exist.");
                
                var users = session.Query<UserProfile>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .Where(x => x.UserName.In(userNames));
                var usersThatDontExist = userNames.Except(users.Select(x => x.UserName));
                if (usersThatDontExist.Any()) throw new ProviderException("User " + usersThatDontExist.First() + " doesn't exist.");

                foreach (var user in users)
                {
                    foreach (var role in roles)
                    {
                        if (user.Roles.Contains(role.Id)) throw new ProviderException(string.Format("User {0} is already in role {1}.", user.UserName, role.RoleName));
                            user.Roles.Add(role.Id);
                    }
                }
                session.SaveChanges();
            }
        }

        public override void CreateRole(string roleName)
        {
            if (roleName == null) throw new ArgumentNullException("roleName");
            if (roleName == string.Empty) throw new ArgumentException("Role name cannot be empty.", "roleName");
            if (roleName.Contains(",")) throw new ArgumentException("Role name cannot contain a comma.", "roleName");

            using (var session = documentStore.OpenSession())
            {
                var roles = session.Query<WebpagesRole>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .Where(x => x.RoleName == roleName);
                if (roles.Count() > 0)
                    throw new ProviderException(string.Format("Role {0} already exists. Cannot create a new role with the same name.", roleName));

                var role = new WebpagesRole { RoleName = roleName };

                session.Store(role);
                session.SaveChanges();
            }
        }

        public override bool DeleteRole(string roleName, bool throwOnPopulatedRole)
        {
            if (roleName == null) throw new ArgumentNullException("roleName");
            if (roleName == string.Empty) throw new ArgumentException("Role name cannot be empty.", "roleName");

            using (var session = documentStore.OpenSession())
            {
                var role = session.Query<WebpagesRole>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .FirstOrDefault(x => x.RoleName == roleName);
                if (role == null) throw new ProviderException(string.Format("Role {0} does not exist.", roleName));

                var usersInRole = session.Query<UserProfile>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .Where(x => x.Roles.Any(roleId => roleId == role.Id));

                if (usersInRole.Any())
                {
                    if (throwOnPopulatedRole)
                        throw new ProviderException(string.Format("Role {0} contains users. As throwOnPopulatedRole is true, refusing to delete.", roleName));
                    foreach (var user in usersInRole)
                        user.Roles.Remove(roleName);
                }
                session.Delete(role);
                session.SaveChanges();
                
                return true;//not sure this is the right thing to return here
            }
        }

        public override string[] FindUsersInRole(string roleName, string usernameToMatch)
        {
            //am sure this could be optimised
            using (var session = documentStore.OpenSession())
            {
                var role = session.Query<WebpagesRole>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .FirstOrDefault(x => x.RoleName == roleName);
                if (role == null) 
                    throw new ProviderException(string.Format("Role {0} does not exist.", roleName));

                documentStore.WaitForNonStaleIndexes();

                var users = session.Query<UserProfile>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .Search(x => x.UserName, "*" + usernameToMatch + "*", 1m, SearchOptions.Guess, EscapeQueryOptions.AllowAllWildcards)
                    .OrderBy(x => x.UserName)
                    .Select(x => x.UserName);

                return users.ToArray();
            }
        }

        public override string[] GetAllRoles()
        {
            using (var session = documentStore.OpenSession())
            {
                var roles = session.Query<WebpagesRole>()
                                   .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                                   .Select(x => x.RoleName);
                return roles.ToArray();
            }
        }

        public override string[] GetRolesForUser(string userName)
        {
            if (userName == null) throw new ArgumentNullException("userName");
            if (userName == string.Empty) throw new ArgumentException("User name cannot be empty.", "userName");

            using (var session = documentStore.OpenSession())
            {
                var user = session.Query<UserProfile>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .FirstOrDefault(x => x.UserName == userName);
                if (user == null) 
                    throw new ProviderException(string.Format("User {0} does not exist.", userName));

                var roles = session.Query<WebpagesRole>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .Where(x => x.Id.In(user.Roles));

                return roles.Select(x => x.RoleName).ToArray();
            }
        }

        public override string[] GetUsersInRole(string roleName)
        {
            if (roleName == null) throw new ArgumentNullException("roleName");
            if (roleName == string.Empty) throw new ArgumentException("Role name cannot be empty.", "roleName");

            using (var session = documentStore.OpenSession())
            {
                var role = session.Query<WebpagesRole>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .FirstOrDefault(x => x.RoleName == roleName);
                if (role == null) throw new ProviderException(string.Format("Role {0} does not exist.", roleName));
                
                var users = session.Query<UserProfile>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .Where(x => x.Roles.Any(roleId => roleId == role.Id))
                    .Select(x => x.UserName);

                return users.ToArray();
            }
        }

        public override bool IsUserInRole(string userName, string roleName)
        {
            if (userName == null) throw new ArgumentNullException("userName");
            if (userName == string.Empty) throw new ArgumentException("User name cannot be empty.", "userName");

            if (roleName == null) throw new ArgumentNullException("roleName");
            if (roleName == string.Empty) throw new ArgumentException("Role name cannot be empty.", "roleName");

            using (var session = documentStore.OpenSession())
            {
                var user = session.Query<UserProfile>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .FirstOrDefault(x => x.UserName == userName);
                if (user == null) 
                    throw new ProviderException(string.Format("User {0} does not exist.", userName));
                
                var role = session.Query<WebpagesRole>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .FirstOrDefault(x => x.RoleName == roleName);
                if (role == null) 
                    throw new ProviderException(string.Format("Role {0} does not exist.", roleName));

                return user.Roles.Contains(role.Id);
            }
        }

        public override void RemoveUsersFromRoles(string[] userNames, string[] roleNames)
        {
            if (userNames == null) throw new ArgumentNullException("userNames");
            if (roleNames == null) throw new ArgumentNullException("roleNames");
            if (userNames.Length == 0 || roleNames.Length == 0) return;

            if (userNames.Any(x => x == null)) throw new ArgumentException("User name cannot be null.", "userNames");
            if (userNames.Any(x => x == string.Empty)) throw new ArgumentException("User name cannot be empty.", "userNames");

            if (roleNames.Any(x => x == null)) throw new ArgumentException("Role name cannot be null.", "roleNames");
            if (roleNames.Any(x => x == string.Empty)) throw new ArgumentException("Role name cannot be empty.", "roleNames");


            using (var session = documentStore.OpenSession())
            {
                var users = session.Query<UserProfile>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .Where(x => x.UserName.In(userNames))
                    .ToList();

                var usersThatDontExist = userNames.Except(users.Select(x => x.UserName));
                if (usersThatDontExist.Any()) throw new ProviderException("User " + usersThatDontExist.First() + " does not exist.");

                var roles = session.Query<WebpagesRole>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .Where(x => x.RoleName.In(roleNames))
                    .ToList();

                var rolesThatDontExist = roleNames.Except(roles.Select(x => x.RoleName));
                if (rolesThatDontExist.Any()) throw new ProviderException("Role " + rolesThatDontExist.First() + " does not exist.");

                foreach (var user in users)
                {
                    foreach (var role in roles)
                    {
                        if (!user.Roles.Contains(role.Id)) 
                            throw new ProviderException(string.Format("User {0} is not currently in role {1}.", user.UserName, role.RoleName));

                        user.Roles.Remove(role.Id);
                    }
                }
                session.SaveChanges();
            }
        }

        public override bool RoleExists(string roleName)
        {
            if (roleName == null) throw new ArgumentNullException("roleName");
            if (roleName == string.Empty) throw new ArgumentException("Value cannot be empty.", "roleName");

            using (var session = documentStore.OpenSession())
            {
                var role = session.Query<WebpagesRole>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .SingleOrDefault(x => x.RoleName == roleName);
                return role != null;
            }
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
    }
}
