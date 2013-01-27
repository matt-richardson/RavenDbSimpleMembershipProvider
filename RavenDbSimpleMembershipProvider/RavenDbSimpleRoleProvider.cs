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
            if (userNames.Length == 0 || roleNames.Length == 0) return;

            using (var session = documentStore.OpenSession())
            {
                var users = session.Query<UserProfile>().Where(x => x.UserName.In(userNames));
                var roles = session.Query<WebpagesRole>().Where(x => x.RoleName.In(roleNames));
                foreach (var user in users)
                {
                    foreach (var role in roles)
                    {
                        if (!user.Roles.Contains(role.Id))
                            user.Roles.Add(role.Id);
                    }
                }
                session.SaveChanges();
            }
        }

        public override void CreateRole(string roleName)
        {
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
            using (var session = documentStore.OpenSession())
            {
                var role = session.Query<WebpagesRole>().FirstOrDefault(x => x.RoleName == roleName);
                if (role == null) throw new ProviderException(string.Format("Role {0} does not exist!", roleName));
                var usersInRole = session.Query<UserProfile>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .Where(x => x.Roles.Any(roleId => roleId == role.Id));

                if (usersInRole.Any())
                {
                    if (throwOnPopulatedRole)
                        throw new ProviderException(string.Format("Role {0} is not empty!", roleName));
                    return false;
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
                    throw new ProviderException(string.Format("Role {0} does not exist!", roleName));

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
            using (var session = documentStore.OpenSession())
            {
                var user = session.Query<UserProfile>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .FirstOrDefault(x => x.UserName == userName);
                if (user == null) 
                    throw new ProviderException(string.Format("User {0} does not exist!", userName));

                var roles = session.Query<WebpagesRole>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .Where(x => x.Id.In(user.Roles));

                return roles.Select(x => x.RoleName).ToArray();
            }
        }

        public override string[] GetUsersInRole(string roleName)
        {
            using (var session = documentStore.OpenSession())
            {
                var role = session.Query<WebpagesRole>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .FirstOrDefault(x => x.RoleName == roleName);
                if (role == null) 
                    throw new ProviderException(string.Format("Role {0} does not exist!", roleName));
                
                var users = session.Query<UserProfile>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .Where(x => x.Roles.Any(roleId => roleId == role.Id))
                    .Select(x => x.UserName);

                return users.ToArray();
            }
        }

        public override bool IsUserInRole(string userName, string roleName)
        {
            using (var session = documentStore.OpenSession())
            {
                var user = session.Query<UserProfile>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .FirstOrDefault(x => x.UserName == userName);
                if (user == null) 
                    throw new ProviderException(string.Format("User {0} does not exist!", userName));
                
                var role = session.Query<WebpagesRole>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .FirstOrDefault(x => x.RoleName == roleName);
                if (role == null) 
                    throw new ProviderException(string.Format("Role {0} does not exist!", roleName));

                return user.Roles.Contains(role.Id);
            }
        }

        public override void RemoveUsersFromRoles(string[] userNames, string[] roleNames)
        {
            if (userNames.Length == 0 || roleNames.Length == 0) return;

            using (var session = documentStore.OpenSession())
            {
                var users = session.Query<UserProfile>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .Where(x => x.UserName.In(userNames))
                    .ToList();

                if (!users.Any()) 
                    return;

                var roles = session.Query<WebpagesRole>()
                    .Customize(x => x.WaitForNonStaleResultsAsOfNow())
                    .Where(x => x.RoleName.In(roleNames))
                    .ToList();

                if (!roles.Any()) return;

                foreach (var user in users)
                {
                    foreach (var role in roles)
                        user.Roles.Remove(role.Id);
                }
                session.SaveChanges();
            }
        }

        public override bool RoleExists(string roleName)
        {
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
