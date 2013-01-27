using Raven.Abstractions.Indexing;
using Raven.Client.Indexes;
using System.Linq;
using RavenDbSimpleMembershipProvider.Domain;

namespace RavenDbSimpleMembershipProvider.Indexes
{
    class UserNameContainsIndex : AbstractIndexCreationTask<UserProfile>
    {
        public UserNameContainsIndex()
        {
            Map = users => from user in users
                           select new { user.UserName };
            
            Index(x => x.UserName, FieldIndexing.Analyzed);
        }
    }
}
