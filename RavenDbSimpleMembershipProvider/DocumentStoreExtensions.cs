using Raven.Client;
using System.Threading;

namespace RavenDbSimpleMembershipProvider
{
    public static class DocumentSessionExtensions
    {
        public static void WaitForNonStaleIndexes(this IDocumentStore documentStore)
        {
            while (documentStore.DatabaseCommands.GetStatistics().StaleIndexes.Length != 0)
            {
                Thread.Sleep(10);
            }
        }
    }
}
