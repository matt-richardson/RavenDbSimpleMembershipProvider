# RavenDbSimpleMembershipProvider #

An implementation of the ExtendedMembershipProvider to use with MVC 4, and the OAuth providers.

A port of [https://github.com/malibeg/MongodbSimpleMembershipProvider](https://github.com/malibeg/MongodbSimpleMembershipProvider) (which in itself a port of [http://www.mattjcowan.com/funcoding/2012/11/10/simplemembershipprovider-in-mvc4-for-mysql-oracle-and-more-with-llblgen/](http://www.mattjcowan.com/funcoding/2012/11/10/simplemembershipprovider-in-mvc4-for-mysql-oracle-and-more-with-llblgen/)).

## Please Note ##
This is still a work in progress. Please let me know if you find any issues, or better yet, please submit a pull request.
Also note that this is really the first time I've worked with RavenDb, so if there are any ways in which it could be improved, please let me know.

## How to use ##

In your MVC 4.0 site, make sure you have the following in your web.config:

    <configuration>
      <system.web>
        <membership defaultProvider="DefaultMembershipProvider">
          <providers>
            <add name="DefaultMembershipProvider"
                 type="RavenDbSimpleMembershipProvider.RavenDbSimpleMembershipProvider"
                 connectionStringName="DefaultConnection"
                 enablePasswordRetrieval="false"
                 enablePasswordReset="true"
                 requiresQuestionAndAnswer="false"
                 requiresUniqueEmail="false"
                 maxInvalidPasswordAttempts="5"
                 minRequiredPasswordLength="6"
                 minRequiredNonalphanumericCharacters="0"
                 passwordAttemptWindow="10"
                 applicationName="/" />
          </providers>
        </membership>
        <roleManager defaultProvider="DefaultRoleProvider">
          <providers>
            <add name="DefaultRoleProvider"
                 type="RavenDbSimpleMembershipProvider.RavenDbSimpleRoleProvider"
                 connectionStringName="DefaultConnection"
                 applicationName="/" />
          </providers>
        </roleManager>
      </system.web>
    </configuration>

The connection string is not used at present (work in progress!).

At some point in the launch of your application, set the DocumentStore property:

    RavenDbSimpleMembershipProvider.RavenDbSimpleMembershipProvider.DocumentStore = DocumentStoreHolder.Store;
    RavenDbSimpleMembershipProvider.RavenDbSimpleRoleProvider.DocumentStore = DocumentStoreHolder.Store;

From there, you should be laughing.

## Known issues ##
* Doesn't support multiple applications in the same database
* Doesn't support the "connectionStringName" attribute
* Doesn't support ravendb in embedded mode (ie, you currently have to pass in the document store)
* Doesn't support unit of work pattern (should it?)
* Uses WaitForNonStaleResultsAsOfNow everywhere to fit in with the interface (which assumes its a immediately consistent data store). Not really convinced is a good idea.
* no tests around the initialize() methods