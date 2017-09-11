using AspNet.Security.OpenIdConnect.Server;
using Exoft.Security.OAuthServer.Providers;

namespace Exoft.Security.OAuthServer.Core
{
    //
    // Summary:
    //     Exposes various settings needed to control the behavior of the OpenID Connect
    //     server.
    public class ExoftOAuthServerOptions : OpenIdConnectServerOptions
    {
        public ExoftOAuthServerOptions(IAuthenticationService service, IAuthenticationConfiguration configuration)
        {
            Provider = new ExoftOAuthServerProvider(service, configuration);
        }
    }
}