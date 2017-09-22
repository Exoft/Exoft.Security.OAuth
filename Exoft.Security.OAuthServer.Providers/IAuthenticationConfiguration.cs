using System;
using System.Collections.Generic;
using System.Text;

namespace Exoft.Security.OAuthServer.Providers
{
    public interface IAuthenticationConfiguration
    {
        int AccessTokenLifetimeMinutes { get; set; }
        int RefreshTokenLifetimeMinutes { get; set; }

        string RequestScope { get; set; }
    }
}
