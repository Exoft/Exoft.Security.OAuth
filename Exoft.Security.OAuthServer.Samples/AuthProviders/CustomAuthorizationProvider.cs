using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using Exoft.Security.OAuthServer.Common;
using Exoft.Security.OAuthServer.Core;
using Exoft.Security.OAuthServer.Providers;
using Exoft.Security.OAuthServer.Samples.Service;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Authentication;

namespace Exoft.Security.OAuthServer.Samples.AuthProviders
{
    public sealed class CustomAuthorizationProvider : ExoftOAuthServerProvider
    {
        public CustomAuthorizationProvider(IAuthenticationService authService, IAuthenticationConfiguration configuration) : base(authService, configuration) { }

        // TODO: Add response filter which will be remove some properties from response: id_token and etc
    }
}
