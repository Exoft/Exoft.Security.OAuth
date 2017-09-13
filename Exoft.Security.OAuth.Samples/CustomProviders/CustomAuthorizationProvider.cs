using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using Exoft.Security.OAuth.Samples.Service;
using Exoft.Security.OAuthServer.Common;
using Exoft.Security.OAuthServer.Core;
using Exoft.Security.OAuthServer.Extensions;
using Exoft.Security.OAuthServer.Providers;
using AuthenticationProperties = Microsoft.AspNetCore.Authentication.AuthenticationProperties;
using IAuthenticationService = Exoft.Security.OAuthServer.Providers.IAuthenticationService;

namespace Exoft.Security.OAuth.Samples.CustomProviders
{
    public sealed class CustomAuthorizationProvider : ExoftOAuthServerProvider
    {
        public CustomAuthorizationProvider(IAuthenticationService authService,
            IAuthenticationConfiguration configuration) : base(authService, configuration) { }
    }
}
