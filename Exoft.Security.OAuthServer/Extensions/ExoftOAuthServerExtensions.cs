using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using Exoft.Security.OAuthServer.Common;
using Exoft.Security.OAuthServer.Core;
using Exoft.Security.OAuthServer.Providers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http.Authentication;

namespace Exoft.Security.OAuthServer.Extensions
{
    public static class ExoftOAuthServerExtensions
    {
        /// <summary>
        /// Use this method, because there we are using old version of AuthenticationTicket object from Asp.Net Core 1.0, until OpenIdConnect update their library to use .Net Core 2.0 objects
        /// </summary>
        /// <param name="context"></param>
        /// <param name="principal"></param>
        /// <param name="properties"></param>
        /// <param name="authenticationScheme"></param>
        /// <param name="scopes"></param>
        /// <param name="resources"></param>
        public static void Validate(this HandleTokenRequestContext context,
            ClaimsPrincipal principal,
            AuthenticationProperties properties,
            string authenticationScheme,
            List<string> scopes = null,
            List<string> resources = null)
        {
            var ticket = new AuthenticationTicket(principal, properties, authenticationScheme);

            if (context.Request.IsClientCredentialsGrantType())
            {
                if (scopes == null || !scopes.Any())
                    scopes = new[]
                    {
                        /* openid: */ OpenIdConnectConstants.Scopes.OpenId,
                        /* email: */ OpenIdConnectConstants.Scopes.Email,
                        /* profile: */ OpenIdConnectConstants.Scopes.Profile,
                    }.ToList();
            }
            else //if (context.Request.IsPasswordGrantType())
            {
                if (scopes == null || !scopes.Any())
                    scopes = new[]
                    {
                        /* openid: */ OpenIdConnectConstants.Scopes.OpenId,
                        /* email: */ OpenIdConnectConstants.Scopes.Email,
                        /* profile: */ OpenIdConnectConstants.Scopes.Profile,
                        /* offline_access: */ OpenIdConnectConstants.Scopes.OfflineAccess
                    }.ToList();
            }

            // Set the list of scopes granted to the client application.
            ticket.SetScopes(scopes.Intersect(context.Request.GetScopes()));

            if (resources != null && resources.Any())
                ticket.SetResources(resources);

            context.Validate(ticket);
        }


        // TODO add desciption about default values if user wants to use this method: 
        // TODO TokenEndpointPath = "/token", AllowInsecureHttp = false
        // TODO AccessTokenLifetime = TimeSpan.FromHours(1), RefreshTokenLifetime = TimeSpan.FromDays(14)

        /// <summary>
        /// 
        /// </summary>
        /// <param name="app"></param>
        /// <param name="service"></param>
        /// <param name="configuration"></param>
        /// <returns></returns>
        public static IApplicationBuilder UseExoftOAuthServer(this IApplicationBuilder app, IAuthenticationService service, IAuthenticationConfiguration configuration)
        {
            var options = new ExoftOAuthServerOptions(service, configuration)
            {
                //AuthorizationEndpointPath = "/authorize",
                TokenEndpointPath = "/token",
                AllowInsecureHttp = false,
                AccessTokenLifetime = TimeSpan.FromHours(OAuthServerConstants.AccessTokenExpireTimeMinutes),
                RefreshTokenLifetime = TimeSpan.FromMinutes(OAuthServerConstants.RefreshTokenExpireTimeMinutes)
            };

            app.UseOpenIdConnectServer(options);

            return app;
        }

        //
        // Summary:
        //     Adds a new OpenID Connect server instance in the ASP.NET Core pipeline.
        //
        // Parameters:
        //   app:
        //     The web application builder.
        //
        //   configuration:
        //     A delegate allowing to modify the options controlling the behavior of the OpenID
        //     Connect server.
        //
        // Returns:
        //     The application builder.
        public static IApplicationBuilder UseExoftOAuthServer(this IApplicationBuilder app,
            Action<ExoftOAuthServerOptions> configuration)
        {
            app.UseOpenIdConnectServer((Action<OpenIdConnectServerOptions>)configuration);
            return app;
        }



        //
        // Summary:
        //     Adds a new OpenID Connect server instance in the ASP.NET Core pipeline.
        //
        // Parameters:
        //   app:
        //     The web application builder.
        //
        //   options:
        //     The options controlling the behavior of the OpenID Connect server.
        //
        // Returns:
        //     The application builder.
        public static IApplicationBuilder UseExoftOAuthServer(this IApplicationBuilder app,
            ExoftOAuthServerOptions options)
        {
            app.UseOpenIdConnectServer(options);
            return app;
        }
    }
}
