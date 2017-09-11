using System;
using AspNet.Security.OpenIdConnect.Server;
using Exoft.Security.OAuthServer.Common;
using Exoft.Security.OAuthServer.Core;
using Exoft.Security.OAuthServer.Providers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;

namespace Exoft.Security.OAuthServer.Extensions
{
    public static class ExoftOAuthServerExtensions
    {
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
