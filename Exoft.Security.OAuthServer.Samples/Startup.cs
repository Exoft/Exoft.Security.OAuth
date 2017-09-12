using System;
using Exoft.Security.OAuthServer.Core;
using Exoft.Security.OAuthServer.Extensions;
using Exoft.Security.OAuthServer.Samples.AuthProviders;
using Exoft.Security.OAuthServer.Samples.Service;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Exoft.Security.OAuthServer.Samples
{
    public class Startup
    {
        public Startup(IHostingEnvironment env)
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true)
                .AddEnvironmentVariables();
            Configuration = builder.Build();
        }

        public IConfigurationRoot Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            // Add framework services.
            services.AddMvc();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        //TODO: add fetching implemented AuthService by dependency injection (similar to samples with ASP .NET Identity)
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            #region Using Exoft.Security.OAuth

            app.UseOAuthValidation();

            var authService = new TestAuthenticationService(
                new User
                {
                    Id = 1,
                    Username = "Markiyan Skolozdra",
                    Role = "Administrator",
                    Password = "P@ssw0rd",
                    Secret = "sD3fPKLnFKZUjnSV4qA/XoJOqsmDfNfxWcZ7kPtLc0I=" // SHA hash of Password - only for testing
                });
            var configs = new TestAuthConfiguration
            {
                Scope = "openid offline_access",
                AccessTokenLifetimeMinutes = 120,
                RefreshTokenLifetimeMinutes = 30
            };
            app.UseExoftOAuthServer(new ExoftOAuthServerOptions(authService, configs)
            {
                Provider = new CustomAuthorizationProvider(authService, configs),
                TokenEndpointPath = "/token",
                AllowInsecureHttp = true,
                AccessTokenLifetime = TimeSpan.FromMinutes(configs.AccessTokenLifetimeMinutes),
                RefreshTokenLifetime = TimeSpan.FromMinutes(configs.RefreshTokenLifetimeMinutes)
            });

            #endregion

            app.UseMvc();
        }
    }
}