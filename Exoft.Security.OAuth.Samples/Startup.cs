using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Exoft.Security.OAuth.Samples.CustomProviders;
using Exoft.Security.OAuth.Samples.Service;
using Exoft.Security.OAuthServer.Core;
using Exoft.Security.OAuthServer.Providers;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Exoft.Security.OAuth.Samples
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            #region TEST DATA
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

            #endregion

            services.AddAuthentication().AddOAuthValidation()

            .AddOpenIdConnectServer(options =>
            {
                //options.ProviderType = typeof(CustomAuthorizationProvider);
                options.ProviderType = typeof(ExoftOAuthServerProvider);

                // Enable the authorization, logout, token and userinfo endpoints.
                options.TokenEndpointPath = "/token";
                options.AccessTokenLifetime = TimeSpan.FromMinutes(configs.AccessTokenLifetimeMinutes);
                options.RefreshTokenLifetime = TimeSpan.FromMinutes(configs.RefreshTokenLifetimeMinutes);

                // Note: see AuthorizationController.cs for more
                // information concerning ApplicationCanDisplayErrors.
                options.ApplicationCanDisplayErrors = true;
                options.AllowInsecureHttp = true;
            });

            //services.AddScoped<CustomAuthorizationProvider>();
            services.AddScoped<ExoftOAuthServerProvider>();

            services.AddSingleton<IAuthenticationService>(p => authService);
            services.AddSingleton<IAuthenticationConfiguration>(p => configs);

            //services.AddTransient<IAuthenticationService, TestAuthenticationService>();
            //services.AddTransient<IAuthenticationConfiguration, TestAuthConfiguration>();

            services.AddMvc();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseAuthentication();

            app.UseMvc();
        }
    }
}
