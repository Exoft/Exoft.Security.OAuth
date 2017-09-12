using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Exoft.Security.OAuth.Samples.CustomProviders;
using Exoft.Security.OAuth.Samples.Service;
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
            services.AddAuthentication().AddOAuthValidation()

            .AddOpenIdConnectServer(options =>
            {
                options.ProviderType = typeof(CustomAuthorizationProvider);

                // Enable the authorization, logout, token and userinfo endpoints.
                options.AuthorizationEndpointPath = "/connect/authorize";
                options.LogoutEndpointPath = "/connect/logout";
                options.TokenEndpointPath = "/token";
                options.UserinfoEndpointPath = "/connect/userinfo";

                // Note: see AuthorizationController.cs for more
                // information concerning ApplicationCanDisplayErrors.
                options.ApplicationCanDisplayErrors = true;
                options.AllowInsecureHttp = true;
            });

            services.AddScoped<CustomAuthorizationProvider>();

            services.AddTransient<IAuthenticationService, TestAuthenticationService>();
            services.AddTransient<IAuthenticationConfiguration, TestAuthConfiguration>();

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
