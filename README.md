# Exoft.Security.OAuth
ASP.NET Core OAuth 2 simple implementation

Exoft.Security.OAuth authentication provider that wraps OpenIdConnect.Server up into an easier-to-use package in ASP.NET Core application.

# Getting Started

To use library you need to follow these steps:

- Have an existing ASP .NET Core project or create new one, recommended to use `.NET Core 2.0` version of target framework;

- Install the appropriate nuget package [**Exoft.Security.OAuthServer 2.x**](https://www.nuget.org/packages/Exoft.Security.OAuthServer)

- Configure the `Startup.cs` file by adding neccassary options, similar to this:

```csharp
public void ConfigureServices(IServiceCollection services)
        {
            #region TEST DATA
            var authService = new TestAuthenticationService(
                new User
                {
                    Id = 1,
                    Username = "admin@admin",
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
                
                options.TokenEndpointPath = "/token";
                options.AccessTokenLifetime = TimeSpan.FromMinutes(configs.AccessTokenLifetimeMinutes);
                options.RefreshTokenLifetime = TimeSpan.FromMinutes(configs.RefreshTokenLifetimeMinutes);
                
                options.ApplicationCanDisplayErrors = true;
                options.AllowInsecureHttp = true;
            });

            //services.AddScoped<CustomAuthorizationProvider>();
            services.AddScoped<ExoftOAuthServerProvider>();

            services.AddSingleton<IAuthenticationService>(p => authService);
            services.AddSingleton<IAuthenticationConfiguration>(p => configs);

            services.AddMvc();
        }
        
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            app.UseAuthentication();
            
            app.UseMvc();
        }
```

Besides settings that contains above you should implement two interfaces: 
- `IAuthenticationService` - implemented methods should contain loading Users, RefreshTokens and credentials validation.
That are: **FindUser, FindRefreshToken, ValidateRequestedUser, ValidateRequestedUserCredentials, AddRefreshToken, DeleteRefreshToken**.
- `IAuthenticationConfiguration` - contains properties that will be used for setting of authentication provider.
For example, specified property `Scope` helps to avoid adding that property in each token request - just pass it once in that place.

`TestAuthenticationService` and `TestAuthConfiguration` classes contain implementation of the interfaces respectively: `IAuthenticationService`, `IAuthenticationConfiguration`.

These implementations will be passed into constructor of `ExoftOAuthServerProvider` object through default DI container. For more customization of authentication you can override default `ExoftOAuthServerProvider` that contains methods which are perform validation and handling of token request.

**Also important step of settings is necessary adding of attribute above each controller with specific parameter, such as following:**

```csharp
    [Authorize(AuthenticationSchemes = OAuthValidationDefaults.AuthenticationScheme]
    public class ResourceController : Controller
    { ... }
```

# Demo

For using your authorization server you just need to make the request with appropriate parameters which are described below.

Request URL: `http://localhost/token`.

Request methods: `POST`.

Parameters which are using for: 

- **Authentication**

`grant_type` with the value `password`

`username` with the user's username

`password` with the user's password


- **Refresh token grant**

`grant_type` with the value `refresh_token`

`refresh_token` with the refresh token


The authorization server will respond with a JSON object containing the following properties:

`token_type` with the value `Bearer`

`expires_in` with an integer representing the TTL of the access token

`access_token` the access token itself

`refresh_token` a refresh token that can be used to acquire a new access token when the original expires


In the case when authentication or request on updating access token were succeeded, the result will be next:

```json
{
    "token_type": "Bearer",
    "access_token": "CfDJ8KZN5Hdk1ppDj3lARi7jAq4UCMP ...",
    "expires_in": 7199,
    "refresh_token": "CfDJ8KZN5Hdk1ppDj3lARi7jAq6P7y ...",
    "id_token": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0 ..."
}
```


- **Client credentials grant**

`grant_type` with the value `client_credentials`

`client_id` with the the client's ID

`client_secret` with the client's secret

`scope` with a space-delimited list of requested scope permissions.

The authorization server will respond with a JSON object containing the following properties:

`token_type` with the value `Bearer`

`expires_in` with an integer representing the TTL of the access token

`access_token` the access token itself


Otherwise, will get the error response, similar to this:

```json
{
    "error": "invalid_grant",
    "error_description": "The refresh token is no longer valid."
}
```

# Samples

Sample project is located in the [directory](https://github.com/Exoft/Exoft.Security.OAuthServer.Samples).
