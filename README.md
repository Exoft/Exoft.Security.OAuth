# Exoft.Security.OAuth
ASP.NET Core OAuth 2 simple implementation

Exoft.Security.OAuth authentication provider that wraps OpenIdConnect.Server up into an easier-to-use package in ASP.NET Core application.

# Getting Started

To use library you need to follow these steps:

- Have an existing ASP .NET Core project or create new one, recommended to use `.NET Core 1.1` version of target framework;

- Install the appropriate nuget package **Exoft.Security.OAuthServer**

- Configure the `Startup.cs` file by adding neccassary options, similar to this:

```csharp
public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            app.UseOAuthValidation();
            
            var authService = new TestAuthenticationService(
                new User
                {
                    Id = 1,
                    Username = "admin@admin",
                    Role = "Administrator",
                    Password = "P@ssw0rd"
                });
            var configs = new TestAuthConfiguration{Scope = "openid offline_access" };
            app.UseExoftOAuthServer(new ExoftOAuthServerOptions(authService, configs)
            {
                Provider = new CustomAuthorizationProvider(authService, configs),
                TokenEndpointPath = "/token",
                AllowInsecureHttp = true,
                AccessTokenLifetime = TimeSpan.FromHours(2),
                RefreshTokenLifetime = TimeSpan.FromMinutes(30)
            });

            app.UseMvc();
        }
```

Besides settings that contains above you should implement two interfaces: 
- `IAuthenticationService` - implemented methods should contain loading Users, RefreshTokens and credentials validation.
That are: **FindUser, FindRefreshToken, ValidateRequestedUser, ValidateRequestedUserCredentials, AddRefreshToken, DeleteRefreshToken**.
- `IAuthenticationConfiguration` - contains properties that will be used for setting of authentication provider.
For example, specified property `Scope` helps to avoid adding that property in each token request - just pass it once in that place.

`TestAuthenticationService` and `TestAuthConfiguration` classes contain implementation of the interfaces respectively: `IAuthenticationService`, `IAuthenticationConfiguration`.

These implementations will be passed into constructor of `ExoftOAuthServerOptions` object. Also, as you can see, there is an opportunity to customize options of `ExoftOAuthServerOptions` object.

For more customization of authentication you can override default `ExoftOAuthServerProvider` that contains methods which are perform validation and handling of token request.


# Demo

For using your authentication server you just need to make the request with appropriate parameters which are described below.

Request URL: `http://localhost/token`.

Request methods: `POST`.

Parameters which are using for: 

- **Authentication**

`grant_type: password`

`username: admin`

`password: admin`

- **Refresh access token**

`grant_type: refresh_token`

`refresh_token: CfDJ8KZN5Hdk1ppDj3lAR`

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
Otherwise, will get the error response, similar to this:

```json
{
    "error": "invalid_grant",
    "error_description": "The refresh token is no longer valid."
}
```

# Samples

Sample project is located in the [directory](https://github.com/Exoft/Exoft.Security.OAuthServer.Samples).
