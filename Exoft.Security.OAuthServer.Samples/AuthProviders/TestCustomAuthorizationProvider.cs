using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using Exoft.Security.OAuthServer.Core;
using Exoft.Security.OAuthServer.Extensions;
using Exoft.Security.OAuthServer.Providers;
using Exoft.Security.OAuthServer.Samples.Service;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Authentication;
using AuthenticationProperties = Microsoft.AspNetCore.Http.Authentication.AuthenticationProperties;
using IAuthenticationService = Exoft.Security.OAuthServer.Providers.IAuthenticationService;

namespace Exoft.Security.OAuthServer.Samples.AuthProviders
{
    public sealed class TestCustomAuthorizationProvider : ExoftOAuthServerProvider
    {
        public TestCustomAuthorizationProvider(IAuthenticationService authService, IAuthenticationConfiguration configuration) : base(authService, configuration) { }

        // Implement OnValidateAuthorizationRequest to support interactive flows (code/implicit/hybrid).
        public override Task ValidateAuthorizationRequest(ValidateAuthorizationRequestContext context)
        {
            // Note: the OpenID Connect server middleware supports the authorization code,
            // implicit/hybrid and custom flows but this authorization provider only accepts
            // response_type=code authorization requests. You may consider relaxing it to support
            // the implicit or hybrid flows. In this case, consider adding checks rejecting
            // implicit/hybrid authorization requests when the client is a confidential application.
            if (!context.Request.IsAuthorizationCodeFlow())
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.UnsupportedResponseType,
                    description: "Only the authorization code flow is supported by this server.");
                return Task.FromResult(0);
            }

            // Note: redirect_uri is not required for pure OAuth2 requests
            // but this provider uses a stricter policy making it mandatory,
            // as required by the OpenID Connect core specification.
            // See http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest.
            //if (string.IsNullOrEmpty(context.RedirectUri))
            //{
            //    context.Reject(
            //        error: OpenIdConnectConstants.Errors.InvalidRequest,
            //        description: "The required redirect_uri parameter was missing.");
            //    return;
            //}

            // Retrieve the application details corresponding to the requested client_id.
            //var user = await (from entity in _database.Users
            //                         where entity.Id.ToString() == context.ClientId
            //                         select entity).SingleOrDefaultAsync(context.HttpContext.RequestAborted);
            //if (user == null)

            if (AuthService.CurrentUser.Id.ToString() != context.ClientId)
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "User not found in the database: " +
                                 "ensure that your client_id is correct.");
                return Task.FromResult(0);
            }

            context.Validate();

            return Task.FromResult(0);
        }

        // Implement OnValidateTokenRequest to support flows using the token endpoint
        // (code/refresh token/password/client credentials/custom grant).
        public override async Task ValidateTokenRequest(ValidateTokenRequestContext context)
        {
            // Reject the token request that don't use grant_type=password or grant_type=refresh_token.
            if (!context.Request.IsPasswordGrantType() && !context.Request.IsRefreshTokenGrantType())
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.UnsupportedGrantType,
                    description: "Only resource owner password credentials and refresh token " +
                                 "are accepted by this authorization server");
                return;
            }

            // Skip client authentication if the client identifier is missing.
            // Note: ASOS will automatically ensure that the calling application
            // cannot use an authorization code or a refresh token if it's not
            // the intended audience, even if client authentication was skipped.
            if (string.IsNullOrEmpty(context.ClientId))
            {
                context.Skip();
                return;
            }
            // Retrieve the User details corresponding to the requested client_id.
            //var user = await(from entity in _database.Users
            //                        where entity.Id.ToString() == context.ClientId
            //                        select entity).SingleOrDefaultAsync(context.HttpContext.RequestAborted);

            //if (user == null)
            if (AuthService.CurrentUser.Id.ToString() != context.ClientId)
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "User not found in the database: ensure that your client_id is correct.");
                return;
            }

            if (string.IsNullOrEmpty(context.ClientSecret))
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Missing credentials: ensure that you specified a client_secret.");
                return;
            }

            if (!string.Equals(context.ClientSecret, AuthService.CurrentUser.Password, StringComparison.Ordinal))
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Invalid credentials: ensure that you specified a correct client_secret.");
                return;
            }
            context.Validate();
        }

        public override async Task HandleTokenRequest(HandleTokenRequestContext context)
        {
            // Resolve ASP.NET Core Identity's user service from the DI container.

            //var manager = context.HttpContext.RequestServices.GetRequiredService<UserManager<ApplicationUser>>();

            // Only handle grant_type=password requests and let ASOS
            // process grant_type=refresh_token requests automatically.
            if (context.Request.IsPasswordGrantType())
            {
                //var user = await users.FirstOrDefaultAsync(u=> u.UserName == context.Request.Username);
                //if (user == null)

                if (AuthService.CurrentUser.Username != context.Request.Username)
                {
                    context.Reject(
                        error: OpenIdConnectConstants.Errors.InvalidGrant,
                        description: "Invalid credentials.");
                    return;
                }
                // Ensure the password is valid.
                //if (!await manager.CheckPasswordAsync(user, context.Request.Password))
                //{
                //    context.Reject(
                //        error: OpenIdConnectConstants.Errors.InvalidGrant,
                //        description: "Invalid credentials.");
                //    return;
                //}


                //var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);

                //// Note: the subject claim is always included in both identity and
                //// access tokens, even if an explicit destination is not specified.
                //identity.AddClaim(OpenIdConnectConstants.Claims.Subject, AuthService.CurrentUser.Id.ToString());
                //identity.AddClaim(OpenIdConnectConstants.Claims.Role, AuthService.CurrentUser.Role);

                //// When adding custom claims, you MUST specify one or more destinations.
                //// Read "part 7" for more information about custom claims and scopes.
                //identity.AddClaim("username", AuthService.CurrentUser.Username,
                //    OpenIdConnectConstants.Destinations.AccessToken,
                //    OpenIdConnectConstants.Destinations.IdentityToken);

                //context.Validate(new ClaimsPrincipal(identity),
                //    new AuthenticationProperties(),
                //    OpenIdConnectServerDefaults.AuthenticationScheme,
                //    new[]
                //    {
                //        /* openid: */ OpenIdConnectConstants.Scopes.OpenId,
                //        /* email: */ OpenIdConnectConstants.Scopes.Email,
                //        /* profile: */ OpenIdConnectConstants.Scopes.Profile}.ToList(),
                //    new[]{ "resource_server" }.ToList());
            }
        }
    }
}