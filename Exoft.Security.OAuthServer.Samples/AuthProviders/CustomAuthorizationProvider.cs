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
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Authentication;

namespace Exoft.Security.OAuthServer.Samples.AuthProviders
{
    public sealed class CustomAuthorizationProvider : ExoftOAuthServerProvider
    {
        public CustomAuthorizationProvider(IAuthenticationService authService, IAuthenticationConfiguration configuration) : base(authService, configuration) { }

        // TODO: Add response filter which will be remove some properties from response: id_token and etc

        private Task HandleUserAuthentication(HandleTokenRequestContext context)
        {
            string clientId = Guid.NewGuid().ToString();

            var user = AuthService.FindUser(u => u.Username == context.Request.Username);

            if (user == null)
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidGrant,
                    description: "Invalid credentials.");
                return Task.FromResult(0);
            }

            if (!AuthService.ValidateRequestedUserCredentials(user, context.Request.Username, context.Request.Password))
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidGrant,
                    description: "The specified user credentials are invalid.");

                return Task.FromResult(0);
            }

            // Create a new ClaimsIdentity containing the claims that
            // will be used to create an id_token and/or an access token.
            var identity = new ClaimsIdentity(
                OpenIdConnectServerDefaults.AuthenticationScheme,
                OpenIdConnectConstants.Claims.Name,
                OpenIdConnectConstants.Claims.Role);

            identity.AddClaim(OpenIdConnectConstants.Claims.Subject, Guid.NewGuid().ToString(),
                OpenIdConnectConstants.Destinations.AccessToken,
                OpenIdConnectConstants.Destinations.IdentityToken);

            identity.AddClaim(OpenIdConnectConstants.Claims.ClientId, Guid.NewGuid().ToString(),
                OpenIdConnectConstants.Destinations.AccessToken,
                OpenIdConnectConstants.Destinations.IdentityToken);

            identity.AddClaim(OpenIdConnectConstants.Claims.Name, user.Id.ToString(),
                OpenIdConnectConstants.Destinations.AccessToken,
                OpenIdConnectConstants.Destinations.IdentityToken);

            identity.AddClaim(OpenIdConnectConstants.Claims.Username, user.Username,
                OpenIdConnectConstants.Destinations.AccessToken,
                OpenIdConnectConstants.Destinations.IdentityToken);

            identity.AddClaim(OpenIdConnectConstants.Claims.Role, user.Role,
                OpenIdConnectConstants.Destinations.AccessToken,
                OpenIdConnectConstants.Destinations.IdentityToken);


            // Create a new authentication ticket holding the user identity.
            var properties = Helpers.GenerateAuthenticationProperties(user, clientId);
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(properties),
                OpenIdConnectServerDefaults.AuthenticationScheme);

            // Set the list of scopes granted to the client application.
            ticket.SetScopes(new[] {
                    /* openid: */ OpenIdConnectConstants.Scopes.OpenId,
                    /* email: */ OpenIdConnectConstants.Scopes.Email,
                    /* profile: */ OpenIdConnectConstants.Scopes.Profile,
                    /* offline_access: */ OpenIdConnectConstants.Scopes.OfflineAccess
                }.Intersect(context.Request.GetScopes()));

            context.Validate(ticket);

            return Task.FromResult(0);
        }

        private Task HandleRefreshTokenRequest(HandleTokenRequestContext context)
        {
            //TODO: add checking RefreshToken expiration (seems it's already implemented by OpenIdConnectServer)

            // Retrieve the token from the database and ensure it is still valid.
            var clientId = context.Ticket.Properties.Items["ClientId"];
            var token = AuthService.FindRefreshToken(t =>
                                        t.TokenIdentifier.Equals(context.Ticket.GetTokenId())
                                        && t.ClientId.Equals(clientId));
            if (token == null)
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidGrant,
                    description: "The refresh token is no longer valid.");

                return Task.FromResult(0);
            }
            AuthService.DeleteRefreshToken(token);

            var reNewTicket = new AuthenticationTicket(
                new ClaimsPrincipal(context.Ticket.Principal),
                new AuthenticationProperties(context.Ticket.Properties.Items),
                OpenIdConnectServerDefaults.AuthenticationScheme);
            context.Validate(reNewTicket);

            return Task.FromResult(0);
        }

        private Task HandleClientCredentialsAuthentication(HandleTokenRequestContext context)
        {
            //TODO
            // add note that currently authentication by grant_type=client_credentials is using search 
            // appropriate Client with comparing ClientId and UserId

            var client = AuthService.FindUser(u => context.Request.ClientId.Equals(u.Id.ToString(), StringComparison.Ordinal));

            if (client == null)
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidGrant,
                    description: "Invalid credentials.");
                return Task.FromResult(0);
            }

            if (!AuthService.ValidateRequestedClientCredentials(client, context.Request.ClientId, context.Request.ClientSecret))
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidGrant,
                    description: "The specified user credentials are invalid.");

                return Task.FromResult(0);
            }

            // Create a new ClaimsIdentity containing the claims that
            // will be used to create an id_token and/or an access token.
            var identity = new ClaimsIdentity(
                OpenIdConnectServerDefaults.AuthenticationScheme,
                OpenIdConnectConstants.Claims.Name,
                OpenIdConnectConstants.Claims.Role);

            identity.AddClaim(OpenIdConnectConstants.Claims.Subject, Guid.NewGuid().ToString(),
                OpenIdConnectConstants.Destinations.AccessToken,
                OpenIdConnectConstants.Destinations.IdentityToken);

            identity.AddClaim(OpenIdConnectConstants.Claims.ClientId, client.Id.ToString(),
                OpenIdConnectConstants.Destinations.AccessToken,
                OpenIdConnectConstants.Destinations.IdentityToken);


            // Create a new authentication ticket holding the user identity.
            var properties = new Dictionary<string, string>
            {
                { "ClientId", client.Id.ToString() },
            };
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(properties),
                OpenIdConnectServerDefaults.AuthenticationScheme);

            // Set the list of scopes granted to the client application.
            ticket.SetScopes(new[] {
                    /* openid: */ OpenIdConnectConstants.Scopes.OpenId,
                    /* email: */ OpenIdConnectConstants.Scopes.Email,
                    /* profile: */ OpenIdConnectConstants.Scopes.Profile,
                }.Intersect(context.Request.GetScopes()));

            context.Validate(ticket);

            return Task.FromResult(0);
        }

        public override Task ExtractTokenRequest(ExtractTokenRequestContext context)
        {
            // Applying auth configurations
            if (!context.Request.HasParameter(OpenIdConnectConstants.Parameters.Scope))
                context.Request.AddParameter(OpenIdConnectConstants.Parameters.Scope,
                    new OpenIdConnectParameter(Configuration.Scope));

            return base.ExtractTokenRequest(context);
        }

        //
        // Summary:
        //     Represents an event called for each request to the token endpoint to determine
        //     if the request is valid and should continue to be processed.
        //
        // Parameters:
        //   context:
        //     The context instance associated with this event.
        //
        // Returns:
        //     A System.Threading.Tasks.Task that can be used to monitor the asynchronous operation.
        //public override Task ValidateTokenRequest(ValidateTokenRequestContext context) { return Task.FromResult(0); }
        public override Task ValidateTokenRequest(ValidateTokenRequestContext context)
        {
            // Reject the token request if it doesn't specify grant_type=authorization_code,
            // grant_type=password or grant_type=refresh_token.
            if (!context.Request.IsPasswordGrantType()
                && !context.Request.IsRefreshTokenGrantType()
                && !context.Request.IsClientCredentialsGrantType())
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.UnsupportedGrantType,
                    description: "Only authorization code, refresh token, client credentials grant types " +
                                 "are accepted by this authorization server.");

                return Task.FromResult(0);
            }

            // Note: client authentication is not mandatory for non-confidential client applications like mobile apps
            // (except when using the client credentials grant type) but this authorization server uses a safer policy
            // that makes client authentication mandatory and returns an error if client_id or client_secret is missing.
            // You may consider relaxing it to support the resource owner password credentials grant type
            // with JavaScript or desktop applications, where client credentials cannot be safely stored.
            // In this case, call context.Skip() to inform the server middleware the client is not trusted.

            if (context.Request.IsClientCredentialsGrantType())
            {
                if (string.IsNullOrEmpty(context.ClientId) || string.IsNullOrEmpty(context.ClientSecret))
                {
                    context.Reject(
                        error: OpenIdConnectConstants.Errors.InvalidRequest,
                        description: "The mandatory 'client_id'/'client_secret' parameters are missing.");

                    return Task.FromResult(0);
                }

                var client = AuthService.FindUser(u => u.Id.ToString() == context.ClientId);
                if (client == null)
                {
                    context.Reject(
                        error: OpenIdConnectConstants.Errors.InvalidClient,
                        description: "The specified client identifier is invalid.");

                    return Task.FromResult(0);
                }

                // Note: to mitigate brute force attacks, you SHOULD strongly consider applying
                // a key derivation function like PBKDF2 to slow down the secret validation process.
                // You SHOULD also consider using a time-constant comparer to prevent timing attacks.
                // For that, you can use the CryptoHelper library developed by @henkmollema:
                // https://github.com/henkmollema/CryptoHelper.
                if (!AuthService.ValidateRequestedClientCredentials(client, context.ClientId, context.ClientSecret))
                {
                    context.Reject(
                        error: OpenIdConnectConstants.Errors.InvalidClient,
                        description: "The specified client credentials are invalid.");

                    return Task.FromResult(0);
                }

                context.Validate();
            }
            else
            {
                context.Skip();
            }

            return Task.FromResult(0);
        }

        //
        // Summary:
        //     Represents an event called for each validated token request to allow the user
        //     code to decide how the request should be handled.
        //
        // Parameters:
        //   context:
        //     The context instance associated with this event.
        //
        // Returns:
        //     A System.Threading.Tasks.Task that can be used to monitor the asynchronous operation.
        //public override Task HandleTokenRequest(HandleTokenRequestContext context) { return Task.FromResult(0);}
        public override Task HandleTokenRequest(HandleTokenRequestContext context)
        {
            // Only handle grant_type=password token requests and let the
            // OpenID Connect server middleware handle the other grant types.
            if (context.Request.IsPasswordGrantType())
            {
                return HandleUserAuthentication(context);
            }
            else if (context.Request.IsRefreshTokenGrantType())
            {
                return HandleRefreshTokenRequest(context);
            }
            else if (context.Request.IsClientCredentialsGrantType())
            {
                return HandleClientCredentialsAuthentication(context);
            }

            return Task.FromResult(0);
        }

        public override Task SerializeRefreshToken(SerializeRefreshTokenContext context)
        {
            int userId = Convert.ToInt32(context.Ticket.Properties.Items["UserId"]);
            string clientId = context.Ticket.Properties.Items["ClientId"];

            var token = AuthService.AddRefreshToken(
                            context.Ticket.GetTokenId(),
                            userId,
                            clientId,
                            DateTime.UtcNow,
                            DateTime.UtcNow.AddMinutes(Configuration.RefreshTokenLifetimeMinutes));

            context.Ticket.Properties.IssuedUtc = token.IssuedUtc;
            context.Ticket.Properties.ExpiresUtc = token.ExpiresUtc;

            return Task.FromResult(0);
        }
    }
}
