using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Authentication;
//using AuthenticationProperties = Microsoft.AspNetCore.Authentication.AuthenticationProperties;

namespace Exoft.Security.OAuthServer.Samlpes
{
    /// <summary>
    /// ONLY FOR TESTING PURPOSES
    /// Uses for verification all neccessary references of OpenIdConnectServer
    /// </summary>
    public sealed class TestOpenIdAuthorizationProvider : OpenIdConnectServerProvider
    {
        //private readonly IManager _database;

        public override Task ValidateAuthorizationRequest(ValidateAuthorizationRequestContext context)
        {
            // Note: the OpenID Connect server middleware supports the authorization code, implicit and hybrid flows
            // but this authorization provider only accepts response_type=code authorization/authentication requests.
            // You may consider relaxing it to support the implicit or hybrid flows. In this case, consider adding
            // checks rejecting implicit/hybrid authorization requests when the client is a confidential application.
            if (!context.Request.IsAuthorizationCodeFlow())
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.UnsupportedResponseType,
                    description: "Only the authorization code flow is supported by this authorization server.");

                return Task.FromResult(0);
            }

            // Note: to support custom response modes, the OpenID Connect server middleware doesn't
            // reject unknown modes before the ApplyAuthorizationResponse event is invoked.
            // To ensure invalid modes are rejected early enough, a check is made here.
            if (!string.IsNullOrEmpty(context.Request.ResponseMode) && !context.Request.IsFormPostResponseMode() &&
                                                                       !context.Request.IsFragmentResponseMode() &&
                                                                       !context.Request.IsQueryResponseMode())
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidRequest,
                    description: "The specified 'response_mode' is unsupported.");

                return Task.FromResult(0);
            }

            // Ensure the client_id parameter corresponds to the Postman client.
            if (!string.Equals(context.Request.ClientId, "postman", StringComparison.Ordinal))
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "The specified client identifier is invalid.");

                return Task.FromResult(0);
            }

            // Ensure the redirect_uri parameter corresponds to the Postman client.
            if (!string.Equals(context.Request.RedirectUri, "https://www.getpostman.com/oauth2/callback", StringComparison.Ordinal))
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "The specified 'redirect_uri' is invalid.");

                return Task.FromResult(0);
            }

            context.Validate();

            return Task.FromResult(0);
        }

        public override Task ValidateTokenRequest(ValidateTokenRequestContext context)
        {
            // Reject the token request if it doesn't specify grant_type=authorization_code,
            // grant_type=password or grant_type=refresh_token.
            if (!context.Request.IsAuthorizationCodeGrantType() &&
                !context.Request.IsPasswordGrantType() &&
                !context.Request.IsRefreshTokenGrantType())
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.UnsupportedGrantType,
                    description: "Only grant_type=authorization_code, grant_type=password or " +
                                 "grant_type=refresh_token are accepted by this server.");

                return Task.FromResult(0);
            }

            // Since there's only one application and since it's a public client
            // (i.e a client that cannot keep its credentials private), call Skip()
            // to inform the server the request should be accepted without
            // enforcing client authentication.
            context.Skip();

            return Task.FromResult(0);
        }

        public override Task HandleTokenRequest(HandleTokenRequestContext context)
        {
            // Only handle grant_type=password token requests and let the
            // OpenID Connect server middleware handle the other grant types.
            if (context.Request.IsPasswordGrantType())
            {
                // Using password derivation and a time-constant comparer is STRONGLY recommended.
                if (!string.Equals(context.Request.Username, "Bob", StringComparison.Ordinal) ||
                    !string.Equals(context.Request.Password, "P@ssw0rd", StringComparison.Ordinal))
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

                identity.AddClaim(OpenIdConnectConstants.Claims.Name, "Bob le Bricoleur",
                    OpenIdConnectConstants.Destinations.AccessToken,
                    OpenIdConnectConstants.Destinations.IdentityToken);

                identity.AddClaim(OpenIdConnectConstants.Claims.Role, "Admin",
                    OpenIdConnectConstants.Destinations.AccessToken,
                    OpenIdConnectConstants.Destinations.IdentityToken);

                // Create a new authentication ticket holding the user identity.
                var ticket = new AuthenticationTicket(
                    new ClaimsPrincipal(identity),
                    new AuthenticationProperties(),
                    OpenIdConnectServerDefaults.AuthenticationScheme);

                // Set the list of scopes granted to the client application.
                ticket.SetScopes(new[] {
                    /* openid: */ OpenIdConnectConstants.Scopes.OpenId,
                    /* email: */ OpenIdConnectConstants.Scopes.Email,
                    /* profile: */ OpenIdConnectConstants.Scopes.Profile,
                    /* offline_access: */ OpenIdConnectConstants.Scopes.OfflineAccess
                }.Intersect(context.Request.GetScopes()));

                context.Validate(ticket);
            }

            return Task.FromResult(0);
        }















        //// Implement OnValidateAuthorizationRequest to support interactive flows (code/implicit/hybrid).
        //public override Task ValidateAuthorizationRequest(ValidateAuthorizationRequestContext context)
        //{
        //    // Note: the OpenID Connect server middleware supports the authorization code,
        //    // implicit/hybrid and custom flows but this authorization provider only accepts
        //    // response_type=code authorization requests. You may consider relaxing it to support
        //    // the implicit or hybrid flows. In this case, consider adding checks rejecting
        //    // implicit/hybrid authorization requests when the client is a confidential application.
        //    if (!context.Request.IsAuthorizationCodeFlow())
        //    {
        //        context.Reject(
        //            error: OpenIdConnectConstants.Errors.UnsupportedResponseType,
        //            description: "Only the authorization code flow is supported by this server.");
        //        return;
        //    }

        //    // Note: redirect_uri is not required for pure OAuth2 requests
        //    // but this provider uses a stricter policy making it mandatory,
        //    // as required by the OpenID Connect core specification.
        //    // See http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest.
        //    //if (string.IsNullOrEmpty(context.RedirectUri))
        //    //{
        //    //    context.Reject(
        //    //        error: OpenIdConnectConstants.Errors.InvalidRequest,
        //    //        description: "The required redirect_uri parameter was missing.");
        //    //    return;
        //    //}

        //    // Retrieve the application details corresponding to the requested client_id.
        //    //var user = await (from entity in _database.Users
        //    //                         where entity.Id.ToString() == context.ClientId
        //    //                         select entity).SingleOrDefaultAsync(context.HttpContext.RequestAborted);
        //    //if (user == null)

        //    if (user.Id.ToString() != context.ClientId)
        //    {
        //        context.Reject(
        //            error: OpenIdConnectConstants.Errors.InvalidClient,
        //            description: "User not found in the database: " +
        //                         "ensure that your client_id is correct.");
        //        return;
        //    }

        //    context.Validate();
        //}

        //// Implement OnValidateTokenRequest to support flows using the token endpoint
        //// (code/refresh token/password/client credentials/custom grant).
        //public override async Task ValidateTokenRequest(ValidateTokenRequestContext context)
        //{
        //    // Reject the token request that don't use grant_type=password or grant_type=refresh_token.
        //    if (!context.Request.IsPasswordGrantType() && !context.Request.IsRefreshTokenGrantType())
        //    {
        //        context.Reject(
        //            error: OpenIdConnectConstants.Errors.UnsupportedGrantType,
        //            description: "Only resource owner password credentials and refresh token " +
        //                         "are accepted by this authorization server");
        //        return;
        //    }

        //    // Skip client authentication if the client identifier is missing.
        //    // Note: ASOS will automatically ensure that the calling application
        //    // cannot use an authorization code or a refresh token if it's not
        //    // the intended audience, even if client authentication was skipped.
        //    if (string.IsNullOrEmpty(context.ClientId))
        //    {
        //        context.Skip();
        //        return;
        //    }
        //    // Retrieve the User details corresponding to the requested client_id.
        //    //var user = await(from entity in _database.Users
        //    //                        where entity.Id.ToString() == context.ClientId
        //    //                        select entity).SingleOrDefaultAsync(context.HttpContext.RequestAborted);

        //    //if (user == null)
        //    if (user.Id.ToString() != context.ClientId)
        //    {
        //        context.Reject(
        //            error: OpenIdConnectConstants.Errors.InvalidClient,
        //            description: "User not found in the database: ensure that your client_id is correct.");
        //        return;
        //    }

        //    if (string.IsNullOrEmpty(context.ClientSecret))
        //    {
        //        context.Reject(
        //            error: OpenIdConnectConstants.Errors.InvalidClient,
        //            description: "Missing credentials: ensure that you specified a client_secret.");
        //        return;
        //    }

        //    if (!string.Equals(context.ClientSecret, user.Password, StringComparison.Ordinal))
        //    {
        //        context.Reject(
        //            error: OpenIdConnectConstants.Errors.InvalidClient,
        //            description: "Invalid credentials: ensure that you specified a correct client_secret.");
        //        return;
        //    }
        //    context.Validate();
        //}

        //public override async Task HandleTokenRequest(HandleTokenRequestContext context)
        //{
        //    // Resolve ASP.NET Core Identity's user manager from the DI container.

        //    //var manager = context.HttpContext.RequestServices.GetRequiredService<UserManager<ApplicationUser>>();
        //    var users = _database.Users;

        //    // Only handle grant_type=password requests and let ASOS
        //    // process grant_type=refresh_token requests automatically.
        //    if (context.Request.IsPasswordGrantType())
        //    {
        //        //var user = await users.FirstOrDefaultAsync(u=> u.UserName == context.Request.Username);
        //        //if (user == null)

        //        if (user.UserName != context.Request.Username)
        //        {
        //            context.Reject(
        //                error: OpenIdConnectConstants.Errors.InvalidGrant,
        //                description: "Invalid credentials.");
        //            return;
        //        }
        //        // Ensure the password is valid.
        //        //if (!await manager.CheckPasswordAsync(user, context.Request.Password))
        //        //{
        //        //    context.Reject(
        //        //        error: OpenIdConnectConstants.Errors.InvalidGrant,
        //        //        description: "Invalid credentials.");
        //        //    return;
        //        //}


        //        var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);

        //        // Note: the subject claim is always included in both identity and
        //        // access tokens, even if an explicit destination is not specified.
        //        identity.AddClaim(OpenIdConnectConstants.Claims.Subject, user.Id.ToString());
        //        identity.AddClaim(OpenIdConnectConstants.Claims.Role, user.Role);

        //        // When adding custom claims, you MUST specify one or more destinations.
        //        // Read "part 7" for more information about custom claims and scopes.
        //        identity.AddClaim("username", user.UserName,
        //            OpenIdConnectConstants.Destinations.AccessToken,
        //            OpenIdConnectConstants.Destinations.IdentityToken);

        //        // Create a new authentication ticket holding the user identity.
        //        var ticket = new AuthenticationTicket(
        //            new ClaimsPrincipal(identity),
        //            new AuthenticationProperties(),
        //            context.Options.AuthenticationScheme);

        //        // Set the list of scopes granted to the client application.
        //        ticket.SetScopes(
        //            /* openid: */ OpenIdConnectConstants.Scopes.OpenId,
        //            /* email: */ OpenIdConnectConstants.Scopes.Email,
        //            /* profile: */ OpenIdConnectConstants.Scopes.Profile);
        //        // Set the resource servers the access token should be issued for.
        //        ticket.SetResources("resource_server");
        //        context.Validate(ticket);
        //    }
        //}
    }
}
