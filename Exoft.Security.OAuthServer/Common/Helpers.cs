using System;
using System.Collections.Generic;
using System.Text;
using Exoft.Security.OAuthServer.Providers;

namespace Exoft.Security.OAuthServer.Common
{
    public class Helpers
    {
        public static Dictionary<string, string> GenerateAuthenticationProperties(IUser user, string clientId)
        {
            var result = new Dictionary<string, string>
            {
                { "UserId", user.Id.ToString() },
                { "Username", user.Username },
                { "ClientId", clientId },
            };

            return result;
        }

        public static string GenRawRefreshToken(string userName)
        {
            return PasswordHelpers.CreateShaHash(userName + Guid.NewGuid());
        }
    }
}
