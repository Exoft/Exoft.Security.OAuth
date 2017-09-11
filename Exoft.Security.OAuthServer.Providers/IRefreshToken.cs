using System;
using System.Collections.Generic;
using System.Text;

namespace Exoft.Security.OAuthServer.Providers
{
    public interface IRefreshToken
    {
        int Id { get; set; }

        string TokenIdentifier { get; set; }

        string Token { get; set; }

        int UserId { get; set; }

        string ClientId { get; set; }
        
        IUser User { get; set; }

        DateTime IssuedUtc { get; set; }

        DateTime ExpiresUtc { get; set; }
    }
}
