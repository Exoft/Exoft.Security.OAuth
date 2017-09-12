using System;
using Exoft.Security.OAuthServer.Providers;

namespace Exoft.Security.OAuth.Samples.Service
{
    public class RefreshToken : IRefreshToken
    {
        public int Id { get; set; }
        public string TokenIdentifier { get; set; }
        public string Token { get; set; }
        public int UserId { get; set; }
        public string ClientId { get; set; }
        public IUser User { get; set; }
        public DateTime IssuedUtc { get; set; }
        public DateTime ExpiresUtc { get; set; }
    }
}
