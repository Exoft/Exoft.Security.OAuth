using Exoft.Security.OAuthServer.Providers;

namespace Exoft.Security.OAuth.Samples.Service
{
    public class User : IUser
    {
        public int Id { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string Role { get; set; }
        public string Secret { get; set; }
    }
}
