using Exoft.Security.OAuthServer.Providers;

namespace Exoft.Security.OAuthServer.Samples.Service
{
    public class User : IUser
    {
        public int Id { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string Role { get; set; }
    }
}
