using Exoft.Security.OAuthServer.Providers;

namespace Exoft.Security.OAuth.Samples.Service
{
    public class TestAuthConfiguration:IAuthenticationConfiguration
    {
        public string Scope { get; set; }

        public float AccessTokenLifetimeMinutes { get; set; }
        public float RefreshTokenLifetimeMinutes { get; set; }

        public TestAuthConfiguration()
        {
            Scope = "openid offline_access";
            AccessTokenLifetimeMinutes = 120;
            RefreshTokenLifetimeMinutes = 30;
        }
    }
}
