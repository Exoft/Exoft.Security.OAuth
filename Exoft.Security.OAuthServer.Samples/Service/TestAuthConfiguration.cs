using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Exoft.Security.OAuthServer.Providers;

namespace Exoft.Security.OAuthServer.Samples.Service
{
    public class TestAuthConfiguration:IAuthenticationConfiguration
    {
        public string Scope { get; set; }
    }
}
