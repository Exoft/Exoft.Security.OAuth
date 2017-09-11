using System;
using System.Collections.Generic;
using System.Text;

namespace Exoft.Security.OAuthServer.Providers
{
    public interface IAuthenticationConfiguration
    {
        string Scope { get; set; }
    }
}
