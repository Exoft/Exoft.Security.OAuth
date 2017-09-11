using System;
using System.Collections.Generic;
using System.Text;

namespace Exoft.Security.OAuthServer.Providers
{
    public interface IUser
    {
        int Id { get; set; }
        
        string Username { get; set; }

        string Password { get; set; }

        string Role { get; set; }
    }
}
