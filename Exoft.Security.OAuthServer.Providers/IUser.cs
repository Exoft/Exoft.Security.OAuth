using System;
using System.Collections.Generic;
using System.Text;

namespace Exoft.Security.OAuthServer.Providers
{
    public interface IUser
    {
        int Id { get; set; }
        
        string Username { get; set; }

        /// <summary>
        /// Should contain SHA hash of entered value
        /// </summary>
        string Password { get; set; }

        string Role { get; set; }

        /// <summary>
        /// Should contain SHA hash of entered value
        /// </summary>
        string Secret { get; set; }
    }
}
