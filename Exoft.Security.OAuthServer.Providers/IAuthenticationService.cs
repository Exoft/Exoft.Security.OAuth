using System;
using System.Collections.Generic;
using System.Text;

namespace Exoft.Security.OAuthServer.Providers
{
    public interface IAuthenticationService
    {
        #region ONLY FOR TESTING PURPOSES
        IUser CurrentUser { get; set; }
        #endregion

        IUser FindUser(Func<IUser, bool> predicate);
        IRefreshToken FindRefreshToken(Func<IRefreshToken, bool> predicate);

        /// <summary>
        /// Checking Is user exists by the following username
        /// </summary>
        /// <param name="username"></param>
        /// <returns></returns>
        bool ValidateRequestedUser(string username);

        /// <summary>
        /// Checking Is user credentials valid
        /// </summary>
        /// <param name="user"></param>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        bool ValidateRequestedUserCredentials(IUser user, string username, string password);
        bool ValidateRequestedClientCredentials(IUser user, string clientId, string clientSecret);
        //bool ValidateRequestedClientCredentials(string clientId, string clientSecret);

        IRefreshToken AddRefreshToken(string tokenIdentifier, int userId, string clientId, DateTime issuedUtc, DateTime expiresUtc);
        void DeleteRefreshToken(IRefreshToken refreshToken);
    }
}
