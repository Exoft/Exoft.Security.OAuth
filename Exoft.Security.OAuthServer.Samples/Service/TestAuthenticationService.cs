using System;
using System.Collections.Generic;
using System.Linq;
using Exoft.Security.OAuthServer.Providers;

namespace Exoft.Security.OAuthServer.Samples.Service
{
    public class TestAuthenticationService: IAuthenticationService
    {
        //public IApplicationUnitOfWork UnitOfWork { get; set; }

        #region ONLY FOR TESTING PURPOSES
        public IUser CurrentUser { get; set; }

        private int _refreshTokenIdIncrementer = 1;
        private int _userIdIncrementer = 2;

        public List<IUser> Users { get; set; }

        public List<IRefreshToken> RefreshTokens { get; set; }

        #endregion region ONLY FOR TESTING PURPOSES

        public TestAuthenticationService()
        {
            Users = new List<IUser>();
            RefreshTokens = new List<IRefreshToken>();
        }

        public TestAuthenticationService(IUser user):this()
        {
            CurrentUser = user;
            Users.Add(user);
        }

        public IUser FindUser(Func<IUser, bool> predicate)
        {
            return Users.FirstOrDefault(predicate);
        }

        public IRefreshToken FindRefreshToken(Func<IRefreshToken, bool> predicate)
        {
            return RefreshTokens.FirstOrDefault(predicate);
        }

        public bool ValidateRequestedUser(string username)
        {
            return Users.Exists(u=> u.Username == username);
        }
        
        public bool ValidateRequestedUserCredentials(IUser user, string username, string password)
        {
            return string.Equals(username, user.Username, StringComparison.Ordinal) &&
                   string.Equals(password, user.Password, StringComparison.Ordinal);
        }

        public bool ValidateRequestedClientCredentials(IUser user, string clientId, string clientSecret)
        {
            return string.Equals(clientId, user.Id.ToString(), StringComparison.Ordinal) &&
                   string.Equals(clientSecret, user.Secret, StringComparison.Ordinal);
        }

        //public bool ValidateRequestedClientCredentials(string clientId, string clientSecret)
        //{
        //    return FindUser(u=> 
        //            clientId.Equals(u.Id.ToString(), StringComparison.Ordinal)
        //            && u.Secret.Equals(clientSecret, StringComparison.Ordinal)) != null;
        //}

        public IRefreshToken AddRefreshToken(string tokenIdentifier, int userId, string clientId, DateTime issuedUtc, DateTime expiresUtc)
        {
            var refreshToken = new RefreshToken
            {
                Id = _refreshTokenIdIncrementer++,
                TokenIdentifier = tokenIdentifier,
                UserId = userId,
                ClientId = clientId,
                IssuedUtc = issuedUtc,
                ExpiresUtc = expiresUtc
            };
            RefreshTokens.Add(refreshToken);

            return refreshToken;
        }
        public void DeleteRefreshToken(IRefreshToken refreshToken)
        {
            RefreshTokens.Remove(refreshToken);
        }
    }
}