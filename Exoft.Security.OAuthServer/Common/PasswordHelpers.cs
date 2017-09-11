using System;
using System.Security.Cryptography;
using System.Text;

namespace Exoft.Security.OAuthServer.Common
{
    public class PasswordHelpers
    {
        private static readonly Random _random = new Random();
        private static readonly object _syncLock = new object();

        public static string CreateMd5Hash(string value)
        {
            using (var md5 = MD5.Create())
            {
                byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes(value));

                return BitConverter.ToString(hash);
            }
        }

        public static string CreateShaHash(string value)
        {
            using (var sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(value));

                return Convert.ToBase64String(hash);
            }
        }

        public static int GetRandomNumber(int min, int max)
        {
            lock (_syncLock)
            { // synchronize
                return _random.Next(min, max);
            }
        }

        public static string GenerateRandomString(int length)
        {
            const string characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

            if (length > 0)
            {
                StringBuilder sb = new StringBuilder(length);

                for (int i = 0; i < length; i++)
                    sb.Append(characters[GetRandomNumber(0, characters.Length)]);

                return sb.ToString();
            }
            return string.Empty;
        }

        public static byte[] GetBytes(string str)
        {
            byte[] bytes = new byte[str.Length * sizeof(char)];
            System.Buffer.BlockCopy(str.ToCharArray(), 0, bytes, 0, bytes.Length);
            return bytes;
        }

        public static string GetString(byte[] bytes)
        {
            char[] chars = bytes.Length < sizeof(char) ? new char[bytes.Length] : new char[bytes.Length / sizeof(char)];
            System.Buffer.BlockCopy(bytes, 0, chars, 0, bytes.Length);
            return new string(chars);
        }
    }
}
