// https://crackstation.net/
// https://www.mscs.dal.ca/~selinger/md5collision/

using System;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

namespace consoleApp
{
    class DonneesSecurite
    {
        private static readonly byte[] key = Encoding.UTF8.GetBytes("cleetropsecrette"); 
        public static string Encrypt(string input)
        {
            var engine = new BlowfishEngine();
            var blockCipher = new PaddedBufferedBlockCipher(engine);
            var keyParam = new KeyParameter(key);
            blockCipher.Init(true, keyParam);

            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            byte[] outputBytes = new byte[blockCipher.GetOutputSize(inputBytes.Length)];
            int length = blockCipher.ProcessBytes(inputBytes, 0, inputBytes.Length, outputBytes, 0);
            blockCipher.DoFinal(outputBytes, length);

            return Convert.ToBase64String(outputBytes);
        }

        public static string Decrypt(string input)
        {
            var engine = new BlowfishEngine();
            var blockCipher = new PaddedBufferedBlockCipher(engine);
            var keyParam = new KeyParameter(key);
            blockCipher.Init(false, keyParam);

            byte[] inputBytes = Convert.FromBase64String(input);
            byte[] outputBytes = new byte[blockCipher.GetOutputSize(inputBytes.Length)];
            int length = blockCipher.ProcessBytes(inputBytes, 0, inputBytes.Length, outputBytes, 0);
            blockCipher.DoFinal(outputBytes, length);

            return Encoding.UTF8.GetString(outputBytes).TrimEnd('\0');
        }


        public static string HashThePassword(string input)
        {
            // Use input string to calculate MD5 hash
            using (System.Security.Cryptography.MD5 md5 = System.Security.Cryptography.MD5.Create())
            {
                return BCrypt.Net.BCrypt.HashPassword(input);           
                    }
        }
    }
}
