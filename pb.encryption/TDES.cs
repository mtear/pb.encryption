using System;
using System.Security.Cryptography;

namespace pb.encryption
{

    /// <summary>
    /// A class to make TDES Encryption very easy to use
    /// </summary>
    public class TDES
    {

        /// <summary>
        /// Generate a TDES key for symmetric encryption
        /// </summary>
        /// <returns>A string TDES key</returns>
        public static string GenerateKey()
        {
            TripleDESCryptoServiceProvider TDES = new TripleDESCryptoServiceProvider();
            TDES.GenerateKey();
            return System.Text.Encoding.ASCII.GetString(TDES.Key);
        }

        /// <summary>
        /// Encrypt a string into a TDES byte array.
        /// Generally this should be converted into a 64 bit string for transmission
        /// </summary>
        /// <param name="key">The TDES key to encrypt with</param>
        /// <param name="data">The data to encrypt</param>
        /// <returns>The data encrypted with the TDES key</returns>
        public static byte[] Encrypt(string key, string data)
        {
            TripleDES des = CreateDES(key);
            ICryptoTransform ct = des.CreateEncryptor();
            byte[] input = System.Text.Encoding.Unicode.GetBytes(data);
            return ct.TransformFinalBlock(input, 0, input.Length);
        }

        /// <summary>
        /// Decrypts a TDES encrypted string into its plain text
        /// </summary>
        /// <param name="key">The TDES key to decrypt with</param>
        /// <param name="cypher">The data to decrypt</param>
        /// <returns>The decrypted plaintext from the TDES string</returns>
        public static string Decrypt(string key, string cypher)
        {
            byte[] b = Convert.FromBase64String(cypher);
            TripleDES des = CreateDES(key);
            ICryptoTransform ct = des.CreateDecryptor();
            byte[] output = ct.TransformFinalBlock(b, 0, b.Length);
            return System.Text.Encoding.Unicode.GetString(output);
        }

        /// <summary>
        /// Helper function that creates TDES objects from a TDES key
        /// </summary>
        /// <param name="key">The TDES key to create the object from</param>
        /// <returns>The TDES encryption object</returns>
        static TripleDES CreateDES(string key)
        {
            MD5 md5 = new MD5CryptoServiceProvider();
            TripleDES des = new TripleDESCryptoServiceProvider();
            des.Key = md5.ComputeHash(System.Text.Encoding.Unicode.GetBytes(key));
            des.IV = new byte[des.BlockSize / 8];
            return des;
        }

    }

}
