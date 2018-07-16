using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace test_sha1
{
    class Program
    {
        static void Main(string[] args)
        {
            



            //Encrypt_sistemas();
            //Console.Write("\n");
            Decrypt_sistemas();
        }


        static void Encrypt_sistemas()
        {
            Console.Write("\t ************ Empriptación MD5 ************");
            Console.Write("\n Ingrese un texto: ");
            string texto = Console.ReadLine();
            Console.Write("\n Texto ingresado: " + texto);


            byte[] toBytes = Encoding.UTF8.GetBytes(texto);
            byte[] ketToBytes = Encoding.UTF8.GetBytes("xxxTokenxxx");

            var passwordBytes = SHA256.Create().ComputeHash(ketToBytes);


            //byte[] hashmessage = AES_Encrypt(toBytes, passwordBytes);

           // texto = string.Join("", hashmessage.Select(b => b.ToString("x2")).ToArray());

           // texto = hmacmd5_EncryptString(texto);
            texto = testMD5.encrypt(texto);


            Console.Write("\n Texto encriptado AES256: " + texto);


            Console.Read();
        }



        static void Decrypt_sistemas()
        {


            Console.Write("\t ************ Decriptación AES256 ************");
            Console.Write("\n Ingrese un texto: ");
            string texto2 = Console.ReadLine();
            Console.Write("\n Texto ingresado: " + texto2);

            byte[] toBytes = Encoding.UTF8.GetBytes(texto2);
            byte[] ketToBytes = Encoding.UTF8.GetBytes("xxxTokenxxx");


           // var passwordBytes = SHA256.Create().ComputeHash(ketToBytes);


            //byte[] hashmessage = AES_Decrypt(toBytes, passwordBytes);


            //texto2 = Encoding.UTF8.GetString(hashmessage);

            //texto2 = Decrypt(texto2);
            texto2 = testMD5.decrypt(texto2);



            Console.Write("\n Texto decriptado AES256: " + texto2);


            Console.Read();
        }


               

        public static string EncryptString(string message)
        {

            byte[] ketToBytes = Encoding.UTF8.GetBytes("xxxTokenxxx");
            var passwordBytes = SHA256.Create().ComputeHash(ketToBytes);

            string KeyString = passwordBytes.ToString();
            string IVString = passwordBytes.ToString();

            byte[] Key = SHA256.Create().ComputeHash(ketToBytes);

            byte[] saltBytes3 = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            var key3 = new Rfc2898DeriveBytes(passwordBytes, saltBytes3, 1000);


            byte[] IV = key3.GetBytes(128 / 8); ;

            string encrypted = null;
            RijndaelManaged rj = new RijndaelManaged();
            rj.Key = Key;
            rj.IV = IV;
            rj.Mode = CipherMode.CBC;

            try
            {
                MemoryStream ms = new MemoryStream();

                using (CryptoStream cs = new CryptoStream(ms, rj.CreateEncryptor(Key, IV), CryptoStreamMode.Write))
                {
                    using (StreamWriter sw = new StreamWriter(cs))
                    {
                        sw.Write(message);
                        sw.Close();
                    }
                    cs.Close();
                }
                byte[] encoded = ms.ToArray();
                //encrypted = Convert.ToBase64String(encoded);

                encrypted = string.Join("", encoded.Select(b => b.ToString("x2")).ToArray());

                ms.Close();
            }
            catch (CryptographicException e)
            {
                Console.WriteLine("A Cryptographic error occurred: {0}", e.Message);
                return null;
            }
            catch (UnauthorizedAccessException e)
            {
                Console.WriteLine("A file error occurred: {0}", e.Message);
                return null;
            }
            catch (Exception e)
            {
                Console.WriteLine("An error occurred: {0}", e.Message);
            }
            finally
            {
                rj.Clear();
            }
            return encrypted;
        }

        
        // Decrypt a string into a string using a key and an IV 
        public static string Decrypt(string cipherData)
        {

            int NumberChars = cipherData.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(cipherData.Substring(i, 2), 16);
           

           cipherData = Convert.ToBase64String(bytes);

                    byte[] ketToBytes = Encoding.UTF8.GetBytes("xxxTokenxxx");
            var passwordBytes = SHA256.Create().ComputeHash(ketToBytes);

            string KeyString = passwordBytes.ToString();
            string IVString = passwordBytes.ToString();

            byte[] saltBytes3 = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            var key3 = new Rfc2898DeriveBytes(passwordBytes, saltBytes3, 1000);


            byte[] key = SHA256.Create().ComputeHash(ketToBytes);
            byte[] iv = key3.GetBytes(128 / 8); ;

            try
            {
                using (var rijndaelManaged =
                       new RijndaelManaged { Key = key, IV = iv, Mode = CipherMode.CBC })
                using (var memoryStream = new MemoryStream(Convert.FromBase64String(cipherData)))
                using (var cryptoStream =
                       new CryptoStream(memoryStream,
                           rijndaelManaged.CreateDecryptor(key, iv),
                           CryptoStreamMode.Read))
                {
                    return new StreamReader(cryptoStream).ReadToEnd();
                }
            }
            catch (CryptographicException e)
            {
                Console.WriteLine("A Cryptographic error occurred: {0}", e.Message);
                return null;
            }
            // You may want to catch more exceptions here...
        }


        static string hmacmd5_EncryptString(string mensaje)
        {
            byte[] ketToBytes = Encoding.UTF8.GetBytes("xxxTokenxxx");
            var passwordBytes = SHA256.Create().ComputeHash(ketToBytes);
            string KeyString = passwordBytes.ToString();

            string message = mensaje;

            System.Text.UTF8Encoding encoding = new System.Text.UTF8Encoding();
            byte[] keyByte = encoding.GetBytes(KeyString);

            HMACMD5 hmacmd5 = new HMACMD5(keyByte);
           

            byte[] messageBytes = encoding.GetBytes(message);
            byte[] hashmessage = hmacmd5.ComputeHash(messageBytes);


            string msjhex = string.Join("", hashmessage.Select(b => b.ToString("x2")).ToArray());
            //string hmac1  = ByteToString(hashmessage);

            return msjhex;
            
        }




        static string hmacmd5_Decrypt(string cipherData)
        {
            int NumberChars = cipherData.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(cipherData.Substring(i, 2), 16);


            cipherData = Convert.ToBase64String(bytes);

            byte[] ketToBytes = Encoding.UTF8.GetBytes("xxxTokenxxx");
            var passwordBytes = SHA256.Create().ComputeHash(ketToBytes);

            string KeyString = passwordBytes.ToString();
            string IVString = passwordBytes.ToString();

            byte[] saltBytes3 = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            var key3 = new Rfc2898DeriveBytes(passwordBytes, saltBytes3, 1000);

            // Step 4. Convert the input string to a byte[]
            System.Text.UTF8Encoding UTF8 = new System.Text.UTF8Encoding();
            byte[] DataToEncrypt = UTF8.GetBytes(KeyString);

            MD5CryptoServiceProvider HashProvider = new MD5CryptoServiceProvider();
            byte[] Results;

            // Step 2. Create a new TripleDESCryptoServiceProvider object
            TripleDESCryptoServiceProvider TDESAlgorithm = new TripleDESCryptoServiceProvider();

            // Step 5. Attempt to encrypt the string
            try
            {
                ICryptoTransform Encryptor = TDESAlgorithm.CreateEncryptor();
                Results = Encryptor.TransformFinalBlock(DataToEncrypt, 0, DataToEncrypt.Length);
            }
            finally
            {
                // Clear the TripleDes and Hashprovider services of any sensitive information
                TDESAlgorithm.Clear();
                HashProvider.Clear();
            }

            // Step 6. Return the encrypted string as a base64 encoded string
            return Convert.ToBase64String(Results);
           
           
        }



        public static string DecryptString(string EncryptedString)
        {

            int NumberChars = EncryptedString.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(EncryptedString.Substring(i, 2), 16);


            EncryptedString = Convert.ToBase64String(bytes);


            byte[] Results;
            System.Text.UTF8Encoding UTF8 = new System.Text.UTF8Encoding();

            // Step 1. We hash the passphrase using MD5
            // We use the MD5 hash generator as the result is a 128 bit byte array
            // which is a valid length for the TripleDES encoder we use below


            byte[] ketToBytes = Encoding.UTF8.GetBytes("xxxTokenxxx");
            var passwordBytes = SHA256.Create().ComputeHash(ketToBytes);


            MD5CryptoServiceProvider HashProvider = new MD5CryptoServiceProvider();
           // byte[] TDESKey = HashProvider.ComputeHash(UTF8.GetBytes(UserName1));

            byte[] TDESKey = passwordBytes;

            // Step 2. Create a new TripleDESCryptoServiceProvider object
            TripleDESCryptoServiceProvider TDESAlgorithm = new TripleDESCryptoServiceProvider();

            



            // Step 3. Setup the decoder
            TDESAlgorithm.Key = TDESKey;
            TDESAlgorithm.Mode = CipherMode.ECB;
            TDESAlgorithm.Padding = PaddingMode.PKCS7;

            // Step 4. Convert the input string to a byte[]
            byte[] DataToDecrypt = Convert.FromBase64String(EncryptedString);

            // Step 5. Attempt to decrypt the string
            try
            {
                ICryptoTransform Decryptor = TDESAlgorithm.CreateDecryptor();
                Results = Decryptor.TransformFinalBlock(DataToDecrypt, 0, DataToDecrypt.Length);
            }
            finally
            {
                // Clear the TripleDes and Hashprovider services of any sensitive information
                TDESAlgorithm.Clear();
                HashProvider.Clear();
            }

            // Step 6. Return the decrypted string in UTF8 format
            return UTF8.GetString(Results);
        }

    }
}
