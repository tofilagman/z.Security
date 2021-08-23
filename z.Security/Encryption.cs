using System;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using z.Security.Nacl;
using z.Security.Nacl.Interop;
using System.Runtime.InteropServices;

namespace z.Security
{
    public static class Encryption
    {
        public static string Decrypt(string mString, string mKey)
        {
            if (mString == "") return mString;
            TripleDESCryptoServiceProvider cryptdes3 = new TripleDESCryptoServiceProvider();
            MD5CryptoServiceProvider hash = new MD5CryptoServiceProvider();
            try
            {
                cryptdes3.Key = hash.ComputeHash(ASCIIEncoding.ASCII.GetBytes(mKey));
                cryptdes3.Mode = CipherMode.ECB;
                ICryptoTransform enc = cryptdes3.CreateDecryptor();
                byte[] buff = Convert.FromBase64String(mString);
                return ASCIIEncoding.ASCII.GetString(enc.TransformFinalBlock(buff, 0, buff.Length));
            }
            catch
            {
                throw new Exception("Bad Data");
            }
            finally
            {
                cryptdes3.Dispose();
                hash.Dispose();
            }
        }

        public static string Encrypt(string mString, string mKey)
        {
            if (mString == "") return mString;
            TripleDESCryptoServiceProvider cryptdes3 = new TripleDESCryptoServiceProvider();
            MD5CryptoServiceProvider hash = new MD5CryptoServiceProvider();
            try
            {
                cryptdes3.Key = hash.ComputeHash(ASCIIEncoding.ASCII.GetBytes(mKey));
                cryptdes3.Mode = CipherMode.ECB;
                ICryptoTransform enc = cryptdes3.CreateEncryptor();
                byte[] buff = ASCIIEncoding.ASCII.GetBytes(mString);

                return Convert.ToBase64String(enc.TransformFinalBlock(buff, 0, buff.Length));
            }
            catch (Exception ex)
            {
                throw new Exception("Bad Data", ex);
            }
            finally
            {
                cryptdes3.Dispose();
                hash.Dispose();
            }
        }

        [Obsolete]
        public static string EncryptA(string mString, int key)
        {
            throw new NotImplementedException("Obsolete: use z.Sql package instead");
        }

        public static string GetSHA1Digest(string Message)
        {
            byte[] data = System.Text.Encoding.ASCII.GetBytes(Message);
            System.Security.Cryptography.SHA1 sha1 = new
            System.Security.Cryptography.SHA1CryptoServiceProvider();
            byte[] result = sha1.ComputeHash(data);
            System.Text.StringBuilder sb = new System.Text.StringBuilder();
            for (int i = 0; i < result.Length; i++)
                sb.Append(result[i].ToString("X2"));
            return sb.ToString().ToLower();
        }

        public static string Encrypt(string plainText, string PasswordHash, string SaltKey, string VIKey)
        {
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);

            byte[] keyBytes = new Rfc2898DeriveBytes(PasswordHash, Encoding.ASCII.GetBytes(SaltKey)).GetBytes(256 / 8);
            var symmetricKey = new RijndaelManaged() { Mode = CipherMode.CBC, Padding = PaddingMode.Zeros };
            var encryptor = symmetricKey.CreateEncryptor(keyBytes, Encoding.ASCII.GetBytes(VIKey));

            byte[] cipherTextBytes;

            using (var memoryStream = new MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                {
                    cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
                    cryptoStream.FlushFinalBlock();
                    cipherTextBytes = memoryStream.ToArray();
                    cryptoStream.Close();
                }
                memoryStream.Close();
            }
            return Convert.ToBase64String(cipherTextBytes);
        }

        public static string Decrypt(string encryptedText, string PasswordHash, string SaltKey, string VIKey)
        {
            byte[] cipherTextBytes = Convert.FromBase64String(encryptedText);
            byte[] keyBytes = new Rfc2898DeriveBytes(PasswordHash, Encoding.ASCII.GetBytes(SaltKey)).GetBytes(256 / 8);
            var symmetricKey = new RijndaelManaged() { Mode = CipherMode.CBC, Padding = PaddingMode.None };

            var decryptor = symmetricKey.CreateDecryptor(keyBytes, Encoding.ASCII.GetBytes(VIKey));
            var memoryStream = new MemoryStream(cipherTextBytes);
            var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
            byte[] plainTextBytes = new byte[cipherTextBytes.Length];

            int decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
            memoryStream.Close();
            cryptoStream.Close();
            return Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount).TrimEnd("\0".ToCharArray());
        }

        [Obsolete]
        public static bool EncryptedA(string FileName, int vKey, ref string vData)
        {
            throw new NotImplementedException("Obsolete");
        }

        public static int CheckSumB(string val)
        {
            int j;
            long k = val.Length & int.MaxValue;
            foreach (char a in val)
            {
                j = Convert.ToInt32(a);
                k += j;
                k = k & int.MaxValue;
            }
            return Convert.ToInt32(k);
        }

        [Obsolete]
        public static bool DecryptLogFile(string pFileName, string vData)
        {
            throw new NotImplementedException("Obsolete");
        }

        public static string Encrypt64(string toEncrypt, string key, bool useHashing = true)
        {
            byte[] keyArray;
            byte[] toEncryptArray = UTF8Encoding.UTF8.GetBytes(toEncrypt);

            //System.Windows.Forms.KryptonMessageBox.Show(key);
            //If hashing use get hashcode regards to your key
            if (useHashing)
            {
                MD5CryptoServiceProvider hashmd5 = new MD5CryptoServiceProvider();
                keyArray = hashmd5.ComputeHash(UTF8Encoding.UTF8.GetBytes(key));
                //Always release the resources and flush data
                // of the Cryptographic service provide. Best Practice

                hashmd5.Clear();
            }
            else
                keyArray = UTF8Encoding.UTF8.GetBytes(key);

            TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();
            //set the secret key for the tripleDES algorithm
            tdes.Key = keyArray;
            //mode of operation. there are other 4 modes.
            //We choose ECB(Electronic code Book)
            tdes.Mode = CipherMode.ECB;
            //padding mode(if any extra byte added)

            tdes.Padding = PaddingMode.PKCS7;

            ICryptoTransform cTransform = tdes.CreateEncryptor();
            //transform the specified region of bytes array to resultArray
            byte[] resultArray =
              cTransform.TransformFinalBlock(toEncryptArray, 0,
              toEncryptArray.Length);
            //Release resources held by TripleDes Encryptor
            tdes.Clear();
            //Return the encrypted data into unreadable string format
            return Convert.ToBase64String(resultArray, 0, resultArray.Length);
        }

        public static string Decrypt64(string cipherString, string key, bool useHashing = true)
        {
            byte[] keyArray;
            //get the byte code of the string

            byte[] toEncryptArray = Convert.FromBase64String(cipherString);

            if (useHashing)
            {
                //if hashing was used get the hash code with regards to your key
                MD5CryptoServiceProvider hashmd5 = new MD5CryptoServiceProvider();
                keyArray = hashmd5.ComputeHash(UTF8Encoding.UTF8.GetBytes(key));
                //release any resource held by the MD5CryptoServiceProvider

                hashmd5.Clear();
            }
            else
            {
                //if hashing was not implemented get the byte code of the key
                keyArray = UTF8Encoding.UTF8.GetBytes(key);
            }

            TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();
            //set the secret key for the tripleDES algorithm
            tdes.Key = keyArray;
            //mode of operation. there are other 4 modes. 
            //We choose ECB(Electronic code Book)

            tdes.Mode = CipherMode.ECB;
            //padding mode(if any extra byte added)
            tdes.Padding = PaddingMode.PKCS7;

            ICryptoTransform cTransform = tdes.CreateDecryptor();
            byte[] resultArray = cTransform.TransformFinalBlock(
                                 toEncryptArray, 0, toEncryptArray.Length);
            //Release resources held by TripleDes Encryptor                
            tdes.Clear();
            //return the Clear decrypted TEXT
            return UTF8Encoding.UTF8.GetString(resultArray);
        }

        #region Soduim

        public static RevampedKeyPair GenerateKeyPair()
        {
            byte[] PublicKey = new Byte[GetPublicKeyBytesLength()];
            byte[] SecretKey = new Byte[GetSecretKeyBytesLength()];

            SodiumPublicKeyBoxLibrary.crypto_box_keypair(PublicKey, SecretKey);

            RevampedKeyPair MyKeyPair = new RevampedKeyPair(PublicKey, SecretKey);

            return MyKeyPair;
        }

        public static int GetPublicKeyBytesLength()
        {
            return SodiumPublicKeyBoxLibrary.crypto_box_publickeybytes();
        }

        public static int GetSecretKeyBytesLength()
        {
            return SodiumPublicKeyBoxLibrary.crypto_box_secretkeybytes();
        }

        public static int GetNonceBytesLength()
        {
            return SodiumPublicKeyBoxLibrary.crypto_box_noncebytes();
        }

        public static byte[] GenerateNonce()
        {
            return SodiumRNG.GetRandomBytes(GetNonceBytesLength());
        }

        public static int GetMACBytesLength()
        {
            return SodiumPublicKeyBoxLibrary.crypto_box_macbytes();
        }

        public static byte[] Create(byte[] Message, byte[] Nonce, byte[] SecretKey, byte[] PublicKey)
        {
            if (SecretKey == null || SecretKey.Length != GetSecretKeyBytesLength())
                throw new ArgumentException("Error: Secret key must be " + GetSecretKeyBytesLength() + " bytes in length");

            if (PublicKey == null || PublicKey.Length != GetPublicKeyBytesLength())
                throw new ArgumentException("Error: Public key must be " + GetPublicKeyBytesLength() + " bytes in length");

            if (Nonce == null || Nonce.Length != GetNonceBytesLength())
                throw new ArgumentException("Error: Nonce must be " + GetNonceBytesLength() + " bytes in length");

            byte[] CipherText = new byte[Message.Length + GetMACBytesLength()];
            int ret = SodiumPublicKeyBoxLibrary.crypto_box_easy(CipherText, Message, Message.Length, Nonce, PublicKey, SecretKey);

            GCHandle MyGeneralGCHandle = new GCHandle();
            MyGeneralGCHandle = GCHandle.Alloc(SecretKey, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), SecretKey.Length);
            MyGeneralGCHandle.Free();

            MyGeneralGCHandle = GCHandle.Alloc(PublicKey, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), PublicKey.Length);
            MyGeneralGCHandle.Free();

            if (ret != 0)
                throw new CryptographicException("Failed to create PublicKeyBox");

            return CipherText;
        }

        public static byte[] Open(byte[] CipherText, byte[] Nonce, byte[] SecretKey, byte[] PublicKey)
        {
            if (SecretKey == null || SecretKey.Length != GetSecretKeyBytesLength())
                throw new ArgumentException("Error: Secret key must be " + GetSecretKeyBytesLength() + " bytes in length");

            if (PublicKey == null || PublicKey.Length != GetPublicKeyBytesLength())
                throw new ArgumentException("Error: Public key must be " + GetPublicKeyBytesLength() + " bytes in length");

            if (Nonce == null || Nonce.Length != GetNonceBytesLength())
                throw new ArgumentException("Error: Nonce must be " + GetNonceBytesLength() + " bytes in length");

            //check to see if there are MAC_BYTES of leading nulls, if so, trim.
            //this is required due to an error in older versions.
            if (CipherText[0] == 0)
            {
                //check to see if trim is needed
                var trim = true;
                for (var i = 0; i < GetMACBytesLength() - 1; i++)
                {
                    if (CipherText[i] != 0)
                    {
                        trim = false;
                        break;
                    }
                }

                //if the leading MAC_BYTES are null, trim it off before going on.
                if (trim)
                {
                    var temp = new Byte[CipherText.Length - GetMACBytesLength()];
                    Array.Copy(CipherText, GetMACBytesLength(), temp, 0, CipherText.Length - GetMACBytesLength());

                    CipherText = temp;
                }
            }

            Byte[] Message = new Byte[CipherText.Length - GetMACBytesLength()];
            int ret = SodiumPublicKeyBoxLibrary.crypto_box_open_easy(Message, CipherText, CipherText.Length, Nonce, PublicKey, SecretKey);

            if (ret != 0)
                throw new CryptographicException("Failed to open PublicKeyBox");

            GCHandle MyGeneralGCHandle = new GCHandle();
            MyGeneralGCHandle = GCHandle.Alloc(SecretKey, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), SecretKey.Length);
            MyGeneralGCHandle.Free();

            MyGeneralGCHandle = GCHandle.Alloc(PublicKey, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), PublicKey.Length);
            MyGeneralGCHandle.Free();

            return Message;
        }

        public static string SendMessage(string data, byte[] secretKey, byte[] publicKey)
        {
            var textBts = Encoding.Default.GetBytes(data);
            var nonce = GenerateNonce();

            var message = Create(textBts, nonce, secretKey, publicKey);
            var messageToBase64 = Convert.ToBase64String(message);
            var nonceBase64 = Convert.ToBase64String(nonce);

            return $"{messageToBase64}.{nonceBase64}";
        }

        public static string ReadMessage(string data, byte[] secretKey, byte[] publicKey)
        {
            var empt = data.Split('.');

            if (empt.Length != 2)
                throw new Exception("Data is not valid");

            var message = Convert.FromBase64String(empt[0]);
            var nonce = Convert.FromBase64String(empt[1]);

            var decryptedMessage = Open(message, nonce, secretKey, publicKey);

            return Encoding.Default.GetString(decryptedMessage);
        }

        #endregion
    }
}
