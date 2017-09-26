using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using static Microsoft.VisualBasic.FileSystem;
using static Microsoft.VisualBasic.Strings;
using Microsoft.VisualBasic;

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

        public static string EncryptA(string mString, int key)
        {
            string s = "";
            foreach (char c in mString)
            {
                int j = Microsoft.VisualBasic.Strings.Asc(c);
                char d = Microsoft.VisualBasic.Strings.Chr(j ^ key);
                s += d;
            }
            return s;
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

        public static bool EncryptedA(string FileName, int vKey, ref string vData)
        {
            long fl = FileLen(FileName);
            int n = default(int), fnum;
            fl -= Len(n);
            vData = new String(' ', Convert.ToInt32(fl));
            fnum = FreeFile();
            FileOpen(fnum, FileName, OpenMode.Binary, OpenAccess.Read);
            FileGet(fnum, ref n);
            FileGet(fnum, ref vData);
            FileClose(fnum);
            return CheckSumB(vData) == n;
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

        public static bool DecryptLogFile(string pFileName, string vData)
        {
            int fnum = FreeFile();
            try
            {
                int c = Asc('A');
                vData = EncryptA(vData, c);
                SetAttr(pFileName, GetAttr(pFileName) & FileAttribute.Normal);
                FileOpen(fnum, pFileName, OpenMode.Output, OpenAccess.Write);
                Print(fnum, vData);
                FileClose(fnum);
                SetAttr(pFileName, GetAttr(pFileName) | FileAttribute.ReadOnly);
                return true;
            }
            finally
            {
                FileClose(fnum);
            }
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
    }
}
