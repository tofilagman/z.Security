using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace z.Security
{
    public static class Extensions
    {
        /// <summary>
        /// tripledes encryption
        /// </summary>
        /// <param name="val"></param>
        /// <param name="key"></param>
        /// <param name="useHash"></param>
        /// <returns></returns>
        public static string Encrypt64(this string val, string key, bool useHash = true) => Encryption.Encrypt64(val, key, useHash);

        /// <summary>
        /// tripledes encryption
        /// </summary>
        /// <param name="val"></param>
        /// <param name="key"></param>
        /// <param name="useHash"></param>
        /// <returns></returns>
        public static string Decrypt64(this string val, string key, bool useHash = true) => Encryption.Decrypt64(val, key, useHash);

    }
}
