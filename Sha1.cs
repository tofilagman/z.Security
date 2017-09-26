using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web;

namespace z.Security
{
    /// <summary>
    /// LJ 20160311
    /// Hash
    /// </summary>
    public sealed class Sha1
    {

        public string hash(string msg, int salt)
        {
            var K = new uint[] { 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6 };
            msg = HttpUtility.UrlDecode(msg, System.Text.Encoding.UTF8);
            msg += Convert.ToChar(0x80) + "" + Convert.ToChar(salt);

            var l = msg.Length / 4 + 2;
            int N = Convert.ToInt32(Math.Ceiling(l / 16d));
            uint[][] M = new uint[Convert.ToInt32(N)][];

            for (var i = 0; i < N; i++)
            {
                M[i] = new uint[16];
                for (var j = 0; j < 16; j++)
                {
                    M[i][j] = GetCharString(msg, i * 64 + j * 4) << 24 | GetCharString(msg, i * 64 + j * 4 + 1) << 16 |
                        GetCharString(msg, i * 64 + j * 4 + 2) << 8 | GetCharString(msg, i * 64 + j * 4 + 3);
                }
            }

            M[N - 1][14] = Convert.ToUInt32(Math.Floor(((msg.Length - 1) * 8) / Math.Pow(2, 32)));
            M[N - 1][15] = Convert.ToUInt32((msg.Length - 1) * 8) & 0xffffffff;

            uint H0 = 0x67452301;
            uint H1 = 0xefcdab89;
            uint H2 = 0x98badcfe;
            uint H3 = 0x10325476;
            uint H4 = 0xc3d2e1f0;

            uint[] W = new uint[80];
            uint a, b, c, d, e;

            for (var i = 0; i < N; i++)
            { 
                for (var t = 0; t < 16; t++) W[t] = M[i][t];
                for (var t = 16; t < 80; t++) W[t] = this.ROTL(Convert.ToUInt32(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]), 1);
                a = H0; b = H1; c = H2; d = H3; e = H4; 
                for (var t = 0; t < 80; t++)
                {
                    uint s = Convert.ToUInt32(Math.Floor(t / 20d));  
                    uint T = (this.ROTL(a, 5) + this.f(s, b, c, d) + e + K[s] + W[t]) & 0xffffffff;
                    e = d;
                    d = c;
                    c = this.ROTL(b, 30);
                    b = a;
                    a = T;
                }
                H0 = (H0 + a) & 0xffffffff;
                H1 = (H1 + b) & 0xffffffff;
                H2 = (H2 + c) & 0xffffffff;
                H3 = (H3 + d) & 0xffffffff;
                H4 = (H4 + e) & 0xffffffff;
            }

            return this.toHexStr(H0).ToLower() + this.toHexStr(H1).ToLower() + this.toHexStr(H2).ToLower() + this.toHexStr(H3).ToLower() + this.toHexStr(H4).ToLower();
        }
        
        private uint f(uint s, uint x, uint y, uint z)
        {
            uint j = default(uint);
            switch (s)
            {
                case 0:
                    j = (x & y) ^ (~x & z);
                    break;
                case 1:
                    j = x ^ y ^ z;
                    break;
                case 2:
                    j = (x & y) ^ (x & z) ^ (y & z);
                    break;
                case 3:
                    j = x ^ y ^ z;
                    break;
            }
            return j;
        }
        
        private uint ROTL(uint x, int n)
        {
            return (x << n) | (x >> (32 - n));
        }

        private string toHexStr(uint n)
        {
            string s = "";
            uint v;
            for (var i = 7; i >= 0; i--)
            {
                v = (n >> (i * 4)) & 0xf;
                s += v.ToString("X");
            }
            return s;
        }

        private uint GetCharString(string msg, int j)
        {
            if (msg.Length <= j) return 0;
            else return Convert.ToUInt32(msg.ToCharArray()[j]);
        }

    }
}
