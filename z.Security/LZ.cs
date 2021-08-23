using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

/// <summary>
/// LJ 20160602
/// </summary>
namespace z.Security
{
    [Obsolete]
    public sealed class LZ
    {

        private const string keyStrBase64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
        private const string keyStrUriSafe = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-$";
        private List<ReverseDicCtx> baseReverseDic = new List<ReverseDicCtx>();
        private char f(int val)
        {
            return Convert.ToChar(val);
        }

        private class ReverseDicCtx
        {
            public string key { get; set; }
            public Dictionary<char, int> letter = new Dictionary<char, int>();
        }

        private int getBaseValue(string alphabet, char character)
        {
            if (!baseReverseDic.Where(x => x.key == alphabet).Any())
            {
                var j = new ReverseDicCtx() { key = alphabet };
                for (var i = 0; i < alphabet.Length; i++)
                    j.letter.Add(alphabet[i], i);
                baseReverseDic.Add(j);
            }
            return baseReverseDic.Where(x => x.key == alphabet).Single().letter[character];
        }

        #region Base64

        public string compressToBase64(string input)
        {
            if (input == null) return "";
            var res = this._compress(input, 6, x => keyStrBase64[x]);
            switch (res.Length & 4)
            {
                default: return res;
                case 1: return res + "===";
                case 2: return res + "==";
                case 3: return res + "=";
            }
        }

        public string decompressFromBase64(string input)
        {
            if (input == null) return "";
            if (input == "") return null;
            return this._decompress(input.Length, 32, x => getBaseValue(keyStrBase64, input[x]));
        }

        #endregion

        #region Base16

        public string compressToUTF16(string input)
        {
            if (input == null) return "";
            return this._compress(input, 15, a => f(a + 32)) + " ";
        }

        public string decompressFromUTF16(string compressed)
        {
            if (compressed == null) return "";
            if (compressed == "") return null;
            return this._decompress(compressed.Length, 16384, index => compressed[index] - 32);
        }

        #endregion

        #region Uint8Array

        /// <summary>
        /// compress into uint8array (UCS-2 big endian format)
        /// </summary>
        /// <returns></returns>
        public uint[] compressToUint8Array(string uncompressed)
        {
            var compressed = this.compress(uncompressed);
            var buf = new uint[compressed.Length * 2];

            for (var i = 0; i < compressed.Length; i++)
            {
                var current_value = compressed[i];
                buf[i * 2] = Convert.ToUInt32(current_value >> 8);
                buf[i * 2 + 1] = Convert.ToUInt32(current_value % 256);
            }
            return buf;
        }

        public string decompressFromUint8Array(uint[] compressed)
        {
            if (compressed == null) return this.decompress(compressed);
            else
            {
                var buf = new int[compressed.Length / 2];
                for (var i = 0; i < buf.Length; i++)
                    buf[i] = Convert.ToInt32(compressed[i * 2] * 256 + compressed[i * 2 + 1]);

                var result = new List<char>();
                foreach (var j in buf)
                    result.Add(f(j));

                return this.decompress(string.Join("", result));
            }
        }

        #endregion

        #region URIComponent

        public string compressToEncodedURIComponent(string input)
        {
            if (input == null) return "";
            return this._compress(input, 6, a => keyStrUriSafe[a]);
        }

        public string decompressFromEncodedURIComponent(string input)
        {
            if (input == null) return "";
            if (input == "") return null;
            input = input.Replace(" ", "+");
            return this._decompress(input.Length, 32, index => getBaseValue(keyStrUriSafe, input[index]));
        }

        #endregion

        #region Compress Implem

        private string compress(string uncompressed)
        {
            return this._compress(uncompressed, 16, a => f(a));
        }

        private string decompress(uint[] compressed)
        {
            throw new NotImplementedException();
        }

        private string decompress(string compressed)
        {
            if (compressed == null) return "";
            if (compressed == "") return null;
            return this._decompress(compressed.Length, 32768, index => compressed[index]);
        }

        #endregion

        #region Compress Algo

        private string _compress(string uncompressed, int bitsPerChar, Func<int, char> getCharFromInt)
        {
            if (uncompressed == null) return "";
            int i, ii;
            int value;
            var context_dictionary = new Dictionary<string, int>();
            var context_dictionaryToCreate = new Dictionary<string, bool>();
            string context_c = "";
            string context_wc = "";
            string context_w = "";
            int context_enlargeIn = 2, // Compensate for the first entry which should not count
             context_dictSize = 3,
             context_numBits = 2;
            var context_data = new List<char>();
            int context_data_val = 0,
            context_data_position = 0;

            for (ii = 0; ii < uncompressed.Length; ii += 1)
            {
                context_c = uncompressed[ii].ToString();
                if (!context_dictionary.ContainsKey(context_c))
                {
                    context_dictionary[context_c] = context_dictSize++;
                    context_dictionaryToCreate[context_c] = true;
                }

                context_wc = context_w + context_c;
                if (context_dictionary.ContainsKey(context_wc))
                {
                    context_w = context_wc;
                }
                else {
                    if (context_dictionaryToCreate.ContainsKey(context_w))
                    {
                        if (context_w[0] < 256)
                        {
                            for (i = 0; i < context_numBits; i++)
                            {
                                context_data_val = (context_data_val << 1);
                                if (context_data_position == bitsPerChar - 1)
                                {
                                    context_data_position = 0;
                                    context_data.Add(getCharFromInt(context_data_val));
                                    context_data_val = 0;
                                }
                                else {
                                    context_data_position++;
                                }
                            }
                            value = context_w[0];
                            for (i = 0; i < 8; i++)
                            {
                                context_data_val = (context_data_val << 1) | (value & 1);
                                if (context_data_position == bitsPerChar - 1)
                                {
                                    context_data_position = 0;
                                    context_data.Add(getCharFromInt(context_data_val));
                                    context_data_val = 0;
                                }
                                else {
                                    context_data_position++;
                                }
                                value = value >> 1;
                            }
                        }
                        else {
                            value = 1;
                            for (i = 0; i < context_numBits; i++)
                            {
                                context_data_val = (context_data_val << 1) | value;
                                if (context_data_position == bitsPerChar - 1)
                                {
                                    context_data_position = 0;
                                    context_data.Add(getCharFromInt(context_data_val));
                                    context_data_val = 0;
                                }
                                else {
                                    context_data_position++;
                                }
                                value = 0;
                            }
                            value = context_w[0];
                            for (i = 0; i < 16; i++)
                            {
                                context_data_val = (context_data_val << 1) | (value & 1);
                                if (context_data_position == bitsPerChar - 1)
                                {
                                    context_data_position = 0;
                                    context_data.Add(getCharFromInt(context_data_val));
                                    context_data_val = 0;
                                }
                                else {
                                    context_data_position++;
                                }
                                value = value >> 1;
                            }
                        }
                        context_enlargeIn--;
                        if (context_enlargeIn == 0)
                        {
                            context_enlargeIn = Convert.ToInt32(Math.Pow(2, context_numBits));
                            context_numBits++;
                        }
                        context_dictionaryToCreate.Remove(context_w);
                    }
                    else {
                        value = context_dictionary[context_w];
                        for (i = 0; i < context_numBits; i++)
                        {
                            context_data_val = (context_data_val << 1) | (value & 1);
                            if (context_data_position == bitsPerChar - 1)
                            {
                                context_data_position = 0;
                                context_data.Add(getCharFromInt(context_data_val));
                                context_data_val = 0;
                            }
                            else {
                                context_data_position++;
                            }
                            value = value >> 1;
                        }
                    }
                    context_enlargeIn--;
                    if (context_enlargeIn == 0)
                    {
                        context_enlargeIn = Convert.ToInt32(Math.Pow(2, context_numBits));
                        context_numBits++;
                    }
                    // Add wc to the dictionary.
                    context_dictionary[context_wc] = context_dictSize++;
                    context_w = context_c;
                }
            }

            // Output the code for w.
            if (context_w != "")
            {
                if (context_dictionaryToCreate.ContainsKey(context_w))
                {
                    if (context_w[0] < 256)
                    {
                        for (i = 0; i < context_numBits; i++)
                        {
                            context_data_val = (context_data_val << 1);
                            if (context_data_position == bitsPerChar - 1)
                            {
                                context_data_position = 0;
                                context_data.Add(getCharFromInt(context_data_val));
                                context_data_val = 0;
                            }
                            else {
                                context_data_position++;
                            }
                        }
                        value = context_w[0];
                        for (i = 0; i < 8; i++)
                        {
                            context_data_val = (context_data_val << 1) | (value & 1);
                            if (context_data_position == bitsPerChar - 1)
                            {
                                context_data_position = 0;
                                context_data.Add(getCharFromInt(context_data_val));
                                context_data_val = 0;
                            }
                            else {
                                context_data_position++;
                            }
                            value = value >> 1;
                        }
                    }
                    else {
                        value = 1;
                        for (i = 0; i < context_numBits; i++)
                        {
                            context_data_val = (context_data_val << 1) | value;
                            if (context_data_position == bitsPerChar - 1)
                            {
                                context_data_position = 0;
                                context_data.Add(getCharFromInt(context_data_val));
                                context_data_val = 0;
                            }
                            else {
                                context_data_position++;
                            }
                            value = 0;
                        }
                        value = context_w[0];
                        for (i = 0; i < 16; i++)
                        {
                            context_data_val = (context_data_val << 1) | (value & 1);
                            if (context_data_position == bitsPerChar - 1)
                            {
                                context_data_position = 0;
                                context_data.Add(getCharFromInt(context_data_val));
                                context_data_val = 0;
                            }
                            else {
                                context_data_position++;
                            }
                            value = value >> 1;
                        }
                    }
                    context_enlargeIn--;
                    if (context_enlargeIn == 0)
                    {
                        context_enlargeIn = Convert.ToInt32(Math.Pow(2, context_numBits));
                        context_numBits++;
                    }
                    context_dictionaryToCreate.Remove(context_w);
                }
                else {
                    value = context_dictionary[context_w];
                    for (i = 0; i < context_numBits; i++)
                    {
                        context_data_val = (context_data_val << 1) | (value & 1);
                        if (context_data_position == bitsPerChar - 1)
                        {
                            context_data_position = 0;
                            context_data.Add(getCharFromInt(context_data_val));
                            context_data_val = 0;
                        }
                        else {
                            context_data_position++;
                        }
                        value = value >> 1;
                    }


                }
                context_enlargeIn--;
                if (context_enlargeIn == 0)
                {
                    context_enlargeIn = Convert.ToInt32(Math.Pow(2, context_numBits));
                    context_numBits++;
                }
            }

            // Mark the end of the stream
            value = 2;
            for (i = 0; i < context_numBits; i++)
            {
                context_data_val = (context_data_val << 1) | (value & 1);
                if (context_data_position == bitsPerChar - 1)
                {
                    context_data_position = 0;
                    context_data.Add(getCharFromInt(context_data_val));
                    context_data_val = 0;
                }
                else {
                    context_data_position++;
                }
                value = value >> 1;
            }

            // Flush the last char
            while (true)
            {
                context_data_val = (context_data_val << 1);
                if (context_data_position == bitsPerChar - 1)
                {
                    context_data.Add(getCharFromInt(context_data_val));
                    break;
                }
                else context_data_position++;
            }

            return string.Join("", context_data);
        }

        class dataCtx
        {
            public int val { get; set; }
            public int position { get; set; }
            public int index { get; set; }
        }

        private string _decompress(int length, int resetValue, Func<int, int> getNextValue)
        {
            var dictionary = new Dictionary<int, string>();
            int next,
             enlargeIn = 4,
             dictSize = 4,
             numBits = 3;
            string entry = "";
            var result = new List<string>();
            int i;
            string w;
            int bits, resb, maxpower, power, c = 0;
            var data = new dataCtx() { val = getNextValue(0), position = resetValue, index = 1 };

            for (i = 0; i < 3; i += 1)
            {
                dictionary[i] = Convert.ToChar(i).ToString();
            }

            bits = 0;
            maxpower = Convert.ToInt32(Math.Pow(2, 2));
            power = 1;
            while (power != maxpower)
            {
                resb = data.val & data.position;
                data.position >>= 1;
                if (data.position == 0)
                {
                    data.position = resetValue;
                    data.val = getNextValue(data.index++);
                }
                bits |= (resb > 0 ? 1 : 0) * power;
                power <<= 1;
            }

            switch (next = bits)
            {
                case 0:
                    bits = 0;
                    maxpower = Convert.ToInt32(Math.Pow(2, 8));
                    power = 1;
                    while (power != maxpower)
                    {
                        resb = data.val & data.position;
                        data.position >>= 1;
                        if (data.position == 0)
                        {
                            data.position = resetValue;
                            data.val = getNextValue(data.index++);
                        }
                        bits |= (resb > 0 ? 1 : 0) * power;
                        power <<= 1;
                    }
                    c = f(bits);
                    break;
                case 1:
                    bits = 0;
                    maxpower = Convert.ToInt32(Math.Pow(2, 16));
                    power = 1;
                    while (power != maxpower)
                    {
                        resb = data.val & data.position;
                        data.position >>= 1;
                        if (data.position == 0)
                        {
                            data.position = resetValue;
                            data.val = getNextValue(data.index++);
                        }
                        bits |= (resb > 0 ? 1 : 0) * power;
                        power <<= 1;
                    }
                    c = f(bits);
                    break;
                case 2:
                    return "";
            }
            dictionary[3] = Convert.ToChar(c).ToString();
            w = c.ToString();
            result.Add(Convert.ToChar(c).ToString());
            while (true)
            {
                if (data.index > length)
                {
                    return "";
                }

                bits = 0;
                maxpower = Convert.ToInt32(Math.Pow(2, numBits));
                power = 1;
                while (power != maxpower)
                {
                    resb = data.val & data.position;
                    data.position >>= 1;
                    if (data.position == 0)
                    {
                        data.position = resetValue;
                        data.val = getNextValue(data.index++);
                    }
                    bits |= (resb > 0 ? 1 : 0) * power;
                    power <<= 1;
                }

                switch (c = bits)
                {
                    case 0:
                        bits = 0;
                        maxpower = Convert.ToInt32(Math.Pow(2, 8));
                        power = 1;
                        while (power != maxpower)
                        {
                            resb = data.val & data.position;
                            data.position >>= 1;
                            if (data.position == 0)
                            {
                                data.position = resetValue;
                                data.val = getNextValue(data.index++);
                            }
                            bits |= (resb > 0 ? 1 : 0) * power;
                            power <<= 1;
                        }

                        dictionary[dictSize++] = f(bits).ToString();
                        c = dictSize - 1;
                        enlargeIn--;
                        break;
                    case 1:
                        bits = 0;
                        maxpower = Convert.ToInt32(Math.Pow(2, 16));
                        power = 1;
                        while (power != maxpower)
                        {
                            resb = data.val & data.position;
                            data.position >>= 1;
                            if (data.position == 0)
                            {
                                data.position = resetValue;
                                data.val = getNextValue(data.index++);
                            }
                            bits |= (resb > 0 ? 1 : 0) * power;
                            power <<= 1;
                        }
                        dictionary[dictSize++] = f(bits).ToString();
                        c = dictSize - 1;
                        enlargeIn--;
                        break;
                    case 2:
                        return string.Join("", result);
                }

                if (enlargeIn == 0)
                {
                    enlargeIn = Convert.ToInt32(Math.Pow(2, numBits));
                    numBits++;
                }

                if (dictionary.ContainsKey(c))
                {
                    entry = dictionary[c];
                }
                else {
                    if (c == dictSize)
                    {
                        entry = w + w[0];
                    }
                    else {
                        return null;
                    }
                }
                result.Add(entry);

                // Add w+entry[0] to the dictionary.
                dictionary[dictSize++] = w + entry[0];
                enlargeIn--;

                w = entry;

                if (enlargeIn == 0)
                {
                    enlargeIn = Convert.ToInt32(Math.Pow(2, numBits));
                    numBits++;
                }

            }
        }

        #endregion

    }
}
