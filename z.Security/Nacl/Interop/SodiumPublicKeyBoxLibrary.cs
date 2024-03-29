﻿using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace z.Security.Nacl.Interop
{
    public static partial class SodiumPublicKeyBoxLibrary
    {
#if IOS
            const string DllName = "__Internal";
#else
        const string DllName = "libsodium";
#endif

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_seedbytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_publickeybytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_secretkeybytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_beforenmbytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_noncebytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_boxzerobytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_macbytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern long crypto_box_messagebytes_max();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_keypair(Byte[] PublicKey, Byte[] SecretKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_seed_keypair(Byte[] PublicKey, Byte[] SecretKey, Byte[] Seed);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_easy(Byte[] CipherText, Byte[] Message, long MessageLength, Byte[] Nonce, Byte[] OtherUserPublicKey, Byte[] CurrentUserPrivateKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_open_easy(Byte[] Message, Byte[] CipherText, long CipherTextLength, Byte[] Nonce, Byte[] OtherUserPublicKey, Byte[] CurrentUserPrivateKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_detached(Byte[] CipherText, Byte[] MAC, Byte[] Message, long MessageLength, Byte[] Nonce, Byte[] OtherUserPublicKey, Byte[] CurrentUserPrivateKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_open_detached(Byte[] Message, Byte[] CipherText, Byte[] MAC, long CipherTextLength, Byte[] Nonce, Byte[] OtherUserPublicKey, Byte[] CurrentUserPrivateKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_beforenm(Byte[] SharedSecret, Byte[] OtherUserPublicKey, Byte[] CurrentUserPrivateKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_easy_afternm(Byte[] CipherText, Byte[] Message, long MessageLength, Byte[] Nonce, Byte[] SharedSecret);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_open_easy_afternm(Byte[] Message, Byte[] CipherText, long CipherTextLength, Byte[] Nonce, Byte[] SharedSecret);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_detached_afternm(Byte[] CipherText, Byte[] MAC, Byte[] Message, long MessageLength, Byte[] Nonce, Byte[] SharedSecret);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_box_open_detached_afternm(Byte[] Message, Byte[] CipherText, Byte[] MAC, long CipherTextLength, Byte[] Nonce, Byte[] SharedSecret);
    }
}
