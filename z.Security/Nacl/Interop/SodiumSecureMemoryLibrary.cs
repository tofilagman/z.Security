using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace z.Security.Nacl.Interop
{
    public static partial class SodiumSecureMemoryLibrary
    {
#if IOS
            const string DllName = "__Internal";
#else
        const string DllName = "libsodium";
#endif

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void sodium_memzero(IntPtr Destination, long Length);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sodium_mlock(IntPtr Destination, long Length);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sodium_munlock(IntPtr Destination, long Length);
    }
}
