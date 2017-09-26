using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.ComponentModel;
using System.Security.Permissions;

namespace z.Security
{
    /// <summary>
    /// LJ Gomez 20130217
    /// </summary>
    public static class Impersonator
    {
        #region P/Invoke.
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern int LogonUser(
            string lpszUserName,
            string lpszDomain,
            string lpszPassword,
            int dwLogonType,
            int dwLogonProvider,
            ref IntPtr phToken);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern int DuplicateToken(
            IntPtr hToken,
            int impersonationLevel,
            ref IntPtr hNewToken);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool RevertToSelf();

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        private static extern bool CloseHandle(
            IntPtr handle);

        private const int LOGON32_LOGON_INTERACTIVE = 2;
        private const int LOGON32_LOGON_NEW_CREDENTIALS = 9;

        private const int LOGON32_PROVIDER_DEFAULT = 0;
        #endregion

        public static WindowsImpersonationContext impersonationContext;
        private static IntPtr token = new IntPtr(0);

        [PermissionSetAttribute(SecurityAction.Demand, Name = "FullTrust")]
        public static WindowsImpersonationContext ImpersonateUser(
            string username,
            string domain,
            string password)
        {
            // WindowsImpersonationContext impersonationContext = null;
            impersonationContext = null;

            WindowsIdentity tempWindowsIdentity = null;
            //IntPtr token = IntPtr.Zero;
            IntPtr tokenDuplicate = IntPtr.Zero;

            if (username.Length == 0)
            {
                throw new Exception("Username cannot be blank.");
            }
            if (password.Length == 0)
            {
                throw new Exception("Password cannot be blank.");
            }

            try
            {
                if (RevertToSelf())
                {
                    if (LogonUser(
                        username,
                        domain,
                        password,
                        LOGON32_LOGON_NEW_CREDENTIALS,
                        LOGON32_PROVIDER_DEFAULT,
                        ref token) != 0)
                    {
                        if (DuplicateToken(token, 2, ref tokenDuplicate) != 0)
                        {
                            tempWindowsIdentity = new WindowsIdentity(tokenDuplicate);
                            impersonationContext = tempWindowsIdentity.Impersonate();
                        }
                        else
                        {
                            throw new Win32Exception(Marshal.GetLastWin32Error());
                        }
                    }
                    else
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    }
                }
                else
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
            }
            finally
            {
                if (token != IntPtr.Zero)
                {
                    CloseHandle(token);
                }
                if (tokenDuplicate != IntPtr.Zero)
                {
                    CloseHandle(tokenDuplicate);
                }
            }

            return impersonationContext;
        }

        public static void Undo()
        {
            impersonationContext.Undo();
            // Free the tokens.
            if (token != IntPtr.Zero)
                CloseHandle(token);
        }
    }



}
