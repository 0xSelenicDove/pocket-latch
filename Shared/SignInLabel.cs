using System.Runtime.InteropServices;

namespace CdfProbe.Shared
{
    internal static class SignInLabel
    {
        // The app's manifest is English; use the Windows user's UI language instead.
        [DllImport("kernel32.dll", ExactSpelling = true)]
        private static extern ushort GetUserDefaultUILanguage();

        internal static string Phone => ForLanguage(GetUserDefaultUILanguage());

        internal static string ForLanguage(ushort language)
        {
            if ((language & 0x3ff) != 0x04) return "your phone";
            // Taiwan, Hong Kong and Macao use Traditional Chinese.
            return language == 0x0404 || language == 0x0c04 || language == 0x1404
                ? "您的手機" : "您的手机";
        }
    }
}
