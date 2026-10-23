using System;
using System.Linq;
using System.Threading.Tasks;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.DataProtection;
using Windows.Storage;
using Windows.Storage.Streams;

namespace CdfProbe.Shared
{
    internal static class ProbeState
    {
        internal const string TaskName = "CdfCompatibilityProbe.Authentication";
        internal const string EntryPoint = "CdfProbe.Background.AuthenticationTask";
        internal const string DeviceName = "PocketLatch phone";
        private static ApplicationDataContainer Settings => ApplicationData.Current.LocalSettings;
        internal static string DeviceId
        {
            get => Settings.Values["DeviceId"] as string;
            set => Settings.Values["DeviceId"] = value;
        }
        internal static string Armed
        {
            get => Settings.Values["Armed"] as string;
            set => Settings.Values["Armed"] = value;
        }

        internal static string AutomaticUnlock
        {
            get => Settings.Values["AutomaticUnlock"] as string;
            set { if (value == null) Settings.Values.Remove("AutomaticUnlock"); else Settings.Values["AutomaticUnlock"] = value; }
        }

        internal static string AutomaticAttempt
        {
            get => Settings.Values["AutomaticAttempt"] as string;
            set { if (value == null) Settings.Values.Remove("AutomaticAttempt"); else Settings.Values["AutomaticAttempt"] = value; }
        }

        internal static bool ClaimAutomaticAttempt(string permission)
        {
            var claimed = AutomaticAttempt;
            if (!UnlockAuthorization.TryClaim(permission, ref claimed)) return false;
            AutomaticAttempt = claimed;
            return true;
        }

        internal static void Disarm() { Settings.Values.Remove("Armed"); }
        internal static string PhoneHost => Settings.Values["PhoneHost"] as string;
        internal static bool PhoneMode => PhoneHost != null;
        internal static async Task ConfigurePhoneAsync(string host, byte[] secret)
        {
            if (secret.Length != 32) throw new ArgumentException("Pairing code must contain 32 bytes.");
            var encrypted = await new DataProtectionProvider("LOCAL=user").ProtectAsync(Buffer(secret));
            Settings.Values["PhoneSecret"] = CryptographicBuffer.EncodeToBase64String(encrypted);
            Settings.Values["PhoneHost"] = host;
        }
        internal static async Task<byte[]> LoadPhoneSecretAsync()
        {
            var value = Settings.Values["PhoneSecret"] as string;
            if (value == null) throw new InvalidOperationException("Pair the phone first.");
            var bytes = Bytes(await new DataProtectionProvider().UnprotectAsync(CryptographicBuffer.DecodeFromBase64String(value)));
            if (bytes.Length != 32) throw new InvalidOperationException("Invalid pairing secret.");
            return bytes;
        }
        internal static void ClearDevice()
        {
            Disarm();
            AutomaticUnlock = null;
            AutomaticAttempt = null;
            Settings.Values.Remove("DeviceId");
            Settings.Values.Remove("ProtectedKeys");
            Settings.Values.Remove("PhoneSecret");
            Settings.Values.Remove("PhoneHost");
        }

        internal static byte[] Bytes(IBuffer buffer)
        {
            byte[] bytes;
            CryptographicBuffer.CopyToByteArray(buffer, out bytes);
            return bytes;
        }
        internal static IBuffer Buffer(byte[] bytes) => CryptographicBuffer.CreateFromByteArray(bytes);

        internal static void Write(string message)
        {
            // Separate entries avoid read/append races between the UI and background process.
            var key = "Log." + DateTime.UtcNow.Ticks.ToString("D19") + "." + Guid.NewGuid().ToString("N");
            Settings.Values[key] = DateTimeOffset.Now.ToString("O") + " " +
                (message.Length > 1500 ? message.Substring(0, 1500) : message);
            foreach (var old in Settings.Values.Keys.Where(k => k.StartsWith("Log.", StringComparison.Ordinal))
                .OrderByDescending(k => k).Skip(150).ToArray()) Settings.Values.Remove(old);
        }

        internal static void Error(string operation, Exception error)
        {
            Write(operation + ": " + error.GetType().Name + " HRESULT=0x" + error.HResult.ToString("X8") +
                " " + error.Message);
            if (!string.IsNullOrEmpty(error.StackTrace)) Write(operation + " stack: " + error.StackTrace);
        }

        internal static void ClearLog()
        {
            // Snapshot only diagnostic keys; pairing, credentials and arm state are untouched.
            foreach (var key in Settings.Values.Keys.Where(k => k.StartsWith("Log.", StringComparison.Ordinal)).ToArray())
                Settings.Values.Remove(key);
        }

        internal static string Report()
        {
            return "PocketLatch diagnostics\r\n" +
                string.Join("\r\n", Settings.Values.Where(p => p.Key.StartsWith("Log.", StringComparison.Ordinal))
                    .OrderBy(p => p.Key).Select(p => p.Value as string));
        }
    }
}
