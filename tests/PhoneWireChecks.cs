using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using Windows.Devices.Bluetooth.GenericAttributeProfile;
using Windows.Security.Cryptography;
using Windows.Storage.Streams;
using CdfProbe.Shared;

// Only storage is stubbed: the actual UWP AES-GCM wire implementation is exercised.
namespace CdfProbe.Shared
{
    internal static class ProbeState
    {
        internal static void Write(string message) => Console.WriteLine(message);
        internal static string PhoneHost => throw new NotSupportedException();
        internal static Task<byte[]> LoadPhoneSecretAsync() => throw new NotSupportedException();
        internal static IBuffer Buffer(byte[] bytes) => CryptographicBuffer.CreateFromByteArray(bytes);
        internal static byte[] Bytes(IBuffer buffer) { CryptographicBuffer.CopyToByteArray(buffer, out var bytes); return bytes; }
    }
}
class PhoneWireChecks
{
    static void Reject(Action action)
    {
        try { action(); } catch { return; }
        throw new Exception("Expected rejection.");
    }
    static async Task AdvertisingStartupChecks()
    {
        int reads = 0;
        await NativeBleTransport.WaitForAdvertisingAsync(() => ++reads == 1
            ? GattServiceProviderAdvertisementStatus.Aborted : GattServiceProviderAdvertisementStatus.Started,
            TimeSpan.FromSeconds(2), CancellationToken.None);
        if (reads != 2) throw new Exception("Transient abort did not recover.");
        foreach (var status in new[] { GattServiceProviderAdvertisementStatus.Aborted,
            GattServiceProviderAdvertisementStatus.Created, GattServiceProviderAdvertisementStatus.Stopped,
            GattServiceProviderAdvertisementStatus.StartedWithoutAllAdvertisementData })
        {
            try {
                await NativeBleTransport.WaitForAdvertisingAsync(() => status, TimeSpan.FromMilliseconds(20), CancellationToken.None);
                throw new Exception("Accepted publisher that never started.");
            } catch (InvalidOperationException error) {
                if (!error.Message.Contains("final status=" + status)) throw;
            }
        }
        using (var canceled = new CancellationTokenSource())
        {
            canceled.Cancel();
            try {
                await NativeBleTransport.WaitForAdvertisingAsync(() => GattServiceProviderAdvertisementStatus.Started,
                    TimeSpan.FromSeconds(2), canceled.Token);
                throw new Exception("Ignored caller cancellation.");
            } catch (OperationCanceledException) { }
        }
        Console.WriteLine("PASS: advertising transient abort, persistent failure, and cancellation");
    }

    static async Task RelayChecks()
    {
        string directory = System.IO.Path.Combine(System.IO.Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        System.IO.Directory.CreateDirectory(directory);
        try {
            var waiting = BluetoothRelay.WaitAsync(directory, "response", CancellationToken.None);
            var bytes = new byte[] { 1, 2, 3 };
            BluetoothRelay.Put(System.IO.Path.Combine(directory, "response"), bytes);
            if (!(await waiting).SequenceEqual(bytes)) throw new Exception("Relay transfer mismatch.");
            Reject(() => BluetoothRelay.Put(System.IO.Path.Combine(directory, "large"), new byte[4101]));
            using (var cancellation = new CancellationTokenSource(50)) {
                try { await BluetoothRelay.WaitAsync(directory, "missing", cancellation.Token); throw new Exception("Ignored cancellation"); }
                catch (OperationCanceledException) { }
            }
            BluetoothRelay.Put(System.IO.Path.Combine(directory, "error"), Encoding.UTF8.GetBytes("Radio unavailable"));
            try { await BluetoothRelay.WaitAsync(directory, "missing", CancellationToken.None); throw new Exception("Ignored host failure"); }
            catch (InvalidOperationException e) { if (e.Message != "Radio unavailable") throw; }
        } finally { System.IO.Directory.Delete(directory, true); }
        Console.WriteLine("PASS: relay transfer, bounds, cancellation and host errors");
    }
    static void Main()
    {
        foreach (var language in new ushort[] { 0x0804, 0x1004 })
            if (SignInLabel.ForLanguage(language) != "您的手机") throw new Exception("Simplified Chinese label");
        foreach (var language in new ushort[] { 0x0404, 0x0c04, 0x1404 })
            if (SignInLabel.ForLanguage(language) != "您的手機") throw new Exception("Traditional Chinese label");
        if (SignInLabel.ForLanguage(0x0409) != "your phone" ||
            SignInLabel.ForLanguage(0) != "your phone") throw new Exception("English fallback label");
        if (string.IsNullOrEmpty(SignInLabel.Phone)) throw new Exception("Windows UI language lookup");
        Console.WriteLine("PASS: Windows sign-in label localization and native language lookup");
        if (!SetupChecks.PolicyText(0).StartsWith("Blocked") ||
            !SetupChecks.PolicyText(1).StartsWith("Configured") ||
            !SetupChecks.PolicyText(null).StartsWith("Not configured") ||
            !SetupChecks.ProtectionText(true).StartsWith("Compatibility warning") ||
            !SetupChecks.ProtectionText(false).StartsWith("VBS is not running"))
            throw new Exception("Setup checks must distinguish blocked, configured and unknown");
        Console.WriteLine("PASS: preliminary policy and protection check states");
        AdvertisingStartupChecks().GetAwaiter().GetResult();
        RelayChecks().GetAwaiter().GetResult();
        var secret = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        var challenge = Enumerable.Range(32, 32).Select(i => (byte)i).ToArray();
        var vector = Convert.FromHexString("000102030405060708090a0b564911ad984e70eec1cba73944f414b63ede006859fe405329bb951cec1164b47396e4fe864d16d364d02942");
        var plain = Encoding.UTF8.GetBytes("{\"operation\":\"authenticate\"}");
        if (!PhoneClient.Open(vector, secret, challenge, "request").SequenceEqual(plain)) throw new Exception("Independent vector mismatch.");
        var frame = PhoneClient.Seal(plain, secret, challenge, "request");
        if (!PhoneClient.Open(frame, secret, challenge, "request").SequenceEqual(plain)) throw new Exception("Roundtrip mismatch.");
        Reject(() => PhoneClient.Open(frame, secret, challenge, "response"));
        var other = (byte[])challenge.Clone(); other[0] ^= 1;
        Reject(() => PhoneClient.Open(frame, secret, other, "request"));
        frame[frame.Length - 1] ^= 1;
        Reject(() => PhoneClient.Open(frame, secret, challenge, "request"));
        Reject(() => PhoneClient.Open(new byte[27], secret, challenge, "request"));
        Reject(() => PhoneClient.Seal(new byte[4096], secret, challenge, "request"));
        Console.WriteLine("PASS: native Windows AES-GCM vector, roundtrip, replay, reflection, tamper and bounds checks.");
    }
}
