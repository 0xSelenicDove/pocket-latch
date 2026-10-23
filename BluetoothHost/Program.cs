using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CdfProbe.Shared;
using Windows.Security.Cryptography;
using Windows.Storage.Streams;

internal static class Program
{
    static async Task Main()
    {
        string root = BluetoothRelay.Root;
        Directory.CreateDirectory(root);
        FileStream singleton;
        try { singleton = new FileStream(Path.Combine(root, "host.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
        catch (IOException) { return; }
        using (singleton)
        {
            while (true)
            {
                try { await ServeAsync(root); }
                catch (Exception e) { ProbeState.Write("Bluetooth host restart: " + e.Message); await Task.Delay(2000); }
            }
        }
    }
    static async Task ServeAsync(string root)
    {
        using (var transport = await NativeBleTransport.OpenAsync("ble", CancellationToken.None))
        using (var heartbeat = new Timer(_ => {
            try { File.WriteAllText(Path.Combine(root, "heartbeat"), "ready"); } catch (IOException) { }
        }, null, 0, 1000))
        {
            while (true)
            {
                foreach (string directory in Directory.GetDirectories(root))
                {
                    if (!Guid.TryParseExact(Path.GetFileName(directory), "N", out _)) continue;
                    string ready = Path.Combine(directory, "ready");
                    if (!File.Exists(ready) || File.Exists(Path.Combine(directory, "response")) || File.Exists(Path.Combine(directory, "error"))) continue;
                    try
                    {
                        byte[] deadline = BluetoothRelay.Read(ready);
                        if (deadline.Length != 8) throw new InvalidDataException("Invalid relay deadline.");
                        long remaining = BitConverter.ToInt64(deadline, 0) - DateTime.UtcNow.Ticks;
                        if (remaining <= 0 || remaining > TimeSpan.FromSeconds(35).Ticks) throw new TimeoutException("Bluetooth request expired.");
                        using (var timeout = new CancellationTokenSource(TimeSpan.FromTicks(remaining)))
                        using (var abandoned = new Timer(_ => { if (!Directory.Exists(directory)) { try { timeout.Cancel(); } catch (ObjectDisposedException) { } } }, null, 100, 100))
                        {
                            byte[] response = await transport.ExchangeAsync(challenge => {
                                BluetoothRelay.Put(Path.Combine(directory, "challenge"), challenge);
                                return BluetoothRelay.WaitAsync(directory, "request", timeout.Token).GetAwaiter().GetResult();
                            }, (reply, challenge) => reply, timeout.Token);
                            BluetoothRelay.Put(Path.Combine(directory, "response"), response);
                        }
                    }
                    catch (Exception e)
                    {
                        if (Directory.Exists(directory))
                            try { BluetoothRelay.Put(Path.Combine(directory, "error"), System.Text.Encoding.UTF8.GetBytes(e.Message)); } catch (IOException) { }
                    }
                }
                await Task.Delay(20);
            }
        }
    }
}
namespace CdfProbe.Shared
{
    internal static class ProbeState
    {
        internal static byte[] Bytes(IBuffer buffer) { CryptographicBuffer.CopyToByteArray(buffer, out byte[] bytes); return bytes; }
        internal static IBuffer Buffer(byte[] bytes) => CryptographicBuffer.CreateFromByteArray(bytes);
        internal static void Write(string message)
        {
            try {
                var values = Windows.Storage.ApplicationData.Current.LocalSettings.Values;
                string key = "Log." + DateTime.UtcNow.Ticks.ToString("D19") + "." + Guid.NewGuid().ToString("N");
                values[key] = DateTimeOffset.Now.ToString("O") + " " + message;
                foreach (var old in values.Keys.Where(k => k.StartsWith("Log.", StringComparison.Ordinal))
                    .OrderByDescending(k => k).Skip(150).ToArray()) values.Remove(old);
            } catch (Exception) { }
        }
    }
}
