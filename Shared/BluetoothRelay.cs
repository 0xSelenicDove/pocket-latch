using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace CdfProbe.Shared
{
    // Package-local IPC carries only challenges and encrypted wire messages, never phone keys.
    internal static class BluetoothRelay
    {
        internal static string Root => Path.Combine(Windows.Storage.ApplicationData.Current.LocalFolder.Path, "BluetoothRelay");
        internal static void Put(string path, byte[] value)
        {
            if (value.Length > BleWire.Maximum) throw new InvalidDataException("Relay message too large.");
            string temporary = path + ".tmp";
            File.WriteAllBytes(temporary, value);
            File.Move(temporary, path);
        }
        internal static byte[] Read(string path)
        {
            using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                if (file.Length > BleWire.Maximum) throw new InvalidDataException("Relay message too large.");
                var bytes = new byte[(int)file.Length];
                int offset = 0, count;
                while (offset < bytes.Length && (count = file.Read(bytes, offset, bytes.Length - offset)) > 0) offset += count;
                if (offset != bytes.Length) throw new EndOfStreamException();
                return bytes;
            }
        }
        internal static async Task<byte[]> WaitAsync(string directory, string name, CancellationToken cancellation)
        {
            while (true)
            {
                cancellation.ThrowIfCancellationRequested();
                if (File.Exists(Path.Combine(directory, "error")))
                    throw new InvalidOperationException(System.Text.Encoding.UTF8.GetString(Read(Path.Combine(directory, "error"))));
                string path = Path.Combine(directory, name);
                if (File.Exists(path)) return Read(path);
                await Task.Delay(20, cancellation);
            }
        }
#if !BLE_HOST
        internal static async Task StartAsync(CancellationToken cancellation)
        {
            Directory.CreateDirectory(Root);
            await Windows.ApplicationModel.FullTrustProcessLauncher.LaunchFullTrustProcessForCurrentAppAsync("Bluetooth");
            using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation))
            {
                timeout.CancelAfter(TimeSpan.FromSeconds(12));
                while (true)
                {
                    timeout.Token.ThrowIfCancellationRequested();
                    string heartbeat = Path.Combine(Root, "heartbeat");
                    if (File.Exists(heartbeat) && DateTime.UtcNow - File.GetLastWriteTimeUtc(heartbeat) < TimeSpan.FromSeconds(3)) return;
                    await Task.Delay(100, timeout.Token);
                }
            }
        }
        internal static async Task<byte[]> ExchangeAsync(Func<byte[], byte[]> makeRequest,
            Func<byte[], byte[], byte[]> readResponse, CancellationToken cancellation)
        {
            string directory = Path.Combine(Root, Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            try
            {
                Put(Path.Combine(directory, "ready"), BitConverter.GetBytes(DateTime.UtcNow.AddSeconds(35).Ticks));
                using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation))
                {
                    timeout.CancelAfter(TimeSpan.FromSeconds(35));
                    var challenge = await WaitAsync(directory, "challenge", timeout.Token);
                    if (challenge.Length != 32) throw new InvalidDataException("Invalid Bluetooth challenge.");
                    Put(Path.Combine(directory, "request"), makeRequest(challenge));
                    var response = await WaitAsync(directory, "response", timeout.Token);
                    timeout.Token.ThrowIfCancellationRequested();
                    return readResponse(response, challenge);
                }
            }
            finally { try { Directory.Delete(directory, true); } catch (IOException) { } }
        }
#endif
    }
}
