using System;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Windows.Data.Json;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;

namespace CdfProbe.Shared
{
    internal static class PhoneClient
    {
        private static byte[] Utf8(string text) => Encoding.UTF8.GetBytes(text);
        internal static void Put(JsonObject json, string name, byte[] value) =>
            json[name] = JsonValue.CreateStringValue(Convert.ToBase64String(value));
        internal static byte[] Get(JsonObject json, string name, int length)
        {
            var bytes = Convert.FromBase64String(json.GetNamedString(name));
            if (bytes.Length != length) throw new InvalidOperationException("Invalid phone response length.");
            return bytes;
        }
        private static CryptographicKey Key(byte[] secret, string direction)
        {
            var hash = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Sha256).HashData(
                ProbeState.Buffer(secret.Concat(Utf8("cdf-wifi-v1/" + direction)).ToArray()));
            return SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesGcm).CreateSymmetricKey(hash);
        }
        internal static byte[] Seal(byte[] plain, byte[] secret, byte[] challenge, string direction)
        {
            Validate(secret, challenge, direction);
            if (plain.Length > 4096 - 28) throw new ArgumentException("Frame too large.");
            var nonce = CryptographicBuffer.GenerateRandom(12);
            var result = CryptographicEngine.EncryptAndAuthenticate(Key(secret, direction),
                ProbeState.Buffer(plain), nonce, ProbeState.Buffer(challenge.Concat(Utf8(direction)).ToArray()));
            return ProbeState.Bytes(nonce).Concat(ProbeState.Bytes(result.EncryptedData))
                .Concat(ProbeState.Bytes(result.AuthenticationTag)).ToArray();
        }
        internal static byte[] Open(byte[] frame, byte[] secret, byte[] challenge, string direction)
        {
            Validate(secret, challenge, direction);
            if (frame.Length < 28 || frame.Length > 4096) throw new ArgumentException("Invalid frame size.");
            return ProbeState.Bytes(CryptographicEngine.DecryptAndAuthenticate(Key(secret, direction),
                ProbeState.Buffer(frame.Skip(12).Take(frame.Length - 28).ToArray()),
                ProbeState.Buffer(frame.Take(12).ToArray()), ProbeState.Buffer(frame.Skip(frame.Length - 16).ToArray()),
                ProbeState.Buffer(challenge.Concat(Utf8(direction)).ToArray())));
        }
        private static void Validate(byte[] secret, byte[] challenge, string direction)
        {
            if (secret.Length != 32 || challenge.Length != 32 || (direction != "request" && direction != "response"))
                throw new ArgumentException("Invalid wire parameters.");
        }
        private static JsonObject ValidateResponse(JsonObject request, byte[] plain)
        {
            var json = JsonObject.Parse(Encoding.UTF8.GetString(plain));
            if (json.GetNamedString("deviceId") != request.GetNamedString("deviceId") ||
                json.GetNamedString("operation") != request.GetNamedString("operation"))
                throw new InvalidOperationException("Phone response does not match this request.");
            if (json.GetNamedString("status") != "approved")
                throw new InvalidOperationException("Phone declined the request.");
            return json;
        }
        internal static async Task<JsonObject> ExchangeAsync(JsonObject request, CancellationToken cancellation, NativeBleTransport bluetooth = null)
        {
            byte[] secret = await ProbeState.LoadPhoneSecretAsync();
            try { return await ExchangeAsync(request, ProbeState.PhoneHost, secret, cancellation, bluetooth); }
            finally { Array.Clear(secret, 0, secret.Length); }
        }
        internal static async Task<JsonObject> ExchangeAsync(JsonObject request, string host, byte[] secret, CancellationToken cancellation, NativeBleTransport bluetooth = null)
        {
            try
            {
                if (host == NativeBleTransport.Endpoint)
                {
                    if (bluetooth == null) throw new InvalidOperationException("Bluetooth transport is not open.");
                    var plain = await bluetooth.ExchangeAsync(
                        challenge => Seal(Utf8(request.Stringify()), secret, challenge, "request"),
                        (frame, challenge) => Open(frame, secret, challenge, "response"), cancellation);
                    return ValidateResponse(request, plain);
                }
                throw new InvalidOperationException("Only direct Bluetooth is supported.");
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception) { throw new InvalidOperationException("Phone exchange failed or was denied. Check Bluetooth, pairing and phone approval."); }
        }
    }
}
