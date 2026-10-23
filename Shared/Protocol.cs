using System;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;

namespace CdfProbe.Shared
{
    internal static class Protocol
    {
        internal static byte[] Mac(byte[] key, params byte[][] parts)
        {
            Require32(key);
            foreach (var part in parts) Require32(part);
            using (var hmac = new HMACSHA256(key))
                return hmac.ComputeHash(parts.SelectMany(p => p).ToArray());
        }

        internal static bool VerifyService(byte[] authKey, byte[] serviceNonce,
            byte[] deviceNonce, byte[] sessionNonce, byte[] serviceHmac)
        {
            Require32(serviceHmac);
            var expected = Mac(authKey, serviceNonce, deviceNonce, sessionNonce);
            int difference = 0;
            for (int i = 0; i < expected.Length; i++) difference |= expected[i] ^ serviceHmac[i];
            return difference == 0;
        }

        private static void Require32(byte[] value)
        {
            if (value == null || value.Length != 32)
                throw new ArgumentException("CDF keys, nonces and MACs must be 32 bytes.");
        }
    }

    internal static class UnlockAuthorization
    {
        // Persist the claim before contacting the phone. A rejected/expired request
        // stays consumed until Windows reports a completed sign-in.
        internal static bool TryClaim(string permission, ref string claimed)
        {
            if (permission == null || permission == claimed) return false;
            claimed = permission;
            return true;
        }

        internal static bool IsValid(string automatic, string currentAutomatic, bool phone,
            string ticket, string currentTicket, string device, DateTime now)
        {
            return AuthorizationTicket.Parse(ticket, device, now) != null &&
                (automatic != null && phone && automatic == currentAutomatic);
        }
    }

    internal sealed class AuthorizationTicket
    {
        internal string Id;
        internal string DeviceId;
        internal long ExpiresUtcTicks;

        internal static string Create(string deviceId, DateTime utcNow)
        {
            return Guid.NewGuid().ToString("N") + "|" + deviceId + "|" +
                utcNow.AddMinutes(2).Ticks.ToString(CultureInfo.InvariantCulture);
        }

        internal static AuthorizationTicket Parse(string text, string deviceId, DateTime utcNow)
        {
            var parts = (text ?? "").Split('|');
            Guid id, device;
            long expires;
            if (parts.Length != 3 || !Guid.TryParseExact(parts[0], "N", out id) ||
                !Guid.TryParseExact(parts[1], "N", out device) || parts[1] != deviceId ||
                !long.TryParse(parts[2], NumberStyles.None, CultureInfo.InvariantCulture, out expires) ||
                expires <= utcNow.Ticks || expires > utcNow.AddMinutes(2).Ticks)
                return null;
            return new AuthorizationTicket { Id = parts[0], DeviceId = parts[1], ExpiresUtcTicks = expires };
        }
    }
}
