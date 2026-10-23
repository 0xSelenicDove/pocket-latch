using System;
using System.Linq;
using CdfProbe.Shared;

internal static class ProtocolChecks
{
    private static void Check(bool condition, string name)
    {
        if (!condition) throw new Exception("FAIL: " + name);
        Console.WriteLine("PASS: " + name);
    }

    private static byte[] Sequence(int start) => Enumerable.Range(start, 32).Select(n => (byte)n).ToArray();
    private static string Hex(byte[] bytes) => BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();

    private static void Main()
    {
        BleWireChecks.Run();
        var deviceKey = Sequence(0);
        var authKey = Sequence(32);
        var serviceNonce = Sequence(64);
        var deviceNonce = Sequence(96);
        var sessionNonce = Sequence(128);
        var serviceHmac = Protocol.Mac(authKey, serviceNonce, deviceNonce, sessionNonce);
        var deviceHmac = Protocol.Mac(deviceKey, deviceNonce);
        var sessionHmac = Protocol.Mac(authKey, deviceHmac, sessionNonce);
        // Independent expected values generated with Python's hmac/hashlib (see README).
        Check(Hex(serviceHmac) == "a332454708797ad0666fdb1dfebed0ef9fe3b43cdea46c8a250e0fd9228dbaa9", "service HMAC known-answer vector");
        Check(Hex(deviceHmac) == "4ac2b456828fef5a81d455c1becccc592a178d9fbd85b2fc514f0f895cd65c7b", "device HMAC known-answer vector");
        Check(Hex(sessionHmac) == "79cb7ba18af5dec467df4f00fe15d244b38b504a6133d43fe303ba1170e034d5", "session HMAC known-answer vector");
        Check(Protocol.VerifyService(authKey, serviceNonce, deviceNonce, sessionNonce, serviceHmac), "valid service accepted");
        serviceHmac[0] ^= 1;
        Check(!Protocol.VerifyService(authKey, serviceNonce, deviceNonce, sessionNonce, serviceHmac), "tampered service rejected");
        bool rejected = false;
        try { Protocol.Mac(new byte[31], deviceNonce); } catch (ArgumentException) { rejected = true; }
        Check(rejected, "malformed key rejected");

        var now = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var deviceId = Guid.NewGuid().ToString("N");
        var armed = AuthorizationTicket.Create(deviceId, now);
        Check(AuthorizationTicket.Parse(armed, deviceId, now) != null, "fresh ticket accepted");
        Check(AuthorizationTicket.Parse(armed, deviceId, now.AddSeconds(119)) != null, "ticket valid before deadline");
        Check(AuthorizationTicket.Parse(armed, deviceId, now.AddMinutes(2)) == null, "ticket rejected at expiry");
        Check(AuthorizationTicket.Parse(armed, Guid.NewGuid().ToString("N"), now) == null, "wrong device rejected");
        Check(AuthorizationTicket.Parse(armed, deviceId, now.AddSeconds(-1)) == null, "future ticket rejected");
        Check(AuthorizationTicket.Parse(null, deviceId, now) == null, "disarmed ticket rejected");
        Check(AuthorizationTicket.Parse("bad|data|9223372036854775807", deviceId, now) == null, "malformed ticket rejected");
        var permission = Guid.NewGuid().ToString("N");
        string claimed = null;
        Check(UnlockAuthorization.TryClaim(permission, ref claimed), "first sign-in request allowed");
        Check(!UnlockAuthorization.TryClaim(permission, ref claimed), "denial or timeout cannot trigger another request");
        var persistedClaim = claimed;
        Check(!UnlockAuthorization.TryClaim(permission, ref persistedClaim), "duplicate task cannot bypass persisted claim");
        claimed = null; // Windows reached the desktop, including PIN fallback.
        Check(UnlockAuthorization.TryClaim(permission, ref claimed), "next sign-in allowed without rearming");
        Check(UnlockAuthorization.TryClaim("new-permission", ref claimed), "explicit pause and re-enable starts a new attempt");
        Check(UnlockAuthorization.IsValid(permission, permission, true, armed, null, deviceId, now), "enabled phone unlock needs no manual arm");
        var next = AuthorizationTicket.Create(deviceId, now.AddMinutes(3));
        Check(next != armed && UnlockAuthorization.IsValid(permission, permission, true, next, null, deviceId, now.AddMinutes(3)), "next unlock uses fresh ticket with same permission");
        Check(!UnlockAuthorization.IsValid(permission, null, true, armed, null, deviceId, now), "pause revokes in-flight approval");
        Check(!UnlockAuthorization.IsValid(permission, "new-permission", true, armed, null, deviceId, now), "re-enable cannot revive old approval");
        Check(!UnlockAuthorization.IsValid(permission, permission, false, armed, null, deviceId, now), "simulator cannot use persistent phone permission");
        Check(!UnlockAuthorization.IsValid(permission, permission, true, armed, null, deviceId, now.AddMinutes(2)), "automatic attempt still expires");
        Check(!UnlockAuthorization.IsValid(permission, permission, true, armed, null, Guid.NewGuid().ToString("N"), now), "automatic permission cannot change paired device");
        Check(!UnlockAuthorization.IsValid(null, null, false, armed, armed, deviceId, now), "simulator authorization is rejected");
        Check(!UnlockAuthorization.IsValid(null, null, false, armed, null, deviceId, now), "manual disarm revokes approval");
    }
}
