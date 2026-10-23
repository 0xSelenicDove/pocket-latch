using System;
using System.Linq;
using CdfProbe.Shared;

internal static class BleWireChecks
{
    private static void Require(bool value) { if (!value) throw new Exception("BLE wire check failed."); }
    private static void Reject(Action action)
    {
        try { action(); } catch (ArgumentException) { return; }
        throw new Exception("Malformed BLE data accepted.");
    }
    internal static void Run()
    {
        var id = Enumerable.Range(0, 8).Select(i => (byte)i).ToArray();
        var payload = BleWire.Frame(Enumerable.Repeat((byte)7, 4096).ToArray());
        foreach (int mtu in new[] { 20, 185, 512 })
        {
            var receiver = new BleWire.Receiver();
            BleWire.Message result = null;
            foreach (var packet in BleWire.Packets(2, id, payload, mtu))
            {
                Require(packet.Length <= mtu);
                result = receiver.Append(packet);
            }
            Require(result != null && result.Kind == 2 && result.Session.SequenceEqual(id) && result.Payload.SequenceEqual(payload));
            Require(BleWire.Unframe(result.Payload).Length == 4096);
        }
        // Fixed protocol vector shared with the Swift test: header + 7 bytes at ATT MTU 20.
        var fragments = BleWire.Packets(2, id, payload, 20).ToArray();
        Require(BitConverter.ToString(fragments[0]).Replace("-", "").ToLowerInvariant() == "0200010203040506070000100400001000070707");
        Reject(() => new BleWire.Receiver().Append(fragments[1]));
        var r = new BleWire.Receiver(); r.Append(fragments[0]);
        Reject(() => r.Append(fragments[0]));
        var changed = (byte[])fragments[1].Clone(); changed[1] ^= 1;
        Reject(() => r.Append(changed));
        changed = (byte[])fragments[1].Clone(); changed[0] = 4;
        Reject(() => r.Append(changed));
        Reject(() => new BleWire.Receiver().Append(new byte[12]));
        Reject(() => BleWire.Packets(2, id, new byte[4101], 20).ToArray());
        Reject(() => BleWire.Packets(2, id, payload, 19).ToArray());
        Reject(() => BleWire.Unframe(new byte[] { 255, 255, 255, 255 }));
        Reject(() => BleWire.Unframe(new byte[] { 0, 0, 0, 28 }));
        foreach (byte kind in new byte[] { 1, 3 })
            Require(new BleWire.Receiver().Append(BleWire.Packets(kind, id, new byte[0], 20).Single()).Kind == kind);
        Console.WriteLine("PASS: BLE shared vector, MTU fragmentation, bounds, ordering, session isolation and empty control packets.");
    }
}
