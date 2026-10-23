using System;
using System.Collections.Generic;
using System.Linq;

namespace CdfProbe.Shared
{
    // Byte-for-byte compatible with the phone's BLEWire. Session IDs route; AES-GCM authenticates.
    internal static class BleWire
    {
        internal const string Service = "8D501100-27F0-4A65-AD64-0E42B41D6401";
        internal const string Downlink = "8D501101-27F0-4A65-AD64-0E42B41D6401";
        internal const string Uplink = "8D501102-27F0-4A65-AD64-0E42B41D6401";
        internal const int Maximum = 4100;
        internal sealed class Message
        {
            internal byte Kind;
            internal byte[] Session, Payload;
        }
        internal static IEnumerable<byte[]> Packets(byte kind, byte[] session, byte[] payload, int mtu)
        {
            if (kind < 1 || kind > 4 || session.Length != 8 || payload.Length > Maximum || mtu < 20)
                throw new ArgumentException("Invalid BLE message.");
            for (int offset = 0; offset < Math.Max(1, payload.Length); offset += mtu - 13)
            {
                int size = Math.Min(mtu - 13, payload.Length - offset);
                var packet = new byte[13 + size];
                packet[0] = kind; Array.Copy(session, 0, packet, 1, 8);
                packet[9] = (byte)(offset >> 8); packet[10] = (byte)offset;
                packet[11] = (byte)(payload.Length >> 8); packet[12] = (byte)payload.Length;
                Array.Copy(payload, offset, packet, 13, size);
                yield return packet;
            }
        }
        internal sealed class Receiver
        {
            private Message message;
            private int used;
            internal Message Append(byte[] packet)
            {
                if (packet.Length < 13 || packet[0] < 1 || packet[0] > 4)
                    throw new ArgumentException("Invalid BLE packet.");
                int offset = packet[9] * 256 + packet[10], total = packet[11] * 256 + packet[12];
                var session = packet.Skip(1).Take(8).ToArray();
                int size = packet.Length - 13;
                if (total > Maximum || offset > total || size > total - offset || (size == 0 && total != 0))
                    throw new ArgumentException("Invalid BLE bounds.");
                if (message == null)
                {
                    if (offset != 0) throw new ArgumentException("Missing BLE first fragment.");
                    message = new Message { Kind = packet[0], Session = session, Payload = new byte[total] };
                }
                if (message.Kind != packet[0] || !message.Session.SequenceEqual(session) ||
                    message.Payload.Length != total || offset != used)
                    throw new ArgumentException("Out-of-order BLE fragment.");
                Array.Copy(packet, 13, message.Payload, used, size); used += size;
                if (used != total) return null;
                var result = message; message = null; used = 0; return result;
            }
        }
        internal static byte[] Frame(byte[] frame)
        {
            if (frame.Length < 28 || frame.Length > 4096) throw new ArgumentException("Invalid encrypted frame.");
            return new byte[] { 0, 0, (byte)(frame.Length >> 8), (byte)frame.Length }.Concat(frame).ToArray();
        }
        internal static byte[] Unframe(byte[] payload)
        {
            if (payload.Length < 4) throw new ArgumentException("Missing frame length.");
            uint size = ((uint)payload[0] << 24) | ((uint)payload[1] << 16) | ((uint)payload[2] << 8) | payload[3];
            if (size < 28 || size > 4096 || payload.Length != size + 4) throw new ArgumentException("Invalid encrypted frame length.");
            return payload.Skip(4).ToArray();
        }
    }
}
