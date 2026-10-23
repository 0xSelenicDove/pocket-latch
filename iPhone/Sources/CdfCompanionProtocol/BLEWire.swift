import Foundation

// Routing IDs are not authentication. Wire's authenticated encryption protects every request.
public enum BLEWire {
    public static let service = "8D501100-27F0-4A65-AD64-0E42B41D6401"
    public static let downlink = "8D501101-27F0-4A65-AD64-0E42B41D6401"
    public static let uplink = "8D501102-27F0-4A65-AD64-0E42B41D6401"
    public static let maximum = 4100
    public enum Failure: Error { case malformed }
    public static func packets(kind: UInt8, session: Data, payload: Data, mtu: Int) throws -> [Data] {
        guard session.count == 8, (1...4).contains(kind), payload.count <= maximum, mtu >= 20 else { throw Failure.malformed }
        let size = mtu - 13
        return stride(from: 0, to: max(1, payload.count), by: size).map { offset in
            Data([kind]) + session + Data([UInt8(offset >> 8), UInt8(offset & 255),
                UInt8(payload.count >> 8), UInt8(payload.count & 255)]) + payload.dropFirst(offset).prefix(size)
        }
    }
    public struct Message { public let kind: UInt8; public let session: Data; public let payload: Data }
    public struct Receiver {
        private var kind: UInt8 = 0
        private var session = Data()
        private var total = 0
        private var buffer = Data()
        public init() {}
        public mutating func append(_ packet: Data) throws -> Message? {
            let p = [UInt8](packet)
            guard p.count >= 13, (1...4).contains(p[0]) else { throw Failure.malformed }
            let id = Data(p[1..<9]), offset = Int(p[9]) << 8 | Int(p[10]), count = Int(p[11]) << 8 | Int(p[12])
            guard count <= BLEWire.maximum, p.count - 13 <= count - offset,
                  offset <= count, p.count > 13 || count == 0 else { throw Failure.malformed }
            if buffer.isEmpty { guard offset == 0 else { throw Failure.malformed }; kind = p[0]; session = id; total = count }
            guard kind == p[0], session == id, total == count, offset == buffer.count else { throw Failure.malformed }
            buffer.append(contentsOf: p.dropFirst(13))
            guard buffer.count == total else { return nil }
            let result = Message(kind: kind, session: session, payload: buffer)
            self = Receiver()
            return result
        }
    }
    public static func framed(_ frame: Data) -> Data {
        var count = UInt32(frame.count).bigEndian
        return withUnsafeBytes(of: &count) { Data($0) } + frame
    }
    public static func unframe(_ data: Data) throws -> Data {
        guard data.count >= 4 else { throw Failure.malformed }
        let count = data.prefix(4).reduce(0) { ($0 << 8) | Int($1) }
        guard (28...4096).contains(count), data.count == count + 4 else { throw Failure.malformed }
        return Data(data.dropFirst(4))
    }
}
