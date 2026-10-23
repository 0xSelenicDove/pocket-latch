import Foundation
import XCTest
@testable import CdfCompanionProtocol

final class BLEWireTests: XCTestCase {
    func testFragmentationAndMalformedSequences() throws {
        let id = Data(0..<8), payload = BLEWire.framed(Data(repeating: 7, count: 4096))
        for mtu in [20, 185, 512] {
            let packets = try BLEWire.packets(kind: 2, session: id, payload: payload, mtu: mtu)
            var receiver = BLEWire.Receiver(), messages = [BLEWire.Message]()
            for packet in packets { if let message = try receiver.append(packet) { messages.append(message) } }
            XCTAssertEqual(messages.count, 1)
            XCTAssertEqual(messages[0].payload, payload)
            XCTAssertEqual(messages[0].session, id)
            XCTAssertEqual(try BLEWire.unframe(messages[0].payload).count, 4096)
        }
        let packets = try BLEWire.packets(kind: 2, session: id, payload: payload, mtu: 20)
        XCTAssertEqual(packets[0].map { String(format: "%02x", $0) }.joined(), "0200010203040506070000100400001000070707")
        var receiver = BLEWire.Receiver()
        XCTAssertThrowsError(try receiver.append(packets[1]))
        receiver = BLEWire.Receiver(); _ = try receiver.append(packets[0])
        XCTAssertThrowsError(try receiver.append(packets[0]))
        var changed = packets[1]; changed[1] ^= 1
        XCTAssertThrowsError(try receiver.append(changed))
        XCTAssertThrowsError(try BLEWire.unframe(Data([0,0,0,28])))
        XCTAssertThrowsError(try BLEWire.packets(kind: 2, session: id, payload: Data(count: 4101), mtu: 20))
        receiver = BLEWire.Receiver()
        let empty = try BLEWire.packets(kind: 1, session: id, payload: Data(), mtu: 20)[0]
        XCTAssertEqual(try receiver.append(empty)?.kind, 1)
    }
}
