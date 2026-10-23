import Foundation
import XCTest
@testable import CdfCompanionProtocol

final class WireTests: XCTestCase {
    let secret = Data(0..<32)
    let challenge = Data(32..<64)
    func testIndependentAESGCMVector() throws {
        // Python cryptography AESGCM + hashlib.sha256; nonce 00..0b.
        let hex = "000102030405060708090a0b564911ad984e70eec1cba73944f414b63ede006859fe405329bb951cec1164b47396e4fe864d16d364d02942"
        let chars = Array(hex)
        let frame = Data(stride(from: 0, to: chars.count, by: 2).map { UInt8(String(chars[$0...$0+1]), radix: 16)! })
        XCTAssertEqual(try Wire.open(frame, secret: secret, challenge: challenge, direction: "request"),
                       Data("{\"operation\":\"authenticate\"}".utf8))
    }
    func testTamperReplayReflectionAndBounds() throws {
        let message = Data("test".utf8)
        let frame = try Wire.seal(message, secret: secret, challenge: challenge, direction: "request")
        XCTAssertEqual(try Wire.open(frame, secret: secret, challenge: challenge, direction: "request"), message)
        var tampered = frame; tampered[tampered.count - 1] ^= 1
        XCTAssertThrowsError(try Wire.open(tampered, secret: secret, challenge: challenge, direction: "request"))
        XCTAssertThrowsError(try Wire.open(frame, secret: secret, challenge: Data(33..<65), direction: "request"))
        XCTAssertThrowsError(try Wire.open(frame, secret: secret, challenge: challenge, direction: "response"))
        XCTAssertThrowsError(try Wire.open(frame, secret: Data(1..<33), challenge: challenge, direction: "request"))
        XCTAssertThrowsError(try Wire.open(Data(), secret: secret, challenge: challenge, direction: "request"))
        XCTAssertThrowsError(try Wire.seal(Data(repeating: 0, count: 4096), secret: secret, challenge: challenge, direction: "request"))
    }
}
