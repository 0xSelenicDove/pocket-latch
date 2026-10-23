import XCTest
@testable import CdfCompanionProtocol

final class PairingInvitationTests: XCTestCase {
    func testScanAcknowledgementRequiresLiveMatchingInvitation() {
        let now = Date(timeIntervalSince1970: 1000)
        let expiry = now.addingTimeInterval(120)
        XCTAssertTrue(PairingInvitation.canAcknowledge(device: "a", pairedDevice: "a", enrollment: true, expires: expiry, now: now))
        XCTAssertFalse(PairingInvitation.canAcknowledge(device: "b", pairedDevice: "a", enrollment: true, expires: expiry, now: now))
        XCTAssertFalse(PairingInvitation.canAcknowledge(device: "a", pairedDevice: nil, enrollment: true, expires: expiry, now: now))
        XCTAssertFalse(PairingInvitation.canAcknowledge(device: "a", pairedDevice: "a", enrollment: false, expires: expiry, now: now))
        XCTAssertFalse(PairingInvitation.canAcknowledge(device: "a", pairedDevice: "a", enrollment: true, expires: nil, now: now))
        XCTAssertFalse(PairingInvitation.canAcknowledge(device: "a", pairedDevice: "a", enrollment: true, expires: now, now: now))
    }

    func testInvitationValidation() throws {
        let now = Date(timeIntervalSince1970: 1000)
        func text(version: Int = 1, transport: String = "mac-ble", id: String = String(repeating: "a", count: 32), size: Int = 32, expiry: Int64 = 1120) throws -> String {
            "cdfpair:" + String(decoding: try JSONEncoder().encode(PairingInvitation(version: version, transport: transport, deviceId: id, secret: Data(repeating: 1, count: size), expires: expiry)), as: UTF8.self)
        }
        XCTAssertEqual(try PairingInvitation.parse(text(), now: now).secret.count, 32)
        XCTAssertEqual(try PairingInvitation.parse(text(transport: "windows-ble"), now: now).transport, "windows-ble")
        for invalid in try [text(version: 2), text(transport: "http"), text(id: "bad"), text(size: 31), text(expiry: 1000), text(expiry: 1121)] {
            XCTAssertThrowsError(try PairingInvitation.parse(invalid, now: now))
        }
        XCTAssertThrowsError(try PairingInvitation.parse("https://example.com", now: now))
    }
    func testWindowsPayloadAndMalformedCodes() throws {
        // Same JSON shape and Base64 encoding emitted by Windows.Data.Json.
        let now = Date(timeIntervalSince1970: 1000)
        let payload = #"cdfpair:{"version":1,"transport":"mac-ble","deviceId":"0123456789abcdef0123456789abcdef","secret":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=","expires":1120}"#
        let invitation = try PairingInvitation.parse(payload, now: now)
        XCTAssertEqual(invitation.secret, Data(0..<32))
        XCTAssertEqual(invitation.deviceId, "0123456789abcdef0123456789abcdef")
        XCTAssertThrowsError(try PairingInvitation.parse(payload, now: Date(timeIntervalSince1970: 1120)))
        for invalid in ["cdfpair:{}", "cdfpair:{", "cdfpair:" + String(repeating: "x", count: 1025),
                        payload.replacingOccurrences(of: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", with: "!not-base64!")] {
            XCTAssertThrowsError(try PairingInvitation.parse(invalid, now: now))
        }
    }

}
