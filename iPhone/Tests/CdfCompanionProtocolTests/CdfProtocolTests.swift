import Foundation
import XCTest
@testable import CdfCompanionProtocol

final class CdfProtocolTests: XCTestCase {
    func testApprovalPromptsHandleAppAndLegacyRequests() {
        XCTAssertEqual(ApprovalPrompt.title(operation: "prepareUnlock", scenario: "SignIn"), "Approve Windows sign-in?")
        for scenario: String? in ["CredentialPrompt", nil, "FutureScenario"] {
            XCTAssertEqual(ApprovalPrompt.title(operation: "prepareUnlock", scenario: scenario), "Approve Windows Hello authentication?")
        }
        XCTAssertEqual(ApprovalPrompt.title(operation: "register", scenario: nil), "Pair this phone with Windows?")
    }

    private func sequence(_ start: Int) -> Data { Data((start..<start + 32).map(UInt8.init)) }
    private let serviceHmac = Data([
        0xa3,0x32,0x45,0x47,0x08,0x79,0x7a,0xd0,0x66,0x6f,0xdb,0x1d,0xfe,0xbe,0xd0,0xef,
        0x9f,0xe3,0xb4,0x3c,0xde,0xa4,0x6c,0x8a,0x25,0x0e,0x0f,0xd9,0x22,0x8d,0xba,0xa9])

    private func respond(mac: Data, deviceKey: Data? = nil, nonce: Data? = nil) throws -> CdfProtocol.Response {
        try CdfProtocol.respond(deviceKey: deviceKey ?? sequence(0), authenticationKey: sequence(32),
            serviceNonce: sequence(64), deviceNonce: sequence(96), sessionNonce: nonce ?? sequence(128),
            serviceHmac: mac)
    }

    func testIndependentWindowsVectors() throws {
        let response = try respond(mac: serviceHmac)
        XCTAssertEqual(response.deviceHmac.map { String(format: "%02x", $0) }.joined(),
            "4ac2b456828fef5a81d455c1becccc592a178d9fbd85b2fc514f0f895cd65c7b")
        XCTAssertEqual(response.sessionHmac.map { String(format: "%02x", $0) }.joined(),
            "79cb7ba18af5dec467df4f00fe15d244b38b504a6133d43fe303ba1170e034d5")
    }

    func testRejectsTamperingAndMalformedInputs() {
        var tampered = serviceHmac
        tampered[0] ^= 1
        XCTAssertThrowsError(try respond(mac: tampered))
        XCTAssertThrowsError(try respond(mac: serviceHmac, nonce: sequence(129)))
        XCTAssertThrowsError(try respond(mac: serviceHmac, deviceKey: Data(repeating: 0, count: 31)))
        XCTAssertThrowsError(try respond(mac: Data()))
    }
    func testUnlockApprovalIsBoundExpiringAndSingleUse() throws {
        let now = Date(), nonce = sequence(64)
        var approval = UnlockApproval()
        XCTAssertFalse(approval.consume(device: "pc", nonce: nonce, now: now))
        try approval.grant(device: "pc", nonce: nonce, now: now)
        XCTAssertTrue(approval.consume(device: "pc", nonce: nonce, now: now.addingTimeInterval(1)))
        XCTAssertFalse(approval.consume(device: "pc", nonce: nonce, now: now))
        try approval.grant(device: "pc", nonce: nonce, now: now)
        XCTAssertFalse(approval.consume(device: "other", nonce: nonce, now: now))
        XCTAssertFalse(approval.consume(device: "pc", nonce: nonce, now: now))
        try approval.grant(device: "pc", nonce: nonce, now: now)
        XCTAssertFalse(approval.consume(device: "pc", nonce: sequence(65), now: now))
        try approval.grant(device: "pc", nonce: nonce, now: now)
        XCTAssertFalse(approval.consume(device: "pc", nonce: nonce, now: now.addingTimeInterval(15)))
        try approval.grant(device: "pc", nonce: nonce, now: now)
        approval.clear()
        XCTAssertFalse(approval.consume(device: "pc", nonce: nonce, now: now))
        XCTAssertThrowsError(try approval.grant(device: "pc", nonce: Data(), now: now))
    }

}
