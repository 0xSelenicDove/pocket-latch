import XCTest
@testable import CdfCompanionProtocol

final class NotificationActionTests: XCTestCase {
    func testOnlyLiveMatchingRequestCanBeActedOn() {
        let now = Date()
        let expiry = now.addingTimeInterval(30)
        XCTAssertTrue(NotificationAction.isCurrent(id: "new", pendingId: "new", hasApproval: true, expires: expiry, now: now))
        XCTAssertFalse(NotificationAction.isCurrent(id: "old", pendingId: "new", hasApproval: true, expires: expiry, now: now))
        XCTAssertFalse(NotificationAction.isCurrent(id: "new", pendingId: nil, hasApproval: true, expires: expiry, now: now))
        XCTAssertFalse(NotificationAction.isCurrent(id: "new", pendingId: "new", hasApproval: false, expires: expiry, now: now))
        XCTAssertFalse(NotificationAction.isCurrent(id: "new", pendingId: "new", hasApproval: true, expires: expiry, now: expiry))
    }
}
