import Foundation

/// QR data is untrusted until validated; scanning never authorizes an unlock.
struct PairingInvitation: Codable {
    let version: Int
    let transport: String
    let deviceId: String
    let secret: Data
    let expires: Int64

    static func parse(_ text: String, now: Date = Date()) throws -> Self {
        guard text.utf8.count <= 1024, text.hasPrefix("cdfpair:") else { throw Invalid.invitation }
        let result = try JSONDecoder().decode(Self.self, from: Data(text.dropFirst(8).utf8))
        let remaining = Double(result.expires) - now.timeIntervalSince1970
        guard result.version == 1, ["mac-ble", "windows-ble"].contains(result.transport), result.secret.count == 32,
              result.deviceId.count == 32,
              result.deviceId.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
              remaining > 0, remaining <= 120 else { throw Invalid.invitation }
        return result
    }
    static func canAcknowledge(device: String, pairedDevice: String?, enrollment: Bool,
                               expires: Date?, now: Date = Date()) -> Bool {
        enrollment && pairedDevice == device && expires.map { now < $0 } == true
    }
    enum Invalid: Error { case invitation }
}


public enum NotificationAction {
    public static func isCurrent(id: String, pendingId: String?, hasApproval: Bool,
                                 expires: Date, now: Date = Date()) -> Bool {
        hasApproval && id == pendingId && now < expires
    }
}
