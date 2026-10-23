import CryptoKit
import Foundation

/// CDF cryptography only. The caller must obtain user approval and enforce
/// session freshness before releasing a response to Windows.
public enum CdfProtocol {
    public enum Failure: Error { case invalidLength, invalidServiceAuthentication }

    public struct Response {
        public let deviceHmac: Data
        public let sessionHmac: Data
    }

    public static func respond(
        deviceKey: Data, authenticationKey: Data,
        serviceNonce: Data, deviceNonce: Data, sessionNonce: Data,
        serviceHmac: Data
    ) throws -> Response {
        guard [deviceKey, authenticationKey, serviceNonce, deviceNonce,
               sessionNonce, serviceHmac].allSatisfy({ $0.count == 32 }) else {
            throw Failure.invalidLength
        }
        let authKey = SymmetricKey(data: authenticationKey)
        guard HMAC<SHA256>.isValidAuthenticationCode(
            serviceHmac, authenticating: serviceNonce + deviceNonce + sessionNonce,
            using: authKey
        ) else { throw Failure.invalidServiceAuthentication }
        let deviceHmac = Data(HMAC<SHA256>.authenticationCode(
            for: deviceNonce, using: SymmetricKey(data: deviceKey)))
        let sessionHmac = Data(HMAC<SHA256>.authenticationCode(
            for: deviceHmac + sessionNonce, using: authKey))
        return Response(deviceHmac: deviceHmac, sessionHmac: sessionHmac)
    }
}

/// In-memory permission for one CDF challenge, bound to the approved PC and nonce.
/// Transport sessions may change between approval and the immediate CDF exchange.
public struct UnlockApproval {
    private var binding: (device: String, nonce: Data, expires: Date)?
    public init() {}
    public mutating func clear() { binding = nil }
    public mutating func grant(device: String, nonce: Data, now: Date) throws {
        binding = nil
        guard nonce.count == 32 else { throw CdfProtocol.Failure.invalidLength }
        binding = (device, nonce, now.addingTimeInterval(15))
    }
    public mutating func consume(device: String, nonce: Data, now: Date) -> Bool {
        let saved = binding
        binding = nil
        guard let saved else { return false }
        return saved.device == device && saved.nonce == nonce && now < saved.expires
    }
}
