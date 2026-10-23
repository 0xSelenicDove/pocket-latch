import CryptoKit
import Foundation

public enum Wire {
    public static let limit = 4096
    public static func seal(_ data: Data, secret: Data, challenge: Data, direction: String) throws -> Data {
        guard secret.count == 32, challenge.count == 32, data.count <= limit - 28,
              ["request", "response"].contains(direction) else { throw CdfProtocol.Failure.invalidLength }
        return try AES.GCM.seal(data, using: key(secret, direction),
            authenticating: challenge + Data(direction.utf8)).combined!
    }
    public static func open(_ data: Data, secret: Data, challenge: Data, direction: String) throws -> Data {
        guard secret.count == 32, challenge.count == 32, (28...limit).contains(data.count),
              ["request", "response"].contains(direction) else { throw CdfProtocol.Failure.invalidLength }
        return try AES.GCM.open(AES.GCM.SealedBox(combined: data), using: key(secret, direction),
            authenticating: challenge + Data(direction.utf8))
    }
    private static func key(_ secret: Data, _ direction: String) -> SymmetricKey {
        SymmetricKey(data: SHA256.hash(data: secret + Data(("cdf-wifi-v1/" + direction).utf8)))
    }
}
