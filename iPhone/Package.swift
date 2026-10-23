// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "CdfCompanionProtocol",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [.library(name: "CdfCompanionProtocol", targets: ["CdfCompanionProtocol"])],
    targets: [
        .target(name: "CdfCompanionProtocol"),
        .testTarget(name: "CdfCompanionProtocolTests", dependencies: ["CdfCompanionProtocol"])
    ]
)
