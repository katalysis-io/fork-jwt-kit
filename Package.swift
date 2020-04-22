// swift-tools-version:5.2
import PackageDescription

let package = Package(
    name: "jwt-kit",
    platforms: [
        .macOS(.v10_15)
    ],
    products: [
        .library(name: "JWTKit", targets: ["JWTKit", "JWT"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "1.0.0")
     ],
    targets: [
        .target(name: "JWTKit", dependencies: [.product(name: "Crypto", package: "swift-crypto")]),
        .target(name: "JWT", dependencies: [.product(name: "Crypto", package: "swift-crypto"), "JWTKit"]),
        .testTarget(name: "JWTKitTests", dependencies: ["JWTKit"]),
    ]
)
