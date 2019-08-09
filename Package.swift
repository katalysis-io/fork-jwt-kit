// swift-tools-version:5.0
import PackageDescription

let package = Package(
    name: "jwt-kit",
    products: [
        .library(name: "JWTKit", targets: ["JWTKit", "JWT"]),
    ],
    dependencies: [
        .package(url: "https://github.com/vapor/crypto-kit.git", from: "4.0.0-alpha"),
     ],
    targets: [
        .target(name: "JWTKit", dependencies: ["OpenCrypto"]),
        .target(name: "JWT", dependencies: ["OpenCrypto", "JWTKit"]),
        .testTarget(name: "JWTKitTests", dependencies: ["JWTKit"]),
    ]
)
