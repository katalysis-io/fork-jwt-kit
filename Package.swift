// swift-tools-version:5.0
import PackageDescription

let package = Package(
    name: "jwt-kit",
    products: [
        .library(name: "JWTKit", targets: ["JWTKit", "JWT"]),
    ],
    dependencies: [ ],
    targets: [
        .systemLibrary(
            name: "CJWTKitOpenSSL",
            pkgConfig: "openssl",
            providers: [
                .apt(["openssl libssl-dev"]),
                .brew(["openssl"])
            ]
        ),
        .target(name: "CJWTKitCrypto", dependencies: ["CJWTKitOpenSSL"]),
        .target(name: "JWTKit", dependencies: ["CJWTKitCrypto"]),
        .target(name: "JWT", dependencies: ["CJWTKitCrypto"]),
        .testTarget(name: "JWTKitTests", dependencies: ["JWTKit"]),
    ]
)
