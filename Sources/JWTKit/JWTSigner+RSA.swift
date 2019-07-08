import CCryptoOpenSSL
import struct Foundation.Data
@testable import CryptoKit

extension JWTSigner {
    // MARK: RSA

    public static func rs256(key: RSAKey) -> JWTSigner {
        return .init(algorithm: RSASigner(
            key: key,
            algorithm: convert(EVP_sha256()),
            name: "RS256"
        ))
    }

    public static func rs384(key: RSAKey) -> JWTSigner {
        return .init(algorithm: RSASigner(
            key: key,
            algorithm: convert(EVP_sha384()),
            name: "RS384"
        ))
    }

    public static func rs512(key: RSAKey) -> JWTSigner {
        return .init(algorithm: RSASigner(
            key: key,
            algorithm: convert(EVP_sha512()),
            name: "RS512"
        ))
    }
}

extension RSAKey: OpenSSLKey {
    func getParameters() throws -> Parameters {
        let pN: OpaquePointer = RSA_get0_n(self.c.pointer);
        let pE: OpaquePointer = RSA_get0_e(self.c.pointer);
        
        return Parameters(n: BN.convert(pN), e: BN.convert(pE));
    }

    struct Parameters {
        public let n: String;
        public let e: String;
    }
}

// MARK: Private

private enum RSAError: Error {
    case privateKeyRequired
    case signFailure
    case keyInitializationFailure
}

private struct RSASigner: JWTAlgorithm, OpenSSLSigner {
    let key: RSAKey
    let algorithm: OpaquePointer
    let name: String

    func sign<Plaintext>(_ plaintext: Plaintext) throws -> [UInt8]
        where Plaintext: DataProtocol
    {
        guard case .private = self.key.type else {
            throw JWTError.signingAlgorithmFailure(RSAError.privateKeyRequired)
        }
        var signatureLength: UInt32 = 0
        var signature = [UInt8](
            repeating: 0,
            count: Int(RSA_size(convert(key.c.pointer)))
        )

        let digest = try self.digest(plaintext)
        guard RSA_sign(
            EVP_MD_type(convert(self.algorithm)),
            digest,
            numericCast(digest.count),
            &signature,
            &signatureLength,
            convert(self.key.c.pointer)
        ) == 1 else {
            throw JWTError.signingAlgorithmFailure(RSAError.signFailure)
        }

        return .init(signature[0..<numericCast(signatureLength)])
    }

    func verify<Signature, Plaintext>(
        _ signature: Signature,
        signs plaintext: Plaintext
    ) throws -> Bool
        where Signature: DataProtocol, Plaintext: DataProtocol
    {
        let digest = try self.digest(plaintext)
        let signature = signature.copyBytes()
        return RSA_verify(
            EVP_MD_type(convert(self.algorithm)),
            digest,
            numericCast(digest.count),
            signature,
            numericCast(signature.count),
            convert(self.key.c.pointer)
        ) == 1
    }
}
