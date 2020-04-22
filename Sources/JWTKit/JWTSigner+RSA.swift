import CJWTKitBoringSSL
import struct Foundation.Data
@testable import Crypto

extension JWTSigner {
    // MARK: RSA

    public static func rs256(key: RSAKey) -> JWTSigner {
        return .init(algorithm: RSASigner(
            key: key,
            algorithm: convert(CJWTKitBoringSSL_EVP_sha256()),
            name: "RS256"
        ))
    }

    public static func rs384(key: RSAKey) -> JWTSigner {
        return .init(algorithm: RSASigner(
            key: key,
            algorithm: convert(CJWTKitBoringSSL_EVP_sha384()),
            name: "RS384"
        ))
    }

    public static func rs512(key: RSAKey) -> JWTSigner {
        return .init(algorithm: RSASigner(
            key: key,
            algorithm: convert(CJWTKitBoringSSL_EVP_sha512()),
            name: "RS512"
        ))
    }
}

public final class RSAKey: OpenSSLKey {
    public static func `public`<Data>(pem data: Data) throws -> RSAKey
        where Data: DataProtocol
    {
        let pkey = try self.load(pem: data) { bio in
            CJWTKitBoringSSL_PEM_read_bio_PUBKEY(bio, nil, nil, nil)
        }
        defer { CJWTKitBoringSSL_EVP_PKEY_free(pkey) }

        guard let c = CJWTKitBoringSSL_EVP_PKEY_get1_RSA(pkey) else {
            throw JWTError.signingAlgorithmFailure(RSAError.keyInitializationFailure)
        }
        return self.init(c, .public)
    }

    public static func `private`<Data>(pem data: Data) throws -> RSAKey
        where Data: DataProtocol
    {
        let pkey = try self.load(pem: data) { bio in
            CJWTKitBoringSSL_PEM_read_bio_PrivateKey(bio, nil, nil, nil)
        }
        defer { CJWTKitBoringSSL_EVP_PKEY_free(pkey) }

        guard let c = CJWTKitBoringSSL_EVP_PKEY_get1_RSA(pkey) else {
            throw JWTError.signingAlgorithmFailure(RSAError.keyInitializationFailure)
        }
        return self.init(c, .private)
    }

    public convenience init?(
        modulus: String,
        exponent: String,
        privateExponent: String? = nil
    ) {
        func decode(_ string: String) -> [UInt8] {
            return [UInt8](string.utf8).base64URLDecodedBytes()
        }
        let n = decode(modulus)
        let e = decode(exponent)
        let d = privateExponent.flatMap { decode($0) }

        guard let rsa = CJWTKitBoringSSL_RSA_new() else {
            return nil
        }

        CJWTKitBoringSSL_RSA_set0_key(
            rsa,
            CJWTKitBoringSSL_BN_bin2bn(n, numericCast(n.count), nil),
            CJWTKitBoringSSL_BN_bin2bn(e, numericCast(e.count), nil),
            d.flatMap { CJWTKitBoringSSL_BN_bin2bn($0, numericCast($0.count), nil) }
        )
        self.init(rsa, d == nil ? .public : .private)
    }

    enum KeyType {
        case `public`, `private`
    }

    let type: KeyType
    let c: UnsafeMutablePointer<RSA>

    init(_ c: UnsafeMutablePointer<RSA>, _ type: KeyType) {
        self.type = type
        self.c = c
    }

    deinit {
        CJWTKitBoringSSL_RSA_free(self.c)
    }
}

extension RSAKey {

    func getParameters() throws -> Parameters {
        let bnN = BN(UnsafeMutablePointer<BIGNUM>(mutating: CJWTKitBoringSSL_RSA_get0_n(self.c)));
        let bnE = BN(UnsafeMutablePointer<BIGNUM>(mutating: CJWTKitBoringSSL_RSA_get0_e(self.c)));
        return Parameters(n: bnN.toBase64(), e: bnE.toBase64());
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
            count: Int(CJWTKitBoringSSL_RSA_size(key.c))
        )

        let digest = try self.digest(plaintext)
        guard CJWTKitBoringSSL_RSA_sign(
            CJWTKitBoringSSL_EVP_MD_type(convert(self.algorithm)),
            digest,
            numericCast(digest.count),
            &signature,
            &signatureLength,
            self.key.c
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
        return CJWTKitBoringSSL_RSA_verify(
            CJWTKitBoringSSL_EVP_MD_type(convert(self.algorithm)),
            digest,
            numericCast(digest.count),
            signature,
            numericCast(signature.count),
            self.key.c
        ) == 1
    }
}
