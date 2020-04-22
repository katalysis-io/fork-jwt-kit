import CJWTKitBoringSSL
import Foundation

protocol OpenSSLSigner {
    var algorithm: OpaquePointer { get }
}

private enum OpenSSLError: Error {
    case digestInitializationFailure
    case digestUpdateFailure
    case digestFinalizationFailure
    case bioPutsFailure
    case bioConversionFailure
}

extension OpenSSLSigner {
    func digest<Plaintext>(_ plaintext: Plaintext) throws -> [UInt8]
        where Plaintext: DataProtocol
    {
        let context = CJWTKitBoringSSL_EVP_MD_CTX_new()
        defer { CJWTKitBoringSSL_EVP_MD_CTX_free(context) }

        guard CJWTKitBoringSSL_EVP_DigestInit_ex(context, convert(self.algorithm), nil) == 1 else {
            throw JWTError.signingAlgorithmFailure(OpenSSLError.digestInitializationFailure)
        }
        let plaintext = plaintext.copyBytes()
        guard CJWTKitBoringSSL_EVP_DigestUpdate(context, plaintext, plaintext.count) == 1 else {
            throw JWTError.signingAlgorithmFailure(OpenSSLError.digestUpdateFailure)
        }
        var digest: [UInt8] = .init(repeating: 0, count: Int(EVP_MAX_MD_SIZE))
        var digestLength: UInt32 = 0

        guard CJWTKitBoringSSL_EVP_DigestFinal_ex(context, &digest, &digestLength) == 1 else {
            throw JWTError.signingAlgorithmFailure(OpenSSLError.digestFinalizationFailure)
        }
        return .init(digest[0..<Int(digestLength)])
    }
}

public protocol OpenSSLKey { }

extension OpenSSLKey {
    static func load<Data, T>(pem data: Data, _ closure: (UnsafeMutablePointer<bio_st>) -> (T?)) throws -> T
        where Data: DataProtocol
    {
        let bio = CJWTKitBoringSSL_BIO_new(CJWTKitBoringSSL_BIO_s_mem())
        defer { CJWTKitBoringSSL_BIO_free(bio) }

        guard (data.copyBytes() + [0]).withUnsafeBytes({ pointer in
            CJWTKitBoringSSL_BIO_puts(bio, pointer.baseAddress?.assumingMemoryBound(to: Int8.self))
        }) >= 0 else {
            throw JWTError.signingAlgorithmFailure(OpenSSLError.bioPutsFailure)
        }

        guard let c = closure(bio!) else {
            throw JWTError.signingAlgorithmFailure(OpenSSLError.bioConversionFailure)
        }
        return c
    }
}

class BN {
    let c: UnsafeMutablePointer<BIGNUM>?;

    public init() {
        self.c = CJWTKitBoringSSL_BN_new();
    }

    init(_ ptr: UnsafeMutablePointer<BIGNUM>?) {
        self.c = ptr;
    }

    deinit {
        CJWTKitBoringSSL_BN_free(self.c);
    }

    public static func convert(_ bnBase64: String) -> BN? {
        let data = Data(bnBase64.utf8).base64URLDecodedBytes()

        let c = data.withUnsafeBytes { (p: UnsafeRawBufferPointer) -> UnsafeMutablePointer<BIGNUM> in
            return CJWTKitBoringSSL_BN_bin2bn(p.baseAddress?.assumingMemoryBound(to: UInt8.self), p.count, nil)
        };
        return BN(c);
    }

    public func toBase64(_ size: Int = 1000) -> String {
        let pBuffer = UnsafeMutablePointer<UInt8>.allocate(capacity: size);
        defer { pBuffer.deallocate() };

        let actualBytes = Int(CJWTKitBoringSSL_BN_bn2bin(self.c, pBuffer));
        let data = Data(bytes: pBuffer, count: actualBytes);
        return String(bytes: data.base64URLEncodedBytes(), encoding: .utf8) ?? "";
    }
}
