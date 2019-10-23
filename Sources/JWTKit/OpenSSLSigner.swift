import CJWTKitCrypto
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
        let context = jwtkit_EVP_MD_CTX_new()
        defer { jwtkit_EVP_MD_CTX_free(context) }

        guard EVP_DigestInit_ex(context, convert(self.algorithm), nil) == 1 else {
            throw JWTError.signingAlgorithmFailure(OpenSSLError.digestInitializationFailure)
        }
        let plaintext = plaintext.copyBytes()
        guard EVP_DigestUpdate(context, plaintext, plaintext.count) == 1 else {
            throw JWTError.signingAlgorithmFailure(OpenSSLError.digestUpdateFailure)
        }
        var digest: [UInt8] = .init(repeating: 0, count: Int(EVP_MAX_MD_SIZE))
        var digestLength: UInt32 = 0

        guard EVP_DigestFinal_ex(context, &digest, &digestLength) == 1 else {
            throw JWTError.signingAlgorithmFailure(OpenSSLError.digestFinalizationFailure)
        }
        return .init(digest[0..<Int(digestLength)])
    }
}

public protocol OpenSSLKey { }

extension OpenSSLKey {
    static func load<Data, T>(pem data: Data, _ closure: (OpaquePointer) -> (T?)) throws -> T
        where Data: DataProtocol
    {
        let bio = BIO_new(BIO_s_mem())
        defer { BIO_free(bio) }

        guard (data.copyBytes() + [0]).withUnsafeBytes({ pointer in
            BIO_puts(bio, pointer.baseAddress?.assumingMemoryBound(to: Int8.self))
        }) >= 0 else {
            throw JWTError.signingAlgorithmFailure(OpenSSLError.bioPutsFailure)
        }

        guard let c = closure(convert(bio!)) else {
            throw JWTError.signingAlgorithmFailure(OpenSSLError.bioConversionFailure)
        }
        return c
    }
}

class BN {
    let c: OpaquePointer;

    public init() {
        self.c = BN_new();
    }

    init(_ ptr: OpaquePointer) {
        self.c = ptr;
    }

    deinit {
        BN_free(self.c);
    }

    public static func convert(_ bnBase64: String) -> BN? {
        guard let data = Data(base64Encoded: bnBase64) else {
            return nil
        }

        let c = data.withUnsafeBytes { (p: UnsafeRawBufferPointer) -> OpaquePointer in
            return BN_bin2bn(p.baseAddress?.assumingMemoryBound(to: UInt8.self), Int32(p.count), nil)
        };
        return BN(c);
    }

    public func toBase64(_ size: Int = 1000) -> String {
        let pBuffer = UnsafeMutablePointer<UInt8>.allocate(capacity: size);
        defer { pBuffer.deallocate() };

        let actualBytes = Int(BN_bn2bin(self.c, pBuffer));
        let data = Data(bytes: pBuffer, count: actualBytes);
        return data.base64EncodedString();
    }
}
