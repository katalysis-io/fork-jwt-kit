import CCryptoOpenSSL
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
        let context = EVP_MD_CTX_new()
        defer { EVP_MD_CTX_free(context) }

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

protocol OpenSSLKey { }

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

struct BN {
    public static func size(_ bn: OpaquePointer) -> Int {
        // BN_num_bytes
        return Int((BN_num_bits(bn) * 7) / 8);
    }
    
    public static func convert(_ bnBase64: String) -> OpaquePointer? {
        guard let data = Data(base64URLEncoded: bnBase64) else {
            return nil
        }
        
        return data.withUnsafeBytes { (p: UnsafeRawBufferPointer) -> OpaquePointer in
            return BN_bin2bn(p.baseAddress?.assumingMemoryBound(to: UInt8.self), Int32(p.count), nil)
        }
    }
    
    public static func convert(_ bn: OpaquePointer) -> String {
        let bnPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: BN.size(bn));
        defer { bnPointer.deallocate() };
        
        let actualBytes = Int(BN_bn2bin(bn, bnPointer));
        let data = Data(bytes: bnPointer, count: actualBytes);
        return data.base64URLEncodedString();
    }
}
