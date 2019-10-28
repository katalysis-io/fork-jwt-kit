import CJWTKitCrypto

extension JWTSigner {
    // MARK: ECDSA

    public static func es256(key: ECDSAKey) -> JWTSigner {
        return .init(algorithm: ECDSASigner(
            key: key,
            algorithm: convert(EVP_sha256()),
            name: "ES256"
        ))
    }

    public static func es384(key: ECDSAKey) -> JWTSigner {
        return .init(algorithm: ECDSASigner(
            key: key,
            algorithm: convert(EVP_sha384()),
            name: "ES384"
        ))
    }

    public static func es512(key: ECDSAKey) -> JWTSigner {
        return .init(algorithm: ECDSASigner(
            key: key,
            algorithm: convert(EVP_sha512()),
            name: "ES512"
        ))
    }
}

public final class ECDSAKey: OpenSSLKey {
    public static func generate() throws -> ECDSAKey {
        guard let c = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1) else {
            throw JWTError.signingAlgorithmFailure(ECDSAError.newKeyByCurveFailure)
        }
        guard EC_KEY_generate_key(c) != 0 else {
            throw JWTError.signingAlgorithmFailure(ECDSAError.generateKeyFailure)
        }
        return .init(c)
    }

    public static func `public`<Data>(pem data: Data) throws -> ECDSAKey
        where Data: DataProtocol
    {
        let c = try self.load(pem: data) { bio in
            PEM_read_bio_EC_PUBKEY(convert(bio), nil, nil, nil)
        }
        return self.init(c)
    }

    public static func `private`<Data>(pem data: Data) throws -> ECDSAKey
        where Data: DataProtocol
    {
        let c = try self.load(pem: data) { bio in
            PEM_read_bio_ECPrivateKey(convert(bio), nil, nil, nil)
        }
        return self.init(c)
    }

    let c: OpaquePointer

    init(_ c: OpaquePointer) {
        self.c = c
    }

    deinit {
        EC_KEY_free(self.c)
    }

    public static func components(x: String, y: String) throws -> ECDSAKey {
        guard let c = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1) else {
            throw JWTError.signingAlgorithmFailure(ECDSAError.newKeyByCurveFailure)
        }

        guard let bnX = BN.convert(x) else {
            throw JWTError.generic(identifier: "ecCoordinates", reason: "Unable to interpret x as BN");
        }
        guard let bnY = BN.convert(y) else {
            throw JWTError.generic(identifier: "ecCoordinates", reason: "Unable to interpret y as BN");
        }

        if (1 != EC_KEY_set_public_key_affine_coordinates(c, bnX.c, bnY.c)) {
            throw JWTError.generic(identifier: "ecCoordinates", reason: "Unable to set public key");
        }

        return .init(c)
    }

    public func getParameters() throws -> Parameters {
        let group: OpaquePointer = EC_KEY_get0_group(self.c);
        let pubKey: OpaquePointer = EC_KEY_get0_public_key(self.c);

        let bnX = BN();
        let bnY = BN();
        if (EC_POINT_get_affine_coordinates_GFp(group, pubKey, bnX.c, bnY.c, nil) != 1) {
            throw JWTError.generic(identifier: "ecCoordinates", reason: "EC coordinates retrieval failed");
        }

        return Parameters(x: bnX.toBase64(), y: bnY.toBase64());
    }


    public struct Parameters {
        public let x: String;
        public let y: String;
    }

}

// MARK: Private

private enum ECDSAError: Error {
    case newKeyByCurveFailure
    case generateKeyFailure
    case signFailure
}

private struct ECDSASigner: JWTAlgorithm, OpenSSLSigner {
    let key: ECDSAKey
    let algorithm: OpaquePointer
    let name: String

    func sign<Plaintext>(_ plaintext: Plaintext) throws -> [UInt8]
        where Plaintext: DataProtocol
    {
        let digest = try self.digest(plaintext)
        guard let signature = ECDSA_do_sign(
            digest,
            numericCast(digest.count),
            self.key.c
        ) else {
            throw JWTError.signingAlgorithmFailure(ECDSAError.signFailure)
        }
        defer { ECDSA_SIG_free(signature) }

        // serialize r+s values
        // see: https://tools.ietf.org/html/rfc7515#appendix-A.3
        var rBytes = [UInt8](repeating: 0, count: 32)
        var sBytes = [UInt8](repeating: 0, count: 32)
        let rCount = Int(BN_bn2bin(jwtkit_ECDSA_SIG_get0_r(signature), &rBytes))
        let sCount = Int(BN_bn2bin(jwtkit_ECDSA_SIG_get0_s(signature), &sBytes))

        // BN_bn2bin can return < 32 bytes which will result in the data
        // being zero-padded on the wrong side
        return .init(
            [UInt8](repeating: 0, count: 32 - rCount) +
            rBytes[0..<rCount] +
            [UInt8](repeating: 0, count: 32 - sCount) +
            sBytes[0..<sCount]
        )
    }

    func verify<Signature, Plaintext>(
        _ signature: Signature,
        signs plaintext: Plaintext
    ) throws -> Bool
        where Signature: DataProtocol, Plaintext: DataProtocol
    {
        let digest = try self.digest(plaintext)

        // parse r+s values
        // see: https://tools.ietf.org/html/rfc7515#appendix-A.3
        let signatureBytes = signature.copyBytes()
        guard signatureBytes.count == 64 else {
            return false
        }

        let signature = ECDSA_SIG_new()
        defer { ECDSA_SIG_free(signature) }

        signatureBytes[0..<32].withUnsafeBufferPointer { r in
            signatureBytes[32..<64].withUnsafeBufferPointer { s in
                // passing bignums to this method transfers ownership
                // (they will be freed when the signature is freed)
                guard jwtkit_ECDSA_SIG_set0(
                    signature,
                    BN_bin2bn(r.baseAddress, 32, nil),
                    BN_bin2bn(s.baseAddress, 32, nil)
                ) == 1 else {
                    fatalError("ECDSA_SIG_set failed")
                }
            }
        }

        return ECDSA_do_verify(
            digest,
            numericCast(digest.count),
            signature,
            self.key.c
        ) == 1
    }
}
