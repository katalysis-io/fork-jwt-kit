import CJWTKitBoringSSL

extension JWTSigner {
    // MARK: ECDSA

    public static func es256(key: ECDSAKey) -> JWTSigner {
        return .init(algorithm: ECDSASigner(
            key: key,
            algorithm: convert(CJWTKitBoringSSL_EVP_sha256()),
            name: "ES256"
        ))
    }

    public static func es384(key: ECDSAKey) -> JWTSigner {
        return .init(algorithm: ECDSASigner(
            key: key,
            algorithm: convert(CJWTKitBoringSSL_EVP_sha384()),
            name: "ES384"
        ))
    }

    public static func es512(key: ECDSAKey) -> JWTSigner {
        return .init(algorithm: ECDSASigner(
            key: key,
            algorithm: convert(CJWTKitBoringSSL_EVP_sha512()),
            name: "ES512"
        ))
    }
}

public final class ECDSAKey: OpenSSLKey {
    public static func generate() throws -> ECDSAKey {
        guard let c = CJWTKitBoringSSL_EC_KEY_new_by_curve_name(NID_X9_62_prime256v1) else {
            throw JWTError.signingAlgorithmFailure(ECDSAError.newKeyByCurveFailure)
        }
        guard CJWTKitBoringSSL_EC_KEY_generate_key(c) != 0 else {
            throw JWTError.signingAlgorithmFailure(ECDSAError.generateKeyFailure)
        }
        return .init(c)
    }

    public static func components(x: String, y: String) throws -> ECDSAKey {
        guard let c = CJWTKitBoringSSL_EC_KEY_new_by_curve_name(NID_X9_62_prime256v1) else {
            throw JWTError.signingAlgorithmFailure(ECDSAError.newKeyByCurveFailure)
        }

        guard let bnX = BN.convert(x) else {
            throw JWTError.generic(identifier: "ecCoordinates", reason: "Unable to interpret x as BN");
        }
        guard let bnY = BN.convert(y) else {
            throw JWTError.generic(identifier: "ecCoordinates", reason: "Unable to interpret y as BN");
        }

        if (1 != CJWTKitBoringSSL_EC_KEY_set_public_key_affine_coordinates(c, bnX.c, bnY.c)) {
            throw JWTError.generic(identifier: "ecCoordinates", reason: "Unable to set public key");
        }

        return .init(c)
    }

    public static func `public`<Data>(pem data: Data) throws -> ECDSAKey
        where Data: DataProtocol
    {
        let c = try self.load(pem: data) { bio in
            CJWTKitBoringSSL_PEM_read_bio_EC_PUBKEY(bio, nil, nil, nil)
        }
        return self.init(c)
    }

    public static func `private`<Data>(pem data: Data) throws -> ECDSAKey
        where Data: DataProtocol
    {
        let c = try self.load(pem: data) { bio in
            CJWTKitBoringSSL_PEM_read_bio_ECPrivateKey(bio, nil, nil, nil)
        }
        return self.init(c)
    }

    public func getParameters() throws -> Parameters {
        let group: OpaquePointer = CJWTKitBoringSSL_EC_KEY_get0_group(self.c);
        let pubKey: OpaquePointer = CJWTKitBoringSSL_EC_KEY_get0_public_key(self.c);

        let bnX = BN();
        let bnY = BN();
        if (CJWTKitBoringSSL_EC_POINT_get_affine_coordinates_GFp(group, pubKey, bnX.c, bnY.c, nil) != 1) {
            throw JWTError.generic(identifier: "ecCoordinates", reason: "EC coordinates retrieval failed");
        }

        return Parameters(x: bnX.toBase64(), y: bnY.toBase64());
    }


    let c: OpaquePointer

    init(_ c: OpaquePointer) {
        self.c = c
    }

    deinit {
        CJWTKitBoringSSL_EC_KEY_free(self.c)
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
        var signatureLength: UInt32 = 0
        var signature = [UInt8](
            repeating: 0,
            count: Int(CJWTKitBoringSSL_ECDSA_size(self.key.c))
        )

        let digest = try self.digest(plaintext)
        guard CJWTKitBoringSSL_ECDSA_sign(
            0,
            digest,
            numericCast(digest.count),
            &signature,
            &signatureLength,
            self.key.c
        ) == 1 else {
            throw JWTError.signingAlgorithmFailure(ECDSAError.signFailure)
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
        return CJWTKitBoringSSL_ECDSA_verify(
            0,
            digest,
            numericCast(digest.count),
            signature,
            numericCast(signature.count),
            self.key.c
        )  == 1
    }
}
