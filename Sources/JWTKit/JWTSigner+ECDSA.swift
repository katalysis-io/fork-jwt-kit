import CCryptoOpenSSL

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

    public static func components(x: String, y: String) throws -> ECDSAKey {
        let ec = try ECDSAKey.generate();
        let group: OpaquePointer = EC_KEY_get0_group(ec.c);
        let pubKey: OpaquePointer = EC_KEY_get0_public_key(ec.c);
        let code = EC_POINT_set_affine_coordinates_GFp(group, pubKey, BN.convert(x), BN.convert(y), nil)
        if (code != 1) {
            throw JWTError.generic(identifier: "ecCoordinates", reason: "Unable to set public key");
        }
        return ec;
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

    public func getParameters() throws -> Parameters {
        let group: OpaquePointer = EC_KEY_get0_group(self.c);
        let pubKey: OpaquePointer = EC_KEY_get0_public_key(self.c);
        
        let pX = UnsafeMutablePointer<UInt8>.allocate(capacity: 100);
        defer { pX.deallocate() };
        let pY = UnsafeMutablePointer<UInt8>.allocate(capacity: 100);
        defer { pY.deallocate() };
        
        // openssl BIGNUM struct in 4xInt and 1xInt*
        let pXw = OpaquePointer(pX);
        let pYw = OpaquePointer(pY);
        
        if (EC_POINT_set_affine_coordinates_GFp(group, pubKey, pXw, pYw, nil) != 1) {
            throw JWTError.generic(identifier: "ecCoordinates", reason: "EC coordinates retrieval failed");
        }
        
        return Parameters(x: BN.convert(pXw), y: BN.convert(pYw));
    }


    let c: OpaquePointer

    init(_ c: OpaquePointer) {
        self.c = c
    }

    deinit {
        EC_KEY_free(self.c)
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
            count: Int(ECDSA_size(self.key.c))
        )

        let digest = try self.digest(plaintext)
        guard ECDSA_sign(
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
        return ECDSA_verify(
            0,
            digest,
            numericCast(digest.count),
            signature,
            numericCast(signature.count),
            self.key.c
        )  == 1
    }
}
