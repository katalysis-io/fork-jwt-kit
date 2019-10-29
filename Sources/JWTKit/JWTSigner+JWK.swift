import Foundation

extension JWTSigners {
    /// Adds a `JWKS` (JSON Web Key Set) to this signers collection
    /// by first decoding the JSON string.
    public func use(jwksJSON json: String) throws {
        let jwks = try JSONDecoder().decode(JWKS.self, from: Data(json.utf8))
        try self.use(jwks: jwks)
    }
    
    /// Adds a `JWKS` (JSON Web Key Set) to this signers collection.
    public func use(jwks: JWKS) throws {
        try jwks.keys.forEach { try self.use(jwk: $0) }
    }
    
    /// Adds a `JWK` (JSON Web Key) to this signers collection.
    public func use(jwk: JWK) throws {
        guard let kid = jwk.kid else {
            throw JWTError.invalidJWK
        }
        try self.use(.jwk(key:jwk), kid: kid)
    }
}


public extension JWTSigners {

    convenience init(jwks: JWKS, skipAnonymousKeys: Bool = true) throws  {
        self.init()
        for jwk in jwks.keys {
            guard let kid = jwk.kid else {
                if skipAnonymousKeys {
                    continue
                } else {
                    throw JWTError.generic(identifier: "missingKID", reason: "At least a JSON Web Key in the JSON Web Key Set is missing a `kid`.")
                }
            }

            try self.use(JWTSigner.jwk(key: jwk), kid: kid)
        }
    }
}
/*
extension JWTSigner {
    /// Creates a JWT sign from the supplied JWK json string.
    public static func jwk(json: String) throws -> JWTSigner {
        let jwk = try JSONDecoder().decode(JWK.self, from: Data(json.utf8))
        return try self.jwk(jwk)
    }
    
    /// Creates a JWT signer with the supplied JWK
    public static func jwk(_ key: JWK) throws -> JWTSigner {
        switch key.keyType {
        case .rsa:
            guard let modulus = key.modulus else {
                throw JWTError.invalidJWK
            }
            guard let exponent = key.exponent else {
                throw JWTError.invalidJWK
            }
            guard let algorithm = key.algorithm else {
                throw JWTError.invalidJWK
            }
            
            guard let rsaKey = RSAKey(
                modulus: modulus,
                exponent: exponent,
                privateExponent: key.privateExponent
                ) else {
                    throw JWTError.invalidJWK
            }
            
            switch algorithm {
            case .rs256:
                return JWTSigner.rs256(key: rsaKey)
            case .rs384:
                return JWTSigner.rs384(key: rsaKey)
            case .rs512:
                return JWTSigner.rs512(key: rsaKey)
            default:
                throw JWTError.invalidJWK
            }
        case .ec:
            guard let x = key.modulus else {
                throw JWTError.invalidJWK
            }
            guard let y = key.exponent else {
                throw JWTError.invalidJWK
            }
            guard let algorithm = key.algorithm else {
                throw JWTError.invalidJWK
            }
            
            guard let ecdsaKey = try? ECDSAKey.components(x: x, y: y) else {
                    throw JWTError.invalidJWK
            }
            
            switch algorithm {
            case .es256:
                return JWTSigner.es256(key: ecdsaKey)
            case .es384:
                return JWTSigner.es384(key: ecdsaKey)
            case .es512:
                return JWTSigner.es512(key: ecdsaKey)
            default:
                throw JWTError.invalidJWK
            }
            
        }
    }
}
*/
