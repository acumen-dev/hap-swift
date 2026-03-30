// HAPKeyDerivation.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto

public enum HAPKeyDerivation {

    // MARK: - Constants

    public static let pairSetupEncryptSalt = Data("Pair-Setup-Encrypt-Salt".utf8)
    public static let pairSetupEncryptInfo = Data("Pair-Setup-Encrypt-Info".utf8)

    public static let pairVerifyEncryptSalt = Data("Pair-Verify-Encrypt-Salt".utf8)
    public static let pairVerifyEncryptInfo = Data("Pair-Verify-Encrypt-Info".utf8)

    public static let controlSalt = Data("Control-Salt".utf8)
    public static let controlWriteInfo = Data("Control-Write-Encryption-Key".utf8)
    public static let controlReadInfo = Data("Control-Read-Encryption-Key".utf8)

    // MARK: - Key Derivation

    public static func deriveKey(
        inputKeyMaterial: Data,
        salt: Data,
        info: Data,
        outputByteCount: Int = 32
    ) -> SymmetricKey {
        let ikm = SymmetricKey(data: inputKeyMaterial)
        return HKDF<SHA512>.deriveKey(
            inputKeyMaterial: ikm,
            salt: salt,
            info: info,
            outputByteCount: outputByteCount
        )
    }

    public static func derivePairSetupEncryptionKey(from sessionKey: Data) -> SymmetricKey {
        deriveKey(
            inputKeyMaterial: sessionKey,
            salt: pairSetupEncryptSalt,
            info: pairSetupEncryptInfo
        )
    }

    public static func derivePairVerifyEncryptionKey(from sharedSecret: Data) -> SymmetricKey {
        deriveKey(
            inputKeyMaterial: sharedSecret,
            salt: pairVerifyEncryptSalt,
            info: pairVerifyEncryptInfo
        )
    }

    public static func deriveSessionKeys(
        from sharedSecret: Data
    ) -> (writeKey: SymmetricKey, readKey: SymmetricKey) {
        let writeKey = deriveKey(
            inputKeyMaterial: sharedSecret,
            salt: controlSalt,
            info: controlWriteInfo
        )
        let readKey = deriveKey(
            inputKeyMaterial: sharedSecret,
            salt: controlSalt,
            info: controlReadInfo
        )
        return (writeKey: writeKey, readKey: readKey)
    }
}
