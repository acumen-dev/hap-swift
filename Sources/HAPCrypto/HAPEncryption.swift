// HAPEncryption.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto

public enum HAPEncryption {

    // MARK: - Encrypt

    public static func encrypt(
        plaintext: Data,
        key: SymmetricKey,
        nonce nonceData: Data
    ) throws -> Data {
        guard nonceData.count == 12 else {
            throw HAPCryptoError.encryptionFailed
        }
        let nonce = try ChaChaPoly.Nonce(data: nonceData)
        let sealed = try ChaChaPoly.seal(plaintext, using: key, nonce: nonce)
        return sealed.ciphertext + sealed.tag
    }

    // MARK: - Decrypt

    public static func decrypt(
        ciphertext: Data,
        key: SymmetricKey,
        nonce nonceData: Data
    ) throws -> Data {
        guard nonceData.count == 12 else {
            throw HAPCryptoError.decryptionFailed
        }
        guard ciphertext.count >= 16 else {
            throw HAPCryptoError.decryptionFailed
        }
        let nonce = try ChaChaPoly.Nonce(data: nonceData)
        let tagStart = ciphertext.count - 16
        let ct = ciphertext[ciphertext.startIndex ..< ciphertext.startIndex + tagStart]
        let tag = ciphertext[ciphertext.startIndex + tagStart ..< ciphertext.endIndex]
        let sealedBox = try ChaChaPoly.SealedBox(nonce: nonce, ciphertext: ct, tag: tag)
        return try ChaChaPoly.open(sealedBox, using: key)
    }

    // MARK: - Nonce Builders

    /// Build 12-byte nonce from frame counter: 4 zero bytes + 8-byte LE counter.
    public static func buildNonce(counter: UInt64) -> Data {
        var nonce = Data(repeating: 0, count: 4)
        var le = counter.littleEndian
        nonce.append(Data(bytes: &le, count: 8))
        return nonce
    }

    /// Build 12-byte nonce from string (e.g. "PS-Msg05"): 4 zero bytes + string bytes padded/truncated to 8.
    public static func buildNonce(from string: String) -> Data {
        var nonce = Data(repeating: 0, count: 4)
        var stringBytes = Data(string.utf8)
        if stringBytes.count < 8 {
            stringBytes.append(Data(repeating: 0, count: 8 - stringBytes.count))
        } else if stringBytes.count > 8 {
            stringBytes = stringBytes.prefix(8)
        }
        nonce.append(stringBytes)
        return nonce
    }
}
