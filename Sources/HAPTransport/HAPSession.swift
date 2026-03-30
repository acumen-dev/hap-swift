// HAPSession.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto
import HAPCrypto

// MARK: - HAPSession

public actor HAPSession {
    private var readKey: SymmetricKey?
    private var writeKey: SymmetricKey?
    private var readCounter: UInt64 = 0
    private var writeCounter: UInt64 = 0

    public var isEncrypted: Bool { readKey != nil }

    public init() {}

    public func establishSession(readKey: SymmetricKey, writeKey: SymmetricKey) {
        self.readKey = readKey
        self.writeKey = writeKey
        self.readCounter = 0
        self.writeCounter = 0
    }

    // MARK: - Encrypt

    /// Encrypts plaintext into a HAP frame: 2-byte LE length + ciphertext + 16-byte auth tag.
    public func encrypt(_ plaintext: Data) throws -> Data {
        guard let writeKey else { throw HAPCryptoError.encryptionFailed }

        let nonce = HAPEncryption.buildNonce(counter: writeCounter)
        let encrypted = try HAPEncryption.encrypt(plaintext: plaintext, key: writeKey, nonce: nonce)

        // Frame: 2-byte LE length of encrypted data, then encrypted data
        var frame = Data(count: 2)
        let length = UInt16(encrypted.count)
        frame[0] = UInt8(length & 0xFF)
        frame[1] = UInt8(length >> 8)
        frame.append(encrypted)

        self.writeCounter += 1
        return frame
    }

    // MARK: - Decrypt

    /// Attempts to decrypt a complete frame from the buffer.
    /// Returns decrypted plaintext if a complete frame is available, nil if more data is needed.
    public func decryptFrame(from buffer: inout Data) throws -> Data? {
        guard let readKey else { throw HAPCryptoError.decryptionFailed }
        guard buffer.count >= 2 else { return nil }

        let length = Int(buffer[buffer.startIndex]) | (Int(buffer[buffer.startIndex + 1]) << 8)
        let totalFrameSize = 2 + length

        guard buffer.count >= totalFrameSize else { return nil }

        let encrypted = buffer[buffer.startIndex + 2 ..< buffer.startIndex + totalFrameSize]

        let nonce = HAPEncryption.buildNonce(counter: readCounter)
        let plaintext = try HAPEncryption.decrypt(ciphertext: Data(encrypted), key: readKey, nonce: nonce)

        self.readCounter += 1
        buffer.removeFirst(totalFrameSize)

        return plaintext
    }
}
