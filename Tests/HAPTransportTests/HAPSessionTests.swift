// HAPSessionTests.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Crypto
import Testing
@testable import HAPTransport

@Suite("HAPSession Tests")
struct HAPSessionTests {

    @Test("encrypt and decrypt round-trip")
    func encryptDecryptRoundTrip() async throws {
        let session = HAPSession()
        let readKey = SymmetricKey(size: .bits256)
        let writeKey = SymmetricKey(size: .bits256)

        await session.establishSession(readKey: writeKey, writeKey: readKey)

        // Create a "remote" session with swapped keys
        let remote = HAPSession()
        await remote.establishSession(readKey: readKey, writeKey: writeKey)

        let plaintext = Data("Hello HAP".utf8)
        let frame = try await remote.encrypt(plaintext)

        var buffer = frame
        let decrypted = try await session.decryptFrame(from: &buffer)
        #expect(decrypted == plaintext)
        #expect(buffer.isEmpty)
    }

    @Test("frame format — 2-byte LE length prefix")
    func frameFormat() async throws {
        let session = HAPSession()
        let key = SymmetricKey(size: .bits256)
        await session.establishSession(readKey: key, writeKey: key)

        let plaintext = Data("test".utf8)
        let frame = try await session.encrypt(plaintext)

        // First 2 bytes are LE length of (ciphertext + 16-byte tag)
        let length = Int(frame[0]) | (Int(frame[1]) << 8)
        #expect(length == plaintext.count + 16)
        #expect(frame.count == 2 + length)
    }

    @Test("partial frame returns nil")
    func partialFrame() async throws {
        let session = HAPSession()
        let key = SymmetricKey(size: .bits256)
        await session.establishSession(readKey: key, writeKey: key)

        // Only 1 byte — not enough for length header
        var buffer = Data([0x10])
        let result = try await session.decryptFrame(from: &buffer)
        #expect(result == nil)
        #expect(buffer.count == 1)  // Buffer unchanged
    }

    @Test("incomplete frame returns nil")
    func incompleteFrame() async throws {
        let session = HAPSession()
        let key = SymmetricKey(size: .bits256)
        await session.establishSession(readKey: key, writeKey: key)

        // Length header says 100 bytes but we only have 10
        var buffer = Data([0x64, 0x00]) + Data(repeating: 0, count: 10)
        let result = try await session.decryptFrame(from: &buffer)
        #expect(result == nil)
    }

    @Test("counter increments after each encrypt")
    func counterIncrement() async throws {
        let session = HAPSession()
        let writeKey = SymmetricKey(size: .bits256)
        let readKey = SymmetricKey(size: .bits256)
        await session.establishSession(readKey: readKey, writeKey: writeKey)

        let frame1 = try await session.encrypt(Data("a".utf8))
        let frame2 = try await session.encrypt(Data("a".utf8))

        // Same plaintext should produce different frames due to different nonces
        #expect(frame1 != frame2)
    }

    @Test("not encrypted by default")
    func notEncryptedByDefault() async {
        let session = HAPSession()
        let encrypted = await session.isEncrypted
        #expect(!encrypted)
    }
}
