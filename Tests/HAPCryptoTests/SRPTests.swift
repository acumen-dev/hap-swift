// SRPTests.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import Testing
@testable import HAPCrypto

@Suite("SRP Tests")
struct SRPTests {

    @Test("full client-server handshake — both derive same session key")
    func fullHandshake() throws {
        let setupCode = "03145154"

        let server = SRPServer(setupCode: setupCode)
        let client = SRPClient()

        let (clientProof, expectedServerProof, clientSessionKey) = try client.processServerChallenge(
            serverPublicKey: server.serverPublicKey,
            salt: server.salt,
            setupCode: setupCode
        )

        let (serverProof, serverSessionKey) = try server.processClientProof(
            clientPublicKey: client.clientPublicKey,
            clientProof: clientProof
        )

        #expect(clientSessionKey == serverSessionKey)
        #expect(serverProof == expectedServerProof)
    }

    @Test("invalid client public key A=0 is rejected")
    func invalidClientPublicKeyZero() throws {
        let server = SRPServer(setupCode: "03145154")
        let zeroKey = Data(repeating: 0, count: 384)
        let fakeProof = Data(repeating: 0, count: 64)

        #expect(throws: HAPCryptoError.self) {
            _ = try server.processClientProof(
                clientPublicKey: zeroKey,
                clientProof: fakeProof
            )
        }
    }

    @Test("wrong client proof is rejected")
    func wrongClientProof() throws {
        let setupCode = "03145154"
        let server = SRPServer(setupCode: setupCode)
        let client = SRPClient()

        let (clientProof, _, _) = try client.processServerChallenge(
            serverPublicKey: server.serverPublicKey,
            salt: server.salt,
            setupCode: setupCode
        )

        // Tamper with proof
        var tamperedProof = clientProof
        tamperedProof[0] ^= 0xFF

        #expect(throws: HAPCryptoError.self) {
            _ = try server.processClientProof(
                clientPublicKey: client.clientPublicKey,
                clientProof: tamperedProof
            )
        }
    }

    @Test("wrong password produces proof mismatch")
    func wrongPassword() throws {
        let server = SRPServer(setupCode: "03145154")
        let client = SRPClient()

        let (clientProof, _, _) = try client.processServerChallenge(
            serverPublicKey: server.serverPublicKey,
            salt: server.salt,
            setupCode: "99999999"  // Wrong password
        )

        #expect(throws: HAPCryptoError.self) {
            _ = try server.processClientProof(
                clientPublicKey: client.clientPublicKey,
                clientProof: clientProof
            )
        }
    }

    @Test("deterministic handshake with known private keys")
    func deterministicHandshake() throws {
        let setupCode = "03145154"
        let salt = Data(repeating: 0xAB, count: 16)
        let serverPrivateKey = Data(repeating: 0x01, count: 32)
        let clientPrivateKey = Data(repeating: 0x02, count: 32)

        let server = SRPServer(salt: salt, setupCode: setupCode, serverPrivateKey: serverPrivateKey)
        let client = SRPClient(clientPrivateKey: clientPrivateKey)

        let (clientProof, expectedServerProof, clientSessionKey) = try client.processServerChallenge(
            serverPublicKey: server.serverPublicKey,
            salt: salt,
            setupCode: setupCode
        )

        let (serverProof, serverSessionKey) = try server.processClientProof(
            clientPublicKey: client.clientPublicKey,
            clientProof: clientProof
        )

        #expect(clientSessionKey == serverSessionKey)
        #expect(serverProof == expectedServerProof)

        // Session key should be deterministic with fixed inputs
        #expect(serverSessionKey.count == 64)  // SHA-512 output
    }

    @Test("multiple handshakes produce different session keys")
    func differentKeysPerHandshake() throws {
        let setupCode = "03145154"

        let server1 = SRPServer(setupCode: setupCode)
        let client1 = SRPClient()
        let (proof1, _, key1) = try client1.processServerChallenge(
            serverPublicKey: server1.serverPublicKey,
            salt: server1.salt,
            setupCode: setupCode
        )
        let (_, serverKey1) = try server1.processClientProof(
            clientPublicKey: client1.clientPublicKey,
            clientProof: proof1
        )

        let server2 = SRPServer(setupCode: setupCode)
        let client2 = SRPClient()
        let (proof2, _, key2) = try client2.processServerChallenge(
            serverPublicKey: server2.serverPublicKey,
            salt: server2.salt,
            setupCode: setupCode
        )
        let (_, serverKey2) = try server2.processClientProof(
            clientPublicKey: client2.clientPublicKey,
            clientProof: proof2
        )

        #expect(key1 == serverKey1)
        #expect(key2 == serverKey2)
        #expect(key1 != key2)  // Different random keys each time
    }
}
