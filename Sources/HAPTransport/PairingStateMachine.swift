// PairingStateMachine.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import HAPCore
import HAPCrypto

// MARK: - PairingStateMachine

public actor PairingStateMachine {
    private let setupCode: String
    private let identity: HAPIdentity
    private let pairingStore: any PairingStore
    private let deviceID: String
    private var state: State = .idle

    private enum State {
        case idle
        case awaitingM3(server: SRPServer)
        case awaitingM5(sessionKey: Data)
        case paired
        case error
    }

    public init(setupCode: String, identity: HAPIdentity, pairingStore: any PairingStore, deviceID: String) {
        // HAP SRP uses the raw 8-digit PIN without any separator characters.
        // Strip dashes so "031-45-154" and "03145154" both work correctly.
        self.setupCode = setupCode.filter(\.isNumber)
        self.identity = identity
        self.pairingStore = pairingStore
        self.deviceID = deviceID
    }

    public func handleRequest(_ data: Data) async throws -> Data {
        let items = try TLV8.decode(data)

        guard let stateItem = items.first(where: { $0.type == TLV8Type.state.rawValue }),
              let stateValue = stateItem.value.first else {
            throw HAPPairingError.invalidState
        }

        switch stateValue {
        case 1: return try handleM1(items)
        case 3: return try handleM3(items)
        case 5: return try await handleM5(items)
        default: throw HAPPairingError.invalidState
        }
    }

    // MARK: - M1 → M2

    private func handleM1(_ items: [TLV8.Item]) throws -> Data {
        guard case .idle = state else {
            return errorResponse(state: 2, error: .unknown)
        }

        // Verify method is pair-setup (0x00)
        if let methodItem = items.first(where: { $0.type == TLV8Type.method.rawValue }),
           let method = methodItem.value.first, method != 0x00 {
            return errorResponse(state: 2, error: .unknown)
        }

        let server = SRPServer(setupCode: setupCode)

        self.state = .awaitingM3(server: server)

        return TLV8.encode([
            (type: TLV8Type.state.rawValue, value: Data([0x02])),
            (type: TLV8Type.publicKey.rawValue, value: server.serverPublicKey),
            (type: TLV8Type.salt.rawValue, value: server.salt),
        ])
    }

    // MARK: - M3 → M4

    private func handleM3(_ items: [TLV8.Item]) throws -> Data {
        guard case .awaitingM3(let server) = state else {
            return errorResponse(state: 4, error: .unknown)
        }

        guard let clientPublicKey = items.first(where: { $0.type == TLV8Type.publicKey.rawValue })?.value,
              let clientProof = items.first(where: { $0.type == TLV8Type.proof.rawValue })?.value else {
            self.state = .error
            return errorResponse(state: 4, error: .authentication)
        }

        do {
            let (serverProof, sessionKey) = try server.processClientProof(
                clientPublicKey: clientPublicKey,
                clientProof: clientProof
            )

            self.state = .awaitingM5(sessionKey: sessionKey)

            return TLV8.encode([
                (type: TLV8Type.state.rawValue, value: Data([0x04])),
                (type: TLV8Type.proof.rawValue, value: serverProof),
            ])
        } catch {
            self.state = .error
            return errorResponse(state: 4, error: .authentication)
        }
    }

    // MARK: - M5 → M6

    private func handleM5(_ items: [TLV8.Item]) async throws -> Data {
        guard case .awaitingM5(let sessionKey) = state else {
            return errorResponse(state: 6, error: .unknown)
        }

        guard let encryptedData = items.first(where: { $0.type == TLV8Type.encryptedData.rawValue })?.value else {
            self.state = .error
            return errorResponse(state: 6, error: .authentication)
        }

        // Derive encryption key for M5
        let encKey = HAPKeyDerivation.derivePairSetupEncryptionKey(from: sessionKey)
        let nonce = HAPEncryption.buildNonce(from: "PS-Msg05")

        // Decrypt M5 payload
        let decrypted: Data
        do {
            decrypted = try HAPEncryption.decrypt(ciphertext: encryptedData, key: encKey, nonce: nonce)
        } catch {
            self.state = .error
            return errorResponse(state: 6, error: .authentication)
        }

        // Parse sub-TLV from decrypted data
        let subItems = try TLV8.decode(decrypted)

        guard let controllerIdentifier = subItems.first(where: { $0.type == TLV8Type.identifier.rawValue })?.value,
              let controllerPublicKey = subItems.first(where: { $0.type == TLV8Type.publicKey.rawValue })?.value,
              let controllerSignature = subItems.first(where: { $0.type == TLV8Type.signature.rawValue })?.value else {
            self.state = .error
            return errorResponse(state: 6, error: .authentication)
        }

        // Derive iOSDeviceX for signature verification
        let iosDeviceX = HAPKeyDerivation.deriveKey(
            inputKeyMaterial: sessionKey,
            salt: Data("Pair-Setup-Controller-Sign-Salt".utf8),
            info: Data("Pair-Setup-Controller-Sign-Info".utf8),
            outputByteCount: 32
        )

        // Build iOSDeviceInfo: iOSDeviceX + iOS device pairing ID + iOS device LTPK
        var iosDeviceInfo = Data()
        iosDeviceX.withUnsafeBytes { iosDeviceInfo.append(contentsOf: $0) }
        iosDeviceInfo.append(controllerIdentifier)
        iosDeviceInfo.append(controllerPublicKey)

        // Verify controller signature
        let valid = try HAPIdentity.verify(
            signature: controllerSignature,
            data: iosDeviceInfo,
            publicKey: controllerPublicKey
        )

        guard valid else {
            self.state = .error
            return errorResponse(state: 6, error: .authentication)
        }

        // Store controller pairing
        let identifierString = String(data: controllerIdentifier, encoding: .utf8) ?? controllerIdentifier.hexString
        try await pairingStore.store(controllerIdentifier: identifierString, publicKey: controllerPublicKey)

        // Build M6 response
        // Derive AccessoryX for signature
        let accessoryX = HAPKeyDerivation.deriveKey(
            inputKeyMaterial: sessionKey,
            salt: Data("Pair-Setup-Accessory-Sign-Salt".utf8),
            info: Data("Pair-Setup-Accessory-Sign-Info".utf8),
            outputByteCount: 32
        )

        let accessoryIdentifier = Data(deviceID.utf8)

        // Build accessory info: AccessoryX + accessory pairing ID + accessory LTPK
        var accessoryInfo = Data()
        accessoryX.withUnsafeBytes { accessoryInfo.append(contentsOf: $0) }
        accessoryInfo.append(accessoryIdentifier)
        accessoryInfo.append(identity.publicKeyData)

        // Sign
        let accessorySignature = try identity.sign(accessoryInfo)

        // Build sub-TLV
        let subTLV = TLV8.encode([
            (type: TLV8Type.identifier.rawValue, value: accessoryIdentifier),
            (type: TLV8Type.publicKey.rawValue, value: identity.publicKeyData),
            (type: TLV8Type.signature.rawValue, value: accessorySignature),
        ])

        // Encrypt with PS-Msg06 nonce
        let m6Nonce = HAPEncryption.buildNonce(from: "PS-Msg06")
        let encrypted = try HAPEncryption.encrypt(plaintext: subTLV, key: encKey, nonce: m6Nonce)

        self.state = .paired

        return TLV8.encode([
            (type: TLV8Type.state.rawValue, value: Data([0x06])),
            (type: TLV8Type.encryptedData.rawValue, value: encrypted),
        ])
    }

    // MARK: - Helpers

    private func errorResponse(state: UInt8, error: TLV8ErrorCode) -> Data {
        TLV8.encode([
            (type: TLV8Type.state.rawValue, value: Data([state])),
            (type: TLV8Type.error.rawValue, value: Data([error.rawValue])),
        ])
    }
}
