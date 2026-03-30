// CharacteristicProtocol.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import HAPCore
import HAPCrypto

// MARK: - CharacteristicProtocol

public struct CharacteristicProtocol: Sendable {
    private let bridge: HAPBridge
    private let pairingStateMachine: PairingStateMachine
    private let pairVerifyStateMachine: PairVerifyStateMachine

    public init(
        bridge: HAPBridge,
        pairingStateMachine: PairingStateMachine,
        pairVerifyStateMachine: PairVerifyStateMachine
    ) {
        self.bridge = bridge
        self.pairingStateMachine = pairingStateMachine
        self.pairVerifyStateMachine = pairVerifyStateMachine
    }

    public func handleRequest(_ request: HTTPRequest) async throws -> HTTPResponse {
        switch (request.method, request.path) {
        case ("POST", "/pair-setup"):
            return try await handlePairSetup(request)
        case ("POST", "/pair-verify"):
            return try await handlePairVerify(request)
        case ("GET", "/accessories"):
            return try await handleGetAccessories()
        case ("GET", let path) where path.hasPrefix("/characteristics"):
            return try await handleGetCharacteristics(request)
        case ("PUT", "/characteristics"):
            return try await handlePutCharacteristics(request)
        default:
            return HTTPProtocol.errorResponse(status: 404, message: "Not Found")
        }
    }

    // MARK: - Pair Setup

    private func handlePairSetup(_ request: HTTPRequest) async throws -> HTTPResponse {
        let responseData = try await pairingStateMachine.handleRequest(request.body)
        return HTTPProtocol.okResponse(body: responseData, contentType: HTTPProtocol.pairingTLV8)
    }

    // MARK: - Pair Verify

    private func handlePairVerify(_ request: HTTPRequest) async throws -> HTTPResponse {
        let responseData = try await pairVerifyStateMachine.handleRequest(request.body)
        return HTTPProtocol.okResponse(body: responseData, contentType: HTTPProtocol.pairingTLV8)
    }

    // MARK: - GET /accessories

    private func handleGetAccessories() async throws -> HTTPResponse {
        let accessories = await bridge.accessoryDatabase()
        let json = encodeAccessoryDatabase(accessories)
        return HTTPProtocol.okResponse(body: json, contentType: HTTPProtocol.hapJSON)
    }

    // MARK: - GET /characteristics?id=AID.IID,...

    private func handleGetCharacteristics(_ request: HTTPRequest) async throws -> HTTPResponse {
        guard let queryStart = request.path.firstIndex(of: "?") else {
            return HTTPProtocol.errorResponse(status: 400, message: "Bad Request")
        }

        let query = request.path[request.path.index(after: queryStart)...]
        guard query.hasPrefix("id=") else {
            return HTTPProtocol.errorResponse(status: 400, message: "Bad Request")
        }

        let idsString = query.dropFirst(3)  // Remove "id="
        let ids = idsString.split(separator: ",")

        var characteristics: [[String: Any]] = []
        for id in ids {
            let parts = id.split(separator: ".")
            guard parts.count == 2,
                  let aid = UInt64(parts[0]),
                  let iid = UInt64(parts[1]) else {
                continue
            }

            var charDict: [String: Any] = ["aid": aid, "iid": iid]
            if let value = await bridge.readCharacteristic(aid: aid, iid: iid) {
                charDict["value"] = encodeValue(value)
            } else {
                charDict["status"] = HAPStatus.resourceDoesNotExist.rawValue
            }
            characteristics.append(charDict)
        }

        let responseDict: [String: Any] = ["characteristics": characteristics]
        let json = try JSONSerialization.data(withJSONObject: responseDict)
        return HTTPProtocol.okResponse(body: json, contentType: HTTPProtocol.hapJSON)
    }

    // MARK: - PUT /characteristics

    private func handlePutCharacteristics(_ request: HTTPRequest) async throws -> HTTPResponse {
        guard let parsed = try? JSONSerialization.jsonObject(with: request.body) as? [String: Any],
              let characteristics = parsed["characteristics"] as? [[String: Any]] else {
            return HTTPProtocol.errorResponse(status: 400, message: "Bad Request")
        }

        for charDict in characteristics {
            guard let aid = charDict["aid"] as? UInt64 ?? (charDict["aid"] as? Int).map(UInt64.init),
                  let iid = charDict["iid"] as? UInt64 ?? (charDict["iid"] as? Int).map(UInt64.init) else {
                continue
            }

            if let rawValue = charDict["value"] {
                let value = decodeValue(rawValue)
                if let value {
                    try await bridge.writeCharacteristic(aid: aid, iid: iid, value: value)
                }
            }
        }

        return HTTPProtocol.noContentResponse()
    }

    // MARK: - JSON Encoding

    private func encodeAccessoryDatabase(_ accessories: [HAPAccessory]) -> Data {
        var accessoryList: [[String: Any]] = []

        for accessory in accessories {
            var serviceList: [[String: Any]] = []

            for service in accessory.services {
                var charList: [[String: Any]] = []

                for char in service.characteristics {
                    var charDict: [String: Any] = [
                        "iid": char.iid,
                        "type": char.type.rawValue,
                        "perms": char.permissions.map(\.rawValue),
                        "format": char.format.rawValue,
                    ]
                    if let value = char.value {
                        charDict["value"] = encodeValue(value)
                    }
                    charList.append(charDict)
                }

                serviceList.append([
                    "type": service.type.rawValue,
                    "characteristics": charList,
                ])
            }

            accessoryList.append([
                "aid": accessory.aid,
                "services": serviceList,
            ])
        }

        let json: [String: Any] = ["accessories": accessoryList]
        return (try? JSONSerialization.data(withJSONObject: json)) ?? Data()
    }

    private func encodeValue(_ value: HAPCharacteristicValue) -> Any {
        switch value {
        case .bool(let v): return v
        case .uint8(let v): return v
        case .uint16(let v): return v
        case .uint32(let v): return v
        case .int32(let v): return v
        case .float(let v): return v
        case .string(let v): return v
        case .data(let v): return v.base64EncodedString()
        case .tlv8(let v): return v.base64EncodedString()
        }
    }

    private func decodeValue(_ raw: Any) -> HAPCharacteristicValue? {
        if let v = raw as? Bool { return .bool(v) }
        if let v = raw as? Int { return .int32(Int32(v)) }
        if let v = raw as? Double { return .float(v) }
        if let v = raw as? String { return .string(v) }
        return nil
    }
}
