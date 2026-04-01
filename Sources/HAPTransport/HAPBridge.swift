// HAPBridge.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import HAPCore
import Logging

// MARK: - HAPBridge

public actor HAPBridge {
    private let logger = Logger(label: "hap.bridge")
    private var accessories: [UInt64: HAPAccessory] = [:]
    private var nextAID: UInt64 = 2
    private var writeHandlers: [String: @Sendable (HAPCharacteristicValue) async throws -> Void] = [:]
    public let category: HAPCategory

    // MARK: - Event subscriptions

    /// Maps "aid.iid" → set of connection IDs that subscribed to events.
    private var subscriptions: [String: Set<Int>] = [:]

    /// Called when a characteristic value changes and subscribers exist.
    /// Parameters: set of connection IDs, serialised EVENT/1.0 payload (pre-JSON,
    /// needs encryption per-connection).
    private var onCharacteristicChange: (@Sendable (_ subscribers: Set<Int>, _ eventData: Data) async -> Void)?

    /// Set the handler called when a subscribed characteristic value changes.
    public func setCharacteristicChangeHandler(
        _ handler: @escaping @Sendable (_ subscribers: Set<Int>, _ eventData: Data) async -> Void
    ) {
        onCharacteristicChange = handler
    }

    private static func handlerKey(aid: UInt64, iid: UInt64) -> String {
        "\(aid).\(iid)"
    }

    public init(info: AccessoryInfo, category: HAPCategory = .bridge) {
        self.category = category

        // Bridge itself is AID=1
        let infoService = HAPService.accessoryInformation(
            name: info.name,
            manufacturer: info.manufacturer,
            model: info.model,
            serialNumber: info.serialNumber,
            firmwareRevision: info.firmwareRevision,
            startIID: 1
        )

        let protocolService = HAPService.protocolInformation(startIID: 8)
        let bridge = HAPAccessory(aid: 1, services: [infoService, protocolService])
        self.accessories[1] = bridge
    }

    // MARK: - Accessory Management

    @discardableResult
    public func addAccessory(info: AccessoryInfo, services: [HAPService]) -> UInt64 {
        let aid = nextAID
        nextAID += 1

        // Build accessory information service
        let infoService = HAPService.accessoryInformation(
            name: info.name,
            manufacturer: info.manufacturer,
            model: info.model,
            serialNumber: info.serialNumber,
            firmwareRevision: info.firmwareRevision,
            startIID: 1
        )

        // Assign IIDs to additional services.
        // Layout: infoService.iid=1, its N chars at 2..N+1,
        //         then service2.iid=N+2, its chars at N+3..., etc.
        var allServices = [infoService]
        var nextIID: UInt64 = infoService.iid + UInt64(infoService.characteristics.count) + 1
        for service in services {
            let serviceIID = nextIID
            nextIID += 1
            var updatedChars: [HAPCharacteristic] = []
            for char in service.characteristics {
                updatedChars.append(HAPCharacteristic(
                    iid: nextIID,
                    type: char.type,
                    value: char.value,
                    permissions: char.permissions,
                    format: char.format
                ))
                nextIID += 1
            }
            allServices.append(HAPService(iid: serviceIID, type: service.type, characteristics: updatedChars))
        }

        let accessory = HAPAccessory(aid: aid, services: allServices)
        accessories[aid] = accessory

        return aid
    }

    public func removeAccessory(aid: UInt64) {
        guard aid != 1 else { return }  // Cannot remove bridge
        accessories.removeValue(forKey: aid)
    }

    // MARK: - Accessory Database

    public func accessoryDatabase() -> [HAPAccessory] {
        accessories.values.sorted { $0.aid < $1.aid }
    }

    // MARK: - Characteristic Access

    public func readCharacteristic(aid: UInt64, iid: UInt64) -> HAPCharacteristicValue? {
        guard let accessory = accessories[aid] else { return nil }
        for service in accessory.services {
            for characteristic in service.characteristics where characteristic.iid == iid {
                return characteristic.value
            }
        }
        return nil
    }

    public func writeCharacteristic(aid: UInt64, iid: UInt64, value: HAPCharacteristicValue) async throws {
        guard var accessory = accessories[aid] else {
            throw HAPError.notFound
        }

        var found = false
        for serviceIndex in 0 ..< accessory.services.count {
            for charIndex in 0 ..< accessory.services[serviceIndex].characteristics.count {
                if accessory.services[serviceIndex].characteristics[charIndex].iid == iid {
                    guard accessory.services[serviceIndex].characteristics[charIndex].isWritable else {
                        throw HAPError.readOnly
                    }
                    accessory.services[serviceIndex].characteristics[charIndex].value = value
                    found = true
                    break
                }
            }
            if found { break }
        }

        guard found else { throw HAPError.notFound }
        accessories[aid] = accessory

        let key = Self.handlerKey(aid: aid, iid: iid)
        if let handler = writeHandlers[key] {
            try await handler(value)
        }
    }

    // MARK: - Write Handlers

    public func registerWriteHandler(
        aid: UInt64,
        iid: UInt64,
        handler: @escaping @Sendable (HAPCharacteristicValue) async throws -> Void
    ) {
        writeHandlers[Self.handlerKey(aid: aid, iid: iid)] = handler
    }

    // MARK: - Characteristic Updates

    public func updateCharacteristic(aid: UInt64, iid: UInt64, value: HAPCharacteristicValue) {
        guard var accessory = accessories[aid] else { return }

        for serviceIndex in 0 ..< accessory.services.count {
            for charIndex in 0 ..< accessory.services[serviceIndex].characteristics.count {
                if accessory.services[serviceIndex].characteristics[charIndex].iid == iid {
                    let oldValue = accessory.services[serviceIndex].characteristics[charIndex].value
                    accessory.services[serviceIndex].characteristics[charIndex].value = value
                    accessories[aid] = accessory

                    // Notify subscribers if value changed
                    if oldValue != value {
                        notifySubscribers(aid: aid, iid: iid, value: value)
                    }
                    return
                }
            }
        }
    }

    // MARK: - Event Subscriptions

    public func subscribe(connectionID: Int, aid: UInt64, iid: UInt64) {
        let key = Self.handlerKey(aid: aid, iid: iid)
        subscriptions[key, default: []].insert(connectionID)
        logger.info("Event subscribe: connection \(connectionID) → aid=\(aid) iid=\(iid)")
    }

    public func unsubscribe(connectionID: Int, aid: UInt64, iid: UInt64) {
        let key = Self.handlerKey(aid: aid, iid: iid)
        subscriptions[key]?.remove(connectionID)
    }

    /// Remove all subscriptions for a disconnected connection.
    public func unsubscribeAll(connectionID: Int) {
        for key in subscriptions.keys {
            subscriptions[key]?.remove(connectionID)
        }
    }

    private func notifySubscribers(aid: UInt64, iid: UInt64, value: HAPCharacteristicValue) {
        let key = Self.handlerKey(aid: aid, iid: iid)
        guard let subscribers = subscriptions[key], !subscribers.isEmpty else {
            logger.debug("Event notify: aid=\(aid) iid=\(iid) — no subscribers")
            return
        }
        guard let handler = onCharacteristicChange else {
            logger.warning("Event notify: aid=\(aid) iid=\(iid) — no handler set")
            return
        }

        logger.info("Event notify: aid=\(aid) iid=\(iid) value=\(value) → \(subscribers.count) subscriber(s)")
        let eventData = Self.buildEventPayload(aid: aid, iid: iid, value: value)
        let subs = subscribers
        Task { await handler(subs, eventData) }
    }

    /// Build the raw HTTP bytes for a HAP EVENT/1.0 message.
    ///
    /// Format:
    /// ```
    /// EVENT/1.0 200 OK\r\n
    /// Content-Type: application/hap+json\r\n
    /// Content-Length: <len>\r\n
    /// \r\n
    /// {"characteristics":[{"aid":<aid>,"iid":<iid>,"value":<value>}]}
    /// ```
    private static func buildEventPayload(aid: UInt64, iid: UInt64, value: HAPCharacteristicValue) -> Data {
        let jsonValue: Any = switch value {
        case .bool(let v): v
        case .uint8(let v): v
        case .uint16(let v): v
        case .uint32(let v): v
        case .int32(let v): v
        case .float(let v): v
        case .string(let v): v
        case .data(let v): v.base64EncodedString()
        case .tlv8(let v): v.base64EncodedString()
        }

        let charDict: [String: Any] = ["aid": aid, "iid": iid, "value": jsonValue]
        let body: [String: Any] = ["characteristics": [charDict]]
        let jsonData = (try? JSONSerialization.data(withJSONObject: body)) ?? Data()

        var event = "EVENT/1.0 200 OK\r\n"
        event += "Content-Type: application/hap+json\r\n"
        event += "Content-Length: \(jsonData.count)\r\n"
        event += "\r\n"

        var data = Data(event.utf8)
        data.append(jsonData)
        return data
    }
}
