// HAPBridge.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation
import HAPCore

// MARK: - HAPBridge

public actor HAPBridge {
    private var accessories: [UInt64: HAPAccessory] = [:]
    private var nextAID: UInt64 = 2
    private var writeHandlers: [String: @Sendable (HAPCharacteristicValue) async throws -> Void] = [:]
    public let category: HAPCategory

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

        let bridge = HAPAccessory(aid: 1, services: [infoService])
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

        // Assign IIDs to additional services, starting after info service
        var allServices = [infoService]
        var iid: UInt64 = UInt64(infoService.characteristics.count + 1)
        for var service in services {
            var updatedChars: [HAPCharacteristic] = []
            for char in service.characteristics {
                updatedChars.append(HAPCharacteristic(
                    iid: iid,
                    type: char.type,
                    value: char.value,
                    permissions: char.permissions,
                    format: char.format
                ))
                iid += 1
            }
            service.characteristics = updatedChars
            allServices.append(service)
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

    public func writeCharacteristic(aid: UInt64, iid: UInt64, value: HAPCharacteristicValue) throws {
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
    }
}
