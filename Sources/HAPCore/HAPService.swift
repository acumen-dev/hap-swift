// HAPService.swift
// Copyright 2026 Monagle Pty Ltd

public struct HAPService: Sendable {
    public let type: HAPServiceType
    public var characteristics: [HAPCharacteristic]

    public init(type: HAPServiceType, characteristics: [HAPCharacteristic]) {
        self.type = type
        self.characteristics = characteristics
    }
}

// MARK: - Factories

extension HAPService {
    public static func accessoryInformation(
        name: String,
        manufacturer: String,
        model: String,
        serialNumber: String,
        firmwareRevision: String,
        startIID: UInt64 = 1
    ) -> HAPService {
        var iid = startIID
        var chars: [HAPCharacteristic] = []

        chars.append(.name(name, iid: iid)); iid += 1
        chars.append(.manufacturer(manufacturer, iid: iid)); iid += 1
        chars.append(.model(model, iid: iid)); iid += 1
        chars.append(.serialNumber(serialNumber, iid: iid)); iid += 1
        chars.append(.firmwareRevision(firmwareRevision, iid: iid)); iid += 1
        chars.append(.identify(iid: iid))

        return HAPService(type: .accessoryInformation, characteristics: chars)
    }

    public static func securitySystem(startIID: UInt64) -> HAPService {
        var iid = startIID
        var chars: [HAPCharacteristic] = []

        chars.append(HAPCharacteristic(
            iid: iid, type: .currentSecuritySystemState, value: .uint8(3),
            permissions: [.read, .notify], format: .uint8
        )); iid += 1

        chars.append(HAPCharacteristic(
            iid: iid, type: .targetSecuritySystemState, value: .uint8(3),
            permissions: [.read, .write, .notify], format: .uint8
        )); iid += 1

        chars.append(HAPCharacteristic(
            iid: iid, type: .securitySystemAlarmType, value: .uint8(0),
            permissions: [.read, .notify], format: .uint8
        ))

        return HAPService(type: .securitySystem, characteristics: chars)
    }

    public static func garageDoorOpener(startIID: UInt64) -> HAPService {
        var iid = startIID
        var chars: [HAPCharacteristic] = []

        chars.append(HAPCharacteristic(
            iid: iid, type: .currentDoorState, value: .uint8(1),
            permissions: [.read, .notify], format: .uint8
        )); iid += 1

        chars.append(HAPCharacteristic(
            iid: iid, type: .targetDoorState, value: .uint8(1),
            permissions: [.read, .write, .notify], format: .uint8
        )); iid += 1

        chars.append(HAPCharacteristic(
            iid: iid, type: .obstructionDetected, value: .bool(false),
            permissions: [.read, .notify], format: .bool
        ))

        return HAPService(type: .garageDoorOpener, characteristics: chars)
    }
}
