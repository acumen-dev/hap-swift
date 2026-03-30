// HAPCharacteristic.swift
// Copyright 2026 Monagle Pty Ltd

public struct HAPCharacteristic: Sendable, Identifiable {
    public let iid: UInt64
    public let type: HAPCharacteristicType
    public var value: HAPCharacteristicValue?
    public let permissions: [HAPPermission]
    public let format: HAPFormat

    public var id: UInt64 { iid }

    public var isReadable: Bool { permissions.contains(.read) }
    public var isWritable: Bool { permissions.contains(.write) }
    public var supportsNotification: Bool { permissions.contains(.notify) }

    public init(
        iid: UInt64,
        type: HAPCharacteristicType,
        value: HAPCharacteristicValue? = nil,
        permissions: [HAPPermission],
        format: HAPFormat
    ) {
        self.iid = iid
        self.type = type
        self.value = value
        self.permissions = permissions
        self.format = format
    }
}

// MARK: - Factories

extension HAPCharacteristic {
    public static func name(_ value: String, iid: UInt64) -> HAPCharacteristic {
        HAPCharacteristic(
            iid: iid, type: .name, value: .string(value),
            permissions: [.read], format: .string
        )
    }

    public static func manufacturer(_ value: String, iid: UInt64) -> HAPCharacteristic {
        HAPCharacteristic(
            iid: iid, type: .manufacturer, value: .string(value),
            permissions: [.read], format: .string
        )
    }

    public static func model(_ value: String, iid: UInt64) -> HAPCharacteristic {
        HAPCharacteristic(
            iid: iid, type: .model, value: .string(value),
            permissions: [.read], format: .string
        )
    }

    public static func serialNumber(_ value: String, iid: UInt64) -> HAPCharacteristic {
        HAPCharacteristic(
            iid: iid, type: .serialNumber, value: .string(value),
            permissions: [.read], format: .string
        )
    }

    public static func firmwareRevision(_ value: String, iid: UInt64) -> HAPCharacteristic {
        HAPCharacteristic(
            iid: iid, type: .firmwareRevision, value: .string(value),
            permissions: [.read], format: .string
        )
    }

    public static func identify(iid: UInt64) -> HAPCharacteristic {
        HAPCharacteristic(
            iid: iid, type: .identify, value: nil,
            permissions: [.write], format: .bool
        )
    }
}
