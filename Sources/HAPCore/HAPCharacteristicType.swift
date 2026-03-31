// HAPCharacteristicType.swift
// Copyright 2026 Monagle Pty Ltd

public struct HAPCharacteristicType: RawRepresentable, Sendable, Hashable {
    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }
}

// MARK: - Accessory Information

extension HAPCharacteristicType {
    public static let name = HAPCharacteristicType(rawValue: "23")
    public static let manufacturer = HAPCharacteristicType(rawValue: "20")
    public static let model = HAPCharacteristicType(rawValue: "21")
    public static let serialNumber = HAPCharacteristicType(rawValue: "30")
    public static let firmwareRevision = HAPCharacteristicType(rawValue: "52")
    public static let identify = HAPCharacteristicType(rawValue: "14")
}

// MARK: - Protocol Information

extension HAPCharacteristicType {
    public static let version = HAPCharacteristicType(rawValue: "37")
}

// MARK: - Security System

extension HAPCharacteristicType {
    public static let currentSecuritySystemState = HAPCharacteristicType(rawValue: "66")
    public static let targetSecuritySystemState = HAPCharacteristicType(rawValue: "67")
    public static let securitySystemAlarmType = HAPCharacteristicType(rawValue: "8E")
}

// MARK: - Garage Door Opener

extension HAPCharacteristicType {
    public static let currentDoorState = HAPCharacteristicType(rawValue: "0E")
    public static let targetDoorState = HAPCharacteristicType(rawValue: "32")
    public static let obstructionDetected = HAPCharacteristicType(rawValue: "24")
}

// MARK: - Full UUID

extension HAPCharacteristicType {
    /// Returns the full 128-bit UUID for this characteristic type, e.g.
    /// `"00000025-0000-1000-8000-0026BB765291"` for `On` (type `"25"`).
    public var fullUUID: String {
        let padded = String(repeating: "0", count: max(0, 8 - rawValue.count)) + rawValue.uppercased()
        return "\(padded)-0000-1000-8000-0026BB765291"
    }
}
