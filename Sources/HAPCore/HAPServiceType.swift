// HAPServiceType.swift
// Copyright 2026 Monagle Pty Ltd

public struct HAPServiceType: RawRepresentable, Sendable, Hashable {
    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }
}

// MARK: - Known Service Types

extension HAPServiceType {
    public static let accessoryInformation = HAPServiceType(rawValue: "3E")
    public static let securitySystem = HAPServiceType(rawValue: "7E")
    public static let garageDoorOpener = HAPServiceType(rawValue: "41")
    public static let protocolInformation = HAPServiceType(rawValue: "A2")
}

// MARK: - Full UUID

extension HAPServiceType {
    public var fullUUID: String {
        "0000\(rawValue)-0000-1000-8000-0026BB765291"
    }
}
