// HAPCharacteristicValue.swift
// Copyright 2026 Monagle Pty Ltd

import Foundation

public enum HAPCharacteristicValue: Sendable, Equatable {
    case bool(Bool)
    case uint8(UInt8)
    case uint16(UInt16)
    case uint32(UInt32)
    case int32(Int32)
    case float(Double)
    case string(String)
    case data(Data)
    case tlv8(Data)

    public var format: HAPFormat {
        switch self {
        case .bool: .bool
        case .uint8: .uint8
        case .uint16: .uint16
        case .uint32: .uint32
        case .int32: .int
        case .float: .float
        case .string: .string
        case .data: .data
        case .tlv8: .tlv8
        }
    }
}
