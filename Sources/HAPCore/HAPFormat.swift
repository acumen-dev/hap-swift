// HAPFormat.swift
// Copyright 2026 Monagle Pty Ltd

public enum HAPFormat: String, Sendable, Codable {
    case bool
    case uint8
    case uint16
    case uint32
    case int32
    case float
    case string
    case data
    case tlv8
}
