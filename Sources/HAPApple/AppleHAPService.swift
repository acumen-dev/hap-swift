// AppleHAPService.swift
// Copyright 2026 Monagle Pty Ltd

#if canImport(Network)
import Foundation
import Logging
import MDNSApple
import HAPCore
import HAPCrypto
import HAPTransport

// MARK: - AppleHAPService

/// High-level HAP service for Apple platforms. Combines TCP server, mDNS advertisement, and bridge management.
public actor AppleHAPService {
    private let bridge: HAPBridge
    private let server: AppleTCPServer
    private let advertiser: HAPAdvertiser
    private let identity: HAPIdentity
    private let pairingStore: any PairingStore
    private let deviceID: String
    private let setupID: String
    private let logger: Logger

    public init(
        info: AccessoryInfo,
        setupCode: String,
        deviceID: String,
        setupID: String = "ACMN",
        identity: HAPIdentity? = nil,
        pairingStore: (any PairingStore)? = nil,
        logger: Logger = Logger(label: "hap.apple")
    ) {
        let identity = identity ?? HAPIdentity()
        let pairingStore = pairingStore ?? InMemoryPairingStore()
        let bridge = HAPBridge(info: info)
        let discovery = AppleServiceDiscovery(logger: logger)

        self.bridge = bridge
        self.identity = identity
        self.pairingStore = pairingStore
        self.deviceID = deviceID
        self.setupID = setupID
        self.logger = logger
        self.advertiser = HAPAdvertiser(discovery: discovery, deviceID: deviceID)
        self.server = AppleTCPServer(
            bridge: bridge,
            setupCode: setupCode,
            identity: identity,
            pairingStore: pairingStore,
            deviceID: deviceID,
            logger: logger
        )
    }

    /// Create a HAP service using an existing bridge that already has accessories provisioned.
    public init(
        bridge: HAPBridge,
        setupCode: String,
        deviceID: String,
        setupID: String = "ACMN",
        identity: HAPIdentity? = nil,
        pairingStore: (any PairingStore)? = nil,
        logger: Logger = Logger(label: "hap.apple")
    ) {
        let identity = identity ?? HAPIdentity()
        let pairingStore = pairingStore ?? InMemoryPairingStore()
        let discovery = AppleServiceDiscovery(logger: logger)

        self.bridge = bridge
        self.identity = identity
        self.pairingStore = pairingStore
        self.deviceID = deviceID
        self.setupID = setupID
        self.logger = logger

        let advertiser = HAPAdvertiser(discovery: discovery, deviceID: deviceID)
        self.advertiser = advertiser

        self.server = AppleTCPServer(
            bridge: bridge,
            setupCode: setupCode,
            identity: identity,
            pairingStore: pairingStore,
            deviceID: deviceID,
            logger: logger
        )
    }

    // MARK: - Port

    /// The TCP port the server is listening on. Zero until ``start(port:)`` completes.
    public nonisolated var port: UInt16 { server.port }

    // MARK: - Lifecycle

    public func start(port: UInt16 = 0) async throws {
        // Wire the pairing change callback now that self is fully initialized.
        let advertiser = self.advertiser
        let bridge = self.bridge
        let pairingStore = self.pairingStore
        let setupID = self.setupID
        let server = self.server

        server.onPairingChange = {
            let isPaired = await pairingStore.isPaired
            let name = await bridge.accessoryDatabase().first?.name ?? "HAP Bridge"
            let category = await bridge.category
            try? await advertiser.advertise(
                name: name,
                port: server.port,
                category: category,
                setupID: setupID,
                isPaired: isPaired
            )
        }

        // Wire up event notifications — when characteristics change, the bridge
        // sends encrypted EVENT/1.0 messages to subscribed connections.
        await bridge.setCharacteristicChangeHandler { [server] subscribers, eventData in
            for connectionID in subscribers {
                await server.sendEvent(eventData, to: connectionID)
            }
        }

        try await server.start(port: port)
        let actualPort = server.port

        let isPaired = await pairingStore.isPaired
        try await advertiser.advertise(
            name: await bridge.accessoryDatabase().first?.name ?? "HAP Bridge",
            port: actualPort,
            category: await bridge.category,
            setupID: setupID,
            isPaired: isPaired
        )

        logger.info("HAP service started on port \(actualPort), device ID: \(deviceID)")
    }

    public func stop() async {
        await advertiser.stopAdvertising()
        await server.stop()
        logger.info("HAP service stopped")
    }

    // MARK: - Accessory Management

    @discardableResult
    public func addAccessory(info: AccessoryInfo, services: [HAPService]) async -> UInt64 {
        await bridge.addAccessory(info: info, services: services)
    }

    public func removeAccessory(aid: UInt64) async {
        await bridge.removeAccessory(aid: aid)
    }
}
#endif
