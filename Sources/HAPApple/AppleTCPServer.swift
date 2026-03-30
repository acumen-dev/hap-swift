// AppleTCPServer.swift
// Copyright 2026 Monagle Pty Ltd

#if canImport(Network)
import Foundation
import Network
import Logging
import HAPCore
import HAPCrypto
import HAPTransport

// MARK: - AppleTCPServer

public final class AppleTCPServer: HAPServer, @unchecked Sendable {
    private let lock = NSLock()
    private var listener: NWListener?
    private var connections: [Int: NWConnection] = [:]
    private var nextConnectionID = 0
    private let logger: Logger
    private let characteristicProtocol: CharacteristicProtocol
    private let pairingStateMachine: PairingStateMachine
    private let pairVerifyStateMachine: PairVerifyStateMachine
    private var _port: UInt16 = 0

    public var port: UInt16 {
        lock.withLock { _port }
    }

    public init(
        bridge: HAPBridge,
        setupCode: String,
        identity: HAPIdentity,
        pairingStore: any PairingStore,
        logger: Logger = Logger(label: "hap.apple.tcp")
    ) {
        self.logger = logger
        self.pairingStateMachine = PairingStateMachine(
            setupCode: setupCode, identity: identity, pairingStore: pairingStore
        )
        self.pairVerifyStateMachine = PairVerifyStateMachine(
            identity: identity, pairingStore: pairingStore
        )
        self.characteristicProtocol = CharacteristicProtocol(
            bridge: bridge,
            pairingStateMachine: pairingStateMachine,
            pairVerifyStateMachine: pairVerifyStateMachine
        )
    }

    // MARK: - HAPServer

    public func start(port: UInt16) async throws {
        let params = NWParameters.tcp
        let listener: NWListener
        if port == 0 {
            listener = try NWListener(using: params)
        } else {
            listener = try NWListener(using: params, on: NWEndpoint.Port(rawValue: port)!)
        }

        listener.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                if let actualPort = listener.port?.rawValue {
                    self.lock.withLock { self._port = actualPort }
                    self.logger.info("HAP server listening on port \(actualPort)")
                }
            case .failed(let error):
                self.logger.error("HAP listener failed: \(error)")
            case .cancelled:
                self.logger.info("HAP listener cancelled")
            default:
                break
            }
        }

        listener.newConnectionHandler = { [weak self] connection in
            self?.handleNewConnection(connection)
        }

        listener.start(queue: .global(qos: .userInitiated))
        self.lock.withLock { self.listener = listener }

        // Wait for listener to be ready
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            listener.stateUpdateHandler = { [weak self] state in
                guard let self else { return }
                switch state {
                case .ready:
                    if let actualPort = listener.port?.rawValue {
                        self.lock.withLock { self._port = actualPort }
                        self.logger.info("HAP server listening on port \(actualPort)")
                    }
                    continuation.resume()
                case .failed(let error):
                    continuation.resume(throwing: error)
                case .cancelled:
                    continuation.resume(throwing: HAPError.unavailable)
                default:
                    break
                }
            }
        }
    }

    public func stop() async {
        let (currentListener, currentConnections) = lock.withLock {
            let l = self.listener
            let c = self.connections
            self.listener = nil
            self.connections.removeAll()
            return (l, c)
        }

        for (_, connection) in currentConnections {
            connection.cancel()
        }
        currentListener?.cancel()
        logger.info("HAP server stopped")
    }

    // MARK: - Connection Handling

    private func handleNewConnection(_ connection: NWConnection) {
        let connectionID = lock.withLock {
            let id = nextConnectionID
            nextConnectionID += 1
            connections[id] = connection
            return id
        }

        logger.debug("New HAP connection \(connectionID)")

        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.logger.debug("Connection \(connectionID) ready")
                self.receiveData(connection: connection, connectionID: connectionID)
            case .failed(let error):
                self.logger.debug("Connection \(connectionID) failed: \(error)")
                self.removeConnection(connectionID)
            case .cancelled:
                self.logger.debug("Connection \(connectionID) cancelled")
                self.removeConnection(connectionID)
            default:
                break
            }
        }

        connection.start(queue: .global(qos: .userInitiated))
    }

    private func receiveData(connection: NWConnection, connectionID: Int) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] content, _, isComplete, error in
            guard let self else { return }

            if let data = content, !data.isEmpty {
                Task {
                    await self.processRequest(data: data, connection: connection, connectionID: connectionID)
                }
            }

            if isComplete {
                self.removeConnection(connectionID)
            } else if let error {
                self.logger.debug("Connection \(connectionID) receive error: \(error)")
                self.removeConnection(connectionID)
            } else {
                // Continue receiving
                self.receiveData(connection: connection, connectionID: connectionID)
            }
        }
    }

    private func processRequest(data: Data, connection: NWConnection, connectionID: Int) async {
        guard let request = HTTPProtocol.parseRequest(from: data) else {
            logger.debug("Connection \(connectionID): failed to parse HTTP request")
            return
        }

        do {
            let response = try await characteristicProtocol.handleRequest(request)
            let responseData = HTTPProtocol.serializeResponse(response)
            connection.send(content: responseData, completion: .contentProcessed { [weak self] error in
                if let error {
                    self?.logger.debug("Connection \(connectionID) send error: \(error)")
                }
            })
        } catch {
            logger.error("Connection \(connectionID) request error: \(error)")
            let errorResponse = HTTPProtocol.errorResponse(status: 500, message: "Internal Server Error")
            let responseData = HTTPProtocol.serializeResponse(errorResponse)
            connection.send(content: responseData, completion: .contentProcessed { _ in })
        }
    }

    private func removeConnection(_ connectionID: Int) {
        let connection = lock.withLock { connections.removeValue(forKey: connectionID) }
        connection?.cancel()
    }
}
#endif
